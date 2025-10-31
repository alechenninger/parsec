package keymanager

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// AWSKMSKeyManager is a KeyManager backed by AWS KMS.
// It uses KMS aliases to provide stable slot identifiers while rotating the underlying CMKs.
type AWSKMSKeyManager struct {
	client      *kms.Client
	aliasPrefix string // e.g., "alias/parsec/"
}

// AWSKMSConfig configures the AWS KMS key manager
type AWSKMSConfig struct {
	// Region is the AWS region (e.g., "us-east-1")
	Region string

	// AliasPrefix is the prefix for KMS aliases (e.g., "alias/parsec/")
	// Must start with "alias/"
	AliasPrefix string

	// Client is an optional pre-configured KMS client for testing
	Client *kms.Client
}

// NewAWSKMSKeyManager creates a new AWS KMS key manager
func NewAWSKMSKeyManager(ctx context.Context, cfg AWSKMSConfig) (*AWSKMSKeyManager, error) {
	var client *kms.Client

	if cfg.Client != nil {
		client = cfg.Client
	} else {
		// Load AWS config
		awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region))
		if err != nil {
			return nil, fmt.Errorf("failed to load AWS config: %w", err)
		}
		client = kms.NewFromConfig(awsCfg)
	}

	// Ensure alias prefix starts with "alias/"
	if cfg.AliasPrefix == "" {
		cfg.AliasPrefix = "alias/parsec/"
	}
	if len(cfg.AliasPrefix) < 6 || cfg.AliasPrefix[:6] != "alias/" {
		return nil, fmt.Errorf("alias prefix must start with 'alias/', got: %s", cfg.AliasPrefix)
	}

	return &AWSKMSKeyManager{
		client:      client,
		aliasPrefix: cfg.AliasPrefix,
	}, nil
}

// CreateKey creates a new KMS key with the given stable slotID.
// If an alias with this slotID already exists, it creates a new CMK, updates the alias,
// and schedules the old CMK for deletion (7 days).
func (m *AWSKMSKeyManager) CreateKey(ctx context.Context, slotID string, keyType KeyType) (*Key, error) {
	// 1. Create new KMS key (CMK)
	keySpec, err := keySpecFromKeyType(keyType)
	if err != nil {
		return nil, err
	}

	createResp, err := m.client.CreateKey(ctx, &kms.CreateKeyInput{
		KeySpec:  keySpec,
		KeyUsage: types.KeyUsageTypeSignVerify,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS key: %w", err)
	}

	newKeyID := aws.ToString(createResp.KeyMetadata.KeyId)
	aliasName := m.aliasPrefix + slotID

	// 2. Get current alias to find old key (if exists)
	oldKeyID, err := m.getKeyIDFromAlias(ctx, aliasName)
	if err != nil && oldKeyID == "" {
		// Alias doesn't exist, that's fine
	} else if err != nil {
		return nil, fmt.Errorf("failed to check existing alias: %w", err)
	}

	// 3. Create or update alias to point to new key
	if oldKeyID != "" {
		// Update existing alias
		_, err = m.client.UpdateAlias(ctx, &kms.UpdateAliasInput{
			AliasName:   aws.String(aliasName),
			TargetKeyId: aws.String(newKeyID),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to update alias: %w", err)
		}
	} else {
		// Create new alias
		_, err = m.client.CreateAlias(ctx, &kms.CreateAliasInput{
			AliasName:   aws.String(aliasName),
			TargetKeyId: aws.String(newKeyID),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create alias: %w", err)
		}
	}

	// 4. Schedule old key for deletion (7 days minimum)
	if oldKeyID != "" {
		_, err = m.client.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
			KeyId:               aws.String(oldKeyID),
			PendingWindowInDays: aws.Int32(7),
		})
		if err != nil {
			// Log but don't fail - the new key is already created and aliased
			fmt.Printf("Warning: failed to schedule old key %s for deletion: %v\n", oldKeyID, err)
		}
	}

	// 5. Get algorithm and create signer
	algorithm, err := algorithmFromKeyType(keyType)
	if err != nil {
		return nil, err
	}

	signer := &kmsSigner{
		client:    m.client,
		keyID:     newKeyID,
		algorithm: algorithm,
	}

	return &Key{
		ID:        newKeyID,
		Algorithm: algorithm,
		Signer:    signer,
	}, nil
}

// GetKey retrieves a key by its stable slotID (resolves alias) for signing operations
func (m *AWSKMSKeyManager) GetKey(ctx context.Context, slotID string) (*Key, error) {
	aliasName := m.aliasPrefix + slotID

	// Resolve alias to actual KMS key ID
	actualKeyID, err := m.getKeyIDFromAlias(ctx, aliasName)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve alias %s: %w", aliasName, err)
	}
	if actualKeyID == "" {
		return nil, fmt.Errorf("alias not found: %s", aliasName)
	}

	// Get key metadata to determine algorithm
	keyMeta, err := m.client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(actualKeyID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe key: %w", err)
	}

	// Determine algorithm
	var algorithm string
	switch keyMeta.KeyMetadata.KeySpec {
	case types.KeySpecEccNistP256:
		algorithm = "ES256"
	case types.KeySpecEccNistP384:
		algorithm = "ES384"
	case types.KeySpecRsa2048, types.KeySpecRsa3072, types.KeySpecRsa4096:
		algorithm = "RS256"
	default:
		return nil, fmt.Errorf("unsupported key spec: %v", keyMeta.KeyMetadata.KeySpec)
	}

	signer := &kmsSigner{
		client:    m.client,
		keyID:     actualKeyID,
		algorithm: algorithm,
	}

	return &Key{
		ID:        actualKeyID,
		Algorithm: algorithm,
		Signer:    signer,
	}, nil
}

// getKeyIDFromAlias resolves an alias to a KMS key ID
func (m *AWSKMSKeyManager) getKeyIDFromAlias(ctx context.Context, aliasName string) (string, error) {
	resp, err := m.client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(aliasName),
	})
	if err != nil {
		// Check if it's a not found error
		return "", nil
	}

	return aws.ToString(resp.KeyMetadata.KeyId), nil
}

// keySpecFromKeyType converts our KeyType to AWS KMS KeySpec
func keySpecFromKeyType(keyType KeyType) (types.KeySpec, error) {
	switch keyType {
	case KeyTypeECP256:
		return types.KeySpecEccNistP256, nil
	case KeyTypeECP384:
		return types.KeySpecEccNistP384, nil
	case KeyTypeRSA2048:
		return types.KeySpecRsa2048, nil
	case KeyTypeRSA4096:
		return types.KeySpecRsa4096, nil
	default:
		return "", fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// algorithmFromKeyType returns the JWT algorithm for a KeyType
func algorithmFromKeyType(keyType KeyType) (string, error) {
	switch keyType {
	case KeyTypeECP256:
		return "ES256", nil
	case KeyTypeECP384:
		return "ES384", nil
	case KeyTypeRSA2048, KeyTypeRSA4096:
		return "RS256", nil
	default:
		return "", fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// kmsSigner implements crypto.Signer using AWS KMS
type kmsSigner struct {
	client    *kms.Client
	keyID     string
	algorithm string
	publicKey crypto.PublicKey // Cached public key
}

// Public returns the public key
func (s *kmsSigner) Public() crypto.PublicKey {
	if s.publicKey != nil {
		return s.publicKey
	}

	// Fetch public key from KMS
	resp, err := s.client.GetPublicKey(context.Background(), &kms.GetPublicKeyInput{
		KeyId: aws.String(s.keyID),
	})
	if err != nil {
		return nil
	}

	pubKey, err := x509.ParsePKIXPublicKey(resp.PublicKey)
	if err != nil {
		return nil
	}

	s.publicKey = pubKey
	return pubKey
}

// Sign signs the digest using KMS
func (s *kmsSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Determine signing algorithm
	var signingAlg types.SigningAlgorithmSpec
	switch s.algorithm {
	case "ES256":
		signingAlg = types.SigningAlgorithmSpecEcdsaSha256
	case "ES384":
		signingAlg = types.SigningAlgorithmSpecEcdsaSha384
	case "RS256":
		signingAlg = types.SigningAlgorithmSpecRsassaPkcs1V15Sha256
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", s.algorithm)
	}

	// Call KMS Sign
	resp, err := s.client.Sign(context.Background(), &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: signingAlg,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS sign failed: %w", err)
	}

	// For ECDSA, KMS returns DER-encoded signature, but crypto.Signer expects (r, s) concatenated
	if s.algorithm == "ES256" || s.algorithm == "ES384" {
		return convertDERToRawECDSA(resp.Signature)
	}

	return resp.Signature, nil
}

// convertDERToRawECDSA converts DER-encoded ECDSA signature to raw (r || s) format
func convertDERToRawECDSA(derSig []byte) ([]byte, error) {
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(derSig, &sig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DER signature: %w", err)
	}

	// Determine key size (32 bytes for P-256, 48 bytes for P-384)
	keySize := (sig.R.BitLen() + 7) / 8
	if keySize < 32 {
		keySize = 32
	}

	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()

	// Pad to key size
	rawSig := make([]byte, keySize*2)
	copy(rawSig[keySize-len(rBytes):keySize], rBytes)
	copy(rawSig[keySize*2-len(sBytes):], sBytes)

	return rawSig, nil
}

// Ensure kmsSigner implements crypto.Signer
var _ crypto.Signer = (*kmsSigner)(nil)
