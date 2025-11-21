package keys

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// AWSKMSKeyManager is a KeyProvider backed by AWS KMS.
type AWSKMSKeyManager struct {
	client      *kms.Client
	keyType     KeyType
	algorithm   string
	aliasPrefix string
}

// AWSKMSConfig configures the AWS KMS key manager
type AWSKMSConfig struct {
	KeyType     KeyType
	Algorithm   string
	Region      string
	AliasPrefix string
	Client      *kms.Client
}

// NewAWSKMSKeyManager creates a new AWS KMS key manager
func NewAWSKMSKeyManager(ctx context.Context, cfg AWSKMSConfig) (*AWSKMSKeyManager, error) {
	if cfg.KeyType == "" {
		return nil, fmt.Errorf("key_type is required")
	}

	algorithm := cfg.Algorithm
	if algorithm == "" {
		// Determine default algorithm
		var err error
		algorithm, err = algorithmFromKeyType(cfg.KeyType)
		if err != nil {
			return nil, err
		}
	}

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
		keyType:     cfg.KeyType,
		algorithm:   algorithm,
		aliasPrefix: cfg.AliasPrefix,
	}, nil
}

func (m *AWSKMSKeyManager) GetKeyHandle(ctx context.Context, namespace string, keyName string) (KeyHandle, error) {
	return &awsKeyHandle{
		manager:   m,
		namespace: namespace,
		keyName:   keyName,
	}, nil
}

func (m *AWSKMSKeyManager) rotateKey(ctx context.Context, namespace string, keyName string) error {
	// 1. Create new KMS key (CMK) using configured keyType
	keySpec, err := keySpecFromKeyType(m.keyType)
	if err != nil {
		return err
	}

	createResp, err := m.client.CreateKey(ctx, &kms.CreateKeyInput{
		KeySpec:  keySpec,
		KeyUsage: types.KeyUsageTypeSignVerify,
	})
	if err != nil {
		return fmt.Errorf("failed to create KMS key: %w", err)
	}

	newKeyID := aws.ToString(createResp.KeyMetadata.KeyId)
	aliasName := m.aliasName(namespace, keyName)

	// 2. Get current alias to find old key (if exists)
	oldKeyID, err := m.getKeyIDFromAlias(ctx, aliasName)
	if err != nil && oldKeyID == "" {
		// Alias doesn't exist, that's fine
	} else if err != nil {
		return fmt.Errorf("failed to check existing alias: %w", err)
	}

	// 3. Create or update alias to point to new key
	if oldKeyID != "" {
		_, err = m.client.UpdateAlias(ctx, &kms.UpdateAliasInput{
			AliasName:   aws.String(aliasName),
			TargetKeyId: aws.String(newKeyID),
		})
		if err != nil {
			return fmt.Errorf("failed to update alias: %w", err)
		}
	} else {
		_, err = m.client.CreateAlias(ctx, &kms.CreateAliasInput{
			AliasName:   aws.String(aliasName),
			TargetKeyId: aws.String(newKeyID),
		})
		if err != nil {
			return fmt.Errorf("failed to create alias: %w", err)
		}
	}

	// 4. Schedule old key for deletion (7 days minimum)
	if oldKeyID != "" {
		_, err = m.client.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
			KeyId:               aws.String(oldKeyID),
			PendingWindowInDays: aws.Int32(7),
		})
		if err != nil {
			fmt.Printf("Warning: failed to schedule old key %s for deletion: %v\n", oldKeyID, err)
		}
	}

	return nil
}

func (m *AWSKMSKeyManager) getKeyIDFromAlias(ctx context.Context, aliasName string) (string, error) {
	resp, err := m.client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(aliasName),
	})
	if err != nil {
		return "", nil // Assume not found if error
	}
	return aws.ToString(resp.KeyMetadata.KeyId), nil
}

func (m *AWSKMSKeyManager) aliasName(namespace, keyName string) string {
	sanitizedNS := strings.ReplaceAll(namespace, ":", "_")
	return fmt.Sprintf("%s%s/%s", m.aliasPrefix, sanitizedNS, keyName)
}

// awsKeyHandle implements KeyHandle
type awsKeyHandle struct {
	manager   *AWSKMSKeyManager
	namespace string
	keyName   string
}

func (h *awsKeyHandle) Sign(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, string, error) {
	aliasName := h.manager.aliasName(h.namespace, h.keyName)

	// Determine signing algorithm
	var signingAlg types.SigningAlgorithmSpec
	switch h.manager.algorithm {
	case "ES256":
		signingAlg = types.SigningAlgorithmSpecEcdsaSha256
	case "ES384":
		signingAlg = types.SigningAlgorithmSpecEcdsaSha384
	case "RS256":
		signingAlg = types.SigningAlgorithmSpecRsassaPkcs1V15Sha256
	default:
		return nil, "", fmt.Errorf("unsupported algorithm: %s", h.manager.algorithm)
	}

	// Call KMS Sign using ALIAS
	// KMS automatically resolves alias to current key ID
	resp, err := h.manager.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(aliasName),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: signingAlg,
	})
	if err != nil {
		return nil, "", fmt.Errorf("KMS sign failed: %w", err)
	}

	usedKeyID := aws.ToString(resp.KeyId)

	var signature []byte
	if h.manager.algorithm == "ES256" || h.manager.algorithm == "ES384" {
		signature, err = convertDERToRawECDSA(resp.Signature)
		if err != nil {
			return nil, "", err
		}
	} else {
		signature = resp.Signature
	}

	return signature, usedKeyID, nil
}

func (h *awsKeyHandle) Metadata(ctx context.Context) (string, string, error) {
	aliasName := h.manager.aliasName(h.namespace, h.keyName)
	keyID, err := h.manager.getKeyIDFromAlias(ctx, aliasName)
	if err != nil {
		return "", "", err
	}
	if keyID == "" {
		return "", "", fmt.Errorf("alias not found: %s", aliasName)
	}
	return keyID, h.manager.algorithm, nil
}

func (h *awsKeyHandle) Public(ctx context.Context) (crypto.PublicKey, error) {
	aliasName := h.manager.aliasName(h.namespace, h.keyName)
	resp, err := h.manager.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(aliasName),
	})
	if err != nil {
		return nil, err
	}

	pubKey, err := x509.ParsePKIXPublicKey(resp.PublicKey)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func (h *awsKeyHandle) Rotate(ctx context.Context) error {
	return h.manager.rotateKey(ctx, h.namespace, h.keyName)
}

// Helper functions
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

// convertDERToRawECDSA converts DER-encoded ECDSA signature to raw (r || s) format
func convertDERToRawECDSA(derSig []byte) ([]byte, error) {
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(derSig, &sig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DER signature: %w", err)
	}

	// Determine key size (32 bytes for P-256, 48 bytes for P-384)
	// Approximate logic based on bit len
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

