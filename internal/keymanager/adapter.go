package keymanager

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"

	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	spirekm "github.com/spiffe/spire/pkg/server/plugin/keymanager"
	keymanagerbase "github.com/spiffe/spire/pkg/server/plugin/keymanager/base"
)

// BaseAdapter adapts a Spire keymanagerbase.Base to the KeyManager interface
type BaseAdapter struct {
	base *keymanagerbase.Base
}

// NewBaseAdapter creates a new adapter for keymanagerbase.Base
func NewBaseAdapter(base *keymanagerbase.Base) *BaseAdapter {
	return &BaseAdapter{base: base}
}

// Name implements catalog.PluginInfo
func (a *BaseAdapter) Name() string {
	return "memory"
}

// Type implements catalog.PluginInfo
func (a *BaseAdapter) Type() string {
	return "KeyManager"
}

// GenerateKey implements the KeyManager interface
func (a *BaseAdapter) GenerateKey(ctx context.Context, id string, keyType spirekm.KeyType) (spirekm.Key, error) {
	kt, err := a.convertKeyType(keyType)
	if err != nil {
		return nil, err
	}

	resp, err := a.base.GenerateKey(ctx, &keymanagerv1.GenerateKeyRequest{
		KeyId:   id,
		KeyType: kt,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	return a.makeKey(id, resp.PublicKey)
}

// GetKey implements the KeyManager interface
func (a *BaseAdapter) GetKey(ctx context.Context, id string) (spirekm.Key, error) {
	resp, err := a.base.GetPublicKey(ctx, &keymanagerv1.GetPublicKeyRequest{
		KeyId: id,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	return a.makeKey(id, resp.PublicKey)
}

// GetKeys implements the KeyManager interface
func (a *BaseAdapter) GetKeys(ctx context.Context) ([]spirekm.Key, error) {
	resp, err := a.base.GetPublicKeys(ctx, &keymanagerv1.GetPublicKeysRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to get keys: %w", err)
	}

	keys := make([]spirekm.Key, 0, len(resp.PublicKeys))
	for _, pk := range resp.PublicKeys {
		key, err := a.makeKey(pk.Id, pk)
		if err != nil {
			return nil, fmt.Errorf("failed to make key %s: %w", pk.Id, err)
		}
		keys = append(keys, key)
	}

	return keys, nil
}

// convertKeyType converts from spirekm.KeyType to keymanagerv1.KeyType
func (a *BaseAdapter) convertKeyType(keyType spirekm.KeyType) (keymanagerv1.KeyType, error) {
	switch keyType {
	case spirekm.ECP256:
		return keymanagerv1.KeyType_EC_P256, nil
	case spirekm.ECP384:
		return keymanagerv1.KeyType_EC_P384, nil
	case spirekm.RSA2048:
		return keymanagerv1.KeyType_RSA_2048, nil
	case spirekm.RSA4096:
		return keymanagerv1.KeyType_RSA_4096, nil
	default:
		return keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE, fmt.Errorf("unsupported key type: %v", keyType)
	}
}

// makeKey creates a Key from the public key response
func (a *BaseAdapter) makeKey(id string, pk *keymanagerv1.PublicKey) (spirekm.Key, error) {
	return &baseKey{
		adapter: a,
		id:      id,
		pk:      pk,
	}, nil
}

// baseKey implements the spirekm.Key interface
type baseKey struct {
	adapter *BaseAdapter
	id      string
	pk      *keymanagerv1.PublicKey
}

// ID returns the key ID
func (k *baseKey) ID() string {
	return k.id
}

// Public returns the public key
func (k *baseKey) Public() crypto.PublicKey {
	// Parse the PKIX data to get the public key
	pubKey, err := parsePublicKeyFromPKIX(k.pk.PkixData)
	if err != nil {
		// Return nil if we can't parse (shouldn't happen with valid data)
		return nil
	}
	return pubKey
}

// Sign signs the digest (implements crypto.Signer)
func (k *baseKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Determine the hash algorithm
	var hashAlg keymanagerv1.HashAlgorithm
	if opts != nil {
		switch opts.HashFunc() {
		case crypto.SHA256:
			hashAlg = keymanagerv1.HashAlgorithm_SHA256
		case crypto.SHA384:
			hashAlg = keymanagerv1.HashAlgorithm_SHA384
		case crypto.SHA512:
			hashAlg = keymanagerv1.HashAlgorithm_SHA512
		default:
			return nil, fmt.Errorf("unsupported hash algorithm: %v", opts.HashFunc())
		}
	} else {
		// Default to SHA256
		hashAlg = keymanagerv1.HashAlgorithm_SHA256
	}

	resp, err := k.adapter.base.SignData(context.Background(), &keymanagerv1.SignDataRequest{
		KeyId: k.id,
		Data:  digest,
		SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
			HashAlgorithm: hashAlg,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return resp.Signature, nil
}

// parsePublicKeyFromPKIX parses a PKIX-encoded public key
func parsePublicKeyFromPKIX(pkixData []byte) (crypto.PublicKey, error) {
	pubKey, err := x509.ParsePKIXPublicKey(pkixData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}
	return pubKey, nil
}
