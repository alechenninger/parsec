package keymanager

import (
	"context"
	"crypto"
)

// KeyManager manages cryptographic keys using stable key names within a namespace.
// The Key.ID is a backend-specific identifier used as the kid in JWTs and JWKS.
type KeyManager interface {
	// CreateKey creates a key that can be later retrieved by namespace and name.
	// namespace: A scoping identifier (e.g. trust domain or token type URN).
	// keyName: A stable internal identifier for the key (e.g. "key-a").
	//
	// When a key with the same namespace and keyName already exists, a new version is
	// created with the same name but a different Key ID (kid). Implementations are
	// expected to remove old key versions.
	//
	// Returns a Key with Key.ID being a unique identifier (used as kid in JWTs).
	CreateKey(ctx context.Context, namespace string, keyName string, keyType KeyType) (*Key, error)

	// GetKey retrieves the current key for a specific namespace and keyName for signing operations.
	GetKey(ctx context.Context, namespace string, keyName string) (*Key, error)
}

// KeyType represents the cryptographic key type
type KeyType string

const (
	KeyTypeECP256  KeyType = "EC-P256"
	KeyTypeECP384  KeyType = "EC-P384"
	KeyTypeRSA2048 KeyType = "RSA-2048"
	KeyTypeRSA4096 KeyType = "RSA-4096"
)

// Key represents a private key for signing
type Key struct {
	// ID is the actual key identifier (kid) used in JWTs
	// This may change with each version for some backends (e.g., AWS KMS key ID)
	ID string

	// Algorithm is the JWT signing algorithm (e.g., "ES256", "RS256")
	Algorithm string

	// Signer is the crypto.Signer for signing operations
	Signer crypto.Signer
}

// PublicKey represents a public key with JWK metadata
type PublicKey struct {
	// ID is the key identifier (kid) used in JWKs
	ID string

	// Algorithm is the JWT signing algorithm (e.g., "ES256", "RS256")
	Algorithm string

	// PublicKey is the actual public key material
	PublicKey crypto.PublicKey
}
