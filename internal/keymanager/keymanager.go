package keymanager

import (
	"context"
	"crypto"
)

// KeyManager manages cryptographic keys using stable slot identifiers.
// slotID is a stable internal identifier used to manage key versions.
// The Key.ID is a backend-specific identifier used as the kid in JWTs and JWKS.
type KeyManager interface {
	// CreateKey creates a new key for the given slotID.
	// For backends like AWS KMS, slotID is used to construct the alias name.
	// When a key with the same slotID already exists, it creates a new version,
	// schedules the old one for deletion, and updates any aliases.
	// Returns a Key with Key.ID being a unique identifier (used as kid in JWTs).
	CreateKey(ctx context.Context, slotID string, keyType KeyType) (*Key, error)

	// GetKey retrieves the current key for a specific slotID for signing operations.
	GetKey(ctx context.Context, slotID string) (*Key, error)
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
