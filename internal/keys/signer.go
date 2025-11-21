package keys

import (
	"context"
	"crypto"
	"errors"

	"github.com/alechenninger/parsec/internal/service"
)

var (
	// ErrKeyMismatch is returned when the key used for signing does not match the expected key ID
	ErrKeyMismatch = errors.New("key mismatch during signing")
)

// KeyID is a unique identifier for a cryptographic key
type KeyID string

// Algorithm is a cryptographic algorithm identifier (e.g., "ES256", "RS256")
type Algorithm string

// KeyHandle represents a logical key version (e.g. a specific file or KMS key version/alias).
// It provides access to signing operations and key metadata.
type KeyHandle interface {
	// Sign signs data. Returns signature and the ID of the key actually used.
	// This allows callers to verify if the key rotated underneath them (if using aliases).
	Sign(ctx context.Context, digest []byte, opts crypto.SignerOpts) (signature []byte, usedKeyID string, err error)

	// Metadata returns the expected Key ID and Algorithm for this handle.
	Metadata(ctx context.Context) (keyID string, alg string, err error)

	// Public returns the public key.
	Public(ctx context.Context) (crypto.PublicKey, error)

	// Rotate rotates this key (creates a new version).
	Rotate(ctx context.Context) error
}

// RotatingSigner manages active keys and rotation.
type RotatingSigner interface {
	// GetCurrentSigner returns a signer bound to the provided context and the current active key.
	// It returns the signer (for use with JWT lib) and the metadata (kid, alg) for JWT headers.
	// The returned Signer detects key mismatches (race conditions) internally.
	GetCurrentSigner(ctx context.Context) (signer crypto.Signer, keyID KeyID, alg Algorithm, err error)

	// PublicKeys returns the current set of valid public keys.
	PublicKeys(ctx context.Context) ([]service.PublicKey, error)

	// Start begins background rotation tasks.
	Start(ctx context.Context) error

	// Stop stops background tasks.
	Stop()
}

// KeyProvider manages creating/retrieving KeyHandles.
type KeyProvider interface {
	// GetKeyHandle returns a handle for a specific namespace and key name.
	GetKeyHandle(ctx context.Context, namespace string, keyName string) (KeyHandle, error)
}

// KeyType represents the cryptographic key type
type KeyType string

const (
	KeyTypeECP256  KeyType = "EC-P256"
	KeyTypeECP384  KeyType = "EC-P384"
	KeyTypeRSA2048 KeyType = "RSA-2048"
	KeyTypeRSA4096 KeyType = "RSA-4096"
)

