package keymanager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"
)

// InMemoryKeyManager is an in-memory implementation of KeyManager for testing and development.
// It generates cryptographic keys in memory using stable slot identifiers.
type InMemoryKeyManager struct {
	mu         sync.RWMutex
	keys       map[string]*Key // Current keys by slotID
	oldKeys    []*Key          // Keys scheduled for deletion
	keyCounter int             // Counter for generating unique key IDs
}

// NewInMemoryKeyManager creates a new in-memory key manager
func NewInMemoryKeyManager() *InMemoryKeyManager {
	return &InMemoryKeyManager{
		keys:       make(map[string]*Key),
		oldKeys:    make([]*Key, 0),
		keyCounter: 0,
	}
}

// CreateKey creates a new key with the given slotID.
// If a key with this slotID already exists, it moves the old key to the deletion queue.
func (m *InMemoryKeyManager) CreateKey(ctx context.Context, slotID string, keyType KeyType) (*Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// If key exists with this slotID, move to oldKeys (simulate deletion scheduling)
	if existing, ok := m.keys[slotID]; ok {
		m.oldKeys = append(m.oldKeys, existing)
	}

	// Generate new key based on keyType
	var signer crypto.Signer
	var algorithm string
	var err error

	switch keyType {
	case KeyTypeECP256:
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate EC-P256 key: %w", err)
		}
		algorithm = "ES256"

	case KeyTypeECP384:
		signer, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate EC-P384 key: %w", err)
		}
		algorithm = "ES384"

	case KeyTypeRSA2048:
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA-2048 key: %w", err)
		}
		algorithm = "RS256"

	case KeyTypeRSA4096:
		signer, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA-4096 key: %w", err)
		}
		algorithm = "RS256"

	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	// Generate a unique kid for this key (changes with each rotation)
	// This is what gets exposed in JWTs and JWKS
	// Use an incrementing counter for deterministic testing
	m.keyCounter++
	kid := fmt.Sprintf("%s-%d", slotID, m.keyCounter)

	key := &Key{
		ID:        kid, // Unique kid for JWKS/JWT
		Algorithm: algorithm,
		Signer:    signer,
	}

	m.keys[slotID] = key

	return key, nil
}

// GetPublicKeys returns all current public keys (not scheduled for deletion)
func (m *InMemoryKeyManager) GetPublicKeys(ctx context.Context) ([]*PublicKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	publicKeys := make([]*PublicKey, 0, len(m.keys))
	for _, key := range m.keys {
		publicKeys = append(publicKeys, &PublicKey{
			ID:        key.ID,
			Algorithm: key.Algorithm,
			PublicKey: key.Signer.Public(),
		})
	}

	return publicKeys, nil
}

// GetKey retrieves a key by its slotID for signing operations
func (m *InMemoryKeyManager) GetKey(ctx context.Context, slotID string) (*Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key, ok := m.keys[slotID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", slotID)
	}

	return key, nil
}
