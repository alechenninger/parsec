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
	keys       map[string]*Key // Current keys by namespace:keyName
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

// CreateKey creates a new key with the given namespace and keyName.
// If a key with this identifier already exists, it moves the old key to the deletion queue.
func (m *InMemoryKeyManager) CreateKey(ctx context.Context, namespace string, keyName string, keyType KeyType) (*Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	storageKey := m.storageKey(namespace, keyName)

	// If key exists with this identifier, move to oldKeys (simulate deletion scheduling)
	if existing, ok := m.keys[storageKey]; ok {
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
	// kid uses namespace and keyName but replaces colon with hyphen for cleaner IDs
	kid := fmt.Sprintf("%s-%s-%d", namespace, keyName, m.keyCounter)

	key := &Key{
		ID:        kid, // Unique kid for JWKS/JWT
		Algorithm: algorithm,
		Signer:    signer,
	}

	m.keys[storageKey] = key

	return key, nil
}

// GetKey retrieves a key by its namespace and keyName for signing operations
func (m *InMemoryKeyManager) GetKey(ctx context.Context, namespace string, keyName string) (*Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	storageKey := m.storageKey(namespace, keyName)
	key, ok := m.keys[storageKey]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", storageKey)
	}

	return key, nil
}

func (m *InMemoryKeyManager) storageKey(namespace, keyName string) string {
	return namespace + ":" + keyName
}
