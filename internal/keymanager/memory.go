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

// memoryKey represents a private key for signing
type memoryKey struct {
	ID        string
	Algorithm string
	Signer    crypto.Signer
}

// InMemoryKeyManager is an in-memory implementation of KeyProvider for testing and development.
type InMemoryKeyManager struct {
	mu         sync.RWMutex
	keyType    KeyType               // The key type this manager creates
	algorithm  string                // The signing algorithm to use
	keys       map[string]*memoryKey // Current keys by namespace:keyName
	oldKeys    []*memoryKey          // Keys scheduled for deletion
	keyCounter int                   // Counter for generating unique key IDs
}

// NewInMemoryKeyManager creates a new in-memory key manager
func NewInMemoryKeyManager(keyType KeyType, algorithm string) *InMemoryKeyManager {
	if algorithm == "" {
		// Determine default algorithm
		switch keyType {
		case KeyTypeECP256:
			algorithm = "ES256"
		case KeyTypeECP384:
			algorithm = "ES384"
		case KeyTypeRSA2048, KeyTypeRSA4096:
			algorithm = "RS256"
		}
	}

	return &InMemoryKeyManager{
		keyType:    keyType,
		algorithm:  algorithm,
		keys:       make(map[string]*memoryKey),
		oldKeys:    make([]*memoryKey, 0),
		keyCounter: 0,
	}
}

// GetKeyHandle returns a handle for a specific namespace and key name.
func (m *InMemoryKeyManager) GetKeyHandle(ctx context.Context, namespace string, keyName string) (KeyHandle, error) {
	return &memoryKeyHandle{
		manager:   m,
		namespace: namespace,
		keyName:   keyName,
	}, nil
}

func (m *InMemoryKeyManager) rotateKey(namespace, keyName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	storageKey := m.storageKey(namespace, keyName)

	// If key exists with this identifier, move to oldKeys (simulate deletion scheduling)
	if existing, ok := m.keys[storageKey]; ok {
		m.oldKeys = append(m.oldKeys, existing)
	}

	// Generate new key based on configured keyType
	var signer crypto.Signer
	var err error

	switch m.keyType {
	case KeyTypeECP256:
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyTypeECP384:
		signer, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyTypeRSA2048:
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	case KeyTypeRSA4096:
		signer, err = rsa.GenerateKey(rand.Reader, 4096)
	default:
		return fmt.Errorf("unsupported key type: %s", m.keyType)
	}
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	m.keyCounter++
	kid := fmt.Sprintf("%s-%s-%d", namespace, keyName, m.keyCounter)

	key := &memoryKey{
		ID:        kid,
		Algorithm: m.algorithm,
		Signer:    signer,
	}

	m.keys[storageKey] = key
	return nil
}

func (m *InMemoryKeyManager) getKey(namespace, keyName string) (*memoryKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key, ok := m.keys[m.storageKey(namespace, keyName)]
	if !ok {
		return nil, fmt.Errorf("key not found: %s:%s", namespace, keyName)
	}
	return key, nil
}

func (m *InMemoryKeyManager) storageKey(namespace, keyName string) string {
	return namespace + ":" + keyName
}

type memoryKeyHandle struct {
	manager   *InMemoryKeyManager
	namespace string
	keyName   string
}

func (h *memoryKeyHandle) Sign(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, string, error) {
	key, err := h.manager.getKey(h.namespace, h.keyName)
	if err != nil {
		return nil, "", err
	}

	sig, err := key.Signer.Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, "", err
	}

	return sig, key.ID, nil
}

func (h *memoryKeyHandle) Metadata(ctx context.Context) (string, string, error) {
	key, err := h.manager.getKey(h.namespace, h.keyName)
	if err != nil {
		return "", "", err
	}
	return key.ID, key.Algorithm, nil
}

func (h *memoryKeyHandle) Public(ctx context.Context) (crypto.PublicKey, error) {
	key, err := h.manager.getKey(h.namespace, h.keyName)
	if err != nil {
		return nil, err
	}
	return key.Signer.Public(), nil
}

func (h *memoryKeyHandle) Rotate(ctx context.Context) error {
	return h.manager.rotateKey(h.namespace, h.keyName)
}
