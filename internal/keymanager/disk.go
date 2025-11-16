package keymanager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/alechenninger/parsec/internal/fs"
	"github.com/google/uuid"
)

// DiskKeyManager is a KeyManager that stores keys on disk as JSON files.
// It's suitable for single-pod Kubernetes deployments with ReadWriteOnce persistent volumes.
type DiskKeyManager struct {
	mu       sync.RWMutex
	keysPath string        // Directory path for storing key files
	fs       fs.FileSystem // Filesystem abstraction for operations
}

// DiskKeyManagerConfig configures the disk key manager
type DiskKeyManagerConfig struct {
	// KeysPath is the directory where key files will be stored
	KeysPath string

	// FileSystem is an optional filesystem abstraction (defaults to OSFileSystem)
	FileSystem fs.FileSystem
}

// keyFileData represents the JSON structure stored on disk
type keyFileData struct {
	ID         string    `json:"id"`
	Algorithm  string    `json:"algorithm"`
	KeyType    string    `json:"key_type"`
	PrivateKey string    `json:"private_key"` // Base64-encoded DER format
	CreatedAt  time.Time `json:"created_at"`
}

// NewDiskKeyManager creates a new disk-based key manager
func NewDiskKeyManager(cfg DiskKeyManagerConfig) (*DiskKeyManager, error) {
	if cfg.KeysPath == "" {
		return nil, fmt.Errorf("keys_path is required")
	}

	// Default to OS filesystem if not provided
	filesystem := cfg.FileSystem
	if filesystem == nil {
		filesystem = fs.NewOSFileSystem()
	}

	// Create directory if it doesn't exist
	if err := filesystem.MkdirAll(cfg.KeysPath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create keys directory: %w", err)
	}

	return &DiskKeyManager{
		keysPath: cfg.KeysPath,
		fs:       filesystem,
	}, nil
}

// CreateKey creates a new key and stores it on disk.
// If a key with this slotID already exists, it deletes the old key file and creates a new one.
func (m *DiskKeyManager) CreateKey(ctx context.Context, slotID string, keyType KeyType) (*Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

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

	// Generate a unique kid using UUID
	kid := uuid.New().String()

	// Marshal private key to PKCS8 DER format
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Encode to base64
	privateKeyB64 := base64.StdEncoding.EncodeToString(privateKeyDER)

	// Create key file data
	data := keyFileData{
		ID:         kid,
		Algorithm:  algorithm,
		KeyType:    string(keyType),
		PrivateKey: privateKeyB64,
		CreatedAt:  time.Now().UTC(),
	}

	// Write to disk atomically
	if err := m.writeKeyFile(slotID, &data); err != nil {
		return nil, fmt.Errorf("failed to write key file: %w", err)
	}

	return &Key{
		ID:        kid,
		Algorithm: algorithm,
		Signer:    signer,
	}, nil
}

// GetKey retrieves a key from disk by its slotID
func (m *DiskKeyManager) GetKey(ctx context.Context, slotID string) (*Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Read key file
	data, err := m.readKeyFile(slotID)
	if err != nil {
		return nil, err
	}

	// Decode base64 private key
	privateKeyDER, err := base64.StdEncoding.DecodeString(data.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	// Parse PKCS8 private key
	privateKeyAny, err := x509.ParsePKCS8PrivateKey(privateKeyDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Type assert to crypto.Signer
	signer, ok := privateKeyAny.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	return &Key{
		ID:        data.ID,
		Algorithm: data.Algorithm,
		Signer:    signer,
	}, nil
}

// writeKeyFile atomically writes a key file to disk
func (m *DiskKeyManager) writeKeyFile(slotID string, data *keyFileData) error {
	keyFilePath := m.keyFilePath(slotID)

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Write atomically (filesystem handles temp file + sync + rename)
	if err := m.fs.WriteFileAtomic(keyFilePath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// readKeyFile reads a key file from disk
func (m *DiskKeyManager) readKeyFile(slotID string) (*keyFileData, error) {
	keyFilePath := m.keyFilePath(slotID)

	// Read file
	jsonData, err := m.fs.ReadFile(keyFilePath)
	if err != nil {
		if m.fs.IsNotExist(err) {
			return nil, fmt.Errorf("key not found: %s", slotID)
		}
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Unmarshal JSON
	var data keyFileData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key file (corrupted?): %w", err)
	}

	return &data, nil
}

// keyFilePath returns the full path to a key file for a given slotID
func (m *DiskKeyManager) keyFilePath(slotID string) string {
	return filepath.Join(m.keysPath, fmt.Sprintf("%s.json", slotID))
}
