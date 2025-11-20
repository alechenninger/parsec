package keymanager

import (
	"context"
	"crypto"
	"encoding/json"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alechenninger/parsec/internal/fs"
)

func TestDiskKeyManager_CreateAndGetKey(t *testing.T) {
	tests := []struct {
		name    string
		keyType KeyType
		wantAlg string
	}{
		{
			name:    "EC-P256",
			keyType: KeyTypeECP256,
			wantAlg: "ES256",
		},
		{
			name:    "EC-P384",
			keyType: KeyTypeECP384,
			wantAlg: "ES384",
		},
		{
			name:    "RSA-2048",
			keyType: KeyTypeRSA2048,
			wantAlg: "RS256",
		},
		{
			name:    "RSA-4096",
			keyType: KeyTypeRSA4096,
			wantAlg: "RS256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			memFS := fs.NewMemFileSystem()
			km, err := NewDiskKeyManager(DiskKeyManagerConfig{
				KeyType:    tt.keyType,
				KeysPath:   "/keys",
				FileSystem: memFS,
			})
			require.NoError(t, err)

			ctx := context.Background()
			ns := "test-ns"
			keyName := "key-a"

			handle, err := km.GetKeyHandle(ctx, ns, keyName)
			require.NoError(t, err)

			// Create a key (rotate)
			err = handle.Rotate(ctx)
			require.NoError(t, err)

			id, alg, err := handle.Metadata(ctx)
			require.NoError(t, err)
			assert.NotEmpty(t, id)
			assert.Equal(t, tt.wantAlg, alg)

			pubKey, err := handle.Public(ctx)
			require.NoError(t, err)
			assert.NotNil(t, pubKey)

			// Sign something
			msg := []byte("message to sign")
			hasher := crypto.SHA256.New()
			hasher.Write(msg)
			digest := hasher.Sum(nil)
			sig, usedID, err := handle.Sign(ctx, digest, crypto.SHA256)
			require.NoError(t, err)
			assert.NotEmpty(t, sig)
			assert.Equal(t, id, usedID)
		})
	}
}

func TestDiskKeyManager_KeyRotation(t *testing.T) {
	memFS := fs.NewMemFileSystem()
	km, err := NewDiskKeyManager(DiskKeyManagerConfig{
		KeyType:    KeyTypeECP256,
		KeysPath:   "/keys",
		FileSystem: memFS,
	})
	require.NoError(t, err)

	ctx := context.Background()
	ns := "test-ns"
	keyName := "key-a"

	handle, err := km.GetKeyHandle(ctx, ns, keyName)
	require.NoError(t, err)

	// Create first key
	err = handle.Rotate(ctx)
	require.NoError(t, err)

	id1, _, err := handle.Metadata(ctx)
	require.NoError(t, err)

	// Create second key (rotation)
	err = handle.Rotate(ctx)
	require.NoError(t, err)

	id2, _, err := handle.Metadata(ctx)
	require.NoError(t, err)

	assert.NotEqual(t, id1, id2)
}

func TestDiskKeyManager_GetKeyNotFound(t *testing.T) {
	memFS := fs.NewMemFileSystem()
	km, err := NewDiskKeyManager(DiskKeyManagerConfig{
		KeyType:    KeyTypeECP256,
		KeysPath:   "/keys",
		FileSystem: memFS,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Try to get a key that doesn't exist
	handle, err := km.GetKeyHandle(ctx, "test-ns", "nonexistent")
	require.NoError(t, err) // Handle creation succeeds

	// Operations should fail
	_, _, err = handle.Metadata(ctx)
	assert.Error(t, err)
}

func TestDiskKeyManager_ConcurrentAccess(t *testing.T) {
	memFS := fs.NewMemFileSystem()
	km, err := NewDiskKeyManager(DiskKeyManagerConfig{
		KeyType:    KeyTypeECP256,
		KeysPath:   "/keys",
		FileSystem: memFS,
	})
	require.NoError(t, err)

	ctx := context.Background()
	ns := "test-ns"

	// Create initial keys
	h1, _ := km.GetKeyHandle(ctx, ns, "key-a")
	h1.Rotate(ctx)

	h2, _ := km.GetKeyHandle(ctx, ns, "key-b")
	h2.Rotate(ctx)

	// Concurrent reads
	const numReaders = 10
	var wg sync.WaitGroup
	wg.Add(numReaders)

	for i := 0; i < numReaders; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				keyName := "key-a"
				if j%2 == 0 {
					keyName = "key-b"
				}

				h, _ := km.GetKeyHandle(ctx, ns, keyName)
				_, _, err := h.Metadata(ctx)
				if err != nil {
					t.Errorf("Metadata failed: %v", err)
				}
			}
		}()
	}

	wg.Wait()
}

func TestDiskKeyManager_CorruptedJSON(t *testing.T) {
	memFS := fs.NewMemFileSystem()
	km, err := NewDiskKeyManager(DiskKeyManagerConfig{
		KeyType:    KeyTypeECP256,
		KeysPath:   "/keys",
		FileSystem: memFS,
	})
	require.NoError(t, err)

	// Manually write corrupted JSON to the filesystem
	memFS.MkdirAll("/keys/test-ns", 0700)
	corruptedJSON := []byte("{invalid json}")
	err = memFS.WriteFileAtomic("/keys/test-ns/key-a.json", corruptedJSON, 0600)
	require.NoError(t, err)

	ctx := context.Background()

	// Try to get the corrupted key
	handle, _ := km.GetKeyHandle(ctx, "test-ns", "key-a")
	_, _, err = handle.Metadata(ctx)
	assert.Error(t, err)
}

func TestDiskKeyManager_FileSystemPersistence(t *testing.T) {
	memFS := fs.NewMemFileSystem()

	// Create first key manager instance
	km1, err := NewDiskKeyManager(DiskKeyManagerConfig{
		KeyType:    KeyTypeECP256,
		KeysPath:   "/keys",
		FileSystem: memFS,
	})
	require.NoError(t, err)

	ctx := context.Background()
	ns := "test-ns"
	keyName := "key-a"

	// Create a key
	h1, _ := km1.GetKeyHandle(ctx, ns, keyName)
	err = h1.Rotate(ctx)
	require.NoError(t, err)

	id1, _, _ := h1.Metadata(ctx)

	// Create second key manager instance (simulating restart)
	km2, err := NewDiskKeyManager(DiskKeyManagerConfig{
		KeyType:    KeyTypeECP256,
		KeysPath:   "/keys",
		FileSystem: memFS,
	})
	require.NoError(t, err)

	// Retrieve the key with second instance
	h2, _ := km2.GetKeyHandle(ctx, ns, keyName)
	id2, _, err := h2.Metadata(ctx)
	require.NoError(t, err)

	assert.Equal(t, id1, id2)
}

func TestDiskKeyManager_AtomicWrite(t *testing.T) {
	memFS := fs.NewMemFileSystem()
	km, err := NewDiskKeyManager(DiskKeyManagerConfig{
		KeyType:    KeyTypeECP256,
		KeysPath:   "/keys",
		FileSystem: memFS,
	})
	require.NoError(t, err)

	ctx := context.Background()
	ns := "test-ns"
	keyName := "key-a"

	// Create a key
	h, _ := km.GetKeyHandle(ctx, ns, keyName)
	err = h.Rotate(ctx)
	require.NoError(t, err)

	// Verify the final file exists
	data, err := memFS.ReadFile("/keys/test-ns/key-a.json")
	require.NoError(t, err)

	// Verify it's valid JSON
	var keyData keyFileData
	err = json.Unmarshal(data, &keyData)
	require.NoError(t, err)
}

func TestDiskKeyManager_InvalidKeyType(t *testing.T) {
	memFS := fs.NewMemFileSystem()

	// Try to create a key manager with invalid type
	_, err := NewDiskKeyManager(DiskKeyManagerConfig{
		KeyType:    KeyType("invalid"),
		KeysPath:   "/keys",
		FileSystem: memFS,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}

func TestNewDiskKeyManager_EmptyKeysPath(t *testing.T) {
	memFS := fs.NewMemFileSystem()
	_, err := NewDiskKeyManager(DiskKeyManagerConfig{
		FileSystem: memFS,
	})
	assert.Error(t, err)
}

func TestNewDiskKeyManager_DefaultsToOSFileSystem(t *testing.T) {
	tempDir := t.TempDir()

	km, err := NewDiskKeyManager(DiskKeyManagerConfig{
		KeyType:  KeyTypeECP256,
		KeysPath: tempDir,
	})
	require.NoError(t, err)

	assert.NotNil(t, km.fs)
}

func TestDiskKeyManager_ExplicitAlgorithm(t *testing.T) {
	memFS := fs.NewMemFileSystem()

	// Configure EC-P256 but explicitly ask for "ES256" (default)
	km, err := NewDiskKeyManager(DiskKeyManagerConfig{
		KeyType:    KeyTypeECP256,
		Algorithm:  "ES256",
		KeysPath:   "/keys",
		FileSystem: memFS,
	})
	require.NoError(t, err)

	assert.Equal(t, "ES256", km.algorithm)

	// Configure RSA-2048 but explicitly ask for "RS512" (non-default)
	km2, err := NewDiskKeyManager(DiskKeyManagerConfig{
		KeyType:    KeyTypeRSA2048,
		Algorithm:  "RS512",
		KeysPath:   "/keys2",
		FileSystem: memFS,
	})
	require.NoError(t, err)

	assert.Equal(t, "RS512", km2.algorithm)

	// Create a key and verify it uses the configured algorithm
	ctx := context.Background()
	h, _ := km2.GetKeyHandle(ctx, "test", "key-a")
	err = h.Rotate(ctx)
	require.NoError(t, err)

	_, alg, err := h.Metadata(ctx)
	require.NoError(t, err)
	assert.Equal(t, "RS512", alg)
}
