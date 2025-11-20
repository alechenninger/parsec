package keymanager

import (
	"context"
	"crypto"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alechenninger/parsec/internal/clock"
)

const testTokenType = "urn:ietf:params:oauth:token-type:txn_token"

// Mock KeyProvider for failure injection
type failKeyProvider struct {
	*InMemoryKeyManager
	failCreate bool
}

func (m *failKeyProvider) GetKeyHandle(ctx context.Context, namespace string, keyName string) (KeyHandle, error) {
	handle, err := m.InMemoryKeyManager.GetKeyHandle(ctx, namespace, keyName)
	if err != nil {
		return nil, err
	}
	return &failKeyHandle{handle: handle, failCreate: m.failCreate}, nil
}

type failKeyHandle struct {
	handle     KeyHandle
	failCreate bool
}

func (h *failKeyHandle) Sign(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, string, error) {
	return h.handle.Sign(ctx, digest, opts)
}
func (h *failKeyHandle) Metadata(ctx context.Context) (string, string, error) {
	return h.handle.Metadata(ctx)
}
func (h *failKeyHandle) Public(ctx context.Context) (crypto.PublicKey, error) {
	return h.handle.Public(ctx)
}
func (h *failKeyHandle) Rotate(ctx context.Context) error {
	if h.failCreate {
		return assert.AnError
	}
	return h.handle.Rotate(ctx)
}

// Helper to create a test RotatingKeyManager with a fake clock and in memory storage
func newTestRotatingKeyManager(t *testing.T, clk clock.Clock, slotStore KeySlotStore, keyManager KeyProvider) (*RotatingKeyManager, KeyProvider) {
	if keyManager == nil {
		// Create an in-memory KeyProvider with EC-P256 key type
		keyManager = NewInMemoryKeyManager(KeyTypeECP256, "ES256")
	}

	// Create in-memory slot store if needed
	if slotStore == nil {
		slotStore = NewInMemoryKeySlotStore()
	}

	// Create key manager registry
	kmRegistry := map[string]KeyProvider{
		"test-km": keyManager,
	}

	// Create rotating key manager with short timings for testing
	rm := NewRotatingKeyManager(RotatingKeyManagerConfig{
		TokenType:          testTokenType, // Test token type
		KeyManagerID:       "test-km",
		KeyManagerRegistry: kmRegistry,
		SlotStore:          slotStore,
		Clock:              clk,
		// Short timings for faster tests
		KeyTTL:            30 * time.Minute, // Longer to avoid premature expiration
		RotationThreshold: 8 * time.Minute,  // Rotate when 8m remaining
		GracePeriod:       2 * time.Minute,
		CheckInterval:     10 * time.Second,
		PrepareTimeout:    1 * time.Minute,
	})

	return rm, keyManager
}

func TestRotatingKeyManager_RotationFailure_MaintainsOldKey(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	// Setup backing KM that we can make fail
	baseKM := NewInMemoryKeyManager(KeyTypeECP256, "ES256")
	mockKM := &failKeyProvider{InMemoryKeyManager: baseKM}

	rm, _ := newTestRotatingKeyManager(t, clk, nil, mockKM)

	ctx := context.Background()

	// 1. Start (succeeds)
	err := rm.Start(ctx)
	require.NoError(t, err)
	defer rm.Stop()

	// Get initial key ID
	clk.Advance(10 * time.Second)
	_, keyID1, _, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err)

	// 2. Advance to just before rotation threshold (22m)
	// KeyTTL=30m, Threshold=8m => Rotate at 22m
	clk.Advance(21 * time.Minute)

	// 3. Set mockKM to fail BEFORE rotation is attempted
	mockKM.failCreate = true

	// 4. Advance past rotation threshold (to 23m)
	clk.Advance(2 * time.Minute)

	// 5. Verify we still have the old key active (rotation failed)
	_, keyID2, _, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.Equal(t, keyID1, keyID2, "should maintain old key on rotation failure")

	// 6. Advance PAST expiration (KeyTTL = 30m, we are at ~23m + 10s)
	// Need to go past 30m total.
	clk.Advance(10 * time.Minute) // Now at ~33m

	// 7. Verify behavior - we expect it to keep using the cached key (graceful degradation)
	// even though it is expired in the store, the cache hasn't been updated because updateActiveKeyCache failed
	_, keyID3, _, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err, "should still have active key from cache even if expired")
	assert.Equal(t, keyID1, keyID3, "should maintain old key even after expiration if rotation fails")
}

func TestRotatingKeyManager_InitialKeyGeneration(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rm, _ := newTestRotatingKeyManager(t, clk, nil, nil)

	ctx := context.Background()

	// Start should generate initial key
	err := rm.Start(ctx)
	require.NoError(t, err)
	defer rm.Stop()

	signer, keyID, algorithm, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.NotEmpty(t, string(keyID))
	assert.Equal(t, "ES256", string(algorithm))
}

func TestRotatingKeyManager_InitialKeyRotationCompletedAtIsNow(t *testing.T) {
	// Use a specific time for the clock to make assertions clear
	startTime := time.Date(2025, 10, 27, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFixtureClock(startTime)
	rm, _ := newTestRotatingKeyManager(t, clk, nil, nil)

	ctx := context.Background()

	// Start should generate initial key
	err := rm.Start(ctx)
	require.NoError(t, err)
	defer rm.Stop()

	// Check that the initial key's RotationCompletedAt is set to the current clock time
	// (not backdated to circumvent grace period)
	slotStore := rm.slotStore
	slots, _, err := slotStore.ListSlots(ctx)
	require.NoError(t, err)
	require.Len(t, slots, 1, "should have 1 slot")

	var slotA *KeySlot
	for _, s := range slots {
		if s.Position == SlotPositionA {
			slotA = s
			break
		}
	}
	require.NotNil(t, slotA, "slot A should exist")
	require.NotNil(t, slotA.RotationCompletedAt, "initial key should have RotationCompletedAt set")

	assert.Equal(t, startTime, *slotA.RotationCompletedAt,
		"initial key RotationCompletedAt should equal clock time (not backdated)")
}

func TestRotatingKeyManager_InitialKeyInGracePeriod(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rm, _ := newTestRotatingKeyManager(t, clk, nil, nil)

	ctx := context.Background()

	// Start generates initial key (set in the past, immediately active)
	err := rm.Start(ctx)
	require.NoError(t, err)
	defer rm.Stop()

	// Trigger first rotation check
	clk.Advance(10 * time.Second)

	// Initial key should be immediately active (no grace period for first key)
	signer, _, _, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.NotNil(t, signer)
}

func TestRotatingKeyManager_PublicKeysIncludesGracePeriodKeys(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rm, _ := newTestRotatingKeyManager(t, clk, nil, nil)

	ctx := context.Background()

	err := rm.Start(ctx)
	require.NoError(t, err)
	defer rm.Stop()

	// Trigger first rotation check to populate cache
	clk.Advance(10 * time.Second)

	// Public keys should include the initial key
	publicKeys, err := rm.PublicKeys(ctx)
	require.NoError(t, err)
	assert.Len(t, publicKeys, 1, "should have 1 key")
	assert.Equal(t, "ES256", publicKeys[0].Algorithm)
	assert.Equal(t, "sig", publicKeys[0].Use)
}

func TestRotatingKeyManager_KeyRotation(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rm, _ := newTestRotatingKeyManager(t, clk, nil, nil)

	ctx := context.Background()

	err := rm.Start(ctx)
	require.NoError(t, err)
	defer rm.Stop()

	// Wait for initial key to be active
	clk.Advance(10 * time.Second) // Trigger first check

	// signer1 is wrapper
	_, keyID1, _, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err)

	// Advance time to trigger rotation (past rotation threshold)
	// KeyTTL=30m, RotationThreshold=8m, so rotation at 22m
	clk.Advance(23 * time.Minute)

	// Should have generated a new key
	publicKeys, err := rm.PublicKeys(ctx)
	require.NoError(t, err)
	assert.Len(t, publicKeys, 2, "should have 2 keys after rotation")

	// Active key should still be the old one (new key in grace period of 2m)
	_, keyID2, _, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.Equal(t, string(keyID1), string(keyID2), "active key should not change during grace period")

	// After new key's grace period, should switch to new key
	clk.Advance(3 * time.Minute) // Past 2m grace period

	_, keyID3, _, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, string(keyID1), string(keyID3), "active key should change after grace period")
}

func TestRotatingKeyManager_KeyExpiration(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rm, _ := newTestRotatingKeyManager(t, clk, nil, nil)

	ctx := context.Background()

	err := rm.Start(ctx)
	require.NoError(t, err)
	defer rm.Stop()

	// Initial key is active
	clk.Advance(10 * time.Second)

	publicKeys1, err := rm.PublicKeys(ctx)
	require.NoError(t, err)
	assert.Len(t, publicKeys1, 1)

	// Trigger rotation at 22m (30m TTL - 8m threshold)
	clk.Advance(23 * time.Minute)

	publicKeys2, err := rm.PublicKeys(ctx)
	require.NoError(t, err)
	assert.Len(t, publicKeys2, 2, "should have 2 keys after rotation")

	// Advance past first key's expiration (30 minutes from initial creation)
	clk.Advance(8 * time.Minute) // ~31m total, first key expires at 30m

	publicKeys3, err := rm.PublicKeys(ctx)
	require.NoError(t, err)
	assert.Len(t, publicKeys3, 1, "expired key should be removed from public keys")

	// Should only have the newer key (the rotated one)
	// KeyID is now a JWK Thumbprint (base64url encoded)
	assert.NotEmpty(t, publicKeys3[0].KeyID, "should have a valid key ID")
	// Verify it's different from the first key (rotation happened)
	assert.NotEqual(t, publicKeys1[0].KeyID, publicKeys3[0].KeyID, "should have rotated to a new key")
}

func TestRotatingKeyManager_AlternatingSlots(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rm, _ := newTestRotatingKeyManager(t, clk, nil, nil)

	ctx := context.Background()

	err := rm.Start(ctx)
	require.NoError(t, err)
	defer rm.Stop()

	// Get initial key
	clk.Advance(10 * time.Second)

	_, keyID1, _, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, string(keyID1), "first key should have an ID")

	// Rotate to second slot at 22m, active at 24m
	clk.Advance(23 * time.Minute) // Trigger rotation at 22m
	clk.Advance(3 * time.Minute)  // Past 2m grace period

	_, keyID2, _, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, string(keyID2), "second key should have an ID")
	assert.NotEqual(t, keyID1, keyID2, "second key should be different from first")

	// Rotate back to first slot (another 22m, active at 24m from second key creation)
	clk.Advance(23 * time.Minute) // Trigger rotation
	clk.Advance(3 * time.Minute)  // Past grace period

	_, keyID3, _, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, string(keyID3), "third key should have an ID")
	assert.NotEqual(t, keyID2, keyID3, "third key should be different from second")
	assert.NotEqual(t, keyID1, keyID3, "third key should be different from first (new key in same slot)")
}

func TestRotatingKeyManager_SigningWorks(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rm, _ := newTestRotatingKeyManager(t, clk, nil, nil)

	ctx := context.Background()

	err := rm.Start(ctx)
	require.NoError(t, err)
	defer rm.Stop()

	// Wait for key to be active
	clk.Advance(10 * time.Second)

	signer, keyID, algorithm, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err)

	// Sign some data (must hash first for ECDSA)
	data := []byte("test message")
	hash := crypto.SHA256.New()
	hash.Write(data)
	hashed := hash.Sum(nil)

	signature, err := signer.Sign(nil, hashed, crypto.SHA256)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)

	// Verify we get the right metadata
	assert.NotEmpty(t, string(keyID))
	assert.Equal(t, "ES256", string(algorithm))

	// Public key should be available for verification
	publicKeys, err := rm.PublicKeys(ctx)
	require.NoError(t, err)
	require.Len(t, publicKeys, 1)

	assert.Equal(t, string(keyID), publicKeys[0].KeyID)
	assert.Equal(t, signer.Public(), publicKeys[0].Key)
}

func TestRotatingKeyManager_MultipleRotations(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rm, _ := newTestRotatingKeyManager(t, clk, nil, nil)

	ctx := context.Background()

	err := rm.Start(ctx)
	require.NoError(t, err)
	defer rm.Stop()

	// Track key IDs through multiple rotations
	var keyIDs []string

	// Initial key
	clk.Advance(10 * time.Second)

	_, keyID, _, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err)
	keyIDs = append(keyIDs, string(keyID))

	// Perform 3 rotations
	for i := 0; i < 3; i++ {
		// Trigger rotation at threshold
		clk.Advance(23 * time.Minute)

		// Wait for grace period
		clk.Advance(3 * time.Minute)

		_, keyID, _, err := rm.GetCurrentSigner(ctx)
		require.NoError(t, err)
		keyIDs = append(keyIDs, string(keyID))
	}

	// Should have 4 key IDs
	assert.Len(t, keyIDs, 4)

	// Verify they are all unique (each is a JWK Thumbprint)
	uniqueKeys := make(map[string]bool)
	for _, kid := range keyIDs {
		assert.NotEmpty(t, kid, "key ID should not be empty")
		assert.False(t, uniqueKeys[kid], "key ID %s should be unique", kid)
		uniqueKeys[kid] = true
	}
	assert.Len(t, uniqueKeys, 4, "all key IDs should be unique")
}

func TestRotatingKeyManager_SlotStoreOptimisticLocking(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rm, _ := newTestRotatingKeyManager(t, clk, nil, nil)

	ctx := context.Background()

	err := rm.Start(ctx)
	require.NoError(t, err)
	defer rm.Stop()

	// Wait for initial key in slot A
	clk.Advance(10 * time.Second)

	// Get the slot store
	slotStore := rm.slotStore

	// Get initial state and version
	slots, version1, err := slotStore.ListSlots(ctx)
	require.NoError(t, err)
	require.Len(t, slots, 1, "should have 1 slot")
	require.NotEqual(t, "", version1, "version should not be empty")

	// Find slotA
	var slotA *KeySlot
	for _, s := range slots {
		if s.Position == SlotPositionA {
			slotA = s
			break
		}
	}
	require.NotNil(t, slotA, "should find slot-a")

	// Test optimistic locking: Save with correct version should succeed
	slotA.KeyManagerID = "test-km-2" // Modify something
	version2, err := slotStore.SaveSlot(ctx, slotA, version1)
	require.NoError(t, err, "should succeed with correct version")
	assert.NotEqual(t, version1, version2, "version should change after save")

	// Try to save with old version - should fail
	slotA.KeyManagerID = "test-km-3"
	_, err = slotStore.SaveSlot(ctx, slotA, version1) // Old version
	assert.ErrorIs(t, err, ErrVersionMismatch, "should fail with old version")

	// Save with correct (current) version should succeed
	version3, err := slotStore.SaveSlot(ctx, slotA, version2)
	require.NoError(t, err, "should succeed with current version")
	assert.NotEqual(t, version2, version3, "version should change after second save")
}

func TestRotatingKeyManager_CachedPublicKeys(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})
	rm, kmProvider := newTestRotatingKeyManager(t, clk, nil, nil)

	ctx := context.Background()

	err := rm.Start(ctx)
	require.NoError(t, err)
	defer rm.Stop()

	// Wait for initial key
	clk.Advance(10 * time.Second)

	// Get public keys (should be from cache)
	publicKeys1, err := rm.PublicKeys(ctx)
	require.NoError(t, err)
	assert.Len(t, publicKeys1, 1)

	// Verify the public key matches what's in the KeyManager
	handle, err := kmProvider.GetKeyHandle(ctx, testTokenType, "key-a")
	require.NoError(t, err)

	pubKey, err := handle.Public(ctx)
	require.NoError(t, err)

	assert.Equal(t, pubKey, publicKeys1[0].Key)

	// Call PublicKeys again - should return cached data (same pointer)
	publicKeys2, err := rm.PublicKeys(ctx)
	require.NoError(t, err)

	// Should be equivalent but not the same slice (we make a copy)
	assert.Equal(t, publicKeys1, publicKeys2)
}

func TestRotatingKeyManager_NoKeysBeforeStart(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rm, _ := newTestRotatingKeyManager(t, clk, nil, nil)

	ctx := context.Background()

	// Before Start, GetCurrentSigner should fail
	_, _, _, err := rm.GetCurrentSigner(ctx)
	assert.Error(t, err)

	// PublicKeys should return empty
	publicKeys, err := rm.PublicKeys(ctx)
	require.NoError(t, err)
	assert.Empty(t, publicKeys)
}

func TestRotatingKeyManager_StopPreventsRotation(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rm, _ := newTestRotatingKeyManager(t, clk, nil, nil)

	ctx := context.Background()

	err := rm.Start(ctx)
	require.NoError(t, err)

	// Wait for initial key
	clk.Advance(10 * time.Second)

	_, keyID1, _, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err)

	// Stop the manager
	rm.Stop()

	// Advance time past rotation threshold
	clk.Advance(25 * time.Minute)

	// Key should not have rotated (manager stopped)
	// GetCurrentSigner should still return the cached key
	_, keyID2, _, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.Equal(t, string(keyID1), string(keyID2))
}

func TestRotatingKeyManager_AlgorithmIsCorrect(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rm, _ := newTestRotatingKeyManager(t, clk, nil, nil)

	ctx := context.Background()

	err := rm.Start(ctx)
	require.NoError(t, err)
	defer rm.Stop()

	// Wait for initial key
	clk.Advance(10 * time.Second)

	_, _, algorithm, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.Equal(t, "ES256", string(algorithm))

	// Public keys should also have the algorithm
	publicKeys, err := rm.PublicKeys(ctx)
	require.NoError(t, err)
	require.Len(t, publicKeys, 1)
	assert.Equal(t, "ES256", publicKeys[0].Algorithm)
}

func TestRotatingKeyManager_ExistingKeyInGracePeriod(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})
	slotStore := NewInMemoryKeySlotStore()
	rm, km := newTestRotatingKeyManager(t, clk, slotStore, nil)

	ctx := context.Background()

	startTime := clk.Now()

	err := rm.Start(ctx)
	require.NoError(t, err)
	defer rm.Stop()

	clk.Advance(10 * time.Second)

	// Now create a new manager, reusing same slot store
	rm2, _ := newTestRotatingKeyManager(t, clk, slotStore, km)

	err = rm2.Start(ctx)
	require.NoError(t, err)
	defer rm2.Stop()

	slots, _, err := slotStore.ListSlots(ctx)
	require.NoError(t, err)
	require.Len(t, slots, 1)
	assert.Equal(t, startTime, *slots[0].RotationCompletedAt)
}

func TestRotatingKeyManager_Namespacing(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})
	km := NewInMemoryKeyManager(KeyTypeECP256, "ES256")
	kmRegistry := map[string]KeyProvider{"test-km": km}
	slotStore := NewInMemoryKeySlotStore()

	trustDomain := "example.com"

	rm := NewRotatingKeyManager(RotatingKeyManagerConfig{
		TokenType:          testTokenType,
		TrustDomain:        trustDomain,
		KeyManagerID:       "test-km",
		KeyManagerRegistry: kmRegistry,
		SlotStore:          slotStore,
		Clock:              clk,
		PrepareTimeout:     1 * time.Minute,
	})

	ctx := context.Background()
	err := rm.Start(ctx)
	require.NoError(t, err)
	defer rm.Stop()

	// Check that key was created with correct namespace
	// InMemoryKeyManager uses "namespace:keyName" as storage key
	// So we should be able to retrieve it using the composite namespace
	compositeNamespace := trustDomain + ":" + testTokenType

	handle, err := km.GetKeyHandle(ctx, compositeNamespace, "key-a")
	require.NoError(t, err)

	_, _, err = handle.Metadata(ctx)
	require.NoError(t, err)

	// Verify we cannot get it with just token type (GetKeyHandle succeeds but Metadata fails)
	handleBad, err := km.GetKeyHandle(ctx, testTokenType, "key-a")
	require.NoError(t, err)

	_, _, err = handleBad.Metadata(ctx)
	assert.Error(t, err)
}
