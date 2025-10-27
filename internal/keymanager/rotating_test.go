package keymanager

import (
	"context"
	"crypto"
	"io"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alechenninger/parsec/internal/clock"
	spirekm "github.com/spiffe/spire/pkg/server/plugin/keymanager"
)

// testLogger creates a logger for tests that discards output
func testLogger() logrus.FieldLogger {
	log := logrus.New()
	log.SetOutput(io.Discard)
	return log
}

// Helper to create a test RotatingKeyManager with a fake clock and in memory storage
func newTestRotatingKeyManager(t *testing.T, clk clock.Clock, stateStore KeySlotStateStore, keyManager spirekm.KeyManager) (*RotatingKeyManager, spirekm.KeyManager) {
	if keyManager == nil {
		// Load an in-memory Spire KeyManager via catalog
		ctx := context.Background()
		pluginHCL := `KeyManager "memory" {
		plugin_data {}
	}`

		log := testLogger()
		spireKM, closer, err := LoadKeyManagerFromHCL(ctx, pluginHCL, log)
		require.NoError(t, err)
		require.NotNil(t, spireKM)
		t.Cleanup(func() {
			if closer != nil {
				closer.Close()
			}
		})
		keyManager = spireKM
	}

	// Create in-memory state store if needed
	if stateStore == nil {
		stateStore = NewInMemoryKeySlotStateStore()
	}

	// Create rotating key manager with short timings for testing
	rm := NewRotatingKeyManager(RotatingKeyManagerConfig{
		KeyManager: keyManager,
		StateStore: stateStore,
		KeyType:    spirekm.ECP256,
		Algorithm:  "ES256",
		Clock:      clk,
		// Short timings for faster tests
		KeyTTL:            30 * time.Minute, // Longer to avoid premature expiration
		RotationThreshold: 8 * time.Minute,  // Rotate when 8m remaining
		GracePeriod:       2 * time.Minute,
		CheckInterval:     10 * time.Second,
	})

	return rm, keyManager
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
	assert.Equal(t, Algorithm("ES256"), algorithm)
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
	stateStore := rm.stateStore
	slotA, err := stateStore.GetSlotState(ctx, KeyIDA)
	require.NoError(t, err)
	require.NotNil(t, slotA)
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

	signer1, keyID1, _, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err)

	// Advance time to trigger rotation (past rotation threshold)
	// KeyTTL=30m, RotationThreshold=8m, so rotation at 22m
	clk.Advance(23 * time.Minute)

	// Should have generated a new key
	publicKeys, err := rm.PublicKeys(ctx)
	require.NoError(t, err)
	assert.Len(t, publicKeys, 2, "should have 2 keys after rotation")

	// Active key should still be the old one (new key in grace period of 2m)
	signer2, keyID2, _, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.Equal(t, string(keyID1), string(keyID2), "active key should not change during grace period")
	assert.Equal(t, signer1, signer2)

	// After new key's grace period, should switch to new key
	clk.Advance(3 * time.Minute) // Past 2m grace period

	signer3, keyID3, _, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, string(keyID1), string(keyID3), "active key should change after grace period")
	assert.NotEqual(t, signer1, signer3)
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

	// Should only have the newer key
	assert.Contains(t, publicKeys3[0].KeyID, "key-b", "should have rotated to key-b slot")
}

func TestRotatingKeyManager_AlternatingSlots(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rm, _ := newTestRotatingKeyManager(t, clk, nil, nil)

	ctx := context.Background()

	err := rm.Start(ctx)
	require.NoError(t, err)
	defer rm.Stop()

	// Get initial key (should be in key-a slot)
	clk.Advance(10 * time.Second)

	_, keyID1, _, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.Contains(t, string(keyID1), "key-a", "first key should be in key-a slot")

	// Rotate to key-b at 22m, active at 24m
	clk.Advance(23 * time.Minute) // Trigger rotation at 22m
	clk.Advance(3 * time.Minute)  // Past 2m grace period

	_, keyID2, _, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.Contains(t, string(keyID2), "key-b", "second key should be in key-b slot")

	// Rotate back to key-a (another 22m, active at 24m from key-b creation)
	clk.Advance(23 * time.Minute) // Trigger rotation
	clk.Advance(3 * time.Minute)  // Past grace period

	_, keyID3, _, err := rm.GetCurrentSigner(ctx)
	require.NoError(t, err)
	assert.Contains(t, string(keyID3), "key-a", "third key should be back in key-a slot")
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

	// Sign some data
	data := []byte("test message")
	signature, err := signer.Sign(nil, data, crypto.SHA256)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)

	// Verify we get the right metadata
	assert.NotEmpty(t, string(keyID))
	assert.Equal(t, Algorithm("ES256"), algorithm)

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

	// Should have 4 unique key IDs
	assert.Len(t, keyIDs, 4)

	// Each should be unique
	seen := make(map[string]bool)
	for _, id := range keyIDs {
		assert.False(t, seen[id], "key IDs should be unique")
		seen[id] = true
	}

	// Should alternate between key-a and key-b slots
	assert.Contains(t, keyIDs[0], "key-a")
	assert.Contains(t, keyIDs[1], "key-b")
	assert.Contains(t, keyIDs[2], "key-a")
	assert.Contains(t, keyIDs[3], "key-b")
}

func TestRotatingKeyManager_StateStoreOptimisticLocking(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})

	rm, _ := newTestRotatingKeyManager(t, clk, nil, nil)

	ctx := context.Background()

	err := rm.Start(ctx)
	require.NoError(t, err)
	defer rm.Stop()

	// Wait for initial key in slot A
	clk.Advance(10 * time.Second)

	// Get the state store
	stateStore := rm.stateStore

	// Trigger a rotation (creates key in slot B)
	clk.Advance(23 * time.Minute)

	// Verify slotB was created with version 0
	slotB, err := stateStore.GetSlotState(ctx, KeyIDB)
	require.NoError(t, err)
	require.NotNil(t, slotB)
	assert.Equal(t, int64(0), slotB.Version, "new slot should start at version 0")

	// Test optimistic locking: try to update with wrong version
	slotB.Algorithm = "RS512"                       // Modify something
	err = stateStore.SaveSlotState(ctx, slotB, 999) // Wrong version
	assert.ErrorIs(t, err, ErrVersionMismatch, "should fail with wrong version")

	// Update with correct version should succeed
	err = stateStore.SaveSlotState(ctx, slotB, slotB.Version)
	require.NoError(t, err, "should succeed with correct version")

	// Verify version incremented
	slotB2, err := stateStore.GetSlotState(ctx, KeyIDB)
	require.NoError(t, err)
	assert.Greater(t, slotB2.Version, slotB.Version, "version should increment after update")
}

func TestRotatingKeyManager_CachedPublicKeys(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})
	rm, spireKM := newTestRotatingKeyManager(t, clk, nil, nil)

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
	keyID := publicKeys1[0].KeyID
	key, err := spireKM.GetKey(ctx, keyID)
	require.NoError(t, err)

	assert.Equal(t, key.Public(), publicKeys1[0].Key)

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

func TestRotatingKeyManager_AlgorithmFromSlotState(t *testing.T) {
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
	assert.Equal(t, Algorithm("ES256"), algorithm)

	// Public keys should also have the algorithm
	publicKeys, err := rm.PublicKeys(ctx)
	require.NoError(t, err)
	require.Len(t, publicKeys, 1)
	assert.Equal(t, "ES256", publicKeys[0].Algorithm)
}

func TestRotatingKeyManager_ExistingKeyInGracePeriod(t *testing.T) {
	clk := clock.NewFixtureClock(time.Time{})
	stateStore := NewInMemoryKeySlotStateStore()
	rm, km := newTestRotatingKeyManager(t, clk, stateStore, nil)

	ctx := context.Background()

	startTime := clk.Now()

	err := rm.Start(ctx)
	require.NoError(t, err)
	defer rm.Stop()

	clk.Advance(10 * time.Second)

	// Now create a new store, reusing same key state
	rm2, _ := newTestRotatingKeyManager(t, clk, stateStore, km)

	err = rm2.Start(ctx)
	require.NoError(t, err)
	defer rm2.Stop()

	states, err := stateStore.ListSlotStates(ctx)
	require.NoError(t, err)
	require.Len(t, states, 1)
	assert.Equal(t, startTime, *states[0].RotationCompletedAt)
}
