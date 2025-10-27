package keymanager

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/alechenninger/parsec/internal/clock"
	"github.com/alechenninger/parsec/internal/service"
	spirekm "github.com/spiffe/spire/pkg/server/plugin/keymanager"
)

const (
	// KeyIDA and KeyIDB are the alternating key identifiers
	KeyIDA = "key-a"
	KeyIDB = "key-b"

	// Default timing parameters (hardcoded for now, configurable later)
	defaultKeyTTL            = 24 * time.Hour
	defaultRotationThreshold = 6 * time.Hour   // Rotate when 6h remaining
	defaultGracePeriod       = 2 * time.Hour   // Don't use new key for 2h after generation
	defaultCheckInterval     = 1 * time.Minute // How often to check for rotation
)

// KeyID is a unique identifier for a cryptographic key
type KeyID string

// Algorithm is a cryptographic algorithm identifier (e.g., "ES256", "RS256")
type Algorithm string

// RotatingKeyManager manages automatic key rotation using Spire's KeyManager
type RotatingKeyManager struct {
	keyManager spirekm.KeyManager
	stateStore KeySlotStateStore
	keyType    spirekm.KeyType
	algorithm  string // Default JWT algorithm for new keys (e.g., "RS256", "ES256")

	// Timing parameters:
	//
	// key            TTL -                 rotation time +
	// generated      rotation threshold    grace period       TTL
	// ^--------------^---------------------^------------------^-------->
	//                new key generated     new key used       previous key removed

	// How long a key is available before it is no longer valid and must not be trusted.
	keyTTL time.Duration
	// How long within the key TTL that we consider the key to be eligible for rotation
	rotationThreshold time.Duration
	// How long after a key is generated that it is not eligible for use.
	// This should be some time less than rotation threshold,
	// so that we do not mint any tokens with the old key immediately before it expires.
	// However, it should not be too small,
	// to ensure clients have enough time to download the new key before it is used.
	gracePeriod time.Duration
	// How often to check for rotation and if key state has changed from another process.
	checkInterval time.Duration

	// Cached data (updated during rotation checks, read on hot path)
	mu              sync.RWMutex
	activeKey       spirekm.Key
	activeAlgorithm string
	publicKeys      []service.PublicKey // All non-expired public keys

	clock  clock.Clock
	ticker clock.Ticker
}

// RotatingKeyManagerConfig configures the RotatingKeyManager
type RotatingKeyManagerConfig struct {
	KeyManager spirekm.KeyManager
	StateStore KeySlotStateStore
	KeyType    spirekm.KeyType
	Algorithm  string // JWT algorithm (e.g., "ES256", "RS256", "RS384", "RS512")
	Clock      clock.Clock

	// Optional timing overrides (uses defaults if not set)
	KeyTTL            time.Duration
	RotationThreshold time.Duration
	GracePeriod       time.Duration
	CheckInterval     time.Duration
}

// NewRotatingKeyManager creates a new rotating key manager
func NewRotatingKeyManager(cfg RotatingKeyManagerConfig) *RotatingKeyManager {
	clk := cfg.Clock
	if clk == nil {
		clk = clock.NewSystemClock()
	}

	keyTTL := cfg.KeyTTL
	if keyTTL == 0 {
		keyTTL = defaultKeyTTL
	}

	rotationThreshold := cfg.RotationThreshold
	if rotationThreshold == 0 {
		rotationThreshold = defaultRotationThreshold
	}

	gracePeriod := cfg.GracePeriod
	if gracePeriod == 0 {
		gracePeriod = defaultGracePeriod
	}

	checkInterval := cfg.CheckInterval
	if checkInterval == 0 {
		checkInterval = defaultCheckInterval
	}

	return &RotatingKeyManager{
		keyManager:        cfg.KeyManager,
		stateStore:        cfg.StateStore,
		keyType:           cfg.KeyType,
		algorithm:         cfg.Algorithm,
		keyTTL:            keyTTL,
		rotationThreshold: rotationThreshold,
		gracePeriod:       gracePeriod,
		checkInterval:     checkInterval,
		clock:             clk,
	}
}

// Start begins the background key rotation process
func (r *RotatingKeyManager) Start(ctx context.Context) error {
	// Ensure we have at least one key
	if err := r.ensureInitialKey(ctx); err != nil {
		return fmt.Errorf("failed to ensure initial key: %w", err)
	}

	// Initialize active key cache
	if err := r.updateActiveKeyCache(ctx); err != nil {
		return fmt.Errorf("failed to initialize active key cache: %w", err)
	}

	// Start background rotation ticker
	r.ticker = r.clock.Ticker(r.checkInterval)
	if err := r.ticker.Start(r.doRotationCheck); err != nil {
		return fmt.Errorf("failed to start rotation ticker: %w", err)
	}

	return nil
}

// Stop gracefully stops the background rotation process
func (r *RotatingKeyManager) Stop() {
	if r.ticker != nil {
		r.ticker.Stop()
	}
}

// doRotationCheck is called periodically by the ticker to check for rotation needs
func (r *RotatingKeyManager) doRotationCheck(ctx context.Context) {
	if err := r.checkAndRotate(ctx); err != nil {
		log.Printf("Error during key rotation check: %v", err)
	}
	// Update active key cache after each check (whether rotation happened or not)
	if err := r.updateActiveKeyCache(ctx); err != nil {
		log.Printf("Error updating active key cache: %v", err)
	}
}

// GetCurrentSigner returns a crypto.Signer for the current active key along with its key ID and algorithm
func (r *RotatingKeyManager) GetCurrentSigner(ctx context.Context) (crypto.Signer, KeyID, Algorithm, error) {
	// Get the current active key and algorithm from cache (no KeyManager call on hot path)
	r.mu.RLock()
	key := r.activeKey
	algorithm := r.activeAlgorithm
	r.mu.RUnlock()

	if key == nil {
		return nil, "", "", fmt.Errorf("no active key available")
	}

	return key, KeyID(key.ID()), Algorithm(algorithm), nil
}

// PublicKeys returns all non-expired public keys from cache
func (r *RotatingKeyManager) PublicKeys(ctx context.Context) ([]service.PublicKey, error) {
	// Return cached public keys (no state store or KeyManager calls on hot path)
	r.mu.RLock()
	keys := make([]service.PublicKey, len(r.publicKeys))
	copy(keys, r.publicKeys)
	r.mu.RUnlock()

	return keys, nil
}

// ensureInitialKey ensures at least one key exists, generating key-a if needed
func (r *RotatingKeyManager) ensureInitialKey(ctx context.Context) error {
	slots, err := r.stateStore.ListSlotStates(ctx)
	if err != nil {
		return fmt.Errorf("failed to list slot states: %w", err)
	}

	// If we have any slots, we're good
	if len(slots) > 0 {
		return nil
	}

	// Initialize slot A
	now := r.clock.Now()

	// Create slot A with initial key
	keyID := r.generateKeyID(KeyIDA)
	_, err = r.keyManager.GenerateKey(ctx, keyID, r.keyType)
	if err != nil {
		return fmt.Errorf("failed to generate initial key: %w", err)
	}

	// Set RotationCompletedAt in the past (past grace period) so the initial key is immediately active
	// There's no need for a grace period on the initial key since there's no previous key to transition from
	rotationCompletedAt := now.Add(-r.gracePeriod - 1*time.Second)

	slotA := &KeySlotState{
		SlotID:              KeyIDA,
		CurrentKeyID:        &keyID,
		RotationCompletedAt: &rotationCompletedAt,
		Algorithm:           r.algorithm,
		Version:             0,
	}
	if err := r.stateStore.SaveSlotState(ctx, slotA, -1); err != nil {
		return fmt.Errorf("failed to save slot A state: %w", err)
	}

	return nil
}

// generateKeyID generates a unique key ID for a slot
func (r *RotatingKeyManager) generateKeyID(slotID string) string {
	return fmt.Sprintf("%s-%s", slotID, uuid.New().String())
}

// checkAndRotate checks if rotation is needed and performs it
func (r *RotatingKeyManager) checkAndRotate(ctx context.Context) error {
	// 1. Read slot states
	slotA, errA := r.stateStore.GetSlotState(ctx, KeyIDA)
	if errA != nil && !errors.Is(errA, ErrSlotStateNotFound) {
		return fmt.Errorf("failed to get slot A state: %w", errA)
	}

	slotB, errB := r.stateStore.GetSlotState(ctx, KeyIDB)
	if errB != nil && !errors.Is(errB, ErrSlotStateNotFound) {
		return fmt.Errorf("failed to get slot B state: %w", errB)
	}

	// 2. Determine which slot needs rotation and which slot to rotate TO
	sourceSlot, targetSlot := r.selectSlotsForRotation(slotA, slotB)
	if sourceSlot == nil || targetSlot == nil {
		return nil // No rotation needed
	}

	// 3. Check if target slot already has a fresh (non-expired) key
	if targetSlot.CurrentKeyID != nil && targetSlot.RotationCompletedAt != nil {
		now := r.clock.Now()
		expiresAt := targetSlot.RotationCompletedAt.Add(r.keyTTL)
		if now.Before(expiresAt) {
			// Target slot has a non-expired key, rotation already happened
			return nil
		}
	}

	// 4. Generate key with unique ID in the target slot
	uniqueKeyID := r.generateKeyID(targetSlot.SlotID)
	_, err := r.keyManager.GenerateKey(ctx, uniqueKeyID, r.keyType)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// 5. Try to bind this key to the target slot
	err = r.bindKeyToSlot(ctx, targetSlot, uniqueKeyID, r.algorithm)
	if errors.Is(err, ErrVersionMismatch) {
		// Another process won the race, that's ok
		log.Printf("Another process bound a key to slot %s, skipping", targetSlot.SlotID)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to bind key to slot: %w", err)
	}

	log.Printf("Bound new key %s to slot %s", uniqueKeyID, targetSlot.SlotID)

	return nil
}

// bindKeyToSlot binds a generated key to a slot
func (r *RotatingKeyManager) bindKeyToSlot(ctx context.Context, slot *KeySlotState, keyID string, algorithm string) error {
	now := r.clock.Now()
	newSlot := &KeySlotState{
		SlotID:              slot.SlotID,
		CurrentKeyID:        &keyID,
		PreviousKeyID:       slot.CurrentKeyID, // Keep reference to previous key
		RotationCompletedAt: &now,              // Mark when bound for grace period
		Algorithm:           algorithm,         // Use provided algorithm for the slot
		Version:             slot.Version,
	}
	return r.stateStore.SaveSlotState(ctx, newSlot, slot.Version)
}

// selectSlotsForRotation determines which slot needs rotation and which slot to rotate to
// Returns (sourceSlot, targetSlot) where sourceSlot has the key that needs rotation
// and targetSlot is where the new key should be placed
func (r *RotatingKeyManager) selectSlotsForRotation(slotA, slotB *KeySlotState) (*KeySlotState, *KeySlotState) {
	now := r.clock.Now()

	// Helper to check if slot needs rotation
	needsRotation := func(slot *KeySlotState) bool {
		if slot == nil {
			return false
		}

		// If CurrentKeyID is nil, slot doesn't have a key
		if slot.CurrentKeyID == nil {
			return false
		}

		// Check if key is expired - expired keys don't need rotation
		if slot.RotationCompletedAt != nil {
			expiresAt := slot.RotationCompletedAt.Add(r.keyTTL)
			if !now.Before(expiresAt) {
				// Key is expired or expiring now, don't rotate it
				return false
			}

			// Check if key is approaching expiration (within rotation threshold)
			rotateAt := expiresAt.Add(-r.rotationThreshold)
			return !now.Before(rotateAt) // >= rotateAt
		}

		return false
	}

	// Check slot A - if it needs rotation, rotate to slot B
	if needsRotation(slotA) {
		// Initialize slot B state if it doesn't exist
		if slotB == nil {
			slotB = &KeySlotState{
				SlotID:  KeyIDB,
				Version: -1, // Will create new
			}
		}
		return slotA, slotB
	}

	// Check slot B - if it needs rotation, rotate to slot A
	if needsRotation(slotB) {
		// Initialize slot A state if it doesn't exist (shouldn't happen but be safe)
		if slotA == nil {
			slotA = &KeySlotState{
				SlotID:  KeyIDA,
				Version: -1,
			}
		}
		return slotB, slotA
	}

	return nil, nil
}

// updateActiveKeyCache queries the state store and updates the cached active key and public keys
// This is called during initialization and periodic rotation checks
func (r *RotatingKeyManager) updateActiveKeyCache(ctx context.Context) error {
	slots, err := r.stateStore.ListSlotStates(ctx)
	if err != nil {
		return fmt.Errorf("failed to list slot states: %w", err)
	}

	if len(slots) == 0 {
		return errors.New("no slots available")
	}

	now := r.clock.Now()
	var activeSlot *KeySlotState
	var publicKeys []service.PublicKey

	// Build list of all non-expired keys and find active key
	for _, slot := range slots {
		// Skip slots without a current key (rotating)
		if slot.CurrentKeyID == nil {
			continue
		}

		// Check if key is expired
		isExpired := false
		if slot.RotationCompletedAt != nil {
			expiresAt := slot.RotationCompletedAt.Add(r.keyTTL)
			if !now.Before(expiresAt) {
				isExpired = true
			}
		}

		if isExpired {
			continue // Skip expired keys
		}

		// Retrieve the key from KeyManager for public keys list
		key, err := r.keyManager.GetKey(ctx, *slot.CurrentKeyID)
		if err != nil {
			log.Printf("Warning: failed to get key %s from key manager: %v", *slot.CurrentKeyID, err)
			continue
		}

		// Add to public keys list (includes keys in grace period)
		publicKeys = append(publicKeys, service.PublicKey{
			KeyID:     *slot.CurrentKeyID,
			Algorithm: slot.Algorithm,
			Key:       key.Public(),
			Use:       "sig",
		})

		// Check if this key is past grace period and can be active
		pastGracePeriod := true
		if slot.RotationCompletedAt != nil {
			gracePeriodEnd := slot.RotationCompletedAt.Add(r.gracePeriod)
			if now.Before(gracePeriodEnd) {
				pastGracePeriod = false
			}
		}

		if !pastGracePeriod {
			continue // Still in grace period, not eligible as active key
		}

		// Select the most recently completed rotation as active
		if activeSlot == nil ||
			(slot.RotationCompletedAt != nil && activeSlot.RotationCompletedAt != nil &&
				slot.RotationCompletedAt.After(*activeSlot.RotationCompletedAt)) {
			activeSlot = slot
		}
	}

	if activeSlot == nil || activeSlot.CurrentKeyID == nil {
		return errors.New("no active key available (all keys expired or in grace period)")
	}

	// Get the active key (might already be in our list, but we need the Key object)
	activeKey, err := r.keyManager.GetKey(ctx, *activeSlot.CurrentKeyID)
	if err != nil {
		return fmt.Errorf("failed to get active key %s from key manager: %w", *activeSlot.CurrentKeyID, err)
	}

	// Update all cached data atomically
	r.mu.Lock()
	r.activeKey = activeKey
	r.activeAlgorithm = activeSlot.Algorithm
	r.publicKeys = publicKeys
	r.mu.Unlock()

	return nil
}
