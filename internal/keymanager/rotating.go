package keymanager

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/alechenninger/parsec/internal/clock"
	"github.com/alechenninger/parsec/internal/service"
)

const (
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

// RotatingKeyManager manages automatic key rotation using a KeyManager
type RotatingKeyManager struct {
	tokenType          string                // Token type URN (issuer identifier)
	keyManagerID       string                // Current KeyManager to use for new keys
	keyManagerRegistry map[string]KeyManager // All available KeyManagers
	slotStore          KeySlotStore
	keyType            KeyType
	algorithm          string        // Default JWT algorithm for new keys (e.g., "RS256", "ES256")
	prepareTimeout     time.Duration // How long to wait before retrying a stuck "preparing" state

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
	activeKey       *Key
	activeAlgorithm string
	publicKeys      []service.PublicKey // All non-expired public keys

	clock  clock.Clock
	ticker clock.Ticker
}

// RotatingKeyManagerConfig configures the RotatingKeyManager
type RotatingKeyManagerConfig struct {
	TokenType          string                // Token type URN (issuer identifier)
	KeyManagerID       string                // Current KeyManager to use for new keys
	KeyManagerRegistry map[string]KeyManager // All available KeyManagers
	SlotStore          KeySlotStore
	KeyType            KeyType
	Algorithm          string // JWT algorithm (e.g., "ES256", "RS256", "RS384", "RS512")
	Clock              clock.Clock

	// Optional timing overrides (uses defaults if not set)
	KeyTTL            time.Duration
	RotationThreshold time.Duration
	GracePeriod       time.Duration
	CheckInterval     time.Duration
	PrepareTimeout    time.Duration // How long to wait before retrying a stuck "preparing" state (default: 1 minute)
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

	prepareTimeout := cfg.PrepareTimeout
	if prepareTimeout == 0 {
		prepareTimeout = 1 * time.Minute
	}

	return &RotatingKeyManager{
		tokenType:          cfg.TokenType,
		keyManagerID:       cfg.KeyManagerID,
		keyManagerRegistry: cfg.KeyManagerRegistry,
		slotStore:          cfg.SlotStore,
		keyType:            cfg.KeyType,
		algorithm:          cfg.Algorithm,
		keyTTL:             keyTTL,
		rotationThreshold:  rotationThreshold,
		gracePeriod:        gracePeriod,
		checkInterval:      checkInterval,
		prepareTimeout:     prepareTimeout,
		clock:              clk,
	}
}

// keyName returns the stable key name for a slot position
func (r *RotatingKeyManager) keyName(p SlotPosition) string {
	if p == SlotPositionA {
		return "key-a"
	}
	return "key-b"
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

	return key.Signer, KeyID(key.ID), Algorithm(algorithm), nil
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
	slots, version, err := r.slotStore.ListSlots(ctx)
	if err != nil {
		return fmt.Errorf("failed to list slots: %w", err)
	}

	// Check if we have any slots for this token type
	hasSlots := false
	for _, slot := range slots {
		if slot.TokenType == r.tokenType {
			hasSlots = true
			break
		}
	}

	// If we have any slots for this token type, we're already initialized
	if hasSlots {
		return nil
	}

	// Get current KeyManager
	km, ok := r.keyManagerRegistry[r.keyManagerID]
	if !ok {
		return fmt.Errorf("key manager not found: %s", r.keyManagerID)
	}

	// Create key in KeyManager using namespace and keyName
	keyName := r.keyName(SlotPositionA)
	_, err = km.CreateKey(ctx, r.tokenType, keyName, r.keyType)
	if err != nil {
		return fmt.Errorf("failed to create initial key: %w", err)
	}

	// Save slot
	now := r.clock.Now()
	slotA := &KeySlot{
		Position:            SlotPositionA,
		TokenType:           r.tokenType,
		KeyManagerID:        r.keyManagerID,
		RotationCompletedAt: &now,
		Algorithm:           r.algorithm,
	}

	_, err = r.slotStore.SaveSlot(ctx, slotA, version)
	if err != nil {
		return fmt.Errorf("failed to save slot A: %w", err)
	}

	return nil
}

// checkAndRotate checks if rotation is needed and performs it using two-phase rotation
func (r *RotatingKeyManager) checkAndRotate(ctx context.Context) error {
	// 1. Read all slots and store version
	slots, storeVersion, err := r.slotStore.ListSlots(ctx)
	if err != nil {
		return fmt.Errorf("failed to list slots: %w", err)
	}

	// Filter slots to find slotA and slotB for this token type
	var slotA, slotB *KeySlot
	for _, slot := range slots {
		if slot.TokenType != r.tokenType {
			continue // Skip slots for other token types
		}
		switch slot.Position {
		case SlotPositionA:
			slotA = slot
		case SlotPositionB:
			slotB = slot
		default:
			return fmt.Errorf("unexpected slot position for token type %s: %s", r.tokenType, slot.Position)
		}
	}

	// 2. Determine which slot needs rotation and which slot to rotate TO
	sourceSlot, targetSlot := r.selectSlotsForRotation(slotA, slotB)
	if sourceSlot == nil || targetSlot == nil {
		return nil // No rotation needed
	}

	now := r.clock.Now()

	// 3. Check if target slot is NOT in "preparing" state - if so, mark it as preparing
	if targetSlot.PreparingAt != nil {
		if now.Sub(*targetSlot.PreparingAt) < r.prepareTimeout {
			// Already preparing and not timed out, wait for the other process
			return nil
		}
		// else: timed out, proceed to generate key
	}

	targetSlot.PreparingAt = &now
	// Use current KeyManager for new key
	targetSlot.KeyManagerID = r.keyManagerID
	storeVersion, err = r.slotStore.SaveSlot(ctx, targetSlot, storeVersion)
	if errors.Is(err, ErrVersionMismatch) {
		return nil // Another process won, that's fine
	}
	if err != nil {
		return err
	}

	// 4. Generate key and complete rotation using current KeyManager
	km, ok := r.keyManagerRegistry[r.keyManagerID]
	if !ok {
		return fmt.Errorf("key manager not found: %s", r.keyManagerID)
	}

	// Use namespace and keyName for KeyManager creation
	keyName := r.keyName(targetSlot.Position)
	key, err := km.CreateKey(ctx, r.tokenType, keyName, r.keyType)
	if err != nil {
		return fmt.Errorf("failed to create key: %w", err)
	}

	// 5. Update slot with rotation completed, clear preparing state
	// Use the version from after we saved the preparing state
	targetSlot.PreparingAt = nil
	targetSlot.RotationCompletedAt = &now
	targetSlot.Algorithm = r.algorithm

	_, err = r.slotStore.SaveSlot(ctx, targetSlot, storeVersion)
	if errors.Is(err, ErrVersionMismatch) {
		// Another process completed rotation, that's ok
		log.Printf("Another process completed rotation for slot %s, skipping", targetSlot.Position)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to save slot: %w", err)
	}

	log.Printf("Completed rotation for slot %s, new kid: %s", targetSlot.Position, key.ID)

	return nil
}

// selectSlotsForRotation determines which slot needs rotation and which slot to rotate to
// Returns (sourceSlot, targetSlot) where sourceSlot has the key that needs rotation
// and targetSlot is where the new key should be placed
func (r *RotatingKeyManager) selectSlotsForRotation(slotA, slotB *KeySlot) (*KeySlot, *KeySlot) {
	now := r.clock.Now()

	// Helper to check if slot needs rotation
	needsRotation := func(slot *KeySlot) bool {
		if slot == nil {
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

	aNeeds := needsRotation(slotA)
	bNeeds := needsRotation(slotB)

	// If both need rotation (shouldn't normally happen), rotate the older one
	if aNeeds && bNeeds {
		// Pick the older key (earlier RotationCompletedAt)
		if slotA.RotationCompletedAt != nil && slotB.RotationCompletedAt != nil {
			if slotA.RotationCompletedAt.Before(*slotB.RotationCompletedAt) {
				return slotA, slotB
			}
			return slotB, slotA
		}
	}

	// Check slot A - if it needs rotation, rotate to slot B
	if aNeeds {
		// Initialize slot B if it doesn't exist
		if slotB == nil {
			slotB = &KeySlot{
				Position:     SlotPositionB,
				TokenType:    r.tokenType,
				KeyManagerID: r.keyManagerID,
			}
		}
		// Don't rotate if target slot (B) already has a recent key
		// This prevents re-rotating A to B when B was just created
		if slotB.RotationCompletedAt != nil {
			// If B is newer than A, don't rotate A again
			if slotA.RotationCompletedAt != nil && slotB.RotationCompletedAt.After(*slotA.RotationCompletedAt) {
				return nil, nil // B is already the newer key
			}
		}
		return slotA, slotB
	}

	// Check slot B - if it needs rotation, rotate to slot A
	if bNeeds {
		// Initialize slot A if it doesn't exist (shouldn't happen but be safe)
		if slotA == nil {
			slotA = &KeySlot{
				Position:     SlotPositionA,
				TokenType:    r.tokenType,
				KeyManagerID: r.keyManagerID,
			}
		}
		// Don't rotate if target slot (A) already has a recent key
		// This prevents re-rotating A to B when B was just created
		if slotA.RotationCompletedAt != nil {
			// If A is newer than B, don't rotate B again
			if slotB.RotationCompletedAt != nil && slotA.RotationCompletedAt.After(*slotB.RotationCompletedAt) {
				return nil, nil // A is already the newer key
			}
		}
		return slotB, slotA
	}

	return nil, nil
}

// updateActiveKeyCache queries the state store and updates the cached active key and public keys
// This is called during initialization and periodic rotation checks
func (r *RotatingKeyManager) updateActiveKeyCache(ctx context.Context) error {
	slots, _, err := r.slotStore.ListSlots(ctx)
	if err != nil {
		return fmt.Errorf("failed to list slots: %w", err)
	}

	// Filter slots for this token type
	var mySlots []*KeySlot
	for _, slot := range slots {
		if slot.TokenType == r.tokenType {
			mySlots = append(mySlots, slot)
		}
	}

	if len(mySlots) == 0 {
		return errors.New("no slots available for this token type")
	}

	now := r.clock.Now()
	var activeSlot *KeySlot
	var publicKeys []service.PublicKey

	// Build list of all non-expired keys and categorize by grace period status
	var preferredSlots []*KeySlot // Keys past grace period
	var fallbackSlots []*KeySlot  // Keys still in grace period

	for _, slot := range mySlots {
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

		// Get the KeyManager that created this key
		km, ok := r.keyManagerRegistry[slot.KeyManagerID]
		if !ok {
			log.Printf("Warning: key manager %s not found for slot %s, skipping", slot.KeyManagerID, slot.Position)
			continue
		}

		// Retrieve the key from KeyManager using namespace and keyName
		keyName := r.keyName(slot.Position)
		key, err := km.GetKey(ctx, r.tokenType, keyName)
		if err != nil {
			log.Printf("Warning: failed to get key %s from key manager: %v", slot.Position, err)
			continue
		}

		// Add to public keys list (includes keys in grace period)
		publicKeys = append(publicKeys, service.PublicKey{
			KeyID:     key.ID,
			Algorithm: slot.Algorithm,
			Key:       key.Signer.Public(),
			Use:       "sig",
		})

		// Check if this key is past grace period
		pastGracePeriod := true
		if slot.RotationCompletedAt != nil {
			gracePeriodEnd := slot.RotationCompletedAt.Add(r.gracePeriod)
			if now.Before(gracePeriodEnd) {
				pastGracePeriod = false
			}
		}

		// Categorize by grace period status
		if pastGracePeriod {
			preferredSlots = append(preferredSlots, slot)
		} else {
			fallbackSlots = append(fallbackSlots, slot)
		}
	}

	// Select active key: prefer keys past grace period (newest),
	// fall back to keys in grace period (oldest for longest distribution time)
	if len(preferredSlots) > 0 {
		// Use newest key past grace period (most recently completed rotation)
		activeSlot = findNewestSlot(preferredSlots)
	} else if len(fallbackSlots) > 0 {
		// Use oldest key in grace period (gives longest time for distribution)
		activeSlot = findOldestSlot(fallbackSlots)
	}

	if activeSlot == nil {
		return errors.New("no keys available")
	}

	// Get the KeyManager that created the active key
	km, ok := r.keyManagerRegistry[activeSlot.KeyManagerID]
	if !ok {
		return fmt.Errorf("key manager %s not found for active slot", activeSlot.KeyManagerID)
	}

	// Get the active key using namespace and keyName
	keyName := r.keyName(activeSlot.Position)
	activeKey, err := km.GetKey(ctx, r.tokenType, keyName)
	if err != nil {
		return fmt.Errorf("failed to get active key %s from key manager: %w", activeSlot.Position, err)
	}

	// Update all cached data atomically
	r.mu.Lock()
	r.activeKey = activeKey
	r.activeAlgorithm = activeSlot.Algorithm
	r.publicKeys = publicKeys
	r.mu.Unlock()

	return nil
}

// findNewestSlot returns the slot with the most recent RotationCompletedAt timestamp.
// This is used to select the active key from slots that are past their grace period.
func findNewestSlot(slots []*KeySlot) *KeySlot {
	if len(slots) == 0 {
		return nil
	}

	newest := slots[0]
	for _, slot := range slots[1:] {
		if slot.RotationCompletedAt != nil && newest.RotationCompletedAt != nil {
			if slot.RotationCompletedAt.After(*newest.RotationCompletedAt) {
				newest = slot
			}
		}
	}
	return newest
}

// findOldestSlot returns the slot with the earliest RotationCompletedAt timestamp.
// This is used to select a fallback key from slots still in their grace period,
// giving the key the longest time for distribution before becoming active.
func findOldestSlot(slots []*KeySlot) *KeySlot {
	if len(slots) == 0 {
		return nil
	}

	oldest := slots[0]
	for _, slot := range slots[1:] {
		if slot.RotationCompletedAt != nil && oldest.RotationCompletedAt != nil {
			if slot.RotationCompletedAt.Before(*oldest.RotationCompletedAt) {
				oldest = slot
			}
		}
	}
	return oldest
}
