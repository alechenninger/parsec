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

// SignResult contains the signature and metadata about the signing operation
type SignResult struct {
	Signature []byte
	KeyID     string
	Algorithm string
}

// PublicKeyInfo contains public key information for verification
type PublicKeyInfo struct {
	KeyID     string
	Algorithm string
	Key       crypto.PublicKey
}

// RotatingKeyManager manages automatic key rotation using Spire's KeyManager
type RotatingKeyManager struct {
	keyManager spirekm.KeyManager
	stateStore KeySlotStateStore
	keyType    spirekm.KeyType
	algorithm  string // JWT algorithm string (e.g., "RS256", "ES256")

	// Timing parameters
	keyTTL            time.Duration
	rotationThreshold time.Duration
	gracePeriod       time.Duration
	checkInterval     time.Duration

	clock  clock.Clock
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// RotatingKeyManagerConfig configures the RotatingKeyManager
type RotatingKeyManagerConfig struct {
	KeyManager spirekm.KeyManager
	StateStore KeySlotStateStore
	KeyType    spirekm.KeyType
	Algorithm  string
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
		stopCh:            make(chan struct{}),
	}
}

// Start begins the background key rotation process
func (r *RotatingKeyManager) Start(ctx context.Context) error {
	// Ensure we have at least one key
	if err := r.ensureInitialKey(ctx); err != nil {
		return fmt.Errorf("failed to ensure initial key: %w", err)
	}

	// Start background rotation goroutine
	r.wg.Add(1)
	go r.rotationLoop()

	return nil
}

// Stop gracefully stops the background rotation process
func (r *RotatingKeyManager) Stop() {
	close(r.stopCh)
	r.wg.Wait()
}

// Sign signs data with the current active key
func (r *RotatingKeyManager) Sign(ctx context.Context, data []byte) (*SignResult, error) {
	// Get the current active key
	keyID, err := r.getCurrentActiveKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get current active key: %w", err)
	}

	// Retrieve the key from Spire KeyManager
	key, err := r.keyManager.GetKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key %s from key manager: %w", keyID, err)
	}

	// Sign the data
	signature, err := key.Sign(nil, data, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("failed to sign data with key %s: %w", keyID, err)
	}

	return &SignResult{
		Signature: signature,
		KeyID:     keyID,
		Algorithm: r.algorithm,
	}, nil
}

// GetCurrentSigner returns a crypto.Signer for the current active key along with its key ID
func (r *RotatingKeyManager) GetCurrentSigner(ctx context.Context) (crypto.Signer, string, error) {
	// Get the current active key
	keyID, err := r.getCurrentActiveKey(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get current active key: %w", err)
	}

	// Retrieve the key from Spire KeyManager
	key, err := r.keyManager.GetKey(ctx, keyID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get key %s from key manager: %w", keyID, err)
	}

	return key, keyID, nil
}

// PublicKeys returns all non-expired public keys
func (r *RotatingKeyManager) PublicKeys(ctx context.Context) ([]PublicKeyInfo, error) {
	// Get all slot states
	slots, err := r.stateStore.ListSlotStates(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list slot states: %w", err)
	}

	now := r.clock.Now()
	var publicKeys []PublicKeyInfo

	for _, slot := range slots {
		// Skip slots without a current key
		if slot.CurrentKeyID == nil {
			continue
		}

		// Only include non-expired keys
		if slot.RotationCompletedAt != nil {
			expiresAt := slot.RotationCompletedAt.Add(r.keyTTL)
			if !now.Before(expiresAt) {
				continue // Expired
			}
		}

		// Retrieve the public key from Spire KeyManager
		key, err := r.keyManager.GetKey(ctx, *slot.CurrentKeyID)
		if err != nil {
			log.Printf("Warning: failed to get key %s from key manager: %v", *slot.CurrentKeyID, err)
			continue
		}

		publicKeys = append(publicKeys, PublicKeyInfo{
			KeyID:     *slot.CurrentKeyID,
			Algorithm: slot.Algorithm,
			Key:       key.Public(),
		})
	}

	return publicKeys, nil
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

	// Initialize both slots
	now := r.clock.Now()

	// Create slot A with initial key
	keyID := r.generateKeyID(KeyIDA)
	_, err = r.keyManager.GenerateKey(ctx, keyID, r.keyType)
	if err != nil {
		return fmt.Errorf("failed to generate initial key: %w", err)
	}

	slotA := &KeySlotState{
		SlotID:              KeyIDA,
		CurrentKeyID:        &keyID,
		RotationCompletedAt: &now,
		Algorithm:           r.algorithm,
		Version:             0,
	}
	if err := r.stateStore.SaveSlotState(ctx, slotA, -1); err != nil {
		return fmt.Errorf("failed to save slot A state: %w", err)
	}

	// Create empty slot B
	slotB := &KeySlotState{
		SlotID:    KeyIDB,
		Algorithm: r.algorithm,
		Version:   0,
	}
	if err := r.stateStore.SaveSlotState(ctx, slotB, -1); err != nil {
		return fmt.Errorf("failed to save slot B state: %w", err)
	}

	return nil
}

// generateKeyID generates a unique key ID for a slot
func (r *RotatingKeyManager) generateKeyID(slotID string) string {
	return fmt.Sprintf("%s-%s", slotID, uuid.New().String())
}

// rotationLoop runs in the background, checking for rotation needs
func (r *RotatingKeyManager) rotationLoop() {
	defer r.wg.Done()

	ticker := time.NewTicker(r.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			ctx := context.Background()
			if err := r.checkAndRotate(ctx); err != nil {
				log.Printf("Error during key rotation check: %v", err)
			}
		}
	}
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

	// 2. Determine which slot needs rotation
	slotToRotate := r.selectSlotForRotation(slotA, slotB)
	if slotToRotate == nil {
		return nil // No rotation needed
	}

	// 3. Initiate rotation if not already started
	if slotToRotate.CurrentKeyID != nil {
		err := r.initiateRotation(ctx, slotToRotate)
		if err != nil && !errors.Is(err, ErrVersionMismatch) {
			return fmt.Errorf("failed to initiate rotation: %w", err)
		}
		// Either succeeded or another process beat us - reload slot state
		slotToRotate, err = r.stateStore.GetSlotState(ctx, slotToRotate.SlotID)
		if err != nil {
			return fmt.Errorf("failed to reload slot state after rotation initiation: %w", err)
		}
	}

	// 4. Generate key with unique ID if slot needs a new key
	if slotToRotate.CurrentKeyID == nil {
		uniqueKeyID := r.generateKeyID(slotToRotate.SlotID)
		_, err := r.keyManager.GenerateKey(ctx, uniqueKeyID, r.keyType)
		if err != nil {
			return fmt.Errorf("failed to generate key: %w", err)
		}

		// 5. Try to bind this key to the slot
		err = r.bindKeyToSlot(ctx, slotToRotate, uniqueKeyID)
		if errors.Is(err, ErrVersionMismatch) {
			// Another process won the race, that's ok
			log.Printf("Another process bound a key to slot %s, skipping", slotToRotate.SlotID)
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to bind key to slot: %w", err)
		}

		log.Printf("Bound new key %s to slot %s", uniqueKeyID, slotToRotate.SlotID)
	}

	return nil
}

// initiateRotation marks a slot as needing rotation
func (r *RotatingKeyManager) initiateRotation(ctx context.Context, slot *KeySlotState) error {
	now := r.clock.Now()
	newSlot := &KeySlotState{
		SlotID:            slot.SlotID,
		CurrentKeyID:      nil, // Null out to indicate rotation needed
		PreviousKeyID:     slot.CurrentKeyID,
		RotationStartedAt: &now,
		Algorithm:         slot.Algorithm,
		Version:           slot.Version,
	}
	return r.stateStore.SaveSlotState(ctx, newSlot, slot.Version)
}

// bindKeyToSlot binds a generated key to a slot
func (r *RotatingKeyManager) bindKeyToSlot(ctx context.Context, slot *KeySlotState, keyID string) error {
	now := r.clock.Now()
	newSlot := &KeySlotState{
		SlotID:              slot.SlotID,
		CurrentKeyID:        &keyID,
		PreviousKeyID:       slot.PreviousKeyID,
		RotationStartedAt:   slot.RotationStartedAt,
		RotationCompletedAt: &now, // Mark when bound for grace period
		Algorithm:           slot.Algorithm,
		Version:             slot.Version,
	}
	return r.stateStore.SaveSlotState(ctx, newSlot, slot.Version)
}

// selectSlotForRotation determines which slot needs rotation
func (r *RotatingKeyManager) selectSlotForRotation(slotA, slotB *KeySlotState) *KeySlotState {
	now := r.clock.Now()

	// Helper to check if slot needs rotation
	needsRotation := func(slot *KeySlotState) bool {
		if slot == nil {
			return false
		}

		// If CurrentKeyID is nil, slot is already in rotation state
		if slot.CurrentKeyID == nil {
			return true
		}

		// Check if key is approaching expiration
		if slot.RotationCompletedAt != nil {
			expiresAt := slot.RotationCompletedAt.Add(r.keyTTL)
			rotateAt := expiresAt.Add(-r.rotationThreshold)
			return now.After(rotateAt)
		}

		return false
	}

	// Check slot A first
	if needsRotation(slotA) {
		return slotA
	}

	// Check slot B
	if needsRotation(slotB) {
		return slotB
	}

	return nil
}

// getCurrentActiveKey returns the currently active key ID
// Active key is the most recent non-expired key that is past its grace period
func (r *RotatingKeyManager) getCurrentActiveKey(ctx context.Context) (string, error) {
	slots, err := r.stateStore.ListSlotStates(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to list slot states: %w", err)
	}

	if len(slots) == 0 {
		return "", errors.New("no slots available")
	}

	now := r.clock.Now()
	var activeSlot *KeySlotState

	for _, slot := range slots {
		// Skip slots without a current key (rotating)
		if slot.CurrentKeyID == nil {
			continue
		}

		// Check grace period (based on RotationCompletedAt - when key was bound)
		if slot.RotationCompletedAt != nil {
			gracePeriodEnd := slot.RotationCompletedAt.Add(r.gracePeriod)
			if now.Before(gracePeriodEnd) {
				continue // Still in grace period
			}
		}

		// Check if key is expired
		if slot.RotationCompletedAt != nil {
			expiresAt := slot.RotationCompletedAt.Add(r.keyTTL)
			if !now.Before(expiresAt) {
				continue // Expired
			}
		}

		// Select the most recently completed rotation
		if activeSlot == nil ||
			(slot.RotationCompletedAt != nil && activeSlot.RotationCompletedAt != nil &&
				slot.RotationCompletedAt.After(*activeSlot.RotationCompletedAt)) {
			activeSlot = slot
		}
	}

	if activeSlot == nil || activeSlot.CurrentKeyID == nil {
		return "", errors.New("no active key available (all keys expired or in grace period)")
	}

	return *activeSlot.CurrentKeyID, nil
}
