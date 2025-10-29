package keymanager

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"
)

var (
	// ErrVersionMismatch is returned when optimistic locking fails
	ErrVersionMismatch = errors.New("version mismatch: store was modified by another process")
)

// StoreVersion is an opaque version identifier for the key slot store
type StoreVersion string

// KeySlot represents a key slot with its current and previous keys
type KeySlot struct {
	SlotID              string     // "key-a" or "key-b"
	CurrentKeyID        *string    // Currently active key ID (nil when rotating)
	PreviousKeyID       *string    // Previous key ID (for cleanup tracking)
	RotationStartedAt   *time.Time // When rotation was initiated
	RotationCompletedAt *time.Time // When new key was bound (for grace period)
	Algorithm           string     // JWT algorithm (e.g., "ES256")
}

// KeySlotStore is an interface for persisting key slots with concurrency control
type KeySlotStore interface {
	// ListSlots returns all slots and the current store version
	ListSlots(ctx context.Context) ([]*KeySlot, StoreVersion, error)

	// SaveSlot saves a slot atomically, returning error if version mismatch
	// expectedVersion is used for optimistic locking (empty string means create new)
	SaveSlot(ctx context.Context, slot *KeySlot, expectedVersion StoreVersion) error
}

// InMemoryKeySlotStore is an in-memory implementation of KeySlotStore
type InMemoryKeySlotStore struct {
	mu      sync.RWMutex
	slots   map[string]*KeySlot
	version int // Store-level version counter
}

// NewInMemoryKeySlotStore creates a new in-memory key slot store
func NewInMemoryKeySlotStore() *InMemoryKeySlotStore {
	return &InMemoryKeySlotStore{
		slots:   make(map[string]*KeySlot),
		version: 0,
	}
}

// SaveSlot saves a slot atomically with optimistic locking
func (s *InMemoryKeySlotStore) SaveSlot(ctx context.Context, slot *KeySlot, expectedVersion StoreVersion) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	currentVersion := StoreVersion(strconv.Itoa(s.version))

	if expectedVersion != currentVersion {
		return ErrVersionMismatch
	}

	// Save a deep copy and increment store version
	slotCopy := s.copySlot(slot)
	s.slots[slot.SlotID] = slotCopy
	s.version++

	return nil
}

// ListSlots returns all slots and the current store version
func (s *InMemoryKeySlotStore) ListSlots(ctx context.Context) ([]*KeySlot, StoreVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	slots := make([]*KeySlot, 0, len(s.slots))
	for _, slot := range s.slots {
		// Return deep copies to prevent external modifications
		slots = append(slots, s.copySlot(slot))
	}

	return slots, StoreVersion(strconv.Itoa(s.version)), nil
}

// copySlot creates a deep copy of a KeySlot
func (s *InMemoryKeySlotStore) copySlot(slot *KeySlot) *KeySlot {
	copy := &KeySlot{
		SlotID:    slot.SlotID,
		Algorithm: slot.Algorithm,
	}

	if slot.CurrentKeyID != nil {
		keyID := *slot.CurrentKeyID
		copy.CurrentKeyID = &keyID
	}

	if slot.PreviousKeyID != nil {
		keyID := *slot.PreviousKeyID
		copy.PreviousKeyID = &keyID
	}

	if slot.RotationStartedAt != nil {
		t := *slot.RotationStartedAt
		copy.RotationStartedAt = &t
	}

	if slot.RotationCompletedAt != nil {
		t := *slot.RotationCompletedAt
		copy.RotationCompletedAt = &t
	}

	return copy
}
