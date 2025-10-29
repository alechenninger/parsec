package keymanager

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	// ErrSlotNotFound is returned when a slot doesn't exist
	ErrSlotNotFound = errors.New("slot not found")

	// ErrVersionMismatch is returned when optimistic locking fails
	ErrVersionMismatch = errors.New("version mismatch: slot was modified by another process")
)

// KeySlot represents a key slot with its current and previous keys
type KeySlot struct {
	SlotID              string     // "key-a" or "key-b"
	CurrentKeyID        *string    // Currently active key ID (nil when rotating)
	PreviousKeyID       *string    // Previous key ID (for cleanup tracking)
	RotationStartedAt   *time.Time // When rotation was initiated
	RotationCompletedAt *time.Time // When new key was bound (for grace period)
	Algorithm           string     // JWT algorithm (e.g., "ES256")
	Version             int64      // For optimistic locking
}

// KeySlotStore is an interface for persisting key slots with concurrency control
type KeySlotStore interface {
	// GetSlot retrieves a specific slot by ID
	GetSlot(ctx context.Context, slotID string) (*KeySlot, error)

	// SaveSlot saves a slot atomically, returning error if version mismatch
	// expectedVersion is used for optimistic locking (-1 means create new)
	SaveSlot(ctx context.Context, slot *KeySlot, expectedVersion int64) error

	// ListSlots returns all slots
	ListSlots(ctx context.Context) ([]*KeySlot, error)
}

// InMemoryKeySlotStore is an in-memory implementation of KeySlotStore
type InMemoryKeySlotStore struct {
	mu    sync.RWMutex
	slots map[string]*KeySlot
}

// NewInMemoryKeySlotStore creates a new in-memory key slot store
func NewInMemoryKeySlotStore() *InMemoryKeySlotStore {
	return &InMemoryKeySlotStore{
		slots: make(map[string]*KeySlot),
	}
}

// GetSlot retrieves a specific slot by ID
func (s *InMemoryKeySlotStore) GetSlot(ctx context.Context, slotID string) (*KeySlot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	slot, ok := s.slots[slotID]
	if !ok {
		return nil, ErrSlotNotFound
	}

	// Return a deep copy to prevent external modifications
	return s.copySlot(slot), nil
}

// SaveSlot saves a slot atomically with optimistic locking
func (s *InMemoryKeySlotStore) SaveSlot(ctx context.Context, slot *KeySlot, expectedVersion int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.slots[slot.SlotID]

	// If expectedVersion is -1, we expect the slot to not exist (create operation)
	if expectedVersion == -1 {
		if exists {
			return ErrVersionMismatch
		}
	} else {
		// Update operation - verify the version matches
		if !exists {
			return ErrVersionMismatch
		}
		if existing.Version != expectedVersion {
			return ErrVersionMismatch
		}
	}

	// Save a deep copy and increment version
	slotCopy := s.copySlot(slot)
	slotCopy.Version = expectedVersion + 1
	s.slots[slot.SlotID] = slotCopy

	return nil
}

// ListSlots returns all slots
func (s *InMemoryKeySlotStore) ListSlots(ctx context.Context) ([]*KeySlot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	slots := make([]*KeySlot, 0, len(s.slots))
	for _, slot := range s.slots {
		// Return deep copies to prevent external modifications
		slots = append(slots, s.copySlot(slot))
	}

	return slots, nil
}

// copySlot creates a deep copy of a KeySlot
func (s *InMemoryKeySlotStore) copySlot(slot *KeySlot) *KeySlot {
	copy := &KeySlot{
		SlotID:    slot.SlotID,
		Algorithm: slot.Algorithm,
		Version:   slot.Version,
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
