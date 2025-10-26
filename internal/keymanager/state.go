package keymanager

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	// ErrSlotStateNotFound is returned when a slot state doesn't exist
	ErrSlotStateNotFound = errors.New("slot state not found")

	// ErrVersionMismatch is returned when optimistic locking fails
	ErrVersionMismatch = errors.New("version mismatch: state was modified by another process")
)

// KeySlotState represents the state of a key slot
type KeySlotState struct {
	SlotID              string     // "key-a" or "key-b"
	CurrentKeyID        *string    // Currently active key ID (nil when rotating)
	PreviousKeyID       *string    // Previous key ID (for cleanup tracking)
	RotationStartedAt   *time.Time // When rotation was initiated
	RotationCompletedAt *time.Time // When new key was bound (for grace period)
	Algorithm           string     // JWT algorithm (e.g., "ES256")
	Version             int64      // For optimistic locking
}

// KeySlotStateStore is an interface for persisting key slot state with concurrency control
type KeySlotStateStore interface {
	// GetSlotState retrieves the state for a specific slot ID
	GetSlotState(ctx context.Context, slotID string) (*KeySlotState, error)

	// SaveSlotState saves slot state atomically, returning error if version mismatch
	// expectedVersion is used for optimistic locking (-1 means create new)
	SaveSlotState(ctx context.Context, state *KeySlotState, expectedVersion int64) error

	// ListSlotStates returns all slot states
	ListSlotStates(ctx context.Context) ([]*KeySlotState, error)
}

// InMemoryKeySlotStateStore is an in-memory implementation of KeySlotStateStore
type InMemoryKeySlotStateStore struct {
	mu     sync.RWMutex
	states map[string]*KeySlotState
}

// NewInMemoryKeySlotStateStore creates a new in-memory key slot state store
func NewInMemoryKeySlotStateStore() *InMemoryKeySlotStateStore {
	return &InMemoryKeySlotStateStore{
		states: make(map[string]*KeySlotState),
	}
}

// GetSlotState retrieves the state for a specific slot ID
func (s *InMemoryKeySlotStateStore) GetSlotState(ctx context.Context, slotID string) (*KeySlotState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, ok := s.states[slotID]
	if !ok {
		return nil, ErrSlotStateNotFound
	}

	// Return a deep copy to prevent external modifications
	return s.copyState(state), nil
}

// SaveSlotState saves slot state atomically with optimistic locking
func (s *InMemoryKeySlotStateStore) SaveSlotState(ctx context.Context, state *KeySlotState, expectedVersion int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.states[state.SlotID]

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
	stateCopy := s.copyState(state)
	stateCopy.Version = expectedVersion + 1
	s.states[state.SlotID] = stateCopy

	return nil
}

// ListSlotStates returns all slot states
func (s *InMemoryKeySlotStateStore) ListSlotStates(ctx context.Context) ([]*KeySlotState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	states := make([]*KeySlotState, 0, len(s.states))
	for _, state := range s.states {
		// Return deep copies to prevent external modifications
		states = append(states, s.copyState(state))
	}

	return states, nil
}

// copyState creates a deep copy of a KeySlotState
func (s *InMemoryKeySlotStateStore) copyState(state *KeySlotState) *KeySlotState {
	copy := &KeySlotState{
		SlotID:    state.SlotID,
		Algorithm: state.Algorithm,
		Version:   state.Version,
	}

	if state.CurrentKeyID != nil {
		keyID := *state.CurrentKeyID
		copy.CurrentKeyID = &keyID
	}

	if state.PreviousKeyID != nil {
		keyID := *state.PreviousKeyID
		copy.PreviousKeyID = &keyID
	}

	if state.RotationStartedAt != nil {
		t := *state.RotationStartedAt
		copy.RotationStartedAt = &t
	}

	if state.RotationCompletedAt != nil {
		t := *state.RotationCompletedAt
		copy.RotationCompletedAt = &t
	}

	return copy
}
