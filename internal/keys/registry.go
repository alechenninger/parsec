package keys

import (
	"context"
	"fmt"
	"sync"
)

// SignerRegistry manages a collection of named RotatingSigners
type SignerRegistry struct {
	signers map[string]RotatingSigner
	mu      sync.RWMutex
}

// NewSignerRegistry creates a new signer registry
func NewSignerRegistry() *SignerRegistry {
	return &SignerRegistry{
		signers: make(map[string]RotatingSigner),
	}
}

// Register adds a signer to the registry
func (r *SignerRegistry) Register(id string, signer RotatingSigner) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.signers[id]; exists {
		return fmt.Errorf("signer with id %s already registered", id)
	}

	r.signers[id] = signer
	return nil
}

// Get retrieves a signer by ID
func (r *SignerRegistry) Get(id string) (RotatingSigner, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	signer, ok := r.signers[id]
	if !ok {
		return nil, fmt.Errorf("signer not found: %s", id)
	}

	return signer, nil
}

// Start starts all registered signers
func (r *SignerRegistry) Start(ctx context.Context) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for id, signer := range r.signers {
		if err := signer.Start(ctx); err != nil {
			return fmt.Errorf("failed to start signer %s: %w", id, err)
		}
	}

	return nil
}

// Stop stops all registered signers
func (r *SignerRegistry) Stop() {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, signer := range r.signers {
		signer.Stop()
	}
}
