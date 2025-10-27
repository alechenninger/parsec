package service

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// SimpleRegistry is a simple in-memory registry of issuers by token type
type SimpleRegistry struct {
	mu      sync.RWMutex
	issuers map[TokenType]Issuer
}

// NewSimpleRegistry creates a new simple issuer registry
func NewSimpleRegistry() *SimpleRegistry {
	return &SimpleRegistry{
		issuers: make(map[TokenType]Issuer),
	}
}

// Register registers an issuer for a token type
func (r *SimpleRegistry) Register(tokenType TokenType, issuer Issuer) *SimpleRegistry {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.issuers[tokenType] = issuer
	return r
}

// GetIssuer returns an issuer for the specified token type
func (r *SimpleRegistry) GetIssuer(tokenType TokenType) (Issuer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	issuer, ok := r.issuers[tokenType]
	if !ok {
		return nil, fmt.Errorf("no issuer registered for token type: %s", tokenType)
	}

	return issuer, nil
}

// ListTokenTypes returns all registered token types
func (r *SimpleRegistry) ListTokenTypes() []TokenType {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]TokenType, 0, len(r.issuers))
	for tokenType := range r.issuers {
		types = append(types, tokenType)
	}

	return types
}

// GetAllPublicKeys returns all public keys from all registered issuers.
// It collects keys from all issuers, aggregating any errors that occur.
// Returns the collected keys along with any errors encountered.
// If some issuers succeed and others fail, both keys and an error are returned.
func (r *SimpleRegistry) GetAllPublicKeys(ctx context.Context) ([]PublicKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var allKeys []PublicKey
	var errs []error

	for tokenType, issuer := range r.issuers {
		keys, err := issuer.PublicKeys(ctx)
		if err != nil {
			// Collect error with context about which issuer failed
			errs = append(errs, fmt.Errorf("issuer for %s: %w", tokenType, err))
			continue
		}

		allKeys = append(allKeys, keys...)
	}

	// Return collected keys along with aggregated errors (if any)
	if len(errs) > 0 {
		return allKeys, newPublicKeysError(errs)
	}

	return allKeys, nil
}

// newPublicKeysError creates an aggregated error from multiple issuer errors
func newPublicKeysError(errs []error) error {
	if len(errs) == 0 {
		return nil
	}

	if len(errs) == 1 {
		return fmt.Errorf("failed to get public keys from 1 issuer: %w", errs[0])
	}

	var errMsgs []string
	for _, err := range errs {
		errMsgs = append(errMsgs, err.Error())
	}

	return fmt.Errorf("failed to get public keys from %d issuers: %s",
		len(errs), strings.Join(errMsgs, "; "))
}
