package issuer

import (
	"fmt"
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
