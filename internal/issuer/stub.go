package issuer

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// StubIssuer is a simple stub issuer for testing
// It generates simple token strings without actual JWT signing
type StubIssuer struct {
	issuerURL             string
	ttl                   time.Duration
	includeRequestContext bool
}

// StubIssuerOption is a functional option for configuring a StubIssuer
type StubIssuerOption func(*StubIssuer)

// WithIncludeRequestContext configures the stub issuer to include request context in the token
// This is useful for testing that request attributes are properly filtered
func WithIncludeRequestContext(include bool) StubIssuerOption {
	return func(s *StubIssuer) {
		s.includeRequestContext = include
	}
}

// NewStubIssuer creates a new stub issuer
func NewStubIssuer(issuerURL string, ttl time.Duration, opts ...StubIssuerOption) *StubIssuer {
	s := &StubIssuer{
		issuerURL: issuerURL,
		ttl:       ttl,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Issue implements the Issuer interface
func (i *StubIssuer) Issue(ctx context.Context, tokenCtx *TokenContext) (*Token, error) {
	now := time.Now()
	expiresAt := now.Add(i.ttl)

	// Generate a simple token ID with microsecond precision for uniqueness
	txnID := fmt.Sprintf("txn-%d", now.UnixNano()/1000)

	// For stub, just create a simple token string
	// Include subject from the token context
	subject := tokenCtx.Subject.Subject

	var tokenValue string
	if i.includeRequestContext {
		// Encode the request context as JSON so tests can verify filtering
		requestContextJSON, err := json.Marshal(tokenCtx.RequestContext)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request context: %w", err)
		}
		// Format: stub-txn-token.{subject}.{txnID}.{requestContextJSON}
		tokenValue = fmt.Sprintf("stub-txn-token.%s.%s.%s", subject, txnID, string(requestContextJSON))
	} else {
		// Simple format without request context
		tokenValue = fmt.Sprintf("stub-txn-token.%s.%s", subject, txnID)
	}

	return &Token{
		Value:     tokenValue,
		Type:      "urn:ietf:params:oauth:token-type:txn_token",
		ExpiresAt: expiresAt,
		IssuedAt:  now,
	}, nil
}

// PublicKeys implements the Issuer interface
// Stub issuer returns an empty slice since it doesn't sign tokens
func (i *StubIssuer) PublicKeys(ctx context.Context) ([]PublicKey, error) {
	// Return empty slice for unsigned stub tokens
	return []PublicKey{}, nil
}
