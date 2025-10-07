package issuer

import (
	"context"
	"fmt"
	"time"

	"github.com/alechenninger/parsec/internal/validator"
)

// StubIssuer is a simple stub issuer for testing
// It generates simple token strings without actual JWT signing
type StubIssuer struct {
	issuerURL string
	ttl       time.Duration
}

// NewStubIssuer creates a new stub issuer
func NewStubIssuer(issuerURL string, ttl time.Duration) *StubIssuer {
	return &StubIssuer{
		issuerURL: issuerURL,
		ttl:       ttl,
	}
}

// Issue implements the Issuer interface
func (i *StubIssuer) Issue(ctx context.Context, result *validator.Result, reqCtx *RequestContext) (*Token, error) {
	now := time.Now()
	expiresAt := now.Add(i.ttl)

	// Generate a simple token ID with microsecond precision for uniqueness
	// In real implementation, this would be UUIDv7
	txnID := fmt.Sprintf("txn-%d", now.UnixNano()/1000)

	// For stub, just create a simple token string
	tokenValue := fmt.Sprintf("stub-txn-token.%s.%s", result.Subject, txnID)

	return &Token{
		Value:         tokenValue,
		Type:          "urn:ietf:params:oauth:token-type:txn_token",
		ExpiresAt:     expiresAt,
		IssuedAt:      now,
		TransactionID: txnID,
	}, nil
}

// JWKSURI implements the Issuer interface
func (i *StubIssuer) JWKSURI() string {
	return fmt.Sprintf("%s/.well-known/jwks.json", i.issuerURL)
}
