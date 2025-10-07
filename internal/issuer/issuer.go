package issuer

import (
	"context"
	"time"

	"github.com/alechenninger/parsec/internal/validator"
)

// Issuer issues transaction tokens based on validated credentials
type Issuer interface {
	// Issue creates a transaction token from a validation result
	// The reqCtx provides additional request context to include in the token
	// TODO: accept authorization context to use as input or possibly return if already trusted
	// TODO: support issuing different token types, not just txn token, and possibly multiple at once
	Issue(ctx context.Context, subject *validator.Result, reqCtx *RequestContext) (*Token, error)

	// JWKSURI returns the URI where the public keys for verifying tokens can be found
	JWKSURI() string
}

// RequestContext contains contextual information about the request
// This will be embedded in the transaction token per draft-ietf-oauth-transaction-tokens
type RequestContext struct {
	// Method is the HTTP method or RPC method name
	Method string

	// Path is the request path/resource being accessed
	Path string

	// IPAddress is the client IP address
	IPAddress string

	// UserAgent is the client user agent
	UserAgent string

	// Additional context
	Additional map[string]any
}

// Token represents an issued transaction token
type Token struct {
	// Value is the encoded token (e.g., JWT string)
	Value string

	// Type is the token type (e.g., "urn:ietf:params:oauth:token-type:txn_token")
	Type string

	// ExpiresAt is when the token expires
	ExpiresAt time.Time

	// IssuedAt is when the token was issued
	IssuedAt time.Time

	// TransactionID is the unique transaction identifier
	TransactionID string
}

// TokenClaims represents the claims in a transaction token
// Based on draft-ietf-oauth-transaction-tokens
type TokenClaims struct {
	// Standard JWT claims
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	JWTID     string   `json:"jti"`

	// Transaction token specific claims
	TransactionID string `json:"txn"` // UUIDv7 for temporal ordering

	// Authorization details (future: structured authorization context)
	AuthorizationDetails map[string]any `json:"azd,omitempty"`

	// Purpose of the token
	Purpose string `json:"purp,omitempty"`

	// Request context
	RequestContext map[string]any `json:"req_ctx,omitempty"`

	// Scope (OAuth2)
	Scope string `json:"scope,omitempty"`
}
