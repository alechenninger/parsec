package issuer

import (
	"context"
	"time"

	"github.com/alechenninger/parsec/internal/claims"
	"github.com/alechenninger/parsec/internal/trust"
)

// TokenContext contains all information needed to mint a token
// This represents the processed, trusted data ready to be signed
type TokenContext struct {
	// Subject identity (attested claims from validated credential)
	Subject *trust.Result

	// Workload identity (attested claims from workload credential, e.g., mTLS)
	Workload *trust.Result

	// TransactionContext goes into the token as "tctx" claim
	// This is the result of applying claim mappers and data sources
	// Per draft-ietf-oauth-transaction-tokens, this replaces the older "azd" claim
	TransactionContext claims.Claims

	// RequestContext goes into the token as "req_ctx" claim
	// Contains information about the request being authorized
	RequestContext claims.Claims

	// Audience for the token (aud claim)
	// This is the trust domain
	Audience string

	// Scope for the token (scope claim)
	Scope string
}

// Issuer creates signed tokens from prepared token context
// The issuer is responsible for cryptographic operations and token formatting
type Issuer interface {
	// Issue creates a signed token from the provided context
	// The token context contains all trusted, processed claims ready to be minted
	Issue(ctx context.Context, tokenCtx *TokenContext) (*Token, error)

	// JWKSURI returns the URI where the public keys for verifying tokens can be found
	JWKSURI() string
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
// Based on draft-ietf-oauth-transaction-tokens-06
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

	// Transaction context (replaces "azd" from earlier drafts)
	// This is the authorization context for the transaction
	TransactionContext claims.Claims `json:"tctx,omitempty"`

	// Purpose of the token
	Purpose string `json:"purp,omitempty"`

	// Request context - information about the request being authorized
	RequestContext claims.Claims `json:"req_ctx,omitempty"`

	// Scope (OAuth2)
	Scope string `json:"scope,omitempty"`
}
