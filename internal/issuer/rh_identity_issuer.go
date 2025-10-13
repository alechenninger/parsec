package issuer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/alechenninger/parsec/internal/service"
)

// RHIdentityIssuer issues Red Hat identity tokens in the x-rh-identity format
// The token is the base64-encoded JSON representation wrapped in {"identity": {...}}
type RHIdentityIssuer struct {
	tokenType string
}

// NewRHIdentityIssuer creates a new Red Hat identity issuer
func NewRHIdentityIssuer(tokenType string) *RHIdentityIssuer {
	return &RHIdentityIssuer{
		tokenType: tokenType,
	}
}

// Issue implements the Issuer interface
// Returns a token in the x-rh-identity format: base64(JSON({"identity": {...}}))
func (i *RHIdentityIssuer) Issue(ctx context.Context, tokenCtx *service.TokenContext) (*service.Token, error) {
	// Wrap transaction context in "identity" wrapper
	// This matches the format expected by Red Hat services
	identityWrapper := map[string]any{
		"identity": tokenCtx.TransactionContext,
	}

	// Serialize to JSON
	identityJSON, err := json.Marshal(identityWrapper)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RH identity: %w", err)
	}

	// Base64-encode the JSON
	encodedToken := base64.StdEncoding.EncodeToString(identityJSON)

	// RH identity tokens don't have a real expiration
	// Use a far-future time to indicate effectively never expires
	neverExpires := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

	return &service.Token{
		Value:     encodedToken,
		Type:      i.tokenType,
		ExpiresAt: neverExpires,
		IssuedAt:  time.Now(),
	}, nil
}

// PublicKeys implements the Issuer interface
// RH identity issuer returns an empty slice since tokens are not signed
func (i *RHIdentityIssuer) PublicKeys(ctx context.Context) ([]service.PublicKey, error) {
	return []service.PublicKey{}, nil
}
