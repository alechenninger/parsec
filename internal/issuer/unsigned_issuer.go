package issuer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/alechenninger/parsec/internal/service"
)

var never = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// UnsignedIssuer issues unsigned tokens containing only the transaction context claims
// The token is the base64-encoded JSON representation of the transaction context
type UnsignedIssuer struct {
	tokenType string
}

// NewUnsignedIssuer creates a new unsigned issuer
func NewUnsignedIssuer(tokenType string) *UnsignedIssuer {
	return &UnsignedIssuer{
		tokenType: tokenType,
	}
}

// Issue implements the Issuer interface
// Returns a token containing base64-encoded JSON of the transaction context claims
func (i *UnsignedIssuer) Issue(ctx context.Context, tokenCtx *service.TokenContext) (*service.Token, error) {
	// Serialize transaction context claims to JSON
	claimsJSON, err := json.Marshal(tokenCtx.TransactionContext)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transaction context: %w", err)
	}

	// Base64-encode the JSON
	encodedToken := base64.StdEncoding.EncodeToString(claimsJSON)

	// Use a far-future expiration time to indicate the token never expires
	// Year 9999 is effectively "never" for practical purposes
	neverExpires := never

	return &service.Token{
		Value:     encodedToken,
		Type:      i.tokenType,
		ExpiresAt: neverExpires,
		IssuedAt:  time.Now(),
	}, nil
}

// PublicKeys implements the Issuer interface
// Unsigned issuer returns an empty slice since tokens are not signed
func (i *UnsignedIssuer) PublicKeys(ctx context.Context) ([]service.PublicKey, error) {
	return []service.PublicKey{}, nil
}
