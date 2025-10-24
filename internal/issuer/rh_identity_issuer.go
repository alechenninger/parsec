package issuer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/alechenninger/parsec/internal/claims"
	"github.com/alechenninger/parsec/internal/clock"
	"github.com/alechenninger/parsec/internal/service"
)

// RHIdentityIssuerConfig is the configuration for creating a Red Hat identity issuer
type RHIdentityIssuerConfig struct {
	// TokenType is the token type to issue
	TokenType string

	// ClaimMappers are the mappers to apply to generate claims
	ClaimMappers []service.ClaimMapper

	// Clock is the time source for token timestamps
	// If nil, uses system clock
	Clock clock.Clock
}

// RHIdentityIssuer issues Red Hat identity tokens in the x-rh-identity format
// The token is the base64-encoded JSON representation wrapped in {"identity": {...}}
type RHIdentityIssuer struct {
	tokenType    string
	claimMappers []service.ClaimMapper
	clock        clock.Clock
}

// NewRHIdentityIssuer creates a new Red Hat identity issuer
func NewRHIdentityIssuer(cfg RHIdentityIssuerConfig) *RHIdentityIssuer {
	clk := cfg.Clock
	if clk == nil {
		clk = clock.NewSystemClock()
	}

	return &RHIdentityIssuer{
		tokenType:    cfg.TokenType,
		claimMappers: cfg.ClaimMappers,
		clock:        clk,
	}
}

// Issue implements the Issuer interface
// Returns a token in the x-rh-identity format: base64(JSON({"identity": {...}}))
func (i *RHIdentityIssuer) Issue(ctx context.Context, issueCtx *service.IssueContext) (*service.Token, error) {
	// Build data source input
	dataSourceInput := &service.DataSourceInput{
		Subject:           issueCtx.Subject,
		Actor:             issueCtx.Actor,
		RequestAttributes: issueCtx.RequestAttributes,
	}

	// Build mapper input
	mapperInput := &service.MapperInput{
		Subject:            issueCtx.Subject,
		Actor:              issueCtx.Actor,
		RequestAttributes:  issueCtx.RequestAttributes,
		DataSourceRegistry: issueCtx.DataSourceRegistry,
		DataSourceInput:    dataSourceInput,
	}

	// Apply claim mappers
	mappedClaims := make(claims.Claims)
	for _, mapper := range i.claimMappers {
		mapperClaims, err := mapper.Map(ctx, mapperInput)
		if err != nil {
			return nil, fmt.Errorf("failed to map claims: %w", err)
		}
		mappedClaims.Merge(mapperClaims)
	}

	// Wrap mapped claims in "identity" wrapper
	// This matches the format expected by Red Hat services
	identityWrapper := map[string]any{
		"identity": mappedClaims,
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
		IssuedAt:  i.clock.Now(),
	}, nil
}

// PublicKeys implements the Issuer interface
// RH identity issuer returns an empty slice since tokens are not signed
func (i *RHIdentityIssuer) PublicKeys(ctx context.Context) ([]service.PublicKey, error) {
	return []service.PublicKey{}, nil
}
