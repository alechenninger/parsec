package issuer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/alechenninger/parsec/internal/claims"
	"github.com/alechenninger/parsec/internal/service"
)

var never = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// UnsignedIssuer issues unsigned tokens containing claim-mapped data
// The token is the base64-encoded JSON representation of the mapped claims
type UnsignedIssuer struct {
	tokenType    string
	claimMappers []service.ClaimMapper
}

// NewUnsignedIssuer creates a new unsigned issuer
func NewUnsignedIssuer(tokenType string, claimMappers []service.ClaimMapper) *UnsignedIssuer {
	return &UnsignedIssuer{
		tokenType:    tokenType,
		claimMappers: claimMappers,
	}
}

// Issue implements the Issuer interface
// Returns a token containing base64-encoded JSON of the mapped claims
func (i *UnsignedIssuer) Issue(ctx context.Context, issueCtx *service.IssueContext) (*service.Token, error) {
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

	// Serialize mapped claims to JSON
	claimsJSON, err := json.Marshal(mappedClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}

	// Base64-encode the JSON
	encodedToken := base64.StdEncoding.EncodeToString(claimsJSON)

	// Use a far-future expiration time to indicate the token never expires
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
