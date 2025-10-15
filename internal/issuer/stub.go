package issuer

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/alechenninger/parsec/internal/claims"
	"github.com/alechenninger/parsec/internal/service"
)

// StubIssuer is a simple stub issuer for testing
// It generates simple token strings without actual JWT signing
type StubIssuer struct {
	issuerURL                 string
	ttl                       time.Duration
	transactionContextMappers []service.ClaimMapper
	requestContextMappers     []service.ClaimMapper
}

// NewStubIssuer creates a new stub issuer
func NewStubIssuer(
	issuerURL string,
	ttl time.Duration,
	transactionContextMappers []service.ClaimMapper,
	requestContextMappers []service.ClaimMapper,
) *StubIssuer {
	return &StubIssuer{
		issuerURL:                 issuerURL,
		ttl:                       ttl,
		transactionContextMappers: transactionContextMappers,
		requestContextMappers:     requestContextMappers,
	}
}

// Issue implements the Issuer interface
func (i *StubIssuer) Issue(ctx context.Context, issueCtx *service.IssueContext) (*service.Token, error) {
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

	// Apply transaction context mappers
	transactionContext := make(claims.Claims)
	for _, mapper := range i.transactionContextMappers {
		mapperClaims, err := mapper.Map(ctx, mapperInput)
		if err != nil {
			return nil, fmt.Errorf("failed to map transaction context: %w", err)
		}
		transactionContext.Merge(mapperClaims)
	}

	// Apply request context mappers
	requestContext := make(claims.Claims)
	for _, mapper := range i.requestContextMappers {
		mapperClaims, err := mapper.Map(ctx, mapperInput)
		if err != nil {
			return nil, fmt.Errorf("failed to map request context: %w", err)
		}
		requestContext.Merge(mapperClaims)
	}

	now := time.Now()
	expiresAt := now.Add(i.ttl)

	// Generate a simple token ID with microsecond precision for uniqueness
	txnID := fmt.Sprintf("txn-%d", now.UnixNano()/1000)

	// Include subject from the issue context
	subject := issueCtx.Subject.Subject

	// Encode the request context as JSON so tests can verify filtering
	requestContextJSON, err := json.Marshal(requestContext)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request context: %w", err)
	}

	// Format: stub-txn-token.{subject}.{txnID}.{requestContextJSON}
	tokenValue := fmt.Sprintf("stub-txn-token.%s.%s.%s", subject, txnID, string(requestContextJSON))

	return &service.Token{
		Value:     tokenValue,
		Type:      "urn:ietf:params:oauth:token-type:txn_token",
		ExpiresAt: expiresAt,
		IssuedAt:  now,
	}, nil
}

// PublicKeys implements the Issuer interface
// Stub issuer returns an empty slice since it doesn't sign tokens
func (i *StubIssuer) PublicKeys(ctx context.Context) ([]service.PublicKey, error) {
	// Return empty slice for unsigned stub tokens
	return []service.PublicKey{}, nil
}
