package issuer

import (
	"context"
	"fmt"

	"github.com/alechenninger/parsec/internal/trust"
)

// TokenService orchestrates token issuance
// This is the core business logic that brings together data sources,
// claim mappers, and issuers to produce tokens
type TokenService struct {
	trustDomain    string
	dataSources    *DataSourceRegistry
	claimMappers   *ClaimMapperRegistry
	issuerRegistry Registry
}

// NewTokenService creates a new token service
func NewTokenService(
	trustDomain string,
	dataSources *DataSourceRegistry,
	claimMappers *ClaimMapperRegistry,
	issuerRegistry Registry,
) *TokenService {
	return &TokenService{
		trustDomain:    trustDomain,
		dataSources:    dataSources,
		claimMappers:   claimMappers,
		issuerRegistry: issuerRegistry,
	}
}

// TrustDomain returns the trust domain for this token service
// The trust domain is used as the audience for all issued tokens
func (ts *TokenService) TrustDomain() string {
	return ts.trustDomain
}

// IssueRequest contains the inputs for token issuance
type IssueRequest struct {
	// Subject identity (attested claims from validated credential)
	Subject *trust.Result

	// Workload identity (attested claims from workload credential, e.g., mTLS)
	// May be nil if workload identity is not available
	Workload *trust.Result

	// RequestAttributes contains information about the request
	RequestAttributes *RequestAttributes

	// TokenTypes specifies which token types to issue
	TokenTypes []TokenType

	// Scope for the tokens
	Scope string
}

// RequestAttributes contains attributes about the incoming request
// This is raw request data that will be processed by claim mappers
type RequestAttributes struct {
	// Method is the HTTP method or RPC method name
	Method string

	// Path is the request path/resource being accessed
	Path string

	// IPAddress is the client IP address
	IPAddress string

	// UserAgent is the client user agent
	UserAgent string

	// Headers contains relevant HTTP headers
	Headers map[string]string

	// Additional arbitrary context
	Additional map[string]any
}

// IssueTokens orchestrates the complete token issuance process
// Returns a map of token type to issued token
func (ts *TokenService) IssueTokens(ctx context.Context, req *IssueRequest) (map[TokenType]*Token, error) {
	// 1. Fetch data from all data sources
	dataSourceInput := &DataSourceInput{
		Subject:           req.Subject,
		Workload:          req.Workload,
		RequestAttributes: req.RequestAttributes,
	}
	dataSourceResults := ts.dataSources.FetchAll(ctx, dataSourceInput)

	// 2. Build mapper input
	mapperInput := &MapperInput{
		Subject:           req.Subject,
		Workload:          req.Workload,
		RequestAttributes: req.RequestAttributes,
		DataSources:       dataSourceResults,
	}

	// 3. Apply claim mappers to build transaction context
	transactionContext, err := ts.claimMappers.MapTransactionContext(ctx, mapperInput)
	if err != nil {
		return nil, fmt.Errorf("failed to map transaction context: %w", err)
	}

	// 4. Apply claim mappers to build request context
	requestContext, err := ts.claimMappers.MapRequestContext(ctx, mapperInput)
	if err != nil {
		return nil, fmt.Errorf("failed to map request context: %w", err)
	}

	// 5. Build token context
	// Audience is always the trust domain per transaction token spec
	tokenCtx := &TokenContext{
		Subject:            req.Subject,
		Workload:           req.Workload,
		TransactionContext: transactionContext,
		RequestContext:     requestContext,
		Audience:           ts.trustDomain,
		Scope:              req.Scope,
	}

	// 6. Issue tokens for each requested type
	tokens := make(map[TokenType]*Token)
	for _, tokenType := range req.TokenTypes {
		iss, err := ts.issuerRegistry.GetIssuer(tokenType)
		if err != nil {
			return nil, fmt.Errorf("no issuer for token type %s: %w", tokenType, err)
		}

		token, err := iss.Issue(ctx, tokenCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to issue %s: %w", tokenType, err)
		}

		tokens[tokenType] = token
	}

	return tokens, nil
}
