package service

import (
	"context"
	"fmt"

	"github.com/alechenninger/parsec/internal/request"
	"github.com/alechenninger/parsec/internal/trust"
)

// TokenService orchestrates token issuance
// This is the core business logic that brings together data sources
// and issuers to produce tokens
type TokenService struct {
	trustDomain    string
	dataSources    *DataSourceRegistry
	issuerRegistry Registry
}

// NewTokenService creates a new token service
func NewTokenService(
	trustDomain string,
	dataSources *DataSourceRegistry,
	issuerRegistry Registry,
) *TokenService {
	return &TokenService{
		trustDomain:    trustDomain,
		dataSources:    dataSources,
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

	// Actor identity (attested claims from actor credential, e.g., mTLS)
	// May be nil if actor identity is not available
	Actor *trust.Result

	// RequestAttributes contains information about the request
	RequestAttributes *request.RequestAttributes

	// TokenTypes specifies which token types to issue
	TokenTypes []TokenType

	// Scope for the tokens
	Scope string
}

// IssueTokens orchestrates the complete token issuance process
// Returns a map of token type to issued token
func (ts *TokenService) IssueTokens(ctx context.Context, req *IssueRequest) (map[TokenType]*Token, error) {
	// Build issue context with base information needed for all issuers
	// Audience is always the trust domain per transaction token spec
	issueCtx := &IssueContext{
		Subject:            req.Subject,
		Actor:              req.Actor,
		RequestAttributes:  req.RequestAttributes,
		Audience:           ts.trustDomain,
		Scope:              req.Scope,
		DataSourceRegistry: ts.dataSources,
	}

	// Issue tokens for each requested type
	tokens := make(map[TokenType]*Token)
	for _, tokenType := range req.TokenTypes {
		iss, err := ts.issuerRegistry.GetIssuer(tokenType)
		if err != nil {
			return nil, fmt.Errorf("no issuer for token type %s: %w", tokenType, err)
		}

		token, err := iss.Issue(ctx, issueCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to issue %s: %w", tokenType, err)
		}

		tokens[tokenType] = token
	}

	return tokens, nil
}
