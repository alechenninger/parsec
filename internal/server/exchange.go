package server

import (
	"context"
	"fmt"

	parsecv1 "github.com/alechenninger/parsec/api/gen/parsec/v1"
	"github.com/alechenninger/parsec/internal/issuer"
	"github.com/alechenninger/parsec/internal/trust"
	"github.com/alechenninger/parsec/internal/validator"
)

// ExchangeServer implements the TokenExchange gRPC service
type ExchangeServer struct {
	parsecv1.UnimplementedTokenExchangeServer

	trustStore     trust.Store
	issuerRegistry issuer.Registry
}

// NewExchangeServer creates a new token exchange server
func NewExchangeServer(trustStore trust.Store, issuerRegistry issuer.Registry) *ExchangeServer {
	return &ExchangeServer{
		trustStore:     trustStore,
		issuerRegistry: issuerRegistry,
	}
}

// Exchange implements the token exchange endpoint (RFC 8693)
func (s *ExchangeServer) Exchange(ctx context.Context, req *parsecv1.TokenExchangeRequest) (*parsecv1.TokenExchangeResponse, error) {
	// 1. Validate the grant type
	if req.GrantType != "urn:ietf:params:oauth:grant-type:token-exchange" {
		return nil, fmt.Errorf("unsupported grant_type: %s", req.GrantType)
	}

	// 2. Validate subject_token
	// Create strongly-typed credential based on token type
	// In production, we'd parse the token_type to determine the specific credential type
	// For now, we'll treat all as bearer tokens
	// TODO: Parse subject_token_type to determine specific credential type (JWT, OIDC, etc.)
	// TODO: Parse token to extract actual issuer (for JWT/OIDC)
	cred := &validator.BearerCredential{
		Token:          req.SubjectToken,
		IssuerIdentity: "default", // TODO: Extract from token
	}

	// Get validator based on credential type and issuer
	val, err := s.trustStore.ValidatorFor(ctx, cred.Type(), cred.Issuer())
	if err != nil {
		return nil, fmt.Errorf("no validator available for issuer %s: %w", cred.Issuer(), err)
	}

	result, err := val.Validate(ctx, cred)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// 3. Determine which token type to issue
	// RFC 8693: If requested_token_type is not specified, default to access_token
	// For parsec, we default to transaction tokens
	requestedTokenType := issuer.TokenTypeTransactionToken
	if req.RequestedTokenType != "" {
		requestedTokenType = issuer.TokenType(req.RequestedTokenType)
	}

	// Get the issuer for the requested token type
	iss, err := s.issuerRegistry.GetIssuer(requestedTokenType)
	if err != nil {
		return nil, fmt.Errorf("unsupported requested_token_type %s: %w", requestedTokenType, err)
	}

	// 4. Issue the token
	reqCtx := &issuer.RequestContext{
		Method: "TokenExchange",
		Path:   "/v1/token",
		Additional: map[string]any{
			"requested_audience": req.Audience,
			"requested_scope":    req.Scope,
		},
	}

	token, err := iss.Issue(ctx, result, reqCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to issue token: %w", err)
	}

	// 5. Return response
	return &parsecv1.TokenExchangeResponse{
		AccessToken:     token.Value,
		IssuedTokenType: string(requestedTokenType),
		TokenType:       "Bearer",
		ExpiresIn:       int64(token.ExpiresAt.Sub(token.IssuedAt).Seconds()),
		Scope:           req.Scope,
	}, nil
}
