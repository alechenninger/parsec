package server

import (
	"context"
	"fmt"

	parsecv1 "github.com/alechenninger/parsec/api/gen/parsec/v1"
	"github.com/alechenninger/parsec/internal/issuer"
	"github.com/alechenninger/parsec/internal/request"
	"github.com/alechenninger/parsec/internal/trust"
)

// ExchangeServer implements the TokenExchange gRPC service
type ExchangeServer struct {
	parsecv1.UnimplementedTokenExchangeServer

	trustStore   trust.Store
	tokenService *issuer.TokenService
}

// NewExchangeServer creates a new token exchange server
func NewExchangeServer(trustStore trust.Store, tokenService *issuer.TokenService) *ExchangeServer {
	return &ExchangeServer{
		trustStore:   trustStore,
		tokenService: tokenService,
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
	cred := &trust.BearerCredential{
		Token: req.SubjectToken,
	}

	// Validate credential against trust store
	// The trust store determines the appropriate validator based on credential type and issuer
	result, err := s.trustStore.Validate(ctx, cred)
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

	// 4. Build request attributes
	reqAttrs := &request.RequestAttributes{
		Method: "TokenExchange",
		Path:   "/v1/token",
		Additional: map[string]any{
			"requested_audience": req.Audience,
			"requested_scope":    req.Scope,
		},
	}

	// 5. Validate audience matches trust domain (per transaction token spec)
	// The audience for transaction tokens is always the trust domain
	if req.Audience != "" && req.Audience != s.tokenService.TrustDomain() {
		return nil, fmt.Errorf("requested audience %q does not match trust domain %q",
			req.Audience, s.tokenService.TrustDomain())
	}

	// 6. Issue the token via TokenService
	// No workload identity in token exchange (it's an external call)
	tokens, err := s.tokenService.IssueTokens(ctx, &issuer.IssueRequest{
		Subject:           result,
		Workload:          nil,
		RequestAttributes: reqAttrs,
		TokenTypes:        []issuer.TokenType{requestedTokenType},
		Scope:             req.Scope,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to issue token: %w", err)
	}

	token, ok := tokens[requestedTokenType]
	if !ok {
		return nil, fmt.Errorf("token service did not return requested token type %s", requestedTokenType)
	}

	// 7. Return response
	return &parsecv1.TokenExchangeResponse{
		AccessToken:     token.Value,
		IssuedTokenType: string(requestedTokenType),
		TokenType:       "Bearer",
		ExpiresIn:       int64(token.ExpiresAt.Sub(token.IssuedAt).Seconds()),
		Scope:           req.Scope,
	}, nil
}
