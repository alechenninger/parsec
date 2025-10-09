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

	// 2. Build request attributes
	reqAttrs := &request.RequestAttributes{
		Method: "TokenExchange",
		Path:   "/v1/token",
		Additional: map[string]any{
			"requested_audience": req.Audience,
			"requested_scope":    req.Scope,
		},
	}

	// 3. Extract actor credential from gRPC context
	actorCred, err := extractActorCredential(ctx)
	var actor *trust.Result
	if actorCred != nil {
		actor, err = s.trustStore.Validate(ctx, actorCred)
		if err != nil {
			return nil, fmt.Errorf("actor validation failed: %w", err)
		}
	} else {
		actor = trust.AnonymousResult()
	}

	// 4. Filter trust store based on actor permissions
	filteredStore, err := s.trustStore.ForActor(ctx, actor, reqAttrs)
	if err != nil {
		return nil, fmt.Errorf("failed to filter trust store: %w", err)
	}

	// 5. Validate subject_token
	// Create strongly-typed credential based on token type
	// In production, we'd parse the token_type to determine the specific credential type
	// For now, we'll treat all as bearer tokens
	// TODO: Parse subject_token_type to determine specific credential type (JWT, OIDC, etc.)
	cred := &trust.BearerCredential{
		Token: req.SubjectToken,
	}

	// Validate subject credential against filtered trust store
	// The filtered store only includes validators the actor is allowed to use
	result, err := filteredStore.Validate(ctx, cred)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// 6. Determine which token type to issue
	// RFC 8693: If requested_token_type is not specified, default to access_token
	// For parsec, we default to transaction tokens
	requestedTokenType := issuer.TokenTypeTransactionToken
	if req.RequestedTokenType != "" {
		requestedTokenType = issuer.TokenType(req.RequestedTokenType)
	}

	// 7. Validate audience matches trust domain (per transaction token spec)
	// The audience for transaction tokens is always the trust domain
	if req.Audience != "" && req.Audience != s.tokenService.TrustDomain() {
		return nil, fmt.Errorf("requested audience %q does not match trust domain %q",
			req.Audience, s.tokenService.TrustDomain())
	}

	// 8. Issue the token via TokenService
	tokens, err := s.tokenService.IssueTokens(ctx, &issuer.IssueRequest{
		Subject:           result,
		Actor:             actor,
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

	// 9. Return response
	return &parsecv1.TokenExchangeResponse{
		AccessToken:     token.Value,
		IssuedTokenType: string(requestedTokenType),
		TokenType:       "Bearer",
		ExpiresIn:       int64(token.ExpiresAt.Sub(token.IssuedAt).Seconds()),
		Scope:           req.Scope,
	}, nil
}
