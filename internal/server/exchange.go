package server

import (
	"context"

	parsecv1 "github.com/alechenninger/parsec/api/gen/parsec/v1"
)

// ExchangeServer implements the TokenExchange gRPC service
type ExchangeServer struct {
	parsecv1.UnimplementedTokenExchangeServer
}

// NewExchangeServer creates a new token exchange server
func NewExchangeServer() *ExchangeServer {
	return &ExchangeServer{}
}

// Exchange implements the token exchange endpoint (RFC 8693)
func (s *ExchangeServer) Exchange(ctx context.Context, req *parsecv1.TokenExchangeRequest) (*parsecv1.TokenExchangeResponse, error) {
	// TODO: Implement token exchange logic
	// 1. Validate subject_token
	// 2. Issue transaction token
	// 3. Return response
	
	return &parsecv1.TokenExchangeResponse{
		AccessToken:      "TODO-implement-token-generation",
		IssuedTokenType:  "urn:ietf:params:oauth:token-type:txn_token",
		TokenType:        "Bearer",
		ExpiresIn:        300, // 5 minutes
	}, nil
}

