package server

import (
	"context"
	"fmt"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/alechenninger/parsec/internal/issuer"
	"github.com/alechenninger/parsec/internal/trust"
)

// TokenTypeSpec specifies a token type to issue and how to deliver it
type TokenTypeSpec struct {
	// Type is the token type to issue
	Type issuer.TokenType

	// HeaderName is the HTTP header to use for this token
	// e.g., "Transaction-Token", "Authorization", "X-Custom-Token"
	HeaderName string
}

// AuthzServer implements Envoy's ext_authz Authorization service
type AuthzServer struct {
	authv3.UnimplementedAuthorizationServer

	trustStore   trust.Store
	tokenService *issuer.TokenService

	// TokenTypesToIssue specifies which token types to issue and their headers
	// This could come from configuration in the future
	TokenTypesToIssue []TokenTypeSpec
}

// NewAuthzServer creates a new ext_authz server
func NewAuthzServer(trustStore trust.Store, tokenService *issuer.TokenService) *AuthzServer {
	// Default: Issue transaction tokens
	// In the future, this could be configured per-route, per-domain, etc.
	return &AuthzServer{
		trustStore:   trustStore,
		tokenService: tokenService,
		TokenTypesToIssue: []TokenTypeSpec{
			{
				Type:       issuer.TokenTypeTransactionToken,
				HeaderName: "Transaction-Token",
			},
		},
	}
}

// Check implements the ext_authz check endpoint
func (s *AuthzServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	// 1. Extract credentials from request
	// The extraction layer returns both the credential and which headers were used
	cred, headersUsed, err := s.extractCredential(req)
	if err != nil {
		return s.denyResponse(codes.Unauthenticated, fmt.Sprintf("failed to extract credentials: %v", err)), nil
	}

	// 2. Validate credentials against trust store
	// The trust store determines the appropriate validator based on credential type and issuer
	result, err := s.trustStore.Validate(ctx, cred)
	if err != nil {
		return s.denyResponse(codes.Unauthenticated, fmt.Sprintf("validation failed: %v", err)), nil
	}

	// 3. Build request attributes
	reqAttrs := s.buildRequestAttributes(req)

	// 4. Extract workload identity (if available)
	// TODO: Extract from mTLS cert, SPIFFE header, etc.
	var workload *trust.Result = nil

	// 5. Issue tokens via TokenService
	tokenTypes := make([]issuer.TokenType, len(s.TokenTypesToIssue))
	for i, spec := range s.TokenTypesToIssue {
		tokenTypes[i] = spec.Type
	}

	issuedTokens, err := s.tokenService.IssueTokens(ctx, &issuer.IssueRequest{
		Subject:           result,
		Workload:          workload,
		RequestAttributes: reqAttrs,
		TokenTypes:        tokenTypes,
		// TODO: Get scope from configuration or request
		Scope: "",
	})
	if err != nil {
		return s.denyResponse(codes.Internal, fmt.Sprintf("failed to issue tokens: %v", err)), nil
	}

	// 6. Build response headers from issued tokens
	responseHeaders := make([]*corev3.HeaderValueOption, 0, len(issuedTokens))
	for _, spec := range s.TokenTypesToIssue {
		if token, ok := issuedTokens[spec.Type]; ok {
			responseHeaders = append(responseHeaders, &corev3.HeaderValueOption{
				Header: &corev3.HeaderValue{
					Key:   spec.HeaderName,
					Value: token.Value,
				},
			})
		}
	}

	// 7. Return OK with issued tokens in headers
	// Remove the external credential headers so they don't leak to backend
	// This creates a security boundary - external credentials stay outside
	return &authv3.CheckResponse{
		Status: &status.Status{
			Code: int32(codes.OK),
		},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: responseHeaders,
				// Remove external credential headers - security boundary
				HeadersToRemove: headersUsed,
			},
		},
	}, nil
}

// extractCredential extracts credentials from the Envoy request
// Returns the credential and the list of headers that were used to extract it
func (s *AuthzServer) extractCredential(req *authv3.CheckRequest) (trust.Credential, []string, error) {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	// TODO: mtls e.g. cert := req.GetAttributes().GetSource().GetCertificate()

	if httpReq == nil {
		return nil, nil, fmt.Errorf("no HTTP request attributes")
	}

	// Look for Authorization header
	authHeader := httpReq.GetHeaders()["authorization"]
	if authHeader == "" {
		return nil, nil, fmt.Errorf("no authorization header")
	}

	// Extract bearer token
	if token, ok := strings.CutPrefix(authHeader, "Bearer "); ok {
		// For bearer tokens, the trust store determines which validator to use
		// based on its configuration (e.g., default validator, token introspection)
		cred := &trust.BearerCredential{
			Token: token,
		}
		// Return the credential and the headers that were used
		headersUsed := []string{"authorization"}
		return cred, headersUsed, nil
	}

	// Future: Handle other authentication schemes
	// - Basic auth: would use "authorization" header
	// - API key in custom header: would track that header name
	// - Cookie-based auth: would track cookie names

	return nil, nil, fmt.Errorf("unsupported authorization scheme")
}

// buildRequestAttributes extracts request attributes from the Envoy request
func (s *AuthzServer) buildRequestAttributes(req *authv3.CheckRequest) *issuer.RequestAttributes {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	if httpReq == nil {
		return &issuer.RequestAttributes{}
	}

	return &issuer.RequestAttributes{
		Method:    httpReq.GetMethod(),
		Path:      httpReq.GetPath(),
		IPAddress: req.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetAddress(),
		UserAgent: httpReq.GetHeaders()["user-agent"],
		Headers:   httpReq.GetHeaders(),
		Additional: map[string]any{
			"host": httpReq.GetHost(),
		},
	}
}

// denyResponse creates a denial response
func (s *AuthzServer) denyResponse(code codes.Code, message string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &status.Status{
			Code:    int32(code),
			Message: message,
		},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Body: message,
			},
		},
	}
}
