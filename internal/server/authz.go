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
	"github.com/alechenninger/parsec/internal/validator"
)

// TokenTypeSpec specifies a token type to issue and how to deliver it
type TokenTypeSpec struct {
	// Type is the token type to issue
	Type issuer.TokenType

	// HeaderName is the HTTP header to use for this token
	// e.g., "Transaction-Token", "Authorization", "X-Custom-Token"
	HeaderName string
}

// IssuedTokens contains the issued tokens
type IssuedTokens struct {
	// Tokens maps token types to their issued tokens
	Tokens map[issuer.TokenType]*issuer.Token
}

// AuthzServer implements Envoy's ext_authz Authorization service
type AuthzServer struct {
	authv3.UnimplementedAuthorizationServer

	trustStore     trust.Store
	issuerRegistry issuer.Registry

	// TokenTypesToIssue specifies which token types to issue and their headers
	// This could come from configuration in the future
	TokenTypesToIssue []TokenTypeSpec
}

// NewAuthzServer creates a new ext_authz server
func NewAuthzServer(trustStore trust.Store, issuerRegistry issuer.Registry) *AuthzServer {
	// Default: Issue transaction tokens
	// In the future, this could be configured per-route, per-domain, etc.
	return &AuthzServer{
		trustStore:     trustStore,
		issuerRegistry: issuerRegistry,
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
	// Use the issuer from the credential to look up the appropriate validator
	val, err := s.trustStore.ValidatorFor(ctx, cred.Type(), cred.Issuer())
	if err != nil {
		return s.denyResponse(codes.Unauthenticated, fmt.Sprintf("no validator available for issuer %s: %v", cred.Issuer(), err)), nil
	}

	result, err := val.Validate(ctx, cred)
	if err != nil {
		return s.denyResponse(codes.Unauthenticated, fmt.Sprintf("validation failed: %v", err)), nil
	}

	// 3. Issue tokens based on configuration
	reqCtx := s.buildRequestContext(req)
	issuedTokens, err := s.issueTokens(ctx, result, reqCtx)
	if err != nil {
		return s.denyResponse(codes.Internal, fmt.Sprintf("failed to issue tokens: %v", err)), nil
	}

	// 4. Build response headers from issued tokens
	responseHeaders := make([]*corev3.HeaderValueOption, 0, len(issuedTokens.Tokens))
	for _, spec := range s.TokenTypesToIssue {
		if token, ok := issuedTokens.Tokens[spec.Type]; ok {
			responseHeaders = append(responseHeaders, &corev3.HeaderValueOption{
				Header: &corev3.HeaderValue{
					Key:   spec.HeaderName,
					Value: token.Value,
				},
			})
		}
	}

	// 5. Return OK with issued tokens in headers
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

// issueTokens issues all configured token types
func (s *AuthzServer) issueTokens(ctx context.Context, result *validator.Result, reqCtx *issuer.RequestContext) (*IssuedTokens, error) {
	tokens := make(map[issuer.TokenType]*issuer.Token)

	for _, spec := range s.TokenTypesToIssue {
		// Get the issuer for this token type
		iss, err := s.issuerRegistry.GetIssuer(spec.Type)
		if err != nil {
			return nil, fmt.Errorf("failed to get issuer for %s: %w", spec.Type, err)
		}

		// Issue the token
		token, err := iss.Issue(ctx, result, reqCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to issue %s: %w", spec.Type, err)
		}

		tokens[spec.Type] = token
	}

	return &IssuedTokens{Tokens: tokens}, nil
}

// extractCredential extracts credentials from the Envoy request
// Returns the credential and the list of headers that were used to extract it
func (s *AuthzServer) extractCredential(req *authv3.CheckRequest) (validator.Credential, []string, error) {
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

		// For bearer tokens, we need to determine the issuer
		// Options:
		// 1. For JWT: Parse token and extract "iss" claim
		// 2. For opaque tokens: Use default/configured issuer
		// TODO: Parse JWT to get actual issuer
		// For now, use "default" as a placeholder

		// One way we could do this is perhaps have a bearer credential factory.
		// This can then just return a token and figure out the issuer as part of the factory method.
		// e.g. if the factory method detects a JWT, it can parse the token and extract the issuer.
		// (rather than here which directly provided the state to a credential struct)
		// This factory could then have state of its own, such as a default trust domain for bearer tokens,
		// or some other way to understand issuer from a bearer token (e.g. PSK)
		issuer := "default"

		cred := &validator.BearerCredential{
			Token:          token,
			IssuerIdentity: issuer,
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

// buildRequestContext creates request context from Envoy request
func (s *AuthzServer) buildRequestContext(req *authv3.CheckRequest) *issuer.RequestContext {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	if httpReq == nil {
		return &issuer.RequestContext{}
	}

	return &issuer.RequestContext{
		Method:    httpReq.GetMethod(),
		Path:      httpReq.GetPath(),
		IPAddress: req.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetAddress(),
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
