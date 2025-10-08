package server

import (
	"context"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/alechenninger/parsec/internal/issuer"
	"github.com/alechenninger/parsec/internal/trust"
)

func TestAuthzServer_Check(t *testing.T) {
	ctx := context.Background()

	// Setup dependencies
	trustStore := trust.NewStubStore()
	trustStore.AddDomain(&trust.Domain{
		Name:          "default",
		Issuer:        "bearer",
		ValidatorType: trust.CredentialTypeBearer,
	})

	stubValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	trustStore.AddValidator(trust.CredentialTypeBearer, "bearer", stubValidator)

	// Setup token service
	dataSourceRegistry := issuer.NewDataSourceRegistry()
	claimMapperRegistry := issuer.NewClaimMapperRegistry()
	claimMapperRegistry.RegisterTransactionContext(issuer.NewPassthroughSubjectMapper())
	claimMapperRegistry.RegisterRequestContext(issuer.NewRequestAttributesMapper())

	issuerRegistry := issuer.NewSimpleRegistry()
	txnTokenIssuer := issuer.NewStubIssuer("https://parsec.test", 5*time.Minute)
	issuerRegistry.Register(issuer.TokenTypeTransactionToken, txnTokenIssuer)

	trustDomain := "parsec.test"
	tokenService := issuer.NewTokenService(trustDomain, dataSourceRegistry, claimMapperRegistry, issuerRegistry)

	authzServer := NewAuthzServer(trustStore, tokenService)

	t.Run("successful authorization", func(t *testing.T) {
		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/resource",
						Headers: map[string]string{
							"authorization": "Bearer test-token-123",
						},
					},
				},
				Source: &authv3.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{
								Address: "192.168.1.1",
							},
						},
					},
				},
			},
		}

		resp, err := authzServer.Check(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Check status
		if resp.Status.Code != 0 { // 0 == OK
			t.Errorf("expected OK status, got code %d: %s", resp.Status.Code, resp.Status.Message)
		}

		// Check OK response
		okResp := resp.GetOkResponse()
		if okResp == nil {
			t.Fatal("expected OK response, got nil")
		}

		// Check transaction token header is present
		foundToken := false
		for _, header := range okResp.Headers {
			if header.Header.Key == "Transaction-Token" {
				foundToken = true
				if header.Header.Value == "" {
					t.Error("transaction token value is empty")
				}
			}
		}
		if !foundToken {
			t.Error("transaction token header not found")
		}

		// Check that authorization header is removed
		if len(okResp.HeadersToRemove) == 0 {
			t.Error("expected headers to be removed, got none")
		}

		foundAuthRemoval := false
		for _, headerName := range okResp.HeadersToRemove {
			if headerName == "authorization" {
				foundAuthRemoval = true
			}
		}
		if !foundAuthRemoval {
			t.Errorf("authorization header not in removal list. Headers to remove: %v", okResp.HeadersToRemove)
		}
	})

	t.Run("missing authorization header", func(t *testing.T) {
		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method:  "GET",
						Path:    "/api/resource",
						Headers: map[string]string{},
					},
				},
			},
		}

		resp, err := authzServer.Check(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should deny
		if resp.Status.Code == 0 {
			t.Error("expected denial, got OK")
		}

		deniedResp := resp.GetDeniedResponse()
		if deniedResp == nil {
			t.Fatal("expected denied response, got nil")
		}
	})

	t.Run("invalid bearer token", func(t *testing.T) {
		// Configure validator to reject
		stubValidator.WithError(trust.ErrInvalidToken)

		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/resource",
						Headers: map[string]string{
							"authorization": "Bearer invalid-token",
						},
					},
				},
			},
		}

		resp, err := authzServer.Check(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should deny
		if resp.Status.Code == 0 {
			t.Error("expected denial, got OK")
		}

		// Reset validator for other tests
		stubValidator.WithError(nil)
	})
}
