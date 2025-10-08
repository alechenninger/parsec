package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alechenninger/parsec/internal/issuer"
	"github.com/alechenninger/parsec/internal/server"
	"github.com/alechenninger/parsec/internal/trust"
	"github.com/alechenninger/parsec/internal/validator"
)

// setupTestDependencies creates stub implementations for testing
func setupTestDependencies() (trust.Store, *issuer.TokenService) {
	trustStore := trust.NewStubStore()
	trustStore.AddDomain(&trust.Domain{
		Name:          "default",
		Issuer:        "default",
		ValidatorType: validator.CredentialTypeBearer,
	})

	stubValidator := validator.NewStubValidator(validator.CredentialTypeBearer)
	trustStore.AddValidator(validator.CredentialTypeBearer, "default", stubValidator)

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

	return trustStore, tokenService
}

// TestTokenExchangeFormEncoded tests that the token exchange endpoint
// accepts application/x-www-form-urlencoded requests per RFC 8693
func TestTokenExchangeFormEncoded(t *testing.T) {
	// Set up dependencies
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	trustStore, tokenService := setupTestDependencies()

	// Start server
	srv := server.New(server.Config{
		GRPCPort:       19090,
		HTTPPort:       18080,
		AuthzServer:    server.NewAuthzServer(trustStore, tokenService),
		ExchangeServer: server.NewExchangeServer(trustStore, tokenService),
	})

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer srv.Stop(ctx)

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Prepare form-encoded request (RFC 8693 format)
	formData := url.Values{}
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	formData.Set("subject_token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test")
	formData.Set("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
	formData.Set("audience", "parsec.test") // Must match trust domain

	// Make request
	req, err := http.NewRequest(
		"POST",
		"http://localhost:18080/v1/token",
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Critical: Set the content type to form-urlencoded
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", resp.StatusCode, body)
	}

	// Verify response contains expected fields (even though it's a stub)
	responseStr := string(body)
	if !strings.Contains(responseStr, "access_token") {
		t.Errorf("Response missing access_token field: %s", responseStr)
	}

	if !strings.Contains(responseStr, "token_type") {
		t.Errorf("Response missing token_type field: %s", responseStr)
	}

	fmt.Printf("✓ Token exchange request with form encoding succeeded\n")
	fmt.Printf("  Response: %s\n", responseStr)
}

// TestTokenExchangeJSON tests that the endpoint still accepts JSON
// for clients that prefer gRPC-style requests
func TestTokenExchangeJSON(t *testing.T) {
	// Set up dependencies
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	trustStore, tokenService := setupTestDependencies()

	// Start server
	srv := server.New(server.Config{
		GRPCPort:       19091,
		HTTPPort:       18081,
		AuthzServer:    server.NewAuthzServer(trustStore, tokenService),
		ExchangeServer: server.NewExchangeServer(trustStore, tokenService),
	})

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer srv.Stop(ctx)

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Prepare JSON request
	jsonData := `{
		"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
		"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
		"audience": "parsec.test"
	}`

	// Make request
	req, err := http.NewRequest(
		"POST",
		"http://localhost:18081/v1/token",
		strings.NewReader(jsonData),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", resp.StatusCode, body)
	}

	fmt.Printf("✓ Token exchange request with JSON succeeded\n")
	fmt.Printf("  Response: %s\n", body)
}
