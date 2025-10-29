package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	spirekm "github.com/spiffe/spire/pkg/server/plugin/keymanager"

	"github.com/alechenninger/parsec/internal/issuer"
	"github.com/alechenninger/parsec/internal/keymanager"
	"github.com/alechenninger/parsec/internal/server"
	"github.com/alechenninger/parsec/internal/service"
	"github.com/alechenninger/parsec/internal/trust"
)

// TestJWKSEndpoint tests that the JWKS endpoint returns valid JSON Web Key Sets
func TestJWKSEndpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup dependencies
	trustStore := trust.NewStubStore()
	stubValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	trustStore.AddValidator(stubValidator)

	dataSourceRegistry := service.NewDataSourceRegistry()
	issuerRegistry := service.NewSimpleRegistry()

	// Create a signing transaction token issuer with a real key
	log := logrus.New()
	log.SetOutput(io.Discard)

	pluginHCL := `KeyManager "memory" {
		plugin_data {}
	}`

	spireKM, closer, err := keymanager.LoadKeyManagerFromHCL(ctx, pluginHCL, "test.example.org", log)
	if err != nil {
		t.Fatalf("Failed to load key manager: %v", err)
	}
	if closer != nil {
		defer closer.Close()
	}

	slotStore := keymanager.NewInMemoryKeySlotStore()
	rotatingKM := keymanager.NewRotatingKeyManager(keymanager.RotatingKeyManagerConfig{
		KeyManager: spireKM,
		SlotStore:  slotStore,
		KeyType:    spirekm.ECP256,
		Algorithm:  "ES256",
	})

	if err := rotatingKM.Start(ctx); err != nil {
		t.Fatalf("Failed to start rotating key manager: %v", err)
	}

	txnIssuer := issuer.NewSigningTransactionTokenIssuer(issuer.SigningTransactionTokenIssuerConfig{
		IssuerURL:                 "https://parsec.test",
		TTL:                       5 * time.Minute,
		KeyManager:                rotatingKM,
		TransactionContextMappers: []service.ClaimMapper{service.NewPassthroughSubjectMapper()},
		RequestContextMappers:     []service.ClaimMapper{service.NewRequestAttributesMapper()},
	})

	issuerRegistry.Register(service.TokenTypeTransactionToken, txnIssuer)

	trustDomain := "parsec.test"
	tokenService := service.NewTokenService(trustDomain, dataSourceRegistry, issuerRegistry)

	// Create claims filter registry
	claimsFilterRegistry := server.NewStubClaimsFilterRegistry()

	// Start server
	srv := server.New(server.Config{
		GRPCPort:       19092,
		HTTPPort:       18082,
		AuthzServer:    server.NewAuthzServer(trustStore, tokenService, nil),
		ExchangeServer: server.NewExchangeServer(trustStore, tokenService, claimsFilterRegistry),
		JWKSServer:     server.NewJWKSServer(server.JWKSServerConfig{IssuerRegistry: issuerRegistry}),
	})

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer srv.Stop(ctx)

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	t.Run("GET /v1/jwks.json", func(t *testing.T) {
		testJWKSEndpoint(t, "http://localhost:18082/v1/jwks.json")
	})

	t.Run("GET /.well-known/jwks.json", func(t *testing.T) {
		testJWKSEndpoint(t, "http://localhost:18082/.well-known/jwks.json")
	})
}

func testJWKSEndpoint(t *testing.T, url string) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify content type is JSON
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Logf("Warning: Expected Content-Type 'application/json', got '%s'", contentType)
	}

	// Parse the JWKS response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}

	if err := json.Unmarshal(body, &jwks); err != nil {
		t.Fatalf("Failed to parse JWKS JSON: %v", err)
	}

	// Verify we have at least one key
	if len(jwks.Keys) == 0 {
		t.Fatal("Expected at least one key in JWKS, got none")
	}

	// Verify the key has required fields per RFC 7517
	key := jwks.Keys[0]

	requiredFields := []string{"kty", "kid", "alg"}
	for _, field := range requiredFields {
		if _, ok := key[field]; !ok {
			t.Errorf("Key missing required field: %s", field)
		}
	}

	// For EC keys, verify curve-specific fields
	if key["kty"] == "EC" {
		ecFields := []string{"crv", "x", "y"}
		for _, field := range ecFields {
			if _, ok := key[field]; !ok {
				t.Errorf("EC key missing required field: %s", field)
			}
		}

		// Verify the curve is P-256 (as configured)
		if key["crv"] != "P-256" {
			t.Errorf("Expected curve P-256, got %v", key["crv"])
		}

		// Verify algorithm
		if key["alg"] != "ES256" {
			t.Errorf("Expected algorithm ES256, got %v", key["alg"])
		}
	}

	// Verify 'use' field if present (should be 'sig' for signing keys)
	if use, ok := key["use"]; ok {
		if use != "sig" {
			t.Errorf("Expected use 'sig', got %v", use)
		}
	}

	t.Logf("✓ JWKS endpoint returned valid key set")
	t.Logf("  Key type: %v", key["kty"])
	t.Logf("  Key ID: %v", key["kid"])
	t.Logf("  Algorithm: %v", key["alg"])
	if key["kty"] == "EC" {
		t.Logf("  Curve: %v", key["crv"])
	}
}

// TestJWKSWithMultipleIssuers tests that JWKS returns keys from multiple issuers
func TestJWKSWithMultipleIssuers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup dependencies
	trustStore := trust.NewStubStore()
	stubValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	trustStore.AddValidator(stubValidator)

	dataSourceRegistry := service.NewDataSourceRegistry()
	issuerRegistry := service.NewSimpleRegistry()

	// Create first issuer (transaction token with signing)
	log := logrus.New()
	log.SetOutput(io.Discard)

	pluginHCL1 := `KeyManager "memory" {
		plugin_data {}
	}`

	spireKM1, closer1, err := keymanager.LoadKeyManagerFromHCL(ctx, pluginHCL1, "test.example.org", log)
	if err != nil {
		t.Fatalf("Failed to load key manager 1: %v", err)
	}
	if closer1 != nil {
		defer closer1.Close()
	}

	slotStore1 := keymanager.NewInMemoryKeySlotStore()
	rotatingKM1 := keymanager.NewRotatingKeyManager(keymanager.RotatingKeyManagerConfig{
		KeyManager: spireKM1,
		SlotStore:  slotStore1,
		KeyType:    spirekm.ECP256,
		Algorithm:  "ES256",
	})

	if err := rotatingKM1.Start(ctx); err != nil {
		t.Fatalf("Failed to start rotating key manager 1: %v", err)
	}

	txnIssuer := issuer.NewSigningTransactionTokenIssuer(issuer.SigningTransactionTokenIssuerConfig{
		IssuerURL:                 "https://parsec.test",
		TTL:                       5 * time.Minute,
		KeyManager:                rotatingKM1,
		TransactionContextMappers: []service.ClaimMapper{service.NewPassthroughSubjectMapper()},
		RequestContextMappers:     []service.ClaimMapper{service.NewRequestAttributesMapper()},
	})

	issuerRegistry.Register(service.TokenTypeTransactionToken, txnIssuer)

	// Create second issuer (access token with different key)
	pluginHCL2 := `KeyManager "memory" {
		plugin_data {}
	}`

	spireKM2, closer2, err := keymanager.LoadKeyManagerFromHCL(ctx, pluginHCL2, "test.example.org", log)
	if err != nil {
		t.Fatalf("Failed to load key manager 2: %v", err)
	}
	if closer2 != nil {
		defer closer2.Close()
	}

	slotStore2 := keymanager.NewInMemoryKeySlotStore()
	rotatingKM2 := keymanager.NewRotatingKeyManager(keymanager.RotatingKeyManagerConfig{
		KeyManager: spireKM2,
		SlotStore:  slotStore2,
		KeyType:    spirekm.ECP384,
		Algorithm:  "ES384",
	})

	if err := rotatingKM2.Start(ctx); err != nil {
		t.Fatalf("Failed to start rotating key manager 2: %v", err)
	}

	accessIssuer := issuer.NewSigningTransactionTokenIssuer(issuer.SigningTransactionTokenIssuerConfig{
		IssuerURL:                 "https://parsec.test",
		TTL:                       15 * time.Minute,
		KeyManager:                rotatingKM2,
		TransactionContextMappers: []service.ClaimMapper{service.NewPassthroughSubjectMapper()},
		RequestContextMappers:     []service.ClaimMapper{},
	})

	issuerRegistry.Register(service.TokenTypeAccessToken, accessIssuer)

	trustDomain := "parsec.test"
	tokenService := service.NewTokenService(trustDomain, dataSourceRegistry, issuerRegistry)

	// Create claims filter registry
	claimsFilterRegistry := server.NewStubClaimsFilterRegistry()

	// Start server
	srv := server.New(server.Config{
		GRPCPort:       19093,
		HTTPPort:       18083,
		AuthzServer:    server.NewAuthzServer(trustStore, tokenService, nil),
		ExchangeServer: server.NewExchangeServer(trustStore, tokenService, claimsFilterRegistry),
		JWKSServer:     server.NewJWKSServer(server.JWKSServerConfig{IssuerRegistry: issuerRegistry}),
	})

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer srv.Stop(ctx)

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Request JWKS
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://localhost:18083/v1/jwks.json")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}

	if err := json.Unmarshal(body, &jwks); err != nil {
		t.Fatalf("Failed to parse JWKS JSON: %v", err)
	}

	// Verify we have keys from both issuers
	if len(jwks.Keys) < 2 {
		t.Fatalf("Expected at least 2 keys (one per issuer), got %d", len(jwks.Keys))
	}

	// Verify we have different curves
	curves := make(map[string]bool)
	for _, key := range jwks.Keys {
		if crv, ok := key["crv"]; ok {
			curves[crv.(string)] = true
		}
	}

	if len(curves) < 2 {
		t.Errorf("Expected keys with different curves, got: %v", curves)
	}

	t.Logf("✓ JWKS endpoint returned keys from multiple issuers")
	t.Logf("  Total keys: %d", len(jwks.Keys))
	t.Logf("  Curves: %v", curves)
}

// TestJWKSWithUnsignedIssuer tests that unsigned issuers don't contribute keys to JWKS
func TestJWKSWithUnsignedIssuer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup dependencies
	trustStore := trust.NewStubStore()
	stubValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	trustStore.AddValidator(stubValidator)

	dataSourceRegistry := service.NewDataSourceRegistry()
	issuerRegistry := service.NewSimpleRegistry()

	// Create an unsigned issuer (no public keys)
	unsignedIssuer := issuer.NewUnsignedIssuer(issuer.UnsignedIssuerConfig{
		TokenType:    string(service.TokenTypeTransactionToken),
		ClaimMappers: []service.ClaimMapper{service.NewPassthroughSubjectMapper()},
	})

	issuerRegistry.Register(service.TokenTypeTransactionToken, unsignedIssuer)

	trustDomain := "parsec.test"
	tokenService := service.NewTokenService(trustDomain, dataSourceRegistry, issuerRegistry)

	// Create claims filter registry
	claimsFilterRegistry := server.NewStubClaimsFilterRegistry()

	// Start server
	srv := server.New(server.Config{
		GRPCPort:       19094,
		HTTPPort:       18084,
		AuthzServer:    server.NewAuthzServer(trustStore, tokenService, nil),
		ExchangeServer: server.NewExchangeServer(trustStore, tokenService, claimsFilterRegistry),
		JWKSServer:     server.NewJWKSServer(server.JWKSServerConfig{IssuerRegistry: issuerRegistry}),
	})

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer srv.Stop(ctx)

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Request JWKS
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://localhost:18084/v1/jwks.json")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}

	if err := json.Unmarshal(body, &jwks); err != nil {
		t.Fatalf("Failed to parse JWKS JSON: %v", err)
	}

	// Verify we have no keys (unsigned issuer doesn't provide public keys)
	if len(jwks.Keys) != 0 {
		t.Errorf("Expected 0 keys from unsigned issuer, got %d", len(jwks.Keys))
	}

	t.Logf("✓ JWKS endpoint correctly returns empty set for unsigned issuer")
}
