package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alechenninger/parsec/internal/issuer"
	"github.com/alechenninger/parsec/internal/server"
	"github.com/alechenninger/parsec/internal/trust"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize components with stub implementations
	// TODO: Replace with real implementations

	// Create trust store with default trust domain
	trustStore := trust.NewStubStore()
	trustStore.AddDomain(&trust.Domain{
		Name:          "default",
		Issuer:        "bearer",
		ValidatorType: trust.CredentialTypeBearer,
	})

	// Add a stub validator
	stubValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	trustStore.AddValidator(trust.CredentialTypeBearer, "bearer", stubValidator)

	// Create data source registry
	dataSourceRegistry := issuer.NewDataSourceRegistry()
	// No data sources registered yet - can be added as needed

	// Create claim mapper registry
	claimMapperRegistry := issuer.NewClaimMapperRegistry()
	// Register a simple passthrough mapper for transaction context
	claimMapperRegistry.RegisterTransactionContext(issuer.NewPassthroughSubjectMapper())
	// Register request attributes mapper for request context
	claimMapperRegistry.RegisterRequestContext(issuer.NewRequestAttributesMapper())

	// Create issuer registry
	issuerRegistry := issuer.NewSimpleRegistry()
	// Register issuers for different token types
	txnTokenIssuer := issuer.NewStubIssuer("https://parsec.example.com", 5*time.Minute)
	issuerRegistry.Register(issuer.TokenTypeTransactionToken, txnTokenIssuer)
	// TODO: Register other token types as needed
	// issuerRegistry.Register(issuer.TokenTypeAccessToken, accessTokenIssuer)

	// Create token service
	// Trust domain is used as the audience for all issued tokens
	trustDomain := "parsec.example.com"
	tokenService := issuer.NewTokenService(trustDomain, dataSourceRegistry, claimMapperRegistry, issuerRegistry)

	// Create service handlers
	authzServer := server.NewAuthzServer(trustStore, tokenService)
	exchangeServer := server.NewExchangeServer(trustStore, tokenService)

	// Create server configuration
	cfg := server.Config{
		GRPCPort:       9090,
		HTTPPort:       8080,
		AuthzServer:    authzServer,
		ExchangeServer: exchangeServer,
	}

	// Create and start server
	srv := server.New(cfg)
	if err := srv.Start(ctx); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	fmt.Println("parsec is running")
	fmt.Println("  gRPC (ext_authz):     localhost:9090")
	fmt.Println("  HTTP (token exchange): http://localhost:8080/v1/token")
	fmt.Println()
	fmt.Println("Note: Using stub implementations for testing")

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nShutting down...")

	// Graceful shutdown
	if err := srv.Stop(ctx); err != nil {
		return fmt.Errorf("error during shutdown: %w", err)
	}

	fmt.Println("Shutdown complete")
	return nil
}
