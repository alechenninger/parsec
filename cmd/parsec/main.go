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
	"github.com/alechenninger/parsec/internal/validator"
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
		Issuer:        "default",
		ValidatorType: validator.CredentialTypeBearer,
	})

	// Add a stub validator
	stubValidator := validator.NewStubValidator(validator.CredentialTypeBearer)
	trustStore.AddValidator(validator.CredentialTypeBearer, "default", stubValidator)

	// Create issuer registry
	issuerRegistry := issuer.NewSimpleRegistry()

	// Register issuers for different token types
	txnTokenIssuer := issuer.NewStubIssuer("https://parsec.example.com", 5*time.Minute)
	issuerRegistry.Register(issuer.TokenTypeTransactionToken, txnTokenIssuer)

	// TODO: Register other token types as needed
	// issuerRegistry.Register(issuer.TokenTypeAccessToken, accessTokenIssuer)

	// Create service handlers
	authzServer := server.NewAuthzServer(trustStore, issuerRegistry)
	exchangeServer := server.NewExchangeServer(trustStore, issuerRegistry)

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
