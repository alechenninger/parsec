package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/alechenninger/parsec/internal/config"
	"github.com/alechenninger/parsec/internal/server"
)

// NewServeCmd creates the serve command
func NewServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the parsec server",
		Long: `Start the parsec gRPC and HTTP servers.

The server will:
  - Listen for gRPC requests (ext_authz, token exchange)
  - Listen for HTTP requests (token exchange via gRPC-gateway transcoding)
  - Load configuration from file, environment variables, and command-line flags

Configuration precedence (highest to lowest):
  1. Command-line flags
  2. Environment variables (PARSEC_*)
  3. Configuration file`,
		RunE: runServe,
	}

	// Server flags
	cmd.Flags().Int("grpc-port", 0, "gRPC server port (default: from config or 9090)")
	cmd.Flags().Int("http-port", 0, "HTTP server port (default: from config or 8080)")
	cmd.Flags().String("trust-domain", "", "trust domain for issued tokens (default: from config)")

	return cmd
}

func runServe(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Determine config file path
	configPath := configFile
	if configPath == "" {
		// Check environment variable
		configPath = os.Getenv("PARSEC_CONFIG")
	}
	if configPath == "" {
		// Default
		configPath = "./configs/parsec.yaml"
	}

	// 2. Load configuration (file + env vars + flags)
	loader, err := config.NewLoaderWithFlags(configPath, cmd.Flags())
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	cfg, err := loader.Get()
	if err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	// 3. Create provider to build all components from config
	provider := config.NewProvider(cfg)

	// 4. Build components via provider
	trustStore, err := provider.TrustStore()
	if err != nil {
		return fmt.Errorf("failed to create trust store: %w", err)
	}

	tokenService, err := provider.TokenService()
	if err != nil {
		return fmt.Errorf("failed to create token service: %w", err)
	}

	claimsFilterRegistry, err := provider.ClaimsFilterRegistry()
	if err != nil {
		return fmt.Errorf("failed to create claims filter registry: %w", err)
	}

	// 5. Create service handlers
	authzServer := server.NewAuthzServer(trustStore, tokenService)
	exchangeServer := server.NewExchangeServer(trustStore, tokenService, claimsFilterRegistry)

	// 6. Create server configuration
	serverCfg := provider.ServerConfig()
	serverCfg.AuthzServer = authzServer
	serverCfg.ExchangeServer = exchangeServer

	// 7. Create and start server
	srv := server.New(serverCfg)
	if err := srv.Start(ctx); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	fmt.Println("parsec is running")
	fmt.Printf("  gRPC (ext_authz):      localhost:%d\n", serverCfg.GRPCPort)
	fmt.Printf("  HTTP (token exchange): http://localhost:%d/v1/token\n", serverCfg.HTTPPort)
	fmt.Printf("  Trust Domain:          %s\n", provider.TrustDomain())
	fmt.Printf("  Config:                %s\n", configPath)

	// 8. Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nShutting down...")

	// 9. Graceful shutdown
	if err := srv.Stop(ctx); err != nil {
		return fmt.Errorf("error during shutdown: %w", err)
	}

	fmt.Println("Shutdown complete")
	return nil
}
