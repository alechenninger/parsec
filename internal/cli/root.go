package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Global flags
	configFile string
)

// NewRootCmd creates the root command for parsec
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "parsec",
		Short: "parsec - OAuth 2.0 Token Exchange and ext_authz service",
		Long: `parsec is a gRPC-first service that implements:
  1. Envoy ext_authz (gRPC) - for authorization at the perimeter
  2. OAuth 2.0 Token Exchange (HTTP via gRPC transcoding) - RFC 8693 compliant

Both services issue transaction tokens following the draft-ietf-oauth-transaction-tokens specification.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Global flags available to all commands
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "config file path (default: ./configs/parsec.yaml)")

	// Add subcommands
	rootCmd.AddCommand(NewServeCmd())

	return rootCmd
}

// Execute runs the root command
func Execute() {
	rootCmd := NewRootCmd()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
