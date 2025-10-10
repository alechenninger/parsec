package config

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/parsers/toml/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/v2"
	"github.com/spf13/pflag"
)

// Loader is a lightweight wrapper around koanf for loading configuration
// from files and environment variables
type Loader struct {
	k          *koanf.Koanf
	configPath string
}

// NewLoader creates a new configuration loader that reads from a file
// and overlays environment variable overrides with PARSEC_ prefix.
//
// The file format (YAML, JSON, or TOML) is auto-detected from the extension.
// Environment variables like PARSEC_SERVER__GRPC_PORT map to server.grpc_port
//
// Configuration precedence: env vars > config file
func NewLoader(configPath string) (*Loader, error) {
	return newLoader(configPath, nil)
}

// NewLoaderWithFlags creates a new configuration loader with command-line flag support.
//
// Configuration precedence (highest to lowest):
//  1. Command-line flags
//  2. Environment variables (PARSEC_*)
//  3. Configuration file
func NewLoaderWithFlags(configPath string, flags *pflag.FlagSet) (*Loader, error) {
	return newLoader(configPath, flags)
}

// newLoader is the internal loader implementation
func newLoader(configPath string, flags *pflag.FlagSet) (*Loader, error) {
	k := koanf.New(".")

	// Auto-detect parser based on file extension
	parser, err := getParserForFile(configPath)
	if err != nil {
		return nil, err
	}

	// Load from file
	if err := k.Load(file.Provider(configPath), parser); err != nil {
		return nil, fmt.Errorf("failed to load config file %s: %w", configPath, err)
	}

	// Load environment variable overrides with PARSEC_ prefix
	// Use double underscore (__) for nesting: PARSEC_SERVER__GRPC_PORT -> server.grpc_port
	// Single underscore is part of the field name: PARSEC_TRUST_DOMAIN -> trust_domain
	if err := k.Load(env.Provider("PARSEC_", ".", envTransform), nil); err != nil {
		return nil, fmt.Errorf("failed to load environment variables: %w", err)
	}

	// Load command-line flags (highest precedence)
	if flags != nil {
		// Map flag names to config keys
		// grpc-port -> server.grpc_port
		// http-port -> server.http_port
		// trust-domain -> trust_domain
		if err := k.Load(posflag.ProviderWithFlag(flags, ".", k, func(f *pflag.Flag) (string, interface{}) {
			key := flagToConfigKey(f.Name)
			// Only override if the flag was explicitly set
			if !f.Changed {
				return "", nil
			}
			return key, posflag.FlagVal(flags, f)
		}), nil); err != nil {
			return nil, fmt.Errorf("failed to load command-line flags: %w", err)
		}
	}

	return &Loader{
		k:          k,
		configPath: configPath,
	}, nil
}

// Get unmarshals the configuration into a Config struct
func (l *Loader) Get() (*Config, error) {
	var cfg Config
	if err := l.k.Unmarshal("", &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	return &cfg, nil
}

// Watch watches the config file for changes and calls onChange with the new config.
// This runs until the context is cancelled or an error occurs.
//
// Note: Not all components can be safely hot-reloaded. Use with caution in production.
func (l *Loader) Watch(ctx context.Context, onChange func(*Config) error) error {
	// Use file provider with watch enabled
	fp := file.Provider(l.configPath)

	// Set up file watcher
	if err := fp.Watch(func(event interface{}, err error) {
		if err != nil {
			// Log error but continue watching
			fmt.Printf("config watch error: %v\n", err)
			return
		}

		// Reload the config
		parser, err := getParserForFile(l.configPath)
		if err != nil {
			fmt.Printf("config parser error: %v\n", err)
			return
		}

		// Create new koanf instance for reload
		k := koanf.New(".")
		if err := k.Load(fp, parser); err != nil {
			fmt.Printf("config reload error: %v\n", err)
			return
		}

		// Reload env vars
		if err := k.Load(env.Provider("PARSEC_", ".", envTransform), nil); err != nil {
			fmt.Printf("env reload error: %v\n", err)
			return
		}

		// Unmarshal new config
		var cfg Config
		if err := k.Unmarshal("", &cfg); err != nil {
			fmt.Printf("config unmarshal error: %v\n", err)
			return
		}

		// Update loader's koanf instance
		l.k = k

		// Call onChange callback
		if err := onChange(&cfg); err != nil {
			fmt.Printf("config onChange error: %v\n", err)
		}
	}); err != nil {
		return fmt.Errorf("failed to watch config file: %w", err)
	}

	// Block until context is cancelled
	<-ctx.Done()
	return ctx.Err()
}

// getParserForFile returns the appropriate koanf parser based on file extension
func getParserForFile(path string) (koanf.Parser, error) {
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".yaml", ".yml":
		return yaml.Parser(), nil
	case ".json":
		return json.Parser(), nil
	case ".toml":
		return toml.Parser(), nil
	default:
		return nil, fmt.Errorf("unsupported config file format: %s (supported: .yaml, .yml, .json, .toml)", ext)
	}
}

// envTransform transforms environment variable names to config keys
// Uses double underscore (__) for nesting:
//
//	PARSEC_SERVER__GRPC_PORT -> server.grpc_port
//	PARSEC_TRUST_DOMAIN -> trust_domain
func envTransform(s string) string {
	// Remove PARSEC_ prefix
	s = strings.TrimPrefix(s, "PARSEC_")
	// Convert to lowercase
	s = strings.ToLower(s)
	// Replace double underscore with dot for nesting
	s = strings.ReplaceAll(s, "__", ".")
	return s
}

// flagToConfigKey maps command-line flag names to config keys
// Examples:
//
//	grpc-port -> server.grpc_port
//	http-port -> server.http_port
//	trust-domain -> trust_domain
func flagToConfigKey(flagName string) string {
	switch flagName {
	case "grpc-port":
		return "server.grpc_port"
	case "http-port":
		return "server.http_port"
	case "trust-domain":
		return "trust_domain"
	default:
		// Default: replace hyphens with underscores
		return strings.ReplaceAll(flagName, "-", "_")
	}
}
