package config

import (
	"context"
	"fmt"
	"maps"
	"os"
	"time"

	"github.com/alechenninger/parsec/internal/claims"
	"github.com/alechenninger/parsec/internal/issuer"
	"github.com/alechenninger/parsec/internal/keys"
	"github.com/alechenninger/parsec/internal/mapper"
	"github.com/alechenninger/parsec/internal/service"
)

// NewIssuerRegistry creates an issuer registry from configuration
func NewIssuerRegistry(cfg Config) (service.Registry, error) {
	registry := service.NewSimpleRegistry()

	// Build key manager registry from global config
	providerRegistry, err := buildKeyProviderRegistry(cfg.KeyManagers)
	if err != nil {
		return nil, fmt.Errorf("failed to build key manager registry: %w", err)
	}

	// Create shared key slot store
	slotStore := keys.NewInMemoryKeySlotStore()

	for _, issuerCfg := range cfg.Issuers {
		if issuerCfg.TokenType == "" {
			return nil, fmt.Errorf("token_type is required for issuer")
		}

		// Use token type directly as service.TokenType (it's already a URN string)
		tokenType := service.TokenType(issuerCfg.TokenType)

		// Create issuer
		iss, err := newIssuer(issuerCfg, cfg.TrustDomain, providerRegistry, slotStore)
		if err != nil {
			return nil, fmt.Errorf("failed to create issuer for token type %s: %w", issuerCfg.TokenType, err)
		}

		// Register issuer
		registry.Register(tokenType, iss)
	}

	return registry, nil
}

// buildKeyProviderRegistry creates a map of KeyProvider instances from configuration
func buildKeyProviderRegistry(configs []KeyManagerConfig) (map[string]keys.KeyProvider, error) {
	registry := make(map[string]keys.KeyProvider)

	for _, cfg := range configs {
		if cfg.ID == "" {
			return nil, fmt.Errorf("key manager id is required")
		}

		if _, exists := registry[cfg.ID]; exists {
			return nil, fmt.Errorf("duplicate key manager id: %s", cfg.ID)
		}

		// Parse key type
		if cfg.KeyType == "" {
			return nil, fmt.Errorf("key manager %s requires key_type", cfg.ID)
		}
		keyType := keys.KeyType(cfg.KeyType)

		var km keys.KeyProvider
		var err error

		switch cfg.Type {
		case "", "memory":
			km = keys.NewInMemoryKeyManager(keyType, cfg.Algorithm)

		case "disk":
			if cfg.KeysPath == "" {
				return nil, fmt.Errorf("disk key manager %s requires keys_path", cfg.ID)
			}
			km, err = keys.NewDiskKeyManager(keys.DiskKeyManagerConfig{
				KeyType:   keyType,
				Algorithm: cfg.Algorithm,
				KeysPath:  cfg.KeysPath,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create disk key manager %s: %w", cfg.ID, err)
			}

		case "aws_kms":
			if cfg.Region == "" {
				return nil, fmt.Errorf("aws_kms key manager %s requires region", cfg.ID)
			}
			if cfg.AliasPrefix == "" {
				return nil, fmt.Errorf("aws_kms key manager %s requires alias_prefix", cfg.ID)
			}
			km, err = keys.NewAWSKMSKeyManager(context.Background(), keys.AWSKMSConfig{
				KeyType:     keyType,
				Algorithm:   cfg.Algorithm,
				Region:      cfg.Region,
				AliasPrefix: cfg.AliasPrefix,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create aws_kms key manager %s: %w", cfg.ID, err)
			}

		default:
			return nil, fmt.Errorf("unknown key manager type for %s: %s (supported: memory, disk, aws_kms)", cfg.ID, cfg.Type)
		}

		registry[cfg.ID] = km
	}

	return registry, nil
}

// newIssuer creates an issuer from configuration
func newIssuer(cfg IssuerConfig, trustDomain string, providerRegistry map[string]keys.KeyProvider, slotStore keys.KeySlotStore) (service.Issuer, error) {
	switch cfg.Type {
	case "stub":
		return newStubIssuer(cfg)
	case "unsigned":
		return newUnsignedIssuer(cfg)
	case "transaction_token":
		return newSigningTransactionTokenIssuer(cfg, trustDomain, providerRegistry, slotStore)
	case "rh_identity":
		return newRHIdentityIssuer(cfg)
	default:
		return nil, fmt.Errorf("unknown issuer type: %s (supported: stub, unsigned, transaction_token, rh_identity)", cfg.Type)
	}
}

// newStubIssuer creates a stub issuer for testing
func newStubIssuer(cfg IssuerConfig) (service.Issuer, error) {
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("stub issuer requires issuer_url")
	}

	// Parse TTL
	ttl := 5 * time.Minute // default
	if cfg.TTL != "" {
		duration, err := time.ParseDuration(cfg.TTL)
		if err != nil {
			return nil, fmt.Errorf("invalid ttl: %w", err)
		}
		ttl = duration
	}

	// Create transaction context mappers
	var txnMappers []service.ClaimMapper
	for i, mapperCfg := range cfg.TransactionContextMappers {
		m, err := newClaimMapper(mapperCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create transaction context mapper %d: %w", i, err)
		}
		txnMappers = append(txnMappers, m)
	}

	// Create request context mappers
	var reqMappers []service.ClaimMapper
	for i, mapperCfg := range cfg.RequestContextMappers {
		m, err := newClaimMapper(mapperCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create request context mapper %d: %w", i, err)
		}
		reqMappers = append(reqMappers, m)
	}

	return issuer.NewStubIssuer(issuer.StubIssuerConfig{
		IssuerURL:                 cfg.IssuerURL,
		TTL:                       ttl,
		TransactionContextMappers: txnMappers,
		RequestContextMappers:     reqMappers,
	}), nil
}

// newSigningTransactionTokenIssuer creates a signing transaction token issuer.
// This issuer signs transaction tokens itself using a key manager (as opposed to delegating to an external service).
func newSigningTransactionTokenIssuer(cfg IssuerConfig, trustDomain string, providerRegistry map[string]keys.KeyProvider, slotStore keys.KeySlotStore) (service.Issuer, error) {
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("transaction_token issuer requires issuer_url")
	}

	// Validate key_manager is specified
	if cfg.KeyManager == "" {
		return nil, fmt.Errorf("transaction_token issuer requires key_manager")
	}

	// Validate key manager exists in registry
	if _, ok := providerRegistry[cfg.KeyManager]; !ok {
		return nil, fmt.Errorf("key manager not found: %s", cfg.KeyManager)
	}

	// Parse TTL
	ttl := 5 * time.Minute // default
	if cfg.TTL != "" {
		duration, err := time.ParseDuration(cfg.TTL)
		if err != nil {
			return nil, fmt.Errorf("invalid ttl: %w", err)
		}
		ttl = duration
	}

	// Create transaction context mappers
	var txnMappers []service.ClaimMapper
	for i, mapperCfg := range cfg.TransactionContextMappers {
		m, err := newClaimMapper(mapperCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create transaction context mapper %d: %w", i, err)
		}
		txnMappers = append(txnMappers, m)
	}

	// Create request context mappers
	var reqMappers []service.ClaimMapper
	for i, mapperCfg := range cfg.RequestContextMappers {
		m, err := newClaimMapper(mapperCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create request context mapper %d: %w", i, err)
		}
		reqMappers = append(reqMappers, m)
	}

	// Initialize rotating key manager with registry and token type
	rotatingKM := keys.NewDualSlotRotatingSigner(keys.DualSlotRotatingSignerConfig{
		TokenType:          cfg.TokenType,
		TrustDomain:        trustDomain,
		KeyProviderID:       cfg.KeyManager,
		KeyProviderRegistry: providerRegistry,
		SlotStore:          slotStore,
		PrepareTimeout:     1 * time.Minute,
	})

	// Start the rotating key manager
	ctx := context.Background()
	if err := rotatingKM.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start rotating key manager: %w", err)
	}

	return issuer.NewSigningTransactionTokenIssuer(issuer.SigningTransactionTokenIssuerConfig{
		IssuerURL:                 cfg.IssuerURL,
		TTL:                       ttl,
		KeyManager:                rotatingKM,
		TransactionContextMappers: txnMappers,
		RequestContextMappers:     reqMappers,
	}), nil
}

// newUnsignedIssuer creates an unsigned issuer (for development/testing)
func newUnsignedIssuer(cfg IssuerConfig) (service.Issuer, error) {
	// Create claim mappers
	var mappers []service.ClaimMapper
	for i, mapperCfg := range cfg.ClaimMappers {
		m, err := newClaimMapper(mapperCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create claim mapper %d: %w", i, err)
		}
		mappers = append(mappers, m)
	}

	return issuer.NewUnsignedIssuer(issuer.UnsignedIssuerConfig{
		TokenType:    cfg.TokenType,
		ClaimMappers: mappers,
	}), nil
}

// newRHIdentityIssuer creates a Red Hat identity issuer
func newRHIdentityIssuer(cfg IssuerConfig) (service.Issuer, error) {
	// Create claim mappers
	var mappers []service.ClaimMapper
	for i, mapperCfg := range cfg.ClaimMappers {
		m, err := newClaimMapper(mapperCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create claim mapper %d: %w", i, err)
		}
		mappers = append(mappers, m)
	}

	return issuer.NewRHIdentityIssuer(issuer.RHIdentityIssuerConfig{
		TokenType:    cfg.TokenType,
		ClaimMappers: mappers,
	}), nil
}

// newClaimMapper creates a claim mapper from configuration
func newClaimMapper(cfg ClaimMapperConfig) (service.ClaimMapper, error) {
	switch cfg.Type {
	case "cel":
		return newCELMapper(cfg)
	case "passthrough":
		return service.NewPassthroughSubjectMapper(), nil
	case "request_attributes":
		return service.NewRequestAttributesMapper(), nil
	case "stub":
		return newStubMapper(cfg)
	default:
		return nil, fmt.Errorf("unknown claim mapper type: %s (supported: cel, passthrough, request_attributes, stub)", cfg.Type)
	}
}

// newCELMapper creates a CEL-based claim mapper
func newCELMapper(cfg ClaimMapperConfig) (service.ClaimMapper, error) {
	script := cfg.Script

	// Load from file if script_file is specified
	if cfg.ScriptFile != "" {
		content, err := os.ReadFile(cfg.ScriptFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read script file %s: %w", cfg.ScriptFile, err)
		}
		script = string(content)
	}

	if script == "" {
		return nil, fmt.Errorf("cel mapper requires script or script_file")
	}

	return mapper.NewCELMapper(script)
}

// newStubMapper creates a stub claim mapper that returns fixed claims
func newStubMapper(cfg ClaimMapperConfig) (service.ClaimMapper, error) {
	if cfg.Claims == nil {
		return nil, fmt.Errorf("stub mapper requires claims")
	}

	// Convert map[string]any to claims.Claims
	fixedClaims := claims.Claims(maps.Clone(cfg.Claims))

	return service.NewStubClaimMapper(fixedClaims), nil
}
