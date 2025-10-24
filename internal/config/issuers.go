package config

import (
	"fmt"
	"os"
	"time"

	"github.com/alechenninger/parsec/internal/claims"
	"github.com/alechenninger/parsec/internal/issuer"
	"github.com/alechenninger/parsec/internal/mapper"
	"github.com/alechenninger/parsec/internal/service"
)

// NewIssuerRegistry creates an issuer registry from configuration
func NewIssuerRegistry(cfg []IssuerConfig) (service.Registry, error) {
	registry := service.NewSimpleRegistry()

	for _, issuerCfg := range cfg {
		if issuerCfg.TokenType == "" {
			return nil, fmt.Errorf("token_type is required for issuer")
		}

		// Use token type directly as service.TokenType (it's already a URN string)
		tokenType := service.TokenType(issuerCfg.TokenType)

		// Create issuer
		iss, err := newIssuer(issuerCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create issuer for token type %s: %w", issuerCfg.TokenType, err)
		}

		// Register issuer
		registry.Register(tokenType, iss)
	}

	return registry, nil
}

// newIssuer creates an issuer from configuration
func newIssuer(cfg IssuerConfig) (service.Issuer, error) {
	switch cfg.Type {
	case "stub":
		return newStubIssuer(cfg)
	case "unsigned":
		return newUnsignedIssuer(cfg)
	case "jwt":
		return nil, fmt.Errorf("jwt issuer not yet implemented")
	case "rh_identity":
		return newRHIdentityIssuer(cfg)
	default:
		return nil, fmt.Errorf("unknown issuer type: %s (supported: stub, unsigned, jwt, rh_identity)", cfg.Type)
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
	fixedClaims := make(claims.Claims)
	for k, v := range cfg.Claims {
		fixedClaims[k] = v
	}

	return service.NewStubClaimMapper(fixedClaims), nil
}
