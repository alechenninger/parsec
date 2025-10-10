package config

import (
	"fmt"

	"github.com/alechenninger/parsec/internal/claims"
	"github.com/alechenninger/parsec/internal/mapper"
	"github.com/alechenninger/parsec/internal/service"
)

// NewClaimMapperRegistry creates a claim mapper registry from configuration
func NewClaimMapperRegistry(cfg ClaimMappersConfig) (*service.ClaimMapperRegistry, error) {
	registry := service.NewClaimMapperRegistry()

	// Register transaction context mappers
	for i, mapperCfg := range cfg.TransactionContext {
		m, err := newClaimMapper(mapperCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create transaction context mapper %d: %w", i, err)
		}
		registry.RegisterTransactionContext(m)
	}

	// Register request context mappers
	for i, mapperCfg := range cfg.RequestContext {
		m, err := newClaimMapper(mapperCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create request context mapper %d: %w", i, err)
		}
		registry.RegisterRequestContext(m)
	}

	return registry, nil
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
	if cfg.Script == "" {
		return nil, fmt.Errorf("cel mapper requires script")
	}

	return mapper.NewCELMapper(cfg.Script)
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
