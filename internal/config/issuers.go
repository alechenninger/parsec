package config

import (
	"fmt"
	"time"

	"github.com/alechenninger/parsec/internal/issuer"
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
	default:
		return nil, fmt.Errorf("unknown issuer type: %s (supported: stub, unsigned, jwt)", cfg.Type)
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

	// Create options
	var opts []issuer.StubIssuerOption
	if cfg.IncludeRequestContext {
		opts = append(opts, issuer.WithIncludeRequestContext(true))
	}

	return issuer.NewStubIssuer(cfg.IssuerURL, ttl, opts...), nil
}

// newUnsignedIssuer creates an unsigned issuer (for development/testing)
func newUnsignedIssuer(cfg IssuerConfig) (service.Issuer, error) {
	// UnsignedIssuer only needs the token type
	// Note: The IssuerURL and TTL fields are ignored for unsigned issuers
	// as they produce tokens that never expire
	tokenType := "urn:ietf:params:oauth:token-type:txn_token"
	if cfg.TokenType == "access_token" {
		tokenType = "urn:ietf:params:oauth:token-type:access_token"
	}

	return issuer.NewUnsignedIssuer(tokenType), nil
}
