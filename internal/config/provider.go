package config

import (
	"fmt"

	"github.com/alechenninger/parsec/internal/server"
	"github.com/alechenninger/parsec/internal/service"
	"github.com/alechenninger/parsec/internal/trust"
)

// Provider constructs all application components from configuration
// This is the main entry point for building a configured parsec instance
type Provider struct {
	config *Config

	// Lazily constructed components (cached after first call)
	trustStore           trust.Store
	dataSourceRegistry   *service.DataSourceRegistry
	claimMapperRegistry  *service.ClaimMapperRegistry
	issuerRegistry       service.Registry
	claimsFilterRegistry server.ClaimsFilterRegistry
	tokenService         *service.TokenService
}

// NewProvider creates a new provider from configuration
func NewProvider(config *Config) *Provider {
	return &Provider{
		config: config,
	}
}

// TrustStore returns the configured trust store
func (p *Provider) TrustStore() (trust.Store, error) {
	if p.trustStore != nil {
		return p.trustStore, nil
	}

	store, err := NewTrustStore(p.config.TrustStore)
	if err != nil {
		return nil, fmt.Errorf("failed to create trust store: %w", err)
	}

	p.trustStore = store
	return store, nil
}

// DataSourceRegistry returns the configured data source registry
func (p *Provider) DataSourceRegistry() (*service.DataSourceRegistry, error) {
	if p.dataSourceRegistry != nil {
		return p.dataSourceRegistry, nil
	}

	registry, err := NewDataSourceRegistry(p.config.DataSources)
	if err != nil {
		return nil, fmt.Errorf("failed to create data source registry: %w", err)
	}

	p.dataSourceRegistry = registry
	return registry, nil
}

// ClaimMapperRegistry returns the configured claim mapper registry
func (p *Provider) ClaimMapperRegistry() (*service.ClaimMapperRegistry, error) {
	if p.claimMapperRegistry != nil {
		return p.claimMapperRegistry, nil
	}

	registry, err := NewClaimMapperRegistry(p.config.ClaimMappers)
	if err != nil {
		return nil, fmt.Errorf("failed to create claim mapper registry: %w", err)
	}

	p.claimMapperRegistry = registry
	return registry, nil
}

// IssuerRegistry returns the configured issuer registry
func (p *Provider) IssuerRegistry() (service.Registry, error) {
	if p.issuerRegistry != nil {
		return p.issuerRegistry, nil
	}

	registry, err := NewIssuerRegistry(p.config.Issuers)
	if err != nil {
		return nil, fmt.Errorf("failed to create issuer registry: %w", err)
	}

	p.issuerRegistry = registry
	return registry, nil
}

// ClaimsFilterRegistry returns the configured claims filter registry
func (p *Provider) ClaimsFilterRegistry() (server.ClaimsFilterRegistry, error) {
	if p.claimsFilterRegistry != nil {
		return p.claimsFilterRegistry, nil
	}

	registry, err := NewClaimsFilterRegistry(p.config.ClaimsFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to create claims filter registry: %w", err)
	}

	p.claimsFilterRegistry = registry
	return registry, nil
}

// TokenService returns the configured token service
func (p *Provider) TokenService() (*service.TokenService, error) {
	if p.tokenService != nil {
		return p.tokenService, nil
	}

	// Build dependencies
	dataSourceRegistry, err := p.DataSourceRegistry()
	if err != nil {
		return nil, err
	}

	claimMapperRegistry, err := p.ClaimMapperRegistry()
	if err != nil {
		return nil, err
	}

	issuerRegistry, err := p.IssuerRegistry()
	if err != nil {
		return nil, err
	}

	// Create token service
	tokenService := service.NewTokenService(
		p.config.TrustDomain,
		dataSourceRegistry,
		claimMapperRegistry,
		issuerRegistry,
	)

	p.tokenService = tokenService
	return tokenService, nil
}

// ServerConfig returns the server configuration
func (p *Provider) ServerConfig() server.Config {
	return server.Config{
		GRPCPort: p.config.Server.GRPCPort,
		HTTPPort: p.config.Server.HTTPPort,
	}
}

// TrustDomain returns the configured trust domain
func (p *Provider) TrustDomain() string {
	return p.config.TrustDomain
}
