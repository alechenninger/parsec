package trust

import (
	"context"

	"github.com/alechenninger/parsec/internal/validator"
)

// Store manages trust domains and their associated validators
type Store interface {
	// GetDomain returns a trust domain by issuer
	GetDomain(ctx context.Context, issuer string) (*Domain, error)

	// ListDomains returns all configured trust domains
	ListDomains(ctx context.Context) ([]*Domain, error)

	// ValidatorFor returns a validator for the given credential type and issuer
	ValidatorFor(ctx context.Context, credType validator.CredentialType, issuer string) (validator.Validator, error)
}

// Domain represents a trust domain configuration
type Domain struct {
	// Name is a human-readable name for the domain
	Name string

	// Issuer is the issuer identifier (e.g., IdP URL)
	Issuer string

	// ValidatorType indicates which validator to use
	ValidatorType validator.CredentialType

	// JWKSURI is the URI to fetch public keys (for JWT/OIDC validators)
	JWKSURI string

	// ValidationEndpoint is the endpoint for token introspection (for OAuth2)
	ValidationEndpoint string

	// ClientID for OAuth2 introspection
	ClientID string

	// ClientSecret for OAuth2 introspection (should be from secure storage)
	ClientSecret string

	// Additional configuration
	Config map[string]any
}
