package trust

import (
	"context"
	"fmt"
	"time"

	"github.com/alechenninger/parsec/internal/claims"
)

// StubStore is a simple in-memory trust store for testing
type StubStore struct {
	domains    map[string]*Domain
	validators map[string]Validator
}

// Domain represents a trust domain configuration
type Domain struct {
	// Name is a human-readable name for the domain
	Name string

	// Issuer is the issuer identifier (e.g., IdP URL)
	Issuer string

	// ValidatorType indicates which validator to use
	ValidatorType CredentialType
}

// NewStubStore creates a new stub trust store
func NewStubStore() *StubStore {
	return &StubStore{
		domains:    make(map[string]*Domain),
		validators: make(map[string]Validator),
	}
}

// AddDomain adds a trust domain to the store
func (s *StubStore) AddDomain(domain *Domain) *StubStore {
	s.domains[domain.Issuer] = domain
	return s
}

// AddValidator adds a validator for a specific credential type and issuer
func (s *StubStore) AddValidator(credType CredentialType, issuer string, v Validator) *StubStore {
	key := fmt.Sprintf("%s:%s", credType, issuer)
	s.validators[key] = v
	return s
}

// Validate implements the Store interface
func (s *StubStore) Validate(ctx context.Context, credential Credential) (*Result, error) {
	// Extract issuer from credential
	issuer, err := extractIssuer(credential)
	if err != nil {
		return nil, fmt.Errorf("failed to extract issuer from credential: %w", err)
	}

	// Look up validator
	key := fmt.Sprintf("%s:%s", credential.Type(), issuer)
	v, ok := s.validators[key]
	if !ok {
		return nil, fmt.Errorf("no validator found for type %s and issuer %s", credential.Type(), issuer)
	}

	// Validate the credential
	return v.Validate(ctx, credential)
}

// extractIssuer extracts the issuer identifier from a credential
func extractIssuer(cred Credential) (string, error) {
	switch c := cred.(type) {
	case *BearerCredential:
		// For bearer tokens, use a default issuer since we can't determine it from the token
		// The trust store should have a default bearer validator configured
		return "bearer", nil
	case *JWTCredential:
		if c.IssuerIdentity == "" {
			return "", fmt.Errorf("JWT credential missing issuer identity")
		}
		return c.IssuerIdentity, nil
	case *OIDCCredential:
		if c.IssuerIdentity == "" {
			return "", fmt.Errorf("OIDC credential missing issuer identity")
		}
		return c.IssuerIdentity, nil
	case *MTLSCredential:
		if c.IssuerIdentity == "" {
			return "", fmt.Errorf("mTLS credential missing issuer identity")
		}
		return c.IssuerIdentity, nil
	default:
		return "", fmt.Errorf("unknown credential type: %T", cred)
	}
}

// StubValidator is a simple stub validator for testing
// It accepts any token and returns a fixed result
type StubValidator struct {
	credType CredentialType
	result   *Result
	err      error
}

// NewStubValidator creates a new stub validator
func NewStubValidator(credType CredentialType) *StubValidator {
	return &StubValidator{
		credType: credType,
		result: &Result{
			Subject:     "test-subject",
			Issuer:      "https://test-issuer.example.com",
			TrustDomain: "test-domain",
			Claims: claims.Claims{
				"email": "test@example.com",
			},
			ExpiresAt: time.Now().Add(time.Hour),
			IssuedAt:  time.Now(),
			Audience:  []string{"https://parsec.example.com"},
			Scope:     "read write",
		},
	}
}

// WithResult configures the stub to return a specific result
func (v *StubValidator) WithResult(result *Result) *StubValidator {
	v.result = result
	return v
}

// WithError configures the stub to return an error
func (v *StubValidator) WithError(err error) *StubValidator {
	v.err = err
	return v
}

// Validate implements the Validator interface
func (v *StubValidator) Validate(ctx context.Context, credential Credential) (*Result, error) {
	if v.err != nil {
		return nil, v.err
	}

	// Type assertion to check for token-based credentials
	switch cred := credential.(type) {
	case *BearerCredential:
		if cred.Token == "" {
			return nil, fmt.Errorf("empty token")
		}
	case *JWTCredential:
		if cred.Token == "" {
			return nil, fmt.Errorf("empty token")
		}
	case *OIDCCredential:
		if cred.Token == "" {
			return nil, fmt.Errorf("empty token")
		}
	default:
		// For other credential types, just validate the type matches
		if credential.Type() != v.credType {
			return nil, fmt.Errorf("credential type mismatch: expected %s, got %s", v.credType, credential.Type())
		}
	}

	// For stub, just return the configured result
	return v.result, nil
}

// Type implements the Validator interface
func (v *StubValidator) Type() CredentialType {
	return v.credType
}
