package trust

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/alechenninger/parsec/internal/claims"
)

// ClaimsFilter defines which claims should be passed through from a credential
type ClaimsFilter interface {
	// Filter filters the claims, returning only those that should be passed through
	Filter(c claims.Claims) claims.Claims
}

// AllowListClaimsFilter only allows claims in the allow list
type AllowListClaimsFilter struct {
	allowedClaims map[string]bool
}

// NewAllowListClaimsFilter creates a new allow list filter
func NewAllowListClaimsFilter(allowedClaims []string) *AllowListClaimsFilter {
	allowed := make(map[string]bool, len(allowedClaims))
	for _, claim := range allowedClaims {
		allowed[claim] = true
	}
	return &AllowListClaimsFilter{
		allowedClaims: allowed,
	}
}

// Filter implements ClaimsFilter
func (f *AllowListClaimsFilter) Filter(c claims.Claims) claims.Claims {
	if c == nil {
		return nil
	}
	filtered := make(claims.Claims)
	for key, value := range c {
		if f.allowedClaims[key] {
			filtered[key] = value
		}
	}
	return filtered
}

// DenyListClaimsFilter blocks claims in the deny list
type DenyListClaimsFilter struct {
	deniedClaims map[string]bool
}

// NewDenyListClaimsFilter creates a new deny list filter
func NewDenyListClaimsFilter(deniedClaims []string) *DenyListClaimsFilter {
	denied := make(map[string]bool, len(deniedClaims))
	for _, claim := range deniedClaims {
		denied[claim] = true
	}
	return &DenyListClaimsFilter{
		deniedClaims: denied,
	}
}

// Filter implements ClaimsFilter
func (f *DenyListClaimsFilter) Filter(c claims.Claims) claims.Claims {
	if c == nil {
		return nil
	}
	filtered := make(claims.Claims)
	for key, value := range c {
		if !f.deniedClaims[key] {
			filtered[key] = value
		}
	}
	return filtered
}

// PassthroughClaimsFilter passes all claims through
type PassthroughClaimsFilter struct{}

// Filter implements ClaimsFilter
func (f *PassthroughClaimsFilter) Filter(c claims.Claims) claims.Claims {
	return c.Copy()
}

// JSONValidator validates unsigned JSON credentials with a Result structure
// It validates that the JSON matches the expected structure and filters claims
// based on the configured filter
type JSONValidator struct {
	credTypes     []CredentialType
	claimsFilter  ClaimsFilter
	trustDomain   string
	requireIssuer bool
}

// JSONValidatorOption is a functional option for configuring a JSONValidator
type JSONValidatorOption func(*JSONValidator)

// WithClaimsFilter sets the claims filter
func WithClaimsFilter(filter ClaimsFilter) JSONValidatorOption {
	return func(v *JSONValidator) {
		v.claimsFilter = filter
	}
}

// WithTrustDomain sets the expected trust domain
// If set, the validator will only accept credentials from this trust domain
func WithTrustDomain(trustDomain string) JSONValidatorOption {
	return func(v *JSONValidator) {
		v.trustDomain = trustDomain
	}
}

// WithRequireIssuer requires that the issuer field be present
func WithRequireIssuer(require bool) JSONValidatorOption {
	return func(v *JSONValidator) {
		v.requireIssuer = require
	}
}

// NewJSONValidator creates a new JSON validator
func NewJSONValidator(opts ...JSONValidatorOption) *JSONValidator {
	v := &JSONValidator{
		credTypes:    []CredentialType{CredentialTypeJSON},
		claimsFilter: &PassthroughClaimsFilter{},
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate implements the Validator interface
func (v *JSONValidator) Validate(ctx context.Context, credential Credential) (*Result, error) {
	// Check credential type
	jsonCred, ok := credential.(*JSONCredential)
	if !ok {
		return nil, fmt.Errorf("expected JSONCredential, got %T", credential)
	}

	if len(jsonCred.RawJSON) == 0 {
		return nil, fmt.Errorf("empty JSON credential")
	}

	// Parse the JSON into a Result structure
	var result Result
	if err := json.Unmarshal(jsonCred.RawJSON, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON credential: %w", err)
	}

	// Validate required fields
	if result.Subject == "" {
		return nil, fmt.Errorf("subject is required")
	}

	if v.requireIssuer && result.Issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}

	// Validate trust domain if configured
	if v.trustDomain != "" && result.TrustDomain != v.trustDomain {
		return nil, fmt.Errorf("trust domain mismatch: expected %s, got %s", v.trustDomain, result.TrustDomain)
	}

	// Filter claims
	result.Claims = v.claimsFilter.Filter(result.Claims)

	return &result, nil
}

// CredentialTypes implements the Validator interface
func (v *JSONValidator) CredentialTypes() []CredentialType {
	return v.credTypes
}
