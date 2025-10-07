package validator

import (
	"context"
	"fmt"
	"time"
)

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
			Claims: map[string]any{
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
