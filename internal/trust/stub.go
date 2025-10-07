package trust

import (
	"context"
	"fmt"

	"github.com/alechenninger/parsec/internal/validator"
)

// StubStore is a simple in-memory trust store for testing
type StubStore struct {
	domains    map[string]*Domain
	validators map[string]validator.Validator
}

// NewStubStore creates a new stub trust store
func NewStubStore() *StubStore {
	return &StubStore{
		domains:    make(map[string]*Domain),
		validators: make(map[string]validator.Validator),
	}
}

// AddDomain adds a trust domain to the store
func (s *StubStore) AddDomain(domain *Domain) *StubStore {
	s.domains[domain.Issuer] = domain
	return s
}

// AddValidator adds a validator for a specific credential type and issuer
func (s *StubStore) AddValidator(credType validator.CredentialType, issuer string, v validator.Validator) *StubStore {
	key := fmt.Sprintf("%s:%s", credType, issuer)
	s.validators[key] = v
	return s
}

// GetDomain implements the Store interface
func (s *StubStore) GetDomain(ctx context.Context, issuer string) (*Domain, error) {
	domain, ok := s.domains[issuer]
	if !ok {
		return nil, fmt.Errorf("trust domain not found for issuer: %s", issuer)
	}
	return domain, nil
}

// ListDomains implements the Store interface
func (s *StubStore) ListDomains(ctx context.Context) ([]*Domain, error) {
	domains := make([]*Domain, 0, len(s.domains))
	for _, domain := range s.domains {
		domains = append(domains, domain)
	}
	return domains, nil
}

// ValidatorFor implements the Store interface
func (s *StubStore) ValidatorFor(ctx context.Context, credType validator.CredentialType, issuer string) (validator.Validator, error) {
	key := fmt.Sprintf("%s:%s", credType, issuer)
	v, ok := s.validators[key]
	if !ok {
		return nil, fmt.Errorf("no validator found for type %s and issuer %s", credType, issuer)
	}
	return v, nil
}
