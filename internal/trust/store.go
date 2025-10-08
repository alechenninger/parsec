package trust

import (
	"context"
)

// Store manages trust domains and their associated validators
type Store interface {
	// Validate validates a credential, determining the appropriate validator
	// based on the credential type and issuer extracted from the credential
	Validate(ctx context.Context, credential Credential) (*Result, error)
}
