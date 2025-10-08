package trust

import (
	"context"
	"errors"
	"time"

	"github.com/alechenninger/parsec/internal/claims"
)

// Common validation errors
var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token expired")
)

// Validator validates external credentials and returns claims about the authenticated subject
type Validator interface {
	// Validate validates a credential and returns the validation result
	// Returns an error if the credential is invalid or validation fails
	Validate(ctx context.Context, credential Credential) (*Result, error)

	// CredentialTypes returns the set of credential types this validator can handle
	// A validator may support multiple types (e.g., JWT validator can handle Bearer or JWT)
	CredentialTypes() []CredentialType
}

// Result contains the validated information about the subject
type Result struct {
	// Subject is the unique identifier of the authenticated subject
	Subject string

	// Issuer is the issuer of the credential (e.g., IdP URL)
	Issuer string

	// TrustDomain is the trust domain the credential belongs to.
	// This namespaces the subject identifier and claims.
	// An issuer is often 1:1 with a trust domain but not always.
	TrustDomain string

	// Claims are additional claims from the credential
	Claims claims.Claims

	// ExpiresAt is when the validated credential expires
	ExpiresAt time.Time

	// IssuedAt is when the credential was issued
	IssuedAt time.Time

	// Audience is the intended audience of the credential
	Audience []string

	// Scope is the OAuth2 scope if applicable
	Scope string
}

// CredentialType indicates the type of credential
type CredentialType string

const (
	CredentialTypeBearer CredentialType = "bearer"
	CredentialTypeJWT    CredentialType = "jwt"
	CredentialTypeOIDC   CredentialType = "oidc"
	CredentialTypeMTLS   CredentialType = "mtls"
	CredentialTypeOAuth2 CredentialType = "oauth2"
)

// Credential is the interface for all credential types
// Credentials encapsulate only the material needed for validation
type Credential interface {
	// Type returns the credential type
	Type() CredentialType
}

// BearerCredential represents a simple bearer token
// For opaque bearer tokens, the trust store determines which validator to use
// based on its configuration (e.g., default validator, token introspection, etc.)
type BearerCredential struct {
	Token string
}

func (c *BearerCredential) Type() CredentialType {
	return CredentialTypeBearer
}

// JWTCredential represents a JWT token with parsed header and claims
type JWTCredential struct {
	BearerCredential
	Algorithm      string
	KeyID          string
	IssuerIdentity string // Parsed from JWT "iss" claim
}

func (c *JWTCredential) Type() CredentialType {
	return CredentialTypeJWT
}

// OIDCCredential represents an OIDC token with additional context
type OIDCCredential struct {
	Token          string
	IssuerIdentity string // Parsed from JWT "iss" claim
	ClientID       string
}

func (c *OIDCCredential) Type() CredentialType {
	return CredentialTypeOIDC
}

// MTLSCredential represents client certificate authentication
type MTLSCredential struct {
	// Certificate is the client certificate (DER encoded)
	Certificate []byte

	// Chain is the certificate chain (DER encoded)
	Chain [][]byte

	// PeerCertificateHash for validation
	PeerCertificateHash string

	// IssuerIdentity identifies the CA/trust domain
	IssuerIdentity string
}

func (c *MTLSCredential) Type() CredentialType {
	return CredentialTypeMTLS
}
