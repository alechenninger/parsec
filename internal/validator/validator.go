package validator

import (
	"context"
	"errors"
	"time"
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

	// Type returns the type of credentials this validator handles
	Type() CredentialType
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

	// Issuer returns the issuer identifier for trust store lookup
	// For JWT/OIDC: the "iss" claim
	// For mTLS: the certificate authority identifier
	// For API keys: the configured issuer/domain
	//
	// TODO: should this be verbatim from credential or some abstraction which we control?
	Issuer() string
}

// BearerCredential represents a simple bearer token
// For opaque bearer tokens, issuer should be determined from context
// (e.g., configured for the endpoint, or parsed from token introspection)
type BearerCredential struct {
	Token          string
	IssuerIdentity string // The issuer/domain this token belongs to
}

func (c *BearerCredential) Type() CredentialType {
	return CredentialTypeBearer
}

func (c *BearerCredential) Issuer() string {
	return c.IssuerIdentity
}

// JWTCredential represents a JWT token with parsed header and claims
type JWTCredential struct {
	Token          string
	Algorithm      string
	KeyID          string
	IssuerIdentity string // Parsed from JWT "iss" claim
}

func (c *JWTCredential) Type() CredentialType {
	return CredentialTypeJWT
}

func (c *JWTCredential) Issuer() string {
	return c.IssuerIdentity
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

func (c *OIDCCredential) Issuer() string {
	return c.IssuerIdentity
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

func (c *MTLSCredential) Issuer() string {
	return c.IssuerIdentity
}

// Result contains the validated information about the subject
type Result struct {
	// Subject is the unique identifier of the authenticated subject
	Subject string

	// Issuer is the issuer of the credential (e.g., IdP URL)
	Issuer string

	// TrustDomain is the trust domain the credential belongs to
	TrustDomain string

	// Claims are additional claims from the credential
	Claims map[string]any

	// ExpiresAt is when the validated credential expires
	ExpiresAt time.Time

	// IssuedAt is when the credential was issued
	IssuedAt time.Time

	// Audience is the intended audience of the credential
	Audience []string

	// Scope is the OAuth2 scope if applicable
	Scope string
}
