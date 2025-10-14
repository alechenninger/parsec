package trust

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/alechenninger/parsec/internal/claims"
)

// JWTValidator validates JWT tokens using JWKS
type JWTValidator struct {
	issuer      string
	jwksURL     string
	cache       *jwk.Cache
	trustDomain string
}

// JWTValidatorConfig contains configuration for JWT validation
type JWTValidatorConfig struct {
	// Issuer is the expected issuer URL (iss claim)
	Issuer string

	// JWKSURL is the URL to fetch JSON Web Key Set from
	// If empty, will attempt to discover from issuer/.well-known/jwks.json
	JWKSURL string

	// TrustDomain is the trust domain this issuer belongs to
	TrustDomain string

	// RefreshInterval for JWKS cache (default: 15 minutes)
	RefreshInterval time.Duration
}

// NewJWTValidator creates a new JWT validator with JWKS support
func NewJWTValidator(cfg JWTValidatorConfig) (*JWTValidator, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}

	jwksURL := cfg.JWKSURL
	if jwksURL == "" {
		// Default: try standard OIDC discovery endpoint
		jwksURL = cfg.Issuer + "/.well-known/jwks.json"
	}

	refreshInterval := cfg.RefreshInterval
	if refreshInterval == 0 {
		refreshInterval = 15 * time.Minute
	}

	// Create JWKS cache with auto-refresh
	cache := jwk.NewCache(context.Background())

	// Register the JWKS URL with the cache
	if err := cache.Register(jwksURL, jwk.WithMinRefreshInterval(refreshInterval)); err != nil {
		return nil, fmt.Errorf("failed to register JWKS URL: %w", err)
	}

	// Pre-fetch the JWKS
	// TODO: could make this lazy as opposed to eager fetch on creation
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := cache.Refresh(ctx, jwksURL); err != nil {
		return nil, fmt.Errorf("failed to fetch initial JWKS: %w", err)
	}

	return &JWTValidator{
		issuer:      cfg.Issuer,
		jwksURL:     jwksURL,
		cache:       cache,
		trustDomain: cfg.TrustDomain,
	}, nil
}

// CredentialTypes returns the credential types this validator can handle
// JWT validator can handle both JWT and Bearer credentials (since Bearer tokens might be JWTs)
func (v *JWTValidator) CredentialTypes() []CredentialType {
	return []CredentialType{CredentialTypeJWT, CredentialTypeBearer}
}

// Validate validates a JWT credential
func (v *JWTValidator) Validate(ctx context.Context, credential Credential) (*Result, error) {
	// Type assertion to JWTCredential or BearerCredential
	var tokenString string
	switch cred := credential.(type) {
	case *JWTCredential:
		tokenString = cred.Token
	case *BearerCredential:
		// Bearer credentials can also be JWTs
		tokenString = cred.Token
	default:
		return nil, fmt.Errorf("unsupported credential type for JWT validator: %T", credential)
	}

	// Fetch the current JWKS
	jwks, err := v.cache.Get(ctx, v.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Parse and validate the JWT
	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithKeySet(jwks),
		jwt.WithValidate(true),
		jwt.WithIssuer(v.issuer),
		// TODO: validate aud
	)
	if err != nil {
		// Check if it's an expiration error
		if jwt.IsValidationError(err) {
			// Check if the error is about expiration
			errMsg := err.Error()
			if strings.Contains(errMsg, "exp") || strings.Contains(errMsg, "expir") {
				return nil, ErrExpiredToken
			}
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// Ensure there is a subject
	subject := token.Subject()
	if subject == "" {
		return nil, fmt.Errorf("%w: missing subject claim", ErrInvalidToken)
	}

	// Extract all claims into our Claims type
	// Use AsMap() to get ALL claims from the token (both standard and private)
	allClaims, err := token.AsMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to extract token claims: %w", err)
	}

	// TODO: Probably should add a ClaimsFilter to validator config so we can configure trust on a per-claim basis
	claimsMap := make(claims.Claims)
	maps.Copy(claimsMap, allClaims)

	// Extract audience
	audiences := token.Audience()

	// Extract scope (OAuth2/OIDC)
	scope := ""
	if scopeClaim, ok := token.Get("scope"); ok {
		if scopeStr, ok := scopeClaim.(string); ok {
			scope = scopeStr
		}
	}

	return &Result{
		Subject:     subject,
		Issuer:      v.issuer,
		TrustDomain: v.trustDomain,
		Claims:      claimsMap,
		ExpiresAt:   token.Expiration(),
		IssuedAt:    token.IssuedAt(),
		Audience:    audiences,
		Scope:       scope,
	}, nil
}

// Close cleans up resources (stops JWKS cache refresh)
func (v *JWTValidator) Close() error {
	// The cache doesn't have an explicit Close method, but stopping the context
	// used during creation will stop background refreshes.
	// For now, we rely on garbage collection.
	// TODO: reexamine this
	return nil
}
