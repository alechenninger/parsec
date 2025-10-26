package issuer

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/alechenninger/parsec/internal/clock"
	"github.com/alechenninger/parsec/internal/keymanager"
	"github.com/alechenninger/parsec/internal/service"
)

// JWTTransactionTokenIssuerConfig is the configuration for creating a JWT transaction token issuer
type JWTTransactionTokenIssuerConfig struct {
	// IssuerURL is the issuer URL (iss claim)
	IssuerURL string

	// TTL is the time-to-live for tokens
	TTL time.Duration

	// SigningAlgorithm is the JWT signing algorithm (RS256, RS384, RS512, ES256, ES384, ES512)
	SigningAlgorithm jwa.SignatureAlgorithm

	// KeyManager handles key rotation and signing
	KeyManager *keymanager.RotatingKeyManager

	// TransactionContextMappers build the "tctx" claim
	TransactionContextMappers []service.ClaimMapper

	// RequestContextMappers build the "req_ctx" claim
	RequestContextMappers []service.ClaimMapper

	// Clock is an optional clock for testing (defaults to system clock)
	Clock clock.Clock
}

// JWTTransactionTokenIssuer issues JWT transaction tokens per draft-ietf-oauth-transaction-tokens
// It uses a RotatingKeyManager for key rotation and signing operations
type JWTTransactionTokenIssuer struct {
	issuerURL                 string
	ttl                       time.Duration
	signingAlgorithm          jwa.SignatureAlgorithm
	keyManager                *keymanager.RotatingKeyManager
	transactionContextMappers []service.ClaimMapper
	requestContextMappers     []service.ClaimMapper
	clock                     clock.Clock
}

// NewJWTTransactionTokenIssuer creates a new JWT transaction token issuer
func NewJWTTransactionTokenIssuer(cfg JWTTransactionTokenIssuerConfig) *JWTTransactionTokenIssuer {
	clk := cfg.Clock
	if clk == nil {
		clk = clock.NewSystemClock()
	}

	return &JWTTransactionTokenIssuer{
		issuerURL:                 cfg.IssuerURL,
		ttl:                       cfg.TTL,
		signingAlgorithm:          cfg.SigningAlgorithm,
		keyManager:                cfg.KeyManager,
		transactionContextMappers: cfg.TransactionContextMappers,
		requestContextMappers:     cfg.RequestContextMappers,
		clock:                     clk,
	}
}

// Issue implements the Issuer interface
// Issues a signed JWT transaction token per draft-ietf-oauth-transaction-tokens
func (i *JWTTransactionTokenIssuer) Issue(ctx context.Context, issueCtx *service.IssueContext) (*service.Token, error) {
	// Apply transaction context mappers
	transactionContext, err := issueCtx.ToClaims(ctx, i.transactionContextMappers)
	if err != nil {
		return nil, fmt.Errorf("failed to map transaction context: %w", err)
	}

	// Apply request context mappers
	requestContext, err := issueCtx.ToClaims(ctx, i.requestContextMappers)
	if err != nil {
		return nil, fmt.Errorf("failed to map request context: %w", err)
	}

	now := i.clock.Now()
	expiresAt := now.Add(i.ttl)

	// Generate UUIDv7 for transaction ID (provides temporal ordering)
	txnID := uuid.NewString()

	// Build JWT token per draft-ietf-oauth-transaction-tokens
	token := jwt.New()

	// Standard JWT claims
	if err := token.Set(jwt.IssuerKey, i.issuerURL); err != nil {
		return nil, fmt.Errorf("failed to set issuer: %w", err)
	}
	if err := token.Set(jwt.SubjectKey, issueCtx.Subject.Subject); err != nil {
		return nil, fmt.Errorf("failed to set subject: %w", err)
	}
	if err := token.Set(jwt.AudienceKey, []string{issueCtx.Audience}); err != nil {
		return nil, fmt.Errorf("failed to set audience: %w", err)
	}
	if err := token.Set(jwt.IssuedAtKey, now.Unix()); err != nil {
		return nil, fmt.Errorf("failed to set issued at: %w", err)
	}
	if err := token.Set(jwt.ExpirationKey, expiresAt.Unix()); err != nil {
		return nil, fmt.Errorf("failed to set expiration: %w", err)
	}
	if err := token.Set(jwt.NotBeforeKey, now.Unix()); err != nil {
		return nil, fmt.Errorf("failed to set not before: %w", err)
	}
	if err := token.Set(jwt.JwtIDKey, uuid.NewString()); err != nil {
		return nil, fmt.Errorf("failed to set JWT ID: %w", err)
	}

	// Transaction token specific claims
	if err := token.Set("txn", txnID); err != nil {
		return nil, fmt.Errorf("failed to set transaction ID: %w", err)
	}

	// Transaction context (tctx) - authorization context for the transaction
	if len(transactionContext) > 0 {
		if err := token.Set("tctx", transactionContext); err != nil {
			return nil, fmt.Errorf("failed to set transaction context: %w", err)
		}
	}

	// Request context (req_ctx) - information about the request being authorized
	if len(requestContext) > 0 {
		if err := token.Set("req_ctx", requestContext); err != nil {
			return nil, fmt.Errorf("failed to set request context: %w", err)
		}
	}

	// Scope (if provided)
	if issueCtx.Scope != "" {
		if err := token.Set("scope", issueCtx.Scope); err != nil {
			return nil, fmt.Errorf("failed to set scope: %w", err)
		}
	}

	// Get the current signer and key ID from the rotating key manager
	signer, keyID, err := i.keyManager.GetCurrentSigner(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get current signer: %w", err)
	}

	// Build JWS headers with the key ID
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, keyID); err != nil {
		return nil, fmt.Errorf("failed to set key ID header: %w", err)
	}

	// Sign the token with the current key
	signedToken, err := jwt.Sign(token,
		jwt.WithKey(i.signingAlgorithm, signer, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	return &service.Token{
		Value:     string(signedToken),
		Type:      "urn:ietf:params:oauth:token-type:txn_token",
		ExpiresAt: expiresAt,
		IssuedAt:  now,
	}, nil
}

// PublicKeys implements the Issuer interface
// Returns all non-expired public keys from the rotating key manager
func (i *JWTTransactionTokenIssuer) PublicKeys(ctx context.Context) ([]service.PublicKey, error) {
	// Get all public keys from the rotating key manager
	keys, err := i.keyManager.PublicKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get public keys: %w", err)
	}

	// Convert to service.PublicKey format
	publicKeys := make([]service.PublicKey, len(keys))
	for i, key := range keys {
		publicKeys[i] = service.PublicKey{
			KeyID:     key.KeyID,
			Algorithm: key.Algorithm,
			Key:       key.Key,
			Use:       "sig",
		}
	}

	return publicKeys, nil
}
