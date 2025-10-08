package trust

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// setupTestJWKS creates a test JWKS server and returns the private key, JWKS URL, and cleanup function
func setupTestJWKS(t *testing.T) (*rsa.PrivateKey, string, func()) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Create JWK from public key
	publicKey, err := jwk.FromRaw(privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create JWK: %v", err)
	}

	// Set key ID
	if err := publicKey.Set(jwk.KeyIDKey, "test-key-1"); err != nil {
		t.Fatalf("failed to set key ID: %v", err)
	}

	// Set algorithm
	if err := publicKey.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("failed to set algorithm: %v", err)
	}

	// Create JWKS
	jwks := jwk.NewSet()
	if err := jwks.AddKey(publicKey); err != nil {
		t.Fatalf("failed to add key to set: %v", err)
	}

	// Create HTTP server serving JWKS
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			t.Errorf("failed to encode JWKS: %v", err)
		}
	}))

	return privateKey, server.URL, server.Close
}

// createTestJWT creates a signed JWT for testing
func createTestJWT(t *testing.T, privateKey *rsa.PrivateKey, claims map[string]interface{}) string {
	token := jwt.New()

	// Set standard claims
	now := time.Now()
	if err := token.Set(jwt.IssuedAtKey, now); err != nil {
		t.Fatalf("failed to set iat: %v", err)
	}
	if err := token.Set(jwt.ExpirationKey, now.Add(1*time.Hour)); err != nil {
		t.Fatalf("failed to set exp: %v", err)
	}

	// Set custom claims
	for key, value := range claims {
		if err := token.Set(key, value); err != nil {
			t.Fatalf("failed to set claim %s: %v", key, err)
		}
	}

	// Create JWK with key ID for signing
	key, err := jwk.FromRaw(privateKey)
	if err != nil {
		t.Fatalf("failed to create JWK from private key: %v", err)
	}
	if err := key.Set(jwk.KeyIDKey, "test-key-1"); err != nil {
		t.Fatalf("failed to set key ID: %v", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("failed to set algorithm: %v", err)
	}

	// Sign the token with the key (including kid in header)
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return string(signed)
}

func TestJWTValidator(t *testing.T) {
	ctx := context.Background()

	// Setup test JWKS server
	privateKey, jwksURL, cleanup := setupTestJWKS(t)
	defer cleanup()

	t.Run("validates valid JWT successfully", func(t *testing.T) {
		// Create validator
		validator, err := NewJWTValidator(JWTValidatorConfig{
			Issuer:      "https://test-issuer.example.com",
			JWKSURL:     jwksURL,
			TrustDomain: "test-domain",
		})
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		// Create valid JWT
		tokenString := createTestJWT(t, privateKey, map[string]interface{}{
			"iss":   "https://test-issuer.example.com",
			"sub":   "user@example.com",
			"email": "user@example.com",
			"name":  "Test User",
		})

		// Create credential
		cred := &JWTCredential{BearerCredential: BearerCredential{Token: tokenString}}

		// Validate
		result, err := validator.Validate(ctx, cred)
		if err != nil {
			t.Fatalf("validation failed: %v", err)
		}

		// Check result
		if result.Subject != "user@example.com" {
			t.Errorf("expected subject 'user@example.com', got %q", result.Subject)
		}
		if result.Issuer != "https://test-issuer.example.com" {
			t.Errorf("expected issuer 'https://test-issuer.example.com', got %q", result.Issuer)
		}
		if result.TrustDomain != "test-domain" {
			t.Errorf("expected trust domain 'test-domain', got %q", result.TrustDomain)
		}
		if result.Claims["email"] != "user@example.com" {
			t.Errorf("expected email claim 'user@example.com', got %v", result.Claims["email"])
		}
	})

	t.Run("validates bearer credential as JWT", func(t *testing.T) {
		validator, err := NewJWTValidator(JWTValidatorConfig{
			Issuer:      "https://test-issuer.example.com",
			JWKSURL:     jwksURL,
			TrustDomain: "test-domain",
		})
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		tokenString := createTestJWT(t, privateKey, map[string]interface{}{
			"iss": "https://test-issuer.example.com",
			"sub": "user@example.com",
		})

		// Use BearerCredential instead of JWTCredential
		cred := &BearerCredential{Token: tokenString}

		result, err := validator.Validate(ctx, cred)
		if err != nil {
			t.Fatalf("validation failed: %v", err)
		}

		if result.Subject != "user@example.com" {
			t.Errorf("expected subject 'user@example.com', got %q", result.Subject)
		}
	})

	t.Run("rejects expired JWT", func(t *testing.T) {
		validator, err := NewJWTValidator(JWTValidatorConfig{
			Issuer:      "https://test-issuer.example.com",
			JWKSURL:     jwksURL,
			TrustDomain: "test-domain",
		})
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		// Create expired token
		token := jwt.New()
		now := time.Now()
		token.Set(jwt.IssuedAtKey, now.Add(-2*time.Hour))
		token.Set(jwt.ExpirationKey, now.Add(-1*time.Hour)) // Expired 1 hour ago
		token.Set(jwt.IssuerKey, "https://test-issuer.example.com")
		token.Set(jwt.SubjectKey, "user@example.com")

		// Create JWK with key ID for signing
		key, _ := jwk.FromRaw(privateKey)
		key.Set(jwk.KeyIDKey, "test-key-1")
		key.Set(jwk.AlgorithmKey, jwa.RS256)

		signed, _ := jwt.Sign(token, jwt.WithKey(jwa.RS256, key))
		cred := &JWTCredential{BearerCredential: BearerCredential{Token: string(signed)}}

		_, err = validator.Validate(ctx, cred)
		if err == nil {
			t.Fatal("expected validation to fail for expired token")
		}
		if err != ErrExpiredToken {
			t.Errorf("expected ErrExpiredToken, got %v", err)
		}
	})

	t.Run("rejects JWT with wrong issuer", func(t *testing.T) {
		validator, err := NewJWTValidator(JWTValidatorConfig{
			Issuer:      "https://test-issuer.example.com",
			JWKSURL:     jwksURL,
			TrustDomain: "test-domain",
		})
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		tokenString := createTestJWT(t, privateKey, map[string]interface{}{
			"iss": "https://wrong-issuer.example.com",
			"sub": "user@example.com",
		})

		cred := &JWTCredential{BearerCredential: BearerCredential{Token: tokenString}}

		_, err = validator.Validate(ctx, cred)
		if err == nil {
			t.Fatal("expected validation to fail for wrong issuer")
		}
	})

	t.Run("rejects JWT with missing subject", func(t *testing.T) {
		validator, err := NewJWTValidator(JWTValidatorConfig{
			Issuer:      "https://test-issuer.example.com",
			JWKSURL:     jwksURL,
			TrustDomain: "test-domain",
		})
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		tokenString := createTestJWT(t, privateKey, map[string]interface{}{
			"iss": "https://test-issuer.example.com",
			// Missing "sub" claim
		})

		cred := &JWTCredential{BearerCredential: BearerCredential{Token: tokenString}}

		_, err = validator.Validate(ctx, cred)
		if err == nil {
			t.Fatal("expected validation to fail for missing subject")
		}
	})

	t.Run("extracts scope and custom claims", func(t *testing.T) {
		validator, err := NewJWTValidator(JWTValidatorConfig{
			Issuer:      "https://test-issuer.example.com",
			JWKSURL:     jwksURL,
			TrustDomain: "test-domain",
		})
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		tokenString := createTestJWT(t, privateKey, map[string]interface{}{
			"iss":    "https://test-issuer.example.com",
			"sub":    "user@example.com",
			"scope":  "read write",
			"groups": []string{"admins", "users"},
			"custom": "value",
		})

		cred := &JWTCredential{BearerCredential: BearerCredential{Token: tokenString}}

		result, err := validator.Validate(ctx, cred)
		if err != nil {
			t.Fatalf("validation failed: %v", err)
		}

		if result.Scope != "read write" {
			t.Errorf("expected scope 'read write', got %q", result.Scope)
		}
		if result.Claims["custom"] != "value" {
			t.Errorf("expected custom claim 'value', got %v", result.Claims["custom"])
		}
	})
}

func TestJWTValidatorConfig(t *testing.T) {
	t.Run("requires issuer", func(t *testing.T) {
		_, err := NewJWTValidator(JWTValidatorConfig{
			JWKSURL:     "https://example.com/jwks",
			TrustDomain: "test-domain",
		})
		if err == nil {
			t.Fatal("expected error for missing issuer")
		}
	})

	t.Run("uses default JWKS URL if not provided", func(t *testing.T) {
		// This will fail to fetch, but we're just testing the URL construction
		validator, _ := NewJWTValidator(JWTValidatorConfig{
			Issuer:      "https://test-issuer.example.com",
			TrustDomain: "test-domain",
		})

		expectedURL := "https://test-issuer.example.com/.well-known/jwks.json"
		if validator != nil && validator.jwksURL != expectedURL {
			t.Errorf("expected JWKS URL %q, got %q", expectedURL, validator.jwksURL)
		}
	})
}
