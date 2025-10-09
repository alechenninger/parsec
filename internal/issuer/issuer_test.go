package issuer

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alechenninger/parsec/internal/claims"
	"github.com/alechenninger/parsec/internal/trust"
)

func TestStubIssuer(t *testing.T) {
	ctx := context.Background()

	t.Run("issues token successfully", func(t *testing.T) {
		issuer := NewStubIssuer("https://parsec.example.com", 5*time.Minute)

		tokenCtx := &TokenContext{
			Subject: &trust.Result{
				Subject:     "user@example.com",
				Issuer:      "https://idp.example.com",
				TrustDomain: "example-domain",
			},
			TransactionContext: claims.Claims{},
			RequestContext: claims.Claims{
				"method": "GET",
				"path":   "/api/resource",
			},
			Audience: "test-audience",
		}

		token, err := issuer.Issue(ctx, tokenCtx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if token == nil {
			t.Fatal("expected token, got nil")
		}

		if token.Value == "" {
			t.Error("expected non-empty token value")
		}

		if token.Type != "urn:ietf:params:oauth:token-type:txn_token" {
			t.Errorf("expected txn_token type, got %s", token.Type)
		}

		if strings.Contains(token.Value, tokenCtx.Subject.Subject) == false {
			t.Error("expected token to contain subject")
		}
	})

	t.Run("token expires after configured TTL", func(t *testing.T) {
		ttl := 10 * time.Minute
		issuer := NewStubIssuer("https://parsec.example.com", ttl)

		tokenCtx := &TokenContext{
			Subject: &trust.Result{
				Subject: "test-user",
			},
			TransactionContext: claims.Claims{},
			RequestContext:     claims.Claims{},
		}

		token, err := issuer.Issue(ctx, tokenCtx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expectedExpiry := time.Now().Add(ttl)
		// Allow 1 second tolerance for test execution time
		diff := token.ExpiresAt.Sub(expectedExpiry)
		if diff > time.Second || diff < -time.Second {
			t.Errorf("expected expiry around %v, got %v (diff: %v)",
				expectedExpiry, token.ExpiresAt, diff)
		}
	})

	t.Run("returns empty public keys for unsigned tokens", func(t *testing.T) {
		issuerURL := "https://parsec.example.com"
		issuer := NewStubIssuer(issuerURL, 5*time.Minute)

		keys, err := issuer.PublicKeys(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if keys == nil {
			t.Fatal("expected keys slice, got nil")
		}

		// Stub issuer should return empty slice (unsigned tokens)
		if len(keys) != 0 {
			t.Errorf("expected empty keys slice, got %d keys", len(keys))
		}
	})

	t.Run("generates unique token values", func(t *testing.T) {
		issuer := NewStubIssuer("https://parsec.example.com", 5*time.Minute)

		tokenCtx := &TokenContext{
			Subject: &trust.Result{
				Subject: "test-user",
			},
			TransactionContext: claims.Claims{},
			RequestContext:     claims.Claims{},
		}

		token1, _ := issuer.Issue(ctx, tokenCtx)
		time.Sleep(10 * time.Millisecond) // Ensure different timestamp
		token2, _ := issuer.Issue(ctx, tokenCtx)

		if token1.Value == token2.Value {
			t.Error("expected unique token values")
		}
	})
}
