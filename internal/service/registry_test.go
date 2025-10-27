package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
)

func TestSimpleRegistry_GetAllPublicKeys(t *testing.T) {
	ctx := context.Background()

	t.Run("returns empty slice when no issuers registered", func(t *testing.T) {
		registry := NewSimpleRegistry()

		keys, err := registry.GetAllPublicKeys(ctx)
		if err != nil {
			t.Fatalf("GetAllPublicKeys failed: %v", err)
		}

		if len(keys) != 0 {
			t.Errorf("expected 0 keys, got %d", len(keys))
		}
	})

	t.Run("returns keys from single issuer", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		issuer := &testIssuerWithKeys{
			publicKeys: []PublicKey{
				{
					KeyID:     "test-key-1",
					Algorithm: "ES256",
					Use:       "sig",
					Key:       &privateKey.PublicKey,
				},
			},
		}

		registry := NewSimpleRegistry()
		registry.Register(TokenTypeTransactionToken, issuer)

		keys, err := registry.GetAllPublicKeys(ctx)
		if err != nil {
			t.Fatalf("GetAllPublicKeys failed: %v", err)
		}

		if len(keys) != 1 {
			t.Fatalf("expected 1 key, got %d", len(keys))
		}

		if keys[0].KeyID != "test-key-1" {
			t.Errorf("expected key ID 'test-key-1', got %q", keys[0].KeyID)
		}
	})

	t.Run("returns keys from multiple issuers", func(t *testing.T) {
		privateKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		privateKey2, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

		issuer1 := &testIssuerWithKeys{
			publicKeys: []PublicKey{
				{
					KeyID:     "issuer1-key",
					Algorithm: "ES256",
					Use:       "sig",
					Key:       &privateKey1.PublicKey,
				},
			},
		}

		issuer2 := &testIssuerWithKeys{
			publicKeys: []PublicKey{
				{
					KeyID:     "issuer2-key",
					Algorithm: "ES384",
					Use:       "sig",
					Key:       &privateKey2.PublicKey,
				},
			},
		}

		registry := NewSimpleRegistry()
		registry.Register(TokenTypeTransactionToken, issuer1)
		registry.Register(TokenTypeAccessToken, issuer2)

		keys, err := registry.GetAllPublicKeys(ctx)
		if err != nil {
			t.Fatalf("GetAllPublicKeys failed: %v", err)
		}

		if len(keys) != 2 {
			t.Fatalf("expected 2 keys, got %d", len(keys))
		}

		// Verify both keys are present
		keyIDs := make(map[string]bool)
		for _, key := range keys {
			keyIDs[key.KeyID] = true
		}

		if !keyIDs["issuer1-key"] {
			t.Error("expected issuer1-key to be present")
		}
		if !keyIDs["issuer2-key"] {
			t.Error("expected issuer2-key to be present")
		}
	})

	t.Run("handles issuers with multiple keys", func(t *testing.T) {
		privateKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		privateKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		issuer := &testIssuerWithKeys{
			publicKeys: []PublicKey{
				{
					KeyID:     "key-1",
					Algorithm: "ES256",
					Use:       "sig",
					Key:       &privateKey1.PublicKey,
				},
				{
					KeyID:     "key-2",
					Algorithm: "ES256",
					Use:       "sig",
					Key:       &privateKey2.PublicKey,
				},
			},
		}

		registry := NewSimpleRegistry()
		registry.Register(TokenTypeTransactionToken, issuer)

		keys, err := registry.GetAllPublicKeys(ctx)
		if err != nil {
			t.Fatalf("GetAllPublicKeys failed: %v", err)
		}

		if len(keys) != 2 {
			t.Fatalf("expected 2 keys, got %d", len(keys))
		}
	})

	t.Run("collects keys and aggregates errors from failing issuers", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		goodIssuer := &testIssuerWithKeys{
			publicKeys: []PublicKey{
				{
					KeyID:     "good-key",
					Algorithm: "ES256",
					Use:       "sig",
					Key:       &privateKey.PublicKey,
				},
			},
		}

		badIssuer := &testIssuerWithError{}

		registry := NewSimpleRegistry()
		registry.Register(TokenTypeTransactionToken, goodIssuer)
		registry.Register(TokenTypeAccessToken, badIssuer)

		keys, err := registry.GetAllPublicKeys(ctx)

		// Should get keys from the good issuer
		if len(keys) != 1 {
			t.Fatalf("expected 1 key from good issuer, got %d", len(keys))
		}

		if keys[0].KeyID != "good-key" {
			t.Errorf("expected key ID 'good-key', got %q", keys[0].KeyID)
		}

		// Should also return an aggregated error
		if err == nil {
			t.Error("expected error from bad issuer, got nil")
		} else {
			// Verify error message contains information about the failed issuer
			errMsg := err.Error()
			if !strings.Contains(errMsg, "urn:ietf:params:oauth:token-type:access_token") {
				t.Errorf("expected error to mention token type, got: %s", errMsg)
			}
		}
	})

	t.Run("returns error when all issuers fail", func(t *testing.T) {
		badIssuer1 := &testIssuerWithError{}
		badIssuer2 := &testIssuerWithError{}

		registry := NewSimpleRegistry()
		registry.Register(TokenTypeTransactionToken, badIssuer1)
		registry.Register(TokenTypeAccessToken, badIssuer2)

		keys, err := registry.GetAllPublicKeys(ctx)

		// Should get no keys
		if len(keys) != 0 {
			t.Errorf("expected 0 keys, got %d", len(keys))
		}

		// Should return an aggregated error
		if err == nil {
			t.Error("expected error when all issuers fail, got nil")
		} else {
			errMsg := err.Error()
			// Should mention that multiple issuers failed
			if !strings.Contains(errMsg, "2 issuers") {
				t.Errorf("expected error to mention 2 issuers, got: %s", errMsg)
			}
		}
	})

	t.Run("handles issuers with no keys", func(t *testing.T) {
		issuerWithoutKeys := &testIssuerWithKeys{
			publicKeys: []PublicKey{},
		}

		registry := NewSimpleRegistry()
		registry.Register(TokenTypeTransactionToken, issuerWithoutKeys)

		keys, err := registry.GetAllPublicKeys(ctx)
		if err != nil {
			t.Fatalf("GetAllPublicKeys failed: %v", err)
		}

		if len(keys) != 0 {
			t.Errorf("expected 0 keys, got %d", len(keys))
		}
	})
}

// testIssuerWithKeys is a test issuer that returns a predefined set of public keys
type testIssuerWithKeys struct {
	publicKeys []PublicKey
}

func (i *testIssuerWithKeys) Issue(ctx context.Context, issueCtx *IssueContext) (*Token, error) {
	return nil, nil
}

func (i *testIssuerWithKeys) PublicKeys(ctx context.Context) ([]PublicKey, error) {
	return i.publicKeys, nil
}

// testIssuerWithError is a test issuer that returns an error
type testIssuerWithError struct{}

func (i *testIssuerWithError) Issue(ctx context.Context, issueCtx *IssueContext) (*Token, error) {
	return nil, nil
}

func (i *testIssuerWithError) PublicKeys(ctx context.Context) ([]PublicKey, error) {
	return nil, context.Canceled
}
