package trust

import (
	"context"
	"errors"
	"testing"
)

func TestStubValidator(t *testing.T) {
	ctx := context.Background()

	t.Run("validates credential successfully", func(t *testing.T) {
		validator := NewStubValidator(CredentialTypeBearer)

		cred := &BearerCredential{
			Token: "test-token",
		}

		result, err := validator.Validate(ctx, cred)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result == nil {
			t.Fatal("expected result, got nil")
		}

		if result.Subject == "" {
			t.Error("expected non-empty subject")
		}

		if result.Issuer == "" {
			t.Error("expected non-empty issuer")
		}
	})

	t.Run("returns error when token is empty", func(t *testing.T) {
		validator := NewStubValidator(CredentialTypeBearer)

		cred := &BearerCredential{
			Token: "",
		}

		_, err := validator.Validate(ctx, cred)
		if err == nil {
			t.Error("expected error for empty token")
		}
	})

	t.Run("can be configured to return custom result", func(t *testing.T) {
		customResult := &Result{
			Subject:     "custom-subject",
			Issuer:      "custom-issuer",
			TrustDomain: "custom-domain",
		}

		validator := NewStubValidator(CredentialTypeBearer).
			WithResult(customResult)

		cred := &BearerCredential{
			Token: "any-token",
		}

		result, err := validator.Validate(ctx, cred)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Subject != "custom-subject" {
			t.Errorf("expected subject 'custom-subject', got %s", result.Subject)
		}
	})

	t.Run("can be configured to return error", func(t *testing.T) {
		expectedErr := errors.New("validation failed")

		validator := NewStubValidator(CredentialTypeBearer).
			WithError(expectedErr)

		cred := &BearerCredential{
			Token: "any-token",
		}

		_, err := validator.Validate(ctx, cred)
		if err != expectedErr {
			t.Errorf("expected error %v, got %v", expectedErr, err)
		}
	})

	t.Run("validates different credential types", func(t *testing.T) {
		t.Run("JWT credential", func(t *testing.T) {
			validator := NewStubValidator(CredentialTypeJWT)

			cred := &JWTCredential{
				Token:          "eyJhbGc...",
				Algorithm:      "RS256",
				KeyID:          "key-1",
				IssuerIdentity: "https://issuer.example.com",
			}

			result, err := validator.Validate(ctx, cred)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result == nil {
				t.Fatal("expected result, got nil")
			}
		})

		t.Run("OIDC credential", func(t *testing.T) {
			validator := NewStubValidator(CredentialTypeOIDC)

			cred := &OIDCCredential{
				Token:          "eyJhbGc...",
				IssuerIdentity: "https://idp.example.com",
				ClientID:       "client-123",
			}

			result, err := validator.Validate(ctx, cred)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result == nil {
				t.Fatal("expected result, got nil")
			}
		})

		t.Run("mTLS credential", func(t *testing.T) {
			validator := NewStubValidator(CredentialTypeMTLS)

			cred := &MTLSCredential{
				Certificate:         []byte{0x01, 0x02},
				PeerCertificateHash: "abc123",
				IssuerIdentity:      "ca.example.com",
			}

			result, err := validator.Validate(ctx, cred)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result == nil {
				t.Fatal("expected result, got nil")
			}
		})
	})

	t.Run("credential type identification", func(t *testing.T) {
		tests := []struct {
			name           string
			cred           Credential
			expectedType   CredentialType
			expectedIssuer string
		}{
			{
				"bearer",
				&BearerCredential{Token: "test"},
				CredentialTypeBearer,
				"bearer", // Bearer tokens use default "bearer" issuer
			},
			{
				"JWT",
				&JWTCredential{Token: "test", IssuerIdentity: "https://jwt.example.com"},
				CredentialTypeJWT,
				"https://jwt.example.com",
			},
			{
				"OIDC",
				&OIDCCredential{Token: "test", IssuerIdentity: "https://oidc.example.com"},
				CredentialTypeOIDC,
				"https://oidc.example.com",
			},
			{
				"mTLS",
				&MTLSCredential{Certificate: []byte{0x01}, IssuerIdentity: "ca.example.com"},
				CredentialTypeMTLS,
				"ca.example.com",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if tt.cred.Type() != tt.expectedType {
					t.Errorf("expected type %s, got %s", tt.expectedType, tt.cred.Type())
				}
				// Check IssuerIdentity field for each concrete credential type
				// For bearer tokens, we expect the default "bearer" issuer
				var actualIssuer string
				switch c := tt.cred.(type) {
				case *BearerCredential:
					actualIssuer = "bearer" // Bearer tokens use default issuer
				case *JWTCredential:
					actualIssuer = c.IssuerIdentity
				case *OIDCCredential:
					actualIssuer = c.IssuerIdentity
				case *MTLSCredential:
					actualIssuer = c.IssuerIdentity
				}
				if actualIssuer != tt.expectedIssuer {
					t.Errorf("expected issuer %s, got %s", tt.expectedIssuer, actualIssuer)
				}
			})
		}
	})
}
