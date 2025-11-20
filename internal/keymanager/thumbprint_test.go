package keymanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeThumbprint_ECDSA_P256(t *testing.T) {
	// Generate an EC P-256 key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Compute thumbprint
	thumbprint, err := ComputeThumbprint(privateKey.Public())
	require.NoError(t, err)

	// Thumbprint should be base64url encoded (43 characters for SHA-256)
	assert.Len(t, thumbprint, 43, "SHA-256 thumbprint should be 43 characters")
	assert.NotContains(t, thumbprint, "+", "base64url should not contain +")
	assert.NotContains(t, thumbprint, "/", "base64url should not contain /")
	assert.NotContains(t, thumbprint, "=", "base64url should not contain padding")
}

func TestComputeThumbprint_ECDSA_P384(t *testing.T) {
	// Generate an EC P-384 key
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	// Compute thumbprint
	thumbprint, err := ComputeThumbprint(privateKey.Public())
	require.NoError(t, err)

	// Thumbprint should be base64url encoded (43 characters for SHA-256)
	assert.Len(t, thumbprint, 43, "SHA-256 thumbprint should be 43 characters")
	assert.NotContains(t, thumbprint, "+", "base64url should not contain +")
	assert.NotContains(t, thumbprint, "/", "base64url should not contain /")
	assert.NotContains(t, thumbprint, "=", "base64url should not contain padding")
}

func TestComputeThumbprint_RSA(t *testing.T) {
	// Generate an RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Compute thumbprint
	thumbprint, err := ComputeThumbprint(privateKey.Public())
	require.NoError(t, err)

	// Thumbprint should be base64url encoded (43 characters for SHA-256)
	assert.Len(t, thumbprint, 43, "SHA-256 thumbprint should be 43 characters")
	assert.NotContains(t, thumbprint, "+", "base64url should not contain +")
	assert.NotContains(t, thumbprint, "/", "base64url should not contain /")
	assert.NotContains(t, thumbprint, "=", "base64url should not contain padding")
}

func TestComputeThumbprint_Deterministic(t *testing.T) {
	// Generate an EC P-256 key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Compute thumbprint multiple times
	thumbprint1, err := ComputeThumbprint(privateKey.Public())
	require.NoError(t, err)

	thumbprint2, err := ComputeThumbprint(privateKey.Public())
	require.NoError(t, err)

	// Thumbprints should be identical for the same key
	assert.Equal(t, thumbprint1, thumbprint2, "thumbprint should be deterministic")
}

func TestComputeThumbprint_UniquenessAcrossDifferentKeys(t *testing.T) {
	// Generate two different keys
	privateKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privateKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Compute thumbprints
	thumbprint1, err := ComputeThumbprint(privateKey1.Public())
	require.NoError(t, err)

	thumbprint2, err := ComputeThumbprint(privateKey2.Public())
	require.NoError(t, err)

	// Thumbprints should be different for different keys
	assert.NotEqual(t, thumbprint1, thumbprint2, "different keys should have different thumbprints")
}

func TestComputeThumbprint_UniquenessAcrossDifferentKeyTypes(t *testing.T) {
	// Generate EC and RSA keys
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Compute thumbprints
	ecThumbprint, err := ComputeThumbprint(ecKey.Public())
	require.NoError(t, err)

	rsaThumbprint, err := ComputeThumbprint(rsaKey.Public())
	require.NoError(t, err)

	// Thumbprints should be different for different key types
	assert.NotEqual(t, ecThumbprint, rsaThumbprint, "different key types should have different thumbprints")
}
