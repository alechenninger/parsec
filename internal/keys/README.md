# Keys Package

The `keys` package provides cryptographic key management and rotation for signing operations.

## Overview

This package manages the lifecycle of signing keys, including creation, rotation, storage, and signing operations. It supports multiple storage backends (in-memory, disk, AWS KMS) and implements automatic key rotation with a dual-slot strategy.

## Core Interfaces

### RotatingSigner

The main interface for signing operations with automatic key rotation:

```go
type RotatingSigner interface {
    GetCurrentSigner(ctx context.Context) (crypto.Signer, KeyID, Algorithm, error)
    PublicKeys(ctx context.Context) ([]service.PublicKey, error)
    Start(ctx context.Context) error
    Stop()
}
```

**Implementation**: `DualSlotRotatingSigner` - Manages two key slots (A/B) for seamless rotation with grace periods.

### KeyProvider

Creates and manages keys in a specific backend:

```go
type KeyProvider interface {
    GetKeyHandle(ctx context.Context, namespace, keyName string) (KeyHandle, error)
}
```

**Implementations**:
- `InMemoryKeyManager` - Stores keys in memory (testing/development)
- `DiskKeyManager` - Stores keys as JSON files on disk
- `AWSKMSKeyManager` - Uses AWS KMS for key operations

### KeyHandle

Represents a logical key with signing and rotation capabilities:

```go
type KeyHandle interface {
    Sign(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, string, error)
    Metadata(ctx context.Context) (keyID, alg string, err error)
    Public(ctx context.Context) (crypto.PublicKey, error)
    Rotate(ctx context.Context) error
}
```

## Key Rotation

The `DualSlotRotatingSigner` implements automatic key rotation:

1. **Two Slots**: Maintains slots A and B for alternating keys
2. **Grace Period**: New keys are published before being used for signing
3. **TTL-based**: Keys rotate before expiration based on configurable thresholds
4. **Seamless**: No downtime during rotation

### Rotation Timeline

```
Key         TTL -              Rotation Time +
Generated   Threshold          Grace Period        TTL
^-----------^------------------^-------------------^-------->
            New key generated  New key used        Old key removed
```

## Configuration Example

```go
// Create key provider registry
diskKM, _ := keys.NewDiskKeyManager(keys.DiskKeyManagerConfig{
    KeyType:  keys.KeyTypeECP256,
    KeysPath: "/var/keys",
})

providerRegistry := map[string]keys.KeyProvider{
    "prod-keys": diskKM,
}

// Create rotating signer
signer := keys.NewDualSlotRotatingSigner(keys.DualSlotRotatingSignerConfig{
    TokenType:          "urn:ietf:params:oauth:token-type:txn_token",
    TrustDomain:        "example.com",
    KeyProviderID:       "prod-keys",
    KeyProviderRegistry: providerRegistry,
    SlotStore:          keys.NewInMemoryKeySlotStore(),
    KeyTTL:             24 * time.Hour,
    RotationThreshold:  6 * time.Hour,
    GracePeriod:        2 * time.Hour,
})

signer.Start(context.Background())
defer signer.Stop()
```

## Key Providers

### Disk Provider

Suitable for single-pod deployments with persistent volumes:

```go
km, err := keys.NewDiskKeyManager(keys.DiskKeyManagerConfig{
    KeyType:  keys.KeyTypeECP256,
    KeysPath: "/mnt/keys",
})
```

### AWS KMS Provider

For production deployments requiring hardware security:

```go
km, err := keys.NewAWSKMSKeyManager(ctx, keys.AWSKMSConfig{
    KeyType:     keys.KeyTypeECP256,
    Region:      "us-east-1",
    AliasPrefix: "alias/parsec/",
})
```

## Supported Key Types

- `KeyTypeECP256` - ECDSA P-256 (ES256)
- `KeyTypeECP384` - ECDSA P-384 (ES384)
- `KeyTypeRSA2048` - RSA 2048-bit (RS256)
- `KeyTypeRSA4096` - RSA 4096-bit (RS256)

## Key Namespacing

Keys are namespaced by trust domain and token type to prevent collisions when multiple services share infrastructure:

```
namespace = trustDomain + ":" + tokenType
```

## Key Identifiers

Public key IDs (`kid` in JWTs) are computed as RFC 7638 JWK Thumbprints, ensuring they're deterministic and collision-resistant.

## Concurrency & Multi-Pod Support

- **Key Slot Store**: Uses optimistic locking for coordination
- **Single-Pod**: In-memory slot store works within a pod
- **Multi-Pod**: Requires distributed slot store implementation (future work)
- **Race Conditions**: Handled gracefully; duplicate key creation is acceptable

## Testing

The package includes comprehensive tests for all providers and rotation scenarios. Use `InMemoryKeyManager` for unit tests.

