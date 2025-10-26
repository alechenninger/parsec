# KeyManager Package

This package provides integration with Spire's KeyManager plugin interface, including automatic key rotation for zero-downtime key management.

## Overview

Spire provides a rich set of KeyManager plugin implementations for managing cryptographic keys across different backends (disk, memory, cloud KMS providers, etc.). This package provides:

1. **RotatingKeyManager**: Automatic dual-key rotation with grace periods
2. **BaseAdapter**: Adapter for Spire's keymanagerbase.Base to the KeyManager interface
3. **KeyStateStore**: Interface for persisting key state with concurrency control

## RotatingKeyManager

`RotatingKeyManager` manages automatic key rotation using a dual-key (A/B) pattern to ensure zero-downtime during key transitions.

### Features

- **Dual-key rotation**: Uses alternating keys (key-a and key-b) for seamless rotation
- **Grace period**: New keys are not used immediately after generation, allowing time for distribution
- **Automatic rotation**: Background goroutine monitors key expiration and rotates proactively
- **Concurrency safe**: Uses optimistic locking to prevent multiple processes from generating keys simultaneously
- **Configurable timing**: Key TTL, rotation threshold, and grace period are all configurable

### Usage

```go
import (
	"context"
	"time"
	
	"github.com/lestrrat-go/jwx/v2/jwa"
	spirekm "github.com/spiffe/spire/pkg/server/plugin/keymanager"
	keymanagerbase "github.com/spiffe/spire/pkg/server/plugin/keymanager/base"
	
	"github.com/alechenninger/parsec/internal/keymanager"
)

// Initialize Spire KeyManager
baseKM := keymanagerbase.New(keymanagerbase.Config{})
spireKM := keymanager.NewBaseAdapter(baseKM)

// Initialize key state store
stateStore := keymanager.NewInMemoryKeyStateStore()

// Create rotating key manager
rotatingKM := keymanager.NewRotatingKeyManager(keymanager.RotatingKeyManagerConfig{
	KeyManager: spireKM,
	StateStore: stateStore,
	KeyType:    spirekm.ECP256,
	Algorithm:  jwa.ES256.String(),
	// Optional: override defaults
	KeyTTL:            24 * time.Hour,
	RotationThreshold: 6 * time.Hour,
	GracePeriod:       2 * time.Hour,
})

// Start rotation (generates initial key if needed)
ctx := context.Background()
if err := rotatingKM.Start(ctx); err != nil {
	// Handle error
}
defer rotatingKM.Stop()

// Sign data (automatically uses the current active key)
result, err := rotatingKM.Sign(ctx, []byte("data to sign"))
if err != nil {
	// Handle error
}
// result.Signature contains the signature
// result.KeyID contains the key ID used
// result.Algorithm contains the algorithm

// Get all non-expired public keys for verification
publicKeys, err := rotatingKM.PublicKeys(ctx)
if err != nil {
	// Handle error
}
```

### Integration with JWT Issuer

The JWT transaction token issuer uses `RotatingKeyManager` to handle key rotation automatically:

```go
issuer := issuer.NewJWTTransactionTokenIssuer(issuer.JWTTransactionTokenIssuerConfig{
	IssuerURL:        "https://example.com",
	TTL:              5 * time.Minute,
	SigningAlgorithm: jwa.ES256,
	KeyManager:       rotatingKM,
	// ... other config
})
```

### Rotation Timing

The rotation follows this pattern:

1. **Initial state**: When started, generates key-a if no keys exist
2. **Active period**: Key is used for signing once past its grace period
3. **Pre-rotation**: When a key is within the rotation threshold of expiration, the alternate key is generated
4. **Grace period**: Newly generated key is distributed but not yet used for signing
5. **Transition**: Once the grace period passes, the new key becomes active
6. **Expiration**: Old key expires and is removed from public keys

**Default timing (configurable):**
- Key TTL: 24 hours
- Rotation threshold: 6 hours before expiration
- Grace period: 2 hours after generation
- Check interval: 1 minute

### Key State Store

The `KeyStateStore` interface provides persistent storage for key metadata with optimistic locking:

```go
type KeyStateStore interface {
	GetKeyState(ctx context.Context, keyID string) (*KeyState, error)
	SaveKeyState(ctx context.Context, state *KeyState, expectedVersion *time.Time) error
	ListKeyStates(ctx context.Context) ([]*KeyState, error)
	DeleteKeyState(ctx context.Context, keyID string) error
}
```

**In-memory implementation**: `InMemoryKeyStateStore` provides a thread-safe in-memory implementation suitable for development and testing.

**Production use**: For production deployments with multiple instances, implement a persistent KeyStateStore backed by a database or distributed storage.

## BaseAdapter

`BaseAdapter` adapts Spire's `keymanagerbase.Base` to the `KeyManager` interface, allowing use of Spire's base key management functionality.

## Benefits

1. **Zero-downtime rotation**: Dual-key pattern ensures no service interruption during key rotation

2. **Automatic management**: Background process handles rotation without manual intervention

3. **Compatibility**: Use any of Spire's existing KeyManager plugins:
   - `disk` - File-based key storage
   - `memory` - In-memory keys (for testing)
   - `awskms` - AWS Key Management Service
   - `gcpkms` - Google Cloud Key Management Service
   - `azurekeyvault` - Azure Key Vault
   - And more...

4. **Testability**: Clock injection and configurable timing make rotation logic fully testable

5. **Safety**: Optimistic locking prevents multiple processes from generating keys concurrently

This design allows Parsec to leverage Spire's battle-tested key management infrastructure while providing automatic rotation capabilities for secure, zero-downtime operation.

