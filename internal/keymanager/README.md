# KeyManager Package

This package provides integration with Spire's KeyManager plugin interface, including automatic key rotation for zero-downtime key management.

## Overview

Spire provides a rich set of KeyManager plugin implementations for managing cryptographic keys across different backends (disk, memory, cloud KMS providers, etc.). This package provides:

1. **RotatingKeyManager**: Automatic dual-key rotation with grace periods
2. **Catalog Integration**: Uses Spire's catalog system to load KeyManager plugins
3. **KeySlotStore**: Interface for persisting key slots with concurrency control

## KeyManager Plugin Loading

Parsec uses Spire's catalog system to load KeyManager plugins. This allows you to use any of Spire's built-in KeyManager implementations:

- **memory**: In-memory key storage (default, good for development/testing)
- **disk**: File-based key storage (persists keys to disk)
- **awskms**: AWS Key Management Service
- **gcpkms**: Google Cloud Key Management Service
- **azurekeyvault**: Azure Key Vault

### Configuration

KeyManager plugins are configured using HCL (HashiCorp Configuration Language) in the `key_manager_plugin` field of your issuer configuration:

```yaml
issuers:
  - token_type: "urn:ietf:params:oauth:token-type:txn_token"
    type: "jwt"
    issuer_url: "https://example.com"
    ttl: "5m"
    key_manager_plugin: |
      KeyManager "disk" {
        plugin_data {
          keys_path = "/var/lib/parsec/keys"
        }
      }
```

If `key_manager_plugin` is omitted, Parsec defaults to the in-memory KeyManager.

See `configs/examples/parsec-keymanagers.yaml` for examples of all supported KeyManager plugins.

## RotatingKeyManager

`RotatingKeyManager` manages automatic key rotation using a dual-key (A/B) pattern to ensure zero-downtime during key transitions.

### Features

- **Dual-key rotation**: Uses alternating keys (key-a and key-b) for seamless rotation
- **Grace period**: New keys are not used immediately after generation, allowing time for distribution
- **Automatic rotation**: Background goroutine monitors key expiration and rotates proactively
- **Concurrency safe**: Uses optimistic locking to prevent multiple processes from generating keys simultaneously
- **Configurable timing**: Key TTL, rotation threshold, and grace period are all configurable
- **Flexible algorithm selection**: Supports any JWT signing algorithm compatible with the key type
- **Algorithm migration**: Algorithm is stored per-slot, allowing gradual migration to new algorithms over time
- **Hot-path optimized**: Both `GetCurrentSigner` and `PublicKeys` are O(1) operations using in-memory cache

### Supported Key Types and Algorithms

The `RotatingKeyManager` requires both a Spire `KeyType` (which determines the cryptographic key material) and a JWT signing `Algorithm` (which determines how signatures are computed).

**Common Configurations:**

| Spire KeyType | Compatible Algorithms | Recommended |
|---------------|----------------------|-------------|
| `ECP256` | `ES256` | `ES256` |
| `ECP384` | `ES384` | `ES384` |
| `RSA2048` | `RS256`, `RS384`, `RS512` | `RS256` |
| `RSA4096` | `RS256`, `RS384`, `RS512` | `RS256` or `RS512` |

**Note**: The key type and algorithm must be compatible (e.g., don't use `ES256` with `RSA2048`). The algorithm determines the hash function and signature format, while the key type determines the underlying key material.

### Algorithm Migration

The `RotatingKeyManager` stores the algorithm in the key slot, not just in the manager configuration. This enables gradual algorithm migration:

1. **Current state**: Keys are signed with `RS256`
2. **Configuration change**: Update the manager config to use `RS512`
3. **Next rotation**: New keys will be generated with `RS512`, while old keys remain valid with `RS256`
4. **Transition period**: Both algorithms are accepted during the grace period
5. **Completion**: Once old keys expire, all tokens use `RS512`

This zero-downtime migration happens automatically without any service interruption or coordination required.

**Example migration scenario:**

```go
// Week 1: Running with RS256
rotatingKM := keymanager.NewRotatingKeyManager(keymanager.RotatingKeyManagerConfig{
    KeyType:   spirekm.RSA4096,
    Algorithm: "RS256",
    // ...
})

// Week 2: Change config to RS512 and restart
rotatingKM := keymanager.NewRotatingKeyManager(keymanager.RotatingKeyManagerConfig{
    KeyType:   spirekm.RSA4096,
    Algorithm: "RS512",  // New keys will use RS512
    // ...
})
// Old RS256 keys remain valid until they expire
// Verifiers accept both RS256 and RS512 tokens during transition
```

### Usage

```go
import (
	"context"
	"time"
	
	spirekm "github.com/spiffe/spire/pkg/server/plugin/keymanager"
	keymanagerbase "github.com/spiffe/spire/pkg/server/plugin/keymanager/base"
	
	"github.com/alechenninger/parsec/internal/keymanager"
)

// Initialize Spire KeyManager
baseKM := keymanagerbase.New(keymanagerbase.Config{})
spireKM := keymanager.NewBaseAdapter(baseKM)

// Initialize key slot store
slotStore := keymanager.NewInMemoryKeySlotStore()

// Create rotating key manager
rotatingKM := keymanager.NewRotatingKeyManager(keymanager.RotatingKeyManagerConfig{
	KeyManager: spireKM,
	SlotStore:  slotStore,
	KeyType:    spirekm.ECP256,
	Algorithm:  "ES256", // JWT signing algorithm
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

// Get the current signer (automatically selects the active key)
signer, keyID, algorithm, err := rotatingKM.GetCurrentSigner(ctx)
if err != nil {
	// Handle error
}
// signer is a crypto.Signer for the current key
// keyID is the unique identifier for the key (type keymanager.KeyID)
// algorithm is the cryptographic algorithm (type keymanager.Algorithm, e.g., "ES256")

// Get all non-expired public keys for verification (cached, very fast)
publicKeys, err := rotatingKM.PublicKeys(ctx)
if err != nil {
	// Handle error
}
// publicKeys is []service.PublicKey with all non-expired keys (including keys in grace period)
// This is a hot-path operation - returns cached data without any I/O
```

### Integration with JWT Issuer

The JWT transaction token issuer uses `RotatingKeyManager` to handle key rotation automatically. The signing algorithm comes from the key manager, ensuring it always matches the key type:

```go
issuer := issuer.NewJWTTransactionTokenIssuer(issuer.JWTTransactionTokenIssuerConfig{
	IssuerURL:  "https://example.com",
	TTL:        5 * time.Minute,
	KeyManager: rotatingKM, // Algorithm provided by key manager
	// ... other config
})
```

### Performance and Caching

The `RotatingKeyManager` uses an in-memory cache for hot-path operations:

**Cached Data:**
- Active signing key (`crypto.Signer`)
- Active key's algorithm
- All non-expired public keys (for verification)

**Cache Updates:**
- Updated during initialization (`Start`)
- Updated periodically by the background rotation goroutine (every `checkInterval`, default 1 minute)
- Updated immediately after successful key generation and binding

**Hot Path Operations (O(1), no I/O):**
- `GetCurrentSigner()`: Returns cached active key, key ID, and algorithm
- `PublicKeys()`: Returns cached list of all non-expired public keys

**Cold Path Operations (involves state store and KeyManager):**
- Key rotation checks (periodic, in background)
- Key generation and binding (only when rotation needed)

This architecture ensures that token signing and public key retrieval (for verification) are extremely fast, while the expensive operations (state queries, key generation) happen infrequently in the background.

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

### Key Slot Store

The `KeySlotStore` interface provides persistent storage for key slots with optimistic locking:

```go
type KeySlotStore interface {
	GetSlot(ctx context.Context, slotID string) (*KeySlot, error)
	SaveSlot(ctx context.Context, slot *KeySlot, expectedVersion int64) error
	ListSlots(ctx context.Context) ([]*KeySlot, error)
}
```

**In-memory implementation**: `InMemoryKeySlotStore` provides a thread-safe in-memory implementation suitable for development and testing.

**Production use**: For production deployments with multiple instances, implement a persistent `KeySlotStore` backed by a database or distributed storage.

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

