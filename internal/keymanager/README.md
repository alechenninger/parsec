# KeyManager Package

Manages cryptographic keys for JWT signing with automatic rotation and zero-downtime key transitions. Includes:

- **RotatingKeyManager**: Automatic dual-key (A/B) rotation with grace periods
- **KeyManager Implementations**: Memory, disk, and AWS KMS backends
- **KeySlotStore**: Rotation state persistence with optimistic locking

## KeyManager Implementations

Parsec supports the following KeyManager implementations:

- **memory**: In-memory key storage (default, good for development/testing)
- **disk**: Filesystem-based key storage with atomic file operations
- **aws_kms**: AWS Key Management Service for managed key storage

**All implementations** are currently limited to single-pod deployments due to the incomplete `InMemoryKeySlotStore`. A persistent `KeySlotStore` implementation is needed for multi-pod coordination regardless of which `KeyManager` is used.

### Configuration

```yaml
key_manager:
  type: "disk"              # "memory", "disk", or "aws_kms"
  keys_path: "/var/keys"    # disk only
  region: "us-east-1"       # aws_kms only
  alias_prefix: "alias/..."  # aws_kms only
```

Defaults to `memory` if omitted. See `configs/examples/parsec-keymanagers.yaml` for full examples.

### Kubernetes Usage

**DiskKeyManager** stores keys as JSON files with atomic writes (collision-safe via `os.CreateTemp`), file permissions 0600.

**⚠️ Current Limitation:** All KeyManagers use `InMemoryKeySlotStore` (incomplete) which:
- Loses rotation state on restart
- Cannot coordinate across pods
- **Limits all deployments to single-pod**

**Multi-Pod Support:** Requires persistent `KeySlotStore` (database/etcd backed). DiskKeyManager also needs RWX volume.

## RotatingKeyManager

Automatic dual-key (A/B) rotation with:
- Grace periods for key distribution before use
- Background monitoring and rotation
- Optimistic locking for concurrency safety
- Configurable timing (TTL, rotation threshold, grace period)
- Algorithm migration support (gradual, zero-downtime)
- Hot-path optimized (O(1) cached operations)

### Key Types and Algorithms

| KeyType | Compatible Algorithms | Recommended |
|---------|----------------------|-------------|
| `ECP256` | `ES256` | `ES256` |
| `ECP384` | `ES384` | `ES384` |
| `RSA2048` | `RS256`, `RS384`, `RS512` | `RS256` |
| `RSA4096` | `RS256`, `RS384`, `RS512` | `RS256`/`RS512` |

### Algorithm Migration

Algorithms are stored per-slot, enabling gradual zero-downtime migration:
1. Update config with new algorithm
2. New keys rotate in with new algorithm
3. Old keys remain valid until expiration
4. Verifiers accept both during transition

### Usage

```go
rotatingKM := keymanager.NewRotatingKeyManager(keymanager.RotatingKeyManagerConfig{
    KeyManager: km,  // memory, disk, or AWS KMS
    SlotStore:  keymanager.NewInMemoryKeySlotStore(),
    KeyType:    keymanager.KeyTypeECP256,
    Algorithm:  "ES256",
})

rotatingKM.Start(ctx)
defer rotatingKM.Stop()

// Get current signer (O(1), cached)
signer, keyID, algorithm, err := rotatingKM.GetCurrentSigner(ctx)

// Get all valid public keys (O(1), cached)
publicKeys, err := rotatingKM.PublicKeys(ctx)
```

### Performance

Hot-path operations (O(1), cached, no I/O):
- `GetCurrentSigner()` - active key
- `PublicKeys()` - all valid public keys

Cold-path (background):
- Rotation checks (every 1 min)
- Key generation (only when needed)

### Rotation Timing

Defaults (all configurable):
- Key TTL: 24h
- Rotation threshold: 6h before expiration
- Grace period: 2h after generation
- Check interval: 1min

Pattern: Generate alternate key at threshold → grace period for distribution → activate → expire old key.

### KeySlotStore

Stores rotation state with optimistic locking (store-level versioning). Returns `ErrVersionMismatch` on concurrent modifications.

**InMemoryKeySlotStore**: ⚠️ Incomplete - for testing/single-pod only. State lost on restart, no multi-pod coordination.

**Production**: Requires persistent implementation (database/etcd with atomic compare-and-swap).

## Summary

- **Zero-downtime rotation** via dual-key pattern
- **Automatic background rotation** with configurable timing  
- **Multiple backends** (memory, disk, AWS KMS)
- **Testable** (clock injection, deterministic timing)
- **Concurrent-safe** (optimistic locking)

