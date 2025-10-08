# Component Contracts

This document defines the interfaces (contracts) between major components in parsec.

## Core Interfaces

### 1. Validator (`internal/validator/validator.go`)

**Purpose**: Validates external credentials and returns claims about the authenticated subject.

```go
type Validator interface {
    Validate(ctx context.Context, credential *Credential) (*Result, error)
    Type() CredentialType
}
```

**Responsibilities**:
- Accept a `Credential` (token, certificate, etc.)
- Validate against the appropriate trust anchor (JWKS, introspection endpoint, CA, etc.)
- Return structured `Result` with subject, issuer, claims
- Return error if validation fails

**Implementations**:
- `StubValidator` - For testing, accepts any non-empty token
- TODO: `OIDCValidator` - Validates JWT tokens with JWKS
- TODO: `OAuth2Validator` - Uses introspection endpoint
- TODO: `MTLSValidator` - Validates client certificates

### 2. Issuer (`internal/issuer/issuer.go`)

**Purpose**: Issues transaction tokens based on validated credentials.

```go
type Issuer interface {
    Issue(ctx context.Context, result *validator.Result, reqCtx *RequestContext) (*Token, error)
    JWKSURI() string
}
```

**Responsibilities**:
- Accept validation result and request context
- Generate transaction token (JWT) with appropriate claims
- Sign token with private key
- Return `Token` with value, type, expiry
- Provide JWKS URI for token verification

**Implementations**:
- `StubIssuer` - For testing, generates simple token strings
- TODO: `JWTIssuer` - Real JWT implementation with signing

### 3. Store (`internal/trust/store.go`)

**Purpose**: Manages trust domains and provides validators for credentials.

```go
type Store interface {
    Validate(ctx context.Context, credential trust.Credential) (*trust.Result, error)
}
```

**Responsibilities**:
- Store trust domain configurations
- Validate credentials by determining the appropriate validator based on credential type and issuer
- Provide trust domain metadata (JWKS URIs, introspection endpoints, etc.)

**Implementations**:
- `StubStore` (in `trust` package) - In-memory store for testing
- TODO: `StaticStore` - Loads from YAML configuration
- TODO: `DynamicStore` - Reloadable configuration

## Data Flow

### Token Exchange Flow

```
1. Client → POST /v1/token (RFC 8693 request)
                ↓
2. ExchangeServer.Exchange()
                ↓
3. Store.Validate() → Validate credential (determines issuer internally)
                ↓
4. Issuer.Issue() → Generate transaction token
                ↓
5. Return TokenExchangeResponse
```

### ext_authz Flow

```
1. Envoy → gRPC Check(CheckRequest)
                ↓
2. AuthzServer.Check()
                ↓
3. extractCredential() → Parse Authorization header
                ↓
4. Store.Validate() → Validate credential (determines issuer internally)
                ↓
5. Issuer.Issue() → Generate transaction token
                ↓
6. Return CheckResponse with Transaction-Token header
```

## Dependency Injection

All services accept their dependencies via constructors:

```go
// Create dependencies
trustStore := trust.NewStubStore()
tokenIssuer := issuer.NewStubIssuer(...)

// Inject into services
authzServer := server.NewAuthzServer(trustStore, tokenIssuer)
exchangeServer := server.NewExchangeServer(trustStore, tokenIssuer)

// Start server
srv := server.New(server.Config{
    AuthzServer:    authzServer,
    ExchangeServer: exchangeServer,
})
```

This enables:
- **Testability**: Swap real implementations with stubs/mocks
- **Flexibility**: Change implementations without modifying consumers
- **Clarity**: Explicit dependencies visible in function signatures

## Testing Strategy

### Unit Tests

Each component can be tested in isolation:

```go
// Test validator independently
validator := NewStubValidator(CredentialTypeBearer)
result, err := validator.Validate(ctx, &Credential{Token: "test"})

// Test issuer independently  
issuer := NewStubIssuer("https://parsec.test", 5*time.Minute)
token, err := issuer.Issue(ctx, validationResult, reqCtx)
```

### Integration Tests

Wire components together with stubs:

```go
// Setup
trustStore := validator.NewStubStore()
trustStore.AddValidator(...)

// Test full flow
authzServer := server.NewAuthzServer(trustStore, tokenIssuer)
response := authzServer.Check(ctx, envoyRequest)
```

### Test Coverage

✅ **Validator**:
- `validator_test.go` - Tests stub validator behavior
- Configurable results and errors
- Empty token validation

✅ **Issuer**:
- `issuer_test.go` - Tests stub issuer behavior
- Token generation
- TTL handling
- Transaction ID uniqueness

✅ **Server**:
- `form_marshaler_test.go` - RFC 8693 form encoding
- `token_exchange_test.go` - End-to-end integration tests

## Future Implementations

### Real Validator (OIDC)

```go
type OIDCValidator struct {
    jwksClient *jwks.Client
    issuer     string
    audience   string
}

func (v *OIDCValidator) Validate(ctx context.Context, cred *Credential) (*Result, error) {
    // Parse JWT
    // Fetch JWKS
    // Verify signature
    // Validate claims (iss, aud, exp)
    // Return Result
}
```

### Real Issuer (JWT)

```go
type JWTIssuer struct {
    keyManager keymanager.Manager  // Spire KeyManager
    issuer     string
    audience   string
}

func (i *JWTIssuer) Issue(ctx context.Context, result *validator.Result, reqCtx *RequestContext) (*Token, error) {
    // Get signing key from KeyManager
    // Build TokenClaims (txn, azd, purp, req_ctx)
    // Sign JWT
    // Return Token
}
```

### Static Store

```go
type StaticStore struct {
    domains map[string]*Domain
    config  *Config
}

func NewStaticStore(configPath string) (*StaticStore, error) {
    // Load YAML config
    // Create validators for each domain
    // Return store
}
```

## Key Design Principles

1. **Interface-driven**: All major components defined by interfaces
2. **Dependency injection**: Explicit dependencies via constructors
3. **Testability**: Stub implementations for all interfaces
4. **Separation of concerns**: Each component has a single responsibility
5. **Extensibility**: New implementations without changing consumers

## Next Steps

1. ✅ Define core interfaces
2. ✅ Create stub implementations
3. ✅ Wire into server handlers
4. ✅ Write unit tests
5. ✅ Validate architecture with integration tests
6. 🚧 Integrate Spire KeyManager
7. 🚧 Implement JWT issuer
8. 🚧 Implement OIDC validator
9. 🚧 Implement configuration loading

