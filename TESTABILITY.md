# Testability

We want production configurations to be testable.

However, production configurations are necessarily coupled to the environment.

## Hermetic mode

What is coupled to the environment?

- Validators: depend on trust bundles, which may be fetched at runtime, and testing relies on their corresponding private keys used to issue credentials, which we'll never have.
- Data sources: likely use network calls to fetch data.
- Issuers: may be invoked over a network, or utilize an external KMS or key store.

All of these need to be designed to be testable. We want to be careful not to "mock" so much away that we lose confidence in our configuration, missing the entire point.

We need to make sure the right abstractions are injectable, in order to enable hermetic mode. We'll do this by ensuring any IO is using an injectable abstraction. For example, where an HTTP request is made, an HTTP client can be injected. Where the filesystem is accessed, a filesystem interface can be injected. Replacements can respond without relying on the environment.

- **Validators**: ✅ JWT validators support HTTP client injection for JWKS fetching. JWKS fixtures provide both HTTP responses and signing APIs for tests. Future: mtls validator with CA bundle fixtures.
- **Data sources**: ✅ HTTP fixtures are available for Lua data sources via configuration. These implement the inversion of control we want.
- **Issuers**: We don't have any signing issuers now that require external services, but fixtures for external issuer services, KMS, or key stores could follow the same pattern.

These fixtures need certain behavior, ranging from simple canned responses for a well known request, to potentially whole faked stateful services. Fixtures should be defined with "types" which can express anything from simple HTTP matching, to an entire fake service that implements some well known protocol (e.g. a JWKS endpoint with in memory generated keys). These fixtures may then have API that can be reused in tests, such as a JWKS fixture being able to sign tokens.

Here is an example configuration (actual configuration schema may be different in practice, and doesn't necessarily even need to be configuration-based):

```
# normal production validator config...
validators:
- name: prod-jwt-validator
  type: jwt_validator
  issuer: "https://idp.example.com"
  jwks_url: "https://idp.example.com/.well-known/jwks.json"
  trust_domain: "prod.example.com"
  refresh_interval: "15m"
- name: mtls-validator
  type: mtls_validator
  trust_domain: "mesh.prod.example.com"
  ca_source: "file:///path/to/ca.pem

# Defined fixtures for testing
fixtures:
  - type: jwks
    issuer_name: prod-jwt-issuer
    url: https://idp.example.com/.well-known/jwks.json
  - type: ca_bundle_file
    issuer_name: mtls-issuer
    path: /path/to/ca.pem
  - type: http_rule
    request:
      method: GET
      # etc...
    response:
      status: 200
      # etc...  
  - type: keymanager
    token_type: "urn:ietf:params:oauth:token-type:txn_token"
    
```

Fixtures should have a config-based API as well as a usable Go API. Tests can then simply be written as separate go tests which use parsec as a library, given the production configuration, and installed fixtures via the Go API. This Go API then also exposes methods for testing as needed, e.g. CA and JWKS fixtures should allow issuing or signing credentials.

Allowing configuration via standard config methods (e.g. file) enables the possibility of the server itself running in a "hermetic" mode for experimentation or integration testing with other systems (e.g. embedded in a testcontainer). This can be explored in the future.

## Implementation Status

### ✅ Completed: JWKS Fixtures for JWT Validators

JWT validators can now be tested hermetically using JWKS fixtures. The implementation follows the design outlined above:

#### HTTP Client Injection
- `JWTValidator` accepts an optional `HTTPClient` via `JWTValidatorConfig`
- The jwx library's JWKS cache uses the injected client for fetching JWKS
- HTTP requests can be intercepted using the existing `httpfixture.Transport`

#### JWKS Fixture Type
- `httpfixture.NewJWKSFixture()` creates a fixture with auto-generated RSA key pairs
- Implements `FixtureProvider` interface to serve JWKS responses
- Provides signing API methods:
  - `CreateAndSignToken()` - creates JWT with standard claims automatically set
  - `CreateAndSignTokenWithExpiry()` - creates JWT with custom expiry
  - `SignToken()` - signs pre-built tokens for maximum control
- Supports custom key IDs and algorithms

#### Usage Example

```go
// Create JWKS fixture
fixture, _ := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
    Issuer:  "https://auth.example.com",
    JWKSURL: "https://auth.example.com/.well-known/jwks.json",
})

// Create validator with fixture
httpClient := &http.Client{
    Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
        Provider: fixture,
        Strict:   true,
    }),
}

validator, _ := trust.NewJWTValidator(trust.JWTValidatorConfig{
    Issuer:      fixture.Issuer(),
    JWKSURL:     fixture.JWKSURL(),
    TrustDomain: "test-domain",
    HTTPClient:  httpClient,
})

// Create and sign test token
tokenString, _ := fixture.CreateAndSignToken(map[string]interface{}{
    "sub": "user@example.com",
    "role": "admin",
})
```

#### Benefits
- ✅ No httptest servers needed
- ✅ Faster test execution
- ✅ Hermetic - no external dependencies
- ✅ Ergonomic API for creating test scenarios
- ✅ Works with production validator code
- ✅ Precise time control for testing expiration scenarios

See `internal/httpfixture/README.md` for complete documentation and `internal/trust/jwt_validator_test.go` for usage examples.

### ✅ Completed: Clock Fixtures for Time Control

Time is another form of IO that needs to be controlled in tests. A clock abstraction enables precise control over time-dependent behavior.

#### Clock Interface
- `clock.Clock` interface abstracts time operations
- `clock.SystemClock` for production use (wraps `time.Now()`)
- `clock.FixtureClock` for testing with controllable time

#### Clock Fixture API
- `NewFixtureClock(startTime)` - create clock at specific time
- `Now()` - get current fixture time (frozen unless manipulated)
- `Set(time)` - set fixture to specific time
- `Advance(duration)` - move time forward
- `Rewind(duration)` - move time backward

#### Integration
- JWKS fixtures accept optional `Clock` for token timestamp generation (iat, exp)
- JWT validators accept optional `Clock` for token validation
- **Token issuers** accept optional `Clock` for issued token timestamps (iat, exp)
- Using the same clock across all components ensures consistent time behavior in tests

#### Usage Example

```go
// Create fixture clock at specific time
fixedTime := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)
clk := clock.NewFixtureClock(fixedTime)

// Create JWKS fixture with controlled clock
fixture, _ := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
    Issuer:  "https://auth.example.com",
    JWKSURL: "https://auth.example.com/.well-known/jwks.json",
    Clock:   clk,
})

// Create validator with same clock
validator, _ := trust.NewJWTValidator(trust.JWTValidatorConfig{
    Issuer:      fixture.Issuer(),
    JWKSURL:     fixture.JWKSURL(),
    TrustDomain: "test-domain",
    HTTPClient:  httpClient,
    Clock:       clk, // Same clock
})

// Create issuer with same clock
issuer := issuer.NewUnsignedIssuer(issuer.UnsignedIssuerConfig{
    TokenType:    "urn:ietf:params:oauth:token-type:txn_token",
    ClaimMappers: []service.ClaimMapper{...},
    Clock:        clk, // Same clock
})

// Create token valid for 1 hour
token, _ := fixture.CreateAndSignToken(map[string]interface{}{
    "sub": "user@example.com",
})

// Token is valid now
validator.Validate(ctx, cred) // ✅ succeeds

// Advance clock by 30 minutes - still valid
clk.Advance(30 * time.Minute)
validator.Validate(ctx, cred) // ✅ succeeds

// Advance by 31 more minutes - expired
clk.Advance(31 * time.Minute)
validator.Validate(ctx, cred) // ❌ fails with ErrExpiredToken
```

#### Benefits
- ✅ Precise control over token timestamps
- ✅ Test expiration scenarios without waiting
- ✅ Reproducible tests independent of system time
- ✅ Test time-based edge cases (e.g., tokens expiring during validation)

See `internal/clock/` package and `internal/trust/jwt_validator_test.go` for usage examples.

### Future Work

Following the same pattern established with JWKS fixtures:

- **CA Bundle Fixtures**: For testing mTLS validators with client certificates
- **Config-based Fixtures**: Allow fixtures to be defined in configuration files
- **Key Rotation**: Support multiple keys in JWKS for testing key rotation scenarios
- **OIDC Discovery**: Fixtures for OIDC discovery endpoints
- **Issuer Fixtures**: For testing external signing services, KMS, key stores