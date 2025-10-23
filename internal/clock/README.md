# Clock Package

The clock package provides time abstractions for testability, enabling precise control over time-dependent behavior in tests.

## Overview

Time is a form of IO that needs to be controlled in tests. The `Clock` interface allows code to use an injectable time source rather than depending directly on `time.Now()`.

## Interface

```go
type Clock interface {
    Now() time.Time
}
```

## Implementations

### SystemClock

For production use - wraps the real system clock:

```go
clock := clock.NewSystemClock()
now := clock.Now() // Returns time.Now()
```

### FixtureClock

For testing - provides controllable time:

```go
// Start at a specific time
fixedTime := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)
clk := clock.NewFixtureClock(fixedTime)

// Get current time (frozen)
now := clk.Now() // Returns fixedTime

// Manipulate time
clk.Set(time.Date(2024, 12, 25, 12, 0, 0, 0, time.UTC))
clk.Advance(2 * time.Hour)
clk.Rewind(30 * time.Minute)
```

## API

### FixtureClock Methods

- `NewFixtureClock(startTime time.Time)` - Create clock at specific time (uses time.Now() if zero time provided)
- `Now()` - Get current fixture time (frozen unless explicitly manipulated)
- `Set(t time.Time)` - Set clock to specific time
- `Advance(d time.Duration)` - Move time forward by duration
- `Rewind(d time.Duration)` - Move time backward by duration

## Usage

### In Production Code

Accept a `Clock` interface and default to `SystemClock`:

```go
type TokenIssuer struct {
    clock clock.Clock
}

func NewTokenIssuer(clk clock.Clock) *TokenIssuer {
    if clk == nil {
        clk = clock.NewSystemClock()
    }
    return &TokenIssuer{clock: clk}
}

func (i *TokenIssuer) IssueToken() string {
    now := i.clock.Now()
    // Use now for timestamps...
}
```

### In Tests

Inject a `FixtureClock` for precise control:

```go
func TestTokenExpiration(t *testing.T) {
    // Create fixture clock
    fixedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
    clk := clock.NewFixtureClock(fixedTime)
    
    // Inject into components
    issuer := NewTokenIssuer(clk)
    validator := NewTokenValidator(clk)
    
    // Issue token valid for 1 hour
    token := issuer.IssueToken()
    
    // Token is valid now
    if err := validator.Validate(token); err != nil {
        t.Error("token should be valid")
    }
    
    // Advance time past expiration
    clk.Advance(2 * time.Hour)
    
    // Token should now be expired
    if err := validator.Validate(token); err == nil {
        t.Error("token should be expired")
    }
}
```

## Benefits

- **Deterministic Tests**: Tests don't depend on system time or wall clock
- **Fast Tests**: No need to wait for time to pass
- **Precise Control**: Test exact time boundaries and edge cases
- **Reproducible**: Same behavior every test run
- **Edge Case Testing**: Easy to test scenarios like:
  - Tokens expiring during validation
  - Time-based rate limiting
  - Scheduled task execution
  - TTL expiration

## Integration

The clock package is integrated with:

- **JWKS Fixtures**: Accept `Clock` for token timestamp generation
- **JWT Validators**: Accept `Clock` for token validation
- **Future Components**: Any time-dependent component should accept a `Clock`

## Example: Testing Token Expiration

```go
func TestJWTExpiration(t *testing.T) {
    // Create shared clock
    fixedTime := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)
    clk := clock.NewFixtureClock(fixedTime)
    
    // Create fixture with clock
    jwksFixture, _ := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
        Issuer:  "https://auth.example.com",
        JWKSURL: "https://auth.example.com/.well-known/jwks.json",
        Clock:   clk,
    })
    
    // Create validator with same clock
    validator, _ := trust.NewJWTValidator(trust.JWTValidatorConfig{
        Issuer:      jwksFixture.Issuer(),
        JWKSURL:     jwksFixture.JWKSURL(),
        TrustDomain: "test",
        HTTPClient:  httpClientWithFixture(jwksFixture),
        Clock:       clk, // Same clock!
    })
    
    // Create token (expires 1 hour from fixedTime)
    token, _ := jwksFixture.CreateAndSignToken(map[string]interface{}{
        "sub": "user@example.com",
    })
    
    // Valid at fixedTime
    _, err := validator.Validate(ctx, createCredential(token))
    assert.NoError(t, err)
    
    // Still valid 30 minutes later
    clk.Advance(30 * time.Minute)
    _, err = validator.Validate(ctx, createCredential(token))
    assert.NoError(t, err)
    
    // Expired 1 hour 1 minute later
    clk.Advance(31 * time.Minute)
    _, err = validator.Validate(ctx, createCredential(token))
    assert.Error(t, err)
    assert.Equal(t, trust.ErrExpiredToken, err)
}
```

## Design Principles

1. **Simple Interface**: Just one method (`Now()`) makes it easy to implement and use
2. **Zero Overhead**: Using `SystemClock` in production has negligible overhead
3. **Explicit Control**: Time only changes when you explicitly manipulate the fixture clock
4. **No Hidden State**: Time is frozen in tests unless you advance it
5. **Composability**: Same clock can be shared across multiple components for consistent time

## Testing the Clock

The clock package itself has comprehensive tests demonstrating all functionality:

- `clock_test.go` - All clock implementations and manipulation methods
- `internal/httpfixture/jwks_fixture_test.go` - Integration with JWKS fixtures
- `internal/trust/jwt_validator_test.go` - Integration with JWT validators

