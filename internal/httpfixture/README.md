# HTTP Fixture System

The HTTP fixture system provides a general-purpose mechanism for intercepting HTTP requests and returning predefined responses. This enables testing and development without external dependencies.

## Overview

The fixture system is built around a simple interface that allows flexible fixture provision strategies:

```go
type FixtureProvider interface {
    GetFixture(req *http.Request) *Fixture
}
```

This design allows:
- Simple matching implementations
- Script-based dynamic fixture generation
- Stateful providers that learn from requests
- Complete control over fixture selection logic

## Components

### Core Types

#### Fixture

Defines an HTTP response:

```go
type Fixture struct {
    StatusCode int               // HTTP status code
    Headers    map[string]string // Response headers
    Body       string            // Response body
    Delay      *time.Duration    // Optional delay before responding
}
```

#### FixtureProvider

Interface for providing fixtures based on requests:

```go
type FixtureProvider interface {
    GetFixture(req *http.Request) *Fixture
}
```

### Built-in Providers

#### MapProvider

Simple key-based lookup using "METHOD URL" format:

```go
provider := httpfixture.NewMapProvider(map[string]*httpfixture.Fixture{
    "GET https://api.example.com/data": {
        StatusCode: 200,
        Body:       `{"result": "success"}`,
    },
})
```

#### RuleBasedProvider

Matches requests against a set of rules with support for:
- Exact URL matching
- Pattern (regex) matching
- Method matching (including wildcard `*`)
- Header matching

```go
rules := []httpfixture.HTTPFixtureRule{
    {
        Request: httpfixture.FixtureRequest{
            Method:  "GET",
            URL:     "https://api.example.com/user/.*",
            URLType: "pattern",
        },
        Response: httpfixture.Fixture{
            StatusCode: 200,
            Body:       `{"user": "any"}`,
        },
    },
}
provider := httpfixture.NewRuleBasedProvider(rules)
```

#### FuncProvider

Maximum flexibility - use any function:

```go
provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
    if strings.HasPrefix(req.URL.Path, "/user/") {
        userID := strings.TrimPrefix(req.URL.Path, "/user/")
        return &httpfixture.Fixture{
            StatusCode: 200,
            Body:       fmt.Sprintf(`{"id": "%s"}`, userID),
        }
    }
    return nil
})
```

### Transport

The `Transport` implements `http.RoundTripper` and delegates fixture provision to a `FixtureProvider`:

```go
transport := httpfixture.NewTransport(httpfixture.TransportConfig{
    Provider: provider,
    Strict:   true,  // Error if no fixture provided
    Fallback: http.DefaultTransport,  // Optional fallback to real HTTP
})

client := &http.Client{Transport: transport}
```

## File-Based Fixtures

### Loading from Files

Fixtures can be defined in JSON or YAML files:

```go
// Load from a single file
provider, err := httpfixture.LoadFixturesFromFile("fixtures.yaml")

// Load from all files in a directory
provider, err := httpfixture.LoadFixturesFromDir("fixtures/")
```

### YAML Format

```yaml
fixtures:
  - request:
      method: GET
      url: https://api.example.com/data
      url_type: exact
    response:
      status: 200
      headers:
        Content-Type: application/json
      body: '{"data": "value"}'

  - request:
      method: GET
      url: https://api.example.com/user/.*
      url_type: pattern
    response:
      status: 200
      body: '{"user": "any"}'
```

### JSON Format

```json
{
  "fixtures": [
    {
      "request": {
        "method": "GET",
        "url": "https://api.example.com/data",
        "url_type": "exact"
      },
      "response": {
        "status": 200,
        "headers": {
          "Content-Type": "application/json"
        },
        "body": "{\"data\": \"value\"}"
      }
    }
  ]
}
```

## Usage with Lua Data Sources

The fixture system integrates seamlessly with Lua data sources:

```go
// Create a fixture provider
provider := httpfixture.NewMapProvider(map[string]*httpfixture.Fixture{
    "GET https://api.example.com/user/alice": {
        StatusCode: 200,
        Body:       `{"username": "alice"}`,
    },
})

// Configure Lua data source with fixtures
ds, err := datasource.NewLuaDataSource(datasource.LuaDataSourceConfig{
    Name:   "user-data",
    Script: script,
    HTTPConfig: &lua.HTTPServiceConfig{
        Timeout:         30 * time.Second,
        FixtureProvider: provider,
    },
})
```

## Testing Examples

### Basic Test with Fixtures

```go
func TestMyDataSource(t *testing.T) {
    provider := httpfixture.NewMapProvider(map[string]*httpfixture.Fixture{
        "GET https://api.example.com/data": {
            StatusCode: 200,
            Body:       `{"test": "data"}`,
        },
    })

    ds := setupDataSource(provider)
    result, err := ds.Fetch(context.Background(), input)
    
    // Assertions...
}
```

### Dynamic Fixtures

```go
func TestWithDynamicFixtures(t *testing.T) {
    callCount := 0
    provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
        callCount++
        return &httpfixture.Fixture{
            StatusCode: 200,
            Body:       fmt.Sprintf(`{"call": %d}`, callCount),
        }
    })

    // Test...
}
```

### File-Based Fixtures for Integration Tests

```go
func TestIntegration(t *testing.T) {
    provider, err := httpfixture.LoadFixturesFromFile("testdata/api_fixtures.yaml")
    if err != nil {
        t.Fatal(err)
    }

    ds := setupDataSource(provider)
    // Run integration test scenarios...
}
```

## Best Practices

1. **Use Fixtures for All Tests**: Avoid real HTTP calls in tests for speed and reliability
2. **Organize Fixtures**: Group related fixtures in separate files
3. **Be Specific**: Match exact URLs when possible, use patterns sparingly
4. **Order Matters**: In rule-based providers, place specific rules before generic ones
5. **Test Fixtures**: Verify your fixtures accurately represent real API responses
6. **Document Fixtures**: Add comments explaining complex patterns or edge cases
7. **Version Control**: Commit fixture files alongside tests

## Advanced Features

### Response Delays

Simulate network latency:

```go
delay := 100 * time.Millisecond
fixture := &httpfixture.Fixture{
    StatusCode: 200,
    Body:       "slow response",
    Delay:      &delay,
}
```

### Header Matching

Match requests based on headers:

```go
rule := httpfixture.HTTPFixtureRule{
    Request: httpfixture.FixtureRequest{
        Method: "GET",
        URL:    "https://api.example.com/secure",
        Headers: map[string]string{
            "Authorization": "Bearer token123",
        },
    },
    Response: httpfixture.Fixture{
        StatusCode: 200,
        Body:       `{"authenticated": true}`,
    },
}
```

### Fallback to Real HTTP

For partial mocking scenarios:

```go
transport := httpfixture.NewTransport(httpfixture.TransportConfig{
    Provider: provider,
    Fallback: http.DefaultTransport,
    Strict:   false,  // Don't error on missing fixtures
})
```

## Architecture

The fixture system is designed to be:

1. **General-Purpose**: Not tied to Lua or any specific use case
2. **Flexible**: Provider interface allows any fixture selection strategy
3. **Composable**: Can be used with any `http.Client`
4. **Testable**: Makes tests fast, deterministic, and hermetic
5. **Extensible**: Easy to add custom providers or matching logic

## Dependencies

The package uses [`github.com/goccy/go-yaml`](https://github.com/goccy/go-yaml) for YAML parsing, which is an actively maintained pure Go YAML 1.2 implementation with excellent error reporting and performance.

## Package Structure

```
internal/httpfixture/
├── fixture.go       # Core types and interfaces
├── providers.go     # Built-in provider implementations
├── transport.go     # HTTP RoundTripper implementation
├── loader.go        # File loading utilities
├── fixture_test.go  # Tests
└── README.md        # This file
```

## Future Enhancements

Potential future additions:
- Request body matching
- Response templating with request data
- Recording mode (capture real responses as fixtures)
- Fixture validation against OpenAPI specs
- HTTP/2 support

