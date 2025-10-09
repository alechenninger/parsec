# parsec Architecture

## Overview

parsec is a gRPC-first service that implements:
1. **Envoy ext_authz** (gRPC) - for authorization at the perimeter
2. **OAuth 2.0 Token Exchange** (HTTP via gRPC transcoding) - RFC 8693 compliant

Both services issue transaction tokens following the [draft-ietf-oauth-transaction-tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/) specification.

## Protocol Architecture

### Unified Stack

```
                    ┌─────────────────┐
                    │   parsec        │
                    │                 │
  gRPC clients ────▶│  gRPC Server    │◀──── Envoy (ext_authz)
                    │    :9090        │
                    │                 │
                    │  ┌───────────┐  │
  HTTP clients ────▶│  │  grpc-    │  │
                    │  │  gateway  │  │
                    │  │   :8080   │  │
                    │  └─────┬─────┘  │
                    │        │        │
                    │        ▼        │
                    │  gRPC Services  │
                    └─────────────────┘
```

**Key Design Decision**: Single gRPC service with HTTP transcoding via grpc-gateway
- No separate HTTP server implementation
- Consistent type definitions across protocols
- Single code path for business logic

## Services

### 1. Authorization Service (ext_authz)

**Interface**: `envoy.service.auth.v3.Authorization`

Implements Envoy's external authorization protocol:
- Receives requests from Envoy with external credentials
- Validates credentials against trust store
- Issues transaction token
- Returns authorization decision with token in custom header

### 2. Token Exchange Service

**Interface**: `parsec.v1.TokenExchange`

Implements RFC 8693 OAuth 2.0 Token Exchange:
- gRPC service definition with HTTP annotations
- Exposed at `POST /v1/token`
- Accepts external tokens, returns tokens of the request type (e.g. transaction token)
- Fully RFC 8693 compliant message structure

**RFC 8693 Compliance:**
The token exchange endpoint supports `application/x-www-form-urlencoded` as required by [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html):
- Custom marshaler registered with grpc-gateway
- Automatically decodes form-encoded requests
- Also accepts JSON for gRPC-style clients
- Responses are JSON (standard OAuth 2.0 token response)

Example RFC 8693 request:
```bash
curl -X POST http://localhost:8080/v1/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=eyJhbGc..." \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
  -d "audience=https://api.example.com"
```

## Project Structure

```
parsec/
├── api/
│   ├── proto/parsec/v1/          # Proto definitions
│   │   └── token_exchange.proto  # Token exchange with HTTP annotations
│   └── gen/                      # Generated code (gitignored)
│
├── cmd/parsec/
│   └── main.go                   # Entry point
│
├── internal/
│   ├── server/
│   │   ├── server.go            # gRPC + HTTP server setup
│   │   ├── authz.go             # ext_authz implementation
│   │   ├── exchange.go          # Token exchange implementation
│   │   └── form_marshaler.go   # RFC 8693 form encoding support
│   │
│   ├── trust/                   # Trust and credential validation
│   │   ├── validator.go         # Validator interface and credential types
│   │   ├── jwt_validator.go    # JWT validation with JWKS
│   │   └── store.go             # Trust store interface
│   │
│   ├── issuer/                  # Token issuance orchestration
│   │   ├── issuer.go            # Issuer interface and TokenContext
│   │   ├── service.go           # TokenService orchestrates issuance
│   │   ├── registry.go          # Registry for managing issuers
│   │   ├── mapper.go            # ClaimMapper for transaction context
│   │   ├── datasource.go        # DataSource interface for enrichment
│   │   └── types.go             # TokenType definitions
│   │
│   ├── datasource/              # Data source implementations
│   │   ├── lua_datasource.go   # Lua-scriptable data sources
│   │   ├── in_memory_caching_datasource.go
│   │   ├── distributed_caching_datasource.go
│   │   ├── examples/            # Example Lua scripts
│   │   └── LUA_DATASOURCE.md   # Lua data source documentation
│   │
│   ├── lua/                     # Lua runtime services
│   │   ├── http.go              # HTTP client for Lua
│   │   ├── json.go              # JSON encoding/decoding
│   │   └── config.go            # Configuration access
│   │
│   ├── claims/
│   │   └── claims.go            # Claims type with helper methods
│   │
│   ├── keymanager/              # Key management (TODO)
│   └── config/                  # Configuration loading (TODO)
│
├── docs/
│   └── CREDENTIAL_DESIGN.md     # Credential extraction and validation design
│
├── CONTRACTS.md                 # Component interface contracts
└── configs/                     # Configuration files (TODO)
```

## Implementation Status

### ✅ Complete

**Core Infrastructure:**
- [x] Go project scaffolding
- [x] Proto definitions for token exchange
- [x] Code generation with buf (remote plugins)
- [x] gRPC server with both services registered
- [x] HTTP server with grpc-gateway transcoding
- [x] RFC 8693 compliance (form-urlencoded support)
- [x] Custom marshaler for grpc-gateway
- [x] Basic build and run

**Trust & Validation:**
- [x] Credential validation interface (`trust.Validator`)
- [x] Strongly-typed credential types (Bearer, JWT, OIDC, mTLS)
- [x] JWT validator with JWKS support
- [x] Trust store interface for multi-domain support
- [x] Credential extraction layer with security boundary

**Token Issuance:**
- [x] Token issuer interface (`issuer.Issuer`)
- [x] Token service orchestration (`issuer.TokenService`)
- [x] Issuer registry for multiple token types
- [x] Claim mapper system for transaction context building
- [x] Transaction token claims structure (draft-ietf-oauth-transaction-tokens)

**Data Enrichment:**
- [x] Data source interface for token enrichment
- [x] Lua-scriptable data sources with HTTP/JSON/config services
- [x] In-memory caching for data sources
- [x] Distributed caching with groupcache
- [x] Cacheable interface for TTL-based caching
- [x] Example Lua scripts (user data, regional data, multi-source)

**Services:**
- [x] ext_authz implementation with credential extraction
- [x] Token exchange implementation (RFC 8693)
- [x] Security boundary: external credentials removed at perimeter
- [x] Request attribute extraction for context building

**Testing & Documentation:**
- [x] Unit tests for validators, issuers, data sources, caching
- [x] Integration tests for token exchange
- [x] CONTRACTS.md - Component interface documentation
- [x] CREDENTIAL_DESIGN.md - Credential design patterns
- [x] LUA_DATASOURCE.md - Lua data source guide

### 🚧 In Progress / TODO

**Key Management:**
- [ ] Spire KeyManager integration
- [ ] Real JWT issuer with signing (currently stub only)
- [ ] Public key exposure (JWKS endpoint)

**Trust Store:**
- [ ] Static trust store implementation (YAML config)
- [ ] Dynamic/reloadable trust store
- [ ] Multi-issuer support in store

**Configuration:**
- [ ] Configuration file format (YAML)
- [ ] Configuration loading and validation
- [ ] Environment variable overrides
- [ ] Hot reload support

**Observability:**
- [ ] Structured logging (zerolog or similar)
- [ ] Metrics (Prometheus)
- [ ] Distributed tracing (OpenTelemetry)
- [ ] Health/readiness checks

**Production Readiness:**
- [ ] Graceful shutdown
- [ ] Rate limiting
- [ ] Circuit breakers for external data sources
- [ ] Comprehensive error handling
- [ ] Production deployment examples

## Building and Running

```bash
# Generate proto code
make proto

# Build
make build

# Run
./bin/parsec
```

Server will start on:
- gRPC: `localhost:9090` (ext_authz, token exchange)
- HTTP: `localhost:8080` (token exchange via transcoding)

## Core Concepts

### Token Issuance Flow

parsec uses a layered architecture for token issuance:

```
1. Credential Extraction
   └─> Strongly-typed credentials (Bearer, JWT, mTLS, etc.)

2. Validation (trust.Validator)
   └─> Validated identity (trust.Result with claims)

3. Data Enrichment (issuer.DataSource)
   └─> Fetch additional context from external sources
   └─> Lua-scriptable with HTTP/JSON services
   └─> In-memory and distributed caching

4. Claim Mapping (issuer.ClaimMapper)
   └─> Build transaction context (tctx) and request context (req_ctx)
   └─> Policy logic: what claims to include in tokens

5. Token Issuance (issuer.Issuer)
   └─> Sign and mint transaction tokens
   └─> JWT with draft-ietf-oauth-transaction-tokens claims
```

### Data Sources

Data sources enable token enrichment by fetching data from external systems:

- **Lua-scriptable**: Write data sources in Lua without recompiling
- **HTTP/JSON/Config services**: Built-in services for common operations
- **Caching**: Automatic in-memory and distributed caching
- **Examples**: User profiles, permissions, regional data, multi-source aggregation

See `internal/datasource/LUA_DATASOURCE.md` for comprehensive documentation.

### Security Boundary

parsec enforces a security boundary at the perimeter:

1. External credentials (OAuth tokens, API keys) are extracted at ext_authz
2. Credentials are validated and transaction tokens are issued
3. **External credential headers are removed** from requests
4. Only transaction tokens reach backend services

This prevents credential leakage and establishes clear trust boundaries.

## Key Design Patterns

### Interface-Driven Design

All major components are defined by interfaces, enabling:
- **Testability**: Stub implementations for all interfaces
- **Flexibility**: Swap implementations without modifying consumers
- **Extensibility**: New implementations without breaking changes

Example interfaces:
- `trust.Validator` - Credential validation
- `trust.Store` - Trust domain management
- `issuer.Issuer` - Token issuance
- `issuer.DataSource` - Data enrichment
- `issuer.ClaimMapper` - Claim transformation

### Registry Pattern

Multiple implementations are managed via registries:
- **`issuer.Registry`**: Maps token types to issuers
- **`issuer.DataSourceRegistry`**: Named data sources
- **`issuer.ClaimMapperRegistry`**: Transaction/request context mappers

This enables dynamic configuration of token issuance behavior.

### Lazy Evaluation

Data sources are fetched lazily during claim mapping:
- Claim mappers receive a `DataSourceRegistry`
- Only fetch data sources they actually need
- Prevents unnecessary external calls
- Caching further optimizes repeated access

### Caching Layers

Data sources support transparent caching:
- **`Cacheable` interface**: Defines cache key and TTL
- **In-memory caching**: Fast local cache with LRU eviction
- **Distributed caching**: groupcache for multi-instance deployments
- Automatic cache key generation from inputs

### Dependency Injection

All services accept dependencies via constructors:

```go
// Create dependencies
trustStore := trust.NewStubStore()
dataSourceRegistry := issuer.NewDataSourceRegistry()
claimMapperRegistry := issuer.NewClaimMapperRegistry()
issuerRegistry := issuer.NewSimpleRegistry()

// Wire together
tokenService := issuer.NewTokenService(
    trustDomain,
    dataSourceRegistry,
    claimMapperRegistry,
    issuerRegistry,
)

// Inject into servers
authzServer := server.NewAuthzServer(trustStore, tokenService)
exchangeServer := server.NewExchangeServer(trustStore, tokenService)
```

## Related Documentation

- **`CONTRACTS.md`**: Detailed interface contracts and data flow
- **`docs/CREDENTIAL_DESIGN.md`**: Credential extraction and validation patterns
- **`internal/datasource/LUA_DATASOURCE.md`**: Lua data source guide with examples
- **`internal/datasource/examples/`**: Example Lua scripts for common scenarios
