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
- Accepts external tokens, returns transaction tokens
- Fully RFC 8693 compliant message structure

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
│   │   └── exchange.go          # Token exchange implementation
│   ├── validator/               # Credential validators (TODO)
│   ├── issuer/                  # Transaction token issuer (TODO)
│   ├── trust/                   # Trust store (TODO)
│   ├── keymanager/              # Spire KeyManager integration (TODO)
│   └── config/                  # Configuration (TODO)
│
└── configs/                      # Configuration files (TODO)
```

## Implementation Status

### ✅ Complete
- [x] Go project scaffolding
- [x] Proto definitions for token exchange
- [x] Code generation with buf (remote plugins)
- [x] gRPC server with both services registered
- [x] HTTP server with grpc-gateway transcoding
- [x] Envoy ext_authz service skeleton
- [x] Token exchange service skeleton
- [x] Basic build and run

### 🚧 TODO
- [ ] Credential validation interface and implementations
- [ ] Transaction token issuer (JWT with txn claims)
- [ ] Trust store (static YAML configuration)
- [ ] Spire KeyManager integration
- [ ] Configuration management
- [ ] Tests (unit and integration)
- [ ] Observability (logging, metrics, tracing)

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

## Next Steps

1. Define core interfaces:
   - `CredentialValidator` - validate external credentials
   - `TransactionTokenIssuer` - issue transaction tokens
   - `TrustStore` - manage trust domain configuration
   
2. Implement Spire KeyManager integration for key management

3. Add configuration loading (YAML + environment variables)

4. Implement basic credential validators (Bearer token, OIDC)

5. Implement transaction token issuer with proper JWT claims

