# parsec Configuration

parsec uses a flexible configuration system based on [koanf](https://github.com/knadh/koanf) that supports multiple formats and sources.

## Quick Start

1. Copy an example configuration:
   ```bash
   cp configs/examples/parsec-minimal.yaml configs/parsec.yaml
   ```

2. Edit the configuration to match your environment

3. Run parsec (it will automatically load `./configs/parsec.yaml`):
   ```bash
   ./bin/parsec serve
   ```

## Configuration Sources

parsec loads configuration from multiple sources in order of precedence (highest to lowest):

1. **Command-Line Flags** - Override specific values via CLI
2. **Environment Variables** - Override any config value
3. **Configuration File** - YAML, JSON, or TOML format

### Command-Line Flags

Override specific configuration values via command-line flags (highest precedence):

```bash
# Use custom config file
./bin/parsec serve --config=/etc/parsec/config.yaml

# Override server ports
./bin/parsec serve --grpc-port=9091 --http-port=8081

# Override trust domain
./bin/parsec serve --trust-domain=prod.example.com

# Combine multiple overrides
./bin/parsec serve --config=./my-config.yaml --grpc-port=9091 --trust-domain=prod.example.com
```

Available flags for `serve` command:
- `--config, -c` - Config file path (default: `./configs/parsec.yaml`)
- `--grpc-port` - gRPC server port (overrides `server.grpc_port`)
- `--http-port` - HTTP server port (overrides `server.http_port`)
- `--trust-domain` - Trust domain for issued tokens (overrides `trust_domain`)

View all commands and flags:
```bash
./bin/parsec --help
./bin/parsec serve --help
```

### Configuration File

By default, parsec looks for `./configs/parsec.yaml`. You can specify a different path:

```bash
./bin/parsec serve --config=/etc/parsec/config.yaml
```

Or via environment variable:

```bash
export PARSEC_CONFIG=/etc/parsec/config.yaml
./bin/parsec serve
```

### Supported Formats

parsec auto-detects the format based on file extension:

- **YAML**: `.yaml` or `.yml` (recommended)
- **JSON**: `.json`
- **TOML**: `.toml`

See `examples/` directory for configuration examples in each format.

### Environment Variables

Environment variables override config file values. Use the `PARSEC_` prefix:

- Use **double underscore (`__`)** for nested fields
- Use **single underscore (`_`)** as part of field names

Examples:

```bash
# Override server ports
export PARSEC_SERVER__GRPC_PORT=9091
export PARSEC_SERVER__HTTP_PORT=8081

# Override trust domain
export PARSEC_TRUST_DOMAIN=prod.example.com

# Start parsec
./bin/parsec
```

Mapping rules:
- `PARSEC_SERVER__GRPC_PORT` → `server.grpc_port`
- `PARSEC_TRUST_DOMAIN` → `trust_domain`
- `PARSEC_TRUST_STORE__TYPE` → `trust_store.type`

## Configuration Reference

### Server

```yaml
server:
  grpc_port: 9090  # gRPC server port (ext_authz, token exchange)
  http_port: 8080  # HTTP server port (gRPC-gateway transcoding)
```

### Trust Domain

```yaml
trust_domain: "parsec.example.com"  # Audience for issued tokens
```

### Trust Store

The trust store manages credential validators:

```yaml
trust_store:
  type: stub_store  # or "filtered_store"
  validators:
    - name: my-validator  # Required for filtered_store
      type: jwt_validator  # jwt_validator, json_validator, stub_validator
      issuer: "https://idp.example.com"
      jwks_url: "https://idp.example.com/.well-known/jwks.json"
      trust_domain: "example.com"
      refresh_interval: "15m"
```

**Validator Types:**

- `jwt_validator` - Validates JWT tokens with JWKS
- `json_validator` - Validates unsigned JSON credentials
- `stub_validator` - Testing validator (accepts any non-empty token)

**Filtered Store** (optional):

```yaml
trust_store:
  type: filtered_store
  validators:
    - name: prod-validator
      # ... validator config ...
  filter:
    type: cel
    script: |
      actor.trust_domain == "prod.example.com" && 
      validator_name == "prod-validator"
```

**Filter Types:**

- `cel` - CEL expression that evaluates to boolean
- `any` - Composite filter that allows if any sub-filter allows
- `passthrough` - Allows all validators (no filtering)

**Composite Filter Example:**

```yaml
trust_store:
  type: filtered_store
  validators:
    - name: prod-validator
    - name: dev-validator
    - name: admin-validator
  filter:
    type: any  # Allow if ANY condition matches
    filters:
      - type: cel
        script: actor.trust_domain == "prod.example.com"
      - type: cel
        script: actor.claims.admin == true
      - type: cel
        script: validator_name == "dev-validator"
```

### Data Sources

Data sources enrich tokens with external data:

```yaml
data_sources:
  - name: user_roles
    type: lua
    script_file: ./scripts/user_roles.lua  # Or use inline script
    config:  # Available to Lua script via config.get()
      api_url: "https://api.example.com"
      api_key: "secret-key"  # Inject via env: PARSEC_DATA_SOURCES__0__CONFIG__API_KEY
    http:  # HTTP client configuration
      timeout: 30s
      # Optional: Use fixtures for testing (no real HTTP calls)
      # fixtures_file: ./test/fixtures/user_api.yaml
      # fixtures_dir: ./test/fixtures/
    caching:
      type: in_memory  # or "distributed", "none"
      ttl: 5m
```

**HTTP Configuration:**

- `timeout` - Duration string for HTTP request timeout (default: 30s)
- `fixtures_file` - Path to YAML/JSON fixtures file (for testing)
- `fixtures_dir` - Path to directory containing fixtures (for testing)

**Caching Types:**

- `in_memory` - Local cache (single instance)
- `distributed` - Groupcache-based distributed cache
- `none` - No caching

### Claim Mappers

Claim mappers build token claims from inputs:

```yaml
claim_mappers:
  transaction_context:  # Builds "tctx" claim
    - type: passthrough  # Pass through subject claims
    - type: cel
      script: |
        {
          "roles": datasource("user_roles").roles,
          "org": datasource("org_metadata").org_id
        }
  
  request_context:  # Builds "req_ctx" claim
    - type: request_attributes  # Include request path, method, etc.
```

**Mapper Types:**

- `passthrough` - Pass through subject claims
- `request_attributes` - Include request metadata (path, method, IP, etc.)
- `cel` - CEL expression returning a map of claims
- `stub` - Fixed claims (for testing)

### Issuers

Issuers create tokens:

```yaml
issuers:
  - token_type: "urn:ietf:params:oauth:token-type:txn_token"
    type: stub  # stub, unsigned, jwt
    issuer_url: "https://parsec.example.com"
    ttl: 5m
```

**Token Types:**

- `urn:ietf:params:oauth:token-type:txn_token` - Transaction token (RFC draft)
- `urn:ietf:params:oauth:token-type:access_token` - OAuth2 access token
- `urn:ietf:params:oauth:token-type:jwt` - Generic JWT token

**Issuer Types:**

- `stub` - Simple test tokens (includes subject and transaction ID)
- `unsigned` - Base64-encoded JSON tokens (never expires)
- `jwt` - Signed JWT tokens (not yet implemented)

### Token Exchange Server

The token exchange server can be configured with claims filtering to control which request_context claims actors can provide:

```yaml
server:
  grpc_port: 9090
  http_port: 8080
  exchange_server:
    claims_filter:
      type: stub  # Allow all claims (passthrough)
```

This configuration is part of the server configuration, similar to how `authz_server` is configured.

## Examples

The `examples/` directory contains complete configuration examples:

- **`parsec-minimal.yaml`** - Simplest working config (stubs only)
- **`parsec-full.yaml`** - Comprehensive example with all features
- **`parsec-production.yaml`** - Production-ready configuration
- **`parsec-minimal.json`** - Minimal config in JSON format
- **`parsec-minimal.toml`** - Minimal config in TOML format

## Hot Reloading

Configuration hot reloading is supported but not yet enabled by default. The infrastructure is in place in `internal/config/loader.go` with the `Watch()` method.

## Configuration Validation

parsec validates configuration at startup and will fail with descriptive errors if:

- Required fields are missing
- Invalid types are specified
- Files referenced (e.g., Lua scripts) don't exist
- URLs or durations are malformed

## Security Considerations

### Sensitive Data

Avoid hardcoding sensitive data in configuration files:

```yaml
# BAD - hardcoded secret
config:
  api_key: "secret123"

# GOOD - reference environment variable
config:
  api_key: "${API_KEY}"
```

### File Permissions

Restrict access to configuration files:

```bash
chmod 600 /etc/parsec/config.yaml
chown parsec:parsec /etc/parsec/config.yaml
```

### Environment Variables

For production deployments, prefer:
- Kubernetes Secrets mounted as environment variables
- HashiCorp Vault
- AWS Secrets Manager / GCP Secret Manager

## Configuration Precedence Examples

Understanding how configuration sources work together:

### Example 1: All defaults
```bash
# Uses ./configs/parsec.yaml with no overrides
./bin/parsec serve
```
Result: All values from config file

### Example 2: Environment variable override
```bash
# Config has grpc_port: 9090
# Env var overrides it to 9091
PARSEC_SERVER__GRPC_PORT=9091 ./bin/parsec serve
```
Result: gRPC on port 9091, everything else from config

### Example 3: Flag override (highest precedence)
```bash
# Config has grpc_port: 9090
# Env var sets it to 9091
# Flag overrides both to 9092
PARSEC_SERVER__GRPC_PORT=9091 ./bin/parsec serve --grpc-port=9092
```
Result: gRPC on port 9092 (flag wins)

### Example 4: Combining sources
```yaml
# configs/prod.yaml
server:
  grpc_port: 9090
  http_port: 8080
trust_domain: "prod.example.com"
```

```bash
# Override specific values while keeping the rest
PARSEC_TRUST_DOMAIN=prod-us.example.com \
  ./bin/parsec serve \
  --config=./configs/prod.yaml \
  --http-port=8081
```

Result:
- grpc_port: 9090 (from config)
- http_port: 8081 (from flag)
- trust_domain: prod-us.example.com (from env var)

## Troubleshooting

### Config file not found

```
Error: failed to load config: failed to load config file ./configs/parsec.yaml: ...
```

**Solution**: Create the config file or use `--config` flag to point to an existing file.

### Invalid format

```
Error: failed to parse config: ...
```

**Solution**: Validate your YAML/JSON/TOML syntax. Use a linter or validator.

### Environment variables not working

**Issue**: Env vars not overriding config values

**Solution**: Use double underscore (`__`) for nesting:
- `PARSEC_SERVER__GRPC_PORT` (correct)
- `PARSEC_SERVER_GRPC_PORT` (wrong - will look for field named `server_grpc_port`)

### Flags not working

**Issue**: Flag values not being applied

**Solution**: Ensure you're using the `serve` command:
- `./bin/parsec serve --grpc-port=9091` (correct)
- `./bin/parsec --grpc-port=9091` (wrong - flags are command-specific)

## Further Reading

- [Architecture Documentation](../ARCHITECTURE.md)
- [Lua Data Sources](../internal/datasource/LUA_DATASOURCE.md)
- [CEL Mappers](../internal/cel/README.md)
- [Validator Filtering](../internal/trust/VALIDATOR_FILTERING.md)

