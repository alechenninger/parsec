# parsec TODO

This document tracks planned work and next steps for the parsec project.

## Experiments
Functionality not yet well understood or yet lacking confidence the current architecture is correct.

### Context reuse / chaining
Sometimes there is existing transaction context which should be used. It can either be context for a new token, or maybe the token can be reused as-is (same transaction trust domain).

### Meta authorization
Different callers (actors) have different privileges in terms of...

- subject token types allowed (e.g. what trust domain, if unsigned is allowed)
- what context types are allowed (again, what trust domain, if unsigned is allowed)
- what token types they can request

## Features
Functionality with well understood expectations and relatively high confidence that it is doable within the current architecture.

### Real JWT Issuer
Implement actual JWT signing with private keys:
- [ ] Integrate with key management (Spire KeyManager or alternatives)
- [ ] Proper transaction token claims structure
- [ ] Public key exposure via JWKS endpoint

### Static Trust Store
Load trust domain configuration from YAML:
- [ ] Define configuration schema
- [ ] Multi-issuer support
- [ ] JWKS URL configuration per issuer

### Configuration Management
Complete configuration loading:
- [ ] YAML configuration file format
- [ ] Environment variable overrides
- [ ] Validation and hot reload

### Observability
Add structured logging and metrics:
- [ ] Request/response logging
- [ ] Token issuance metrics
- [ ] Data source performance metrics
- [ ] Distributed tracing

### Production Hardening
- [ ] Graceful shutdown
- [ ] Health checks
- [ ] Rate limiting for data sources
- [ ] Circuit breakers for external calls

### Key Management
- [ ] Spire KeyManager integration
- [ ] Real JWT issuer with signing (currently stub only)
- [ ] Public key exposure (JWKS endpoint)

### Trust Store
- [ ] Static trust store implementation (YAML config)
- [ ] Dynamic/reloadable trust store
- [ ] Multi-issuer support in store

### Configuration
- [ ] Configuration file format (YAML)
- [ ] Configuration loading and validation
- [ ] Environment variable overrides
- [ ] Hot reload support

### Observability
- [ ] Structured logging (zerolog or similar)
- [ ] Metrics (Prometheus)
- [ ] Distributed tracing (OpenTelemetry)
- [ ] Health/readiness checks

### Production Readiness
- [ ] Graceful shutdown
- [ ] Rate limiting
- [ ] Circuit breakers for external data sources
- [ ] Comprehensive error handling
- [ ] Production deployment examples

