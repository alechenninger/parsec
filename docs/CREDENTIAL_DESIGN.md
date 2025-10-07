# Credential Design

## Overview

Credentials in parsec are strongly typed values that encapsulate only the material needed for validation. The extraction layer (e.g., `ext_authz`) is responsible for parsing credentials from transport-level concerns (headers, TLS, etc.) and tracking which headers were used.

## Design Principles

### 1. Strongly Typed Credentials

Each credential type has its own struct with type-specific fields:

```go
type Credential interface {
    Type() CredentialType
    Issuer() string  // For trust store lookup
}

type BearerCredential struct {
    Token          string
    IssuerIdentity string  // Issuer/domain for this token
}

type JWTCredential struct {
    Token          string
    Algorithm      string  // Parsed from JWT header
    KeyID          string  // Parsed from JWT header
    IssuerIdentity string  // Parsed from JWT "iss" claim
}

type MTLSCredential struct {
    Certificate         []byte
    Chain               [][]byte
    PeerCertificateHash string
    IssuerIdentity      string  // CA identifier
}
```

**Benefits:**
- Type safety at compile time
- Type-specific methods available (e.g., `JWTCredential` could have `GetClaims()`)
- Clear documentation of what data each credential type needs
- No `map[string]string` soup
- Issuer identification enables multi-trust-domain support

### 2. Issuer Identification for Trust Store Lookup

Each credential identifies its issuer, enabling the trust store to select the appropriate validator:

```go
// Extraction determines issuer
cred := &JWTCredential{
    Token:          token,
    IssuerIdentity: "https://accounts.google.com",  // Parsed from JWT
}

// Trust store uses issuer for lookup
validator, err := trustStore.ValidatorFor(ctx, cred.Type(), cred.Issuer())
```

**How issuers are determined:**
- **JWT/OIDC**: Parsed from the `iss` claim in the token
- **Bearer (opaque)**: From configuration or token introspection
- **mTLS**: From the certificate authority identifier
- **API Key**: From configuration mapping key→issuer

**Why this matters:**
- Supports multiple identity providers simultaneously
- Each provider can have different trust anchors (JWKS, CA certs)
- Enables fine-grained trust policies per issuer
- Clear mapping: credential → issuer → validator → trust anchor

### 3. Separation of Concerns

Credentials contain **only validation data**, not transport metadata:

- ❌ Credentials do NOT know about HTTP headers
- ❌ Credentials do NOT know how they were extracted
- ✅ Credentials ARE just the material needed for validation

The **extraction layer** handles transport concerns:

```go
// extractCredential returns: (credential, headersUsed, error)
func (s *AuthzServer) extractCredential(req *CheckRequest) (Credential, []string, error) {
    authHeader := req.GetHeaders()["authorization"]
    
    if strings.HasPrefix(authHeader, "Bearer ") {
        cred := &BearerCredential{
            Token: strings.TrimPrefix(authHeader, "Bearer "),
        }
        headersUsed := []string{"authorization"}
        return cred, headersUsed, nil
    }
    
    // Future: Parse other schemes (JWT with specific header, API keys, etc.)
}
```

**Benefits:**
- Clear responsibility: extraction layer handles transport, validator handles validation
- Headers can be tracked dynamically based on extraction logic
- Same credential type can be extracted from different sources (header, cookie, query param)
- Easy to add new extraction methods without changing credential types

### 3. Security Boundary in ext_authz

The extraction layer tracks which headers were used, and ext_authz removes them from requests forwarded to backends:

```go
// 1. Extract credential and track headers used
cred, headersUsed, err := s.extractCredential(req)

// 2. Validate and issue transaction token
result, err := validator.Validate(ctx, cred)
token, err := issuer.Issue(ctx, result, reqCtx)

// 3. Remove external credential headers - security boundary
return &CheckResponse{
    HttpResponse: &CheckResponse_OkResponse{
        OkResponse: &OkHttpResponse{
            Headers: []*HeaderValueOption{
                {Header: &HeaderValue{Key: "Transaction-Token", Value: token.Value}},
            },
            HeadersToRemove: headersUsed, // Remove external credentials
        },
    },
}
```

**Why this matters:**
- External credentials (OAuth tokens, API keys, etc.) stay at the perimeter
- Backend services only see transaction tokens
- Prevents credential leakage to untrusted services
- Clear trust boundary enforcement

## Examples

### Example 1: Bearer Token

```go
// Extraction
authHeader := req.GetHeaders()["authorization"]
cred := &BearerCredential{
    Token: strings.TrimPrefix(authHeader, "Bearer "),
}
headersUsed := []string{"authorization"}

// Validation
validator.Validate(ctx, cred) // Just validates the token

// Security: "authorization" header removed from forwarded request
```

### Example 2: JWT with Header and Issuer Parsing

```go
// Extraction - parse JWT to get algorithm, key ID, and issuer
token := extractTokenFromHeader(req)
header := parseJWTHeader(token)
claims := parseJWTClaims(token) // Don't validate yet, just extract

cred := &JWTCredential{
    Token:          token,
    Algorithm:      header.Algorithm,
    KeyID:          header.KeyID,
    IssuerIdentity: claims.Issuer,  // e.g., "https://accounts.google.com"
}
headersUsed := []string{"authorization"}

// Trust store lookup using issuer
validator, err := trustStore.ValidatorFor(ctx, cred.Type(), cred.Issuer())
// Gets validator configured for accounts.google.com with appropriate JWKS

// Validation - can use Algorithm and KeyID to select specific key
validator.Validate(ctx, cred)

// Security: "authorization" header removed
```

### Example 3: API Key in Custom Header

```go
// Extraction
apiKey := req.GetHeaders()["x-api-key"]

cred := &BearerCredential{  // Reuse bearer for simple keys
    Token: apiKey,
}
headersUsed := []string{"x-api-key"}  // Track custom header

// Validation
validator.Validate(ctx, cred)

// Security: "x-api-key" header removed - key stays at perimeter
```

### Example 4: mTLS

```go
// Extraction - from TLS layer, not headers
tlsInfo := req.GetAttributes().GetSource().GetCertificate()

cred := &MTLSCredential{
    Certificate:         tlsInfo.GetCertificate(),
    Chain:               tlsInfo.GetChain(),
    PeerCertificateHash: tlsInfo.GetHash(),
}
headersUsed := nil  // No headers used for mTLS

// Validation - validates certificate against CA
validator.Validate(ctx, cred)

// Security: No headers to remove (TLS layer)
```

## Type Assertions in Validators

Validators can use type assertions to access type-specific fields:

```go
type JWTValidator struct {
    jwksClient *jwks.Client
}

func (v *JWTValidator) Validate(ctx context.Context, credential Credential) (*Result, error) {
    // Type assert to access JWT-specific fields
    jwtCred, ok := credential.(*JWTCredential)
    if !ok {
        return nil, fmt.Errorf("expected JWTCredential, got %T", credential)
    }
    
    // Now we can use type-specific fields
    key, err := v.jwksClient.GetKey(jwtCred.KeyID)
    if err != nil {
        return nil, err
    }
    
    // Validate JWT with specific algorithm
    return validateJWT(jwtCred.Token, key, jwtCred.Algorithm)
}
```

## Future Enhancements

### Multi-Source Extraction

Same credential type from different sources:

```go
// Bearer from Authorization header
cred, headers := extractBearerFromAuthHeader(req)

// Bearer from Cookie
cred, headers := extractBearerFromCookie(req)

// Bearer from Query Parameter (for websockets)
cred, headers := extractBearerFromQuery(req)
```

### Composite Credentials

For multi-factor auth:

```go
type CompositeCredential struct {
    Primary   Credential  // e.g., JWT
    Secondary Credential  // e.g., API key
}

headersUsed := []string{"authorization", "x-api-key"}
```

### Proof-of-Possession

For DPoP or similar:

```go
type DPoPCredential struct {
    AccessToken string
    ProofJWT    string
    Method      string
    URI         string
}

headersUsed := []string{"authorization", "dpop"}
```

## Testing

Type safety makes testing easier:

```go
func TestJWTValidation(t *testing.T) {
    cred := &JWTCredential{
        Token:     "eyJhbGc...",
        Algorithm: "RS256",
        KeyID:     "key-1",
    }
    
    result, err := validator.Validate(ctx, cred)
    // ... assertions
}
```

No need to build maps or worry about string keys - everything is type-checked at compile time.

## Summary

| Aspect | Approach |
|--------|----------|
| **Credential Type** | Strongly typed structs implementing `Credential` interface |
| **Credential Content** | Only validation material, no transport metadata |
| **Issuer Identification** | Each credential identifies its issuer for trust store lookup |
| **Header Tracking** | Extraction layer returns `(credential, headersUsed, error)` |
| **Security Boundary** | ext_authz removes headers used for external credentials |
| **Type Safety** | Compile-time checking, no string maps |
| **Multi-Trust-Domain** | Issuer field enables multiple IdPs/trust domains |
| **Extensibility** | Easy to add new credential types without changing contracts |

This design cleanly separates:
1. **Extraction** (transport → credential)
2. **Validation** (credential → claims)
3. **Security** (removing external credentials at boundary)

