package config

// Config is the root configuration structure for parsec
type Config struct {
	// Server configuration (gRPC and HTTP ports)
	Server ServerConfig `koanf:"server"`

	// TrustDomain is the trust domain for this parsec instance
	// Used as the audience for all issued tokens
	TrustDomain string `koanf:"trust_domain"`

	// AuthzServer configuration for ext_authz service
	AuthzServer *AuthzServerConfig `koanf:"authz_server"`

	// ExchangeServer configuration for token exchange service
	ExchangeServer *ExchangeServerConfig `koanf:"exchange_server"`

	// TrustStore configuration (validators and filtering)
	TrustStore TrustStoreConfig `koanf:"trust_store"`

	// DataSources for token enrichment
	DataSources []DataSourceConfig `koanf:"data_sources"`

	// Issuers configuration for different token types
	Issuers []IssuerConfig `koanf:"issuers"`

	// Fixtures for hermetic testing (HTTP rules, etc.)
	Fixtures []FixtureConfig `koanf:"fixtures"`

	// Observability configuration (logging, metrics, tracing)
	Observability *ObservabilityConfig `koanf:"observability"`
}

// ServerConfig contains network-level server settings
type ServerConfig struct {
	// GRPCPort is the port for gRPC services (ext_authz, token exchange)
	GRPCPort int `koanf:"grpc_port"`

	// HTTPPort is the port for HTTP services (gRPC-gateway transcoding)
	HTTPPort int `koanf:"http_port"`
}

// AuthzServerConfig configures the ext_authz authorization server
type AuthzServerConfig struct {
	// TokenTypes specifies which token types to issue and how to deliver them
	TokenTypes []TokenTypeConfig `koanf:"token_types"`
}

// TokenTypeConfig specifies a token type to issue via ext_authz
type TokenTypeConfig struct {
	// Type is the OAuth token type URN
	// Examples:
	//   - "urn:ietf:params:oauth:token-type:txn_token" (transaction token)
	//   - "urn:ietf:params:oauth:token-type:access_token" (access token)
	//   - "urn:ietf:params:oauth:token-type:jwt" (JWT)
	Type string `koanf:"type"`

	// HeaderName is the HTTP header to use for this token
	// e.g., "Transaction-Token", "Authorization", "X-Custom-Token"
	HeaderName string `koanf:"header_name"`
}

// ExchangeServerConfig configures the token exchange server
type ExchangeServerConfig struct {
	// ClaimsFilter determines which request_context claims actors can provide
	ClaimsFilter ClaimsFilterConfig `koanf:"claims_filter"`
}

// TrustStoreConfig configures the trust store and its validators
type TrustStoreConfig struct {
	// Type selects the trust store implementation
	// Options: "stub_store", "filtered_store"
	Type string `koanf:"type"`

	// Validators is the list of validators to add to the store
	Validators []NamedValidatorConfig `koanf:"validators"`

	// Filter configuration (only used when Type is "filtered_store")
	Filter *ValidatorFilterConfig `koanf:"filter"`
}

// NamedValidatorConfig is a validator with a name (for FilteredStore)
type NamedValidatorConfig struct {
	// Name uniquely identifies this validator
	Name string `koanf:"name"`

	// ValidatorConfig contains the actual validator configuration
	ValidatorConfig `koanf:",squash"`
}

// ValidatorConfig configures a credential validator
type ValidatorConfig struct {
	// Type selects the validator implementation
	// Options: "jwt_validator", "json_validator", "stub_validator"
	Type string `koanf:"type"`

	// JWT Validator fields
	Issuer          string `koanf:"issuer"`
	JWKSURL         string `koanf:"jwks_url"`
	TrustDomain     string `koanf:"trust_domain"`
	RefreshInterval string `koanf:"refresh_interval"` // Duration string like "15m"

	// JSON Validator fields
	// (TrustDomain is shared)

	// Stub Validator fields
	CredentialTypes []string `koanf:"credential_types"` // e.g., ["bearer", "jwt"]
}

// ValidatorFilterConfig configures validator filtering for actors
type ValidatorFilterConfig struct {
	// Type selects the filter implementation
	// Options: "cel", "any", "passthrough"
	Type string `koanf:"type"`

	// CEL filter fields
	Script string `koanf:"script"`

	// Any filter fields (composite filter - allows if any sub-filter allows)
	Filters []ValidatorFilterConfig `koanf:"filters"`
}

// DataSourceConfig configures a data source
type DataSourceConfig struct {
	// Name uniquely identifies this data source
	Name string `koanf:"name"`

	// Type selects the data source implementation
	// Options: "lua"
	Type string `koanf:"type"`

	// Lua data source fields
	ScriptFile string         `koanf:"script_file"` // Path to Lua script
	Script     string         `koanf:"script"`      // Inline Lua script (alternative to ScriptFile)
	Config     map[string]any `koanf:"config"`      // Config values available to script

	// HTTP configuration
	HTTPConfig *HTTPConfig `koanf:"http"`

	// Caching configuration
	Caching *CachingConfig `koanf:"caching"`
}

// HTTPConfig configures HTTP client for Lua data sources
type HTTPConfig struct {
	// Timeout for HTTP requests (default: 30s)
	Timeout string `koanf:"timeout"` // Duration string like "30s"
}

// CachingConfig configures caching for a data source
type CachingConfig struct {
	// Type selects the caching implementation
	// Options: "in_memory", "distributed", "none"
	Type string `koanf:"type"`

	// TTL is the cache time-to-live
	TTL string `koanf:"ttl"` // Duration string like "5m"

	// Distributed caching fields
	GroupName string `koanf:"group_name"` // For groupcache
	CacheSize int64  `koanf:"cache_size"` // Cache size in bytes
}

// ClaimMapperConfig configures a claim mapper
type ClaimMapperConfig struct {
	// Type selects the mapper implementation
	// Options: "cel", "passthrough", "request_attributes", "stub"
	Type string `koanf:"type"`

	// Optional name for the mapper
	Name string `koanf:"name"`

	// CEL mapper fields
	ScriptFile string `koanf:"script_file"` // Path to CEL script file
	Script     string `koanf:"script"`      // Inline CEL script (alternative to ScriptFile)

	// Stub mapper fields
	Claims map[string]any `koanf:"claims"`
}

// IssuerConfig configures a token issuer
type IssuerConfig struct {
	// TokenType is the OAuth token type URN this issuer handles
	// Examples:
	//   - "urn:ietf:params:oauth:token-type:txn_token" (transaction token)
	//   - "urn:ietf:params:oauth:token-type:access_token" (access token)
	//   - "urn:ietf:params:oauth:token-type:jwt" (JWT)
	TokenType string `koanf:"token_type"`

	// Type selects the issuer implementation
	// Options: "stub", "unsigned", "transaction_token", "rh_identity"
	Type string `koanf:"type"`

	// Common fields
	IssuerURL string `koanf:"issuer_url"`
	TTL       string `koanf:"ttl"` // Duration string like "5m"

	// KeyManager configuration
	// Used for transaction tokens to configure the key manager
	KeyManager *KeyManagerConfig `koanf:"key_manager"`

	// Transaction token issuer fields (stub, transaction_token types)
	// These mappers build the "tctx" and "req_ctx" claims
	TransactionContextMappers []ClaimMapperConfig `koanf:"transaction_context"`
	RequestContextMappers     []ClaimMapperConfig `koanf:"request_context"`

	// Simple issuer fields (unsigned, rh_identity types)
	// These mappers build the token's claim structure
	ClaimMappers []ClaimMapperConfig `koanf:"claim_mappers"`

	// Stub issuer fields (deprecated - use mappers instead)
	IncludeRequestContext bool `koanf:"include_request_context"`
}

// KeyManagerConfig configures a key manager
type KeyManagerConfig struct {
	// Type selects the key manager implementation
	// Options: "memory", "aws_kms"
	Type string `koanf:"type"`

	// AWS KMS fields
	Region      string `koanf:"region"`       // AWS region (e.g., "us-east-1")
	AliasPrefix string `koanf:"alias_prefix"` // KMS alias prefix (e.g., "alias/parsec/")
}

// ClaimsFilterConfig configures the claims filter registry
type ClaimsFilterConfig struct {
	// Type selects the filter registry implementation
	// Options: "stub", "cel", "allowlist"
	Type string `koanf:"type"`

	// CEL-based filter
	Script string `koanf:"script"`

	// Allowlist-based filter
	AllowedClaims []string `koanf:"allowed_claims"`

	// Per-actor rules
	ActorRules map[string][]string `koanf:"actor_rules"` // Map of actor pattern to allowed claims
}

// FixtureConfig configures a fixture for hermetic testing
type FixtureConfig struct {
	// Type selects the fixture type
	// Options: "http_rule", "jwks"
	Type string `koanf:"type"`

	// HTTP rule fields (when Type is "http_rule")
	Request  FixtureRequest  `koanf:"request"`
	Response FixtureResponse `koanf:"response"`

	// JWKS fields (when Type is "jwks")
	Issuer    string `koanf:"issuer"`    // Issuer URL (iss claim)
	JWKSURL   string `koanf:"jwks_url"`  // URL where JWKS will be served
	KeyID     string `koanf:"key_id"`    // Optional key identifier (defaults to "test-key-1")
	Algorithm string `koanf:"algorithm"` // Optional algorithm (defaults to "RS256")
}

// FixtureRequest defines request matching criteria for HTTP fixtures
type FixtureRequest struct {
	// Method is the HTTP method to match (e.g., "GET", "POST", "*" for any)
	Method string `koanf:"method"`

	// URL is the URL to match (exact or pattern based on URLType)
	URL string `koanf:"url"`

	// URLType specifies how to match the URL
	// Options: "exact" (default), "pattern" (regex)
	URLType string `koanf:"url_type"`

	// Headers are optional headers to match
	Headers map[string]string `koanf:"headers"`
}

// FixtureResponse defines the HTTP response to return for a fixture
type FixtureResponse struct {
	// StatusCode is the HTTP status code (e.g., 200, 404)
	StatusCode int `koanf:"status"`

	// Headers are optional response headers
	Headers map[string]string `koanf:"headers"`

	// Body is the response body content
	Body string `koanf:"body"`
}

// ObservabilityConfig configures application observability
type ObservabilityConfig struct {
	// Type selects the observer implementation
	// Options: "logging", "noop", "composite"
	Type string `koanf:"type"`

	// LogLevel sets the default log level for logging observer
	// Options: "debug", "info", "warn", "error"
	// Default: "info"
	LogLevel string `koanf:"log_level"`

	// LogFormat sets the log format
	// Options: "json", "text"
	// Default: "json"
	LogFormat string `koanf:"log_format"`

	// Event-specific logging configuration
	TokenIssuance *EventLoggingConfig `koanf:"token_issuance"`
	TokenExchange *EventLoggingConfig `koanf:"token_exchange"`
	AuthzCheck    *EventLoggingConfig `koanf:"authz_check"`

	// Composite observer fields - allows multiple observers
	Observers []ObservabilityConfig `koanf:"observers"`
}

// EventLoggingConfig configures logging for a specific event type
type EventLoggingConfig struct {
	// LogLevel overrides the default log level for this event
	// Options: "debug", "info", "warn", "error"
	LogLevel string `koanf:"log_level"`

	// LogFormat overrides the default log format for this event
	// Options: "json", "text"
	LogFormat string `koanf:"log_format"`

	// Enabled controls whether this event type is logged
	// Default: true
	Enabled *bool `koanf:"enabled"`
}
