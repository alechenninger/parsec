package issuer

import (
	"context"
	"time"

	"github.com/alechenninger/parsec/internal/trust"
)

// DataSource provides additional data for token context building
// Data sources can fetch information from external systems (databases, APIs, etc.)
// to enrich the token context.
type DataSource interface {
	// Name identifies this data source.
	// The name is used as a key in the data map passed to claim mappers.
	Name() string

	// CacheKey returns a key that can be used to cache the data source results.
	// This is used to avoid re-fetching data if it hasn't changed.
	CacheKey(ctx context.Context, input *DataSourceInput) DataSourceCacheKey

	// CacheTTL returns the time-to-live for cached entries.
	// The actual TTL may vary. This is a hint.
	// In general, values should last for at _most_ the TTL.
	//
	// Return 0 to disable TTL-based expiration (cache indefinitely).
	CacheTTL() time.Duration

	// Fetch retrieves data based on the input.
	// Returns serialized data to avoid unnecessary serialization/deserialization.
	// If the data source fetches from a remote API that returns JSON,
	// it can return the raw JSON bytes directly without deserializing first.
	//
	// Returns nil result and nil error if the data source has nothing to contribute.
	// Returns non-nil error only for fatal errors that should fail token issuance.
	Fetch(ctx context.Context, input *DataSourceInput) (*DataSourceResult, error)
}

type DataSourceCacheKey string

// DataSourceContentType identifies the serialization format of data source results
type DataSourceContentType string

const (
	// ContentTypeJSON indicates the data is JSON-encoded
	ContentTypeJSON DataSourceContentType = "application/json"
)

// DataSourceResult contains serialized data from a data source
type DataSourceResult struct {
	// Data is the serialized data (e.g., JSON bytes)
	Data []byte

	// ContentType identifies how to deserialize the data
	ContentType DataSourceContentType
}

// RequestAttributes contains attributes about the incoming request
// This is raw request data that will be processed by data sources and claim mappers
type RequestAttributes struct {
	// Method is the HTTP method or RPC method name
	Method string

	// Path is the request path/resource being accessed
	Path string

	// IPAddress is the client IP address
	IPAddress string

	// UserAgent is the client user agent
	UserAgent string

	// Headers contains relevant HTTP headers
	Headers map[string]string

	// Additional arbitrary context
	Additional map[string]any
}

// DataSourceInput contains the inputs available to a data source
type DataSourceInput struct {
	// Subject identity (attested claims from validated credential)
	Subject *trust.Result

	// Workload identity (attested claims from workload credential)
	Workload *trust.Result

	// RequestAttributes contains information about the request
	RequestAttributes *RequestAttributes
}

// DataSourceRegistry manages data sources and provides data fetching capabilities
// This interface decouples the token service from specific caching implementations
type DataSourceRegistry interface {
	// Register adds a data source to the registry
	Register(source DataSource)

	// FetchAll invokes all registered data sources and returns their results
	// Returns a map of data source name to data
	// If a data source returns an error, it is skipped (treated as optional)
	FetchAll(ctx context.Context, input *DataSourceInput) map[string]map[string]any
}

