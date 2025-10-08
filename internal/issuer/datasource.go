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
	// The name is used as a key for lookups in the registry.
	Name() string

	// Fetch retrieves data based on the input.
	// Returns serialized data to avoid unnecessary serialization/deserialization.
	// If the data source fetches from a remote API that returns JSON,
	// it can return the raw JSON bytes directly without deserializing first.
	//
	// Returns nil result and nil error if the data source has nothing to contribute.
	// Returns non-nil error only for fatal errors that should fail token issuance.
	Fetch(ctx context.Context, input *DataSourceInput) (*DataSourceResult, error)
}

// DataSourceCacheKey is a key for caching data source results
type DataSourceCacheKey string

// Cacheable is an optional interface that data sources can implement
// to enable caching of their results
type Cacheable interface {
	// CacheKey returns a key that can be used to cache the data source results.
	// This is used to avoid re-fetching data if it hasn't changed.
	CacheKey(ctx context.Context, input *DataSourceInput) DataSourceCacheKey

	// CacheTTL returns the time-to-live for cached entries.
	// The actual TTL may vary. This is a hint.
	// In general, values should last for at _most_ the TTL.
	//
	// Return 0 to disable TTL-based expiration (cache indefinitely).
	CacheTTL() time.Duration
}

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

// DataSourceRegistry is a simple registry that stores data sources by name
type DataSourceRegistry struct {
	sources map[string]DataSource
}

// NewDataSourceRegistry creates a new data source registry
func NewDataSourceRegistry() *DataSourceRegistry {
	return &DataSourceRegistry{
		sources: make(map[string]DataSource),
	}
}

// Register adds a data source to the registry
func (r *DataSourceRegistry) Register(source DataSource) {
	r.sources[source.Name()] = source
}

// Get retrieves a data source by name
// Returns nil if the data source is not found
func (r *DataSourceRegistry) Get(name string) DataSource {
	return r.sources[name]
}

// Names returns the names of all registered data sources
func (r *DataSourceRegistry) Names() []string {
	names := make([]string, 0, len(r.sources))
	for name := range r.sources {
		names = append(names, name)
	}
	return names
}
