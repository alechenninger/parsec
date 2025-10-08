package issuer

import (
	"context"

	"github.com/alechenninger/parsec/internal/validator"
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

	// Fetch retrieves data based on the input.
	//
	// Returns nil data and nil error if the data source has nothing to contribute.
	// Returns non-nil error only for fatal errors that should fail token issuance.
	Fetch(ctx context.Context, input *DataSourceInput) (map[string]any, error)
}

type DataSourceCacheKey string

// DataSourceInput contains the inputs available to a data source
type DataSourceInput struct {
	// Subject identity (attested claims from validated credential)
	Subject *validator.Result

	// Workload identity (attested claims from workload credential)
	Workload *validator.Result

	// RequestAttributes contains information about the request
	RequestAttributes *RequestAttributes
}

// DataSourceRegistry manages data sources
type DataSourceRegistry struct {
	sources []DataSource
}

// NewDataSourceRegistry creates a new data source registry
func NewDataSourceRegistry() *DataSourceRegistry {
	return &DataSourceRegistry{
		sources: make([]DataSource, 0),
	}
}

// Register adds a data source to the registry
func (r *DataSourceRegistry) Register(source DataSource) {
	r.sources = append(r.sources, source)
}

// FetchAll invokes all registered data sources and returns their results
// Returns a map of data source name to data
// If a data source returns an error, it is skipped (treated as optional)
func (r *DataSourceRegistry) FetchAll(ctx context.Context, input *DataSourceInput) map[string]map[string]any {
	results := make(map[string]map[string]any)

	for _, source := range r.sources {
		// TODO: add caching with e.g. groupcache
		data, err := source.Fetch(ctx, input)
		if err != nil {
			// For now, treat all data sources as optional
			// In the future, we could add a Required() bool method to DataSource
			continue
		}
		if data != nil {
			results[source.Name()] = data
		}
	}

	return results
}
