package datasource

import (
	"context"
	"encoding/json"
	"time"

	"github.com/alechenninger/parsec/internal/issuer"
)

// StubDataSource is a simple stub data source for testing
type StubDataSource struct {
	name     string
	data     map[string]any
	cacheTTL time.Duration
}

// NewStubDataSource creates a new stub data source with no TTL
func NewStubDataSource(name string, data map[string]any) *StubDataSource {
	return &StubDataSource{
		name:     name,
		data:     data,
		cacheTTL: 0, // No TTL by default
	}
}

// NewStubDataSourceWithTTL creates a new stub data source with a cache TTL
func NewStubDataSourceWithTTL(name string, data map[string]any, ttl time.Duration) *StubDataSource {
	return &StubDataSource{
		name:     name,
		data:     data,
		cacheTTL: ttl,
	}
}

// Name implements the issuer.DataSource interface
func (s *StubDataSource) Name() string {
	return s.name
}

// CacheKey implements the issuer.DataSource interface
func (s *StubDataSource) CacheKey(ctx context.Context, input *issuer.DataSourceInput) issuer.DataSourceCacheKey {
	// Stub data source always returns the same data, so cache key is just the name
	return issuer.DataSourceCacheKey(s.name)
}

// CacheTTL implements the issuer.DataSource interface
func (s *StubDataSource) CacheTTL() time.Duration {
	return s.cacheTTL
}

// Fetch implements the issuer.DataSource interface
func (s *StubDataSource) Fetch(ctx context.Context, input *issuer.DataSourceInput) (*issuer.DataSourceResult, error) {
	if s.data == nil {
		return nil, nil
	}

	// Serialize the data to JSON
	jsonData, err := json.Marshal(s.data)
	if err != nil {
		return nil, err
	}

	return &issuer.DataSourceResult{
		Data:        jsonData,
		ContentType: issuer.ContentTypeJSON,
	}, nil
}
