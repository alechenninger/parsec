package issuer

import (
	"context"
	"encoding/json"
)

// StubDataSource is a simple stub data source for testing
type StubDataSource struct {
	name string
	data map[string]any
}

// NewStubDataSource creates a new stub data source
func NewStubDataSource(name string, data map[string]any) *StubDataSource {
	return &StubDataSource{
		name: name,
		data: data,
	}
}

// Name implements the DataSource interface
func (s *StubDataSource) Name() string {
	return s.name
}

// CacheKey implements the DataSource interface
func (s *StubDataSource) CacheKey(ctx context.Context, input *DataSourceInput) DataSourceCacheKey {
	// Stub data source always returns the same data, so cache key is just the name
	return DataSourceCacheKey(s.name)
}

// Fetch implements the DataSource interface
func (s *StubDataSource) Fetch(ctx context.Context, input *DataSourceInput) (*DataSourceResult, error) {
	if s.data == nil {
		return nil, nil
	}

	// Serialize the data to JSON
	jsonData, err := json.Marshal(s.data)
	if err != nil {
		return nil, err
	}

	return &DataSourceResult{
		Data:        jsonData,
		ContentType: ContentTypeJSON,
	}, nil
}
