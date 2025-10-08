package issuer

import "context"

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

// Fetch implements the DataSource interface
func (s *StubDataSource) Fetch(ctx context.Context, input *DataSourceInput) (map[string]any, error) {
	return s.data, nil
}
