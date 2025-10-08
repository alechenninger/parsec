package issuer

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/alechenninger/parsec/internal/trust"
)

// CountingDataSource tracks how many times Fetch is called
type CountingDataSource struct {
	name       string
	data       map[string]any
	fetchCount atomic.Int32
}

func NewCountingDataSource(name string, data map[string]any) *CountingDataSource {
	return &CountingDataSource{
		name: name,
		data: data,
	}
}

func (c *CountingDataSource) Name() string {
	return c.name
}

func (c *CountingDataSource) CacheKey(ctx context.Context, input *DataSourceInput) DataSourceCacheKey {
	// Generate cache key based on data content, specifically user_id
	if userID, ok := c.data["user_id"].(string); ok {
		return DataSourceCacheKey(c.name + ":" + userID)
	}
	// If no user_id, use the data map as a string representation
	if len(c.data) > 0 {
		return DataSourceCacheKey(c.name + ":data")
	}
	// If no data at all, return empty to disable caching
	return ""
}

func (c *CountingDataSource) Fetch(ctx context.Context, input *DataSourceInput) (*DataSourceResult, error) {
	c.fetchCount.Add(1)

	if c.data == nil {
		return nil, nil
	}

	// Serialize the data to JSON
	jsonData, err := json.Marshal(c.data)
	if err != nil {
		return nil, err
	}

	return &DataSourceResult{
		Data:        jsonData,
		ContentType: ContentTypeJSON,
	}, nil
}

func (c *CountingDataSource) GetFetchCount() int32 {
	return c.fetchCount.Load()
}

func TestDataSourceRegistry_CachingWithSameKey(t *testing.T) {
	registry := NewDataSourceRegistry()

	testData := map[string]any{
		"user_id": "12345",
		"email":   "test@example.com",
	}

	// Create a counting data source - cache key will be based on user_id
	countingSource := NewCountingDataSource("test-source", testData)
	registry.Register(countingSource)

	input := &DataSourceInput{
		Subject: &trust.Result{
			Subject: "user123",
			Issuer:  "https://issuer.example.com",
			Claims:  map[string]any{"sub": "user123"},
		},
	}

	ctx := context.Background()

	// First fetch - should call the underlying Fetch
	results1 := registry.FetchAll(ctx, input)
	if countingSource.GetFetchCount() != 1 {
		t.Errorf("Expected fetch count to be 1 after first call, got %d", countingSource.GetFetchCount())
	}

	// Verify the data
	if results1["test-source"] == nil {
		t.Fatal("Expected data from test-source, got nil")
	}
	if results1["test-source"]["user_id"] != "12345" {
		t.Errorf("Expected user_id to be '12345', got %v", results1["test-source"]["user_id"])
	}

	// Second fetch with same cache key - should use cache
	results2 := registry.FetchAll(ctx, input)
	if countingSource.GetFetchCount() != 1 {
		t.Errorf("Expected fetch count to still be 1 (cached), got %d", countingSource.GetFetchCount())
	}

	// Verify the cached data
	if results2["test-source"] == nil {
		t.Fatal("Expected cached data from test-source, got nil")
	}
	if results2["test-source"]["user_id"] != "12345" {
		t.Errorf("Expected cached user_id to be '12345', got %v", results2["test-source"]["user_id"])
	}

	// Third fetch - should still use cache
	results3 := registry.FetchAll(ctx, input)
	if countingSource.GetFetchCount() != 1 {
		t.Errorf("Expected fetch count to still be 1 (cached), got %d", countingSource.GetFetchCount())
	}

	if results3["test-source"]["email"] != "test@example.com" {
		t.Errorf("Expected cached email to be 'test@example.com', got %v", results3["test-source"]["email"])
	}
}

func TestDataSourceRegistry_CachingWithDifferentKeys(t *testing.T) {
	registry := NewDataSourceRegistry()

	testData := map[string]any{
		"data": "test",
	}

	// Create a data source that returns different cache keys based on input
	dynamicSource := &DynamicCacheKeyDataSource{
		name: "dynamic-source",
		data: testData,
	}
	registry.Register(dynamicSource)

	ctx := context.Background()

	// First fetch with one subject
	input1 := &DataSourceInput{
		Subject: &trust.Result{
			Subject: "user1",
			Issuer:  "https://issuer.example.com",
			Claims:  map[string]any{"sub": "user1"},
		},
	}

	registry.FetchAll(ctx, input1)
	firstFetchCount := dynamicSource.GetFetchCount()
	if firstFetchCount != 1 {
		t.Errorf("Expected fetch count to be 1, got %d", firstFetchCount)
	}

	// Second fetch with different subject (different cache key)
	input2 := &DataSourceInput{
		Subject: &trust.Result{
			Subject: "user2",
			Issuer:  "https://issuer.example.com",
			Claims:  map[string]any{"sub": "user2"},
		},
	}

	registry.FetchAll(ctx, input2)
	secondFetchCount := dynamicSource.GetFetchCount()
	if secondFetchCount != 2 {
		t.Errorf("Expected fetch count to be 2 (different cache key), got %d", secondFetchCount)
	}

	// Fetch again with first subject - should use cache
	registry.FetchAll(ctx, input1)
	thirdFetchCount := dynamicSource.GetFetchCount()
	if thirdFetchCount != 2 {
		t.Errorf("Expected fetch count to still be 2 (cached), got %d", thirdFetchCount)
	}
}

func TestDataSourceRegistry_NoCacheKey(t *testing.T) {
	registry := NewDataSourceRegistry()

	// Empty data will result in empty cache key, disabling caching
	testData := map[string]any{}

	// Create a data source with no data - will return empty cache key
	countingSource := NewCountingDataSource("no-cache-source", testData)
	registry.Register(countingSource)

	input := &DataSourceInput{
		Subject: &trust.Result{
			Subject: "user123",
			Issuer:  "https://issuer.example.com",
			Claims:  map[string]any{"sub": "user123"},
		},
	}

	ctx := context.Background()

	// First fetch
	registry.FetchAll(ctx, input)
	if countingSource.GetFetchCount() != 1 {
		t.Errorf("Expected fetch count to be 1, got %d", countingSource.GetFetchCount())
	}

	// Second fetch - should NOT use cache since cache key is empty
	registry.FetchAll(ctx, input)
	if countingSource.GetFetchCount() != 2 {
		t.Errorf("Expected fetch count to be 2 (no caching), got %d", countingSource.GetFetchCount())
	}
}

func TestDataSourceRegistry_MultipleDataSources(t *testing.T) {
	registry := NewDataSourceRegistry()

	// Register multiple data sources - cache keys will be based on data content
	source1 := NewCountingDataSource("source1", map[string]any{"data": "one"})
	source2 := NewCountingDataSource("source2", map[string]any{"data": "two"})
	source3 := NewCountingDataSource("source3", map[string]any{"data": "three"})

	registry.Register(source1)
	registry.Register(source2)
	registry.Register(source3)

	input := &DataSourceInput{
		Subject: &trust.Result{
			Subject: "user123",
			Issuer:  "https://issuer.example.com",
			Claims:  map[string]any{"sub": "user123"},
		},
	}

	ctx := context.Background()

	// First fetch - all should be called
	results := registry.FetchAll(ctx, input)

	if len(results) != 3 {
		t.Errorf("Expected 3 data sources, got %d", len(results))
	}

	if source1.GetFetchCount() != 1 || source2.GetFetchCount() != 1 || source3.GetFetchCount() != 1 {
		t.Errorf("Expected all sources to be fetched once, got %d, %d, %d",
			source1.GetFetchCount(), source2.GetFetchCount(), source3.GetFetchCount())
	}

	// Second fetch - all should use cache
	results2 := registry.FetchAll(ctx, input)

	if len(results2) != 3 {
		t.Errorf("Expected 3 data sources, got %d", len(results2))
	}

	if source1.GetFetchCount() != 1 || source2.GetFetchCount() != 1 || source3.GetFetchCount() != 1 {
		t.Errorf("Expected all sources to still be at 1 (cached), got %d, %d, %d",
			source1.GetFetchCount(), source2.GetFetchCount(), source3.GetFetchCount())
	}

	// Verify the data
	if results2["source1"]["data"] != "one" {
		t.Errorf("Expected source1 data to be 'one', got %v", results2["source1"]["data"])
	}
	if results2["source2"]["data"] != "two" {
		t.Errorf("Expected source2 data to be 'two', got %v", results2["source2"]["data"])
	}
	if results2["source3"]["data"] != "three" {
		t.Errorf("Expected source3 data to be 'three', got %v", results2["source3"]["data"])
	}
}

// DynamicCacheKeyDataSource returns different cache keys based on the subject
type DynamicCacheKeyDataSource struct {
	name       string
	data       map[string]any
	fetchCount atomic.Int32
}

func (d *DynamicCacheKeyDataSource) Name() string {
	return d.name
}

func (d *DynamicCacheKeyDataSource) CacheKey(ctx context.Context, input *DataSourceInput) DataSourceCacheKey {
	if input.Subject == nil || input.Subject.Claims["sub"] == nil {
		return ""
	}
	// Return a cache key based on the subject
	return DataSourceCacheKey("sub:" + input.Subject.Claims["sub"].(string))
}

func (d *DynamicCacheKeyDataSource) Fetch(ctx context.Context, input *DataSourceInput) (*DataSourceResult, error) {
	d.fetchCount.Add(1)

	if d.data == nil {
		return nil, nil
	}

	// Serialize the data to JSON
	jsonData, err := json.Marshal(d.data)
	if err != nil {
		return nil, err
	}

	return &DataSourceResult{
		Data:        jsonData,
		ContentType: ContentTypeJSON,
	}, nil
}

func (d *DynamicCacheKeyDataSource) GetFetchCount() int32 {
	return d.fetchCount.Load()
}
