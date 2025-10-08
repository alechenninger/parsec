package datasource

import (
	"context"
	"testing"
	"time"

	"github.com/alechenninger/parsec/internal/issuer"
	"github.com/alechenninger/parsec/internal/trust"
)

func TestRoundTimeToInterval(t *testing.T) {
	tests := []struct {
		name     string
		time     time.Time
		interval time.Duration
		want     time.Time
	}{
		{
			name:     "1 hour interval",
			time:     time.Date(2025, 10, 8, 14, 37, 42, 0, time.UTC),
			interval: 1 * time.Hour,
			want:     time.Date(2025, 10, 8, 14, 0, 0, 0, time.UTC),
		},
		{
			name:     "24 hour interval (day)",
			time:     time.Date(2025, 10, 8, 14, 37, 42, 0, time.UTC),
			interval: 24 * time.Hour,
			want:     time.Date(2025, 10, 8, 0, 0, 0, 0, time.UTC),
		},
		{
			name:     "15 minute interval",
			time:     time.Date(2025, 10, 8, 14, 37, 42, 0, time.UTC),
			interval: 15 * time.Minute,
			want:     time.Date(2025, 10, 8, 14, 30, 0, 0, time.UTC),
		},
		{
			name:     "5 minute interval",
			time:     time.Date(2025, 10, 8, 14, 37, 42, 0, time.UTC),
			interval: 5 * time.Minute,
			want:     time.Date(2025, 10, 8, 14, 35, 0, 0, time.UTC),
		},
		{
			name:     "zero interval returns original time",
			time:     time.Date(2025, 10, 8, 14, 37, 42, 0, time.UTC),
			interval: 0,
			want:     time.Date(2025, 10, 8, 14, 37, 42, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := roundTimeToInterval(tt.time, tt.interval)
			if !got.Equal(tt.want) {
				t.Errorf("roundTimeToInterval() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildInternalCacheKey(t *testing.T) {
	now := time.Date(2025, 10, 8, 14, 37, 42, 0, time.UTC)

	tests := []struct {
		name    string
		ttl     time.Duration
		userKey issuer.DataSourceCacheKey
		want    string
	}{
		{
			name:    "no TTL uses user key directly",
			ttl:     0,
			userKey: "user:12345",
			want:    "user:12345",
		},
		{
			name:    "1 hour TTL adds time component",
			ttl:     1 * time.Hour,
			userKey: "user:12345",
			want:    "user:12345:2025-10-08T14:00:00Z",
		},
		{
			name:    "24 hour TTL rounds to day",
			ttl:     24 * time.Hour,
			userKey: "user:12345",
			want:    "user:12345:2025-10-08T00:00:00Z",
		},
		{
			name:    "5 minute TTL",
			ttl:     5 * time.Minute,
			userKey: "user:12345",
			want:    "user:12345:2025-10-08T14:35:00Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := NewCountingDataSourceWithTTL("test", map[string]any{}, tt.ttl)
			got := buildInternalCacheKey(source, tt.userKey, now)
			if got != tt.want {
				t.Errorf("buildInternalCacheKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDataSourceRegistry_CachingWithTTL(t *testing.T) {
	registry := NewRegistry()

	testData := map[string]any{
		"user_id": "ttl-test-user",
		"value":   "original",
	}

	// Create a data source with 1 hour TTL
	source := NewCountingDataSourceWithTTL("ttl-test-source", testData, 1*time.Hour)
	registry.Register(source)

	input := &issuer.DataSourceInput{
		Subject: &trust.Result{
			Subject: "user123",
			Issuer:  "https://issuer.example.com",
			Claims:  map[string]any{"sub": "user123"},
		},
	}

	ctx := context.Background()

	// First fetch - should call the underlying Fetch
	results1 := registry.FetchAll(ctx, input)
	if source.GetFetchCount() != 1 {
		t.Errorf("Expected fetch count to be 1, got %d", source.GetFetchCount())
	}
	if results1["ttl-test-source"]["user_id"] != "ttl-test-user" {
		t.Errorf("Expected user_id, got %v", results1["ttl-test-source"]["user_id"])
	}

	// Second fetch - should use cache (within same hour)
	results2 := registry.FetchAll(ctx, input)
	if source.GetFetchCount() != 1 {
		t.Errorf("Expected fetch count to still be 1 (cached), got %d", source.GetFetchCount())
	}

	// The cache key includes the rounded time, so within the same hour,
	// we should get the same cached result
	if results2["ttl-test-source"]["value"] != "original" {
		t.Errorf("Expected cached value, got %v", results2["ttl-test-source"]["value"])
	}
}

func TestDataSourceRegistry_TTLExpiration(t *testing.T) {
	// This test demonstrates the concept but cannot actually test time passage
	// In real usage, when time advances past the TTL interval, a new cache key
	// is generated and a new fetch occurs

	registry := NewRegistry()

	testData := map[string]any{
		"user_id": "expiry-test",
		"data":    "value",
	}

	// Create a data source with a very short TTL for demonstration
	source := NewCountingDataSourceWithTTL("expiry-source", testData, 1*time.Minute)
	registry.Register(source)

	input := &issuer.DataSourceInput{
		Subject: &trust.Result{
			Subject: "user123",
			Issuer:  "https://issuer.example.com",
			Claims:  map[string]any{"sub": "user123"},
		},
	}

	ctx := context.Background()

	// First fetch
	registry.FetchAll(ctx, input)
	initialCount := source.GetFetchCount()

	if initialCount != 1 {
		t.Errorf("Expected initial fetch count 1, got %d", initialCount)
	}

	// Note: In real usage, if you wait 1 minute, the next fetch would generate
	// a different internal cache key (with the new rounded time), causing a cache miss
	// and triggering a new fetch. This naturally expires old cache entries via LRU.
}

func TestDataSourceRegistry_DifferentTTLsPerSource(t *testing.T) {
	registry := NewRegistry()

	// Source 1: No TTL (cache indefinitely)
	source1 := NewCountingDataSourceWithTTL("no-ttl-source", map[string]any{"data": "one"}, 0)

	// Source 2: 1 hour TTL
	source2 := NewCountingDataSourceWithTTL("hourly-source", map[string]any{"data": "two"}, 1*time.Hour)

	// Source 3: 24 hour TTL
	source3 := NewCountingDataSourceWithTTL("daily-source", map[string]any{"data": "three"}, 24*time.Hour)

	registry.Register(source1)
	registry.Register(source2)
	registry.Register(source3)

	input := &issuer.DataSourceInput{
		Subject: &trust.Result{
			Subject: "user123",
			Issuer:  "https://issuer.example.com",
			Claims:  map[string]any{"sub": "user123"},
		},
	}

	ctx := context.Background()

	// Fetch all sources
	results := registry.FetchAll(ctx, input)

	// Verify all were fetched
	if len(results) != 3 {
		t.Errorf("Expected 3 sources, got %d", len(results))
	}

	// All should have been fetched once
	if source1.GetFetchCount() != 1 || source2.GetFetchCount() != 1 || source3.GetFetchCount() != 1 {
		t.Errorf("Expected all sources fetched once, got %d, %d, %d",
			source1.GetFetchCount(), source2.GetFetchCount(), source3.GetFetchCount())
	}

	// Second fetch - all should use cache
	results2 := registry.FetchAll(ctx, input)

	if len(results2) != 3 {
		t.Errorf("Expected 3 cached sources, got %d", len(results2))
	}

	// Verify still cached (counts unchanged)
	if source1.GetFetchCount() != 1 || source2.GetFetchCount() != 1 || source3.GetFetchCount() != 1 {
		t.Errorf("Expected all sources still cached, got %d, %d, %d",
			source1.GetFetchCount(), source2.GetFetchCount(), source3.GetFetchCount())
	}
}
