package datasource

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/alechenninger/parsec/internal/issuer"
	"github.com/golang/groupcache"
)

// Registry is a groupcache-backed implementation of issuer.Registry
type Registry struct {
	sources []issuer.DataSource
	caches  map[string]*groupcache.Group
	mu      sync.RWMutex
}

// NewRegistry creates a new data source registry with groupcache support
func NewRegistry() *Registry {
	return &Registry{
		sources: make([]issuer.DataSource, 0),
		caches:  make(map[string]*groupcache.Group),
	}
}

// Register adds a data source to the registry
func (r *Registry) Register(source issuer.DataSource) {
	r.sources = append(r.sources, source)
	r.initCacheForSource(source)
}

// initCacheForSource creates a groupcache.Group for a data source
func (r *Registry) initCacheForSource(source issuer.DataSource) {
	r.mu.Lock()
	defer r.mu.Unlock()

	sourceName := source.Name()
	if _, exists := r.caches[sourceName]; exists {
		return
	}

	// Create a getter function that will fetch data on cache miss
	getter := groupcache.GetterFunc(func(ctx context.Context, key string, dest groupcache.Sink) error {
		// The key is the cache key, but we need the input to call Fetch
		// We'll store the input in the context
		input, ok := ctx.Value(dataSourceInputKey{}).(fetchInput)
		if !ok {
			return fmt.Errorf("missing data source input in context")
		}

		// Call the actual data source Fetch
		result, err := source.Fetch(input.ctx, input.input)
		if err != nil {
			return fmt.Errorf("data source fetch failed: %w", err)
		}

		if result == nil {
			return fmt.Errorf("data source returned nil result")
		}

		// Create cache entry with both data and content type
		entry := cachedEntry{
			Data:        result.Data,
			ContentType: result.ContentType,
		}

		// Serialize the cache entry
		entryBytes, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("failed to marshal cache entry: %w", err)
		}

		// Store in cache
		return dest.SetBytes(entryBytes)
	})

	// Create the cache group with 64MB size (configurable)
	r.caches[sourceName] = groupcache.NewGroup(
		"datasource:"+sourceName,
		64<<20, // 64 MB
		getter,
	)
}

// Context key type for storing input in context
type dataSourceInputKey struct{}

type fetchInput struct {
	ctx   context.Context
	input *issuer.DataSourceInput
}

// cachedEntry wraps the data and content type for storage in cache.
// Storing the content type ensures we can properly deserialize cached entries
// even if the data source changes its content type or supports multiple formats.
type cachedEntry struct {
	Data        []byte
	ContentType issuer.DataSourceContentType
}

// roundTimeToInterval rounds the given time to the nearest interval.
// For example, with a 24-hour interval, it rounds to midnight of the current day.
// This is used to create time-based cache keys that expire naturally via LRU.
func roundTimeToInterval(t time.Time, interval time.Duration) time.Time {
	if interval <= 0 {
		return t
	}
	// Convert to Unix timestamp
	unixTime := t.Unix()
	// Round down to the nearest interval
	intervalSeconds := int64(interval.Seconds())
	rounded := (unixTime / intervalSeconds) * intervalSeconds
	return time.Unix(rounded, 0).UTC()
}

// buildInternalCacheKey creates the actual cache key used in groupcache,
// incorporating the TTL-based time interval if configured.
func buildInternalCacheKey(source issuer.DataSource, userKey issuer.DataSourceCacheKey, now time.Time) string {
	ttl := source.CacheTTL()
	if ttl == 0 {
		// No TTL, use the user's key directly
		return string(userKey)
	}

	// Round the current time to the nearest TTL interval
	rounded := roundTimeToInterval(now, ttl)
	// Format as RFC3339 for readability in cache keys
	timeComponent := rounded.Format(time.RFC3339)

	// Combine user key with time component
	return string(userKey) + ":" + timeComponent
}

// FetchAll invokes all registered data sources and returns their results
// Returns a map of data source name to data
// If a data source returns an error, it is skipped (treated as optional)
// Uses groupcache to cache results based on the cache key from each source
func (r *Registry) FetchAll(ctx context.Context, input *issuer.DataSourceInput) map[string]map[string]any {
	results := make(map[string]map[string]any)

	for _, source := range r.sources {
		sourceName := source.Name()

		// Get the cache key from the source
		cacheKey := source.CacheKey(ctx, input)

		var resultData []byte
		var contentType issuer.DataSourceContentType

		if cacheKey == "" {
			// No cache key means we skip caching for this fetch
			result, err := source.Fetch(ctx, input)
			if err != nil || result == nil {
				// Treat data sources as optional
				continue
			}
			resultData = result.Data
			contentType = result.ContentType
		} else {
			// Get the cache for this source
			r.mu.RLock()
			cache, exists := r.caches[sourceName]
			r.mu.RUnlock()

			if !exists {
				// No cache configured, fetch directly
				result, err := source.Fetch(ctx, input)
				if err != nil || result == nil {
					continue
				}
				resultData = result.Data
				contentType = result.ContentType
			} else {
				// Build internal cache key with TTL-based time component
				internalKey := buildInternalCacheKey(source, cacheKey, time.Now())

				// Fetch from cache (or trigger fetch on miss)
				// Store the input in context for the getter function
				fetchCtx := context.WithValue(ctx, dataSourceInputKey{}, fetchInput{
					ctx:   ctx,
					input: input,
				})

				var cachedEntryBytes []byte
				err := cache.Get(fetchCtx, internalKey, groupcache.AllocatingByteSliceSink(&cachedEntryBytes))
				if err != nil {
					// Cache fetch failed, treat as optional
					continue
				}

				// Deserialize the cache entry
				var entry cachedEntry
				if err := json.Unmarshal(cachedEntryBytes, &entry); err != nil {
					// Failed to unmarshal cache entry, skip this source
					continue
				}

				resultData = entry.Data
				contentType = entry.ContentType
			}
		}

		// Deserialize based on content type
		data, err := r.deserialize(resultData, contentType)
		if err != nil {
			// Deserialization failed, skip this source
			continue
		}

		if data != nil {
			results[sourceName] = data
		}
	}

	return results
}

// deserialize converts serialized data back to map[string]any based on content type
// TODO: we could make deserialization based on content type externalized with its own types/interface/whatever
func (r *Registry) deserialize(data []byte, contentType issuer.DataSourceContentType) (map[string]any, error) {
	switch contentType {
	case issuer.ContentTypeJSON:
		var result map[string]any
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unsupported content type: %s", contentType)
	}
}
