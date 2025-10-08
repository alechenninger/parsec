package datasource

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/golang/groupcache"

	"github.com/alechenninger/parsec/internal/issuer"
)

// DistributedCachingDataSource wraps a cacheable data source with groupcache
// for distributed caching across multiple servers
type DistributedCachingDataSource struct {
	source    issuer.DataSource
	cacheable issuer.Cacheable
	group     *groupcache.Group
}

// DistributedCachingConfig configures the distributed caching data source
type DistributedCachingConfig struct {
	// GroupName is the name for this groupcache group
	// Should be unique per data source type
	GroupName string

	// CacheSizeBytes is the maximum size of the cache in bytes
	// Default: 64MB
	CacheSizeBytes int64
}

// NewDistributedCachingDataSource wraps a data source with distributed caching using groupcache
// Returns the original source if it doesn't implement Cacheable
//
// Note: groupcache requires that you set up the peer pool before creating caching data sources
// See groupcache documentation for details on setting up peers
func NewDistributedCachingDataSource(source issuer.DataSource, config DistributedCachingConfig) issuer.DataSource {
	cacheable, ok := source.(issuer.Cacheable)
	if !ok {
		// Source is not cacheable, return as-is
		return source
	}

	if config.GroupName == "" {
		config.GroupName = "datasource:" + source.Name()
	}

	if config.CacheSizeBytes == 0 {
		config.CacheSizeBytes = 64 << 20 // 64MB default
	}

	// Create the getter function that will be called on cache miss
	// This may be called on a different server in the groupcache peer pool
	getter := groupcache.GetterFunc(func(ctx context.Context, key string, dest groupcache.Sink) error {
		// Deserialize the cache key back into the masked input
		maskedInput, err := DeserializeInputFromJSON(key)
		if err != nil {
			return fmt.Errorf("failed to deserialize cache key: %w", err)
		}

		// Fetch using the masked input
		// The masked input is sufficient for fetching by design of Cacheable interface
		result, err := source.Fetch(ctx, maskedInput)
		if err != nil {
			return fmt.Errorf("data source fetch failed: %w", err)
		}

		if result == nil {
			return fmt.Errorf("data source returned nil result")
		}

		// Wrap result with content type for deserialization
		entry := cachedEntry{
			Data:        result.Data,
			ContentType: result.ContentType,
		}

		// Serialize for storage in cache
		entryBytes, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("failed to marshal cache entry: %w", err)
		}

		// Store in groupcache
		// Note: groupcache handles its own eviction based on LRU and cache size
		// The TTL from Cacheable is not used in groupcache (it uses LRU instead)
		return dest.SetBytes(entryBytes)
	})

	// Create the groupcache group
	group := groupcache.NewGroup(config.GroupName, config.CacheSizeBytes, getter)

	return &DistributedCachingDataSource{
		source:    source,
		cacheable: cacheable,
		group:     group,
	}
}

// cachedEntry wraps the data and content type for storage in cache
type cachedEntry struct {
	Data        []byte                       `json:"data"`
	ContentType issuer.DataSourceContentType `json:"content_type"`
}

// Name forwards to the underlying data source
func (c *DistributedCachingDataSource) Name() string {
	return c.source.Name()
}

// Fetch checks the distributed cache first, then fetches from source on miss
func (c *DistributedCachingDataSource) Fetch(ctx context.Context, input *issuer.DataSourceInput) (*issuer.DataSourceResult, error) {
	// Get the cache key (which is the masked input with only relevant fields)
	maskedInput := c.cacheable.CacheKey(input)

	// Serialize the masked input into a cache key string
	// This must be reversible (JSON) for distributed caching
	cacheKeyStr, err := SerializeInputToJSON(&maskedInput)
	if err != nil {
		// If serialization fails, fall back to direct fetch
		return c.source.Fetch(ctx, input)
	}

	// Fetch from groupcache (will hit cache or call getter)
	var cachedBytes []byte
	err = c.group.Get(ctx, cacheKeyStr, groupcache.AllocatingByteSliceSink(&cachedBytes))
	if err != nil {
		return nil, fmt.Errorf("groupcache fetch failed: %w", err)
	}

	// Deserialize the cached entry
	var entry cachedEntry
	if err := json.Unmarshal(cachedBytes, &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cached entry: %w", err)
	}

	return &issuer.DataSourceResult{
		Data:        entry.Data,
		ContentType: entry.ContentType,
	}, nil
}

// SerializeInputToJSON serializes a DataSourceInput to JSON (reversible)
// This is used for distributed caching where the key must be deserializable
func SerializeInputToJSON(input *issuer.DataSourceInput) (string, error) {
	jsonBytes, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("failed to marshal input to JSON: %w", err)
	}
	return string(jsonBytes), nil
}

// DeserializeInputFromJSON deserializes a JSON cache key back into a DataSourceInput
// This is used by groupcache when fetching on a remote server
func DeserializeInputFromJSON(key string) (*issuer.DataSourceInput, error) {
	var input issuer.DataSourceInput
	if err := json.Unmarshal([]byte(key), &input); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON to input: %w", err)
	}
	return &input, nil
}
