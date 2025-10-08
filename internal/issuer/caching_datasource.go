package issuer

import (
	"context"
	"sync"
	"time"
)

// CachingDataSource wraps a cacheable data source with caching logic
// It implements DataSource but not Cacheable (it does the caching itself)
type CachingDataSource struct {
	source    DataSource
	cacheable Cacheable
	cache     *sync.Map // map[string]*cacheEntry
}

// cacheEntry stores cached data with expiration
type cacheEntry struct {
	result    *DataSourceResult
	expiresAt time.Time
}

// NewCachingDataSource wraps a data source with caching if it implements Cacheable
// Returns the original source if it doesn't implement Cacheable
func NewCachingDataSource(source DataSource) DataSource {
	cacheable, ok := source.(Cacheable)
	if !ok {
		// Source is not cacheable, return as-is
		return source
	}

	return &CachingDataSource{
		source:    source,
		cacheable: cacheable,
		cache:     &sync.Map{},
	}
}

// Name forwards to the underlying data source
func (c *CachingDataSource) Name() string {
	return c.source.Name()
}

// Fetch checks the cache first, then fetches from source on miss
func (c *CachingDataSource) Fetch(ctx context.Context, input *DataSourceInput) (*DataSourceResult, error) {
	// Get cache key from the cacheable source
	cacheKey := string(c.cacheable.CacheKey(ctx, input))

	// Check cache
	if entry, ok := c.cache.Load(cacheKey); ok {
		cached := entry.(*cacheEntry)
		// Check if cache entry is still valid
		if cached.expiresAt.IsZero() || time.Now().Before(cached.expiresAt) {
			return cached.result, nil
		}
		// Cache entry expired, remove it
		c.cache.Delete(cacheKey)
	}

	// Cache miss or expired - fetch from source
	result, err := c.source.Fetch(ctx, input)
	if err != nil {
		return nil, err
	}

	// Store in cache if result is not nil
	if result != nil {
		ttl := c.cacheable.CacheTTL()
		var expiresAt time.Time
		if ttl > 0 {
			expiresAt = time.Now().Add(ttl)
		}
		// expiresAt stays zero if TTL is 0 (cache indefinitely)

		c.cache.Store(cacheKey, &cacheEntry{
			result:    result,
			expiresAt: expiresAt,
		})
	}

	return result, nil
}
