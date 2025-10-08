# Data Source Caching with Groupcache

This document describes the caching implementation for data sources using [groupcache](https://github.com/golang/groupcache).

## Overview

Data sources leverage automatic caching to avoid expensive re-fetches of data. The caching is implemented using groupcache, which provides:

- Automatic cache filling with deduplication (only one fetch per cache key across all concurrent requests)
- In-memory LRU cache with configurable size (currently 64MB per data source)
- No cache expiration (cache entries never expire, ensuring consistent behavior)

### Serialized Data Interface

The `DataSource` interface is designed to work with **pre-serialized data**, avoiding unnecessary serialization/deserialization round-trips:

- Data sources return `*DataSourceResult` with serialized bytes and a content type
- If fetching from a remote API that returns JSON, the raw JSON bytes can be returned directly
- The cache stores these bytes as-is without additional serialization
- Deserialization happens only once when `FetchAll` returns results to the caller

## How It Works

### Cache Key Generation

Each data source must implement the `CacheKey` method:

```go
CacheKey(ctx context.Context, input *DataSourceInput) DataSourceCacheKey
```

The cache key should:
- Be unique for each distinct set of data
- Return an empty string (`""`) to disable caching for a particular fetch
- Be deterministic (same input always produces same key)

### Caching Behavior

1. **Cache Hit**: If data for the cache key exists in memory, it's returned immediately without calling `Fetch`
2. **Cache Miss**: On the first request with a given cache key:
   - The data source's `Fetch` method is called
   - The serialized result is stored directly in the cache (no additional serialization)
   - Concurrent requests with the same cache key wait for the first fetch to complete (deduplication)
3. **No Cache Key**: If `CacheKey` returns an empty string, the fetch bypasses the cache entirely

### Data Source Interface

```go
type DataSource interface {
    Name() string
    CacheKey(ctx context.Context, input *DataSourceInput) DataSourceCacheKey
    CacheTTL() time.Duration // Return 0 to disable TTL
    Fetch(ctx context.Context, input *DataSourceInput) (*DataSourceResult, error)
}

type DataSourceResult struct {
    Data        []byte                // Serialized data (e.g., JSON bytes)
    ContentType DataSourceContentType // How to deserialize (e.g., "application/json")
}
```

### Cache TTL (Time-To-Live)

Data sources can specify a cache TTL via the `CacheTTL()` method. The TTL works by:

1. Rounding the current time to the nearest TTL interval
2. Incorporating that rounded time into the internal cache key
3. When time advances past the interval, a new cache key is generated
4. Old entries naturally age out via LRU eviction

**Examples:**
- TTL of 24 hours → Rounds to midnight of current day
- TTL of 1 hour → Rounds to start of current hour
- TTL of 5 minutes → Rounds to nearest 5-minute mark
- TTL of 0 → No expiration (cache indefinitely)

This approach:
- ✅ Avoids explicit expiration checks
- ✅ Works naturally with LRU cache
- ✅ Transparent to the data source implementation
- ✅ Efficient (no background cleanup needed)

### Example: Stub Data Source (No TTL)

```go
func (s *StubDataSource) CacheKey(ctx context.Context, input *DataSourceInput) DataSourceCacheKey {
    return DataSourceCacheKey(s.name)
}

func (s *StubDataSource) CacheTTL() time.Duration {
    return 0 // Cache indefinitely
}

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
```

### Example: Data Source with 1-Hour TTL

```go
type UserRolesDataSource struct {
    db *sql.DB
}

func (u *UserRolesDataSource) CacheTTL() time.Duration {
    return 1 * time.Hour // Cache for 1 hour
}

func (u *UserRolesDataSource) CacheKey(ctx context.Context, input *DataSourceInput) DataSourceCacheKey {
    if input.Subject == nil {
        return ""
    }
    return DataSourceCacheKey("roles:" + input.Subject.Subject)
}

// Internal cache keys will look like:
// "roles:user123:2025-10-08T14:00:00Z"  (hour 14)
// "roles:user123:2025-10-08T15:00:00Z"  (hour 15) <- new fetch triggered
```

### Example: Daily Cache TTL

```go
type UserProfileDataSource struct {
    api *http.Client
}

func (u *UserProfileDataSource) CacheTTL() time.Duration {
    return 24 * time.Hour // Cache for 24 hours (expires at midnight)
}

func (u *UserProfileDataSource) CacheKey(ctx context.Context, input *DataSourceInput) DataSourceCacheKey {
    return DataSourceCacheKey("profile:" + input.Subject.Subject)
}

// Internal cache keys will look like:
// "profile:user123:2025-10-08T00:00:00Z"  (Oct 8)
// "profile:user123:2025-10-09T00:00:00Z"  (Oct 9) <- new fetch at midnight
```

### Example: Remote API Data Source (Zero-Copy)

```go
type RemoteAPIDataSource struct {
    apiURL string
}

func (r *RemoteAPIDataSource) Fetch(ctx context.Context, input *DataSourceInput) (*DataSourceResult, error) {
    // Fetch from remote API
    resp, err := http.Get(r.apiURL)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    // Read JSON response directly - no need to deserialize and re-serialize!
    jsonData, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    
    return &DataSourceResult{
        Data:        jsonData,
        ContentType: ContentTypeJSON,
    }, nil
}
```

### Example: User Data Source (Cache Key per User)

```go
func (u *UserDataSource) CacheKey(ctx context.Context, input *DataSourceInput) DataSourceCacheKey {
    if input.Subject == nil {
        return "" // No caching without subject
    }
    // Cache per user ID
    return DataSourceCacheKey(fmt.Sprintf("user:%s", input.Subject.Subject))
}

func (u *UserDataSource) Fetch(ctx context.Context, input *DataSourceInput) (*DataSourceResult, error) {
    // Fetch user data from database
    user, err := u.db.GetUser(input.Subject.Subject)
    if err != nil {
        return nil, err
    }
    
    jsonData, err := json.Marshal(user)
    if err != nil {
        return nil, err
    }
    
    return &DataSourceResult{
        Data:        jsonData,
        ContentType: ContentTypeJSON,
    }, nil
}
```

## Cache Configuration

- **Cache Size**: Each data source gets 64MB of cache space (configurable in `initCacheForSource`)
- **Eviction**: LRU (Least Recently Used) when cache is full
- **Serialization**: Pre-serialized by data source; stored with content type in cache
- **Content Type Storage**: Content type is stored alongside data in cache for proper deserialization
- **Deserialization**: Happens once in `FetchAll` based on cached content type
- **TTL**: Time-to-live via time-interval-based cache keys (transparent to data source)
- **Concurrency**: Thread-safe with automatic request deduplication

### TTL Behavior

When a data source specifies a TTL:
1. Current time is rounded to nearest TTL interval
2. Rounded time is appended to the cache key
3. Example: User key `"user:12345"` with 1-hour TTL becomes `"user:12345:2025-10-08T14:00:00Z"`
4. After 1 hour, key becomes `"user:12345:2025-10-08T15:00:00Z"` (cache miss, re-fetch)
5. Old entry `"user:12345:2025-10-08T14:00:00Z"` eventually evicted by LRU

## Benefits

1. **Performance**: Eliminates redundant fetches for the same data
2. **Zero-Copy**: Remote data sources can return raw bytes without deserializing/re-serializing
3. **Consistency**: Groupcache ensures only one fetch happens per cache key across all concurrent requests
4. **Scalability**: In-memory cache reduces load on external systems (databases, APIs, etc.)
5. **Simplicity**: Data sources implement `CacheKey` and `Fetch` - the registry handles caching automatically

## Testing

See `datasource_test.go` for comprehensive tests covering:
- Cache hits and misses
- Different cache keys
- No cache key (disabled caching)
- Multiple data sources
- Concurrent requests (deduplication)

## Distributed Caching

For multi-node deployments, see [DATASOURCE_CLUSTER.md](DATASOURCE_CLUSTER.md) for information on:
- Configuring groupcache for distributed caching across multiple parsec nodes
- Kubernetes StatefulSet deployment examples
- Docker Compose multi-node setup
- Dynamic cluster membership and scaling
- Security and monitoring

Using distributed caching provides:
- **Increased Capacity**: 3 nodes = 3x total cache capacity
- **Cluster-Wide Deduplication**: Only one fetch per key across all nodes
- **Hot Key Replication**: Popular keys automatically replicate to prevent hot spots

## Future Enhancements

Potential improvements:
- Configurable cache size per data source
- Additional content types (protobuf, msgpack, etc.)
- Metrics and monitoring (cache hit rate, TTL expiry tracking, etc.)
- More efficient cache entry encoding (e.g., binary format instead of JSON wrapper)
- Jitter for TTL to prevent thundering herd at interval boundaries

