# Cache TTL Implementation

## Overview

Cache Time-To-Live (TTL) has been implemented for data sources using a clever time-interval-based approach that works naturally with groupcache's LRU eviction.

## How It Works

### The Concept

Instead of explicit expiration checks, TTL is achieved by:

1. **Time Rounding**: Current time is rounded to the nearest TTL interval
2. **Key Augmentation**: Rounded time is transparently added to the cache key
3. **Natural Expiration**: When time advances past the interval, a new key is generated
4. **LRU Eviction**: Old entries are eventually evicted from the LRU cache

### Example: 1-Hour TTL

```
Current time: 2025-10-08 14:37:42
TTL: 1 hour
Rounded time: 2025-10-08 14:00:00

User's cache key: "user:12345"
Internal cache key: "user:12345:2025-10-08T14:00:00Z"

At 15:00:00, internal key becomes: "user:12345:2025-10-08T15:00:00Z"
→ Cache miss, triggers new fetch
```

### Example: 24-Hour TTL (Daily)

```
Current time: 2025-10-08 14:37:42
TTL: 24 hours
Rounded time: 2025-10-08 00:00:00 (midnight)

Internal cache key: "profile:user123:2025-10-08T00:00:00Z"

At midnight the next day: "profile:user123:2025-10-09T00:00:00Z"
→ Cache miss, fetches fresh data
```

## Interface Changes

### New Method: `CacheTTL()`

```go
type DataSource interface {
    Name() string
    CacheKey(ctx context.Context, input *DataSourceInput) DataSourceCacheKey
    CacheTTL() time.Duration  // NEW!
    Fetch(ctx context.Context, input *DataSourceInput) (*DataSourceResult, error)
}
```

**Return values:**
- `0` = No TTL (cache indefinitely)
- `1 * time.Hour` = Expire every hour
- `24 * time.Hour` = Expire daily at midnight
- `5 * time.Minute` = Expire every 5 minutes

## Implementation Details

### Time Rounding Function

```go
func roundTimeToInterval(t time.Time, interval time.Duration) time.Time {
    if interval <= 0 {
        return t
    }
    unixTime := t.Unix()
    intervalSeconds := int64(interval.Seconds())
    rounded := (unixTime / intervalSeconds) * intervalSeconds
    return time.Unix(rounded, 0).UTC()
}
```

### Internal Cache Key Builder

```go
func buildInternalCacheKey(source DataSource, userKey DataSourceCacheKey, now time.Time) string {
    ttl := source.CacheTTL()
    if ttl == 0 {
        return string(userKey)  // No TTL
    }
    
    rounded := roundTimeToInterval(now, ttl)
    timeComponent := rounded.Format(time.RFC3339)
    return string(userKey) + ":" + timeComponent
}
```

### Transparent to Data Sources

The TTL logic is completely transparent - data sources only need to implement `CacheTTL()` and return a duration. The registry handles all the time-based key generation internally.

## Usage Examples

### No TTL (Default)

```go
func (s *StubDataSource) CacheTTL() time.Duration {
    return 0  // Cache indefinitely
}
```

### Hourly Refresh

```go
type UserRolesDataSource struct {
    db *sql.DB
}

func (u *UserRolesDataSource) CacheTTL() time.Duration {
    return 1 * time.Hour  // Refresh every hour
}

func (u *UserRolesDataSource) CacheKey(ctx context.Context, input *DataSourceInput) DataSourceCacheKey {
    return DataSourceCacheKey("roles:" + input.Subject.Subject)
}
```

Internal cache keys:
- `"roles:user123:2025-10-08T14:00:00Z"` (14:00-14:59)
- `"roles:user123:2025-10-08T15:00:00Z"` (15:00-15:59)

### Daily Refresh

```go
type UserProfileDataSource struct {
    api *http.Client
}

func (u *UserProfileDataSource) CacheTTL() time.Duration {
    return 24 * time.Hour  // Refresh daily at midnight
}

func (u *UserProfileDataSource) CacheKey(ctx context.Context, input *DataSourceInput) DataSourceCacheKey {
    return DataSourceCacheKey("profile:" + input.Subject.Subject)
}
```

Internal cache keys:
- `"profile:user123:2025-10-08T00:00:00Z"` (all day Oct 8)
- `"profile:user123:2025-10-09T00:00:00Z"` (all day Oct 9)

### Short-Lived Cache

```go
type RateLimitDataSource struct {
    redis *redis.Client
}

func (r *RateLimitDataSource) CacheTTL() time.Duration {
    return 5 * time.Minute  // Refresh every 5 minutes
}
```

Internal cache keys:
- `"ratelimit:user123:2025-10-08T14:00:00Z"` (14:00-14:04)
- `"ratelimit:user123:2025-10-08T14:05:00Z"` (14:05-14:09)

## Benefits

1. **✅ Simple**: Just return a duration, no complex expiration logic
2. **✅ Efficient**: No background cleanup, no expiration checks
3. **✅ Natural**: Works with LRU eviction automatically
4. **✅ Transparent**: Data sources don't manage time logic
5. **✅ Flexible**: Different TTLs for different data sources
6. **✅ Predictable**: Deterministic cache key generation

## Testing

Comprehensive tests cover:
- ✅ Time rounding for various intervals
- ✅ Internal cache key generation
- ✅ Caching with TTL
- ✅ Different TTLs per data source
- ✅ No TTL (indefinite caching)

See `datasource_ttl_test.go` for test cases.

## Considerations

### Thundering Herd

All requests at the moment a TTL interval rolls over will experience a cache miss simultaneously. This could cause a "thundering herd" if many requests arrive at the same time.

**Mitigation strategies:**
- Groupcache's built-in deduplication helps (only one fetch per key)
- Consider adding jitter to TTL intervals in the future
- Short TTLs (< 1 minute) may need more careful consideration

### Time Synchronization

All nodes in a distributed cluster should have synchronized clocks (via NTP) to ensure consistent cache key generation. Small time skews are usually acceptable since cache keys round to intervals.

### Cache Size

With TTL, you'll have multiple time-sliced versions of the same user key in cache:
- `"user:123:2025-10-08T14:00:00Z"`
- `"user:123:2025-10-08T15:00:00Z"`
- etc.

Old entries will be evicted by LRU when cache fills up. Monitor cache size and adjust as needed.

## Future Enhancements

- **Jitter**: Add random jitter to TTL to spread out cache misses
- **Stale-While-Revalidate**: Serve stale data while fetching fresh data in background
- **Metrics**: Track TTL expiry events and cache turnover rate
- **Configurable Rounding**: Allow custom rounding strategies (e.g., round to business hours)

