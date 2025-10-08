# Data Source Quick Start Guide

## Single-Node Setup (Simple)

For development or single-instance deployments:

```go
import "github.com/alechenninger/parsec/internal/issuer"

// Create registry
registry := issuer.NewDataSourceRegistry()

// Register your data sources
userDataSource := NewUserDataSource(db)
registry.Register(userDataSource)

// Use in token service
tokenService := issuer.NewTokenService(trustDomain, registry, claimMappers, issuerRegistry)
```

## Multi-Node Setup (Distributed)

For production with multiple parsec instances:

```go
import (
    "net/http"
    "github.com/alechenninger/parsec/internal/issuer"
)

// Configure cluster
config := issuer.ClusterConfig{
    SelfURL: os.Getenv("PARSEC_SELF_URL"),        // "http://parsec-1:8080"
    PeerURLs: strings.Split(                       // All nodes including self
        os.Getenv("PARSEC_PEER_URLS"), ","),
}

// Create cluster-aware registry
registry := issuer.NewDataSourceClusterRegistry(config)

// Register data sources (same as single-node)
userDataSource := NewUserDataSource(db)
registry.Register(userDataSource)

// Mount groupcache HTTP handler for peer communication
http.Handle("/_groupcache/", registry)

// Use in token service (same as single-node)
tokenService := issuer.NewTokenService(trustDomain, registry, claimMappers, issuerRegistry)

// Start server
http.ListenAndServe(":8080", nil)
```

## Implementing a Data Source

```go
type MyDataSource struct {
    db *sql.DB
}

func (m *MyDataSource) Name() string {
    return "my-data-source"
}

func (m *MyDataSource) CacheKey(ctx context.Context, input *issuer.DataSourceInput) issuer.DataSourceCacheKey {
    // Return empty string to disable caching for this fetch
    if input.Subject == nil {
        return ""
    }
    // Cache per user
    return issuer.DataSourceCacheKey("user:" + input.Subject.Subject)
}

func (m *MyDataSource) Fetch(ctx context.Context, input *issuer.DataSourceInput) (*issuer.DataSourceResult, error) {
    // Fetch from database, API, etc.
    data, err := m.db.QueryUser(input.Subject.Subject)
    if err != nil {
        return nil, err
    }
    
    // Serialize to JSON
    jsonData, err := json.Marshal(data)
    if err != nil {
        return nil, err
    }
    
    return &issuer.DataSourceResult{
        Data:        jsonData,
        ContentType: issuer.ContentTypeJSON,
    }, nil
}
```

## Environment Variables

For containerized deployments:

```bash
# Single-node (development)
PARSEC_SELF_URL=http://localhost:8080
PARSEC_PEER_URLS=http://localhost:8080

# Multi-node (production)
PARSEC_SELF_URL=http://parsec-1.example.com:8080
PARSEC_PEER_URLS=http://parsec-1.example.com:8080,http://parsec-2.example.com:8080,http://parsec-3.example.com:8080
```

## When to Use Each

### Use Single-Node (`DataSourceRegistry`) when:
- Development/testing
- Single parsec instance
- Simple deployment
- Don't need distributed cache

### Use Multi-Node (`DataSourceClusterRegistry`) when:
- Multiple parsec instances (HA, load balancing)
- Need distributed cache capacity
- Want cluster-wide deduplication
- Running in Kubernetes/cloud

## Key Differences

| Feature | Single-Node | Multi-Node |
|---------|------------|------------|
| Cache capacity | 64MB per data source | 64MB per data source per node |
| Deduplication | Per node | Cluster-wide |
| Setup complexity | Simple | Requires peer configuration |
| HTTP endpoint | Not needed | Requires `/_groupcache/` mount |
| Hot key replication | No | Yes |

## Further Reading

- [DATASOURCE_CACHING.md](DATASOURCE_CACHING.md) - Detailed caching behavior
- [DATASOURCE_CLUSTER.md](DATASOURCE_CLUSTER.md) - Distributed setup guide

