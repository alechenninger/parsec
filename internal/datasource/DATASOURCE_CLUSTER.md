# Distributed Data Source Caching

This guide explains how to configure groupcache for distributed caching across multiple parsec nodes.

## Overview

Groupcache uses **consistent hashing** to distribute cache entries across a cluster of nodes. Benefits include:

- **Distributed Storage**: Cache is spread across all nodes (e.g., 3 nodes = 3x total cache capacity)
- **Automatic Routing**: Requests for a cache key automatically go to the node that owns it
- **Cluster-Wide Deduplication**: Only one fetch happens per cache key across the entire cluster
- **Hot Spot Mitigation**: Super hot keys are automatically replicated to prevent overload
- **Resilient**: Works even if some nodes are temporarily unavailable

## Configuration

### 1. Basic Cluster Setup

```go
package main

import (
    "net/http"
    "github.com/alechenninger/parsec/internal/issuer"
)

func main() {
    // Configure the cluster
    config := issuer.ClusterConfig{
        // This node's URL (must be accessible by other nodes)
        SelfURL: "http://parsec-node1.example.com:8080",
        
        // All nodes in the cluster (including self)
        PeerURLs: []string{
            "http://parsec-node1.example.com:8080",
            "http://parsec-node2.example.com:8080",
            "http://parsec-node3.example.com:8080",
        },
        
        // Optional: custom path for groupcache traffic (default: "/_groupcache/")
        BasePath: "/_groupcache/",
    }
    
    // Create cluster-aware registry
    registry := issuer.NewDataSourceClusterRegistry(config)
    
    // Register your data sources (same as before)
    userDataSource := NewUserDataSource(db)
    registry.Register(userDataSource)
    
    // Mount groupcache HTTP handler for peer-to-peer communication
    http.Handle("/_groupcache/", registry)
    
    // Your regular application handlers
    http.HandleFunc("/token-exchange", handleTokenExchange)
    
    // Start HTTP server
    http.ListenAndServe(":8080", nil)
}
```

### 2. Environment-Based Configuration

For containerized deployments (Kubernetes, Docker Compose, etc.):

```go
func loadClusterConfigFromEnv() issuer.ClusterConfig {
    selfURL := os.Getenv("PARSEC_SELF_URL")
    if selfURL == "" {
        selfURL = "http://localhost:8080"
    }
    
    // Comma-separated list of peer URLs
    peerURLsStr := os.Getenv("PARSEC_PEER_URLS")
    peerURLs := strings.Split(peerURLsStr, ",")
    if len(peerURLs) == 0 || peerURLs[0] == "" {
        // Single-node mode
        peerURLs = []string{selfURL}
    }
    
    return issuer.ClusterConfig{
        SelfURL:  selfURL,
        PeerURLs: peerURLs,
    }
}
```

### 3. Kubernetes StatefulSet Example

**deployment.yaml:**
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: parsec
spec:
  serviceName: parsec
  replicas: 3
  selector:
    matchLabels:
      app: parsec
  template:
    metadata:
      labels:
        app: parsec
    spec:
      containers:
      - name: parsec
        image: parsec:latest
        env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: PARSEC_SELF_URL
          value: "http://$(POD_NAME).parsec.default.svc.cluster.local:8080"
        - name: PARSEC_PEER_URLS
          value: "http://parsec-0.parsec.default.svc.cluster.local:8080,http://parsec-1.parsec.default.svc.cluster.local:8080,http://parsec-2.parsec.default.svc.cluster.local:8080"
        ports:
        - containerPort: 8080
          name: http
---
apiVersion: v1
kind: Service
metadata:
  name: parsec
spec:
  clusterIP: None  # Headless service for StatefulSet
  selector:
    app: parsec
  ports:
  - port: 8080
    name: http
```

### 4. Docker Compose Example

**docker-compose.yml:**
```yaml
version: '3.8'

services:
  parsec-1:
    image: parsec:latest
    environment:
      PARSEC_SELF_URL: "http://parsec-1:8080"
      PARSEC_PEER_URLS: "http://parsec-1:8080,http://parsec-2:8080,http://parsec-3:8080"
    ports:
      - "8081:8080"

  parsec-2:
    image: parsec:latest
    environment:
      PARSEC_SELF_URL: "http://parsec-2:8080"
      PARSEC_PEER_URLS: "http://parsec-1:8080,http://parsec-2:8080,http://parsec-3:8080"
    ports:
      - "8082:8080"

  parsec-3:
    image: parsec:latest
    environment:
      PARSEC_SELF_URL: "http://parsec-3:8080"
      PARSEC_PEER_URLS: "http://parsec-1:8080,http://parsec-2:8080,http://parsec-3:8080"
    ports:
      - "8083:8080"
```

## How It Works

### Request Flow

1. **Local Cache Hit**: 
   - Key hashes to local node → return immediately from local cache

2. **Remote Cache Hit**:
   - Key hashes to node-2 → HTTP request to node-2 → node-2 returns from cache

3. **Cache Miss (Local Owner)**:
   - Key hashes to local node → fetch from data source → cache locally → return

4. **Cache Miss (Remote Owner)**:
   - Key hashes to node-2 → HTTP request to node-2 → node-2 fetches from data source → node-2 caches → returns to node-1 → node-1 may cache as hot key

### Consistent Hashing

Groupcache uses consistent hashing to determine which node owns which cache keys:

```
Key: "user:12345" → Hash → Node 2 is owner
Key: "user:67890" → Hash → Node 1 is owner
Key: "user:11111" → Hash → Node 3 is owner
```

When a node joins or leaves, only a portion of keys are remapped (not all keys).

### Hot Key Replication

If a key is requested frequently from multiple nodes, groupcache automatically replicates it to those nodes, preventing hot spots.

## Dynamic Cluster Membership

For elastic scaling scenarios, you can update the peer list at runtime:

```go
// Update cluster topology when nodes are added/removed
func (s *Server) UpdateClusterTopology(newPeerURLs []string) {
    s.dataSourceRegistry.UpdatePeers(newPeerURLs)
}

// Example: watch Kubernetes endpoints and update
func watchKubernetesEndpoints(registry *issuer.DataSourceClusterRegistry) {
    // Pseudo-code
    watcher.OnChange(func(endpoints []string) {
        peerURLs := make([]string, len(endpoints))
        for i, ep := range endpoints {
            peerURLs[i] = fmt.Sprintf("http://%s:8080", ep)
        }
        registry.UpdatePeers(peerURLs)
    })
}
```

## Monitoring and Observability

### Cluster Stats

```go
stats := registry.GetClusterStats()
log.Printf("Running with %d peers: %v", stats.PeerCount, stats.PeerURLs)
```

### Cache Statistics

Groupcache provides built-in stats:

```go
import "github.com/golang/groupcache"

// Get stats for a specific cache group
group := groupcache.GetGroup("datasource:users")
if group != nil {
    stats := group.Stats
    log.Printf("Cache stats: Gets=%d Hits=%d Loads=%d", 
        stats.Gets, stats.CacheHits, stats.Loads)
}
```

### Metrics Endpoint

```go
http.HandleFunc("/metrics/cache", func(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "# Cache Metrics\n")
    
    // For each registered data source
    for _, sourceName := range registry.GetDataSourceNames() {
        group := groupcache.GetGroup("datasource:" + sourceName)
        if group != nil {
            stats := group.Stats
            fmt.Fprintf(w, "cache_gets{source=%q} %d\n", sourceName, stats.Gets.Get())
            fmt.Fprintf(w, "cache_hits{source=%q} %d\n", sourceName, stats.CacheHits.Get())
            fmt.Fprintf(w, "cache_loads{source=%q} %d\n", sourceName, stats.Loads.Get())
        }
    }
})
```

## Migration from Single-Node

To migrate from `DataSourceRegistry` to `DataSourceClusterRegistry`:

```go
// Before (single-node)
registry := issuer.NewDataSourceRegistry()
registry.Register(myDataSource)

// After (distributed)
config := issuer.ClusterConfig{
    SelfURL:  getSelfURL(),
    PeerURLs: getPeerURLs(),
}
registry := issuer.NewDataSourceClusterRegistry(config)
registry.Register(myDataSource)

// Mount the groupcache handler
http.Handle("/_groupcache/", registry)
```

The API is backward compatible - `DataSourceClusterRegistry` embeds `DataSourceRegistry`.

## Best Practices

1. **Stable Node URLs**: Use DNS names or service discovery, not IP addresses
2. **All Nodes Must Know All Peers**: Every node should have the complete peer list
3. **Network Latency**: Keep nodes in the same region/datacenter for low latency
4. **Cache Size**: Set per-node cache size based on available memory (64MB default)
5. **Security**: Consider mTLS or network policies for inter-node communication
6. **Health Checks**: Monitor node availability and update peer lists if nodes fail

## Troubleshooting

### Node Can't Reach Peers

```
Error: failed to fetch from peer: connection refused
```

**Solution**: Verify:
- Network connectivity between nodes
- Firewall rules allow traffic on port 8080
- SelfURL and PeerURLs are correct and accessible

### Cache Not Distributing

```
All requests going to local node only
```

**Solution**: 
- Ensure all nodes have the same peer list
- Verify `http.Handle("/_groupcache/", registry)` is mounted
- Check that SelfURL matches what other nodes use to reach this node

### Inconsistent Data

```
Different nodes returning different cached values for same key
```

**Solution**:
- This shouldn't happen with groupcache (consistent hashing)
- Check if multiple cache groups have the same name
- Verify all nodes are running the same code version

## Performance Characteristics

- **Local Cache Hit**: ~100ns (in-memory lookup)
- **Remote Cache Hit**: ~1-5ms (HTTP round-trip within datacenter)
- **Cache Miss**: Depends on data source (database, API, etc.)
- **Cluster-Wide Deduplication**: Only one node fetches, all others wait

## Security Considerations

Groupcache HTTP communication is **not encrypted by default**. For production:

1. **Use mTLS**: Run groupcache over HTTPS with client certificates
2. **Network Isolation**: Keep cache traffic on private network
3. **Kubernetes NetworkPolicy**: Restrict traffic to parsec pods only
4. **Authentication**: Add auth middleware to groupcache endpoint

Example with TLS:
```go
// Use TLS for groupcache peer communication
http.HandleFunc("/_groupcache/", func(w http.ResponseWriter, r *http.Request) {
    // Verify client certificate
    if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
        http.Error(w, "client certificate required", http.StatusUnauthorized)
        return
    }
    registry.ServeHTTP(w, r)
})
```

