package datasource

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/alechenninger/parsec/internal/issuer"
	"github.com/golang/groupcache"
)

// ClusterConfig contains configuration for distributed caching
type ClusterConfig struct {
	// SelfURL is this node's URL (e.g., "http://localhost:8080")
	SelfURL string

	// PeerURLs are the URLs of all nodes in the cluster (including self)
	// e.g., ["http://node1:8080", "http://node2:8080", "http://node3:8080"]
	PeerURLs []string

	// BasePath is the HTTP path prefix for groupcache (default: "/_groupcache/")
	BasePath string
}

// issuer.DataSourceClusterRegistry is a distributed-cache-enabled Registry
type ClusterRegistry struct {
	*Registry
	pool   *groupcache.HTTPPool
	config ClusterConfig
	mu     sync.Mutex
}

// NewDataSourceClusterRegistry creates a new registry with distributed caching
func NewDataSourceClusterRegistry(config ClusterConfig) *ClusterRegistry {
	if config.BasePath == "" {
		config.BasePath = "/_groupcache/"
	}

	// Create the base registry
	baseRegistry := NewRegistry()

	// Create HTTP pool for this node
	pool := groupcache.NewHTTPPool(config.SelfURL)

	// Set the peer list (groupcache will use consistent hashing)
	pool.Set(config.PeerURLs...)

	return &ClusterRegistry{
		Registry: baseRegistry,
		pool:     pool,
		config:   config,
	}
}

// ServeHTTP implements http.Handler for groupcache peer communication
func (r *ClusterRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.pool.ServeHTTP(w, req)
}

// Register adds a data source and creates a distributed cache group
// This overrides the base Register to use the cluster-aware pool
func (r *ClusterRegistry) Register(source issuer.DataSource) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Add to sources list
	r.sources = append(r.sources, source)

	// Initialize cache with cluster awareness
	r.initCacheForSourceCluster(source)
}

// initCacheForSourceCluster creates a groupcache.Group that's aware of the cluster
func (r *ClusterRegistry) initCacheForSourceCluster(source issuer.DataSource) {
	sourceName := source.Name()
	if _, exists := r.caches[sourceName]; exists {
		return
	}

	// Create the same getter as before
	getter := groupcache.GetterFunc(func(ctx context.Context, key string, dest groupcache.Sink) error {
		input, ok := ctx.Value(dataSourceInputKey{}).(fetchInput)
		if !ok {
			return fmt.Errorf("missing data source input in context")
		}

		result, err := source.Fetch(input.ctx, input.input)
		if err != nil {
			return fmt.Errorf("data source fetch failed: %w", err)
		}

		if result == nil {
			return fmt.Errorf("data source returned nil result")
		}

		entry := cachedEntry{
			Data:        result.Data,
			ContentType: result.ContentType,
		}

		entryBytes, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("failed to marshal cache entry: %w", err)
		}

		return dest.SetBytes(entryBytes)
	})

	// Create the cache group - this will now participate in the cluster
	// The HTTPPool we configured will handle peer communication automatically
	r.caches[sourceName] = groupcache.NewGroup(
		"datasource:"+sourceName,
		64<<20, // 64 MB per node
		getter,
	)
}

// UpdatePeers dynamically updates the peer list (for elastic scaling)
func (r *ClusterRegistry) UpdatePeers(peerURLs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.config.PeerURLs = peerURLs
	r.pool.Set(peerURLs...)
}

// GetClusterStats returns information about the cluster configuration
func (r *ClusterRegistry) GetClusterStats() ClusterStats {
	return ClusterStats{
		SelfURL:   r.config.SelfURL,
		PeerURLs:  r.config.PeerURLs,
		PeerCount: len(r.config.PeerURLs),
	}
}

// ClusterStats provides information about the cluster
type ClusterStats struct {
	SelfURL   string
	PeerURLs  []string
	PeerCount int
}

// Example usage in your main.go or server initialization:
//
// func setupDistributedCaching() *ClusterRegistry {
//     config := ClusterConfig{
//         SelfURL: "http://parsec-node1.example.com:8080",
//         PeerURLs: []string{
//             "http://parsec-node1.example.com:8080",
//             "http://parsec-node2.example.com:8080",
//             "http://parsec-node3.example.com:8080",
//         },
//     }
//
//     registry := NewDataSourceClusterRegistry(config)
//
//     // Register your data sources
//     registry.Register(myDataSource)
//
//     // Mount the groupcache HTTP handler
//     http.Handle("/_groupcache/", registry)
//
//     return registry
// }
