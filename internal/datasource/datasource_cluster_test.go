package datasource

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/alechenninger/parsec/internal/issuer"
	"github.com/alechenninger/parsec/internal/trust"
)

func TestDataSourceClusterRegistry_BasicSetup(t *testing.T) {
	// Create a test data source with unique name to avoid groupcache group name collision
	testData := map[string]any{
		"user_id": "test-user",
		"email":   "test@example.com",
	}
	source := NewCountingDataSource("cluster-test-source", testData)

	// Create cluster configuration (single-node for this test)
	config := ClusterConfig{
		SelfURL:  "http://localhost:8080",
		PeerURLs: []string{"http://localhost:8080"},
		BasePath: "/_groupcache/",
	}

	// Create cluster registry
	registry := NewDataSourceClusterRegistry(config)
	registry.Register(source)

	// Verify the registry was created
	if registry == nil {
		t.Fatal("Expected registry to be created")
	}

	// Verify stats
	stats := registry.GetClusterStats()
	if stats.SelfURL != config.SelfURL {
		t.Errorf("Expected SelfURL %s, got %s", config.SelfURL, stats.SelfURL)
	}
	if stats.PeerCount != 1 {
		t.Errorf("Expected 1 peer, got %d", stats.PeerCount)
	}

	// Test that FetchAll still works
	input := &issuer.DataSourceInput{
		Subject: &trust.Result{
			Subject: "user123",
			Issuer:  "https://issuer.example.com",
			Claims:  map[string]any{"sub": "user123"},
		},
	}

	results := registry.FetchAll(context.Background(), input)
	if results["cluster-test-source"] == nil {
		t.Fatal("Expected data from cluster-test-source")
	}
	if results["cluster-test-source"]["user_id"] != "test-user" {
		t.Errorf("Expected user_id 'test-user', got %v", results["cluster-test-source"]["user_id"])
	}

	// Verify fetch was called once
	if source.GetFetchCount() != 1 {
		t.Errorf("Expected fetch count 1, got %d", source.GetFetchCount())
	}

	// Fetch again - should use cache
	results2 := registry.FetchAll(context.Background(), input)
	if results2["cluster-test-source"]["email"] != "test@example.com" {
		t.Errorf("Expected cached email, got %v", results2["cluster-test-source"]["email"])
	}
	if source.GetFetchCount() != 1 {
		t.Errorf("Expected fetch count still 1 (cached), got %d", source.GetFetchCount())
	}
}

// Note: This test is skipped because groupcache only allows one HTTPPool per process.
// In production, you only create one issuer.DataSourceClusterRegistry per application instance.
func TestDataSourceClusterRegistry_HTTPHandler(t *testing.T) {
	t.Skip("Skipping: groupcache only allows one HTTPPool per process")
}

func TestDataSourceClusterRegistry_UpdatePeers(t *testing.T) {
	t.Skip("Skipping: groupcache only allows one HTTPPool per process")

	config := ClusterConfig{
		SelfURL:  "http://node1:8080",
		PeerURLs: []string{"http://node1:8080"},
	}
	registry := NewDataSourceClusterRegistry(config)

	// Initial state
	stats := registry.GetClusterStats()
	if stats.PeerCount != 1 {
		t.Errorf("Expected 1 peer initially, got %d", stats.PeerCount)
	}

	// Update peers (simulating cluster expansion)
	newPeers := []string{
		"http://node1:8080",
		"http://node2:8080",
		"http://node3:8080",
	}
	registry.UpdatePeers(newPeers)

	// Verify updated
	stats = registry.GetClusterStats()
	if stats.PeerCount != 3 {
		t.Errorf("Expected 3 peers after update, got %d", stats.PeerCount)
	}
	if len(stats.PeerURLs) != 3 {
		t.Errorf("Expected 3 peer URLs, got %d", len(stats.PeerURLs))
	}
}

func TestDataSourceClusterRegistry_MultipleDataSources(t *testing.T) {
	t.Skip("Skipping: groupcache only allows one HTTPPool per process")

	config := ClusterConfig{
		SelfURL:  "http://localhost:8080",
		PeerURLs: []string{"http://localhost:8080"},
	}
	registry := NewDataSourceClusterRegistry(config)

	// Register multiple data sources
	source1 := NewCountingDataSource("source1", map[string]any{"data": "one"})
	source2 := NewCountingDataSource("source2", map[string]any{"data": "two"})
	source3 := NewCountingDataSource("source3", map[string]any{"data": "three"})

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

	// Fetch all
	results := registry.FetchAll(context.Background(), input)

	// Verify all sources returned data
	if len(results) != 3 {
		t.Errorf("Expected 3 data sources, got %d", len(results))
	}
	if results["source1"]["data"] != "one" {
		t.Errorf("Expected source1 data 'one', got %v", results["source1"]["data"])
	}
	if results["source2"]["data"] != "two" {
		t.Errorf("Expected source2 data 'two', got %v", results["source2"]["data"])
	}
	if results["source3"]["data"] != "three" {
		t.Errorf("Expected source3 data 'three', got %v", results["source3"]["data"])
	}
}

// Example of how to set up a cluster from environment variables
func ExampleNewDataSourceClusterRegistry_fromEnv() {
	// In production, you would load these from environment variables:
	// selfURL := os.Getenv("PARSEC_SELF_URL")
	// peerURLs := strings.Split(os.Getenv("PARSEC_PEER_URLS"), ",")

	config := ClusterConfig{
		SelfURL: "http://parsec-node1.example.com:8080",
		PeerURLs: []string{
			"http://parsec-node1.example.com:8080",
			"http://parsec-node2.example.com:8080",
			"http://parsec-node3.example.com:8080",
		},
	}

	registry := NewDataSourceClusterRegistry(config)

	// Register data sources
	// registry.Register(myDataSource)

	// Mount HTTP handler
	http.Handle("/_groupcache/", registry)

	// Start server
	// http.ListenAndServe(":8080", nil)

	_ = registry // Use registry in your application
}

// Example showing cachedEntry serialization (for understanding cache format)
func TestCachedEntry_Serialization(t *testing.T) {
	entry := cachedEntry{
		Data:        []byte(`{"user_id":"12345","email":"test@example.com"}`),
		ContentType: issuer.ContentTypeJSON,
	}

	// Serialize
	serialized, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Failed to serialize: %v", err)
	}

	// Deserialize
	var decoded cachedEntry
	if err := json.Unmarshal(serialized, &decoded); err != nil {
		t.Fatalf("Failed to deserialize: %v", err)
	}

	// Verify
	if decoded.ContentType != issuer.ContentTypeJSON {
		t.Errorf("Expected content type %s, got %s", issuer.ContentTypeJSON, decoded.ContentType)
	}
	if string(decoded.Data) != string(entry.Data) {
		t.Errorf("Data mismatch: expected %s, got %s", string(entry.Data), string(decoded.Data))
	}
}
