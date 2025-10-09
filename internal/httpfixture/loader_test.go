package httpfixture

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFixturesFromFile_JSON(t *testing.T) {
	// Create a temporary JSON fixture file
	tmpDir := t.TempDir()
	fixtureFile := filepath.Join(tmpDir, "fixtures.json")

	jsonContent := `{
  "fixtures": [
    {
      "request": {
        "method": "GET",
        "url": "https://api.example.com/user/alice"
      },
      "response": {
        "status": 200,
        "headers": {
          "Content-Type": "application/json"
        },
        "body": "{\"username\": \"alice\"}"
      }
    },
    {
      "request": {
        "method": "POST",
        "url": "https://api.example.com/create"
      },
      "response": {
        "status": 201,
        "body": "{\"created\": true}"
      }
    }
  ]
}`

	if err := os.WriteFile(fixtureFile, []byte(jsonContent), 0644); err != nil {
		t.Fatalf("failed to create fixture file: %v", err)
	}

	provider, err := LoadFixturesFromFile(fixtureFile)
	if err != nil {
		t.Fatalf("failed to load fixtures: %v", err)
	}

	// Test first fixture
	req := httptest.NewRequest("GET", "https://api.example.com/user/alice", nil)
	fixture := provider.GetFixture(req)
	if fixture == nil {
		t.Fatal("expected fixture, got nil")
	}
	if fixture.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", fixture.StatusCode)
	}
	if fixture.Body != `{"username": "alice"}` {
		t.Errorf("Body = %q, want %q", fixture.Body, `{"username": "alice"}`)
	}

	// Test second fixture
	req = httptest.NewRequest("POST", "https://api.example.com/create", nil)
	fixture = provider.GetFixture(req)
	if fixture == nil {
		t.Fatal("expected fixture, got nil")
	}
	if fixture.StatusCode != 201 {
		t.Errorf("StatusCode = %d, want 201", fixture.StatusCode)
	}
}

func TestLoadFixturesFromFile_YAML(t *testing.T) {
	// Create a temporary YAML fixture file
	tmpDir := t.TempDir()
	fixtureFile := filepath.Join(tmpDir, "fixtures.yaml")

	yamlContent := `fixtures:
  - request:
      method: GET
      url: https://api.example.com/data
    response:
      status: 200
      headers:
        Content-Type: application/json
      body: '{"data": "value"}'
  - request:
      method: GET
      url: https://api.example.com/user/.*
      url_type: pattern
    response:
      status: 200
      body: '{"user": "any"}'
`

	if err := os.WriteFile(fixtureFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to create fixture file: %v", err)
	}

	provider, err := LoadFixturesFromFile(fixtureFile)
	if err != nil {
		t.Fatalf("failed to load fixtures: %v", err)
	}

	// Test exact match fixture
	req := httptest.NewRequest("GET", "https://api.example.com/data", nil)
	fixture := provider.GetFixture(req)
	if fixture == nil {
		t.Fatal("expected fixture, got nil")
	}
	if fixture.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", fixture.StatusCode)
	}

	// Test pattern match fixture
	req = httptest.NewRequest("GET", "https://api.example.com/user/alice", nil)
	fixture = provider.GetFixture(req)
	if fixture == nil {
		t.Fatal("expected fixture for pattern match, got nil")
	}
	if fixture.Body != `{"user": "any"}` {
		t.Errorf("Body = %q, want %q", fixture.Body, `{"user": "any"}`)
	}
}

func TestLoadFixturesFromFile_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	fixtureFile := filepath.Join(tmpDir, "invalid.json")

	if err := os.WriteFile(fixtureFile, []byte("{invalid json}"), 0644); err != nil {
		t.Fatalf("failed to create fixture file: %v", err)
	}

	_, err := LoadFixturesFromFile(fixtureFile)
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestLoadFixturesFromFile_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	fixtureFile := filepath.Join(tmpDir, "invalid.yaml")

	if err := os.WriteFile(fixtureFile, []byte("invalid: yaml: content:"), 0644); err != nil {
		t.Fatalf("failed to create fixture file: %v", err)
	}

	_, err := LoadFixturesFromFile(fixtureFile)
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

func TestLoadFixturesFromFile_NonExistent(t *testing.T) {
	_, err := LoadFixturesFromFile("/nonexistent/file.json")
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}

func TestLoadFixturesFromDir(t *testing.T) {
	tmpDir := t.TempDir()

	// Create multiple fixture files
	jsonFile := filepath.Join(tmpDir, "api1.json")
	jsonContent := `{
  "fixtures": [
    {
      "request": {
        "method": "GET",
        "url": "https://api1.example.com/data"
      },
      "response": {
        "status": 200,
        "body": "api1 data"
      }
    }
  ]
}`
	if err := os.WriteFile(jsonFile, []byte(jsonContent), 0644); err != nil {
		t.Fatalf("failed to create json file: %v", err)
	}

	yamlFile := filepath.Join(tmpDir, "api2.yaml")
	yamlContent := `fixtures:
  - request:
      method: GET
      url: https://api2.example.com/data
    response:
      status: 200
      body: api2 data
`
	if err := os.WriteFile(yamlFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to create yaml file: %v", err)
	}

	// Create a non-fixture file (should be ignored)
	if err := os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("ignored"), 0644); err != nil {
		t.Fatalf("failed to create txt file: %v", err)
	}

	provider, err := LoadFixturesFromDir(tmpDir)
	if err != nil {
		t.Fatalf("failed to load fixtures: %v", err)
	}

	// Test fixture from JSON file
	req := httptest.NewRequest("GET", "https://api1.example.com/data", nil)
	fixture := provider.GetFixture(req)
	if fixture == nil {
		t.Fatal("expected fixture from JSON file, got nil")
	}
	if fixture.Body != "api1 data" {
		t.Errorf("Body = %q, want %q", fixture.Body, "api1 data")
	}

	// Test fixture from YAML file
	req = httptest.NewRequest("GET", "https://api2.example.com/data", nil)
	fixture = provider.GetFixture(req)
	if fixture == nil {
		t.Fatal("expected fixture from YAML file, got nil")
	}
	if fixture.Body != "api2 data" {
		t.Errorf("Body = %q, want %q", fixture.Body, "api2 data")
	}
}

func TestLoadFixturesFromDir_NonExistent(t *testing.T) {
	_, err := LoadFixturesFromDir("/nonexistent/directory")
	if err == nil {
		t.Error("expected error for non-existent directory, got nil")
	}
}

func TestLoadFixturesFromDir_Empty(t *testing.T) {
	tmpDir := t.TempDir()

	provider, err := LoadFixturesFromDir(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should not match anything
	req := httptest.NewRequest("GET", "https://api.example.com/data", nil)
	fixture := provider.GetFixture(req)
	if fixture != nil {
		t.Error("expected nil for empty fixture set, got fixture")
	}
}
