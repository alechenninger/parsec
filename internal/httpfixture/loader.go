package httpfixture

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/goccy/go-yaml"
)

// LoadFixturesFromFile loads fixtures from a JSON or YAML file
func LoadFixturesFromFile(path string) (*RuleBasedProvider, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read fixture file: %w", err)
	}

	var fixtureSet FixtureSet

	// Detect format by extension
	if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
		if err := yaml.Unmarshal(data, &fixtureSet); err != nil {
			return nil, fmt.Errorf("failed to parse YAML fixtures: %w", err)
		}
	} else {
		if err := json.Unmarshal(data, &fixtureSet); err != nil {
			return nil, fmt.Errorf("failed to parse JSON fixtures: %w", err)
		}
	}

	return NewRuleBasedProvider(fixtureSet.Rules), nil
}

// LoadFixturesFromDir loads all fixture files from a directory
func LoadFixturesFromDir(dir string) (*RuleBasedProvider, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read fixture directory: %w", err)
	}

	var allRules []HTTPFixtureRule

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		if strings.HasSuffix(path, ".json") || strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			provider, err := LoadFixturesFromFile(path)
			if err != nil {
				return nil, err
			}
			allRules = append(allRules, provider.rules...)
		}
	}

	return NewRuleBasedProvider(allRules), nil
}
