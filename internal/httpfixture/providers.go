package httpfixture

import (
	"net/http"
	"regexp"
)

// RuleBasedProvider matches requests against a set of rules
type RuleBasedProvider struct {
	rules []HTTPFixtureRule
}

// NewRuleBasedProvider creates a new rule-based fixture provider
func NewRuleBasedProvider(rules []HTTPFixtureRule) *RuleBasedProvider {
	return &RuleBasedProvider{rules: rules}
}

// GetFixture returns a fixture for the given request if any rule matches
func (p *RuleBasedProvider) GetFixture(req *http.Request) *Fixture {
	for _, rule := range p.rules {
		if p.matches(req, rule.Request) {
			return &rule.Response
		}
	}
	return nil
}

// matches checks if a request matches the given criteria
func (p *RuleBasedProvider) matches(req *http.Request, criteria FixtureRequest) bool {
	// Match method
	if criteria.Method != "*" && criteria.Method != "" && req.Method != criteria.Method {
		return false
	}

	// Match URL (exact or pattern)
	urlType := criteria.URLType
	if urlType == "" {
		urlType = "exact"
	}

	if urlType == "pattern" {
		matched, err := regexp.MatchString(criteria.URL, req.URL.String())
		if err != nil || !matched {
			return false
		}
	} else {
		if req.URL.String() != criteria.URL {
			return false
		}
	}

	// Match headers if specified
	for key, value := range criteria.Headers {
		if req.Header.Get(key) != value {
			return false
		}
	}

	return true
}

// MapProvider provides fixtures based on a simple map lookup (method+URL key)
type MapProvider struct {
	fixtures map[string]*Fixture
}

// NewMapProvider creates a new map-based fixture provider
// Key format: "METHOD URL" (e.g., "GET https://api.example.com/user/alice")
func NewMapProvider(fixtures map[string]*Fixture) *MapProvider {
	return &MapProvider{fixtures: fixtures}
}

// GetFixture returns a fixture for the given request based on method+URL key
func (p *MapProvider) GetFixture(req *http.Request) *Fixture {
	key := req.Method + " " + req.URL.String()
	return p.fixtures[key]
}

// FuncProvider uses a function to provide fixtures (most flexible)
type FuncProvider struct {
	fn func(*http.Request) *Fixture
}

// NewFuncProvider creates a new function-based fixture provider
func NewFuncProvider(fn func(*http.Request) *Fixture) *FuncProvider {
	return &FuncProvider{fn: fn}
}

// GetFixture returns a fixture by calling the provided function
func (p *FuncProvider) GetFixture(req *http.Request) *Fixture {
	return p.fn(req)
}
