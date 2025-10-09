package httpfixture

import (
	"net/http"
	"time"
)

// Fixture defines an HTTP response to return for requests
type Fixture struct {
	StatusCode int               `json:"status" yaml:"status"`
	Headers    map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Body       string            `json:"body" yaml:"body"`
	Delay      *time.Duration    `json:"delay,omitempty" yaml:"delay,omitempty"`
}

// FixtureProvider returns a fixture for a request, or nil if no fixture applies
type FixtureProvider interface {
	GetFixture(req *http.Request) *Fixture
}

// HTTPFixtureRule defines request criteria and corresponding response (for file-based fixtures)
type HTTPFixtureRule struct {
	Request  FixtureRequest `json:"request" yaml:"request"`
	Response Fixture        `json:"response" yaml:"response"`
}

// FixtureRequest defines request matching criteria (for file-based fixtures)
type FixtureRequest struct {
	Method  string            `json:"method" yaml:"method"`                         // e.g., "GET", "POST", "*" for any
	URL     string            `json:"url" yaml:"url"`                               // exact match or pattern
	URLType string            `json:"url_type,omitempty" yaml:"url_type,omitempty"` // "exact" (default) or "pattern"
	Headers map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`   // optional header matching
}

// FixtureSet is a collection of fixture rules (for file loading)
type FixtureSet struct {
	Rules []HTTPFixtureRule `json:"fixtures" yaml:"fixtures"`
}
