package httpfixture

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Transport implements http.RoundTripper using a FixtureProvider
type Transport struct {
	provider FixtureProvider
	fallback http.RoundTripper // optional fallback to real HTTP
	strict   bool              // if true, error when no fixture provided
}

// TransportConfig configures the fixture transport
type TransportConfig struct {
	Provider FixtureProvider
	Fallback http.RoundTripper // optional fallback transport
	Strict   bool              // if true, error when provider returns nil
}

// NewTransport creates a new fixture transport
func NewTransport(config TransportConfig) *Transport {
	return &Transport{
		provider: config.Provider,
		fallback: config.Fallback,
		strict:   config.Strict,
	}
}

// RoundTrip implements http.RoundTripper
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Ask provider for a fixture
	fixture := t.provider.GetFixture(req)

	if fixture != nil {
		// Apply delay if specified
		if fixture.Delay != nil {
			time.Sleep(*fixture.Delay)
		}

		// Create response from fixture
		return createResponse(fixture, req), nil
	}

	// No fixture provided
	if t.strict {
		return nil, fmt.Errorf("no fixture provided for request: %s %s", req.Method, req.URL)
	}

	if t.fallback != nil {
		return t.fallback.RoundTrip(req)
	}

	return nil, fmt.Errorf("no fixture provided and no fallback configured")
}

// createResponse creates an HTTP response from a fixture
func createResponse(fixture *Fixture, req *http.Request) *http.Response {
	resp := &http.Response{
		StatusCode: fixture.StatusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(fixture.Body)),
		Request:    req,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}

	for key, value := range fixture.Headers {
		resp.Header.Set(key, value)
	}

	return resp
}
