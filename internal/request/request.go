// Package request provides common request-related types used across the Parsec system.
//
// This package contains types that represent HTTP/RPC request context and attributes,
// which are used by multiple packages including trust validation and token issuance.
package request

// RequestAttributes contains attributes about the incoming request
// This is used for both token issuance context and validator filtering decisions
// All fields are exported and JSON-serializable
type RequestAttributes struct {
	// Method is the HTTP method or RPC method name
	Method string `json:"method,omitempty"`

	// Path is the request path/resource being accessed
	Path string `json:"path,omitempty"`

	// IPAddress is the client IP address
	IPAddress string `json:"ip_address,omitempty"`

	// UserAgent is the client user agent
	UserAgent string `json:"user_agent,omitempty"`

	// Headers contains relevant HTTP headers
	Headers map[string]string `json:"headers,omitempty"`

	// Additional arbitrary context
	// This can include:
	// - "host": The HTTP host header
	// - "context_extensions": Envoy's context extensions (map[string]string)
	// - Custom application-specific context
	Additional map[string]any `json:"additional,omitempty"`
}
