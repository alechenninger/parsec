package claims

import "maps"

// Claims represents a set of claims as key-value pairs
// This is used for both transaction context (tctx) and request context (req_ctx)
// as well as validated credential claims
type Claims map[string]any

// Copy creates a shallow copy of the claims
func (c Claims) Copy() Claims {
	if c == nil {
		return nil
	}
	result := make(Claims, len(c))
	maps.Copy(result, c)
	return result
}

// Merge merges the other claims into this claims set
// If a key exists in both, the value from other overwrites the existing value
func (c Claims) Merge(other Claims) {
	if other == nil {
		return
	}
	maps.Copy(c, other)
}

// Get returns the value for the given key, or nil if not present
func (c Claims) Get(key string) any {
	return c[key]
}

// GetString returns the value as a string, or empty string if not present or not a string
func (c Claims) GetString(key string) string {
	if v, ok := c[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// Has returns true if the key exists in the claims
func (c Claims) Has(key string) bool {
	_, ok := c[key]
	return ok
}
