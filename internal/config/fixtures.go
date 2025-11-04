package config

import (
	"github.com/alechenninger/parsec/internal/httpfixture"
)

// BuildHTTPFixtureProvider creates an HTTP fixture provider from fixture configurations
// Returns nil if no http_rule fixtures are configured (normal production mode)
func BuildHTTPFixtureProvider(fixtures []FixtureConfig) httpfixture.FixtureProvider {
	if len(fixtures) == 0 {
		return nil
	}

	var rules []httpfixture.HTTPFixtureRule
	for _, f := range fixtures {
		if f.Type != "http_rule" {
			continue
		}

		rule := httpfixture.HTTPFixtureRule{
			Request: httpfixture.FixtureRequest{
				Method:  f.Request.Method,
				URL:     f.Request.URL,
				URLType: f.Request.URLType,
				Headers: f.Request.Headers,
			},
			Response: httpfixture.Fixture{
				StatusCode: f.Response.StatusCode,
				Headers:    f.Response.Headers,
				Body:       f.Response.Body,
			},
		}
		rules = append(rules, rule)
	}

	if len(rules) == 0 {
		return nil
	}

	return httpfixture.NewRuleBasedProvider(rules)
}

