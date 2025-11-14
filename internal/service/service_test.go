package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alechenninger/parsec/internal/trust"
)

func TestTokenService_IssueTokens_Observability(t *testing.T) {
	ctx := context.Background()

	t.Run("successful issuance calls probe methods in correct order", func(t *testing.T) {
		// Setup
		fakeObs := newFakeObserver(t)
		subject := &trust.Result{Subject: "user-123", TrustDomain: "prod"}
		actor := &trust.Result{Subject: "workload-456", TrustDomain: "prod"}

		stubToken := &Token{
			Value:     "token-value",
			Type:      string(TokenTypeTransactionToken),
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}

		issuer := &testIssuerStub{token: stubToken}
		registry := NewSimpleRegistry()
		registry.Register(TokenTypeTransactionToken, issuer)

		service := NewTokenService("trust.example.com", nil, registry, fakeObs)

		// Execute
		req := &IssueRequest{
			Subject:    subject,
			Actor:      actor,
			Scope:      "read write",
			TokenTypes: []TokenType{TokenTypeTransactionToken},
		}

		tokens, err := service.IssueTokens(ctx, req)

		// Verify business logic succeeded
		if err != nil {
			t.Fatalf("IssueTokens failed: %v", err)
		}
		if len(tokens) != 1 {
			t.Fatalf("expected 1 token, got %d", len(tokens))
		}

		// Verify observer saw probe started with correct parameters and method sequence
		scope := "read write"
		p := fakeObs.assertProbeStartedWith(subject, actor, &scope, []TokenType{TokenTypeTransactionToken})
		p.assertProbeSequence(
			probe("TokenTypeIssuanceStarted", TokenTypeTransactionToken),
			probe("TokenTypeIssuanceSucceeded", TokenTypeTransactionToken, stubToken),
			"End",
		)
	})

	t.Run("issuer not found calls probe correctly", func(t *testing.T) {
		fakeObs := newFakeObserver(t)
		registry := NewSimpleRegistry() // Empty registry - no issuers

		service := NewTokenService("trust.example.com", nil, registry, fakeObs)

		req := &IssueRequest{
			Subject:    &trust.Result{Subject: "user-123"},
			TokenTypes: []TokenType{TokenTypeTransactionToken},
		}

		_, err := service.IssueTokens(ctx, req)

		// Verify business logic failed as expected
		if err == nil {
			t.Fatal("expected error when issuer not found")
		}

		// Verify observer saw probe with correct method sequence including error
		p := fakeObs.assertProbeStartedWith(nil, nil, nil, nil)
		p.assertProbeSequence(
			probe("TokenTypeIssuanceStarted", TokenTypeTransactionToken),
			probe("IssuerNotFound", TokenTypeTransactionToken, errorContaining("no issuer")),
			"End",
		)
	})

	t.Run("token issuance failure calls probe correctly", func(t *testing.T) {
		fakeObs := newFakeObserver(t)
		issueErr := errors.New("signing failed")
		issuer := &testIssuerStub{err: issueErr}

		registry := NewSimpleRegistry()
		registry.Register(TokenTypeTransactionToken, issuer)

		service := NewTokenService("trust.example.com", nil, registry, fakeObs)

		req := &IssueRequest{
			Subject:    &trust.Result{Subject: "user-123"},
			TokenTypes: []TokenType{TokenTypeTransactionToken},
		}

		_, err := service.IssueTokens(ctx, req)

		// Verify business logic failed as expected
		if err == nil {
			t.Fatal("expected error when token issuance fails")
		}

		// Verify observer saw probe with correct method sequence including error
		p := fakeObs.assertProbeStartedWith(nil, nil, nil, nil)
		p.assertProbeSequence(
			probe("TokenTypeIssuanceStarted", TokenTypeTransactionToken),
			probe("TokenTypeIssuanceFailed", TokenTypeTransactionToken, issueErr),
			"End",
		)
	})

	t.Run("multiple token types are observed independently", func(t *testing.T) {
		fakeObs := newFakeObserver(t)

		token1 := &Token{Value: "token1", Type: string(TokenTypeTransactionToken)}
		token2 := &Token{Value: "token2", Type: string(TokenTypeAccessToken)}

		registry := NewSimpleRegistry()
		registry.Register(TokenTypeTransactionToken, &testIssuerStub{token: token1})
		registry.Register(TokenTypeAccessToken, &testIssuerStub{token: token2})

		service := NewTokenService("trust.example.com", nil, registry, fakeObs)

		req := &IssueRequest{
			Subject:    &trust.Result{Subject: "user-123"},
			TokenTypes: []TokenType{TokenTypeTransactionToken, TokenTypeAccessToken},
		}

		_, err := service.IssueTokens(ctx, req)
		if err != nil {
			t.Fatalf("IssueTokens failed: %v", err)
		}

		// Verify observer saw probe with correct method sequence
		// Should have: (Started + Succeeded) * 2 + End = 5 calls
		p := fakeObs.assertProbeStartedWith(nil, nil, nil, nil)
		p.assertProbeSequence(
			probe("TokenTypeIssuanceStarted", TokenTypeTransactionToken),
			probe("TokenTypeIssuanceSucceeded", TokenTypeTransactionToken, token1),
			probe("TokenTypeIssuanceStarted", TokenTypeAccessToken),
			probe("TokenTypeIssuanceSucceeded", TokenTypeAccessToken, token2),
			"End",
		)
	})

	t.Run("composite observer delegates to all observers", func(t *testing.T) {
		// Setup multiple fake observers
		fakeObs1 := newFakeObserver(t)
		fakeObs2 := newFakeObserver(t)
		fakeObs3 := newFakeObserver(t)

		composite := NewCompositeObserver(fakeObs1, fakeObs2, fakeObs3)

		stubToken := &Token{Value: "token1", Type: string(TokenTypeTransactionToken)}
		registry := NewSimpleRegistry()
		registry.Register(TokenTypeTransactionToken, &testIssuerStub{token: stubToken})

		service := NewTokenService("trust.example.com", nil, registry, composite)

		req := &IssueRequest{
			Subject:    &trust.Result{Subject: "user-123"},
			TokenTypes: []TokenType{TokenTypeTransactionToken},
		}

		_, err := service.IssueTokens(ctx, req)
		if err != nil {
			t.Fatalf("IssueTokens failed: %v", err)
		}

		// Verify all three observers were called and each created a probe with correct sequence
		for i, fakeObs := range []*fakeObserver{fakeObs1, fakeObs2, fakeObs3} {
			fakeObs.assertProbeCount(1)
			if len(fakeObs.probes) == 0 {
				t.Errorf("observer %d did not create a probe", i+1)
				continue
			}
			p := fakeObs.probes[0]
			p.assertProbeSequence(
				probe("TokenTypeIssuanceStarted", TokenTypeTransactionToken),
				probe("TokenTypeIssuanceSucceeded", TokenTypeTransactionToken, stubToken),
				"End",
			)
		}
	})
}

// fakeObserver creates fake probes and tracks them for test assertions.
// Tests should assert against the observer, which knows about all probes created.
type fakeObserver struct {
	t *testing.T

	// List of all probes created (one per TokenIssuanceStarted call)
	probes []*fakeProbe
}

func newFakeObserver(t *testing.T) *fakeObserver {
	return &fakeObserver{t: t, probes: []*fakeProbe{}}
}

func (o *fakeObserver) TokenIssuanceStarted(
	ctx context.Context,
	subject *trust.Result,
	actor *trust.Result,
	scope string,
	tokenTypes []TokenType,
) (context.Context, TokenIssuanceProbe) {
	// Create request-scoped probe
	probe := newFakeProbe(o.t, subject, actor, scope, tokenTypes)
	o.probes = append(o.probes, probe)
	return ctx, probe
}

// assertProbeCount verifies the expected number of probes were created
func (o *fakeObserver) assertProbeCount(expected int) {
	o.t.Helper()
	if len(o.probes) != expected {
		o.t.Errorf("expected %d probe(s), got %d", expected, len(o.probes))
	}
}

// assertProbeStartedWith finds a probe that was started with the given parameters.
// Returns the probe if found, fails the test if not found or if criteria don't match.
// Pass nil for parameters you don't want to check.
func (o *fakeObserver) assertProbeStartedWith(subject *trust.Result, actor *trust.Result, scope *string, tokenTypes []TokenType) *fakeProbe {
	o.t.Helper()

	if len(o.probes) == 0 {
		o.t.Fatal("no probes were created")
		return nil
	}

	// For now, just check the first probe (most common case)
	// Could be extended to search through all probes if needed
	probe := o.probes[0]

	if subject != nil && probe.subject != subject {
		o.t.Errorf("expected probe with subject %v, got %v", subject, probe.subject)
	}
	if actor != nil && probe.actor != actor {
		o.t.Errorf("expected probe with actor %v, got %v", actor, probe.actor)
	}
	if scope != nil && probe.scope != *scope {
		o.t.Errorf("expected probe with scope %q, got %q", *scope, probe.scope)
	}
	if tokenTypes != nil {
		if len(probe.tokenTypes) != len(tokenTypes) {
			o.t.Errorf("expected probe with %d token types, got %d", len(tokenTypes), len(probe.tokenTypes))
		} else {
			for i, tt := range tokenTypes {
				if probe.tokenTypes[i] != tt {
					o.t.Errorf("expected token type[%d] %v, got %v", i, tt, probe.tokenTypes[i])
				}
			}
		}
	}

	return probe
}

// getProbe returns the probe at the given index (0-based)
func (o *fakeObserver) getProbe(index int) *fakeProbe {
	o.t.Helper()
	if index < 0 || index >= len(o.probes) {
		o.t.Fatalf("probe index %d out of range (have %d probes)", index, len(o.probes))
		return nil
	}
	return o.probes[index]
}

// fakeProbe is a request-scoped test double that records method calls.
// It simply captures the sequence of calls for later assertion.
type fakeProbe struct {
	t      *testing.T
	states []probeState

	// Parameters captured at probe creation (from TokenIssuanceStarted)
	subject    *trust.Result
	actor      *trust.Result
	scope      string
	tokenTypes []TokenType
}

// probeState represents a single probe method call with its arguments.
type probeState interface {
	method() string
	arguments() []any
}

// Concrete state types (one per probe method)

type tokenTypeIssuanceStartedState struct {
	tokenType TokenType
}

func (s *tokenTypeIssuanceStartedState) method() string { return "TokenTypeIssuanceStarted" }
func (s *tokenTypeIssuanceStartedState) arguments() []any {
	return []any{s.tokenType}
}

type tokenTypeIssuanceSucceededState struct {
	tokenType TokenType
	token     *Token
}

func (s *tokenTypeIssuanceSucceededState) method() string { return "TokenTypeIssuanceSucceeded" }
func (s *tokenTypeIssuanceSucceededState) arguments() []any {
	return []any{s.tokenType, s.token}
}

type tokenTypeIssuanceFailedState struct {
	tokenType TokenType
	err       error
}

func (s *tokenTypeIssuanceFailedState) method() string { return "TokenTypeIssuanceFailed" }
func (s *tokenTypeIssuanceFailedState) arguments() []any {
	return []any{s.tokenType, s.err}
}

type issuerNotFoundState struct {
	tokenType TokenType
	err       error
}

func (s *issuerNotFoundState) method() string { return "IssuerNotFound" }
func (s *issuerNotFoundState) arguments() []any {
	return []any{s.tokenType, s.err}
}

type endState struct{}

func (s *endState) method() string { return "End" }
func (s *endState) arguments() []any {
	return []any{}
}

func newFakeProbe(t *testing.T, subject *trust.Result, actor *trust.Result, scope string, tokenTypes []TokenType) *fakeProbe {
	return &fakeProbe{
		t:          t,
		states:     []probeState{},
		subject:    subject,
		actor:      actor,
		scope:      scope,
		tokenTypes: tokenTypes,
	}
}

// recordState records a new method call
func (f *fakeProbe) recordState(state probeState) {
	f.states = append(f.states, state)
}

func (f *fakeProbe) TokenTypeIssuanceStarted(tokenType TokenType) {
	f.recordState(&tokenTypeIssuanceStartedState{
		tokenType: tokenType,
	})
}

func (f *fakeProbe) TokenTypeIssuanceSucceeded(tokenType TokenType, token *Token) {
	f.recordState(&tokenTypeIssuanceSucceededState{
		tokenType: tokenType,
		token:     token,
	})
}

func (f *fakeProbe) TokenTypeIssuanceFailed(tokenType TokenType, err error) {
	f.recordState(&tokenTypeIssuanceFailedState{
		tokenType: tokenType,
		err:       err,
	})
}

func (f *fakeProbe) IssuerNotFound(tokenType TokenType, err error) {
	f.recordState(&issuerNotFoundState{
		tokenType: tokenType,
		err:       err,
	})
}

func (f *fakeProbe) End() {
	f.recordState(&endState{})
}

// assertProbeSequence verifies the exact sequence of probe method calls.
// Accepts either strings (method names) or probeMatcher functions.
func (f *fakeProbe) assertProbeSequence(expected ...any) {
	f.t.Helper()
	if len(f.states) != len(expected) {
		f.t.Errorf("expected %d probe calls, got %d", len(expected), len(f.states))
		f.t.Logf("actual probe calls: %v", f.methodNames())
		return
	}
	for i, exp := range expected {
		state := f.states[i]
		switch e := exp.(type) {
		case string:
			// Simple method name matching
			if state.method() != e {
				f.t.Errorf("probe call %d: expected method %s, got %s", i, e, state.method())
			}
		case probeMatcher:
			// Custom matcher function
			if !e(state) {
				f.t.Errorf("probe call %d: matcher failed for %s", i, state.method())
			}
		default:
			f.t.Errorf("invalid expected type at position %d: %T", i, exp)
		}
	}
}

// methodNames returns just the method names from states for logging
func (f *fakeProbe) methodNames() []string {
	names := make([]string, len(f.states))
	for i, state := range f.states {
		names[i] = state.method()
	}
	return names
}

// ArgumentMatcher allows flexible matching of probe arguments
type ArgumentMatcher interface {
	Matches(actual any) bool
}

// errorContaining creates a matcher that checks if an error's message contains a substring
type errorContaining string

func (e errorContaining) Matches(actual any) bool {
	err, ok := actual.(error)
	if !ok || err == nil {
		return false
	}
	return strings.Contains(err.Error(), string(e))
}

// anyError matches any non-nil error
type anyErrorMatcher struct{}

func anyError() ArgumentMatcher {
	return anyErrorMatcher{}
}

func (anyErrorMatcher) Matches(actual any) bool {
	err, ok := actual.(error)
	return ok && err != nil
}

// probeMatcher is a function that matches against a probeState
type probeMatcher func(probeState) bool

// probe creates a matcher that checks probe method name and optionally arguments.
// Arguments can be either concrete values (checked with ==) or ArgumentMatcher instances.
func probe(method string, args ...any) probeMatcher {
	return func(s probeState) bool {
		if s.method() != method {
			return false
		}
		if len(args) == 0 {
			return true // Just matching method name
		}
		stateArgs := s.arguments()
		if len(args) != len(stateArgs) {
			return false
		}
		for i, expected := range args {
			// Check if expected is an ArgumentMatcher
			if matcher, ok := expected.(ArgumentMatcher); ok {
				if !matcher.Matches(stateArgs[i]) {
					return false
				}
			} else {
				// Direct equality comparison
				if expected != stateArgs[i] {
					return false
				}
			}
		}
		return true
	}
}

// testIssuerStub is a simple stub issuer for testing
type testIssuerStub struct {
	token *Token
	err   error
}

func (i *testIssuerStub) Issue(ctx context.Context, issueCtx *IssueContext) (*Token, error) {
	if i.err != nil {
		return nil, i.err
	}
	return i.token, nil
}

func (i *testIssuerStub) PublicKeys(ctx context.Context) ([]PublicKey, error) {
	return nil, nil
}
