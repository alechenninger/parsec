package service

import (
	"context"
	"errors"
	"fmt"
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

		// Get the probe that was created for this request
		probe := fakeObs.lastProbe

		// Verify probe was called correctly with exact sequence
		probe.assertCallSequence("TokenTypeIssuanceStarted", "TokenTypeIssuanceSucceeded", "End")

		// Verify observer was called with correct parameters
		if fakeObs.startSubject != subject {
			t.Errorf("Observer called with wrong subject")
		}
		if fakeObs.startActor != actor {
			t.Errorf("Observer called with wrong actor")
		}
		if fakeObs.startScope != "read write" {
			t.Errorf("Observer called with scope %q, expected %q", fakeObs.startScope, "read write")
		}

		// Verify token type was tracked correctly
		probe.assertTokenTypeStarted(TokenTypeTransactionToken)
		probe.assertTokenTypeSucceeded(TokenTypeTransactionToken)
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

		// Verify probe calls in exact sequence
		probe := fakeObs.lastProbe
		probe.assertCallSequence("TokenTypeIssuanceStarted", "IssuerNotFound", "End")
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

		// Verify probe calls in exact sequence
		probe := fakeObs.lastProbe
		probe.assertCallSequence("TokenTypeIssuanceStarted", "TokenTypeIssuanceFailed", "End")

		// Verify failure was recorded with correct token type
		probe.assertTokenTypeFailed(TokenTypeTransactionToken)
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

		// Should have: (Started + Succeeded) * 2 + End = 5 calls
		probe := fakeObs.lastProbe
		probe.assertCallSequence(
			"TokenTypeIssuanceStarted", "TokenTypeIssuanceSucceeded",
			"TokenTypeIssuanceStarted", "TokenTypeIssuanceSucceeded",
			"End",
		)

		// Verify both token types were started and succeeded
		probe.assertTokenTypeStarted(TokenTypeTransactionToken)
		probe.assertTokenTypeSucceeded(TokenTypeTransactionToken)
		probe.assertTokenTypeStarted(TokenTypeAccessToken)
		probe.assertTokenTypeSucceeded(TokenTypeAccessToken)
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

		// Verify all three observers were called
		for i, fakeObs := range []*fakeObserver{fakeObs1, fakeObs2, fakeObs3} {
			if fakeObs.lastProbe == nil {
				t.Errorf("observer %d was not called", i+1)
				continue
			}

			probe := fakeObs.lastProbe
			probe.assertCallSequence("TokenTypeIssuanceStarted", "TokenTypeIssuanceSucceeded", "End")
			probe.assertTokenTypeStarted(TokenTypeTransactionToken)
			probe.assertTokenTypeSucceeded(TokenTypeTransactionToken)
		}
	})
}

// fakeObserver creates fake probes and captures parameters passed to TokenIssuanceStarted
type fakeObserver struct {
	t *testing.T

	// Captured parameters from TokenIssuanceStarted
	startSubject    *trust.Result
	startActor      *trust.Result
	startScope      string
	startTokenTypes []TokenType

	// The last probe created (for test assertions)
	lastProbe *fakeProbe
}

func newFakeObserver(t *testing.T) *fakeObserver {
	return &fakeObserver{t: t}
}

func (o *fakeObserver) TokenIssuanceStarted(
	ctx context.Context,
	subject *trust.Result,
	actor *trust.Result,
	scope string,
	tokenTypes []TokenType,
) (context.Context, TokenIssuanceProbe) {
	// Capture parameters for test assertions
	o.startSubject = subject
	o.startActor = actor
	o.startScope = scope
	o.startTokenTypes = tokenTypes

	// Create request-scoped probe
	probe := newFakeProbe(o.t)
	o.lastProbe = probe
	return ctx, probe
}

// fakeProbe is a request-scoped test double that records calls and enforces invariants.
//
// It uses a state-based design where each recorded call becomes a state object
// that knows what valid transitions are allowed. Each state validates the next
// state, keeping validation logic cohesive and the probe implementation simple.
type fakeProbe struct {
	t      *testing.T
	states []probeState
}

// probeState represents a single probe method call with its arguments.
// Each state knows how to validate transitions to the next state.
type probeState interface {
	method() string
	arguments() []any
	canTransitionTo(next probeState) error
}

// Concrete state types (one per probe method)

type tokenTypeIssuanceStartedState struct {
	tokenType TokenType
}

func (s *tokenTypeIssuanceStartedState) method() string { return "TokenTypeIssuanceStarted" }
func (s *tokenTypeIssuanceStartedState) arguments() []any {
	return []any{s.tokenType}
}
func (s *tokenTypeIssuanceStartedState) canTransitionTo(next probeState) error {
	switch n := next.(type) {
	case *tokenTypeIssuanceStartedState:
		if n.tokenType == s.tokenType {
			return fmt.Errorf("token type %s started twice without completion", s.tokenType)
		}
		return nil
	case *tokenTypeIssuanceSucceededState, *tokenTypeIssuanceFailedState, *issuerNotFoundState:
		return nil
	case *endState:
		return fmt.Errorf("cannot End with token type %s still in flight", s.tokenType)
	default:
		return fmt.Errorf("invalid transition from TokenTypeIssuanceStarted to %s", next.method())
	}
}

type tokenTypeIssuanceSucceededState struct {
	tokenType TokenType
	token     *Token
}

func (s *tokenTypeIssuanceSucceededState) method() string { return "TokenTypeIssuanceSucceeded" }
func (s *tokenTypeIssuanceSucceededState) arguments() []any {
	return []any{s.tokenType, s.token}
}
func (s *tokenTypeIssuanceSucceededState) canTransitionTo(next probeState) error {
	switch next.(type) {
	case *tokenTypeIssuanceStartedState, *endState:
		return nil
	case *tokenTypeIssuanceSucceededState, *tokenTypeIssuanceFailedState:
		return errors.New("cannot succeed/fail after already completing a token type")
	default:
		return fmt.Errorf("invalid transition from TokenTypeIssuanceSucceeded to %s", next.method())
	}
}

type tokenTypeIssuanceFailedState struct {
	tokenType TokenType
	err       error
}

func (s *tokenTypeIssuanceFailedState) method() string { return "TokenTypeIssuanceFailed" }
func (s *tokenTypeIssuanceFailedState) arguments() []any {
	return []any{s.tokenType, s.err}
}
func (s *tokenTypeIssuanceFailedState) canTransitionTo(next probeState) error {
	switch next.(type) {
	case *endState:
		return nil
	case *tokenTypeIssuanceStartedState, *tokenTypeIssuanceSucceededState:
		return errors.New("cannot continue after token type issuance failed")
	default:
		return fmt.Errorf("invalid transition from TokenTypeIssuanceFailed to %s", next.method())
	}
}

type issuerNotFoundState struct {
	tokenType TokenType
	err       error
}

func (s *issuerNotFoundState) method() string { return "IssuerNotFound" }
func (s *issuerNotFoundState) arguments() []any {
	return []any{s.tokenType, s.err}
}
func (s *issuerNotFoundState) canTransitionTo(next probeState) error {
	switch next.(type) {
	case *endState:
		return nil
	default:
		return errors.New("IssuerNotFound must be followed by End")
	}
}

type endState struct{}

func (s *endState) method() string { return "End" }
func (s *endState) arguments() []any {
	return []any{}
}
func (s *endState) canTransitionTo(next probeState) error {
	return errors.New("End called multiple times")
}

func newFakeProbe(t *testing.T) *fakeProbe {
	return &fakeProbe{
		t:      t,
		states: []probeState{},
	}
}

// recordState validates and records a new state transition
func (f *fakeProbe) recordState(state probeState) {
	if len(f.states) > 0 {
		lastState := f.states[len(f.states)-1]
		if err := lastState.canTransitionTo(state); err != nil {
			f.t.Error(err)
		}
	}
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

// assertCallSequence verifies the exact sequence of method calls.
// Accepts either strings (method names) or stateMatcher functions.
func (f *fakeProbe) assertCallSequence(expected ...any) {
	f.t.Helper()
	if len(f.states) != len(expected) {
		f.t.Errorf("expected %d calls, got %d", len(expected), len(f.states))
		f.t.Logf("actual calls: %v", f.methodNames())
		return
	}
	for i, exp := range expected {
		state := f.states[i]
		switch e := exp.(type) {
		case string:
			// Simple method name matching
			if state.method() != e {
				f.t.Errorf("call %d: expected method %s, got %s", i, e, state.method())
			}
		case stateMatcher:
			// Custom matcher function
			if !e(state) {
				f.t.Errorf("call %d: matcher failed for %s", i, state.method())
			}
		default:
			f.t.Errorf("invalid expected type at position %d: %T", i, exp)
		}
	}
}

// assertTokenTypeStarted checks that a specific token type was started
func (f *fakeProbe) assertTokenTypeStarted(tokenType TokenType) {
	f.t.Helper()
	for _, state := range f.states {
		if s, ok := state.(*tokenTypeIssuanceStartedState); ok && s.tokenType == tokenType {
			return
		}
	}
	f.t.Errorf("expected TokenTypeIssuanceStarted for %s, but it was not called", tokenType)
}

// assertTokenTypeSucceeded checks that a specific token type succeeded
func (f *fakeProbe) assertTokenTypeSucceeded(tokenType TokenType) {
	f.t.Helper()
	for _, state := range f.states {
		if s, ok := state.(*tokenTypeIssuanceSucceededState); ok && s.tokenType == tokenType {
			return
		}
	}
	f.t.Errorf("expected TokenTypeIssuanceSucceeded for %s, but it was not called", tokenType)
}

// assertTokenTypeFailed checks that a specific token type failed
func (f *fakeProbe) assertTokenTypeFailed(tokenType TokenType) {
	f.t.Helper()
	for _, state := range f.states {
		if s, ok := state.(*tokenTypeIssuanceFailedState); ok && s.tokenType == tokenType {
			return
		}
	}
	f.t.Errorf("expected TokenTypeIssuanceFailed for %s, but it was not called", tokenType)
}

// methodNames returns just the method names from states for logging
func (f *fakeProbe) methodNames() []string {
	names := make([]string, len(f.states))
	for i, state := range f.states {
		names[i] = state.method()
	}
	return names
}

// stateMatcher is a function that matches against a probeState
type stateMatcher func(probeState) bool

// call creates a matcher that checks method name and optionally arguments
func call(method string, args ...any) stateMatcher {
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
			if expected != stateArgs[i] {
				return false
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
