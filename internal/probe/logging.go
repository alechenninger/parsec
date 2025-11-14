package probe

import (
	"context"
	"log/slog"

	"github.com/alechenninger/parsec/internal/service"
	"github.com/alechenninger/parsec/internal/trust"
)

// loggingObserver creates request-scoped logging probes
type loggingObserver struct {
	logger *slog.Logger
}

// NewLoggingTokenServiceObserver creates an observer that logs token issuance events
// using structured logging with slog.
func NewLoggingTokenServiceObserver(logger *slog.Logger) service.TokenServiceObserver {
	if logger == nil {
		logger = slog.Default()
	}
	return &loggingObserver{
		logger: logger,
	}
}

func (o *loggingObserver) TokenIssuanceStarted(
	ctx context.Context,
	subject *trust.Result,
	actor *trust.Result,
	scope string,
	tokenTypes []service.TokenType,
) (context.Context, service.TokenIssuanceProbe) {
	attrs := []slog.Attr{
		slog.String("scope", scope),
		slog.Any("token_types", tokenTypes),
	}

	if subject != nil {
		attrs = append(attrs,
			slog.String("subject_id", subject.Subject),
			slog.String("subject_trust_domain", subject.TrustDomain),
		)
	}

	if actor != nil {
		attrs = append(attrs,
			slog.String("actor_id", actor.Subject),
			slog.String("actor_trust_domain", actor.TrustDomain),
		)
	}

	o.logger.LogAttrs(ctx, slog.LevelDebug, "Starting token issuance", attrs...)

	// Return a request-scoped probe that captures the context
	return ctx, &loggingProbe{
		ctx:    ctx,
		logger: o.logger,
	}
}

// loggingProbe is a request-scoped probe that logs events for a single token issuance
type loggingProbe struct {
	ctx    context.Context
	logger *slog.Logger
}

func (p *loggingProbe) TokenTypeIssuanceStarted(tokenType service.TokenType) {
	p.logger.LogAttrs(p.ctx, slog.LevelDebug,
		"Issuing token",
		slog.String("token_type", string(tokenType)),
	)
}

func (p *loggingProbe) TokenTypeIssuanceSucceeded(tokenType service.TokenType, token *service.Token) {
	attrs := []slog.Attr{
		slog.String("token_type", string(tokenType)),
	}

	if token != nil {
		attrs = append(attrs,
			slog.Time("issued_at", token.IssuedAt),
			slog.Time("expires_at", token.ExpiresAt),
		)
	}

	p.logger.LogAttrs(p.ctx, slog.LevelDebug, "Token issued successfully", attrs...)
}

func (p *loggingProbe) TokenTypeIssuanceFailed(tokenType service.TokenType, err error) {
	p.logger.LogAttrs(p.ctx, slog.LevelError,
		"Token issuance failed",
		slog.String("token_type", string(tokenType)),
		slog.String("error", err.Error()),
	)
}

func (p *loggingProbe) IssuerNotFound(tokenType service.TokenType, err error) {
	p.logger.LogAttrs(p.ctx, slog.LevelError,
		"No issuer found for token type",
		slog.String("token_type", string(tokenType)),
		slog.String("error", err.Error()),
	)
}

func (p *loggingProbe) End() {
	p.logger.LogAttrs(p.ctx, slog.LevelDebug, "Token issuance completed")
}
