package service

// TokenType identifies the type of token being issued
type TokenType string

const (
	// TokenTypeTransactionToken is a transaction token per draft-ietf-oauth-transaction-tokens
	TokenTypeTransactionToken TokenType = "urn:ietf:params:oauth:token-type:txn_token"

	// TokenTypeAccessToken is a standard OAuth2 access token
	TokenTypeAccessToken TokenType = "urn:ietf:params:oauth:token-type:access_token"

	// TokenTypeJWT is a JWT token (generic)
	TokenTypeJWT TokenType = "urn:ietf:params:oauth:token-type:jwt"

	// TokenTypeRHIdentity is a Red Hat identity token (x-rh-identity format)
	TokenTypeRHIdentity TokenType = "urn:redhat:params:oauth:token-type:rh-identity"
)

// Registry manages multiple issuers by token type
type Registry interface {
	// GetIssuer returns an issuer for the specified token type
	GetIssuer(tokenType TokenType) (Issuer, error)

	// ListTokenTypes returns all registered token types
	ListTokenTypes() []TokenType
}
