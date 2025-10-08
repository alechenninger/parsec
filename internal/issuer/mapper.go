package issuer

import (
	"context"

	"github.com/alechenninger/parsec/internal/claims"
	"github.com/alechenninger/parsec/internal/trust"
)

// ClaimMapper transforms inputs into claims for the token
// Claim mappers implement policy logic - what information to include in tokens
type ClaimMapper interface {
	// Map produces claims based on the input
	// Returns nil if the mapper has no claims to contribute
	Map(ctx context.Context, input *MapperInput) (claims.Claims, error)
}

// MapperInput contains all inputs available to a claim mapper
type MapperInput struct {
	// Subject identity (attested claims from validated credential)
	Subject *trust.Result

	// Workload identity (attested claims from workload credential)
	Workload *trust.Result

	// RequestAttributes contains information about the request
	RequestAttributes *RequestAttributes

	// DataSources contains data fetched from registered data sources
	// Map key is the data source name
	DataSources map[string]map[string]any
}

// ClaimMapperRegistry manages claim mappers for different claim types
type ClaimMapperRegistry struct {
	// TransactionContextMappers build the "tctx" claim
	TransactionContextMappers []ClaimMapper

	// RequestContextMappers build the "req_ctx" claim
	RequestContextMappers []ClaimMapper
}

// NewClaimMapperRegistry creates a new claim mapper registry
func NewClaimMapperRegistry() *ClaimMapperRegistry {
	return &ClaimMapperRegistry{
		TransactionContextMappers: make([]ClaimMapper, 0),
		RequestContextMappers:     make([]ClaimMapper, 0),
	}
}

// RegisterTransactionContext adds a mapper for transaction context claims
func (r *ClaimMapperRegistry) RegisterTransactionContext(mapper ClaimMapper) {
	r.TransactionContextMappers = append(r.TransactionContextMappers, mapper)
}

// RegisterRequestContext adds a mapper for request context claims
func (r *ClaimMapperRegistry) RegisterRequestContext(mapper ClaimMapper) {
	r.RequestContextMappers = append(r.RequestContextMappers, mapper)
}

// MapTransactionContext applies all transaction context mappers
func (r *ClaimMapperRegistry) MapTransactionContext(ctx context.Context, input *MapperInput) (claims.Claims, error) {
	result := make(claims.Claims)

	for _, mapper := range r.TransactionContextMappers {
		mapperClaims, err := mapper.Map(ctx, input)
		if err != nil {
			return nil, err
		}
		result.Merge(mapperClaims)
	}

	return result, nil
}

// MapRequestContext applies all request context mappers
func (r *ClaimMapperRegistry) MapRequestContext(ctx context.Context, input *MapperInput) (claims.Claims, error) {
	result := make(claims.Claims)

	for _, mapper := range r.RequestContextMappers {
		mapperClaims, err := mapper.Map(ctx, input)
		if err != nil {
			return nil, err
		}
		result.Merge(mapperClaims)
	}

	return result, nil
}
