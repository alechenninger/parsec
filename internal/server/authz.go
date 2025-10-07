package server

import (
	"context"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
)

// AuthzServer implements Envoy's ext_authz Authorization service
type AuthzServer struct {
	authv3.UnimplementedAuthorizationServer
}

// NewAuthzServer creates a new ext_authz server
func NewAuthzServer() *AuthzServer {
	return &AuthzServer{}
}

// Check implements the ext_authz check endpoint
func (s *AuthzServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	// TODO: Implement authorization logic
	// 1. Extract credentials from request (Authorization header, mTLS cert, etc.)
	// 2. Validate credentials against trust store
	// 3. Issue transaction token
	// 4. Return OK with transaction token in header

	// For now, return a simple OK response with a placeholder transaction token
	return &authv3.CheckResponse{
		Status: &status.Status{
			Code: int32(codes.OK),
		},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:   "Transaction-Token",
							Value: "TODO-implement-token-generation",
						},
					},
				},
			},
		},
	}, nil
}
