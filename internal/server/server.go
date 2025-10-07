package server

import (
	"context"
	"fmt"
	"net"
	"net/http"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	parsecv1 "github.com/alechenninger/parsec/api/gen/parsec/v1"
)

// Server manages the gRPC and HTTP servers
type Server struct {
	grpcServer *grpc.Server
	httpServer *http.Server
	
	grpcPort int
	httpPort int
}

// Config contains server configuration
type Config struct {
	GRPCPort int
	HTTPPort int
}

// New creates a new server with the given configuration
func New(cfg Config) *Server {
	return &Server{
		grpcPort: cfg.GRPCPort,
		httpPort: cfg.HTTPPort,
	}
}

// Start starts both the gRPC and HTTP servers
func (s *Server) Start(ctx context.Context) error {
	// Create gRPC server
	s.grpcServer = grpc.NewServer()
	
	// Register services
	authv3.RegisterAuthorizationServer(s.grpcServer, NewAuthzServer())
	parsecv1.RegisterTokenExchangeServer(s.grpcServer, NewExchangeServer())
	
	// Start gRPC server
	grpcListener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.grpcPort))
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC port %d: %w", s.grpcPort, err)
	}
	
	go func() {
		fmt.Printf("gRPC server listening on :%d\n", s.grpcPort)
		if err := s.grpcServer.Serve(grpcListener); err != nil {
			fmt.Printf("gRPC server error: %v\n", err)
		}
	}()
	
	// Create HTTP server with grpc-gateway
	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	
	// Register HTTP handlers (transcoding from gRPC)
	endpoint := fmt.Sprintf("localhost:%d", s.grpcPort)
	if err := parsecv1.RegisterTokenExchangeHandlerFromEndpoint(ctx, mux, endpoint, opts); err != nil {
		return fmt.Errorf("failed to register token exchange handler: %w", err)
	}
	
	// Start HTTP server
	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.httpPort),
		Handler: mux,
	}
	
	go func() {
		fmt.Printf("HTTP server (grpc-gateway) listening on :%d\n", s.httpPort)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("HTTP server error: %v\n", err)
		}
	}()
	
	return nil
}

// Stop gracefully stops both servers
func (s *Server) Stop(ctx context.Context) error {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
	
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	
	return nil
}

