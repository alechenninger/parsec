FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY api/ ./api/

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o parsec ./cmd/parsec

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests (needed for JWKS fetching)
RUN apk --no-cache add ca-certificates

# Create non-root user for OpenShift compatibility
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

WORKDIR /home/appuser

# Copy the binary from builder stage
COPY --from=builder /app/parsec .

# Copy default configuration (can be overridden with volume mount)
COPY configs/ ./configs/

# Set ownership and permissions
RUN chown -R 1001:1001 /home/appuser && \
    chmod +x /home/appuser/parsec

USER 1001

# Expose gRPC port (default parsec port)
EXPOSE 9090

# Expose HTTP gateway port (if enabled)
EXPOSE 8080

# Default command runs the serve subcommand
CMD ["./parsec", "serve"]
