# ─── Build Stage ─────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Copy go module files first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /trusted-dns \
    ./cmd/trusted-dns

# ─── Runtime Stage ───────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -S tdns && adduser -S tdns -G tdns

COPY --from=builder /trusted-dns /usr/local/bin/trusted-dns

# DNS port
EXPOSE 53/udp

# Health check: verify process is running
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD pgrep trusted-dns || exit 1

# Run as root to bind port 53 (required for UDP port < 1024)
# The application itself handles minimal privileges
USER root

ENTRYPOINT ["/usr/local/bin/trusted-dns"]
