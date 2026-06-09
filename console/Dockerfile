# Multi-stage build for Kyanos Console (gRPC + HTTP backend + Vue frontend)
#
# Stage 1: Build the Vue frontend
# Stage 2: Build the Go binary (with embedded frontend assets)
# Stage 3: Minimal runtime image

# ── Stage 1: Frontend ──────────────────────────────────────────────
FROM node:20-bookworm-slim AS frontend-builder

WORKDIR /src/frontend

# Copy package files first for layer caching
COPY console/frontend/package.json console/frontend/package-lock.json* ./
RUN npm ci --prefer-offline 2>/dev/null || npm install

# Copy frontend source and build
COPY console/frontend/ ./
RUN npm run build

# ── Stage 2: Go backend ────────────────────────────────────────────
FROM golang:1.24-bookworm AS builder

WORKDIR /src

# Copy go module files first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy full source tree
COPY . .

# Copy built frontend assets into console/frontend/dist
COPY --from=frontend-builder /src/frontend/dist ./console/frontend/dist

# Build the kyanos binary (static linked)
ARG VERSION=dev
ARG COMMIT_ID=unknown
ARG BUILD_TIME=unknown

RUN CGO_ENABLED=1 CGO_LDFLAGS="-Xlinker -rpath=. -static" \
    go build -tags static \
    -ldflags "-s -w \
      -X kyanos/version.Version=${VERSION} \
      -X kyanos/version.CommitID=${COMMIT_ID} \
      -X kyanos/version.BuildTime=${BUILD_TIME} \
      -linkmode external -extldflags '-static'" \
    -o /out/kyanos .

# ── Stage 3: Runtime ───────────────────────────────────────────────
FROM ubuntu:22.04 AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/kyanos-console

# Copy the compiled binary
COPY --from=builder /out/kyanos ./kyanos

# Copy frontend dist for static file serving
COPY --from=frontend-builder /src/frontend/dist ./frontend/dist

# Ensure binary is executable
RUN chmod +x ./kyanos

# Create storage directory (for optional persistence)
RUN mkdir -p /var/lib/kyanos-console

EXPOSE 9090 8080

ENTRYPOINT ["./kyanos"]
CMD ["console", "--grpc-addr", ":9090", "--http-addr", ":8080"]
