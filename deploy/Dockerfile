# Multi-stage build for Kyanos GNSS diagnostic agent
# Stage 1: Build the eBPF programs and Go binary
FROM golang:1.24-bookworm AS builder

# Install BPF build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    gcc \
    make \
    git \
    pkg-config \
    libelf-dev \
    linux-headers-generic \
    flex \
    bison \
    rsync \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy go module files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy full source tree (includes bpf/, libbpf/, vmlinux/, etc.)
COPY . .

# Initialize submodules if not already present
RUN git submodule update --init --recursive 2>/dev/null || true

# Build BPF programs and generate Go bindings
RUN make build-bpf

# Generate BTF data for older kernels (x86_64 target for TKE)
RUN make btfgen BUILD_ARCH=x86_64 ARCH_BPF_NAME=x86

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

# Stage 2: Minimal runtime image
FROM ubuntu:22.04 AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libelf1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/kyanos

# Copy the compiled binary
COPY --from=builder /out/kyanos ./kyanos

# Copy BTF files for kernels without built-in BTF support
COPY --from=builder /src/.output/btf ./btf/

# Ensure binary is executable
RUN chmod +x ./kyanos

ENTRYPOINT ["./kyanos"]
CMD ["watch", "ntrip", "--diag"]
