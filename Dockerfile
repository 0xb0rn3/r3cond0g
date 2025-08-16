# Multi-stage build for R3COND0G
FROM golang:1.21-alpine AS go-builder

# Install build dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libpcap-dev \
    linux-headers \
    git

# Set working directory
WORKDIR /build

# Copy Go source files
COPY main.go go.mod go.sum ./

# Download dependencies
RUN go mod download

# Build the binary
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o r3cond0g main.go

# Python stage
FROM python:3.11-alpine

# Metadata
LABEL maintainer="0xb0rn3 & 0xbv1"
LABEL version="3.0.0"
LABEL description="R3COND0G - Advanced Network Reconnaissance Platform"

# Install runtime dependencies
RUN apk add --no-cache \
    libpcap \
    tcpdump \
    nmap \
    nmap-scripts \
    graphviz \
    git \
    bash \
    curl \
    wget \
    bind-tools \
    iputils \
    net-tools \
    ca-certificates \
    shadow \
    sudo \
    libcap

# Create non-root user
RUN groupadd -r r3cond0g && \
    useradd -r -g r3cond0g -d /home/r3cond0g -s /bin/bash r3cond0g && \
    mkdir -p /home/r3cond0g && \
    chown -R r3cond0g:r3cond0g /home/r3cond0g

# Set working directory
WORKDIR /opt/r3cond0g

# Copy files from builder
COPY --from=go-builder /build/r3cond0g ./
COPY r3cond0g_controller.py ./
COPY run ./
COPY requirements.txt ./

# Create necessary directories
RUN mkdir -p probes reports cache && \
    chown -R r3cond0g:r3cond0g /opt/r3cond0g

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set capabilities on binary
RUN setcap cap_net_raw,cap_net_admin=eip ./r3cond0g

# Make scripts executable
RUN chmod +x run r3cond0g

# Switch to non-root user
USER r3cond0g

# Environment variables
ENV PATH="/opt/r3cond0g:${PATH}"
ENV PYTHONUNBUFFERED=1
ENV R3COND0G_HOME=/opt/r3cond0g

# Generate initial probe definitions
RUN python3 r3cond0g_controller.py --generate-probes || true

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["./r3cond0g", "--version"]

# Volume for persistent data
VOLUME ["/opt/r3cond0g/cache", "/opt/r3cond0g/reports"]

# Default command
ENTRYPOINT ["./run"]
CMD ["--interactive"]
