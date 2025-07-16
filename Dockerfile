# Multi-stage build for bitchat-terminal
FROM rust:1.85-bookworm as builder

# Accept git hash as build argument
ARG GIT_HASH=unknown

# Install build dependencies for Bluetooth Low Energy support
RUN apt-get update && apt-get install -y \
    pkg-config \
    libdbus-1-dev \
    libbluetooth-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Cargo files first for better caching
COPY Cargo.toml ./
COPY src/ ./src/

# Build with git hash as environment variable
RUN echo "Building with git hash: $GIT_HASH" && \
    GIT_HASH=$GIT_HASH cargo build --release

# Runtime stage with minimal dependencies
FROM debian:bookworm-slim

# Install runtime dependencies for Bluetooth
RUN apt-get update && apt-get install -y \
    bluetooth \
    bluez \
    bluez-tools \
    dbus \
    systemd \
    sudo \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for the application
RUN useradd -m -s /bin/bash bitchat && \
    usermod -a -G bluetooth bitchat

# Copy the built binary from builder stage
COPY --from=builder /app/target/release/bitchat /usr/local/bin/bitchat

# Set proper permissions for Bluetooth access
RUN setcap 'cap_net_raw,cap_net_admin+eip' /usr/local/bin/bitchat || true

# Create directory for app state
RUN mkdir -p /home/bitchat/.config/bitchat && \
    chown -R bitchat:bitchat /home/bitchat/.config

# Expose any ports if needed (not typically required for BLE mesh)
# EXPOSE 8080

# Set environment variables
ENV RUST_LOG=info
ENV USER=bitchat

# Switch to non-root user
#USER bitchat
WORKDIR /home/bitchat

# Health check to verify the binary works
#HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
#    CMD /usr/local/bin/bitchat --help || exit 1

# Entry point
ENTRYPOINT ["/usr/local/bin/bitchat"]
CMD []
