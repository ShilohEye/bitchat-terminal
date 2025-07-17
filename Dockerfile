FROM rust:1.88-slim-trixie AS builder

RUN apt-get update && \
    apt-get install -y pkg-config libdbus-1-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app


# Set working directory
WORKDIR /app

# Copy only Cargo.toml and Cargo.lock first for dependency caching
COPY Cargo.toml ./

# Create a dummy main.rs to satisfy cargo build for dependency compilation
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies only (this layer will be cached unless Cargo.toml changes)
RUN cargo build && rm -rf src/

# Copy the actual source code
COPY src/ ./src/

ARG GIT_HASH
# Build the actual application (only this layer rebuilds when code changes)
RUN    GIT_HASH=$GIT_HASH cargo build
 

# Runtime stage
FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y libdbus-1-3 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/debug/bitchat /app/
#COPY --from=builder /app/target/release/bitchat /app/
CMD ["./bitchat", "--debug-full"]
