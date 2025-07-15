# Build stage
FROM rust:1.88-slim-trixie AS builder

RUN apt-get update && \
    apt-get install -y pkg-config libdbus-1-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cargo build --release

# Runtime stage
FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y libdbus-1-3 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/bitchat /app/
CMD ["./bitchat"]
