FROM rust:1.85 as builder
WORKDIR /app

# Pre-cache deps
COPY Cargo.toml Cargo.toml
COPY discovery/Cargo.toml discovery/Cargo.toml
COPY node/Cargo.toml node/Cargo.toml
RUN mkdir -p discovery/src node/src \
 && echo "fn main(){}" > discovery/src/main.rs \
 && echo "fn main(){}" > node/src/main.rs \
 && cargo build -p discovery -p node --release || true

# Build
COPY . .
RUN cargo build -p discovery --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/discovery /usr/local/bin/discovery
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/discovery"]


