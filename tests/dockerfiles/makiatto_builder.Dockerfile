FROM docker.io/rustlang/rust:nightly-slim AS builder

WORKDIR /app
RUN apt update && apt install -y \
    libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates/makiatto ./crates/makiatto

RUN mkdir tests
COPY <<EOF tests/Cargo.toml
[package]
name = "integration-tests"
version = "0.0.0"
edition = "2024"

[[bin]]
name = "docker-test-mock"
path = "src/main.rs"
EOF

RUN mkdir tests/src && echo 'fn main() {}' > tests/src/main.rs
RUN cargo build -p makiatto

FROM busybox:stable AS export
COPY --from=builder /app/target/debug/makiatto /makiatto
