FROM docker.io/rustlang/rust:nightly-slim AS builder

WORKDIR /app

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

RUN cargo build --release -p makiatto

FROM scratch AS export
COPY --from=builder /app/target/release/makiatto /makiatto
