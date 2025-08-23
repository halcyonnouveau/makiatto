FROM docker.io/rustlang/rust:nightly-slim AS builder

WORKDIR /app
RUN apt update && apt install -y \
    libssl-dev pkg-config sqlite3 \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY benches ./benches
COPY tests ./tests

RUN cargo build -p makiatto

FROM busybox:stable AS export
COPY --from=builder /app/target/debug/makiatto /makiatto
