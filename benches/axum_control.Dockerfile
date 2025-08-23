FROM debian:bookworm-slim AS builder

WORKDIR /app
RUN apt update && apt install -y \
    curl build-essential \
    libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly
ENV PATH="/root/.cargo/bin:${PATH}"

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY benches ./benches
COPY tests ./tests

RUN cargo build -p axum-control --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --home-dir /var/axum-control --create-home --shell /bin/sh axum-control && \
    mkdir -p /var/axum-control/files /usr/local/bin && \
    chown -R axum-control:axum-control /var/axum-control

COPY --from=builder /app/target/release/axum-control /usr/local/bin/axum-control

RUN chmod +x /usr/local/bin/axum-control && chown axum-control:axum-control /usr/local/bin/axum-control
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/axum-control

EXPOSE 80
VOLUME ["/var/axum-control/files"]

USER axum-control
CMD ["/usr/local/bin/axum-control"]
