FROM debian:bookworm-slim AS builder

WORKDIR /app
RUN apt update && apt install -y \
    curl build-essential \
    libssl-dev pkg-config sqlite3 \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly
ENV PATH="/root/.cargo/bin:${PATH}"

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY benches ./benches
COPY tests ./tests

RUN cargo build -p makiatto --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    sqlite3 ca-certificates libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --home-dir /var/makiatto --create-home --shell /bin/sh makiatto && \
    mkdir -p /var/makiatto/sites /etc/makiatto /usr/local/bin && \
    chown -R makiatto:makiatto /var/makiatto /etc/makiatto

COPY --from=builder /app/target/release/makiatto /usr/local/bin/makiatto

RUN chmod +x /usr/local/bin/makiatto && chown makiatto:makiatto /usr/local/bin/makiatto && chown makiatto:makiatto /etc/makiatto && chown -R makiatto:makiatto /var/makiatto
RUN echo 'net.ipv4.ip_unprivileged_port_start=0' >> /etc/sysctl.conf
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/makiatto

EXPOSE 80
VOLUME ["/etc/makiatto", "/var/makiatto"]

CMD ["su", "-s", "/bin/bash", "makiatto", "-c", "exec /usr/local/bin/makiatto --only axum,dns,corrosion"]
