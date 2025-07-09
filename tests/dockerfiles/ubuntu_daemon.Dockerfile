ARG NODE_NAME="test-node"
ARG NETWORK_ADDRESS="10.44.44.1"
ARG PRIVATE_KEY="MMCuhphKHNySo6txZv30CEAGrWiM4RwiLQOo1FwEY0U="
ARG PUBLIC_KEY="h07faApSCGsmb37MUylyTq2bYcV1uRbQbAKnwz7xq2A="
ARG CORRO_BOOTSTRAP="[]"

FROM makiatto-builder:latest AS builder
FROM makiatto-test-ubuntu_base

ARG NETWORK_ADDRESS
ARG PRIVATE_KEY
ARG PUBLIC_KEY
ARG CORRO_BOOTSTRAP

RUN useradd --system --home-dir /var/makiatto --create-home --shell /bin/false makiatto && \
    mkdir -p /var/makiatto/sites /etc/makiatto /usr/local/bin

COPY <<EOF /etc/sudoers.d/makiatto
makiatto ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/sbin/setcap, /usr/bin/mkdir, /usr/bin/chown, /usr/bin/chmod, /usr/bin/ip, /usr/sbin/ip
EOF

COPY --from=builder /makiatto /usr/local/bin/makiatto
RUN chmod +x /usr/local/bin/makiatto && chown root:root /usr/local/bin/makiatto

RUN echo 'net.ipv4.ip_unprivileged_port_start=0' > /etc/sysctl.d/50-unprivileged-ports.conf

COPY <<EOF /etc/makiatto.toml
[node]
name = "${NODE_NAME}"
data_dir = "/var/makiatto"
is_nameserver = false

[network]
interface = "wawa0"
port = 51880
address = "${NETWORK_ADDRESS}"
private_key = "${PRIVATE_KEY}"
public_key = "${PUBLIC_KEY}"

[dns]
addr = "0.0.0.0:53"
geolite_path = "/var/makiatto/GeoLite2-City.mmdb"

[web]
http_addr = "0.0.0.0:80"
https_addr = "0.0.0.0:443"
static_dir = "/var/makiatto/sites"

[corrosion.admin]
path = "/var/makiatto/admin.sock"

[corrosion.db]
path = "/var/makiatto/cluster.db"

[corrosion.gossip]
addr = "0.0.0.0:8787"
external_addr = "${NETWORK_ADDRESS}:8787"
bootstrap = ${CORRO_BOOTSTRAP}
plaintext = true

[corrosion.api]
addr = "127.0.0.1:8181"
EOF

RUN chown makiatto:makiatto /etc/makiatto.toml

EXPOSE 22 53 80 443 8181 8787 51880

CMD ["/bin/bash", "-c", "/usr/sbin/sshd && exec su -s /bin/bash makiatto -c 'exec /usr/local/bin/makiatto'"]
