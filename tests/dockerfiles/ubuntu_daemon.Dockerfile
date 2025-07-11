FROM makiatto-builder:latest AS builder
FROM makiatto-test-ubuntu_base

ARG NODE_NAME
ARG CORRO_BOOTSTRAP

RUN useradd --system --home-dir /var/makiatto --create-home --shell /bin/false makiatto && \
    mkdir -p /var/makiatto/sites /etc/makiatto /usr/local/bin

COPY <<EOF /etc/sudoers.d/makiatto
makiatto ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/sbin/setcap, /usr/bin/mkdir, /usr/bin/chown, /usr/bin/chmod, /usr/bin/ip, /usr/sbin/ip
EOF

COPY --from=builder /makiatto /usr/local/bin/makiatto
RUN chmod +x /usr/local/bin/makiatto && chown makiatto:makiatto /usr/local/bin/makiatto
RUN echo 'net.ipv4.ip_unprivileged_port_start=0' > /etc/sysctl.d/50-unprivileged-ports.conf

COPY tests/fixtures/makiatto.toml /etc/makiatto/makiatto.toml
RUN chown makiatto:makiatto /etc/makiatto/makiatto.toml

EXPOSE 22 53 80 443 8181 8787 51880
VOLUME ["/etc/makiatto"]

CMD ["/bin/bash", "-c", "/usr/sbin/sshd && exec su -s /bin/bash makiatto -c 'exec /usr/local/bin/makiatto'"]
