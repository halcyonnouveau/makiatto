FROM docker.io/ubuntu:24.04

RUN apt update && apt install -y \
    openssh-server sudo iproute2 wireguard ca-certificates libcap2-bin curl sqlite3 resolvconf \
    && rm -rf /var/lib/apt/lists/*

RUN touch /run/.containerenv
RUN echo "root:wa2000" | chpasswd
RUN echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config

RUN mkdir -p /var/run/sshd /run/sshd /root/.ssh
COPY tests/fixtures/.ssh/id_ed25519.pub /root/.ssh/authorized_keys
RUN chmod 600 /root/.ssh/authorized_keys && chmod 700 /root/.ssh

CMD ["/usr/sbin/sshd", "-D"]
