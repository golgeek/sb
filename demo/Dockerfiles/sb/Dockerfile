FROM golang:1.26-bookworm as builder
WORKDIR /app
ADD . /app
RUN go build -o sb

FROM debian:bookworm

# Install base required packages
RUN apt-get update && apt-get -yy install curl gnupg openssh-server libpam-google-authenticator sudo supervisor

# Supervisorctl conf
RUN mkdir /run/sshd
ADD demo/assets/supervisor.d/supervisord.conf /etc/supervisor/supervisord.conf

# SB binary and config
RUN mkdir /etc/sb
RUN mkdir /opt/sb
COPY --from=builder /app/sb /opt/sb/sb

# We setup the sb
RUN /opt/sb/sb setup

# Create the fist user
ADD demo/assets/ssh-keys/id_ed25519.pub /root/authorized_keys
RUN if ! id t800; then /opt/sb/sb account create --username t800 --public-key "$(cat /root/authorized_keys)"; fi

# Create the first group (the owners group, which has specific permissions in a specific sudoers file)
RUN if ! getent group bg_owners; then /opt/sb/sb group create --name owners --owner-account t800 --algo ed25519 --size 256; fi

RUN echo "Host examplevm\n    SendEnv LANG LC_*\n    HashKnownHosts yes\n    GSSAPIAuthentication yes\n    StrictHostKeyChecking no" >> /etc/ssh/ssh_config

WORKDIR /home/sb

EXPOSE 22

CMD ["/usr/bin/supervisord"]
