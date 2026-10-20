#!/bin/sh
# Runs only inside the new dedicated Ubuntu guest, through cloud-init.
set -eu
umask 077
test "$(id -u)" = 0
. /etc/os-release
test "$ID" = ubuntu
test "$VERSION_CODENAME" = noble
test "$(dpkg --print-architecture)" = amd64

# The image is pinned, but security updates and current stable signed packages
# are intentional. Record the resolved package versions for this installation.
install -d -m 0755 /etc/apt/keyrings
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
fingerprint=$(gpg --batch --show-keys --with-colons /etc/apt/keyrings/docker.asc | awk -F: '$1 == "fpr" { print $10; exit }')
test "$fingerprint" = 9DC858229FC7DD38854AE2D88D81803C0EBFCD88
chmod 0644 /etc/apt/keyrings/docker.asc
cat > /etc/apt/sources.list.d/docker.sources <<'EOF'
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: noble
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/docker.asc
EOF

# Docker must use iptables for the owned DOCKER-USER ingress rules below.
# Block service startup during installation until the firewall drop-in exists.
systemctl mask docker.service docker.socket
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
docker_version=$(dpkg-query --show --showformat='${Version}' docker-ce)
dpkg --compare-versions "$docker_version" ge '5:28.0.0'
install -d -m 0755 /etc/docker /etc/systemd/system/docker.service.d
printf '%s\n' '{"iptables":true,"ip6tables":true,"live-restore":true,"log-driver":"local","log-opts":{"max-size":"10m","max-file":"3"}}' > /etc/docker/daemon.json
cat > /etc/systemd/system/docker.service.d/covee-firewall.conf <<'EOF'
[Unit]
Requires=covee-guest-firewall.service
After=covee-guest-firewall.service network-online.target
Wants=network-online.target

[Service]
ExecStartPre=/usr/local/sbin/covee-guest-firewall docker
ExecStartPost=/usr/local/sbin/covee-guest-firewall verify
EOF
systemctl daemon-reload
systemctl enable --now covee-guest-firewall.service
systemctl unmask docker.service docker.socket
systemctl enable --now docker.service
docker compose version
compose_version=$(docker compose version --short | sed 's/^v//')
dpkg --compare-versions "$compose_version" ge '2.24.4'
dpkg-query --show --showformat='${Package}\t${Version}\n' > /var/log/covee-package-versions.tsv
install -d -m 0700 -o covee -g covee /srv/covee
install -d -m 0750 -o covee -g covee /opt/covee
