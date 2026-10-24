#!/usr/bin/env bash
# Runs INSIDE the agent LXC as root. Prepares it to receive deploys from the runner and gives
# the service account its own SSH key for the Proxmox nodes.
# Env: DEPLOY_PUBKEY (runner's deploy key), INSTALLER (path to pushed proxmox-janitor-install)
# Prints AGENT_PUBKEY=<the service account's public key> on the last line.
#
# The `deploy` user can only stage files and run the root-owned installer via sudo;
# the installer writes the systemd unit itself, so a deploy can't change what runs as root.
set -euo pipefail
: "${DEPLOY_PUBKEY:?}" "${INSTALLER:?}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv rsync sudo openssh-server openssh-client tzdata ca-certificates >/dev/null
systemctl enable --now ssh >/dev/null

id proxmox-janitor >/dev/null 2>&1 || useradd --system --home-dir /var/lib/proxmox-janitor --shell /usr/sbin/nologin proxmox-janitor
id deploy >/dev/null 2>&1 || useradd --create-home --shell /bin/bash deploy

install -d -m 700 -o deploy -g deploy /home/deploy/.ssh /home/deploy/staging
echo "$DEPLOY_PUBKEY" > /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys
chmod 600 /home/deploy/.ssh/authorized_keys

# The key the nodes pin to their forced command (node/janitor-cmd). Never leaves this box.
install -d -m 755 -o proxmox-janitor -g proxmox-janitor /var/lib/proxmox-janitor
install -d -m 700 -o proxmox-janitor -g proxmox-janitor /var/lib/proxmox-janitor/.ssh
if [[ ! -f /var/lib/proxmox-janitor/.ssh/id_ed25519 ]]; then
  runuser -u proxmox-janitor -- ssh-keygen -q -t ed25519 -N "" -C "proxmox-janitor@$(hostname)" -f /var/lib/proxmox-janitor/.ssh/id_ed25519
fi

install -d -m 755 /opt/proxmox-janitor
install -d -m 750 -g proxmox-janitor /etc/proxmox-janitor
install -m 750 -o root -g root "$INSTALLER" /usr/local/sbin/proxmox-janitor-install

echo 'deploy ALL=(root) NOPASSWD: /usr/local/sbin/proxmox-janitor-install' > /etc/sudoers.d/proxmox-janitor-deploy
chmod 440 /etc/sudoers.d/proxmox-janitor-deploy
visudo -cf /etc/sudoers.d/proxmox-janitor-deploy >/dev/null

echo "agent LXC ready"
echo "AGENT_PUBKEY=$(cat /var/lib/proxmox-janitor/.ssh/id_ed25519.pub)"
