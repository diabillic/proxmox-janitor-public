#!/usr/bin/env bash
# Runs INSIDE the runner LXC as root. Installs a GitHub Actions runner as a service.
# Env: GH_URL (https://github.com/owner/repo), REG_TOKEN (registration token, 1h TTL),
#      RUNNER_NAME (hostname), RUNNER_LABELS (proxmox,lan),
#      RUNNER_DIR (/opt/actions-runner; use one dir per repo to host several runners on one LXC)
# Re-running with a fresh REG_TOKEN re-registers (--replace). All instances share the
# `runner` user and its deploy key.
set -euo pipefail
: "${GH_URL:?}" "${REG_TOKEN:?}"
RUNNER_NAME=${RUNNER_NAME:-$(hostname)}
RUNNER_LABELS=${RUNNER_LABELS:-proxmox,lan}
DIR=${RUNNER_DIR:-/opt/actions-runner}

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl jq git rsync openssh-client python3 python3-venv ca-certificates >/dev/null

id runner >/dev/null 2>&1 || useradd --create-home --shell /bin/bash runner

# Deploy key the workflow uses to reach the agent LXC. Never leaves this box.
if [[ ! -f /home/runner/.ssh/id_ed25519 ]]; then
  install -d -m 700 -o runner -g runner /home/runner/.ssh
  runuser -u runner -- ssh-keygen -q -t ed25519 -N "" -C "deploy@$RUNNER_NAME" -f /home/runner/.ssh/id_ed25519
fi

if [[ ! -x "$DIR/config.sh" ]]; then
  ver=$(curl -fsSL https://api.github.com/repos/actions/runner/releases/latest | jq -r .tag_name | sed 's/^v//')
  install -d -o runner -g runner "$DIR"
  curl -fsSL "https://github.com/actions/runner/releases/download/v$ver/actions-runner-linux-x64-$ver.tar.gz" \
    | runuser -u runner -- tar -xz -C "$DIR"
  "$DIR/bin/installdependencies.sh" >/dev/null
fi

cd "$DIR"
if [[ -f .runner ]]; then
  # Re-registration: drop the local registration; --replace takes over the name on GitHub.
  ./svc.sh stop >/dev/null 2>&1 || true
  ./svc.sh uninstall >/dev/null 2>&1 || true
  rm -f .runner .credentials .credentials_rsaparams .service
fi
runuser -u runner -- ./config.sh --unattended --replace \
  --url "$GH_URL" --token "$REG_TOKEN" \
  --name "$RUNNER_NAME" --labels "$RUNNER_LABELS" --work _work
./svc.sh install runner >/dev/null
./svc.sh start >/dev/null
./svc.sh status | grep -E "Active:" || true

echo "DEPLOY_PUBKEY=$(cat /home/runner/.ssh/id_ed25519.pub)"
