#!/usr/bin/env bash
# Runs ON one Proxmox node as root (once per node; re-runnable). Installs the forced-command
# script and, through the cluster-shared authorized_keys, pins the agent's key to it.
#   install-node-access.sh <janitor-cmd file> <agent pubkey file> <agent IP>
# The key line is restricted: no shell, no forwarding, no pty, only from the agent's IP, and
# every login runs /usr/local/sbin/janitor-cmd, which accepts a fixed set of requests.
set -euo pipefail
CMD=${1:?janitor-cmd file}; PUB=${2:?agent public key file}; FROM=${3:?agent IP}

install -m 755 -o root -g root "$CMD" /usr/local/sbin/janitor-cmd

# /root/.ssh/authorized_keys links to /etc/pve/priv/authorized_keys on every node, so the
# key line only needs adding once; replacing by comment keeps re-runs idempotent.
KEYS=/etc/pve/priv/authorized_keys
key=$(awk '{print $1" "$2" "$3}' "$PUB")
comment=$(awk '{print $3}' "$PUB")
line="command=\"/usr/local/sbin/janitor-cmd\",restrict,from=\"$FROM\" $key"
if ! grep -qxF "$line" "$KEYS"; then
  # This file is root access to the whole cluster: back it up, and only write a result whose
  # line count is exactly what dropping the old agent line(s) and adding one should give.
  cp -p "$KEYS" "/root/authorized_keys.bak-proxmox-janitor-$(date +%Y%m%d%H%M%S)"
  orig=$(wc -l < "$KEYS"); drop=$(grep -c -F " $comment" "$KEYS" || true)
  tmp=$(mktemp)
  rc=0; grep -v -F " $comment" "$KEYS" > "$tmp" || rc=$?
  [[ $rc -le 1 ]] || { echo "grep failed ($rc); authorized_keys left unchanged" >&2; rm -f "$tmp"; exit 1; }
  echo "$line" >> "$tmp"
  [[ $(wc -l < "$tmp") -eq $((orig - drop + 1)) ]] || { echo "unexpected line count; unchanged" >&2; rm -f "$tmp"; exit 1; }
  cat "$tmp" > "$KEYS"  # /etc/pve is a cluster filesystem: write in place
  rm -f "$tmp"
  echo "authorized the agent key ($comment) from $FROM"
fi
echo "node $(hostname) ready"
