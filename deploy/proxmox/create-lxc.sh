#!/usr/bin/env bash
# Runs ON the Proxmox host as root. Idempotent: an existing CTID is started, not recreated.
#   create-lxc.sh <ctid|auto> <hostname> <pubkey-file> [tags]
# Env: STORAGE (auto: first active rootdir storage), BRIDGE (vmbr0), VLAN, CORES (1),
#      MEMORY (512), DISK (4), TEMPLATE_STORAGE (local), DISTRO (debian-13)
# Prints "CTID=<id>" and "IP=<addr>" on the last two lines.
set -euo pipefail

CTID=${1:?ctid or auto}; NAME=${2:?hostname}; PUBKEY=${3:?pubkey file}; TAGS=${4:-}
BRIDGE=${BRIDGE:-vmbr0}; CORES=${CORES:-1}; MEMORY=${MEMORY:-512}; DISK=${DISK:-4}
TEMPLATE_STORAGE=${TEMPLATE_STORAGE:-local}; DISTRO=${DISTRO:-debian-13}

# Reuse a container that already has this hostname so re-runs never duplicate.
existing=$(pct list | awk -v n="$NAME" 'NR>1 && $NF==n {print $1; exit}')
if [[ -n "$existing" ]]; then
  CTID=$existing
  echo "CT $CTID ($NAME) already exists"
else
  [[ "$CTID" == auto ]] && CTID=$(pvesh get /cluster/nextid)
  STORAGE=${STORAGE:-$(pvesm status --content rootdir --enabled 1 | awk 'NR>1 && $3=="active" {print $1; exit}')}
  [[ -n "$STORAGE" ]] || { echo "no active rootdir storage found; set STORAGE" >&2; exit 1; }

  # The catalog lists other architectures too (arm64 sorts after amd64), so pin to the host's.
  arch=$(dpkg --print-architecture)
  pveam update >/dev/null
  tmpl=$(pveam available --section system | awk -v d="$DISTRO-standard" -v a="_$arch." '$2 ~ d && index($2, a) {print $2}' | sort -V | tail -1)
  [[ -n "$tmpl" ]] || { echo "no $DISTRO template available" >&2; exit 1; }
  pveam list "$TEMPLATE_STORAGE" | grep -q "$tmpl" || pveam download "$TEMPLATE_STORAGE" "$tmpl"

  net="name=eth0,bridge=$BRIDGE,ip=dhcp"
  [[ -n "${VLAN:-}" ]] && net+=",tag=$VLAN"

  echo "Creating CT $CTID ($NAME) from $tmpl on $STORAGE"
  pct create "$CTID" "$TEMPLATE_STORAGE:vztmpl/$tmpl" \
    --hostname "$NAME" --unprivileged 1 --features nesting=1 \
    --cores "$CORES" --memory "$MEMORY" --swap 256 \
    --rootfs "$STORAGE:$DISK" --net0 "$net" \
    --ssh-public-keys "$PUBKEY" --onboot 1 ${TAGS:+--tags "$TAGS"}
fi

pct status "$CTID" | grep -q running || pct start "$CTID"

# Wait for a DHCP lease.
for _ in $(seq 1 60); do
  ip=$(pct exec "$CTID" -- sh -c "ip -4 -o addr show eth0 | awk '{print \$4}' | cut -d/ -f1" 2>/dev/null || true)
  [[ -n "$ip" ]] && break
  sleep 2
done
[[ -n "${ip:-}" ]] || { echo "CT $CTID got no IPv4 address" >&2; exit 1; }

mac=$(pct config "$CTID" | sed -n 's/^net0:.*hwaddr=\([^,]*\).*/\1/p')
echo "MAC=$mac"
echo "CTID=$CTID"
echo "IP=$ip"
