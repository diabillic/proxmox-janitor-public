#!/usr/bin/env bash
# Runner LXCs for low-priority work, one per node. Run from an admin workstation with root SSH
# to the nodes and gh authenticated with admin on the repos. Re-runnable: an existing LXC is
# reused and its runner instances re-registered.
#
# The runners carry only `low-priority` and their node's name as labels, so they never match a
# job that asks for anything else (e.g. [self-hosted, proxmox]). A job opts in with
#   runs-on: [self-hosted, low-priority]          # or [self-hosted, low-priority, <node>]
# Avoid bare `runs-on: self-hosted`: any runner in the repo can take that.
#
# Env: NODES (SSH aliases or addresses of the low-priority nodes; required),
#      REPOS (owner/name ..., default this repo; GitHub runners are per repo on personal
#      accounts, so each repo gets its own instance on every runner LXC),
#      LABELS (low-priority), TAGS (Proxmox tags, "ci;low-priority"), RUNNER_PREFIX (gh-runner),
#      ADMIN_PUBKEY, GH_BIN, plus STORAGE / BRIDGE / VLAN / TEMPLATE_STORAGE / DISTRO for create-lxc.sh.
set -euo pipefail

: "${NODES:?set NODES='node-a node-b' (SSH aliases or addresses of the low-priority nodes)}"
GH=${GH_BIN:-gh}
HERE=$(cd "$(dirname "$0")" && pwd)
REPOS=${REPOS:-$(cd "$HERE" && "$GH" repo view --json nameWithOwner --jq .nameWithOwner)}
LABELS=${LABELS:-low-priority}
TAGS=${TAGS:-ci;low-priority}
PREFIX=${RUNNER_PREFIX:-gh-runner}
ADMIN_PUBKEY=${ADMIN_PUBKEY:-$HOME/.ssh/id_ed25519.pub}
REMOTE=/root/low-priority-runners

passthru=""
for v in STORAGE BRIDGE VLAN TEMPLATE_STORAGE DISTRO; do
  [[ -n "${!v:-}" ]] && passthru+="$v=${!v} "
done

kv() { sed -n "s/^$1=//p" <<<"$2" | tail -1; }

summary=""
for host in $NODES; do
  node=$(ssh "$host" hostname)
  name="$PREFIX-$node"
  echo "==> $node: runner LXC $name"
  ssh "$host" "mkdir -p $REMOTE"
  scp -q "$HERE/proxmox/create-lxc.sh" "$HERE/lxc/bootstrap-runner.sh" "$host:$REMOTE/"
  scp -q "$ADMIN_PUBKEY" "$host:$REMOTE/admin.pub"
  out=$(ssh "$host" "$passthru MEMORY=2048 CORES=2 DISK=12 bash $REMOTE/create-lxc.sh auto $name $REMOTE/admin.pub '$TAGS'")
  echo "$out"
  ct=$(kv CTID "$out"); ip=$(kv IP "$out")
  ssh "$host" "pct push $ct $REMOTE/bootstrap-runner.sh /root/bootstrap-runner.sh"

  for repo in $REPOS; do
    echo "==> $node: registering $name for $repo"
    token=$("$GH" api -X POST "repos/$repo/actions/runners/registration-token" --jq .token)
    ssh "$host" "pct exec $ct -- env LC_ALL=C.UTF-8 GH_URL=https://github.com/$repo REG_TOKEN=$token \
      RUNNER_NAME=$name RUNNER_LABELS=$LABELS,$node RUNNER_DIR=/opt/actions-runner-${repo#*/} \
      bash /root/bootstrap-runner.sh" | grep -v '^DEPLOY_PUBKEY='
  done
  summary+="  CT $ct  $name  $ip  labels $LABELS,$node"$'\n'
done

printf '\nDone.\n%s' "$summary"
echo "Jobs opt in with runs-on: [self-hosted, ${LABELS%%,*}]"
