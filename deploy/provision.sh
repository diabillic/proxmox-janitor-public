#!/usr/bin/env bash
# One-time (re-runnable) provisioning of the janitor as a container on a Docker host. Run from an
# admin workstation with root SSH to every Proxmox node and gh authenticated with admin on this
# repo. The Docker hosts must already be prepared with the dockerfile-agent repository's
# deploy/docker-host.sh (agent-deploy, agent-redeploy, the deploy user and its runner).
#
# It gives the janitor its SSH key (created inside its state volume, it never leaves the host),
# pins that key to node/janitor-cmd on every node and to agent-redeploy-ssh on every Docker host,
# writes the janitor's known_hosts, registers a runner instance for this repo, and sets the
# repository variables the deploy workflow needs.
#
# Env: NODES        "name=ssh-alias-or-address ..." for every Proxmox node (required)
#      JANITOR_VM   "<node>:<vmid>" of the Docker VM the janitor runs on (required)
#      DOCKER_VMS   "<node>:<vmid> ..." Docker VMs whose agent containers it rebuilds (default JANITOR_VM)
#      RUNNER       "<node>:<ctid>" of the runner LXC that deploys to JANITOR_VM (required)
#      ADMIN_KEY    SSH key the Docker VMs accept for root, e.g. ~/.ssh/id_ed25519 (cloud-init)
#      PRIORITY     high (default) or low; BUS_HOST_PORT for the agent bus; GH_REPO, GH_BIN
# Node names are SSH aliases or addresses for root on that node.
set -euo pipefail

: "${NODES:?set NODES='pve1=pve1.lan pve2=pve2.lan ...'}" "${JANITOR_VM:?set JANITOR_VM=<node>:<vmid>}"
: "${RUNNER:?set RUNNER=<node>:<runner ctid>}"
GH=${GH_BIN:-gh}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=${GH_REPO:-$(cd "$HERE" && "$GH" repo view --json nameWithOwner --jq .nameWithOwner)}
DOCKER_VMS=${DOCKER_VMS:-$JANITOR_VM}
VOLUME=proxmox-janitor-data
read -r -a node_list <<<"$NODES"
declare -A ssh_of
for entry in "${node_list[@]}"; do ssh_of[${entry%%=*}]=${entry#*=}; done
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
: > "$tmp/vm_known_hosts"
opts=(-o UserKnownHostsFile="$tmp/vm_known_hosts" -o StrictHostKeyChecking=yes)
[[ -n "${ADMIN_KEY:-}" ]] && opts+=(-i "$ADMIN_KEY" -o IdentitiesOnly=yes)

# "<ip> <name> <ssh host key>" of a VM, read through the QEMU guest agent (nothing trusted on first use).
vm_info() {
  local node=${1%%:*} vmid=${1#*:}
  ssh "${ssh_of[$node]:-$node}" python3 - "$vmid" <<'EOF'
import json, subprocess, sys
vmid = sys.argv[1]
def run(*a):
    return subprocess.run(a, capture_output=True, text=True).stdout
ip = next((a["ip-address"] for i in json.loads(run("qm", "guest", "cmd", vmid, "network-get-interfaces") or "[]")
           if i["name"] != "lo" and not i["name"].startswith(("docker", "br-", "veth"))
           for a in i.get("ip-addresses", []) if a["ip-address-type"] == "ipv4"), "")
name = next((l.split(": ", 1)[1] for l in run("qm", "config", vmid).splitlines() if l.startswith("name: ")), vmid)
out = json.loads(run("qm", "guest", "exec", vmid, "--", "cat", "/etc/ssh/ssh_host_ed25519_key.pub") or "{}")
print(ip, name, " ".join((out.get("out-data") or "").split()[:2]))
EOF
}

read -r JIP JNAME JKEY <<<"$(vm_info "$JANITOR_VM")"
[[ -n "$JIP" && "$JKEY" == ssh-ed25519\ * ]] || { echo "couldn't read $JANITOR_VM's address and host key" >&2; exit 1; }
echo "$JIP $JKEY" >> "$tmp/vm_known_hosts"
vm() { ssh "${opts[@]}" "root@$1" "${@:2}"; }

echo "==> Janitor key in volume $VOLUME on $JNAME ($JIP)"
PUB=$(vm "$JIP" "set -e
docker volume create $VOLUME >/dev/null
if ! docker run --rm -v $VOLUME:/d busybox test -f /d/.ssh/id_ed25519; then
  t=\$(mktemp -d)
  ssh-keygen -q -t ed25519 -N '' -C 'proxmox-janitor@$JNAME' -f \$t/id_ed25519
  tar -C \$t -cf - id_ed25519 id_ed25519.pub | docker run --rm -i -v $VOLUME:/d busybox sh -c \
    'mkdir -p /d/.ssh && tar -C /d/.ssh -xf - && chmod 700 /d/.ssh && chmod 600 /d/.ssh/id_ed25519'
  rm -rf \$t
fi
docker run --rm -v $VOLUME:/d busybox cat /d/.ssh/id_ed25519.pub")
[[ "$PUB" == ssh-ed25519\ * ]] || { echo "no janitor key" >&2; exit 1; }
echo "$PUB" > "$tmp/janitor.pub"

echo "==> Node access (forced command + key pinned to $JIP) and the nodes' host keys"
: > "$tmp/known_hosts"
first=${node_list[0]#*=}
cluster_ips=$(ssh "$first" "pvesh get /cluster/status --output-format json | python3 -c 'import json,sys; [print(n[\"name\"]+\"=\"+n[\"ip\"]) for n in json.load(sys.stdin) if n[\"type\"]==\"node\"]'")
pve_nodes=""
for entry in "${node_list[@]}"; do
  name=${entry%%=*}; host=${entry#*=}
  addr=$(sed -n "s/^$name=//p" <<<"$cluster_ips")
  [[ -n "$addr" ]] || { echo "node $name is not in the cluster" >&2; exit 1; }
  scp -q "$HERE/../node/janitor-cmd" "$HERE/proxmox/install-node-access.sh" "$tmp/janitor.pub" "$host:/tmp/"
  ssh "$host" "bash /tmp/install-node-access.sh /tmp/janitor-cmd /tmp/janitor.pub $JIP && rm -f /tmp/janitor-cmd /tmp/install-node-access.sh /tmp/janitor.pub"
  echo "$addr $(ssh "$host" cat /etc/ssh/ssh_host_ed25519_key.pub | cut -d' ' -f1,2)" >> "$tmp/known_hosts"
  pve_nodes+="${pve_nodes:+,}$name=$addr"
done

echo "==> Docker hosts: the janitor may start and watch agent rebuilds"
docker_hosts=""
for v in $DOCKER_VMS; do
  read -r ip name key <<<"$(vm_info "$v")"
  [[ -n "$ip" && "$key" == ssh-ed25519\ * ]] || { echo "couldn't read $v's address and host key" >&2; exit 1; }
  grep -q "^$ip " "$tmp/vm_known_hosts" || echo "$ip $key" >> "$tmp/vm_known_hosts"
  echo "$ip $key" >> "$tmp/known_hosts"
  from=$JIP
  [[ "$ip" == "$JIP" ]] && from="$JIP,172.16.0.0/12"  # from its own container, sshd sees the bridge address
  line="command=\"/usr/local/sbin/agent-redeploy-ssh\",restrict,from=\"$from\" $(cut -d' ' -f1-3 "$tmp/janitor.pub")"
  vm "$ip" "set -e
test -x /usr/local/sbin/agent-redeploy-ssh || { echo 'agent-redeploy is missing: run docker-host.sh from the dockerfile-agent repo first' >&2; exit 1; }
f=/home/deploy/.ssh/authorized_keys; t=\$(mktemp)
grep -v 'agent-redeploy-ssh' \$f > \$t || true
echo '$line' >> \$t
install -m 600 -o deploy -g deploy \$t \$f; rm -f \$t"
  echo "  $name ($ip)"
  docker_hosts+="${docker_hosts:+,}$name=$ip"
done

echo "==> known_hosts into $VOLUME"
vm "$JIP" "docker run --rm -i -v $VOLUME:/d busybox sh -c 'cat > /d/known_hosts'" < "$tmp/known_hosts"

echo "==> Runner instance for $REPO on CT ${RUNNER#*:}"
rnode=${RUNNER%%:*}; rct=${RUNNER#*:}
token=$("$GH" api -X POST "repos/$REPO/actions/runners/registration-token" --jq .token)
scp -q "$HERE/lxc/bootstrap-runner.sh" "${ssh_of[$rnode]:-$rnode}:/tmp/bootstrap-runner.sh"
ssh "${ssh_of[$rnode]:-$rnode}" "pct push $rct /tmp/bootstrap-runner.sh /root/bootstrap-runner.sh && rm -f /tmp/bootstrap-runner.sh && \
  pct exec $rct -- env LC_ALL=C.UTF-8 GH_URL=https://github.com/$REPO REG_TOKEN=$token RUNNER_NAME=\$(pct exec $rct -- hostname) \
  RUNNER_DIR=/opt/actions-runner-${REPO#*/} bash /root/bootstrap-runner.sh" | grep -E 'Active:|added' || true

echo "==> Repository variables"
"$GH" variable set AGENT_HOST --repo "$REPO" --body "$JIP"
"$GH" variable set PRIORITY --repo "$REPO" --body "${PRIORITY:-high}"
"$GH" variable set PVE_NODES --repo "$REPO" --body "$pve_nodes"
"$GH" variable set DOCKER_HOSTS --repo "$REPO" --body "$docker_hosts"
"$GH" variable set SELF_GUEST --repo "$REPO" --body "${JANITOR_VM#*:}"
[[ -n "${BUS_HOST_PORT:-}" ]] && "$GH" variable set BUS_HOST_PORT --repo "$REPO" --body "$BUS_HOST_PORT"

cat <<EOF

Done. The janitor deploys to $JNAME ($JIP); its key is pinned to that address on every node.
Push to main (or re-run the workflow) to deploy it.
EOF
