#!/usr/bin/env bash
# Turns on unattended security upgrades in every running LXC on the given nodes (re-runnable; run it
# again after adding containers). Containers without apt are skipped. VMs set this up themselves
# (the dockerfile-agent repository's docker-host.sh does it for Docker hosts).
#   NODES="pve1 pve2 ..." deploy/unattended-upgrades.sh        (SSH aliases or addresses for root)
# Env: EXCLUDE ("vmid ..." to leave alone)
set -euo pipefail
: "${NODES:?set NODES='pve1 pve2 ...'}"
HERE=$(cd "$(dirname "$0")" && pwd)
failed=0
for host in $NODES; do
  scp -q "$HERE/lxc/enable-unattended-upgrades.sh" "$host:/tmp/enable-unattended-upgrades.sh"
  out=$(ssh "$host" "for ct in \$(pct list | awk 'NR>1 && \$2==\"running\" {print \$1}'); do
      case ' ${EXCLUDE:-} ' in *\" \$ct \"*) echo \"\$ct excluded\"; continue;; esac
      name=\$(pct config \$ct | sed -n 's/^hostname: //p')
      pct push \$ct /tmp/enable-unattended-upgrades.sh /tmp/enable-unattended-upgrades.sh
      res=\$(pct exec \$ct -- sh /tmp/enable-unattended-upgrades.sh 2>&1 | tail -1)
      pct exec \$ct -- rm -f /tmp/enable-unattended-upgrades.sh
      echo \"\$ct \$name \$res\"
    done; rm -f /tmp/enable-unattended-upgrades.sh")
  while read -r line; do
    [[ -n "$line" ]] || continue
    echo "  $host: ${line/@@/}"
    [[ "$line" == *@@FAIL* ]] && failed=1
  done <<<"$out"
done
exit $failed
