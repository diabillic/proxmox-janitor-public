#!/usr/bin/env bash
# Runs INSIDE a runner LXC as root. A runner that updates itself keeps its previous version and the
# unpacked download, about 1.4 GB per instance, and nothing ever removes them. This does, weekly.
# It covers every /opt/actions-runner* instance, so a new instance needs no setup.
#   runner-cleanup.sh install     copy this to /usr/local/sbin and start the weekly timer (re-runnable)
#   runner-cleanup --dry-run      show what would go
#   runner-cleanup                remove it now
# An instance that never updated has plain bin and externals folders, and is left alone.
set -uo pipefail

SELF=/usr/local/sbin/runner-cleanup
WHEN="Sat 04:00 America/New_York"
SETTLE_MINUTES=60  # a download younger than this may still be in use by an update

if [[ "${1:-}" == install ]]; then
  [[ "$0" -ef "$SELF" ]] || install -m 755 -o root -g root "$0" "$SELF" || exit 1
  cat >/etc/systemd/system/runner-cleanup.service <<EOF
[Unit]
Description=Remove what GitHub runner self-updates leave behind

[Service]
Type=oneshot
ExecStart=$SELF
Nice=10
IOSchedulingClass=idle
EOF
  cat >/etc/systemd/system/runner-cleanup.timer <<EOF
[Unit]
Description=Weekly cleanup of GitHub runner self-update leftovers

[Timer]
OnCalendar=$WHEN
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload && systemctl enable --now runner-cleanup.timer || exit 1
  systemctl list-timers runner-cleanup.timer --no-pager | sed -n 2p
  exit 0
fi

dry=false
[[ "${1:-}" == --dry-run ]] && dry=true
failed=0
total=0

remove() {  # remove <instance> <path>
  local kb
  kb=$(du -xsk "$2" | cut -f1)
  total=$((total + kb))
  echo "$1: $($dry && echo would remove || echo removing) ${2#"$1/"} ($((kb / 1024)) MB)"
  $dry && return 0
  rm -rf -- "$2" || failed=1
}

for dir in /opt/actions-runner*/; do
  dir=${dir%/}
  [[ -L "$dir/bin" && -L "$dir/externals" ]] || continue
  if pgrep -f "^$dir/[^ ]*Runner\.Worker" >/dev/null; then
    echo "$dir: running a job, skipped"
    continue
  fi
  current=$(basename "$(readlink -f "$dir/bin")")
  current=${current#bin.}
  updating=false
  for path in "$dir"/bin.* "$dir"/externals.*; do
    [[ -d "$path" ]] || continue
    version=${path##*/}
    version=${version#*.}
    [[ "$version" == "$current" ]] && continue
    if [[ "$(printf '%s\n%s\n' "$version" "$current" | sort -V | head -1)" == "$version" ]]; then
      remove "$dir" "$path"
    else
      updating=true  # newer than the one in use: an update has it ready and is waiting to switch
      echo "$dir: update to $version in progress, keeping it"
    fi
  done
  download="$dir/_work/_update"
  if [[ -d "$download" ]] && ! $updating && [[ -n "$(find "$download" -maxdepth 0 -mmin +"$SETTLE_MINUTES")" ]]; then
    remove "$dir" "$download"
  fi
done

echo "$($dry && echo would free || echo freed) $((total / 1024)) MB"
exit "$failed"
