#!/bin/sh
# Runs INSIDE a Debian/Ubuntu guest as root (re-runnable). Turns on unattended security upgrades,
# daily, never rebooting by itself: the janitor restarts guests that need it in its weekly window.
# Prints @@OK, @@SKIP <why> or @@FAIL <why> on the last line.
export DEBIAN_FRONTEND=noninteractive LC_ALL=C
command -v apt-get >/dev/null 2>&1 || { echo "@@SKIP no apt"; exit 0; }
if ! dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then
  apt-get update -q >/dev/null 2>&1
  apt-get install -y -q unattended-upgrades >/dev/null 2>&1 \
    || { echo "@@FAIL couldn't install unattended-upgrades (can apt reach its mirrors?)"; exit 0; }
fi
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
cat > /etc/apt/apt.conf.d/52homelab-unattended <<'EOF'
// Security updates only, no automatic reboots: the Proxmox janitor restarts guests in its weekly window.
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF
systemctl enable --now unattended-upgrades apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1
if [ "$(apt-config dump APT::Periodic::Unattended-Upgrade | sed -n 's/.*"\(.*\)";/\1/p')" = 1 ] \
   && systemctl is-enabled --quiet apt-daily-upgrade.timer; then
  echo "@@OK"
else
  echo "@@FAIL the configuration didn't take effect"
fi
