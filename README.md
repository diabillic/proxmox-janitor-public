# Proxmox janitor

Keeps a Proxmox VE cluster patched, healthy and roomy:

- **Patching:** every node and every guest (LXC containers and VMs with `apt`) in a weekly
  maintenance window, with restarts and reboots where updates need them.
- **Container rebuilds:** every agent container on the Docker hosts is rebuilt in the same window,
  so each image gets a fresh base and a full OS upgrade.
- **CPU and RAM:** alerts when a node or guest stays above a threshold.
- **Disks:** volumes are grown, along with the filesystem inside the guest, before they fill up.

## What it does

| When | What |
|---|---|
| Daily at `CHECK_TIME` (07:00) | Checks every node and running guest for updates and needed restarts, and reports anything new. |
| Weekly at `WINDOW_DAY` `WINDOW_TIME` (Sun 03:00) | The maintenance window, three phases one step at a time: **1.** every guest gets a pre-patch snapshot, `apt full-upgrade`, a restart if it needs one, then the snapshot is deleted. **2.** Every Docker host rebuilds every agent container. **3.** Every node gets `apt full-upgrade`, then a reboot if needed. A summary is posted at the end. |
| Every `MONITOR_SECONDS` (60) | CPU and RAM of every node and running guest. Above `CPU_PERCENT` / `MEM_PERCENT` (80) for `SUSTAIN_MINUTES` (15) sends an alert, and another when it's back to normal. |
| Every `DISK_MINUTES` (15) | Every filesystem of every running guest. Above `DISK_PERCENT` (85), the volume grows by enough to bring it back to about `DISK_TARGET_PERCENT` (70), between `GROW_MIN_GB` (5) and `GROW_MAX_GB` (50) at a time, and the filesystem grows with it. |

Guardrails:

- **Snapshots:** if the pre-patch snapshot fails, the guest isn't patched. A failed patch or
  restart keeps its snapshot for rollback (at most `SNAPSHOT_KEEP` per guest).
- **Node reboots:** one at a time, only while the cluster is quorate with every node online.
  Guests that were running and don't start on boot are started again afterwards.
- **Disk growth:** never grows into a storage beyond `STORAGE_MAX_PERCENT` (90). Volumes only ever
  grow, never shrink. VMs need the QEMU guest agent, and the filesystem must be ext4, xfs or
  btrfs on the disk's last partition or on the whole disk. LVM inside a VM isn't grown.
  Anything it can't grow is reported instead.
- **Rebuilds:** a rebuilt container that doesn't stay up is rolled back to the previous one by
  `agent-deploy`.
- **Exclusions:** `EXCLUDE_GUESTS` (VMIDs or names) are never patched, restarted or resized.
- **Restarting itself:** the janitor runs inside one of the guests, as one of the containers, on
  one of the nodes. Whatever would restart it comes last in its phase, and the step is recorded
  first. After the restart it finds the unfinished window and finishes it. Rebooting its own node
  is announced before it happens.

## Uptime Kuma monitors

With `KUMA_URL` set, the janitor gives every agent container a **Docker Container** monitor in Uptime Kuma.
Every `KUMA_SYNC_MINUTES` (10) it asks each Docker host which containers `agent-deploy` runs there
(apps such as Uptime Kuma itself are left out). Any agent without a monitor gets one, by container name
on that host's Docker host entry, with the same settings: `KUMA_INTERVAL` (60 s) and `KUMA_RETRIES` (1),
plus the notification called `KUMA_NOTIFICATION` (`Discord`). A new agent has its monitor within one
sync of its first deploy. Monitors are only added, never changed or deleted.

Uptime Kuma needs a Docker host entry per Docker host, named as in `DOCKER_HOSTS` (or mapped with
`KUMA_DOCKER_HOSTS`). Point each entry at a read-only Docker socket proxy (the dockerfile-agent
repository's `deploy/apps/docker-socket-proxy`), not at the Docker API itself. Create the notification
and the entries once, from inside the janitor container, with the webhook on stdin:

```bash
echo "$DISCORD_WEBHOOK" | docker exec -i proxmox-janitor python -m proxmox_janitor.kuma setup   --docker-host docker1=tcp://docker-socket-proxy:2375 --docker-host docker2=tcp://192.0.2.22:2376
```

The account must not use 2FA; the janitor logs in with a username and password.

The janitor's own container has a Docker health check (`python -m proxmox_janitor.health`), so its monitor
reports more than "running". It turns `unhealthy` when one of its loops stops coming round: the scheduler
(every 30 s), the health monitor (`MONITOR_SECONDS` plus 15 min), the Uptime Kuma sync
(`KUMA_SYNC_MINUTES` plus 10 min), or the job worker (idle, or a job running over 12 h), or when the
agent bus stops answering `/health`. `docker inspect --format '{{json .State.Health}}' proxmox-janitor`
shows why.

## How it reaches the cluster

It holds one SSH key and no Proxmox API token.

- **Proxmox nodes:** the key is pinned to `node/janitor-cmd`:
  `command="/usr/local/sbin/janitor-cmd",restrict,from="<janitor address>"`. That script accepts a
  fixed set of requests (inventory, checks, patching, snapshots, guest restart/start, disk reports
  and growth, node reboot) with validated arguments, and nothing else. There's no shell.
- **Docker hosts:** the same key is pinned to `agent-redeploy-ssh` on the `deploy` user. It can
  start a rebuild of every agent and read its status, nothing else.

## Agent bus (MCP for an assistant such as Hermes Agent)

Same as the other agents (see the sonarr-health-agent README). Read-only tools: `janitor_status`,
`health`, `list_updates`, `job_status`, plus the common `agent_*` tools. Destructive tools, which
need your approval: `patch_guests` (patch now instead of waiting for the window), `patch_node`
(patches only; a needed reboot waits for the window) and `redeploy_containers`.

## Deploy

Every push to `main` runs the tests. The deploy job then sends the build context (the generated
`Dockerfile` and `.dockerignore`, `requirements.txt` and the package) and a rendered `agent.env` to
a Docker host. There, the root-owned `agent-deploy` builds the image and replaces the container,
and rolls back if the new one doesn't stay up. Each build pulls the newest base image and runs
`apt-get full-upgrade`, so every deployed image is fully patched. State lives in the
`proxmox-janitor-data` volume.

| Variable | Expected value |
|---|---|
| `AGENT_HOST` | Address of the Docker host. |
| `PRIORITY` | `high` (default) or `low`. Picks the deploying runner (`[self-hosted, proxmox]` or `[self-hosted, low-priority]`) and sets the container label `homelab.priority`. |
| `BUS_HOST_PORT` | Optional. Host port for the agent bus when several agents share a host. The container still listens on `AGENT_BUS_PORT`. |

To prepare a Docker host, run `deploy/docker-host.sh` from the dockerfile-agent repository. It
installs `agent-deploy`, creates the `deploy` user, allows only the given runners in, and turns
on unattended security upgrades. The systemd unit and bootstrap in `deploy/lxc/` describe the
service, and the dockerfile-agent generates the Dockerfile from them.

### One-time setup

Prepare the Docker hosts with the dockerfile-agent repository's `deploy/docker-host.sh`. Then, from a
workstation with root SSH to every node and `gh` logged in:

```bash
NODES="pve1=pve1.lan pve2=pve2.lan pve3=pve3.lan" JANITOR_VM=pve1:100 DOCKER_VMS="pve1:100 pve2:117" \
  RUNNER=pve1:104 ADMIN_KEY=~/.ssh/id_ed25519 BUS_HOST_PORT=8767 deploy/provision.sh
```

It creates the janitor's key inside its state volume, pins it to `janitor-cmd` on every node and
to `agent-redeploy-ssh` on every Docker host (from the janitor's address only), writes its
`known_hosts`, registers a runner instance, and sets `AGENT_HOST`, `PRIORITY`, `PVE_NODES`,
`DOCKER_HOSTS` and `SELF_GUEST`. Give the Docker hosts DHCP reservations, because the node access
is pinned to the janitor's address. `deploy/low-priority-runners.sh` adds low-priority runners
(see its header).

## Secrets and variables

This repository contains **no secrets**. Set them under **Settings → Secrets and variables →
Actions**.

| Kind | Name | Expected value |
|---|---|---|
| secret | `NOTIFY_URLS` | Comma-separated Apprise URLs. A Discord webhook (`https://discord.com/api/webhooks/<id>/<token>`) gets formatted embeds. |
| secret | `AGENT_BUS_TOKEN` | Long random bearer token for the agent bus (`openssl rand -hex 32`); the same value goes in your assistant's MCP config. |
| secret | `APPROVAL_NOTIFY_URLS` | Apprise URL(s) of an audit channel your assistant can't read. Required for any requested change to run. |
| secret | `PUBLIC_DEPLOY_KEY` | Only for mirroring a private copy to a public one. |
| variable | `AGENT_HOST`, `PRIORITY`, `BUS_HOST_PORT` | The Docker host to deploy to, `high` or `low` (picks the runner), and the agent bus host port. `provision.sh` sets the first two. |
| variable | `PVE_NODES` | `name=address,...` for every node (set by `provision.sh`). |
| variable | `DOCKER_HOSTS` | `name=address,...` of the Docker hosts whose agents are rebuilt (set by `provision.sh`). |
| variable | `SELF_GUEST` | VMID of the guest the janitor runs in (set by `provision.sh`). |
| variable | `KUMA_URL`, `KUMA_USERNAME` | Uptime Kuma's address as the janitor reaches it, e.g. `http://192.0.2.21:3001`, and its login. Unset turns monitor syncing off. |
| secret | `KUMA_PASSWORD` | That login's password. |
| variables | `KUMA_NOTIFICATION`, `KUMA_DOCKER_HOSTS`, `KUMA_SYNC_MINUTES`, `KUMA_INTERVAL`, `KUMA_RETRIES` | Optional: notification name (`Discord`), `host=kuma name` mapping, and defaults 10 / 60 / 1. |
| variable | `TIMEZONE` | IANA zone for the schedule, e.g. `America/New_York` (default `UTC`). |
| variable | `APPROVAL_MODE` | `client` (assistant buttons) or `code` (default `code`). |
| variables | `CHECK_TIME`, `WINDOW_DAY`, `WINDOW_TIME`, `WINDOW_HOURS`, `REBOOT_GUESTS`, `REBOOT_NODES`, `REDEPLOY`, `KEEP_SNAPSHOTS`, `SNAPSHOT_KEEP`, `EXCLUDE_GUESTS`, `CPU_PERCENT`, `MEM_PERCENT`, `SUSTAIN_MINUTES`, `MONITOR_SECONDS`, `DISK_PERCENT`, `DISK_TARGET_PERCENT`, `GROW_MIN_GB`, `GROW_MAX_GB`, `STORAGE_MAX_PERCENT`, `DISK_MINUTES`, `RENOTIFY_HOURS`, `AGENT_BUS_PORT`, `BOT_ALERT_URL` | Optional overrides; see `.env.example` for the defaults. |

## Local run

```bash
pip install -r requirements.txt pytest
pytest -q
python -m proxmox_janitor --once   # one check and one health pass, changes nothing (needs the env above)
```
