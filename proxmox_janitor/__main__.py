"""Entry point: python -m proxmox_janitor [--once]."""

from __future__ import annotations

import argparse
import logging
import os
import threading
import time
from datetime import datetime
from zoneinfo import ZoneInfo

from .bus import Approvals, BusTool, Runtime, schema, serve_mcp
from .config import Config
from .janitor import Janitor, schedule_due
from .kuma import KumaSync
from .monitor import Monitor
from .notify import Notifier
from .pve import Cluster, Remote
from .state import State

log = logging.getLogger("proxmox_janitor")
STALE_WINDOW_HOURS = 24  # an unfinished window older than this isn't resumed


def bus_tools(janitor: Janitor, monitor: Monitor, runtime: Runtime) -> list[BusTool]:
    """What the assistant may call. Changes are destructive, so the assistant must get the operator's
    approval for each call; the janitor queues the work and reports results itself."""
    return runtime.common_tools(check_is_destructive=False) + [
        BusTool("janitor_status", "Every node and guest: priority, pending updates (and how many are security), "
                "whether it needs a restart/reboot, errors; the schedule, the maintenance window's progress and "
                "recent jobs.", schema(), janitor.status),
        BusTool("health", "Current CPU and memory use of every node and running guest (percent), and which are "
                "over their threshold and since when.", schema(),
                lambda: {"latest": monitor.latest, "over_since": dict(monitor.state["over"]),
                         "thresholds": {"cpu": janitor.cfg.cpu_percent, "mem": janitor.cfg.mem_percent,
                                        "minutes": janitor.cfg.sustain_minutes, "disk": janitor.cfg.disk_percent}}),
        BusTool("list_updates", "The pending package updates for one node or guest (by node name, VMID or "
                "guest name).", schema({"target": {"type": "string"}}, ["target"]), janitor.list_updates),
        BusTool("job_status", "Recent jobs and their per-target results, or one job by id.",
                schema({"job_id": {"type": "integer"}}), janitor.job_status),
        BusTool("patch_guests", "Patch these guests now instead of waiting for the maintenance window: rollback "
                "snapshot, apt full-upgrade, restart if needed, snapshot deleted on success. Runs in the "
                "background; results are posted to the notification channel.",
                schema({"vmids": {"type": "array", "items": {"type": "integer"}}}, ["vmids"]),
                janitor.request_guests, read_only=False),
        BusTool("patch_node", "Patch one Proxmox node now (apt full-upgrade; refused if the cluster isn't "
                "quorate). A needed reboot waits for the maintenance window. Runs in the background.",
                schema({"node": {"type": "string"}}, ["node"]), janitor.request_node, read_only=False),
        BusTool("redeploy_containers", "Rebuild every agent container on a Docker host now (or 'all'): fresh "
                "base image and apt full-upgrade, rolling back any that fail to start.",
                schema({"host": {"type": "string"}}), janitor.request_redeploy, read_only=False),
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="Proxmox janitor")
    parser.add_argument("--once", action="store_true", help="run one check and one health pass, then exit (no changes)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = Config.from_env()
    try:
        tz = ZoneInfo(cfg.timezone)
    except Exception:
        raise SystemExit(f"Unknown TIMEZONE {cfg.timezone!r}")
    state = State(cfg.state_path)
    footer = (f"Daily check {cfg.check_time} · maintenance window {cfg.window_day.title()} {cfg.window_time} · "
              f"{cfg.timezone}")
    notifier = Notifier(cfg.notify_urls, cfg.renotify_hours, state, cfg.bot_alert_url, cfg.bus_token, footer)
    runtime = Runtime("janitor", revision=_revision())
    cluster = Cluster(cfg.nodes, cfg.ssh_key, cfg.known_hosts)
    docker = Remote(cfg.docker_hosts, cfg.ssh_key, cfg.known_hosts, user="deploy")
    janitor = Janitor(cluster, docker, cfg, notifier, state, runtime)
    monitor = Monitor(cluster, cfg, notifier, state, janitor.ops)
    if args.once:
        janitor.check()
        monitor.grow = False  # --once changes nothing
        monitor.run_once()
        return

    approvals = Approvals("janitor", cfg.approval_urls, mode=cfg.approval_mode)
    if cfg.bus_token and cfg.bus_port:
        serve_mcp("0.0.0.0", cfg.bus_port, cfg.bus_token, bus_tools(janitor, monitor, runtime), "proxmox-janitor",
                  approvals)
    log.info("Starting: nodes=%s docker_hosts=%s self=%s tz=%s check=%s window=%s %s reboot_guests=%s "
             "reboot_nodes=%s redeploy=%s cpu/mem=%s/%s%% for %smin disk=%s%%->%s%% bus=%s approvals=%s/%s",
             ",".join(cfg.nodes), ",".join(cfg.docker_hosts) or "-", cfg.self_guest or "-", cfg.timezone,
             cfg.check_time, cfg.window_day, cfg.window_time, cfg.reboot_guests, cfg.reboot_nodes, cfg.redeploy,
             cfg.cpu_percent, cfg.mem_percent, cfg.sustain_minutes, cfg.disk_percent, cfg.disk_target_percent,
             bool(cfg.bus_token), approvals.enabled, approvals.mode)
    log.info("Uptime Kuma: %s", f"{cfg.kuma_url} every {cfg.kuma_sync_minutes} min" if cfg.kuma_url else "off")

    threading.Thread(target=janitor.worker, name="janitor-worker", daemon=True).start()
    threading.Thread(target=monitor.loop, name="janitor-monitor", daemon=True).start()
    if cfg.kuma_url and cfg.docker_hosts:
        threading.Thread(target=KumaSync(docker, cfg, notifier, state).loop, name="janitor-kuma", daemon=True).start()
    win = state["window"]
    if win.get("steps") and not win.get("finished"):
        if time.time() - (win.get("started") or 0) < STALE_WINDOW_HOURS * 3600:
            log.info("Resuming the unfinished maintenance window")
            janitor.submit("resume", [], "startup")
        else:
            win["finished"] = time.time()
            state.save()
            notifier.report("Maintenance window abandoned", ["⚠️ An unfinished window older than "
                                                             f"{STALE_WINDOW_HOURS}h was found at startup and not resumed."])
    else:
        janitor.submit("check", [], "startup")
    last = state["schedule"]
    while True:
        if runtime.wake.wait(30):  # the assistant asked for a check now
            runtime.wake.clear()
            janitor.submit("check", [], "agent bus")
        now = datetime.now(tz)
        for kind in schedule_due(cfg, last, now):
            with state.lock:
                last[kind] = now.date().isoformat()
            state.save()
            log.info("Scheduled %s", kind)
            janitor.submit(kind, [], "schedule")


def _revision() -> str:
    try:
        with open(os.path.join(os.path.dirname(__file__), "..", "REVISION"), encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return "dev"


if __name__ == "__main__":
    main()
