"""Settings from the environment (agent.env, rendered by the deploy workflow)."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        raise SystemExit(f"{name} must be a whole number, got {raw!r}") from None


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    return default if not raw else raw in ("1", "true", "yes", "on")


def _list(name: str) -> list[str]:
    return [x.strip() for x in os.environ.get(name, "").replace("\n", ",").split(",") if x.strip()]


def _time(name: str, default: str) -> str:
    raw = os.environ.get(name, "").strip() or default
    if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", raw):
        raise SystemExit(f"{name} must be HH:MM (24h), got {raw!r}")
    return raw


def _pairs(name: str, example: str) -> dict[str, str]:
    out = {}
    for item in _list(name):
        key, sep, addr = item.partition("=")
        if not sep or not key.strip() or not addr.strip():
            raise SystemExit(f"{name} entries must be name=address (e.g. {example}), got {item!r}")
        out[key.strip()] = addr.strip()
    return out


@dataclass
class Config:
    nodes: dict[str, str]  # Proxmox node name -> SSH address
    docker_hosts: dict[str, str] = field(default_factory=dict)  # guest name -> SSH address (agent-redeploy)
    self_guest: str = ""  # VMID of the guest the janitor itself runs in: always handled last
    ssh_key: str = "/var/lib/proxmox-janitor/.ssh/id_ed25519"
    known_hosts: str = "/var/lib/proxmox-janitor/known_hosts"

    # Schedule (local time in `timezone`): a check every day, the maintenance window every week
    timezone: str = "UTC"
    check_time: str = "07:00"
    window_day: str = "sun"
    window_time: str = "03:00"
    window_hours: int = 3  # don't start a missed window later than this after window_time

    # Maintenance window: every guest, then every agent container, then every node
    reboot_guests: bool = True  # restart guests whose patches need it (the janitor's own guest last)
    reboot_nodes: bool = True  # reboot nodes one at a time, quorum checked (the janitor's own node last)
    redeploy: bool = True  # rebuild every agent container on the docker hosts
    keep_snapshots: bool = False  # true: keep the pre-patch snapshot after a successful patch too
    snapshot_keep: int = 2
    exclude: list[str] = field(default_factory=list)  # VMIDs or names never patched, restarted or resized

    # Health: guests resized when CPU/RAM stay high (nodes alerted), disks grown when they fill up
    cpu_percent: int = 75
    mem_percent: int = 75
    sustain_minutes: int = 15
    resize: bool = True  # false: only alert
    resize_target_percent: int = 60  # size a guest so the load it had is about this much of the new size
    resize_max_cores: int = 8  # per guest, and never more than its node has
    resize_max_mem_gb: int = 32  # per guest
    node_mem_max_percent: int = 90  # never commit more of a node's RAM than this to running guests
    monitor_seconds: int = 60
    disk_percent: int = 85  # grow a volume once a filesystem on it is this full
    disk_target_percent: int = 70  # ...by enough to bring it back to about this
    grow_min_gb: int = 5
    grow_max_gb: int = 50
    storage_max_percent: int = 90  # never grow into a storage beyond this
    disk_minutes: int = 15

    # Uptime Kuma: a Docker container monitor for every agent (unset KUMA_URL turns it off)
    kuma_url: str = ""
    kuma_username: str = ""
    kuma_password: str = ""
    kuma_notification: str = "Discord"  # the notification every monitor gets, by name
    kuma_docker_hosts: dict[str, str] = field(default_factory=dict)  # docker host -> its name in Uptime Kuma
    kuma_sync_minutes: int = 10
    kuma_interval: int = 60
    kuma_retries: int = 1

    state_path: str = "/var/lib/proxmox-janitor/state.json"
    notify_urls: list[str] = field(default_factory=list)
    renotify_hours: int = 24

    # Agent bus: MCP endpoint for an assistant (Hermes), and where to hand it alerts
    bus_token: str = ""
    bus_port: int = 8765
    bot_alert_url: str = ""
    approval_urls: list[str] = field(default_factory=list)
    approval_mode: str = "code"  # "code" (agent-enforced) or "client" (assistant asks; audited)

    @classmethod
    def from_env(cls) -> "Config":
        nodes = _pairs("PVE_NODES", "pve1=192.0.2.11")
        if not nodes:
            raise SystemExit("PVE_NODES is required (e.g. pve1=192.0.2.11,pve2=192.0.2.12)")
        day = (os.environ.get("WINDOW_DAY") or "sun").strip().lower()[:3]
        if day not in DAYS:
            raise SystemExit(f"WINDOW_DAY must be a weekday name, got {day!r}")
        target, threshold = _int("DISK_TARGET_PERCENT", 70), _int("DISK_PERCENT", 85)
        if not 10 <= target < threshold <= 99:
            raise SystemExit("need 10 <= DISK_TARGET_PERCENT < DISK_PERCENT <= 99")
        cpu, mem = min(100, max(1, _int("CPU_PERCENT", 75))), min(100, max(1, _int("MEM_PERCENT", 75)))
        resize_target = _int("RESIZE_TARGET_PERCENT", 60)
        if not 10 <= resize_target < min(cpu, mem):
            raise SystemExit("need 10 <= RESIZE_TARGET_PERCENT < CPU_PERCENT and MEM_PERCENT")
        return cls(
            nodes=nodes,
            docker_hosts=_pairs("DOCKER_HOSTS", "docker1=192.0.2.21"),
            self_guest=os.environ.get("SELF_GUEST", "").strip(),
            ssh_key=os.environ.get("SSH_KEY", "").strip() or cls.ssh_key,
            known_hosts=os.environ.get("KNOWN_HOSTS", "").strip() or cls.known_hosts,
            timezone=os.environ.get("TIMEZONE", "").strip() or "UTC",
            check_time=_time("CHECK_TIME", "07:00"),
            window_day=day,
            window_time=_time("WINDOW_TIME", "03:00"),
            window_hours=max(1, _int("WINDOW_HOURS", 3)),
            reboot_guests=_bool("REBOOT_GUESTS", True),
            reboot_nodes=_bool("REBOOT_NODES", True),
            redeploy=_bool("REDEPLOY", True),
            keep_snapshots=_bool("KEEP_SNAPSHOTS", False),
            snapshot_keep=min(9, max(1, _int("SNAPSHOT_KEEP", 2))),
            exclude=_list("EXCLUDE_GUESTS"),
            cpu_percent=cpu,
            mem_percent=mem,
            sustain_minutes=max(1, _int("SUSTAIN_MINUTES", 15)),
            resize=_bool("RESIZE", True),
            resize_target_percent=resize_target,
            resize_max_cores=max(1, _int("RESIZE_MAX_CORES", 8)),
            resize_max_mem_gb=max(1, _int("RESIZE_MAX_MEM_GB", 32)),
            node_mem_max_percent=min(99, max(50, _int("NODE_MEM_MAX_PERCENT", 90))),
            monitor_seconds=max(15, _int("MONITOR_SECONDS", 60)),
            disk_percent=threshold,
            disk_target_percent=target,
            grow_min_gb=max(1, _int("GROW_MIN_GB", 5)),
            grow_max_gb=min(999, max(1, _int("GROW_MAX_GB", 50))),
            storage_max_percent=min(99, max(50, _int("STORAGE_MAX_PERCENT", 90))),
            disk_minutes=max(5, _int("DISK_MINUTES", 15)),
            kuma_url=os.environ.get("KUMA_URL", "").strip().rstrip("/"),
            kuma_username=os.environ.get("KUMA_USERNAME", "").strip(),
            kuma_password=os.environ.get("KUMA_PASSWORD", ""),
            kuma_notification=os.environ.get("KUMA_NOTIFICATION", "").strip() or "Discord",
            kuma_docker_hosts=_pairs("KUMA_DOCKER_HOSTS", "docker1=docker1"),
            kuma_sync_minutes=max(1, _int("KUMA_SYNC_MINUTES", 10)),
            kuma_interval=max(20, _int("KUMA_INTERVAL", 60)),
            kuma_retries=max(0, _int("KUMA_RETRIES", 1)),
            state_path=os.environ.get("STATE_PATH", "/var/lib/proxmox-janitor/state.json"),
            notify_urls=_list("NOTIFY_URLS"),
            renotify_hours=_int("RENOTIFY_HOURS", 24),
            bus_token=os.environ.get("AGENT_BUS_TOKEN", "").strip(),
            bus_port=_int("AGENT_BUS_PORT", 8765),
            bot_alert_url=os.environ.get("BOT_ALERT_URL", "").strip(),
            approval_urls=_list("APPROVAL_NOTIFY_URLS"),
            approval_mode=os.environ.get("APPROVAL_MODE", "").strip().lower() or "code",
        )
