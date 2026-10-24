"""Health: sustained CPU/RAM alerts for every guest and node, and disks grown before they fill.

CPU and RAM come from the cluster's own resource view (one call for everything) every
MONITOR_SECONDS. A value over its threshold starts a timer; once it has stayed over for
SUSTAIN_MINUTES it's reported, and reported as cleared when it drops back.

Every DISK_MINUTES each running guest's volumes are read (LXC: df inside, VM: guest agent). When a
filesystem passes DISK_PERCENT its volume grows by enough to bring it back to about
DISK_TARGET_PERCENT (GROW_MIN_GB..GROW_MAX_GB at a time) and the filesystem with it, unless the
storage would pass STORAGE_MAX_PERCENT. Anything that can't be grown is reported instead.
"""

from __future__ import annotations

import logging
import math
import time

from . import health
from .config import Config
from .findings import Finding
from .notify import CPU, DISK, MEM, Notifier, is_health
from .pve import Cluster, RemoteError
from .state import State

log = logging.getLogger(__name__)

GIB = 1024 ** 3
KIND_LABEL = {"lxc": "CT", "qemu": "VM"}
GROW_COOLDOWN = 3600  # don't grow the same volume again within this
PASS_GRACE = 15 * 60  # longest a pass (every node and guest, plus any disk growth) should take


def grow_gb(used: int, total: int, target_percent: int, min_gb: int, max_gb: int) -> int:
    """GiB to add so `used` is about target_percent of the grown filesystem."""
    need = used / (target_percent / 100) - total
    return min(max_gb, max(min_gb, math.ceil(need / GIB)))


def _label(kind: str, ident: str, name: str, node: str) -> tuple[str, str]:
    if kind == "node":
        return f"node {name}", f"**{name}** · host"
    return (f"{name} ({KIND_LABEL.get(kind, kind)} {ident} on {node})",
            f"**{name}** · {KIND_LABEL.get(kind, kind)} {ident} on {node}")


class Monitor:
    def __init__(self, cluster: Cluster, cfg: Config, notifier: Notifier, state: State, ops=None, clock=time.time,
                 grow: bool = True):
        self.cluster, self.cfg, self.notifier, self.state, self.ops, self.clock = cluster, cfg, notifier, state, ops, clock
        self.grow = grow  # False: report what would be grown, change nothing
        self.disk_findings: list[Finding] = []
        self.last_disk_at = 0.0
        self.latest: dict[str, dict] = {}  # key -> {label, cpu, mem} from the last sample, for the bus

    def _excluded(self, vmid: str, name: str) -> bool:
        return vmid in self.cfg.exclude or name in self.cfg.exclude

    # --- CPU and RAM ---

    def sample(self, inv: dict) -> list[Finding]:
        now, over = self.clock(), self.state["over"]
        seen, findings, latest = set(), [], {}
        rows = [("node", n["node"], n["node"], n["node"], n) for n in inv.get("nodes") or [] if n.get("status") == "online"]
        rows += [(g.get("type", "lxc"), str(g["vmid"]), g.get("name") or str(g["vmid"]), g.get("node", "?"), g)
                 for g in inv.get("guests") or []
                 if g.get("status") == "running" and not g.get("template")
                 and not self._excluded(str(g["vmid"]), g.get("name") or "")]
        for kind, ident, name, node, r in rows:
            plain, md = _label(kind, ident, name, node)
            values = {"cpu": (r.get("cpu") or 0) * 100,
                      "mem": (r.get("mem") or 0) * 100 / r["maxmem"] if r.get("maxmem") else 0}
            latest[f"{'node' if kind == 'node' else 'guest'}:{ident}"] = {"name": name, "kind": kind, "node": node,
                                                                          **{k: round(v, 1) for k, v in values.items()}}
            for metric, limit, section, what in (("cpu", self.cfg.cpu_percent, CPU, "CPU"),
                                                 ("mem", self.cfg.mem_percent, MEM, "memory")):
                key = f"{metric}:{'node' if kind == 'node' else 'guest'}:{ident}"
                seen.add(key)
                if values[metric] < limit:
                    over.pop(key, None)
                    continue
                since = over.setdefault(key, now)
                minutes = int((now - since) // 60)
                if minutes >= self.cfg.sustain_minutes:
                    findings.append(Finding(
                        key, f"{plain}: {what} at {values[metric]:.0f}% for {minutes} min (alert above {limit}%).",
                        section=section, line=f"{md} — {values[metric]:.0f}% for {minutes} min"))
        for key in [k for k in over if k not in seen]:  # stopped, removed or excluded since
            del over[key]
        self.latest = latest
        return findings

    # --- disks ---

    def check_disks(self, inv: dict) -> list[Finding]:
        findings = []
        for g in inv.get("guests") or []:
            vmid, name, node = str(g["vmid"]), g.get("name") or str(g["vmid"]), g.get("node", "?")
            if g.get("status") != "running" or g.get("template") or self._excluded(vmid, name) or node not in self.cfg.nodes:
                continue
            plain, md = _label(g.get("type", "lxc"), vmid, name, node)
            try:
                disks = self.cluster.call(node, "guest-disks", vmid, timeout=180)
            except RemoteError as exc:
                findings.append(Finding(f"disk:guest:{vmid}", f"Couldn't read disk usage of {plain}: {exc}",
                                        section=DISK, line=f"{md} — couldn't read disk usage: {exc}"))
                continue
            for vol in disks.get("volumes") or []:
                for fs in vol.get("filesystems") or []:
                    f = self._check_fs(vmid, node, plain, md, vol, fs)
                    if f:
                        findings.append(f)
        return findings

    def _check_fs(self, vmid: str, node: str, plain: str, md: str, vol: dict, fs: dict) -> Finding | None:
        used, total = fs.get("used") or 0, fs.get("total") or 0
        if not total:
            return None
        pct = used * 100 / total
        if pct < self.cfg.disk_percent:
            return None
        key = f"disk:guest:{vmid}:{vol['disk']}:{fs.get('mount')}"
        where = f"{fs.get('mount')} ({vol['disk']})"

        def problem(why: str) -> Finding:
            return Finding(key, f"{plain}: {where} is {pct:.0f}% full and wasn't grown: {why}",
                           section=DISK, line=f"{md} — {where} {pct:.0f}% full, not grown: {why}")

        if not fs.get("growable"):
            return problem("its filesystem can't be grown automatically (not the last partition, LVM, or "
                           f"{fs.get('type')})")
        gb = grow_gb(used, total, self.cfg.disk_target_percent, self.cfg.grow_min_gb, self.cfg.grow_max_gb)
        st_used, st_total = vol.get("storage_used") or 0, vol.get("storage_total") or 0
        if not st_total or (st_used + gb * GIB) * 100 / st_total > self.cfg.storage_max_percent:
            return problem(f"storage {vol.get('storage')} would be over {self.cfg.storage_max_percent}% used "
                           f"after adding {gb} GB")
        if not self.grow:
            return problem(f"would add {gb} GB (growing is off in this run)")
        grown = self.state["grown"]
        if self.clock() - grown.get(f"{vmid}:{vol['disk']}", 0) < GROW_COOLDOWN:
            return problem("it was grown less than an hour ago and is still this full")
        if self.ops is not None and not self.ops.acquire(blocking=False):
            return None  # the maintenance window (or a request) is busy; try on the next pass
        try:
            res = self.cluster.call(node, "guest-grow", vmid, vol["disk"], str(gb), str(self.cfg.storage_max_percent),
                                    timeout=1200)
        except RemoteError as exc:
            return problem(str(exc))
        finally:
            if self.ops is not None:
                self.ops.release()
        grown[f"{vmid}:{vol['disk']}"] = self.clock()
        after = next((f for v in res.get("volumes") or [] if v.get("disk") == vol["disk"]
                      for f in v.get("filesystems") or [] if f.get("mount") == fs.get("mount")), None)
        now_pct = f"{after['used'] * 100 / after['total']:.0f}%" if after and after.get("total") else "unknown"
        self.notifier.report("Disk grown", [f"💾 {md}: {where} was {pct:.0f}% full; added {gb} GB to "
                                            f"{vol['disk']} and grew the filesystem. Now {now_pct} used."])
        log.info("Grew %s %s by %s GB", plain, vol["disk"], gb)
        return None

    # --- loop ---

    def run_once(self) -> None:
        try:
            inv = self.cluster.inventory()
        except RemoteError as exc:
            log.warning("Monitor: %s", exc)
            return
        findings = self.sample(inv)
        if self.clock() - self.last_disk_at >= self.cfg.disk_minutes * 60:
            self.last_disk_at = self.clock()
            self.disk_findings = self.check_disks(inv)
        self.notifier.send(findings + self.disk_findings, owns=is_health)
        self.state.save()

    def loop(self) -> None:
        while True:
            health.beat("monitor", self.cfg.monitor_seconds + PASS_GRACE)
            try:
                self.run_once()
            except Exception:  # keep monitoring
                log.exception("Monitor cycle failed")
            time.sleep(self.cfg.monitor_seconds)
