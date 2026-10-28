"""Health: guests given more CPU/RAM when they stay busy, nodes alerted, disks grown before they fill.

CPU and RAM come from the cluster's own resource view (one call for everything) every
MONITOR_SECONDS; a VM's RAM comes from its guest agent instead, because Proxmox counts the guest's
page cache as used. A value over its threshold starts a timer. Once it has stayed over for
SUSTAIN_MINUTES, a guest gets enough cores or memory to bring that load back to about
RESIZE_TARGET_PERCENT (at most double, RESIZE_MAX_CORES / RESIZE_MAX_MEM_GB, what its node has).
An LXC takes it live; a VM at its next restart, which the maintenance window does. A node, or a
guest that can't be raised, is reported instead, and reported as cleared when it drops back.

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
from .notify import CPU, DISK, MEM, Notifier, is_health, labels
from .pve import Cluster, RemoteError
from .state import State

log = logging.getLogger(__name__)

GIB, MIB = 1024 ** 3, 1024 ** 2
GROW_COOLDOWN = 3600  # don't grow the same volume again within this
RESIZE_COOLDOWN = 3600  # nor raise the same guest's CPU or RAM again
MEM_STEP = 512  # MiB
PASS_GRACE = 15 * 60  # longest a pass (every node and guest, plus any disk growth) should take


def grow_gb(used: int, total: int, target_percent: int, min_gb: int, max_gb: int) -> int:
    """GiB to add so `used` is about target_percent of the grown filesystem."""
    need = used / (target_percent / 100) - total
    return min(max_gb, max(min_gb, math.ceil(need / GIB)))


def resize_to(metric: str, cur: int, used: float, target_percent: int, max_value: int) -> int:
    """New cores (or MiB) so `used` cores (or bytes) is about target_percent of it: at least one
    step up, at most double, at most max_value."""
    if metric == "cpu":
        need, step = math.ceil(used / (target_percent / 100)), 1
    else:
        need, step = math.ceil(used / (target_percent / 100) / MIB / MEM_STEP) * MEM_STEP, MEM_STEP
    return min(max(cur + step, need), cur * 2, max_value)


def _amount(metric: str, n: int) -> str:
    return f"{n} cores" if metric == "cpu" else f"{n / 1024:g} GB"


class Monitor:
    def __init__(self, cluster: Cluster, cfg: Config, notifier: Notifier, state: State, ops=None, clock=time.time,
                 grow: bool = True):
        self.cluster, self.cfg, self.notifier, self.state, self.ops, self.clock = cluster, cfg, notifier, state, ops, clock
        self.grow = grow  # False: report what would be grown, change nothing
        self.disk_findings: list[Finding] = []
        self.last_disk_at = 0.0
        self.latest: dict[str, dict] = {}  # key -> {label, cpu, mem} from the last sample, for the bus
        # Keys of a resize or grow put off while the window (or a request) is busy: still unresolved
        self.waiting: set[str] = set()
        self.disks_waiting: set[str] = set()

    # --- CPU and RAM ---

    def sample(self, inv: dict) -> list[Finding]:
        now, over = self.clock(), self.state["over"]
        seen, findings, latest = set(), [], {}
        self.waiting = set()
        rows = [("node", n["node"], n["node"], n["node"], n) for n in inv.get("nodes") or [] if n.get("status") == "online"]
        rows += [(g.get("type", "lxc"), str(g["vmid"]), g.get("name") or str(g["vmid"]), g.get("node", "?"), g)
                 for g in inv.get("guests") or []
                 if g.get("status") == "running" and not g.get("template")
                 and not self.cfg.excluded(str(g["vmid"]), g.get("name") or "")]
        for kind, ident, name, node, r in rows:
            plain, md = labels(kind, ident, name, node)
            total = r.get("memtotal") or r.get("maxmem")
            values = {"cpu": (r.get("cpu") or 0) * 100,
                      # None: a VM whose guest agent didn't answer (the host's figure includes its page cache)
                      "mem": None if r.get("mem_source") == "host" else (r.get("mem") or 0) * 100 / total if total else 0}
            latest[f"{'node' if kind == 'node' else 'guest'}:{ident}"] = {
                "name": name, "kind": kind, "node": node,
                **{k: None if v is None else round(v, 1) for k, v in values.items()}}
            for metric, limit, section, what in (("cpu", self.cfg.cpu_percent, CPU, "CPU"),
                                                 ("mem", self.cfg.mem_percent, MEM, "memory")):
                key = f"{metric}:{'node' if kind == 'node' else 'guest'}:{ident}"
                seen.add(key)
                value = values[metric]
                if value is None or value < limit:
                    over.pop(key, None)
                    continue
                since = over.setdefault(key, now)
                minutes = int((now - since) // 60)
                if minutes < self.cfg.sustain_minutes:
                    continue
                if kind != "node" and self.cfg.resize:
                    f = self._resize(key, metric, what, section, r, value, minutes, plain, md)
                else:
                    f = Finding(key, f"{plain}: {what} at {value:.0f}% for {minutes} min (alert above {limit}%).",
                                section=section, line=f"{md} — {value:.0f}% for {minutes} min")
                if f:
                    findings.append(f)
        for key in [k for k in over if k not in seen]:  # stopped, removed or excluded since
            del over[key]
        self.latest = latest
        return findings

    def _resize(self, key: str, metric: str, what: str, section: str, r: dict, value: float, minutes: int,
                plain: str, md: str) -> Finding | None:
        """Give a guest more cores or memory. None when done (or put off while the window is busy)."""
        def problem(why: str) -> Finding:
            return Finding(key, f"{plain}: {what} at {value:.0f}% for {minutes} min and wasn't raised: {why}",
                           section=section, line=f"{md} — {value:.0f}% for {minutes} min, not raised: {why}")

        if metric == "cpu":
            cur, used, cap = int(r.get("maxcpu") or 1), (r.get("maxcpu") or 1) * value / 100, self.cfg.resize_max_cores
        else:
            cur, used, cap = int(r.get("maxmem") or 0) // MIB, r.get("mem") or 0, self.cfg.resize_max_mem_gb * 1024
        resized, now = self.state["resized"], self.clock()
        last = resized.get(key)
        if last and not last.get("error") and not last.get("live") and cur < last["to"]:
            return problem(f"already raised to {_amount(metric, last['to'])}, which a VM takes at its next restart "
                           "(the maintenance window does that)")
        if last and now - last["at"] < RESIZE_COOLDOWN:
            return problem(last.get("error") or "it was raised less than an hour ago and is still this busy")
        new = resize_to(metric, cur, used, self.cfg.resize_target_percent, cap)
        if new <= cur:
            return problem(f"it already has the most the janitor gives a guest ({_amount(metric, cap)})")
        if self.ops is not None and not self.ops.acquire(blocking=False):
            self.waiting.add(key)  # the maintenance window (or a request) is busy; try on the next pass
            return None
        try:
            res = self.cluster.call(r.get("node", "?"), "guest-resize", str(r["vmid"]),
                                    "cores" if metric == "cpu" else "memory", str(new),
                                    str(self.cfg.node_mem_max_percent), timeout=180)
        except RemoteError as exc:
            resized[key] = {"at": now, "error": str(exc)}
            return problem(str(exc))
        finally:
            if self.ops is not None:
                self.ops.release()
        live = bool(res.get("live"))
        resized[key] = {"at": now, "to": int(res.get("to") or new), "live": live}
        self.state["over"].pop(key, None)  # measure again from the new size
        when = "It took effect right away." if live else \
            "A VM takes it at its next restart; the maintenance window restarts it."
        self.notifier.report(f"{what[0].upper()}{what[1:]} raised",
                             [f"⬆️ {md}: {what} was at {value:.0f}% for {minutes} min; raised from "
                              f"{_amount(metric, cur)} to {_amount(metric, resized[key]['to'])}. {when}"])
        log.info("Raised %s %s %s -> %s (live=%s)", plain, metric, cur, resized[key]["to"], live)
        return None

    # --- disks ---

    def check_disks(self, inv: dict) -> list[Finding]:
        findings = []
        self.disks_waiting = set()
        for g in inv.get("guests") or []:
            vmid, name, node = str(g["vmid"]), g.get("name") or str(g["vmid"]), g.get("node", "?")
            if g.get("status") != "running" or g.get("template") or self.cfg.excluded(vmid, name) or node not in self.cfg.nodes:
                continue
            plain, md = labels(g.get("type", "lxc"), vmid, name, node)
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
            self.disks_waiting.add(key)  # the maintenance window (or a request) is busy; try on the next pass
            return None
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
        self.notifier.send(findings + self.disk_findings, owns=is_health, waiting=self.waiting | self.disks_waiting)
        self.state.save()

    def loop(self) -> None:
        while True:
            health.beat("monitor", self.cfg.monitor_seconds + PASS_GRACE)
            try:
                self.run_once()
            except Exception:  # keep monitoring
                log.exception("Monitor cycle failed")
            time.sleep(self.cfg.monitor_seconds)
