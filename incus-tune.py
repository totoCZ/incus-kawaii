#!/usr/bin/env python3
"""Reconciler for incus container tuning: NUMA placement + network hook.

Per container, regardless of running state:

  - NUMA placement (CPU + memory) pinned to a single node:
      * `limits.cpu.nodes` (incus-native, applies on next start)
      * `raw.lxc = lxc.cgroup2.cpuset.mems=<n>` (incus has no
        first-class memory.nodes key as of 6.23)
      * live cgroup write to `cpuset.mems` for running containers so the
        change takes effect without a restart

  - Network start hook in `raw.lxc`: a container-level `raw.lxc`
    *replaces* the default profile's `raw.lxc` (it does not merge), so we
    must explicitly carry the right `lxc.hook.start` line here. The line
    is picked from the container's expanded devices:

      * if `/opt/clat-inject` is mounted, install the CLAT hook
        (`/clat-inject/run.sh`); that script invokes net-wait itself
        before bringing CLAT up
      * else if `/opt/net-inject` is mounted, install the plain
        net-wait hook (`/net-inject/net-wait`)
      * else, leave the hook line out — the container hasn't opted into
        either system

Placement policy:
  Containers in PINNED go to their assigned node unconditionally.

  All others are balanced by *memory weight* across nodes:
    - Running containers' actual RSS is read from cgroup memory.current.
    - Stopped containers fall back to their configured limits.memory, or
      a conservative estimate if unset.
    - Existing placements for *running* containers are preserved unless
      the inter-node memory imbalance fraction exceeds RUNNING_HYSTERESIS
      (default 15%). Moving a running container doesn't migrate existing
      pages — only new allocations shift — so small gains aren't worth
      the mixed-node period.
    - Stopped containers are freely reassigned; they have no warm pages.
    - When multiple containers are unplaced, the heaviest are placed first
      so the largest footprints anchor the node choice before smaller
      containers fill gaps.

Side effect: clears legacy explicit `limits.cpu` cpusets (commas/ranges)
so the cpuset is governed by limits.cpu.nodes alone. Integer values of
limits.cpu (cpu count caps) are left alone.
"""

from __future__ import annotations

import json
import math
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

# ── design notes / wishlist ────────────────────────────────────────────────────
#
# Runtime limit theory
#   Runtimes with GC or managed thread pools (Go, .NET, JVM, Node, Ruby) probe
#   the host's CPU count and available memory at startup and size their internal
#   structures to fit: GC heaps, thread-pool floors, card tables, segment counts.
#   On a 56-core host a .NET container spawns 56 Server GC heaps + 56 idle
#   threads whether it handles 1 QPS or 1 000 QPS.  A limits.cpu of 4 is not a
#   constraint — it is correct configuration that gives the runtime an honest
#   view of the machine it lives on.
#
#   C / Rust / Nim ARC: no runtime inflation.  Limits add OOM risk with no
#   behavioral benefit.  Only use them for resource partitioning on shared nodes.
#
# What this module does (Phase 1 — nudge)
#   • Memory ceiling: RSS → next power-of-2 GiB anchor.  Generous, not tight.
#     90 MB RSS → 1 GiB ceiling.  24 GiB RSS → 32 GiB ceiling.
#     Gives the GC a reference point; it collects before the kernel does.
#   • CPU count: avg_cores → next even integer ≥ 2.
#     1.3 avg → 2.  3.1 avg → 4.  Sizes thread-pool floor and GC heap count.
#   Only fills in *missing* limits; never lowers or removes existing ones.
#
# Future work (Phase 2 — feedback controller)
#   watch  /sys/fs/cgroup/.../memory.events  → memory.high hit count
#          cpu.stat usage_usec delta         → instantaneous CPU pressure
#   rules  memory.high events > N in window  → bump ceiling to next anchor
#          cpu sustained > 80 % for > 30 s  → bump cpu +2
#          bump count ≥ 3                   → notify human, stop auto-bumping
#          stability window (6 h calm)      → decay bump counter
#   .NET note: bumping CPU also grows GC heap count, which increases RSS
#   baseline — correlate CPU + memory pressure before bumping either axis.
#
# ──────────────────────────────────────────────────────────────────────────────

# Only list containers whose placement must be specific.
# Everything else gets balanced automatically.
PINNED: dict[str, int] = {
    "geth":     0,
    "grandine": 0,
    "ingress":  0,
}

# ── resource limit overrides ───────────────────────────────────────────────────
# Per-container control over automatic limit suggestions.
#   absent key          → auto-anchor computed from live metrics
#   value = None        → skip this resource (don't set any limit)
#   value = str / int   → explicit limit, bypasses auto-anchor
#
# Chain nodes with huge page-cache footprints need None for memory: the anchor
# would fire at e.g. 32 GiB but actual RSS can climb past that legitimately.
RESOURCE_OVERRIDES: dict[str, dict[str, str | int | None]] = {
    "geth":     {"memory": None},   # 20–30 GiB page cache; anchor unreliable
    "grandine": {"memory": None},   # eth consensus client; state size varies
}

# ── balancer tuning ────────────────────────────────────────────────────────────

# Pressure score weights — must sum to 1.0.
# Memory dominates: page-fault latency is the primary NUMA cost.
# CPU matters too: a CPU-heavy container on a node whose CPUs are
# all across the interconnect pays a scheduling penalty on every syscall.
MEM_WEIGHT: float = 0.6
CPU_WEIGHT: float = 0.4

# Minimum fractional *pressure* imbalance to trigger a move for a running
# container.  Below this threshold the existing placement wins: moving a
# running container only shifts future allocations; existing warm pages
# stay until reclaim, so small gains aren't worth the mixed-node period.
RUNNING_HYSTERESIS: float = 0.15   # 15 % of normalised pressure range

# Fallback weights for containers where we can't read real metrics.
STOPPED_MEM_ESTIMATE_MB: int  = 256
RUNNING_MEM_ESTIMATE_MB: int  = 1024
STOPPED_CPU_ESTIMATE_CORES: float = 0.1
RUNNING_CPU_ESTIMATE_CORES: float = 1.0


# ── helpers ────────────────────────────────────────────────────────────────────

def run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


# ── resource anchor helpers ────────────────────────────────────────────────────

_MEM_ANCHORS_GIB: list[int] = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512]


def _memory_anchor_bytes(rss_bytes: int) -> int:
    """Next power-of-2 GiB ceiling strictly above current RSS. Minimum 1 GiB."""
    gib = rss_bytes / (1 << 30)
    for a in _MEM_ANCHORS_GIB:
        if a > gib:
            return a * (1 << 30)
    return _MEM_ANCHORS_GIB[-1] * (1 << 30)


def _cpu_anchor(avg_cores: float) -> int:
    """Round up to next even CPU count, minimum 2."""
    return max(2, math.ceil(avg_cores / 2) * 2)


def _limit_hints(
    name: str, m: ContainerMetrics, config: dict[str, str]
) -> tuple[str, str]:
    """Return (mem_hint, cpu_hint) strings for table display.

    Shows the current limit if already set, the auto-anchor with a leading
    arrow (→) if the limit is absent, or 'skip' if overridden to None.
    """
    overrides = RESOURCE_OVERRIDES.get(name, {})
    cur_mem = config.get("limits.memory", "")
    cur_cpu = config.get("limits.cpu", "")

    # Memory column
    if cur_mem:
        mem_h = cur_mem
    elif overrides.get("memory") is None and "memory" in overrides:
        mem_h = "skip"
    elif "memory" in overrides and overrides["memory"] is not None:
        mem_h = f"→{overrides['memory']}"
    elif m.rss_bytes > 0:
        ab = _memory_anchor_bytes(m.rss_bytes)
        mem_h = f"→{ab >> 30}GiB"
    else:
        mem_h = "?"

    # CPU column
    if cur_cpu and cur_cpu.isdigit():
        cpu_h = cur_cpu
    elif overrides.get("cpu") is None and "cpu" in overrides:
        cpu_h = "skip"
    elif "cpu" in overrides and overrides["cpu"] is not None:
        cpu_h = f"→{overrides['cpu']}"
    elif m.cpu_cores > 0:
        cpu_h = f"→{_cpu_anchor(m.cpu_cores)}"
    else:
        cpu_h = "?"

    return mem_h, cpu_h


def _memory_ceiling_bytes(
    name: str, m: ContainerMetrics, config: dict[str, str]
) -> int | None:
    """Ceiling in bytes for the % used calculation.

    Priority: configured limit → explicit override → auto-anchor → None.
    Returns None when no ceiling is known or the resource is skipped.
    """
    overrides = RESOURCE_OVERRIDES.get(name, {})
    cur_mem = config.get("limits.memory", "")

    if cur_mem:
        return _parse_memory_limit(cur_mem)
    if "memory" in overrides:
        if overrides["memory"] is None:
            return None
        return _parse_memory_limit(str(overrides["memory"]))
    if m.rss_bytes > 0:
        return _memory_anchor_bytes(m.rss_bytes)
    return None


def numa_nodes() -> list[int]:
    with open("/sys/devices/system/node/online") as f:
        spec = f.read().strip()
    nodes: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            nodes.extend(range(int(a), int(b) + 1))
        else:
            nodes.append(int(part))
    return nodes


def list_containers() -> list[dict[str, Any]]:
    """Return all containers (any state) with expanded devices + status."""
    return json.loads(run(["incus", "list", "--format", "json"]))


def cfg_get(name: str, key: str) -> str:
    try:
        return run(["incus", "config", "get", name, key]).strip()
    except subprocess.CalledProcessError:
        return ""


def cfg_set(name: str, key: str, value: str) -> None:
    subprocess.run(["incus", "config", "set", name, f"{key}={value}"], check=True)


def cfg_unset(name: str, key: str) -> None:
    subprocess.run(["incus", "config", "unset", name, key], check=True)


# ── metrics ────────────────────────────────────────────────────────────────────

@dataclass
class ContainerMetrics:
    name: str
    # Balancing weight: anon+shmem only — page cache is reclaimable and
    # must not be counted as load (geth fills Node 0 with FS cache which
    # would otherwise push every other container onto Node 1).
    memory_bytes: int
    # Average CPU cores consumed over the container's lifetime.
    # Derived from state.cpu.usage_ns / uptime, or limits.cpu if set.
    # Not instantaneous — but deterministic without a two-sample poll.
    cpu_cores: float
    # Full memory.current for display; 0 if unavailable.
    rss_bytes: int
    is_estimated: bool  # True → some metric fell back to a proxy/estimate
    is_running: bool

    @property
    def memory_mb(self) -> float:
        return self.memory_bytes / (1 << 20)

    @property
    def source_tag(self) -> str:
        return "estimate" if self.is_estimated else "actual"


_MEM_SUFFIXES: list[tuple[str, int]] = [
    ("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10),
    ("GB",  10 ** 9), ("MB",  10 ** 6), ("KB",  10 ** 3),
]


def _parse_memory_limit(raw: str) -> int | None:
    """Parse an incus memory string such as '4GiB', '512MB', '1073741824'."""
    s = raw.strip()
    for suffix, mult in _MEM_SUFFIXES:
        if s.endswith(suffix):
            try:
                return int(s[: -len(suffix)]) * mult
            except ValueError:
                return None
    try:
        return int(s)
    except ValueError:
        return None


def _cgroup_int(name: str, fname: str) -> int | None:
    """Read a single integer from a container's cgroup v2 file."""
    try:
        with open(f"/sys/fs/cgroup/lxc.payload.{name}/{fname}") as f:
            v = int(f.read().strip())
        # Sanity-check: values above 4 TiB are almost certainly bogus
        # (e.g. memory.current = max_int when the cgroup is inactive).
        return v if v < (1 << 42) else None
    except (OSError, ValueError):
        return None


def _cgroup_stat(name: str) -> dict[str, int]:
    """Parse /sys/fs/cgroup/lxc.payload.<name>/memory.stat into a dict."""
    try:
        with open(f"/sys/fs/cgroup/lxc.payload.{name}/memory.stat") as f:
            result: dict[str, int] = {}
            for line in f:
                parts = line.split()
                if len(parts) == 2:
                    try:
                        result[parts[0]] = int(parts[1])
                    except ValueError:
                        pass
            return result
    except OSError:
        return {}


def _anon_bytes(name: str) -> int | None:
    """
    Return the working-set memory weight for NUMA balancing.

    We use anon + shmem from memory.stat, *not* memory.current.

    memory.current includes the page cache, which for a chain node like
    geth can be 100+ GB of reclaimable file pages.  Counting that as load
    causes the balancer to treat Node 0 as saturated and exile everything
    else to Node 1 — the opposite of what we want.

    anon  = heap, stack, anonymous mmap  (not reclaimable without swap)
    shmem = tmpfs / shared memory        (also not trivially reclaimable)

    These are the bytes that actually need NUMA-local placement.
    """
    stat = _cgroup_stat(name)
    anon = stat.get("anon")
    if anon is None:
        return None
    shmem = stat.get("shmem", 0)
    total = anon + shmem
    return total if total < (1 << 42) else None


def _node_cpu_count(node: int) -> int:
    """Physical CPU count on a NUMA node, parsed from cpulist."""
    try:
        with open(f"/sys/devices/system/node/node{node}/cpulist") as f:
            spec = f.read().strip()
        count = 0
        for part in spec.split(","):
            if "-" in part:
                a, b = part.split("-")
                count += int(b) - int(a) + 1
            else:
                count += 1
        return max(count, 1)
    except OSError:
        return 1


def _node_mem_bytes(node: int) -> int:
    """Total physical memory on a NUMA node, in bytes."""
    try:
        with open(f"/sys/devices/system/node/node{node}/meminfo") as f:
            for line in f:
                if "MemTotal" in line:
                    # format: "Node 0 MemTotal:    131086336 kB"
                    kb = int(line.split()[-2])
                    return kb * 1024
    except (OSError, ValueError, IndexError):
        pass
    return 128 * (1 << 30)   # 128 GiB safe fallback


def gather_metrics(
    containers: list[dict[str, Any]],
) -> dict[str, ContainerMetrics]:
    """
    Collect dual-axis load metrics for every container.

    Memory weight (memory_bytes):
      1. anon + shmem from cgroup memory.stat   — actual working set,
         excludes reclaimable page cache
      2. limits.memory                           — planning proxy
      3. Built-in estimate

    CPU weight (cpu_cores — average cores over container lifetime):
      1. state.cpu.usage_ns / uptime_seconds     — from incus list JSON,
         no extra subprocess, deterministic without two-sample polling
      2. limits.cpu integer                      — allocation cap as proxy
      3. Built-in estimate

    cpu_cores is a historical average, not instantaneous.  It is a sound
    NUMA placement signal: a container averaging 12 cores over its life is
    more CPU-hungry than one averaging 0.2, even without live sampling.
    The hysteresis threshold absorbs short-term variation.
    """
    out: dict[str, ContainerMetrics] = {}

    for c in containers:
        name: str = c["name"]
        running: bool = c.get("status") == "Running"
        state: dict[str, Any] = c.get("state") or {}
        estimated = False

        # ── memory ────────────────────────────────────────────────────────────
        mem_weight: int | None = None
        rss: int = 0

        if running:
            mem_weight = _anon_bytes(name)
            rss = _cgroup_int(name, "memory.current") or 0

        if mem_weight is None:
            raw_limit = cfg_get(name, "limits.memory")
            if raw_limit:
                mem_weight = _parse_memory_limit(raw_limit)
                estimated = estimated or (mem_weight is not None)

        if mem_weight is None:
            mb = RUNNING_MEM_ESTIMATE_MB if running else STOPPED_MEM_ESTIMATE_MB
            mem_weight = mb << 20
            estimated = True

        # ── CPU ───────────────────────────────────────────────────────────────
        cpu_cores: float | None = None

        if running:
            cpu_ns = (state.get("cpu") or {}).get("usage")
            if cpu_ns and cpu_ns > 0:
                created_at = c.get("created_at", "")
                try:
                    dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                    uptime_s = (datetime.now(timezone.utc) - dt).total_seconds()
                    if uptime_s > 60:  # ignore brand-new containers
                        cpu_cores = cpu_ns / 1e9 / uptime_s
                except (ValueError, TypeError):
                    pass

        if cpu_cores is None:
            raw_cpu = cfg_get(name, "limits.cpu")
            if raw_cpu and raw_cpu.isdigit():
                cpu_cores = float(raw_cpu)
                estimated = True

        if cpu_cores is None:
            cpu_cores = RUNNING_CPU_ESTIMATE_CORES if running else STOPPED_CPU_ESTIMATE_CORES
            estimated = True

        out[name] = ContainerMetrics(
            name=name,
            memory_bytes=mem_weight,
            cpu_cores=cpu_cores,
            rss_bytes=rss,
            is_estimated=estimated,
            is_running=running,
        )
    return out


# ── balancer ───────────────────────────────────────────────────────────────────

# Node capacities are read once and cached at module level the first time
# assign_smart runs, so repeated reconciler calls don't re-stat the fs.
_node_capacity_cache: dict[int, tuple[int, int]] = {}   # node → (mem_bytes, cpu_count)


def _node_capacity(node: int) -> tuple[int, int]:
    if node not in _node_capacity_cache:
        _node_capacity_cache[node] = (_node_mem_bytes(node), _node_cpu_count(node))
    return _node_capacity_cache[node]


def _node_pressure(
    placement: dict[str, int],
    metrics: dict[str, ContainerMetrics],
    nodes: list[int],
) -> dict[int, float]:
    """
    Normalised pressure score per node in [0, ∞).

    pressure(n) = MEM_WEIGHT × (sum_anon(n) / node_mem_total(n))
                + CPU_WEIGHT × (sum_cores(n) / node_cpu_count(n))

    Normalising against node capacity means a node with 128 GB and 64 cores
    is compared fairly against one with 128 GB and 32 cores — the score
    reflects utilisation fraction, not raw bytes or core-counts.
    """
    mem_sum:  dict[int, int]   = {n: 0   for n in nodes}
    cpu_sum:  dict[int, float] = {n: 0.0 for n in nodes}

    for cname, node in placement.items():
        m = metrics[cname]
        mem_sum[node] += m.memory_bytes
        cpu_sum[node] += m.cpu_cores

    scores: dict[int, float] = {}
    for n in nodes:
        node_mem, node_cpus = _node_capacity(n)
        mem_pressure = mem_sum[n] / max(node_mem, 1)
        cpu_pressure = cpu_sum[n] / max(node_cpus, 1)
        scores[n] = MEM_WEIGHT * mem_pressure + CPU_WEIGHT * cpu_pressure

    return scores


def assign_smart(
    containers: list[dict[str, Any]],
    nodes: list[int],
) -> tuple[dict[str, int], dict[str, ContainerMetrics]]:
    """
    Dual-metric NUMA balancer (memory + CPU) with hysteresis for running
    containers.

    Returns (placement, metrics) where placement maps each container name
    to its desired NUMA node.

    Placement decisions use a normalised pressure score:
        pressure(n) = MEM_WEIGHT × (anon_bytes / node_mem)
                    + CPU_WEIGHT × (avg_cores  / node_cpus)

    This prevents a node's large-but-reclaimable page cache from looking
    like genuine load, and accounts for CPU-hungry containers that have
    small memory footprints.

    Algorithm
    ---------
    Pass 1 — Pinned
        Non-negotiable; placed first so their weight anchors pressure.

    Pass 2 — Existing placements (read from limits.cpu.nodes)
        Loaded tentatively.  Running containers stay put unless Pass 4
        decides to move them.  Stopped containers are re-evaluated freely.

    Pass 3 — Unplaced containers
        Sorted by combined (mem + cpu) weight descending so the heaviest
        containers anchor node choice before smaller ones fill gaps.
        Each lands on the least-pressure node (alphabetical tie-break).

    Pass 4 — Rebalance review
        Iterates existing placements largest-pressure-first.  Running
        containers are only moved if the pressure delta between current
        and best alternative node exceeds RUNNING_HYSTERESIS, because
        moving a running container shifts only future allocations —
        existing warm pages stay until reclaim.  Stopped containers move
        freely.  Pressure is recomputed after each decision.
    """
    names = [c["name"] for c in containers]
    running_by_name = {c["name"]: c.get("status") == "Running" for c in containers}
    metrics = gather_metrics(containers)
    placement: dict[str, int] = {}

    def pressure() -> dict[int, float]:
        return _node_pressure(placement, metrics, nodes)

    def container_weight(name: str) -> float:
        """Scalar sort key combining both axes (unnormalised, for ordering)."""
        m = metrics[name]
        node_mem, node_cpus = _node_capacity(nodes[0])  # same hardware, same scale
        return MEM_WEIGHT * m.memory_bytes / node_mem + CPU_WEIGHT * m.cpu_cores / node_cpus

    # ── Pass 1: pinned ─────────────────────────────────────────────────────────
    for name in sorted(names):
        if name in PINNED and PINNED[name] in nodes:
            placement[name] = PINNED[name]

    # ── Pass 2: load existing assignments tentatively ──────────────────────────
    existing: dict[str, int] = {}
    for name in sorted(names):
        if name in placement:
            continue
        raw = cfg_get(name, "limits.cpu.nodes")
        if raw.isdigit() and int(raw) in nodes:
            n = int(raw)
            existing[name] = n
            placement[name] = n

    # ── Pass 3: place containers with no prior assignment ──────────────────────
    unplaced = sorted(
        (n for n in names if n not in placement),
        key=container_weight,
        reverse=True,
    )
    for name in unplaced:
        p = pressure()
        best = min(nodes, key=lambda k: (p[k], k))
        placement[name] = best

    # ── Pass 4: rebalance review for existing placements ──────────────────────
    for name in sorted(existing, key=container_weight, reverse=True):
        cur_node = placement[name]
        p = pressure()

        other_nodes = [nd for nd in nodes if nd != cur_node]
        if not other_nodes:
            continue

        best_other = min(other_nodes, key=lambda k: (p[k], k))

        if p[best_other] >= p[cur_node]:
            continue  # already on the lighter side

        if running_by_name[name]:
            imbalance = p[cur_node] - p[best_other]
            if imbalance <= RUNNING_HYSTERESIS:
                continue

            m = metrics[name]
            print(
                f"  [{name}] rebalancing running container "
                f"node {cur_node} → {best_other}  "
                f"pressure delta {imbalance:.3f}  "
                f"({_fmt_mb(m.memory_bytes)} anon, {m.cpu_cores:.1f} cores avg)"
            )
        # Stopped: no warm pages, move freely.

        placement[name] = best_other

    return placement, metrics


# ── raw.lxc helpers ────────────────────────────────────────────────────────────

MEMS_LINE_PREFIX = "lxc.cgroup2.cpuset.mems="
HOOK_LINE_PREFIX = "lxc.hook.start"

HOOK_BY_MOUNT: list[tuple[str, list[str]]] = [
    ("/opt/clat-inject", [
        "lxc.hook.start = /net-inject/net-wait",
        "lxc.hook.start = /clat-inject/clat-init",
    ]),
    ("/opt/net-inject", [
        "lxc.hook.start = /net-inject/net-wait",
    ]),
]


def desired_hook_lines(devices: dict[str, Any]) -> list[str]:
    sources = {d.get("source") for d in devices.values() if d.get("type") == "disk"}
    for source, lines in HOOK_BY_MOUNT:
        if source in sources:
            return list(lines)
    return []


def desired_raw_lxc(existing: str, target: str, hook_lines: list[str]) -> str:
    """Rewrite raw.lxc, replacing cpuset.mems and hook lines in-place."""
    lines = [ln for ln in existing.splitlines() if ln.strip()]
    lines = [ln for ln in lines if not ln.startswith(MEMS_LINE_PREFIX)]
    lines = [ln for ln in lines if not ln.lstrip().startswith(HOOK_LINE_PREFIX)]
    lines.extend(hook_lines)
    lines.append(f"{MEMS_LINE_PREFIX}{target}")
    return "\n".join(lines)


def live_cgroup_mems(name: str, target: str) -> bool:
    """Best-effort: write cpuset.mems to the running container's cgroup."""
    try:
        with open(f"/sys/fs/cgroup/lxc.payload.{name}/cpuset.mems", "w") as f:
            f.write(target)
        return True
    except OSError:
        return False


# ── reconcile ──────────────────────────────────────────────────────────────────

def reconcile_limits(name: str, m: ContainerMetrics) -> bool:
    """Set limits.cpu and limits.memory if not already configured.

    Fills in *missing* limits only — never lowers or removes existing ones.
    Returns True if any change was made.
    """
    overrides = RESOURCE_OVERRIDES.get(name, {})
    changed = False

    # ── CPU: nudge thread-pool floor and GC heap count ────────────────────────
    if "cpu" not in overrides:
        target_cpu: int | None = _cpu_anchor(m.cpu_cores) if m.cpu_cores > 0 else None
        cpu_label = f"avg {m.cpu_cores:.1f}c → next even"
    elif overrides["cpu"] is None:
        target_cpu = None
        cpu_label = ""
    else:
        target_cpu = int(overrides["cpu"])  # type: ignore[arg-type]
        cpu_label = "override"

    if target_cpu is not None:
        cur = cfg_get(name, "limits.cpu")
        if not cur:
            cfg_set(name, "limits.cpu", str(target_cpu))
            print(f"  {name}: limits.cpu -> {target_cpu}  ({cpu_label})")
            changed = True

    # ── Memory: generous ceiling to give GC a collection reference ────────────
    if "memory" not in overrides:
        if m.rss_bytes > 0:
            ab = _memory_anchor_bytes(m.rss_bytes)
            target_mem: str | None = f"{ab >> 30}GiB"
            mem_label = f"rss {_fmt_mb(m.rss_bytes)} → next GiB anchor"
        else:
            target_mem = None
            mem_label = ""
    elif overrides["memory"] is None:
        target_mem = None
        mem_label = ""
    else:
        target_mem = str(overrides["memory"])
        mem_label = "override"

    if target_mem is not None:
        cur = cfg_get(name, "limits.memory")
        if not cur:
            cfg_set(name, "limits.memory", target_mem)
            print(f"  {name}: limits.memory -> {target_mem}  ({mem_label})")
            changed = True

    return changed


def reconcile(
    name: str, target_node: int, devices: dict[str, Any], running: bool
) -> tuple[bool, bool]:
    """Apply desired tuning. Returns (changed, mem_pages_stale)."""
    target = str(target_node)
    changed = False
    mem_pages_stale = False

    # 1. Clear legacy explicit cpuset; rely on cpu.nodes instead.
    cur_cpu = cfg_get(name, "limits.cpu")
    if cur_cpu and ("," in cur_cpu or "-" in cur_cpu):
        cfg_unset(name, "limits.cpu")
        print(f"  {name}: cleared limits.cpu={cur_cpu!r}")
        changed = True

    # 2. CPU node pinning (incus-native).
    cur_cpu_nodes = cfg_get(name, "limits.cpu.nodes")
    if cur_cpu_nodes != target:
        cfg_set(name, "limits.cpu.nodes", target)
        print(f"  {name}: limits.cpu.nodes {cur_cpu_nodes or '-'} -> {target}")
        changed = True

    # 3. Memory node pinning + hook chain via raw.lxc.
    hooks = desired_hook_lines(devices)
    cur_raw = cfg_get(name, "raw.lxc")
    new_raw = desired_raw_lxc(cur_raw, target, hooks)
    if new_raw != cur_raw:
        cfg_set(name, "raw.lxc", new_raw)
        what = []
        if MEMS_LINE_PREFIX + target not in cur_raw:
            what.append(f"cpuset.mems={target}")
        cur_hooks = [
            ln for ln in cur_raw.splitlines()
            if ln.lstrip().startswith(HOOK_LINE_PREFIX)
        ]
        if cur_hooks != hooks:
            what.append(
                f"hooks={[h.split('=', 1)[1].strip() for h in hooks] or 'none'}"
            )
        print(f"  {name}: raw.lxc {' + '.join(what) or 'updated'}")
        changed = True

    # 4. Live cgroup write — new allocations land on the target node now.
    if running:
        cur_live = ""
        try:
            with open(f"/sys/fs/cgroup/lxc.payload.{name}/cpuset.mems") as f:
                cur_live = f.read().strip()
        except OSError:
            pass
        if cur_live and cur_live != target:
            if live_cgroup_mems(name, target):
                print(f"  {name}: live cpuset.mems {cur_live} -> {target}")
                changed = True
                mem_pages_stale = True
        elif not cur_live:
            live_cgroup_mems(name, target)

    return changed, mem_pages_stale


# ── main ───────────────────────────────────────────────────────────────────────

def _fmt_mb(b: int) -> str:
    mb = b / (1 << 20)
    if mb >= 1024:
        return f"{mb / 1024:>6.1f} GB"
    return f"{mb:>6.0f} MB"


def main() -> int:
    nodes = numa_nodes()
    if len(nodes) < 2:
        print(f"Only {len(nodes)} NUMA node(s); nothing to balance.")
        return 0

    containers = list_containers()
    names = [c["name"] for c in containers]
    devices_by_name = {c["name"]: (c.get("expanded_devices") or {}) for c in containers}
    running_by_name = {c["name"]: (c.get("status") == "Running")    for c in containers}
    configs_by_name = {c["name"]: (c.get("config") or {})           for c in containers}

    desired, metrics = assign_smart(containers, nodes)

    # ── diagnostics ────────────────────────────────────────────────────────────
    pressures = _node_pressure(desired, metrics, nodes)

    print(f"NUMA nodes: {nodes}")
    for n in nodes:
        node_mem, node_cpus = _node_capacity(n)
        print(f"  Node {n}: {_fmt_mb(node_mem)} RAM  {node_cpus} CPUs")
    print()

    hdr = (
        f"{'Container':<24} {'State':<8} {'Node':>4}  {'Anon':>9}  {'RSS':>9}"
        f"  {'CPU avg':>7}  {'Src':<10}  {'Mem ceil':>10}  {'%':>5}  {'CPU':>4}"
    )
    print(hdr)
    print("-" * len(hdr))
    for name in sorted(names):
        m = metrics[name]
        cfg = configs_by_name[name]
        state   = "running" if m.is_running else "stopped"
        pin     = " [P]" if name in PINNED else ""
        src_tag = (m.source_tag + pin)
        rss_col = _fmt_mb(m.rss_bytes) if m.rss_bytes else "        -"
        mem_h, cpu_h = _limit_hints(name, m, cfg)
        ceil_b  = _memory_ceiling_bytes(name, m, cfg)
        if ceil_b and m.rss_bytes:
            pct_col = f"{100 * m.rss_bytes / ceil_b:>4.0f}%"
        else:
            pct_col = "    -"
        print(
            f"  {name:<22} {state:<8} {desired[name]:>4}  "
            f"{_fmt_mb(m.memory_bytes):>9}  {rss_col:>9}  "
            f"{m.cpu_cores:>6.1f}c  {src_tag:<10}  "
            f"{mem_h:>10}  {pct_col}  {cpu_h:>4}"
        )
    print("-" * len(hdr))
    for n in nodes:
        p = pressures[n]
        node_mem, node_cpus = _node_capacity(n)
        node_anon = sum(
            metrics[nm].memory_bytes for nm, nd in desired.items() if nd == n
        )
        node_cpu = sum(
            metrics[nm].cpu_cores for nm, nd in desired.items() if nd == n
        )
        print(
            f"  Node {n}: pressure {p:.3f}  "
            f"anon {_fmt_mb(node_anon)}/{_fmt_mb(node_mem)}  "
            f"cpu {node_cpu:.1f}/{node_cpus} cores"
        )

    if len(nodes) == 2:
        n0, n1 = nodes[0], nodes[1]
        delta = abs(pressures[n0] - pressures[n1])
        print(f"  Pressure delta: {delta:.3f}  (hysteresis threshold {RUNNING_HYSTERESIS:.2f})")
    print()

    # ── apply ─────────────────────────────────────────────────────────────────
    any_changes = False
    stale_pages: list[str] = []
    for name in sorted(names):
        ch, pages_stale = reconcile(
            name, desired[name], devices_by_name[name], running_by_name[name]
        )
        ch |= reconcile_limits(name, metrics[name])
        any_changes |= ch
        if pages_stale:
            stale_pages.append(name)

    if not any_changes:
        print("All containers already match desired tuning.")
    if stale_pages:
        print(
            "\nMemory node changed on running container(s). New allocations"
            " will land on the target node, but already-allocated pages"
            " remain until reclaimed or faulted. Restart to migrate fully:"
            f" {', '.join(stale_pages)}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())