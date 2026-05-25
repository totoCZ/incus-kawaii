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
  Containers listed in PINNED go to their assigned node; all others get a
  stable placement: existing assignments are preserved, and unassigned
  containers are spread across nodes by count (least-loaded, alphabetical
  tie-break).

Side effect: clears legacy explicit `limits.cpu` cpusets (commas/ranges)
so the cpuset is governed by limits.cpu.nodes alone. Integer values of
limits.cpu (cpu count caps) are left alone.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

# Only list containers whose placement must be specific.
# Everything else gets balanced automatically.
PINNED: dict[str, int] = {
    "geth": 0,
    "nimbus": 1,
    "ingress": 0,
}


def run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


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
    data = json.loads(run(["incus", "list", "--format", "json"]))
    return data


def cfg_get(name: str, key: str) -> str:
    try:
        return run(["incus", "config", "get", name, key]).strip()
    except subprocess.CalledProcessError:
        return ""


def cfg_set(name: str, key: str, value: str) -> None:
    subprocess.run(["incus", "config", "set", name, f"{key}={value}"], check=True)


def cfg_unset(name: str, key: str) -> None:
    subprocess.run(["incus", "config", "unset", name, key], check=True)


def assign(names: list[str], nodes: list[int]) -> tuple[dict[str, int], dict[int, int]]:
    """Return desired node for each container."""
    desired: dict[str, int] = {}
    counts: dict[int, int] = {n: 0 for n in nodes}

    # Pass 1: pinned overrides + preserve existing assignments.
    for name in sorted(names):
        if name in PINNED and PINNED[name] in nodes:
            n = PINNED[name]
        else:
            existing = cfg_get(name, "limits.cpu.nodes")
            if existing.isdigit() and int(existing) in nodes:
                n = int(existing)
            else:
                continue
        desired[name] = n
        counts[n] += 1

    # Pass 2: balance the rest onto the least-loaded node.
    for name in sorted(names):
        if name in desired:
            continue
        n = min(nodes, key=lambda k: (counts[k], k))
        desired[name] = n
        counts[n] += 1

    return desired, counts


MEMS_LINE_PREFIX = "lxc.cgroup2.cpuset.mems="
HOOK_LINE_PREFIX = "lxc.hook.start"

# Mapping from a disk-device source path to the ordered list of
# lxc.hook.start lines we install when that mount is present on the
# container. First match wins. Multiple hooks are allowed: LXC runs
# them in order inside the container's namespace before exec'ing the
# OCI cmd, so chaining net-wait → clat-init brings up CLAT only after
# the network is ready.
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
    """Rewrite raw.lxc:
      - replace any lxc.cgroup2.cpuset.mems= line with the new target
      - replace any lxc.hook.start line(s) with our chosen hook chain
        (or remove, if the container has no eligible mount)
      - preserve every other line verbatim
    """
    lines = [ln for ln in existing.splitlines() if ln.strip()]
    lines = [ln for ln in lines if not ln.startswith(MEMS_LINE_PREFIX)]
    lines = [ln for ln in lines if not ln.lstrip().startswith(HOOK_LINE_PREFIX)]
    lines.extend(hook_lines)
    lines.append(f"{MEMS_LINE_PREFIX}{target}")
    return "\n".join(lines)


def live_cgroup_mems(name: str, target: str) -> bool:
    """Best-effort: write cpuset.mems to the running container's cgroup so
    the change takes effect immediately. Returns True if written."""
    path = f"/sys/fs/cgroup/lxc.payload.{name}/cpuset.mems"
    try:
        with open(path, "w") as f:
            f.write(target)
        return True
    except OSError:
        return False


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
            what.append(f"hooks={[h.split('=',1)[1].strip() for h in hooks] or 'none'}")
        print(f"  {name}: raw.lxc {' + '.join(what) or 'updated'}")
        changed = True

    # 4. Live cgroup write so new allocations land on the target node now.
    #    Existing allocated pages stay put until faulted/reclaimed.
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


def main() -> int:
    nodes = numa_nodes()
    if len(nodes) < 2:
        print(f"Only {len(nodes)} NUMA node(s); nothing to balance.")
        return 0

    containers = list_containers()
    names = [c["name"] for c in containers]
    devices_by_name = {c["name"]: (c.get("expanded_devices") or {}) for c in containers}
    running_by_name = {c["name"]: (c.get("status") == "Running") for c in containers}

    desired, counts = assign(names, nodes)

    print(f"NUMA nodes: {nodes}")
    print(f"Placement: {dict(sorted(desired.items()))}")
    print(f"Per-node counts: {counts}\n")

    any_changes = False
    stale_pages: list[str] = []
    for name in sorted(names):
        ch, pages_stale = reconcile(
            name, desired[name], devices_by_name[name], running_by_name[name]
        )
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
