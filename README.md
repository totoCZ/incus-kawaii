# Incus Kawaii

A collection of utilities and hooks for tuning and extending Incus containers, with a focus on OCI compatibility, NUMA optimization, and IPv6-only environments.

## Components

### [incus-tune.py](incus-tune.py)
A reconciler script for Incus container tuning. It automates:
* **NUMA Placement:** Pins containers (CPU and memory) to a single NUMA node.
* **Network Hooks:** Manages `raw.lxc` hooks for network initialization, specifically ensuring CLAT support when needed.

### [clat-inject/](clat-inject/)
Provides CLAT (Customer-side Translator) injection for containers on IPv6-only hosts with NAT64.
* **clat-init:** A static C tool that replaces shell scripts to bring up the `tundra` NAT64 translator inside a container.
* **np_proxy:** A static helper to add IPv6 proxy NDP entries via netlink.
* **tundra:** A NAT64/CLAT translator (binary and configuration template).

### [incus-dns/](incus-dns/)
Synchronizes Incus instance IPv6 addresses with Technitium DNS by watching `incus monitor` events and updating AAAA records.

### [net-inject/](net-inject/)
Network synchronization tools for OCI containers.
* **net-wait:** A static C tool designed as an LXC start hook. It ensures a container's IPv6 default route and `/etc/resolv.conf` are ready before the main application starts, preventing race conditions in OCI entrypoints.
