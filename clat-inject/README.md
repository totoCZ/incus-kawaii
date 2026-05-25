# clat-inject

CLAT (Customer-side Translator) injection for Incus containers. This enables IPv4 outbound connectivity on IPv6-only hosts using NAT64 (64:ff9b::/96).

## Contents
- **clat-init.c**: Static C replacement for the start hook. It derives a CLAT address, configures the `tundra` translator, and sets necessary sysctls (`proxy_ndp`, `forwarding`).
- **np_proxy.c**: Static helper to add IPv6 proxy NDP entries via netlink.
- **tundra**: The core NAT64/CLAT translator binary.
- **tundra.conf.tmpl**: Configuration template for `tundra`.
- **INJECT.txt**: Detailed documentation on manual injection steps and prerequisites.

## Usage
Typically managed via `incus-tune.py` which installs the required hooks and mounts.
