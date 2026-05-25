# net-inject

Network synchronization utilities for Incus OCI containers.

## Contents
- **net-wait.c**: A static C tool designed to be used as an `lxc.hook.start`. It blocks the container startup until a default IPv6 route is present and `/etc/resolv.conf` is populated, ensuring OCI entrypoints have working network connectivity.

## Build
Run `make` in this directory to produce the static `net-wait` binary.
