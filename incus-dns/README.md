# incus-dns

Synchronizes Incus instance IPv6 addresses with Technitium DNS.

## Features
- Watches `incus monitor` for instance lifecycle events.
- Automatically creates and updates AAAA records in a specified Technitium DNS zone.
- Lightweight Python service.

## Configuration
Configuration is handled via `pyproject.toml` or a dedicated config file (see `main.py`).
