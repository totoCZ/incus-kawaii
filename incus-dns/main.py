#!/usr/bin/env python3
"""
incus-dns-sync.py
Watches `incus monitor` for instance state changes and syncs
their IPv6 addresses as AAAA records into Technitium DNS
under the zone  x.c.domain.tld
"""

import json
import logging
import subprocess
import sys
import time
import tomllib
from pathlib import Path

import urllib.error
import urllib.parse
import urllib.request

# ──────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("incus-dns-sync")


# ──────────────────────────────────────────────────────────────
# Config loader
# ──────────────────────────────────────────────────────────────
DEFAULT_CONFIG_PATH = Path("/etc/incus-dns-sync/config.toml")

def load_config(path: Path = DEFAULT_CONFIG_PATH) -> dict:
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
    return cfg


# ──────────────────────────────────────────────────────────────
# Technitium API helpers
# ──────────────────────────────────────────────────────────────
class TechnitiumClient:
    def __init__(self, base_url: str, token: str, zone: str, ttl: int = 300, ptr: bool = True):
        self.base_url = base_url.rstrip("/")
        self.token    = token
        self.zone     = zone          # e.g.  x.c.domain.tld
        self.ttl      = ttl
        self.ptr      = ptr           # auto-create PTR record via Technitium

    def _request(self, path: str, params: dict) -> dict:
        params["token"] = self.token
        url = f"{self.base_url}{path}?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                if data.get("status") != "ok":
                    raise RuntimeError(f"Technitium error: {data}")
                return data
        except urllib.error.URLError as exc:
            raise ConnectionError(f"Cannot reach Technitium at {self.base_url}: {exc}") from exc

    def wait_until_ready(self, retries: int = 30, delay: float = 5.0) -> None:
        """Block until Technitium responds, useful right after container start."""
        log.info("Waiting for Technitium to become ready …")
        for attempt in range(1, retries + 1):
            try:
                self._request("/api/zones/list", {})
                log.info("Technitium is up and responding ✓")
                return
            except (ConnectionError, Exception) as exc:
                log.warning(
                    "Attempt %d/%d – not ready yet (%s). Retrying in %.0fs …",
                    attempt, retries, exc, delay,
                )
                time.sleep(delay)
        raise TimeoutError(
            f"Technitium did not become ready after {retries} attempts."
        )

    def list_records(self, fqdn: str) -> list[dict]:
        """Return all AAAA records for *fqdn* in the managed zone."""
        try:
            data = self._request(
                "/api/zones/records/get",
                {"domain": fqdn, "zone": self.zone, "type": "AAAA"},
            )
            return data.get("response", {}).get("records", [])
        except Exception:
            return []

    def upsert_aaaa(self, name: str, ipv6: str) -> None:
        """Add or update an AAAA record for *name* (short label, not FQDN)."""
        fqdn = f"{name}.{self.zone}"
        existing = self.list_records(fqdn)

        # If the exact record already exists, skip.
        for rec in existing:
            if rec.get("rData", {}).get("ipAddress") == ipv6:
                log.info("AAAA %s → %s already correct, skipping.", fqdn, ipv6)
                return

        # Delete stale records first (same name, different address).
        for rec in existing:
            old_ip = rec.get("rData", {}).get("ipAddress", "")
            log.info("Removing stale AAAA %s → %s", fqdn, old_ip)
            self._request(
                "/api/zones/records/delete",
                {
                    "zone":        self.zone,
                    "domain":      fqdn,
                    "type":        "AAAA",
                    "ipAddress":   old_ip,
                },
            )

        # Add the new record.
        log.info("Adding AAAA %s → %s (TTL %d, PTR %s)", fqdn, ipv6, self.ttl, self.ptr)
        self._request(
            "/api/zones/records/add",
            {
                "zone":           self.zone,
                "domain":         fqdn,
                "type":           "AAAA",
                "ttl":            str(self.ttl),
                "ipAddress":      ipv6,
                "ptr": "true" if self.ptr else "false",
            },
        )

    def delete_aaaa(self, name: str) -> None:
        """Remove *all* AAAA records for *name* from the zone."""
        fqdn     = f"{name}.{self.zone}"
        existing = self.list_records(fqdn)
        if not existing:
            log.info("No AAAA records for %s, nothing to delete.", fqdn)
            return
        for rec in existing:
            ip = rec.get("rData", {}).get("ipAddress", "")
            log.info("Deleting AAAA %s → %s", fqdn, ip)
            self._request(
                "/api/zones/records/delete",
                {
                    "zone":      self.zone,
                    "domain":    fqdn,
                    "type":      "AAAA",
                    "ipAddress": ip,
                },
            )


# ──────────────────────────────────────────────────────────────
# Incus helpers
# ──────────────────────────────────────────────────────────────
def get_instance_ipv6(instance_name: str, iface: str = "eth0") -> str | None:
    """
    Query `incus list <name> --format json` and extract the best global-scope
    IPv6 address on *iface*.  Prefers public (non-ULA) addresses over ULA
    (fc00::/7 — fcXX/fdXX prefixes).  Falls back to ULA if that's all there is.
    Returns None when no usable address is found yet.
    """
    try:
        raw = subprocess.check_output(
            ["incus", "list", instance_name, "--format", "json"],
            stderr=subprocess.PIPE,
            timeout=10,
        )
        instances = json.loads(raw)
    except (subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError) as e:
        log.warning("get_instance_ipv6(%s) failed: %s", instance_name, e)
        return None

    if not instances:
        return None

    state = instances[0].get("state") or {}
    networks = state.get("network") or {}

    # Try the specified iface first, then any other (skip loopback).
    candidates = [iface] + [k for k in networks if k not in (iface, "lo")]

    for nic in candidates:
        for addr in networks.get(nic, {}).get("addresses", []):
            if addr.get("family") != "inet6" or addr.get("scope") != "global":
                continue
            ip = addr["address"]
            # ULA only: fc00::/7  (fcXX or fdXX)
            if ip.lower().startswith(("fc", "fd")):
                return ip

    return None  # no ULA found


# ──────────────────────────────────────────────────────────────
# Monitor loop
# ──────────────────────────────────────────────────────────────
INTERESTING_ACTIONS = {
    "instance-started",
    "instance-stopped",
    "instance-deleted",
    "instance-updated",   # network changes can surface here
    "network-state",
}

def monitor(dns: TechnitiumClient, cfg: dict) -> None:
    """
    Stream `incus monitor --type lifecycle` and react to events.
    Reconnects automatically on process crash / socket error.
    """
    iface        = cfg.get("incus", {}).get("interface", "eth0")
    start_grace  = float(cfg.get("incus", {}).get("start_grace_seconds", 4))
    slaac_retry_interval = float(cfg.get("incus", {}).get("slaac_retry_interval", 3))
    slaac_retry_timeout  = float(cfg.get("incus", {}).get("slaac_retry_timeout", 30))

    log.info("Starting incus monitor loop …")
    while True:
        try:
            proc = subprocess.Popen(
                ["incus", "monitor", "--type", "lifecycle", "--format", "json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
            )
            log.info("incus monitor process started (pid %d)", proc.pid)

            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                action   = event.get("metadata", {}).get("action", "")
                source   = event.get("metadata", {}).get("source", "")
                # source looks like  /1.0/instances/mycontainer
                name = source.split("/")[-1] if source else ""

                if not name or action not in INTERESTING_ACTIONS:
                    continue

                log.info("Event: %s  instance: %s", action, name)

                if action in ("instance-stopped", "instance-deleted"):
                    dns.delete_aaaa(name)

                elif action in ("instance-started", "instance-updated", "network-state"):
                    if action == "instance-started":
                        log.debug("Waiting %.0fs for %s to acquire IPv6 …", start_grace, name)
                        time.sleep(start_grace)

                    ipv6 = get_instance_ipv6(name, iface)
                    if ipv6:
                        dns.upsert_aaaa(name, ipv6)
                    elif action == "instance-started":
                        # SLAAC may not have completed yet; poll until we get an address.
                        deadline = time.monotonic() + slaac_retry_timeout
                        while time.monotonic() < deadline:
                            time.sleep(slaac_retry_interval)
                            ipv6 = get_instance_ipv6(name, iface)
                            if ipv6:
                                dns.upsert_aaaa(name, ipv6)
                                break
                            log.debug("Still no IPv6 for %s, retrying …", name)
                        else:
                            log.warning("No global IPv6 found for %s after %.0fs, giving up.", name, slaac_retry_timeout)
                    else:
                        log.warning("No global IPv6 found for %s, will retry on next event.", name)

            proc.wait()
            stderr_out = proc.stderr.read().strip()
            log.warning(
                "incus monitor exited (code %s)%s. Restarting in 5 s …",
                proc.returncode,
                f": {stderr_out}" if stderr_out else "",
            )
            time.sleep(5)

        except FileNotFoundError:
            log.error("`incus` binary not found. Retrying in 30 s …")
            time.sleep(30)
        except KeyboardInterrupt:
            log.info("Interrupted, shutting down.")
            break


# ──────────────────────────────────────────────────────────────
# Initial full sync  (run once on startup)
# ──────────────────────────────────────────────────────────────
def initial_sync(dns: TechnitiumClient, cfg: dict) -> None:
    """
    Walk all running instances and ensure their DNS records are
    correct before entering the event loop.
    """
    iface = cfg.get("incus", {}).get("interface", "eth0")
    log.info("Running initial full sync …")
    try:
        raw = subprocess.check_output(
            ["incus", "list", "--format", "json"],
            stderr=subprocess.PIPE,
            timeout=15,
        )
        instances = json.loads(raw)
    except Exception as exc:
        log.warning("Could not list instances for initial sync: %s", exc)
        return

    for inst in instances:
        name   = inst.get("name", "")
        status = inst.get("status", "").lower()
        if not name:
            continue
        if status == "running":
            ipv6 = get_instance_ipv6(name, iface)
            if ipv6:
                dns.upsert_aaaa(name, ipv6)
            else:
                log.warning("Running instance %s has no global IPv6 yet.", name)
        else:
            # Remove DNS for stopped/frozen instances.
            dns.delete_aaaa(name)

    log.info("Initial sync complete.")


# ──────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────
def main() -> None:
    config_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_CONFIG_PATH
    cfg = load_config(config_path)

    tech_cfg = cfg["technitium"]
    dns = TechnitiumClient(
        base_url = tech_cfg["url"],
        token    = tech_cfg["api_token"],
        zone     = tech_cfg["zone"],
        ttl      = int(tech_cfg.get("ttl", 300)),
        ptr      = bool(tech_cfg.get("create_ptr", True)),
    )

    # Block until Technitium (which itself lives in a container) is reachable.
    wait_cfg = tech_cfg.get("wait", {})
    dns.wait_until_ready(
        retries = int(wait_cfg.get("retries", 36)),
        delay   = float(wait_cfg.get("delay_seconds", 5)),
    )

    initial_sync(dns, cfg)
    monitor(dns, cfg)


if __name__ == "__main__":
    main()
