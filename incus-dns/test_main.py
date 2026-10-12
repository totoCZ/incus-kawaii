import json
import tempfile
import subprocess
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from main import (
    DeletionScheduler,
    ServiceCnameState,
    TechnitiumClient,
    get_instance_ipv6,
    initial_sync,
)


class RecordingTechnitiumClient(TechnitiumClient):
    def __init__(self, state: ServiceCnameState):
        super().__init__(
            base_url="http://dns.invalid",
            token="test-token",
            zone="c.example.test",
            service_zone="s.example.test",
            service_cname_state=state,
        )
        self.calls: list[tuple[str, dict]] = []
        self.service_records: list[dict] = []
        # fqdn -> [{"ipAddress": ..., "ttl": ...}]
        self.aaaa: dict[str, list[dict]] = {}
        # When set, AAAA adds with ptr=true fail the way a token without
        # reverse-zone permissions does.
        self.deny_ptr = False
        self.soas: dict[str, dict] = {
            zone: {
                "primaryNameServer": f"dns.{zone}",
                "responsiblePerson": f"hostadmin@{zone}",
                "serial": 100,
                "refresh": 900,
                "retry": 300,
                "expire": 604800,
                "minimum": 900,
                "useSerialDateScheme": False,
            }
            for zone in (self.zone, self.service_zone)
        }

    @property
    def soa(self) -> dict:
        return self.soas[self.zone]

    def _request(self, path: str, params: dict) -> dict:
        self.calls.append((path, params.copy()))

        if path == "/api/zones/records/get":
            if params.get("type") == "SOA":
                # The real API returns the apex NS record alongside the SOA.
                soa = self.soas[params["zone"]]
                return {"status": "ok", "response": {"records": [
                    {"type": "NS", "rData": {"nameServer": f"dns.{params['zone']}"}},
                    {"type": "SOA", "rData": dict(soa)},
                ]}}
            if params.get("zone") == self.service_zone:
                return {"status": "ok", "response": {"records": self.service_records}}
            if str(params.get("listZone", "")).lower() == "true":
                records = [
                    {"name": fqdn, "type": "AAAA", "ttl": item["ttl"],
                     "rData": {"ipAddress": item["ipAddress"]}}
                    for fqdn, items in self.aaaa.items() for item in items
                ]
                return {"status": "ok", "response": {"records": records}}
            fqdn = params.get("domain")
            records = [
                {"name": fqdn, "type": "AAAA", "ttl": item["ttl"],
                 "rData": {"ipAddress": item["ipAddress"]}}
                for item in self.aaaa.get(fqdn, [])
            ]
            return {"status": "ok", "response": {"records": records}}

        if path == "/api/zones/records/add":
            if params.get("type") == "CNAME":
                self.service_records.append({
                    "type": "CNAME", "rData": {"cname": params["cname"]},
                })
            elif params.get("type") == "AAAA":
                if self.deny_ptr and str(params.get("ptr")).lower() == "true":
                    raise RuntimeError(
                        "Technitium error: {'status': 'error', 'errorMessage': "
                        "'Cannot update reverse zone to add PTR record: "
                        "access was denied.'}")
                self.aaaa.setdefault(params["domain"], []).append(
                    {"ipAddress": params["ipAddress"], "ttl": int(params["ttl"])})
            return {"status": "ok", "response": {"records": []}}

        if path == "/api/zones/records/update":
            if params.get("type") == "SOA":
                self.soas[params["zone"]].update(minimum=int(params["minimum"]))
            elif params.get("type") == "AAAA":
                for item in self.aaaa.get(params["domain"], []):
                    if item["ipAddress"] == params["ipAddress"]:
                        item["ttl"] = int(params["ttl"])
            return {"status": "ok", "response": {"records": []}}

        if path == "/api/zones/records/delete" and params.get("type") == "AAAA":
            self.aaaa[params["domain"]] = [
                item for item in self.aaaa.get(params["domain"], [])
                if item["ipAddress"] != params["ipAddress"]
            ]
            return {"status": "ok", "response": {"records": []}}

        return {"status": "ok", "response": {"records": []}}

    @property
    def cname_adds(self) -> list[dict]:
        return [params for path, params in self.calls
                if path == "/api/zones/records/add" and params.get("type") == "CNAME"]

    def paths(self) -> list[str]:
        return [path for path, _ in self.calls]

    def set_aaaa(self, label: str, ip: str, ttl: int = 3600) -> None:
        self.aaaa[f"{label}.{self.zone}"] = [{"ipAddress": ip, "ttl": ttl}]


class ServiceCnameTests(unittest.TestCase):
    def test_instance_query_timeout_does_not_crash_the_monitor(self):
        with patch("main.subprocess.check_output", side_effect=subprocess.TimeoutExpired("incus", 10)):
            self.assertIsNone(get_instance_ipv6("api"))

    def test_null_network_state_does_not_crash_the_monitor(self):
        payload = b'[{"name": "stopped-api", "state": {"network": null}}]'
        with patch("main.subprocess.check_output", return_value=payload):
            self.assertIsNone(get_instance_ipv6("stopped-api"))

    def test_initial_baseline_marks_existing_instances_without_dns_requests(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "cname-state.json"
            state = ServiceCnameState(state_path)
            state.initialize_existing_instances(["api", "postgresql"])

            self.assertTrue(state_path.exists())
            self.assertFalse(state.claim_creation("api"))
            self.assertFalse(state.claim_creation("postgresql"))
            self.assertTrue(state.claim_creation("new-service"))

    def test_cname_is_created_once_and_aaaa_sync_never_recreates_it(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "cname-state.json"
            client = RecordingTechnitiumClient(ServiceCnameState(state_path))

            client.seed_service_cname_on_creation("api")
            self.assertEqual(len(client.cname_adds), 1)
            self.assertEqual(client.cname_adds[0]["cname"], "api.c.example.test")

            # This models a restart/rebuild/address-change sync after an admin
            # has removed the alias: no CNAME API call may be made here.
            client.service_records.clear()
            client.upsert_aaaa("api", "fdcc:c99d:b6cf:10::42")
            self.assertEqual(len(client.cname_adds), 1)

            # Reloading the state (as happens on daemon restart) preserves the
            # one-time claim even when the CNAME no longer exists in DNS.
            reloaded = RecordingTechnitiumClient(ServiceCnameState(state_path))
            reloaded.seed_service_cname_on_creation("api")
            self.assertEqual(reloaded.cname_adds, [])

    def test_deleting_an_instance_releases_only_its_creation_claim(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state = ServiceCnameState(Path(temp_dir) / "cname-state.json")
            self.assertTrue(state.claim_creation("api"))
            self.assertFalse(state.claim_creation("api"))
            state.forget_deleted_instance("api")
            self.assertTrue(state.claim_creation("api"))


class NegativeCacheProtectionTests(unittest.TestCase):
    """The generator must never expose a negative answer it can avoid."""

    def make_client(self) -> RecordingTechnitiumClient:
        # None of these tests trigger CNAME seeding, so a never-written
        # state path is enough.
        state = ServiceCnameState(Path("/nonexistent-cname-state.json"))
        return RecordingTechnitiumClient(state)

    def test_address_change_adds_before_removing_stale(self):
        client = self.make_client()
        client.set_aaaa("mqtt", "fdcc::1")
        client.upsert_aaaa("mqtt", "fdcc::2")

        paths = client.paths()
        add_at = paths.index("/api/zones/records/add")
        delete_at = paths.index("/api/zones/records/delete")
        self.assertLess(add_at, delete_at, "new address must exist before old is removed")
        self.assertEqual(
            client.aaaa["mqtt.c.example.test"],
            [{"ipAddress": "fdcc::2", "ttl": 300}],
        )

    def test_ttl_only_change_updates_in_place_without_gap(self):
        client = self.make_client()
        client.set_aaaa("mqtt", "fdcc::1", ttl=3600)
        client.upsert_aaaa("mqtt", "fdcc::1")

        self.assertNotIn("/api/zones/records/add", client.paths())
        self.assertNotIn("/api/zones/records/delete", client.paths())
        update = [p for p in client.calls
                  if p[0] == "/api/zones/records/update" and p[1].get("type") == "AAAA"]
        self.assertEqual(len(update), 1)
        self.assertEqual(update[0][1]["ipAddress"], "fdcc::1")
        self.assertEqual(update[0][1]["ttl"], "300")
        self.assertEqual(client.aaaa["mqtt.c.example.test"][0]["ttl"], 300)

    def test_unchanged_record_is_skipped(self):
        client = self.make_client()
        client.set_aaaa("mqtt", "fdcc::1", ttl=300)
        client.upsert_aaaa("mqtt", "fdcc::1")
        self.assertEqual(client.paths(), ["/api/zones/records/get"])

    def test_enforce_negative_ttl_caps_soa_minimum(self):
        client = self.make_client()
        client.enforce_negative_ttl(60)

        soa_updates = [p for p in client.calls
                       if p[0] == "/api/zones/records/update" and p[1].get("type") == "SOA"]
        self.assertEqual(len(soa_updates), 2)  # zone + service zone
        for _, params in soa_updates:
            self.assertEqual(params["minimum"], "60")
            self.assertEqual(params["responsiblePerson"],
                             f"hostadmin@{params['zone']}")
            self.assertEqual(params["serial"], "100")
        self.assertEqual({zone: soa["minimum"] for zone, soa in client.soas.items()},
                         {"c.example.test": 60, "s.example.test": 60})

        # Idempotent: an already-capped zone is only re-read, never re-updated.
        client.enforce_negative_ttl(60)
        soa_updates_after = [p for p in client.calls
                             if p[0] == "/api/zones/records/update" and p[1].get("type") == "SOA"]
        self.assertEqual(len(soa_updates_after), len(soa_updates))

    def test_ptr_denial_still_adds_the_aaaa_record(self):
        client = self.make_client()
        client.deny_ptr = True
        client.upsert_aaaa("mqtt", "fdcc::1")

        self.assertEqual(client.aaaa["mqtt.c.example.test"],
                         [{"ipAddress": "fdcc::1", "ttl": 300}])
        adds = [params for path, params in client.calls
                if path == "/api/zones/records/add" and params.get("type") == "AAAA"]
        self.assertEqual(len(adds), 2)
        self.assertEqual(adds[0]["ptr"], "true")
        self.assertEqual(adds[1]["ptr"], "false")

    def test_non_ptr_errors_are_not_masked(self):
        client = self.make_client()
        client.deny_ptr = True
        with patch.object(client, "_request",
                          side_effect=RuntimeError("Technitium error: zone denied")):
            with self.assertRaises(RuntimeError):
                client.upsert_aaaa("mqtt", "fdcc::1")

    def test_initial_sync_survives_a_failing_instance(self):
        client = self.make_client()
        client.set_aaaa("bad", "fdcc::9")
        client.set_aaaa("good", "fdcc::1", ttl=300)

        def flaky_upsert(name, ipv6):
            if name == "bad":
                raise RuntimeError("Technitium error: boom")
            client.set_aaaa(name, ipv6, ttl=300)

        full_list = json.dumps([
            {"name": "bad", "status": "Running"},
            {"name": "good", "status": "Running"},
        ]).encode()
        bad_state = json.dumps([{"name": "bad", "state": {"network": {}}}]).encode()
        good_state = json.dumps([{
            "name": "good", "state": {"network": {"eth0": {"addresses": [
                {"family": "inet6", "scope": "global", "address": "fdcc::1"},
            ]}}},
        }]).encode()

        def fake_incus(argv, **kwargs):
            per_instance = {"bad": bad_state, "good": good_state}
            if argv[:2] == ["incus", "list"] and argv[2] == "--format":
                return full_list
            return per_instance[argv[2]]

        with patch("main.subprocess.check_output", side_effect=fake_incus), \
                patch.object(client, "upsert_aaaa", side_effect=flaky_upsert):
            initial_sync(client, {"incus": {"interface": "eth0"}})

        # "good" was still processed to completion.
        self.assertEqual(client.aaaa["good.c.example.test"][0]["ttl"], 300)

    def test_initial_sync_keeps_stopped_instances_and_removes_orphans(self):
        client = self.make_client()
        client.set_aaaa("api", "fdcc::1")
        client.set_aaaa("stopped-api", "fdcc::2")
        client.set_aaaa("ghost", "fdcc::3")

        full_list = json.dumps([
            {"name": "api", "status": "Running"},
            {"name": "stopped-api", "status": "Stopped"},
        ]).encode()
        api_state = json.dumps([{
            "name": "api",
            "state": {"network": {"eth0": {"addresses": [
                {"family": "inet6", "scope": "global", "address": "fdcc::1"},
            ]}}},
        }]).encode()

        def fake_incus(argv, **kwargs):
            if argv[:2] != ["incus", "list"]:
                raise AssertionError(f"unexpected command: {argv}")
            if argv[2] == "--format":          # full listing
                return full_list
            if argv[2] == "api":               # per-instance state query
                return api_state
            raise AssertionError(f"unexpected instance query: {argv}")

        with patch("main.subprocess.check_output", side_effect=fake_incus):
            initial_sync(client, {"incus": {"interface": "eth0"}})

        deletes = [params for path, params in client.calls
                   if path == "/api/zones/records/delete"]
        self.assertEqual(deletes, [{"zone": "c.example.test",
                                    "domain": "ghost.c.example.test",
                                    "type": "AAAA", "ipAddress": "fdcc::3"}])
        self.assertIn("stopped-api.c.example.test", client.aaaa)
        self.assertIn("api.c.example.test", client.aaaa)


class DeletionSchedulerTests(unittest.TestCase):
    class StubDns:
        def __init__(self):
            self.deleted: list[str] = []

        def delete_aaaa(self, name: str) -> None:
            self.deleted.append(name)

    def test_fire_keeps_record_when_instance_exists_again(self):
        stub = self.StubDns()
        scheduler = DeletionScheduler(stub, grace_seconds=0)
        with patch("main.instance_exists", return_value=True):
            scheduler._fire("mqtt")
        self.assertEqual(stub.deleted, [])

    def test_fire_deletes_when_instance_is_really_gone(self):
        stub = self.StubDns()
        scheduler = DeletionScheduler(stub, grace_seconds=0)
        with patch("main.instance_exists", return_value=False):
            scheduler._fire("mqtt")
        self.assertEqual(stub.deleted, ["mqtt"])

    def test_cancelled_deletion_never_fires(self):
        stub = self.StubDns()
        scheduler = DeletionScheduler(stub, grace_seconds=0.05)
        with patch("main.instance_exists", return_value=False):
            scheduler.schedule("mqtt")
            scheduler.cancel("mqtt")
            # give a would-be timer ample time to (wrongly) fire
            time.sleep(0.2)
        self.assertEqual(stub.deleted, [])

    def test_scheduled_deletion_fires_after_grace(self):
        stub = self.StubDns()
        scheduler = DeletionScheduler(stub, grace_seconds=0.05)
        with patch("main.instance_exists", return_value=False):
            scheduler.schedule("mqtt")
            timer = scheduler._timers.get("mqtt")
            if timer:
                timer.join(timeout=2)
        self.assertEqual(stub.deleted, ["mqtt"])


if __name__ == "__main__":
    unittest.main()
