import tempfile
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from main import ServiceCnameState, TechnitiumClient, get_instance_ipv6


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

    def _request(self, path: str, params: dict) -> dict:
        self.calls.append((path, params.copy()))
        if path == "/api/zones/records/get" and params["zone"] == self.service_zone:
            return {"status": "ok", "response": {"records": self.service_records}}
        if path == "/api/zones/records/add" and params.get("type") == "CNAME":
            self.service_records.append({
                "type": "CNAME", "rData": {"cname": params["cname"]},
            })
        return {"status": "ok", "response": {"records": []}}

    @property
    def cname_adds(self) -> list[dict]:
        return [params for path, params in self.calls
                if path == "/api/zones/records/add" and params.get("type") == "CNAME"]


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


if __name__ == "__main__":
    unittest.main()
