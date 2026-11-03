import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BACKEND = ROOT / "msfconsole (1).py"
spec = importlib.util.spec_from_file_location("osint_backend", BACKEND)
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)


class ScopeTests(unittest.TestCase):
    def test_localhost_is_in_default_scope(self):
        self.assertEqual(backend.normalize_target("localhost"), "localhost")
        self.assertEqual(backend.normalize_target("127.0.0.1"), "127.0.0.1")

    def test_http_url_normalizes_to_hostname(self):
        self.assertEqual(backend.normalize_target("http://localhost:8080/path"), "localhost")

    def test_public_host_is_rejected_by_default(self):
        with self.assertRaises(backend.ScopeError):
            backend.normalize_target("example.com")

    def test_url_credentials_are_rejected(self):
        with self.assertRaises(backend.ScopeError):
            backend.normalize_target("https://user:pass@localhost/")

    def test_invalid_target_is_rejected(self):
        with self.assertRaises(backend.ScopeError):
            backend.normalize_target("bad host")


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.client = backend.app.test_client()

    def test_health_endpoint(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "ok")

    def test_scan_requires_json_target(self):
        response = self.client.post("/api/scan", json={})
        self.assertEqual(response.status_code, 400)

    def test_scan_rejects_out_of_scope_host(self):
        response = self.client.post("/api/scan", json={"target": "example.com"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("OSINT_ALLOWED_TARGETS", response.json["error"])

    def test_nmap_grepable_output_is_parsed(self):
        from unittest.mock import patch
        output = "Host: 127.0.0.1 () Ports: 22/open/tcp//ssh///,80/open/tcp//http///"
        fake = type("Completed", (), {"returncode": 0, "stdout": output, "stderr": ""})()
        with patch.object(backend.shutil, "which", return_value="/usr/bin/nmap"), \
             patch.object(backend.subprocess, "run", return_value=fake):
            result = backend.scan_ports("127.0.0.1")
        self.assertEqual([item["port"] for item in result], [22, 80])
        self.assertEqual(result[0]["protocol"], "tcp")
        self.assertEqual(result[0]["service"], "ssh")

    def test_analyze_returns_defensive_guidance(self):
        response = self.client.post(
            "/api/analyze",
            json={"scan_results": [{"port": 23, "service": "telnet"}]},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Replace Telnet", response.json["recommendations"][0]["recommendation"])

    def test_analyze_rejects_oversized_list(self):
        response = self.client.post("/api/analyze", json={"scan_results": [{}] * 1001})
        self.assertEqual(response.status_code, 400)

    def test_asset_api_create_list_update_delete(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from osint_cyber.storage import AssetStore

        with tempfile.TemporaryDirectory() as directory:
            store = AssetStore(Path(directory) / "test.sqlite3")
            with patch.object(backend, "ASSET_STORE", store):
                payload = {
                    "asset_id": "api-asset-1",
                    "name": "Local app",
                    "asset_type": "web_app",
                    "address": "localhost",
                    "environment": "test",
                    "criticality": "low",
                }
                created = self.client.post("/api/assets", json=payload)
                self.assertEqual(created.status_code, 201)
                listed = self.client.get("/api/assets")
                self.assertEqual(listed.status_code, 200)
                self.assertEqual(listed.json["total"], 1)
                changed = self.client.patch(
                    "/api/assets/api-asset-1", json={"criticality": "high"}
                )
                self.assertEqual(changed.status_code, 200)
                self.assertEqual(changed.json["asset"]["criticality"], "high")
                deleted = self.client.delete("/api/assets/api-asset-1")
                self.assertEqual(deleted.status_code, 200)
                missing = self.client.get("/api/assets/api-asset-1")
                self.assertEqual(missing.status_code, 404)

    def test_cors_allows_configured_local_origin(self):
        response = self.client.get(
            "/api/health", headers={"Origin": "http://localhost:3000"}
        )
        self.assertEqual(
            response.headers.get("Access-Control-Allow-Origin"),
            "http://localhost:3000",
        )

    def test_cors_does_not_allow_arbitrary_origin(self):
        response = self.client.get(
            "/api/health", headers={"Origin": "https://attacker.invalid"}
        )
        self.assertIsNone(response.headers.get("Access-Control-Allow-Origin"))

    def test_preflight_is_supported(self):
        response = self.client.options(
            "/api/assets", headers={"Origin": "http://localhost:3000"}
        )
        self.assertIn(response.status_code, (200, 204))

    def test_remediation_plan_api_returns_planning_only_tasks(self):
        response = self.client.post("/api/remediation/plan", json={
            "assets": [{
                "asset_id": "owned-app",
                "address": "localhost",
                "environment": "production",
            }],
            "observations_by_asset": {
                "owned-app": [{"service": "telnet", "port": 23}],
            },
            "priorities_by_asset": {"owned-app": "high"},
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["summary"]["execution"], "planning_only")
        self.assertEqual(response.json["plan"][0]["priority"], "high")

    def test_controls_api_flags_production_telnet(self):
        response = self.client.post("/api/controls/evaluate", json={
            "assets": [{
                "asset_id": "authorized-prod",
                "address": "localhost",
                "environment": "production",
                "owner": "Platform",
            }],
            "observations_by_asset": {
                "authorized-prod": [{"service": "telnet", "port": 23}],
            },
        })
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any(
            finding["control_id"] == "NET-001"
            for finding in response.json["findings"]
        ))

    def test_exploit_and_brute_routes_are_not_exposed(self):
        for route in ("/api/exploit", "/api/brute"):
            response = self.client.post(route, json={"target": "localhost"})
            self.assertIn(response.status_code, (404, 405))


if __name__ == "__main__":
    unittest.main()
