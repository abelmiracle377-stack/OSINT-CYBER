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

    def test_exploit_and_brute_routes_are_not_exposed(self):
        for route in ("/api/exploit", "/api/brute"):
            response = self.client.post(route, json={"target": "localhost"})
            self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
