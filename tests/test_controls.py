import unittest

from osint_cyber.controls import evaluate_asset_controls, summarize_controls


class AssetControlTests(unittest.TestCase):
    def test_detects_missing_owner(self):
        findings = evaluate_asset_controls([
            {"asset_id": "a-1", "address": "app.example.org", "environment": "test"}
        ])
        self.assertEqual(findings[0]["control_id"], "INV-001")

    def test_detects_telnet_on_production(self):
        findings = evaluate_asset_controls(
            [{"asset_id": "prod", "address": "app.example.org", "environment": "production", "owner": "Ops"}],
            {"prod": [{"service": "telnet", "port": 23}]},
        )
        self.assertTrue(any(row["control_id"] == "NET-001" for row in findings))

    def test_http_without_https_is_flagged(self):
        findings = evaluate_asset_controls(
            [{"asset_id": "web", "address": "web.example.org", "environment": "production", "owner": "Web"}],
            {"web": [{"service": "http", "port": 80}]},
        )
        self.assertTrue(any(row["control_id"] == "WEB-001" for row in findings))

    def test_http_with_https_does_not_raise_http_control(self):
        findings = evaluate_asset_controls(
            [{"asset_id": "web", "address": "web.example.org", "environment": "production", "owner": "Web"}],
            {"web": [{"service": "http", "port": 80}, {"service": "https", "port": 443}]},
        )
        self.assertFalse(any(row["control_id"] == "WEB-001" for row in findings))

    def test_duplicate_asset_id_rejected(self):
        item = {"asset_id": "same", "address": "a.example.org"}
        with self.assertRaises(ValueError):
            evaluate_asset_controls([item, item])

    def test_summary_counts_levels_and_controls(self):
        findings = evaluate_asset_controls([
            {"asset_id": "a", "address": "a.example.org", "environment": "test"}
        ])
        summary = summarize_controls(findings)
        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["by_level"]["medium"], 1)
        self.assertEqual(summary["evaluation"], "metadata_and_observation_based")


if __name__ == "__main__":
    unittest.main()
