import unittest

from osint_cyber.remediation import build_remediation_plan, summarize_plan


class RemediationPlanTests(unittest.TestCase):
    def setUp(self):
        self.assets = [
            {"asset_id": "prod-1", "address": "app.example.org", "environment": "production"},
            {"asset_id": "dev-1", "address": "dev.example.org", "environment": "development"},
        ]
        self.observations = {
            "prod-1": [
                {"service": "telnet", "port": 23},
                {"service": "https", "port": 443},
                {"service": "telnet", "port": 23},
            ],
            "dev-1": [{"service": "unknown-service", "port": 9999}],
        }

    def test_builds_tasks_with_service_guidance(self):
        tasks = build_remediation_plan(
            self.assets, self.observations,
            {"prod-1": "critical", "dev-1": "low"},
        )
        self.assertEqual(len(tasks), 3)
        telnet = next(task for task in tasks if task["service"] == "telnet")
        self.assertIn("SSH", telnet["action"])
        self.assertEqual(telnet["priority"], "critical")
        self.assertEqual(telnet["status"], "open")

    def test_deduplicates_same_service_and_port(self):
        tasks = build_remediation_plan(self.assets, self.observations)
        self.assertEqual(sum(task["service"] == "telnet" for task in tasks), 1)

    def test_unknown_service_gets_safe_generic_guidance(self):
        tasks = build_remediation_plan(self.assets, self.observations)
        unknown = next(task for task in tasks if task["asset_id"] == "dev-1")
        self.assertIn("service owner", unknown["action"].lower())

    def test_priority_sorting(self):
        tasks = build_remediation_plan(
            self.assets, self.observations,
            {"prod-1": "critical", "dev-1": "low"},
        )
        self.assertEqual(tasks[0]["priority"], "critical")
        self.assertEqual(tasks[-1]["priority"], "low")

    def test_stable_task_id(self):
        tasks = build_remediation_plan(self.assets, self.observations)
        telnet = next(task for task in tasks if task["service"] == "telnet")
        self.assertEqual(telnet["task_id"], "prod-1:23:telnet")

    def test_rejects_invalid_port(self):
        with self.assertRaises(ValueError):
            build_remediation_plan(
                self.assets, {"prod-1": [{"service": "ssh", "port": 70000}]}
            )

    def test_rejects_duplicate_asset_ids(self):
        with self.assertRaises(ValueError):
            build_remediation_plan(
                [self.assets[0], self.assets[0]], self.observations
            )

    def test_rejects_invalid_priority(self):
        with self.assertRaises(ValueError):
            build_remediation_plan(
                self.assets, self.observations, {"prod-1": "urgent"}
            )

    def test_plan_summary(self):
        tasks = build_remediation_plan(
            self.assets, self.observations,
            {"prod-1": "high", "dev-1": "low"},
        )
        summary = summarize_plan(tasks)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["by_priority"]["high"], 2)
        self.assertEqual(summary["execution"], "planning_only")


if __name__ == "__main__":
    unittest.main()
