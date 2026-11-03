import unittest

from osint_cyber.inventory import (
    Asset,
    InventoryValidationError,
    export_csv,
    import_csv,
    normalize_address,
    summarize_inventory,
    validate_asset,
    validate_unique_assets,
)
from osint_cyber.risk import prioritize_services, score_service
from osint_cyber.reporting import build_report, to_json, to_markdown


def sample(asset_id="asset-1", address="example.org", **extra):
    return {
        "asset_id": asset_id,
        "name": "Example",
        "asset_type": "domain",
        "address": address,
        "owner": "Security",
        "environment": "production",
        "criticality": "high",
        **extra,
    }


class AddressNormalizationTests(unittest.TestCase):
    def test_normalizes_hostname(self):
        self.assertEqual(normalize_address("EXAMPLE.ORG."), "example.org")

    def test_normalizes_http_url_to_host(self):
        self.assertEqual(normalize_address("https://Example.org:443/path"), "example.org")

    def test_normalizes_ipv6(self):
        self.assertEqual(normalize_address("[::1]"), "::1")

    def test_rejects_unsupported_scheme(self):
        with self.assertRaises(InventoryValidationError):
            normalize_address("ftp://example.org")

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(InventoryValidationError):
            normalize_address("https://user:pass@example.org")

    def test_rejects_spaces(self):
        with self.assertRaises(InventoryValidationError):
            normalize_address("example org")


class AssetValidationTests(unittest.TestCase):
    def test_valid_asset_is_normalized(self):
        asset = validate_asset(sample())
        self.assertEqual(asset.address, "example.org")
        self.assertEqual(asset.criticality, "high")

    def test_required_name(self):
        record = sample()
        record["name"] = ""
        with self.assertRaises(InventoryValidationError):
            validate_asset(record)

    def test_invalid_asset_type(self):
        with self.assertRaises(InventoryValidationError):
            validate_asset(sample(asset_type="unknown attack"))

    def test_invalid_environment(self):
        with self.assertRaises(InventoryValidationError):
            validate_asset(sample(environment="prod"))

    def test_invalid_criticality(self):
        with self.assertRaises(InventoryValidationError):
            validate_asset(sample(criticality="urgent"))

    def test_rejects_unknown_field(self):
        with self.assertRaises(InventoryValidationError):
            validate_asset({**sample(), "secret": "value"})

    def test_rejects_duplicate_ids(self):
        with self.assertRaises(InventoryValidationError):
            validate_unique_assets([sample(), sample(address="other.example")])

    def test_rejects_duplicate_normalized_addresses(self):
        with self.assertRaises(InventoryValidationError):
            validate_unique_assets([sample(), sample(asset_id="asset-2", address="https://example.org/")])

    def test_summary_counts(self):
        assets = validate_unique_assets([
            sample(),
            sample(asset_id="asset-2", address="other.example", criticality="critical", environment="staging"),
        ])
        summary = summarize_inventory(assets)
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["by_environment"], {"production": 1, "staging": 1})


class CsvInterchangeTests(unittest.TestCase):
    def test_csv_round_trip(self):
        assets = validate_unique_assets([sample()])
        parsed = import_csv(export_csv(assets))
        self.assertEqual(parsed, assets)

    def test_requires_header(self):
        with self.assertRaises(InventoryValidationError):
            import_csv("")

    def test_requires_core_columns(self):
        with self.assertRaises(InventoryValidationError):
            import_csv("asset_id,name\na,b\n")

    def test_rejects_unknown_column(self):
        with self.assertRaises(InventoryValidationError):
            import_csv("asset_id,name,asset_type,address,extra\na,b,domain,b.example,x\n")


class PrioritizationTests(unittest.TestCase):
    def test_production_critical_service_scores_higher(self):
        production = score_service({"service": "telnet", "port": 23}, "critical", "production")
        dev = score_service({"service": "https", "port": 443}, "low", "development")
        self.assertGreater(production.score, dev.score)
        self.assertEqual(production.priority, "critical")

    def test_port_range_validation(self):
        with self.assertRaises(ValueError):
            score_service({"service": "ssh", "port": 70000})

    def test_sorted_by_score_then_port(self):
        result = prioritize_services(
            [{"service": "https", "port": 443}, {"service": "telnet", "port": 23}],
            "high",
            "production",
        )
        self.assertEqual(result[0]["service"], "telnet")

    def test_unknown_service_has_explanation(self):
        result = score_service({"service": "made-up", "port": 8000})
        self.assertTrue(any("heuristic" in item.lower() for item in result.rationale))


class ReportTests(unittest.TestCase):
    def test_report_contains_summary_and_limitations(self):
        report = build_report(validate_unique_assets([sample()]))
        self.assertEqual(report["summary"]["total"], 1)
        self.assertTrue(report["limitations"])

    def test_json_is_valid(self):
        report = build_report(validate_unique_assets([sample()]))
        self.assertIn('"schema_version": "1.0"', to_json(report))

    def test_markdown_escapes_table_pipe(self):
        asset = validate_asset(sample(name="Example | prod"))
        report = build_report([asset])
        self.assertIn("Example \\| prod", to_markdown(report))


if __name__ == "__main__":
    unittest.main()
