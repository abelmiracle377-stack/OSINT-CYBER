import tempfile
import unittest
from pathlib import Path

from osint_cyber.inventory import InventoryValidationError
from osint_cyber.storage import AssetStore


def asset(asset_id="web-01", address="app.example.org"):
    return {
        "asset_id": asset_id,
        "name": "Example app",
        "asset_type": "web_app",
        "address": address,
        "owner": "Engineering",
        "environment": "production",
        "criticality": "high",
        "notes": "Owned service",
    }


class AssetStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = AssetStore(Path(self.temp.name) / "inventory.sqlite3")

    def tearDown(self):
        self.temp.cleanup()

    def test_create_and_get(self):
        created = self.store.create(asset())
        self.assertEqual(self.store.get("web-01"), created)
        self.assertEqual(self.store.count(), 1)

    def test_duplicate_asset_is_rejected(self):
        self.store.create(asset())
        with self.assertRaises(InventoryValidationError):
            self.store.create(asset(asset_id="web-02"))

    def test_list_filters(self):
        self.store.create(asset())
        self.store.create({
            **asset("dev-01", "dev.example.org"),
            "environment": "development",
            "criticality": "low",
        })
        self.assertEqual(len(self.store.list(environment="production")), 1)
        self.assertEqual(len(self.store.list(criticality="low")), 1)

    def test_update_validates_changes(self):
        self.store.create(asset())
        changed = self.store.update("web-01", {"criticality": "critical"})
        self.assertEqual(changed.criticality, "critical")

    def test_update_missing_raises(self):
        with self.assertRaises(KeyError):
            self.store.update("missing", {"name": "Nope"})

    def test_delete_is_idempotent_result(self):
        self.store.create(asset())
        self.assertTrue(self.store.delete("web-01"))
        self.assertFalse(self.store.delete("web-01"))
        self.assertEqual(self.store.count(), 0)

    def test_replace_all_is_validated(self):
        self.store.create(asset())
        replacement = self.store.replace_all([asset("new-01", "new.example.org")])
        self.assertEqual([item.asset_id for item in replacement], ["new-01"])
        self.assertIsNone(self.store.get("web-01"))

    def test_pagination_bounds(self):
        with self.assertRaises(ValueError):
            self.store.list(limit=0)


if __name__ == "__main__":
    unittest.main()
