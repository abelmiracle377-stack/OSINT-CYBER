"""SQLite persistence for the local asset inventory.

The database stores asset metadata only. It does not initiate network activity.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable

from .inventory import Asset, InventoryValidationError, validate_asset

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    address TEXT NOT NULL UNIQUE,
    owner TEXT NOT NULL DEFAULT '',
    environment TEXT NOT NULL,
    criticality TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assets_environment ON assets(environment);
CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality);
"""


class AssetStore:
    """Small context-managed SQLite repository for validated Asset records."""

    def __init__(self, database: str | Path):
        self.database = str(database)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _session(self):
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._session() as connection:
            connection.executescript(SCHEMA)

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Asset:
        return Asset(**dict(row))

    def create(self, record: dict[str, object]) -> Asset:
        asset = validate_asset(record)
        fields = tuple(asset.as_dict())
        values = tuple(asset.as_dict()[field] for field in fields)
        placeholders = ", ".join("?" for _ in fields)
        columns = ", ".join(fields)
        try:
            with self._session() as connection:
                connection.execute(
                    f"INSERT INTO assets ({columns}) VALUES ({placeholders})",
                    values,
                )
        except sqlite3.IntegrityError as exc:
            raise InventoryValidationError("asset ID or normalized address already exists") from exc
        return asset

    def get(self, asset_id: str) -> Asset | None:
        with self._session() as connection:
            row = connection.execute(
                "SELECT * FROM assets WHERE asset_id = ?", (asset_id,)
            ).fetchone()
        return self._from_row(row) if row else None

    def list(
        self,
        environment: str | None = None,
        criticality: str | None = None,
        limit: int = 500,
        offset: int = 0,
    ) -> list[Asset]:
        if not 1 <= limit <= 5000 or offset < 0:
            raise ValueError("limit must be 1..5000 and offset must be non-negative")
        clauses: list[str] = []
        params: list[object] = []
        if environment:
            clauses.append("environment = ?")
            params.append(environment)
        if criticality:
            clauses.append("criticality = ?")
            params.append(criticality)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.extend([limit, offset])
        with self._session() as connection:
            rows = connection.execute(
                f"SELECT * FROM assets{where} ORDER BY asset_id LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        return [self._from_row(row) for row in rows]

    def update(self, asset_id: str, changes: dict[str, object]) -> Asset:
        current = self.get(asset_id)
        if current is None:
            raise KeyError(asset_id)
        record = current.as_dict()
        record.update(changes)
        record["asset_id"] = asset_id
        updated = validate_asset(record)
        values = updated.as_dict()
        try:
            with self._session() as connection:
                connection.execute(
                    """UPDATE assets SET name=?, asset_type=?, address=?, owner=?,
                       environment=?, criticality=?, notes=?, created_at=? WHERE asset_id=?""",
                    (
                        values["name"], values["asset_type"], values["address"],
                        values["owner"], values["environment"], values["criticality"],
                        values["notes"], values["created_at"], asset_id,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise InventoryValidationError("normalized address already exists") from exc
        return updated

    def delete(self, asset_id: str) -> bool:
        with self._session() as connection:
            cursor = connection.execute("DELETE FROM assets WHERE asset_id = ?", (asset_id,))
            return cursor.rowcount == 1

    def count(self) -> int:
        with self._session() as connection:
            row = connection.execute("SELECT COUNT(*) AS total FROM assets").fetchone()
        return int(row["total"])

    def replace_all(self, records: Iterable[dict[str, object]]) -> list[Asset]:
        """Atomically replace inventory after validating the complete input."""
        from .inventory import validate_unique_assets

        assets = validate_unique_assets(records)
        with self._session() as connection:
            connection.execute("DELETE FROM assets")
            for asset in assets:
                values = asset.as_dict()
                connection.execute(
                    """INSERT INTO assets
                       (asset_id, name, asset_type, address, owner, environment, criticality, notes, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    tuple(values[field] for field in (
                        "asset_id", "name", "asset_type", "address", "owner",
                        "environment", "criticality", "notes", "created_at"
                    )),
                )
        return assets
