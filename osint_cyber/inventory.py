"""Validated asset inventory helpers and CSV interchange.

This module stores descriptive inventory metadata only. It does not resolve,
probe, or contact asset addresses.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable, TextIO
from urllib.parse import urlparse

HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
ALLOWED_SCHEMES = {"http", "https"}
CSV_FIELDS = ("asset_id", "name", "asset_type", "address", "owner", "environment", "criticality", "notes", "created_at")


class InventoryValidationError(ValueError):
    """A supplied inventory record is invalid."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize_address(raw: str) -> str:
    """Normalize a hostname, IP address, or HTTP(S) URL without network access."""
    if not isinstance(raw, str) or not raw.strip():
        raise InventoryValidationError("address is required")
    value = raw.strip()
    if len(value) > 2048 or any(ch.isspace() for ch in value):
        raise InventoryValidationError("address contains invalid whitespace or is too long")

    if "://" in value:
        parsed = urlparse(value)
        if parsed.scheme.lower() not in ALLOWED_SCHEMES or not parsed.hostname:
            raise InventoryValidationError("only valid HTTP(S) URLs are supported")
        if parsed.username or parsed.password:
            raise InventoryValidationError("credentials are not allowed in asset URLs")
        host = parsed.hostname
    else:
        host = value.strip("[]")

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        hostname = host.rstrip(".").lower()
        if len(hostname) > 253 or not hostname:
            raise InventoryValidationError("hostname length is invalid")
        labels = hostname.split(".")
        if any(not HOST_LABEL.fullmatch(label) for label in labels):
            raise InventoryValidationError("address must be a valid hostname or IP")
        return hostname


@dataclass(frozen=True)
class Asset:
    asset_id: str
    name: str
    asset_type: str
    address: str
    owner: str = ""
    environment: str = "unknown"
    criticality: str = "medium"
    notes: str = ""
    created_at: str = ""

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def validate_asset(record: dict[str, object]) -> Asset:
    """Validate a dictionary and return a normalized immutable Asset."""
    allowed = set(CSV_FIELDS)
    unknown = set(record) - allowed
    if unknown:
        raise InventoryValidationError(f"unknown fields: {', '.join(sorted(unknown))}")

    def text(field: str, required: bool = False, max_length: int = 500) -> str:
        value = record.get(field, "")
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise InventoryValidationError(f"{field} must be text")
        value = value.strip()
        if required and not value:
            raise InventoryValidationError(f"{field} is required")
        if len(value) > max_length:
            raise InventoryValidationError(f"{field} exceeds {max_length} characters")
        return value

    asset_id = text("asset_id", required=True, max_length=80)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,79}", asset_id):
        raise InventoryValidationError("asset_id contains unsupported characters")
    name = text("name", required=True, max_length=120)
    asset_type = text("asset_type", required=True, max_length=40).lower()
    if asset_type not in {"domain", "ip", "web_app", "server", "endpoint", "cloud_resource", "other"}:
        raise InventoryValidationError("asset_type is not supported")

    address = normalize_address(text("address", required=True, max_length=2048))
    owner = text("owner", max_length=120)
    environment = text("environment", max_length=40).lower() or "unknown"
    if environment not in {"production", "staging", "development", "test", "unknown"}:
        raise InventoryValidationError("environment is not supported")
    criticality = text("criticality", max_length=20).lower() or "medium"
    if criticality not in {"low", "medium", "high", "critical"}:
        raise InventoryValidationError("criticality must be low, medium, high, or critical")
    notes = text("notes", max_length=2000)
    created_at = text("created_at", max_length=40) or utc_now()
    try:
        datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InventoryValidationError("created_at must be an ISO-8601 timestamp") from exc

    return Asset(asset_id, name, asset_type, address, owner, environment, criticality, notes, created_at)


def validate_unique_assets(records: Iterable[dict[str, object]]) -> list[Asset]:
    """Validate records and reject duplicate IDs or normalized addresses."""
    assets: list[Asset] = []
    ids: set[str] = set()
    addresses: set[str] = set()
    for record in records:
        asset = validate_asset(record)
        if asset.asset_id in ids:
            raise InventoryValidationError(f"duplicate asset_id: {asset.asset_id}")
        if asset.address in addresses:
            raise InventoryValidationError(f"duplicate address: {asset.address}")
        ids.add(asset.asset_id)
        addresses.add(asset.address)
        assets.append(asset)
    return assets


def import_csv(source: str | TextIO) -> list[Asset]:
    """Parse inventory CSV with strict columns and duplicate validation."""
    stream = io.StringIO(source, newline="") if isinstance(source, str) else source
    reader = csv.DictReader(stream)
    if reader.fieldnames is None:
        raise InventoryValidationError("CSV header is missing")
    headers = tuple(name.strip() for name in reader.fieldnames)
    if not {"asset_id", "name", "asset_type", "address"}.issubset(headers):
        raise InventoryValidationError("CSV requires asset_id, name, asset_type, and address columns")
    unknown = set(headers) - set(CSV_FIELDS)
    if unknown:
        raise InventoryValidationError(f"unknown CSV columns: {', '.join(sorted(unknown))}")
    return validate_unique_assets(dict(row) for row in reader)


def export_csv(assets: Iterable[Asset]) -> str:
    """Serialize validated assets to stable, newline-terminated CSV."""
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for asset in assets:
        writer.writerow(asset.as_dict())
    return stream.getvalue()


def summarize_inventory(assets: Iterable[Asset]) -> dict[str, object]:
    """Produce counts by environment, criticality, and asset type."""
    items = list(assets)
    def count(field: str) -> dict[str, int]:
        result: dict[str, int] = {}
        for item in items:
            key = getattr(item, field)
            result[key] = result.get(key, 0) + 1
        return dict(sorted(result.items()))
    return {
        "total": len(items),
        "by_environment": count("environment"),
        "by_criticality": count("criticality"),
        "by_asset_type": count("asset_type"),
    }
