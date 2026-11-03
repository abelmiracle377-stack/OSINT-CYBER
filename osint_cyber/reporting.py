"""Generate portable reports from validated asset and scan data."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterable

from .inventory import Asset, summarize_inventory


def build_report(
    assets: Iterable[Asset],
    scan_results: dict[str, list[dict[str, Any]]] | None = None,
    recommendations: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Build a deterministic report envelope with a generation timestamp."""
    items = list(assets)
    scans = scan_results or {}
    guidance = recommendations or {}
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "summary": summarize_inventory(items),
        "assets": [asset.as_dict() for asset in items],
        "scan_results": scans,
        "recommendations": guidance,
        "limitations": [
            "Service inventory is observational and may be incomplete.",
            "Prioritization is heuristic and is not a vulnerability verdict.",
            "Only authorized assets should be assessed.",
        ],
    }


def to_json(report: dict[str, Any], pretty: bool = True) -> str:
    """Serialize a report using stable key ordering."""
    return json.dumps(report, indent=2 if pretty else None, sort_keys=True, ensure_ascii=False)


def to_markdown(report: dict[str, Any]) -> str:
    """Render a concise human-readable report without interpreting user text as markup."""
    summary = report.get("summary") or {}
    lines = [
        "# OSINT-CYBER Inventory Report",
        "",
        f"Generated: {report.get('generated_at', 'unknown')}",
        "",
        "## Summary",
        "",
        f"- Total assets: {summary.get('total', 0)}",
        f"- Environments: {summary.get('by_environment', {})}",
        f"- Criticality: {summary.get('by_criticality', {})}",
        f"- Asset types: {summary.get('by_asset_type', {})}",
        "",
        "## Assets",
        "",
        "| ID | Name | Type | Address | Environment | Criticality |",
        "|---|---|---|---|---|---|",
    ]
    for asset in report.get("assets", []):
        values = [
            asset.get("asset_id", ""), asset.get("name", ""), asset.get("asset_type", ""),
            asset.get("address", ""), asset.get("environment", ""), asset.get("criticality", ""),
        ]
        escaped = [str(value).replace("|", "\\|").replace("\n", " ") for value in values]
        lines.append("| " + " | ".join(escaped) + " |")
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in report.get("limitations", []))
    return "\n".join(lines) + "\n"
