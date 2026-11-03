"""Declarative baseline checks for defensive asset inventory observations.

Checks operate only on caller-supplied metadata and scan observations. They
never connect to hosts and intentionally avoid claiming vulnerability status.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable

VALID_LEVELS = {"info", "low", "medium", "high", "critical"}


@dataclass(frozen=True)
class ControlFinding:
    control_id: str
    title: str
    level: str
    asset_id: str
    message: str
    evidence: str
    recommendation: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def evaluate_asset_controls(
    assets: Iterable[dict[str, Any]],
    observations_by_asset: dict[str, list[dict[str, Any]]] | None = None,
) -> list[dict[str, str]]:
    """Evaluate a small, explainable baseline against supplied inventory data."""
    observations = observations_by_asset or {}
    findings: list[ControlFinding] = []
    seen: set[str] = set()
    for asset in assets:
        if not isinstance(asset, dict):
            raise ValueError("each asset must be an object")
        asset_id = str(asset.get("asset_id") or "").strip()
        if not asset_id:
            raise ValueError("asset_id is required")
        if asset_id in seen:
            raise ValueError(f"duplicate asset_id: {asset_id}")
        seen.add(asset_id)
        env = str(asset.get("environment") or "unknown").lower()
        criticality = str(asset.get("criticality") or "medium").lower()
        owner = str(asset.get("owner") or "").strip()
        address = str(asset.get("address") or "").strip()

        if not owner:
            findings.append(ControlFinding(
                "INV-001", "Asset owner is recorded", "medium", asset_id,
                "No owner is recorded for this asset.",
                "owner is empty",
                "Assign an accountable team or service owner.",
            ))
        if env == "production" and criticality in {"high", "critical"} and not address:
            findings.append(ControlFinding(
                "INV-002", "Critical production asset has an address", "high", asset_id,
                "A production asset with elevated criticality has no address.",
                f"environment={env}; criticality={criticality}; address is empty",
                "Complete the asset record before relying on inventory or response workflows.",
            ))
        items = observations.get(asset_id, [])
        if not isinstance(items, list):
            raise ValueError(f"observations for {asset_id} must be a list")
        observed_services = {
            str(item.get("service") or "unknown").strip().lower()
            for item in items if isinstance(item, dict)
        }
        if env == "production" and "telnet" in observed_services:
            findings.append(ControlFinding(
                "NET-001", "Telnet is not observed on production assets", "high", asset_id,
                "Telnet appears in the supplied service observations for a production asset.",
                "service=telnet",
                "Validate the observation and replace Telnet with a secure remote administration protocol.",
            ))
        if env == "production" and "ftp" in observed_services:
            findings.append(ControlFinding(
                "NET-002", "Plain FTP is not observed on production assets", "high", asset_id,
                "FTP appears in the supplied service observations for a production asset.",
                "service=ftp",
                "Validate the observation and prefer SFTP or FTPS with restricted access.",
            ))
        if env == "production" and "http" in observed_services and "https" not in observed_services:
            findings.append(ControlFinding(
                "WEB-001", "HTTPS service is inventoried", "medium", asset_id,
                "HTTP is observed without a corresponding HTTPS observation.",
                "service=http; service=https not present in supplied observations",
                "Confirm whether HTTPS is available and ensure sensitive traffic uses TLS.",
            ))
    findings.sort(key=lambda finding: (finding.level, finding.asset_id, finding.control_id))
    return [finding.as_dict() for finding in findings]


def summarize_controls(findings: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Return totals by level and control ID."""
    rows = list(findings)
    by_level = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    by_control: dict[str, int] = {}
    for finding in rows:
        level = str(finding.get("level") or "info")
        if level in by_level:
            by_level[level] += 1
        control_id = str(finding.get("control_id") or "unknown")
        by_control[control_id] = by_control.get(control_id, 0) + 1
    return {
        "total": len(rows),
        "by_level": by_level,
        "by_control": dict(sorted(by_control.items())),
        "evaluation": "metadata_and_observation_based",
    }
