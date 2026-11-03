"""Rule-based remediation planning from service observations.

This module creates actionable, non-invasive recommendations. It does not
attempt remediation, connect to targets, or claim that an observation is a CVE.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

VALID_PRIORITIES = {"low", "medium", "high", "critical"}
VALID_ENVIRONMENTS = {"production", "staging", "development", "test", "unknown"}

SERVICE_GUIDANCE: dict[str, dict[str, str]] = {
    "telnet": {
        "title": "Replace Telnet with SSH",
        "action": "Disable Telnet and use SSH with key-based authentication.",
        "verification": "Confirm the service is disabled and approved SSH access works.",
        "owner": "Infrastructure",
    },
    "ftp": {
        "title": "Replace FTP with a secure transfer protocol",
        "action": "Disable plaintext FTP; use SFTP or FTPS with managed credentials.",
        "verification": "Confirm the legacy FTP listener is closed and secure transfer succeeds.",
        "owner": "Infrastructure",
    },
    "redis": {
        "title": "Restrict Redis exposure",
        "action": "Bind Redis to a private interface, apply network controls, and enable authentication/ACLs.",
        "verification": "Verify only approved application networks can reach Redis.",
        "owner": "Platform",
    },
    "smb": {
        "title": "Review SMB exposure",
        "action": "Restrict SMB to trusted networks and disable obsolete SMB versions.",
        "verification": "Check firewall rules and confirm legacy protocol support is disabled.",
        "owner": "Infrastructure",
    },
    "rdp": {
        "title": "Harden remote desktop access",
        "action": "Limit RDP to a VPN or bastion, require MFA, and review account access.",
        "verification": "Confirm public/untrusted networks cannot reach RDP and MFA is enforced.",
        "owner": "IT Operations",
    },
    "mysql": {
        "title": "Restrict database access",
        "action": "Keep MySQL on private networks and allow only required application identities.",
        "verification": "Review ingress rules and test access using an approved application identity.",
        "owner": "Database",
    },
    "postgresql": {
        "title": "Restrict database access",
        "action": "Keep PostgreSQL on private networks and enforce least-privilege roles and TLS.",
        "verification": "Review ingress rules, role grants, and TLS configuration.",
        "owner": "Database",
    },
    "mongodb": {
        "title": "Harden MongoDB access",
        "action": "Restrict network reachability and require authenticated, least-privilege access.",
        "verification": "Confirm unauthenticated and untrusted-network access is denied.",
        "owner": "Database",
    },
    "http": {
        "title": "Review plaintext HTTP",
        "action": "Prefer HTTPS and redirect HTTP where appropriate; avoid sending sensitive data over plaintext.",
        "verification": "Check redirect behavior and confirm sensitive routes require HTTPS.",
        "owner": "Application",
    },
    "ssh": {
        "title": "Review SSH configuration",
        "action": "Use key-based authentication, disable obsolete algorithms, and restrict source networks.",
        "verification": "Audit effective sshd configuration and permitted source ranges.",
        "owner": "Infrastructure",
    },
    "unknown": {
        "title": "Identify and review the service",
        "action": "Confirm the service owner and business purpose before deciding whether it should remain exposed.",
        "verification": "Record the verified service identity and approved exposure.",
        "owner": "Asset Owner",
    },
}

PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass(frozen=True)
class RemediationTask:
    task_id: str
    title: str
    asset_id: str
    asset_address: str
    service: str
    port: int
    priority: str
    action: str
    verification: str
    owner: str
    environment: str
    status: str = "open"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _validate_observation(observation: dict[str, Any]) -> tuple[str, int]:
    if not isinstance(observation, dict):
        raise ValueError("each observation must be an object")
    service = str(observation.get("service") or "unknown").strip().lower()
    if len(service) > 80 or not service:
        service = "unknown"
    try:
        port = int(observation.get("port", 0))
    except (TypeError, ValueError) as exc:
        raise ValueError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return service, port


def build_remediation_plan(
    assets: Iterable[dict[str, Any]],
    observations_by_asset: dict[str, list[dict[str, Any]]],
    priorities_by_asset: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Build stable tasks keyed to inventory IDs and their observed services.

    Assets must contain asset_id and address. Optional environment defaults to
    unknown. Each priority is supplied by an upstream assessment or defaults
    to medium; this function does not infer exploitability.
    """
    priorities = priorities_by_asset or {}
    tasks: list[RemediationTask] = []
    seen_assets: set[str] = set()
    for asset in assets:
        if not isinstance(asset, dict):
            raise ValueError("each asset must be an object")
        asset_id = str(asset.get("asset_id") or "").strip()
        address = str(asset.get("address") or "").strip()
        if not asset_id or not address:
            raise ValueError("asset_id and address are required for remediation planning")
        if asset_id in seen_assets:
            raise ValueError(f"duplicate asset_id: {asset_id}")
        seen_assets.add(asset_id)
        environment = str(asset.get("environment") or "unknown").lower()
        if environment not in VALID_ENVIRONMENTS:
            raise ValueError(f"unsupported environment for {asset_id}")
        priority = str(priorities.get(asset_id, "medium")).lower()
        if priority not in VALID_PRIORITIES:
            raise ValueError(f"unsupported priority for {asset_id}")
        observations = observations_by_asset.get(asset_id, [])
        if not isinstance(observations, list):
            raise ValueError(f"observations for {asset_id} must be a list")
        for service, port in sorted({_validate_observation(item) for item in observations}):
            guide = SERVICE_GUIDANCE.get(service, SERVICE_GUIDANCE["unknown"])
            # Stable IDs make plans diff-friendly and safe to compare between runs.
            task_id = f"{asset_id}:{port}:{service}"
            tasks.append(RemediationTask(
                task_id=task_id,
                title=guide["title"],
                asset_id=asset_id,
                asset_address=address,
                service=service,
                port=port,
                priority=priority,
                action=guide["action"],
                verification=guide["verification"],
                owner=guide["owner"],
                environment=environment,
            ))
    tasks.sort(key=lambda task: (
        PRIORITY_ORDER[task.priority], task.environment, task.asset_id, task.port, task.service
    ))
    return [task.as_dict() for task in tasks]


def summarize_plan(tasks: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Summarize plan state and ownership without mutating the input."""
    rows = list(tasks)
    by_priority = {priority: 0 for priority in ("critical", "high", "medium", "low")}
    by_status: dict[str, int] = {}
    by_owner: dict[str, int] = {}
    for row in rows:
        priority = str(row.get("priority", "medium"))
        if priority in by_priority:
            by_priority[priority] += 1
        status = str(row.get("status", "open"))
        by_status[status] = by_status.get(status, 0) + 1
        owner = str(row.get("owner", "Unassigned"))
        by_owner[owner] = by_owner.get(owner, 0) + 1
    return {
        "total": len(rows),
        "by_priority": by_priority,
        "by_status": dict(sorted(by_status.items())),
        "by_owner": dict(sorted(by_owner.items())),
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "execution": "planning_only",
    }
