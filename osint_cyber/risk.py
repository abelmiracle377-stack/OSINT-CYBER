"""Explainable defensive prioritization for observed service inventory."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

CRITICALITY_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SERVICE_BASE = {
    "telnet": 5, "ftp": 4, "redis": 4, "smb": 4, "rdp": 4,
    "mysql": 3, "postgresql": 3, "mongodb": 3, "http": 2, "https": 1,
    "ssh": 2, "unknown": 2,
}
ENVIRONMENT_WEIGHT = {"production": 2, "staging": 1, "development": 0, "test": 0, "unknown": 1}


@dataclass(frozen=True)
class Finding:
    service: str
    port: int
    score: int
    priority: str
    rationale: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "port": self.port,
            "score": self.score,
            "priority": self.priority,
            "rationale": list(self.rationale),
        }


def score_service(
    item: dict[str, Any],
    asset_criticality: str = "medium",
    environment: str = "unknown",
) -> Finding:
    """Score an observed service using declared context, not a vulnerability claim."""
    service = str(item.get("service") or "unknown").strip().lower()
    try:
        port = int(item.get("port", 0))
    except (TypeError, ValueError) as exc:
        raise ValueError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    criticality = asset_criticality.lower()
    env = environment.lower()
    if criticality not in CRITICALITY_WEIGHT:
        raise ValueError("unknown asset criticality")
    if env not in ENVIRONMENT_WEIGHT:
        raise ValueError("unknown environment")

    base = SERVICE_BASE.get(service, SERVICE_BASE["unknown"])
    criticality_points = CRITICALITY_WEIGHT[criticality]
    environment_points = ENVIRONMENT_WEIGHT[env]
    score = min(10, base + criticality_points + environment_points)
    priority = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    rationale = (
        f"Service baseline for {service}: {base}",
        f"Asset criticality ({criticality}): +{criticality_points}",
        f"Environment ({env}): +{environment_points}",
        "Heuristic prioritization only; not a CVE or vulnerability determination.",
    )
    return Finding(service, port, score, priority, rationale)


def prioritize_services(
    results: list[dict[str, Any]],
    asset_criticality: str = "medium",
    environment: str = "unknown",
) -> list[dict[str, Any]]:
    """Return a stable highest-priority-first list of service findings."""
    findings = [
        score_service(item, asset_criticality, environment)
        for item in results
        if isinstance(item, dict)
    ]
    findings.sort(key=lambda item: (-item.score, item.port, item.service))
    return [item.as_dict() for item in findings]
