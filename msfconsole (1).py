#!/usr/bin/env python3
"""Scoped, non-destructive network inventory API.

Only scan targets explicitly listed in OSINT_ALLOWED_TARGETS. The API deliberately
does not expose exploitation, credential attacks, or arbitrary shell execution.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
import time
from typing import Any
from urllib.parse import urlparse

from flask import Flask, jsonify, request
from osint_cyber.inventory import InventoryValidationError, validate_unique_assets, summarize_inventory
from osint_cyber.risk import prioritize_services
from osint_cyber.reporting import build_report, to_markdown
from osint_cyber.storage import AssetStore
from osint_cyber.remediation import build_remediation_plan, summarize_plan
from osint_cyber.controls import evaluate_asset_controls, summarize_controls

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
app.config["JSON_SORT_KEYS"] = False
FRONTEND_ORIGINS = {
    origin.strip().rstrip("/")
    for origin in os.environ.get(
        "FRONTEND_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"
    ).split(",")
    if origin.strip()
}

@app.after_request
def add_cors_headers(response):
    """Allow configured local frontend origins without wildcard credentials."""
    origin = request.headers.get("Origin", "").rstrip("/")
    if origin in FRONTEND_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Methods"] = "GET,POST,PATCH,DELETE,OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
        response.headers["Access-Control-Max-Age"] = "600"
    return response

NMAP_BIN = os.environ.get("NMAP_BIN", "nmap")
SCAN_TIMEOUT_SECONDS = int(os.environ.get("SCAN_TIMEOUT_SECONDS", "90"))
ASSET_STORE = AssetStore(os.environ.get("OSINT_DB_PATH", "osint_cyber.sqlite3"))
ALLOWED_TARGETS = {
    value.strip().lower()
    for value in os.environ.get("OSINT_ALLOWED_TARGETS", "127.0.0.1,localhost,::1").split(",")
    if value.strip()
}
TARGET_RE = re.compile(r"^[a-zA-Z0-9.-]+$")


class ScopeError(ValueError):
    """Raised when a requested host is outside the configured assessment scope."""


def normalize_target(raw: Any) -> str:
    """Normalize a hostname, IP, or URL to a host and enforce explicit scope."""
    if not isinstance(raw, str) or not raw.strip():
        raise ScopeError("A target host is required.")
    value = raw.strip()
    if len(value) > 253 or any(ch.isspace() for ch in value):
        raise ScopeError("Target format is invalid.")

    if "://" in value:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ScopeError("Only valid HTTP(S) URLs or hostnames are accepted.")
        if parsed.username or parsed.password:
            raise ScopeError("Credentials must not be embedded in target URLs.")
        host = parsed.hostname
    else:
        host = value.strip("[]")

    host = host.rstrip(".").lower()
    if not host or not TARGET_RE.fullmatch(host):
        try:
            ipaddress.ip_address(host)
        except ValueError as exc:
            raise ScopeError("Target must be a valid hostname or IP address.") from exc

    if host not in ALLOWED_TARGETS:
        # Permit a configured CIDR only when it is explicitly present in the scope.
        try:
            candidate = ipaddress.ip_address(host)
        except ValueError:
            candidate = None
        in_scope = False
        if candidate:
            for entry in ALLOWED_TARGETS:
                try:
                    if "/" in entry and candidate in ipaddress.ip_network(entry, strict=False):
                        in_scope = True
                        break
                except ValueError:
                    continue
        if not in_scope:
            raise ScopeError("Target is not in OSINT_ALLOWED_TARGETS. Add it only after obtaining authorization.")
    return host


def scan_ports(target: str) -> list[dict[str, Any]]:
    """Run a bounded TCP connect/service inventory against one in-scope host."""
    binary = shutil.which(NMAP_BIN)
    if not binary:
        raise RuntimeError("Nmap is not installed or NMAP_BIN does not point to it.")

    command = [
        binary,
        "-n",
        "-sT",
        "-sV",
        "--version-light",
        "--top-ports",
        "1000",
        "--open",
        "-oG",
        "-",
        target,
    ]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=SCAN_TIMEOUT_SECONDS,
        check=False,
    )
    if completed.returncode not in (0, 1):
        message = completed.stderr.strip()[:500] or "Nmap failed."
        raise RuntimeError(message)

    found: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        port_section = line.split("Ports:", 1)[1].split("Ignored State:", 1)[0]
        for entry in port_section.split(","):
            parts = entry.strip().split("/")
            if len(parts) < 7 or parts[1] != "open":
                continue
            try:
                port = int(parts[0])
            except ValueError:
                continue
            found.append(
                {
                    "port": port,
                    "protocol": parts[2],
                    "service": parts[4] or "unknown",
                    "version": parts[6] or "not identified",
                    "state": parts[1],
                }
            )
    return found


def analyze_services(scan_results: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Return defensive follow-up guidance; this does not test for vulnerabilities."""
    guidance: list[dict[str, str]] = []
    recommendations = {
        "ftp": "Prefer SFTP/FTPS; disable anonymous access and restrict source networks.",
        "telnet": "Replace Telnet with SSH and disable the cleartext service.",
        "ssh": "Review key-based authentication, patch level, and source-IP restrictions.",
        "http": "Review TLS termination, security headers, and exposed application routes.",
        "https": "Verify certificate validity, TLS configuration, and security headers.",
        "smb": "Restrict SMB to trusted networks; disable SMBv1 and review share permissions.",
        "rdp": "Restrict RDP behind a VPN or gateway and require MFA.",
        "mysql": "Do not expose database ports publicly; enforce least-privilege accounts.",
        "postgresql": "Restrict database access to application networks and enforce strong auth.",
        "redis": "Bind Redis to trusted interfaces and require authentication/ACLs.",
    }
    seen: set[tuple[int, str]] = set()
    for item in scan_results:
        service = str(item.get("service", "unknown")).lower()
        key = (int(item.get("port", 0)), service)
        if key in seen:
            continue
        seen.add(key)
        tip = recommendations.get(service)
        if tip:
            guidance.append({"service": service, "port": str(key[0]), "recommendation": tip})
        else:
            guidance.append(
                {
                    "service": service,
                    "port": str(key[0]),
                    "recommendation": "Confirm business need, patch status, access controls, and network exposure.",
                }
            )
    return guidance


@app.route("/api/<path:unused>", methods=["OPTIONS"])
def api_preflight(unused: str):
    return ("", 204)


@app.errorhandler(413)
def payload_too_large(_: Exception):
    return jsonify({"error": "Request body exceeds the 16 KB limit."}), 413


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "scanner_available": shutil.which(NMAP_BIN) is not None})


@app.post("/api/scan")
def api_scan():
    body = request.get_json(silent=True) or {}
    try:
        target = normalize_target(body.get("target"))
    except ScopeError as exc:
        return jsonify({"error": str(exc)}), 400
    try:
        results = scan_ports(target)
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Scan timed out; reduce scope or increase SCAN_TIMEOUT_SECONDS."}), 504
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 503
    return jsonify({"target": target, "scan_results": results, "timestamp": time.time()})


@app.post("/api/analyze")
def api_analyze():
    body = request.get_json(silent=True) or {}
    results = body.get("scan_results")
    if not isinstance(results, list) or len(results) > 1000:
        return jsonify({"error": "scan_results must be a list of at most 1000 entries."}), 400
    safe_results = [
        item for item in results
        if isinstance(item, dict) and str(item.get("port", "")).isdigit()
    ]
    return jsonify({"recommendations": analyze_services(safe_results)})




@app.get("/api/assets")
def api_assets_list():
    """List locally stored inventory metadata with bounded pagination."""
    try:
        limit = int(request.args.get("limit", "500"))
        offset = int(request.args.get("offset", "0"))
        assets = ASSET_STORE.list(
            environment=request.args.get("environment") or None,
            criticality=request.args.get("criticality") or None,
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"total": ASSET_STORE.count(), "assets": [asset.as_dict() for asset in assets]})


@app.post("/api/assets")
def api_assets_create():
    """Persist one validated inventory record."""
    body = request.get_json(silent=True) or {}
    try:
        asset = ASSET_STORE.create(body)
    except (InventoryValidationError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"asset": asset.as_dict()}), 201


@app.get("/api/assets/<asset_id>")
def api_assets_get(asset_id: str):
    asset = ASSET_STORE.get(asset_id)
    if asset is None:
        return jsonify({"error": "asset not found"}), 404
    return jsonify({"asset": asset.as_dict()})


@app.patch("/api/assets/<asset_id>")
def api_assets_update(asset_id: str):
    body = request.get_json(silent=True) or {}
    try:
        asset = ASSET_STORE.update(asset_id, body)
    except KeyError:
        return jsonify({"error": "asset not found"}), 404
    except (InventoryValidationError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"asset": asset.as_dict()})


@app.delete("/api/assets/<asset_id>")
def api_assets_delete(asset_id: str):
    if not ASSET_STORE.delete(asset_id):
        return jsonify({"error": "asset not found"}), 404
    return jsonify({"deleted": asset_id})


@app.post("/api/inventory/summary")
def api_inventory_summary():
    """Validate a small submitted asset list and return aggregate counts."""
    body = request.get_json(silent=True) or {}
    records = body.get("assets")
    if not isinstance(records, list) or len(records) > 5000:
        return jsonify({"error": "assets must be a list of at most 5000 records"}), 400
    try:
        assets = validate_unique_assets(records)
    except (InventoryValidationError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"summary": summarize_inventory(assets), "assets": [item.as_dict() for item in assets]})


@app.post("/api/risk/prioritize")
def api_risk_prioritize():
    """Prioritize provided observations using explainable heuristics."""
    body = request.get_json(silent=True) or {}
    results = body.get("scan_results")
    if not isinstance(results, list) or len(results) > 1000:
        return jsonify({"error": "scan_results must be a list of at most 1000 entries"}), 400
    try:
        findings = prioritize_services(
            results,
            str(body.get("asset_criticality", "medium")),
            str(body.get("environment", "unknown")),
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"findings": findings})




@app.post("/api/controls/evaluate")
def api_controls_evaluate():
    """Evaluate local inventory observations against simple defensive baselines."""
    body = request.get_json(silent=True) or {}
    assets = body.get("assets")
    observations = body.get("observations_by_asset", {})
    if not isinstance(assets, list) or len(assets) > 5000:
        return jsonify({"error": "assets must be a list of at most 5000 records"}), 400
    if not isinstance(observations, dict):
        return jsonify({"error": "observations_by_asset must be an object"}), 400
    try:
        findings = evaluate_asset_controls(assets, observations)
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"findings": findings, "summary": summarize_controls(findings)})


@app.post("/api/remediation/plan")
def api_remediation_plan():
    """Generate non-executing remediation tasks from submitted asset observations."""
    body = request.get_json(silent=True) or {}
    assets = body.get("assets")
    observations = body.get("observations_by_asset", {})
    priorities = body.get("priorities_by_asset", {})
    if not isinstance(assets, list) or len(assets) > 5000:
        return jsonify({"error": "assets must be a list of at most 5000 records"}), 400
    if not isinstance(observations, dict) or not isinstance(priorities, dict):
        return jsonify({"error": "observations_by_asset and priorities_by_asset must be objects"}), 400
    try:
        plan = build_remediation_plan(assets, observations, priorities)
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"plan": plan, "summary": summarize_plan(plan)})


@app.post("/api/report/markdown")
def api_report_markdown():
    """Render a Markdown report for validated asset metadata."""
    body = request.get_json(silent=True) or {}
    records = body.get("assets")
    if not isinstance(records, list) or len(records) > 5000:
        return jsonify({"error": "assets must be a list of at most 5000 records"}), 400
    try:
        assets = validate_unique_assets(records)
        report = build_report(assets, body.get("scan_results"), body.get("recommendations"))
    except (InventoryValidationError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"markdown": to_markdown(report), "report": report})


@app.errorhandler(405)
def method_not_allowed(_: Exception):
    return jsonify({"error": "Method not allowed."}), 405


if __name__ == "__main__":
    # Debug mode is intentionally off; use a production WSGI server for deployment.
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")), debug=False)
