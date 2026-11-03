# Architecture and Data Flow

## Components

- `msfconsole (1).py`: Flask HTTP layer and bounded Nmap adapter.
- `osint_cyber.inventory`: strict metadata validation, address normalization, duplicate detection, CSV interchange, and aggregate summaries. It performs no network lookups.
- `osint_cyber.risk`: explainable heuristic ranking for observed services using service baseline, asset criticality, and environment.
- `osint_cyber.reporting`: JSON report envelope and Markdown rendering.
- `jsx_e55d.jsx.txt`: React dashboard for scoped scan results and defensive recommendations.
- `tests/`: API, parsing, validation, interchange, ranking, and report regression coverage.

## Trust boundaries

1. A scan request is normalized and checked against `OSINT_ALLOWED_TARGETS` before Nmap is started.
2. Nmap is invoked as an argument array, never through a shell.
3. The scanner uses TCP connect mode, a bounded top-port list, and a timeout.
4. Inventory endpoints accept metadata only and do not resolve or contact listed addresses.
5. Analysis endpoints return recommendations and heuristics. They do not claim to prove a vulnerability.

## Request flow

```text
Browser
  | JSON request
  v
Flask route
  | validate input / enforce scope
  +--> Nmap adapter --> parsed service observations
  +--> inventory module --> normalized metadata and summary
  +--> risk module --> explainable priority scores
  +--> reporting module --> JSON / Markdown output
  |
  v
JSON response
```

## API examples

Inventory validation:

```json
{
  "assets": [
    {
      "asset_id": "asset-001",
      "name": "Example production site",
      "asset_type": "domain",
      "address": "https://example.org",
      "owner": "Platform",
      "environment": "production",
      "criticality": "high",
      "notes": "Documented asset"
    }
  ]
}
```

Service prioritization:

```json
{
  "scan_results": [{"port": 23, "service": "telnet"}],
  "asset_criticality": "critical",
  "environment": "production"
}
```

## Limitations

- Hostname validation is syntactic; it does not resolve DNS.
- Service identification may be incomplete or incorrect.
- A service risk score is a prioritization aid, not a vulnerability rating.
- The local Flask development server is not suitable for public deployment.
