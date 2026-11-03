# OSINT-CYBER

A small, local-first network inventory tool with defensive configuration guidance. The API is intentionally non-destructive: it does not exploit services, try credentials, or run arbitrary shell commands.

## Features

- Explicit target scope using `OSINT_ALLOWED_TARGETS`
- Bounded Nmap TCP connect/service inventory (top 1,000 ports)
- Defensive service recommendations and explainable service prioritization
- Validated asset inventory with duplicate detection and CSV import/export
- JSON and Markdown inventory report generation
- Flask API and a React UI
- Regression tests for target validation, Nmap parsing, inventory, prioritization, CSV, and reports

## Requirements

- Python 3.10+
- Flask (see `requirements.txt`)
- Nmap installed and available on PATH
- Node/npm only if building the React frontend

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On PowerShell, activate with `.venv\\Scripts\\Activate.ps1`.

The default scope is localhost only. To authorize additional assets, set an explicit list or CIDR after obtaining permission:

```bash
export OSINT_ALLOWED_TARGETS="127.0.0.1,localhost,192.0.2.10,192.0.2.0/24"
python "msfconsole (1).py"
```

PowerShell:

```powershell
$env:OSINT_ALLOWED_TARGETS = "127.0.0.1,localhost,192.0.2.10"
python ".\\msfconsole (1).py"
```

The API listens on `127.0.0.1:5000` by default. Do not expose the development server to the public internet. For deployment, use a production WSGI server and appropriate authentication/network controls.

## API

- `GET /api/health` — health and Nmap availability
- `POST /api/scan` — JSON body: `{"target":"localhost"}`; target must be in configured scope
- `POST /api/analyze` — JSON body: `{"scan_results":[...]}`; returns defensive guidance only
- `POST /api/inventory/summary` — validates asset records and returns aggregate counts
- `POST /api/risk/prioritize` — applies transparent heuristic prioritization to service observations
- `POST /api/report/markdown` — validates assets and returns a Markdown report plus its JSON structure

Out-of-scope targets return HTTP 400. Nmap execution uses an argument list (not a shell string) and has a timeout. The service-analysis output is guidance, not a vulnerability verdict. Risk prioritization is a transparent heuristic based on service, declared asset criticality, and environment; it is not a CVE score or proof of exploitability. Asset inventory functions are local data processing and do not contact listed hosts.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Responsible use

Only scan systems you own or have explicit authorization to assess. Keep the scope narrow and document permission. This project intentionally omits exploitation and password-guessing endpoints.
