# AutoReconX

AutoReconX is an automated reconnaissance and attack-surface mapping CLI for authorized security assessments.

It combines multiple reconnaissance tools into a single pipeline, correlates discovered assets, prioritizes interesting targets, stores results in SQLite, and generates JSON and HTML reports.

> **Authorized use only:** Use AutoReconX only on systems you own or have explicit permission to test.

## Features

- Subdomain discovery
- DNS resolution
- Port discovery
- Service enumeration
- HTTP probing
- Web crawling
- Asset normalization and correlation
- Scan prioritization
- SQLite persistence
- JSON and HTML reports
- Passive, standard, and full scan profiles
- Public-IP active-scan safety controls

## Requirements

- Linux (Kali Linux recommended)
- Python 3.12+
- Git

AutoReconX integrates with:

- Subfinder
- dnsx
- Naabu
- Nmap
- ProjectDiscovery httpx
- Katana

These are external programs and must be installed separately if the selected scan profile/stage requires them.

## Installation

Clone the repository:

```bash
git clone <YOUR-GITHUB-REPOSITORY-URL>
cd AutoReconX
```

### Option 1 — Virtual environment (recommended)

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install AutoReconX:

```bash
python -m pip install -e .
```

For development, including pytest and Ruff:

```bash
python -m pip install -e ".[dev]"
```

The virtual environment must be activated again when opening a new terminal:

```bash
source .venv/bin/activate
```

### Option 2 — Without a virtual environment

A virtual environment is not required.

On systems with `pipx`:

```bash
sudo apt install pipx
pipx ensurepath
pipx install .
```

Open a new terminal if necessary, then verify:

```bash
autoreconx --help
```

Using a virtual environment is recommended when developing AutoReconX from source.

## Usage

Show available commands:

```bash
autoreconx --help
```

Show scan options:

```bash
autoreconx scan --help
```

Check the version:

```bash
autoreconx version
```

### Passive scan

```bash
autoreconx scan <AUTHORIZED_DOMAIN> --profile passive
```

### Standard scan

```bash
autoreconx scan <AUTHORIZED_DOMAIN> --profile standard
```

### Full scan

```bash
autoreconx scan <AUTHORIZED_TARGET> --profile full
```

The `full` profile enables active reconnaissance stages. Use it only where active scanning is explicitly authorized.

Individual stages can also be enabled manually:

```bash
autoreconx scan <AUTHORIZED_TARGET> --ports --services --web --crawl
```

For explicitly authorized public-IP scanning, AutoReconX provides the `--allow-public` safety override:

```bash
autoreconx scan <AUTHORIZED_PUBLIC_IP> --allow-public --ports
```

## Scan Profiles

- `passive` — passive domain reconnaissance
- `standard` — DNS resolution and web reconnaissance
- `full` — complete reconnaissance pipeline including active stages

## Output

Each scan creates a timestamped workspace:

```text
workspaces/<SCAN_ID>/
├── raw/                 # Raw reconnaissance tool output
├── autoreconx.db        # SQLite correlated scan data
└── reports/
    ├── report.json
    └── report.html
```

AutoReconX preserves both the original tool output and its processed attack-surface representation.

## Pipeline

```text
Target
  ↓
Scope Validation
  ↓
Subdomain Discovery
  ↓
DNS Resolution
  ↓
Port Discovery
  ↓
Service Enumeration
  ↓
HTTP Probing
  ↓
Web Crawling
  ↓
Normalization & Correlation
  ↓
SQLite Persistence
  ↓
Prioritization
  ↓
JSON + HTML Reports
```

Stages are enabled or disabled according to the selected profile/options.

## Development

Run the project checks with:

```bash
ruff check src tests
python -m pytest -q
```

## Legal & Ethical Use

AutoReconX is intended for:

- Authorized penetration testing
- Defensive security assessments
- Systems owned by the user
- Security labs and CTF environments where scanning is permitted

Do not use AutoReconX against systems without authorization.

## License

MIT License.
