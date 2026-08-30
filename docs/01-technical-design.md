# AutoReconX — Technical Design Specification

**Version:** 1.0 
**Status:** Pre-Implementation 
**Project:** AutoReconX — Automated Reconnaissance & Attack Surface Mapping Framework 
**Primary Language:** Python 3.12+ 
**Target Environment:** Linux / Kali Linux 
**Database:** SQLite 
**License:** MIT 
**Author:** Tanjan Singh Karki 
**Last Updated:** 2026-08-30 


1. Technical Design Objective

The technical design defines how AutoReconX will be implemented internally.

The framework will act as an orchestration and intelligence layer around established reconnaissance tools rather than replacing them.

The core pipeline is:

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
Normalization
  ↓
Correlation
  ↓
Prioritization
  ↓
Database
  ↓
Report

The design prioritizes:

modularity
safety
reproducibility
structured data
extensibility
reliable error handling
2. Core Technology Stack
Component	Technology
Programming	Python 3.12+
CLI	Typer
Configuration	YAML
Database	SQLite
ORM / DB Layer	SQLAlchemy
Validation	Pydantic
Logging	Python logging
Testing	Pytest
Packaging	pyproject.toml
Containerization	Docker
CI/CD	GitHub Actions
Reports	Jinja2 + HTML
Data formats	JSON / YAML / XML
Version control	Git

For the first version, we should avoid adding unnecessary infrastructure such as Redis, PostgreSQL, Elasticsearch, Kafka, or Kubernetes.

The project is primarily a local offensive-security CLI framework, so lightweight architecture is preferable.

3. External Reconnaissance Toolchain

AutoReconX will integrate the following tools:

Subfinder → Passive subdomain discovery
dnsx      → DNS resolution
Naabu     → Fast port discovery
Nmap      → Detailed service enumeration
httpx     → HTTP probing/fingerprinting
Katana    → Web crawling

Each tool will have its own adapter.

src/autoreconx/modules/

├── subfinder.py
├── dnsx.py
├── naabu.py
├── nmap.py
├── httpx.py
└── katana.py

This prevents the main application from becoming tightly coupled to individual tools.

4. Module Architecture

Every reconnaissance module should follow a common interface.

Conceptually:

class ReconModule:

    def validate(self, context):
        ...

    def build_command(self, context):
        ...

    def execute(self, context):
        ...

    def parse(self, output):
        ...

    def normalize(self, data):
        ...

For example:

SubfinderModule
       ↓
execute()
       ↓
raw output
       ↓
parse()
       ↓
normalize()
       ↓
Subdomain objects

The same architecture will be used for Nmap, httpx, Katana, etc.

Why?

If we later add another tool, we can create another adapter without modifying the entire framework.

5. Scan Context

Every scan will have a shared context.

Example:

ScanContext
│
├── scan_id
├── target
├── scope
├── profile
├── configuration
├── logger
├── database
├── workspace
└── discovered_assets

Modules receive this context rather than independently managing configuration.

This gives us consistent behavior throughout the pipeline.

6. Scope Engine

The scope engine is a mandatory security control.

Before any active operation:

Input Target
     ↓
Scope Validator
     ↓
Allowed?
 ┌───┴───┐
YES      NO
 │        │
Scan    Reject

Example:

scope:
  allowed:
    - "*.lab.local"

  excluded:
    - "production.lab.local"

The engine must support:

exact domains
subdomains
IP addresses
CIDR ranges
exclusions

The important principle is:

No reconnaissance module should directly execute against a target without passing through scope validation.

7. Command Execution Layer

External tools should not be launched directly from individual modules.

Instead:

Recon Module
     ↓
Command Runner
     ↓
Process
     ↓
stdout / stderr
     ↓
Parser

The command runner will handle:

timeout
exit codes
stdout
stderr
process termination
logging
execution duration

We should use argument lists rather than unsafe shell-string construction.

For example, conceptually:

["nmap", "-sV", "-oX", output_file, target]

rather than dynamically constructing shell commands.

This reduces command-injection risk inside the framework.

8. Raw Output Management

Every tool's original output should be preserved.

Example:

results/
└── scans/
    └── SCAN-001/
        ├── raw/
        │   ├── subfinder/
        │   ├── dnsx/
        │   ├── naabu/
        │   ├── nmap/
        │   ├── httpx/
        │   └── katana/
        │
        ├── normalized/
        ├── report/
        └── scan.json

This is important because normalized data may contain parsing errors.

Keeping raw evidence allows us to:

debug parsers
reproduce results
verify findings
develop improved parsers later
9. Data Normalization

Different tools produce different output formats.

For example:

Subfinder → domains
dnsx      → DNS records
Naabu     → ports
Nmap      → services
httpx     → HTTP metadata
Katana    → URLs

AutoReconX converts these into common internal models.

Raw Tool Output
       ↓
Parser
       ↓
Observation
       ↓
Canonical Asset

The framework therefore separates:

Observation from Asset.

10. Core Data Model

The initial database will contain the following major entities:

Scan
 │
 ├── Domain
 │     └── Subdomain
 │           └── Host
 │                 ├── IP
 │                 ├── Port
 │                 │    └── Service
 │                 └── WebApplication
 │                        ├── Technology
 │                        └── Endpoint
 │
 └── Observation
Main entities

Scan

id
target
profile
start_time
end_time
status
tool_versions

Subdomain

id
hostname
source
first_seen
last_seen

Host

id
hostname
ip
ipv6

Port

id
host_id
port
protocol
state

Service

id
port_id
name
product
version
banner
confidence

WebApplication

id
url
scheme
port
status_code
title
server

Endpoint

id
web_application_id
url
method
parameter
source
11. Observation and Provenance Model

A major design feature is evidence tracking.

Instead of storing:

nginx

we store something closer to:

Technology:
nginx

Source:
httpx

Confidence:
High

Observed:
2026-08-30

This means the framework can explain:

Why do we believe this asset or technology exists?

Sources may include:

subfinder
dnsx
naabu
nmap
httpx
katana

This will become particularly useful for reporting and troubleshooting.

12. Correlation Engine

The correlation engine connects separate observations into a single attack-surface model.

Example:

api.lab.local
      │
      ▼
10.10.10.20
      │
 ┌────┴─────┐
 ▼          ▼
22/tcp     443/tcp
            │
            ▼
      https://api.lab.local
            │
       ┌────┼────┐
       ▼    ▼    ▼
     /api /auth /docs

Instead of six independent discoveries, AutoReconX represents them as related assets.

This is one of the main features that differentiates the project from simply running a sequence of tools.

13. Deduplication

Multiple tools can discover the same asset.

Example:

Subfinder → api.lab.local
dnsx      → api.lab.local
httpx     → api.lab.local

The system should create:

ONE asset

with:

Sources:
- Subfinder
- dnsx
- httpx

rather than three separate records.

Deduplication keys will depend on asset type—for example, normalized hostname, IP address, or normalized URL.

14. Scan Profiles

Three initial profiles:

Passive
Subfinder
DNS-related discovery
Minimal interaction
Standard
Subfinder
 ↓
dnsx
 ↓
Naabu
 ↓
Nmap
 ↓
httpx
Full
Subfinder
 ↓
dnsx
 ↓
Naabu
 ↓
Nmap
 ↓
httpx
 ↓
Katana
 ↓
Correlation
 ↓
Prioritization

Profiles allow the tester to choose reconnaissance depth according to the authorized assessment.

15. Prioritization Engine

AutoReconX will not claim that an asset is vulnerable.

Instead, it will calculate investigation priority.

Potential signals:

admin hostname
api hostname
dev/staging hostname
authentication endpoint
unusual exposed service
newly discovered asset
multiple exposed ports
interesting web path

Example:

admin.lab.local

Priority: HIGH

Reasons:
- Administrative naming
- Web application detected
- Authentication endpoint
- Newly discovered

This is a prioritization mechanism—not a vulnerability severity rating.

16. Reporting Architecture

Reports will be generated from the normalized database rather than directly from individual tools.

Database
   ↓
Report Engine
   ├── JSON
   ├── Markdown
   └── HTML

This ensures all report formats contain the same underlying information.

Report sections
Executive Summary
Scope
Scan Configuration
Toolchain
Discovery Statistics
Subdomains
Hosts
Ports
Services
Web Applications
Technologies
Endpoints
Interesting Assets
Priority Ranking
Errors / Limitations
17. CLI Design

Initial CLI structure:

autoreconx version

autoreconx validate --target example.com

autoreconx scan \
    --target example.com \
    --profile standard

autoreconx report \
    --scan SCAN-001 \
    --format html

autoreconx status \
    --scan SCAN-001

The CLI should remain simple enough that a penetration tester can understand it immediately.

18. Configuration Design

Configuration will use YAML.

Example:

project:
  name: AutoReconX

scan:
  profile: standard
  timeout: 30
  concurrency: 10

scope:
  allowed: []
  excluded: []

output:
  directory: ./results
  formats:
    - json
    - markdown
    - html

CLI arguments should be able to override non-sensitive configuration values.

19. Error Handling

Modules should fail gracefully.

Example:

Subfinder   ✓
dnsx        ✓
Naabu       ✓
Nmap        ✓
httpx       ✓
Katana      ⚠ failed

The scan should report:

Status: COMPLETED_WITH_WARNINGS

rather than silently pretending everything succeeded.

Every failure should contain:

module
error
timestamp
exit code

when available.

20. Testing Strategy

Testing will use Pytest.

Unit tests
Scope validation
Configuration
Parsers
Normalization
Deduplication
Priority calculation
Integration tests
Tool adapter
     ↓
Parser
     ↓
Normalizer
     ↓
Database
End-to-end

Use our controlled Docker lab:

AutoReconX
     ↓
Lab Environment
     ↓
Complete Scan
     ↓
Expected Assets
     ↓
Compare Results

The E2E tests will not depend on public websites.

21. Docker Lab

We will create a deliberately controlled environment:

                Kali / Host
                    │
                AutoReconX
                    │
             Docker Network
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
      web01       api01       linux01

The lab will contain known:

DNS names
ports
services
web applications
endpoints
technologies

This allows us to verify whether AutoReconX actually discovers what it is supposed to discover.

22. Initial Repository Structure
autoreconx/
│
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── pyproject.toml
├── Dockerfile
│
├── docs/
│   ├── master-specification.md
│   ├── technical-design.md
│   ├── architecture.md
│   └── methodology.md
│
├── src/
│   └── autoreconx/
│       ├── cli/
│       ├── core/
│       ├── modules/
│       ├── models/
│       ├── parsers/
│       ├── correlation/
│       ├── reporting/
│       ├── storage/
│       └── utils/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
│
├── lab/
├── examples/
└── .github/
    └── workflows/
23. Development Order

We will implement it in this exact order:

1. Project skeleton
       ↓
2. Configuration
       ↓
3. Logging
       ↓
4. CLI
       ↓
5. Scope engine
       ↓
6. Command runner
       ↓
7. Subfinder adapter
       ↓
8. dnsx adapter
       ↓
9. Data models
       ↓
10. Normalization
       ↓
11. SQLite storage
       ↓
12. Naabu
       ↓
13. Nmap
       ↓
14. httpx
       ↓
15. Katana
       ↓
16. Correlation
       ↓
17. Prioritization
       ↓
18. Reporting
       ↓
19. Testing
       ↓
20. Docker + CI

This prevents us from building advanced functionality on an unstable foundation.

24. Definition of Done for v1.0

AutoReconX will be considered ready for its first serious GitHub release when:

 Scope enforcement works
 CLI is functional
 All six core tools have adapters
 Tool failures are handled correctly
 Raw outputs are preserved
 Results are normalized
 Duplicate assets are merged
 Provenance is recorded
 Assets are correlated
 Priority ranking works
 SQLite persistence works
 JSON/Markdown/HTML reports work
 Unit tests exist
 Integration tests exist
 Controlled E2E lab works
 Docker deployment works
 GitHub Actions CI works
 Security documentation exists
 Technical documentation is complete
Final Design Principle

The most important architectural decision is this:

                External Tools
                     │
       ┌─────────────┼─────────────┐
       ▼             ▼             ▼
   Discovery    Enumeration     Crawling
       │             │             │
       └─────────────┼─────────────┘
                     ▼
              AutoReconX Core
                     │
       ┌─────────────┼─────────────┐
       ▼             ▼             ▼
   Normalize      Correlate     Prioritize
       │             │             │
       └─────────────┼─────────────┘
                     ▼
              Security Intelligence
                     │
                     ▼
                  Reports

AutoReconX is not valuable because it can execute six existing tools. It becomes valuable when it can reliably transform the outputs of those tools into one coherent, evidence-backed attack-surface model.
