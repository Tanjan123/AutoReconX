# AutoReconX — Technical Design

**Version:** 1.0
**Status:** Pre-Implementation
**Project:** AutoReconX — Automated Reconnaissance & Attack Surface Mapping Framework
**Primary Language:** Python 3.12+
**Target Environment:** Kali Linux / Debian-based Linux
**Database:** SQLite
**License:** MIT
**Author:** Tanjan Singh Karki
**Last Updated:** 2026-08-31

---

## 1. Technical Objective

AutoReconX will act as an orchestration and intelligence layer around established offensive-security reconnaissance tools.

The framework will automate the collection, processing, correlation, and reporting of reconnaissance data.

The high-level pipeline is:

```text
Target
  ↓
Scope Validation
  ↓
Discovery
  ↓
Enumeration
  ↓
HTTP / Web Recon
  ↓
Normalization
  ↓
Correlation
  ↓
Prioritization
  ↓
Storage
  ↓
Reporting
```

The technical design prioritizes:

* Modularity
* Safety
* Reproducibility
* Structured data
* Reliable error handling
* Extensibility

---

## 2. Technology Stack

| Component        | Technology        |
| ---------------- | ----------------- |
| Programming      | Python 3.12+      |
| CLI              | Typer             |
| Configuration    | YAML              |
| Validation       | Pydantic          |
| Database         | SQLite            |
| Database Layer   | SQLAlchemy        |
| Logging          | Python `logging`  |
| Testing          | Pytest            |
| Packaging        | `pyproject.toml`  |
| Reports          | Jinja2 + HTML     |
| Data Formats     | JSON / YAML / XML |
| Version Control  | Git               |
| Containerization | Docker            |
| CI               | GitHub Actions    |

The initial implementation will remain lightweight. Technologies such as PostgreSQL, Redis, Elasticsearch, Kafka, and Kubernetes are intentionally excluded from V1.

---

## 3. External Toolchain

AutoReconX will initially integrate:

| Tool          | Function                            |
| ------------- | ----------------------------------- |
| **Subfinder** | Passive subdomain discovery         |
| **dnsx**      | DNS resolution                      |
| **Naabu**     | Port discovery                      |
| **Nmap**      | Service/version enumeration         |
| **httpx**     | HTTP probing and fingerprinting     |
| **Katana**    | Web crawling and endpoint discovery |

These tools perform the reconnaissance operations while AutoReconX manages their execution and processes their results.

---

## 4. Modular Design

Each reconnaissance capability will operate as an independent module.

Conceptually:

```text
Recon Module
     ↓
Validate
     ↓
Build Command
     ↓
Execute
     ↓
Parse Output
     ↓
Normalize Results
```

Initial modules:

```text
modules/
├── subfinder
├── dnsx
├── naabu
├── nmap
├── httpx
└── katana
```

A common module interface will allow additional tools to be integrated without redesigning the core system.

---

## 5. Scan Context

Every reconnaissance run will use a shared execution context containing information such as:

```text
ScanContext
├── scan_id
├── target
├── scope
├── profile
├── configuration
├── workspace
├── logger
└── discovered_assets
```

Modules will consume this shared context rather than maintaining separate configuration and state.

This provides consistent behavior across the entire reconnaissance pipeline.

---

## 6. Scope & Safety Architecture

Scope validation will occur before reconnaissance begins.

```text
Target
  ↓
Scope Validator
  ↓
Allowed?
 ┌──────┴──────┐
YES           NO
 ↓             ↓
Scan          Reject
```

The system will support:

* Domains and subdomains
* IP addresses
* CIDR ranges
* Explicit exclusions

Reconnaissance will be non-destructive by default.

No module should execute against a target without passing through the scope-control layer.

---

## 7. Command Execution

External tools will be executed through a centralized command runner rather than directly from individual modules.

```text
Module
  ↓
Command Runner
  ↓
External Tool
  ↓
stdout / stderr
  ↓
Parser
```

The runner will manage:

* Argument construction
* Timeouts
* Exit codes
* stdout/stderr
* Process termination
* Execution duration
* Logging

Commands should use structured argument lists instead of unsafe shell-string construction.

Example:

```text
["nmap", "-sV", "-oX", "output.xml", "target"]
```

This reduces command-injection risk within the framework.

---

## 8. Output & Evidence Handling

Raw tool output should be preserved before normalization.

Conceptually:

```text
Raw Output
    ↓
Parser
    ↓
Normalized Data
    ↓
Database
```

Preserving raw output allows us to:

* Debug parsing problems
* Verify results
* Reproduce reconnaissance
* Improve parsers later

Generated scan results will remain local and will not be committed to Git unless specifically intended as sanitized examples.

---

## 9. Data Architecture

AutoReconX will convert different tool outputs into common security entities.

Initial entities include:

```text
Scan
Target
Domain
Subdomain
Host
IP Address
Port
Service
Web Application
URL / Endpoint
Technology
Observation
Tool Execution
```

Relationships will allow the system to represent:

```text
Domain
  ↓
Subdomain
  ↓
IP
  ↓
Port
  ↓
Service
  ↓
Web Application
  ↓
Technology / Endpoint
```

Each observation should retain provenance such as the source tool, scan ID, timestamp, and confidence where applicable.

---

## 10. Correlation & Deduplication

Different tools may discover the same asset.

For example:

```text
Subfinder → api.example.com
dnsx      → api.example.com
httpx     → api.example.com
```

AutoReconX should represent these as one logical asset with multiple evidence sources.

The correlation layer will therefore:

* Normalize identifiers
* Remove duplicates
* Connect related assets
* Preserve discovery sources
* Build the overall attack-surface model

This is a core differentiator of the project.

---

## 11. Scan Profiles

The initial system will support three conceptual profiles:

### Passive

```text
Subfinder
↓
DNS-related discovery
```

### Standard

```text
Subfinder
↓
dnsx
↓
Naabu
↓
Nmap
↓
httpx
```

### Full

```text
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
```

Profiles allow reconnaissance depth to be selected according to the authorized assessment.

---

## 12. Storage

SQLite will be used for V1.

The database will store:

* Scan information
* Targets
* Discovered assets
* Relationships
* Observations
* Tool executions
* Execution status

SQLite is appropriate because AutoReconX is initially designed as a local, single-user CLI framework.

The storage layer should be abstracted enough to allow a future PostgreSQL implementation without redesigning the application.

---

## 13. Prioritization

AutoReconX will identify **investigation priority**, not claim that an asset is vulnerable.

Potential signals include:

* Administrative hostnames
* API-related hosts
* Development/staging indicators
* Authentication endpoints
* Unusual exposed services
* Multiple exposed ports
* Interesting web paths
* Newly discovered assets

Example:

```text
admin.example.com

Priority: HIGH

Reasons:
- Administrative hostname
- Web application detected
- Authentication endpoint
```

The initial scoring system will be transparent and rule-based so that users can understand why an asset was prioritized.

---

## 14. Reporting

Reports will be generated from normalized stored data rather than directly from individual tools.

```text
SQLite
  ↓
Report Engine
  ├── JSON
  ├── Markdown
  └── HTML
```

Reports should contain:

* Target and scope
* Scan information
* Discovery statistics
* Domains/subdomains
* Hosts/IPs
* Ports/services
* Web applications
* Technologies
* Endpoints
* Priority indicators
* Tool provenance
* Errors and limitations

---

## 15. Configuration & Logging

Configuration will be separated from application code.

Initial configuration will control:

* Scan profile
* Tool paths
* Timeouts
* Concurrency
* Output location
* Database location
* Logging level

Sensitive values such as API keys must be supplied through environment variables or protected configuration and must never be committed to Git.

Logging will record important execution events and failures without exposing secrets.

---

## 16. Testing & Reliability

Testing will use Pytest.

### Unit Testing

Core components such as:

* Scope validation
* Configuration
* Parsers
* Normalization
* Deduplication
* Prioritization
* Storage

### Integration Testing

```text
Tool Adapter
     ↓
Parser
     ↓
Normalizer
     ↓
Database
```

### End-to-End Testing

A controlled Docker laboratory will provide known hosts, ports, services, web applications, and endpoints so complete reconnaissance runs can be verified.

Tool failures should be isolated where possible. A partial failure should produce a clear warning rather than silently reporting an incomplete successful scan.

---

## 17. Implementation Principles

The implementation will follow these principles:

1. Keep the core engine independent from external tools.
2. Use adapters for individual reconnaissance tools.
3. Keep raw evidence separate from normalized data.
4. Preserve provenance for important observations.
5. Validate scope before execution.
6. Prefer safe structured process execution.
7. Keep V1 lightweight and locally deployable.
8. Test each component before integrating the next.
9. Avoid unnecessary infrastructure.
10. Design extension points without prematurely implementing them.

**Current Status:** Technical design finalized — implementation not yet started.
