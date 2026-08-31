# AutoReconX — Implementation Plan

**Version:** 1.0
**Status:** Pre-Implementation
**Project:** AutoReconX — Automated Reconnaissance & Attack Surface Mapping Framework
**Parent Documents:** `00-master-specification.md`, `01-technical-design.md`, `02-requirements.md`, `03-architecture.md`
**Primary Language:** Python 3.12+
**Target Environment:** Kali Linux / Debian-based Linux
**Database:** SQLite
**Last Updated:** 2026-08-31

---

## 1. Implementation Objective

This document defines the practical implementation roadmap for AutoReconX.

The project will be developed incrementally, starting with the Python foundation and core execution components before integrating reconnaissance tools.

The implementation flow is:

```text
Project Setup
     ↓
Python Environment
     ↓
Configuration
     ↓
Models
     ↓
Scope & Target Handling
     ↓
Command Runner
     ↓
First Recon Module
     ↓
Parsers & Normalization
     ↓
Remaining Modules
     ↓
SQLite Storage
     ↓
Correlation
     ↓
Prioritization
     ↓
Reporting
     ↓
Testing & Integration
```

The objective is to produce a working system at every major stage rather than building the entire framework before testing it.

---

## 2. Phase 1 — Project Foundation

Create the initial repository and Python package.

Initial structure:

```text
AutoReconX/
├── src/autoreconx/
├── tests/
├── docs/
├── examples/
├── scripts/
├── results/
├── pyproject.toml
├── README.md
├── LICENSE
└── .gitignore
```

Tasks:

* Initialize Git repository.
* Configure `pyproject.toml`.
* Create Python virtual environment.
* Configure development dependencies.
* Establish package structure.
* Add basic logging.
* Configure `.gitignore`.
* Create initial README.
* Make the first Git commit.

The repository should run successfully before reconnaissance functionality is added.

---

## 3. Phase 2 — Configuration System

Implement centralized configuration using YAML and validated Python models.

Configuration should support:

```text
Profile
Tool paths
Timeouts
Concurrency
Output directory
Database location
Logging level
Enabled modules
```

Pydantic will validate configuration values.

Environment variables should be used for sensitive values where required.

Example conceptual configuration:

```yaml
profile: standard

timeouts:
  default: 120

concurrency: 4

output:
  directory: results/

database:
  path: results/autoreconx.db
```

Configuration loading and validation should be tested before continuing.

---

## 4. Phase 3 — Core Models

Implement the internal data models required by the framework.

Initial models:

```text
Scan
Target
Domain
Subdomain
IP Address
Port
Service
URL
Technology
Observation
ToolExecution
```

Models should represent normalized reconnaissance information rather than raw tool-specific output.

Important metadata should include:

* Unique identifier
* Source/tool
* Scan ID
* Timestamp
* Confidence where applicable
* Relationships

These models become the common language between modules, parsers, storage, and reporting.

---

## 5. Phase 4 — Scope & Target Engine

Implement target validation before any external tool can execute.

The scope engine should support:

```text
Domain
Subdomain
IPv4 / IPv6
CIDR
Explicit exclusions
```

Responsibilities:

* Validate target syntax.
* Normalize target representation.
* Store authorized scope.
* Apply exclusions.
* Prevent unintended target expansion.
* Provide a final target list to the execution engine.

Testing should include both valid and invalid targets.

No reconnaissance module should bypass this component.

---

## 6. Phase 5 — Command Execution Engine

Implement the centralized command runner.

Conceptually:

```text
Module
   ↓
Command Specification
   ↓
Command Runner
   ↓
External Tool
   ↓
Execution Result
```

The runner should manage:

* Executable validation
* Argument handling
* Process execution
* stdout/stderr
* Exit status
* Timeout
* Execution duration
* Process failure
* Logging

Commands should use structured argument lists rather than shell command strings.

Example:

```python
["nmap", "-sV", "-oX", "output.xml", target]
```

The command runner should be tested independently before integrating reconnaissance modules.

---

## 7. Phase 6 — First Reconnaissance Module

The first implementation module should be **Subfinder** because it provides a clear starting point for the reconnaissance pipeline.

Initial flow:

```text
Target
  ↓
Scope Validation
  ↓
Subfinder
  ↓
Raw Output
  ↓
Parser
  ↓
Normalized Subdomains
```

The module should:

1. Validate prerequisites.
2. Build the command.
3. Execute through the central runner.
4. Preserve raw output.
5. Parse results.
6. Normalize discovered domains/subdomains.
7. Return structured results.

This module becomes the reference implementation for the common module interface.

---

## 8. Phase 7 — DNS & Network Modules

After the first module is stable, implement:

```text
dnsx
  ↓
Naabu
  ↓
Nmap
```

### DNS Module

Resolve discovered domains/subdomains and capture relevant DNS relationships.

### Port Module

Use Naabu for controlled port discovery.

### Service Module

Use Nmap for detailed service/version enumeration against discovered hosts and ports.

The resulting flow becomes:

```text
Subfinder
    ↓
dnsx
    ↓
Naabu
    ↓
Nmap
```

Each module should be independently testable and should consume normalized data from previous stages where appropriate.

---

## 9. Phase 8 — HTTP & Web Reconnaissance

Implement the web reconnaissance modules:

```text
httpx
  ↓
Katana
```

### HTTP Module

Collect useful HTTP information such as:

* URL
* HTTP/HTTPS status
* Title
* Server indicators
* Technology indicators where available
* Response metadata

### Crawl Module

Use Katana to discover URLs/endpoints from confirmed web applications.

The extended pipeline becomes:

```text
Subdomain
    ↓
DNS
    ↓
Ports
    ↓
Services
    ↓
HTTP
    ↓
Crawl
```

Web crawling should only operate on discovered and permitted web targets.

---

## 10. Phase 9 — Parsing & Normalization

Build parser components for each supported tool.

```text
Raw Output
    ↓
Tool Parser
    ↓
Normalized Model
```

Parsers should support the most reliable structured output available from each tool.

Normalization should:

* Standardize domains.
* Normalize IP addresses.
* Normalize ports/services.
* Normalize URLs.
* Remove duplicate observations.
* Preserve source information.
* Preserve scan/run relationships.

Parser tests should use sanitized fixture files instead of requiring live targets for every unit test.

---

## 11. Phase 10 — SQLite Storage

Implement the persistence layer using SQLAlchemy and SQLite.

Storage should support:

```text
Runs
Targets
Assets
Relationships
Observations
Tool Executions
```

The storage layer should provide operations for:

* Creating a scan.
* Storing discovered assets.
* Updating existing assets.
* Recording relationships.
* Recording tool execution results.
* Querying normalized reconnaissance data.

Database operations should be tested independently from external reconnaissance tools.

---

## 12. Phase 11 — Correlation & Deduplication

Implement the correlation layer after normalized data and storage are stable.

Example:

```text
Subfinder → api.example.com
dnsx      → api.example.com
httpx     → https://api.example.com
```

These observations should be correlated into a logical attack-surface representation.

The correlation layer should:

* Identify equivalent assets.
* Connect domains to IPs.
* Connect IPs to ports.
* Connect ports to services.
* Connect hosts to URLs.
* Connect URLs to technologies.
* Preserve multiple evidence sources.

This stage is one of the main areas where AutoReconX adds value beyond simply running existing tools.

---

## 13. Phase 12 — Prioritization

Implement a transparent rule-based priority engine.

Possible signals include:

```text
Administrative hostname
API hostname
Development/staging hostname
Authentication endpoint
Unusual exposed service
Multiple open ports
Interesting web path
Newly discovered asset
```

The result should explain **why** an asset received a priority.

Example:

```text
Asset: admin.example.com

Priority: HIGH

Reasons:
- Administrative hostname
- Web application detected
- Authentication endpoint
```

The system must distinguish **investigation priority** from confirmed vulnerability.

---

## 14. Phase 13 — Reporting

Implement report generation from normalized SQLite data.

Initial outputs:

```text
JSON
HTML
```

Reports should include:

* Target and scope
* Scan information
* Discovery statistics
* Domains/subdomains
* IP addresses
* Ports
* Services
* Web applications
* Technologies
* Endpoints
* Priority indicators
* Tool provenance
* Errors and limitations

The reporting layer should not depend directly on individual reconnaissance tools.

---

## 15. Phase 14 — CLI Integration

Once the underlying components work, integrate them into the Typer-based CLI.

The CLI should eventually support workflows such as:

```bash
autoreconx --target example.com
```

Module selection:

```bash
autoreconx --target example.com --modules subdomain,dns,http
```

Output configuration:

```bash
autoreconx --target example.com --output results/
```

Additional commands/options will be introduced only when required by the implementation.

The CLI should provide clear progress information, warnings, errors, and final result locations.

---

## 16. Phase 15 — Testing & Laboratory Validation

Testing will occur continuously rather than only at the end.

### Unit Tests

Test:

* Configuration
* Scope validation
* Models
* Command construction
* Parsers
* Normalization
* Deduplication
* Prioritization
* Storage

### Integration Tests

Verify:

```text
Module
  ↓
Runner
  ↓
External Tool
  ↓
Parser
  ↓
Normalizer
  ↓
Database
```

### End-to-End Test

Use a controlled Docker laboratory with known hosts, services, ports, and web applications.

A complete scan should execute:

```text
Target
 ↓
Discovery
 ↓
DNS
 ↓
Ports
 ↓
Services
 ↓
HTTP
 ↓
Crawl
 ↓
Correlation
 ↓
Priority
 ↓
Storage
 ↓
Report
```

---

## 17. Git & Development Workflow

Development should follow small, traceable changes.

```text
Implement
   ↓
Test
   ↓
Review
   ↓
Document
   ↓
Commit
```

Commits should represent meaningful components, for example:

```text
Initialize project structure
Add configuration system
Implement scope validator
Add command runner
Add Subfinder module
Add DNS module
Add port scanning module
...
```

Generated reconnaissance results, databases containing real assessment data, secrets, and local environment files should not be committed to Git.

---

## 18. V1 Completion Criteria

V1 will be considered implementation-complete when AutoReconX can:

1. Accept and validate an authorized target.
2. Enforce configured scope.
3. Execute reconnaissance modules through the central runner.
4. Detect missing external dependencies.
5. Collect raw tool output and execution metadata.
6. Parse and normalize reconnaissance results.
7. Correlate major asset relationships.
8. Store results in SQLite.
9. Assign explainable investigation priorities.
10. Generate JSON and HTML reports.
11. Handle partial tool failures without silently producing false results.
12. Complete an end-to-end reconnaissance run against the controlled laboratory environment.

---

## 19. Implementation Order

The final implementation sequence is:

```text
01. Repository & Python Environment
        ↓
02. Configuration
        ↓
03. Core Models
        ↓
04. Scope & Target Engine
        ↓
05. Command Runner
        ↓
06. Subfinder Module
        ↓
07. dnsx Module
        ↓
08. Naabu Module
        ↓
09. Nmap Module
        ↓
10. httpx Module
        ↓
11. Katana Module
        ↓
12. Parsers & Normalization
        ↓
13. SQLite Storage
        ↓
14. Correlation
        ↓
15. Prioritization
        ↓
16. Reporting
        ↓
17. CLI Integration
        ↓
18. Testing & Lab Validation
        ↓
19. V1 Documentation & Release
```

The sequence may be adjusted when implementation reveals technical dependencies, but changes should remain consistent with the architecture defined in `03-architecture.md`.

---

**Current Status:** Implementation plan finalized — ready to begin Phase 1: project repository and Python environment setup.
