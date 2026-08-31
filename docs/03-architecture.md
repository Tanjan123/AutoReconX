# AutoReconX — System Architecture

**Version:** 1.0
**Status:** Pre-Implementation
**Project:** AutoReconX — Automated Reconnaissance & Attack Surface Mapping Framework
**Parent Documents:** `00-master-specification.md`, `01-technical-design.md`, `02-requirements.md`
**Primary Language:** Python 3.12+
**Target Environment:** Kali Linux / Debian-based Linux
**Database:** SQLite
**License:** MIT
**Author:** Tanjan Singh Karki
**Last Updated:** 2026-08-31

---

## 1. Architecture Objective

AutoReconX will use a modular architecture where a central Python engine orchestrates specialized reconnaissance tools, processes their output, correlates discovered assets, assigns priority, and produces structured reports.

The framework is intended to add **automation, normalization, correlation, and reporting** around existing security tools rather than replacing them.

---

## 2. High-Level Architecture

```text
                         User
                          │
                          ▼
                    ┌───────────┐
                    │    CLI    │
                    └─────┬─────┘
                          │
                          ▼
                ┌───────────────────┐
                │   Core Engine     │
                │                   │
                │ Scope Validation  │
                │ Run Management    │
                │ Module Control    │
                └─────────┬─────────┘
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
        Discovery      Scanning      Web
             │            │            │
        Subfinder       Naabu       httpx
        dnsx            Nmap        Katana
             │            │            │
             └────────────┼────────────┘
                          ▼
                 ┌─────────────────┐
                 │ Output Parsers  │
                 └────────┬────────┘
                          ▼
                 ┌─────────────────┐
                 │ Normalization   │
                 └────────┬────────┘
                          ▼
                 ┌─────────────────┐
                 │ Asset Correlation│
                 └────────┬────────┘
                          ▼
                 ┌─────────────────┐
                 │ Priority Engine │
                 └────────┬────────┘
                          ▼
                 ┌─────────────────┐
                 │ Storage / SQLite│
                 └────────┬────────┘
                          ▼
                 ┌─────────────────┐
                 │ Reporting       │
                 │ JSON / HTML     │
                 └─────────────────┘
```

---

## 3. Core Components

AutoReconX will initially consist of the following logical components:

### 3.1 CLI Layer

Responsible for:

* Accepting user arguments
* Selecting targets
* Selecting modules
* Configuring output
* Starting reconnaissance runs
* Displaying progress and errors

The CLI should remain separate from the core engine so the framework can later support other interfaces.

### 3.2 Core Engine

The core engine coordinates the complete workflow.

Responsibilities include:

* Creating reconnaissance runs
* Validating scope
* Loading configuration
* Selecting modules
* Managing execution order
* Handling failures
* Passing results between modules
* Triggering storage and reporting

### 3.3 Tool Runner

A dedicated execution layer will interact with external binaries.

Responsibilities:

* Verify executable availability
* Build commands from validated parameters
* Execute processes safely
* Capture stdout/stderr
* Track exit codes
* Enforce timeouts
* Record execution metadata

External commands should not be scattered throughout the application.

### 3.4 Reconnaissance Modules

Each major reconnaissance capability will be implemented as an independent module.

Initial modules:

```text
subdomain
dns
ports
services
http
crawl
```

Each module should have a predictable interface so additional tools can be integrated later.

---

## 4. Initial Tool Mapping

| Module    | Primary Tool | Output                 |
| --------- | ------------ | ---------------------- |
| Subdomain | Subfinder    | Domains/subdomains     |
| DNS       | dnsx         | Resolved DNS records   |
| Ports     | Naabu        | Open ports             |
| Services  | Nmap         | Services/versions      |
| HTTP      | httpx        | URLs/status/technology |
| Crawl     | Katana       | URLs/endpoints         |

A module may eventually support multiple tools, but V1 should keep one primary implementation per capability.

---

## 5. Data Flow

Data will move through several transformations:

```text
Raw Tool Output
      ↓
Parser
      ↓
Normalized Object
      ↓
Correlation
      ↓
Priority
      ↓
Database
      ↓
Report
```

For example:

```text
Subfinder
   ↓
example.com
api.example.com
dev.example.com
   ↓
Normalized Asset
   ↓
DNS resolution
   ↓
IP relationship
   ↓
HTTP probing
   ↓
URL + status + technology
   ↓
Priority
```

This prevents every external tool from requiring custom logic throughout the entire application.

---

## 6. Common Data Model

AutoReconX will use normalized entities rather than storing unrelated raw strings.

Initial entities:

```text
Run
Target
Domain
Subdomain
IP Address
Port
Service
URL
Technology
Finding / Observation
Tool Execution
```

Relationships may include:

```text
Domain → Subdomain
Subdomain → IP
IP → Port
Port → Service
Domain/Subdomain → URL
URL → Technology
Asset → Observation
Run → Assets
Run → Tool Executions
```

Each discovered asset should retain useful provenance such as:

* Discovery source
* Tool
* Run ID
* Timestamp
* Confidence where applicable

---

## 7. Storage Architecture

SQLite will be used for the initial version because it is:

* Lightweight
* Local
* Easy to deploy
* Suitable for a single-user reconnaissance framework
* Easy to back up and inspect

Conceptually:

```text
SQLite
 ├── runs
 ├── targets
 ├── assets
 ├── domains
 ├── ip_addresses
 ├── ports
 ├── services
 ├── urls
 ├── technologies
 ├── observations
 └── tool_executions
```

The schema will be finalized before implementation.

---

## 8. Module Interface

Reconnaissance modules should follow a common conceptual interface:

```text
Module
 ├── name
 ├── description
 ├── dependencies
 ├── validate()
 ├── build_command()
 ├── execute()
 ├── parse()
 └── normalize()
```

This allows the core engine to treat different reconnaissance tools consistently.

For example:

```text
Core Engine
    │
    ├── SubdomainModule
    ├── DNSModule
    ├── PortModule
    ├── ServiceModule
    ├── HTTPModule
    └── CrawlModule
```

---

## 9. Execution Strategy

The initial execution strategy will be sequential where dependencies exist and parallel where tasks are independent.

Example:

```text
Subdomain Discovery
        ↓
DNS Resolution
        ↓
        ├──────────────┐
        ▼              ▼
     Port Scan      HTTP Probe
        │              │
        ▼              ▼
      Nmap           Crawl
        └──────┬───────┘
               ▼
          Correlation
```

Parallel execution will be introduced carefully with configurable concurrency limits.

Reliability is more important than maximum scan speed in V1.

---

## 10. Scope & Safety Layer

Scope validation must occur before reconnaissance begins.

The safety layer should:

* Validate target syntax
* Track authorized targets
* Prevent accidental target expansion
* Apply configured execution limits
* Use non-destructive reconnaissance by default
* Prevent automatic exploitation

The system should make the target and scope visible in both CLI output and generated reports.

---

## 11. Error & Failure Model

Failures should be isolated where possible.

Example:

```text
Subfinder
   ↓
Success

dnsx
   ↓
Success

Naabu
   ↓
Failure
   ↓
Log failure
   ↓
Continue permitted stages
```

The system should distinguish between:

```text
INFO
WARNING
ERROR
FATAL
```

A failed optional module should not automatically destroy all previously collected reconnaissance data.

---

## 12. Configuration

Configuration should eventually control:

* Tool paths
* Default timeouts
* Concurrency
* Enabled modules
* Output directory
* Database location
* Logging level
* Scan profiles

Configuration should be separated from source code.

Secrets such as API keys must be supplied through environment variables or protected configuration and must never be committed to Git.

---

## 13. Reporting Architecture

Reporting will consume normalized database data rather than raw tool output.

```text
SQLite
   ↓
Report Data Layer
   ↓
 ┌───────────────┐
 │               │
 ▼               ▼
JSON            HTML
```

JSON will provide machine-readable results.

HTML will provide a human-readable reconnaissance summary containing:

* Target and scope
* Run information
* Discovered assets
* Open ports
* Services
* HTTP endpoints
* Technologies
* Priority indicators
* Tool/provenance information

---

## 14. Project Directory Architecture

The implementation is expected to follow this structure:

```text
AutoReconX/
│
├── src/
│   └── autoreconx/
│       ├── core/
│       ├── cli/
│       ├── modules/
│       ├── runner/
│       ├── parsers/
│       ├── models/
│       ├── storage/
│       ├── correlation/
│       ├── prioritization/
│       ├── reporting/
│       └── utils/
│
├── tests/
│   ├── unit/
│   └── integration/
│
├── docs/
├── examples/
├── scripts/
├── results/
├── pyproject.toml
├── README.md
├── LICENSE
└── .gitignore
```

`results/` will remain locally generated and excluded from Git where appropriate.

---

## 15. Architecture Principles

AutoReconX development will follow these principles:

1. **Modular:** components can be replaced or extended.
2. **Tool-agnostic:** external tools remain replaceable.
3. **Observable:** executions and failures are logged.
4. **Traceable:** results retain provenance.
5. **Safe by default:** reconnaissance only, with explicit scope.
6. **Testable:** core logic should be independently testable.
7. **Reproducible:** configurations and tool versions should be documented.
8. **Incremental:** functionality will be implemented and verified in stages.

---

## 16. Future Extension Points

The architecture should allow future additions without redesigning the entire system.

Potential future capabilities include:

* Additional reconnaissance tools
* Passive intelligence providers
* Technology fingerprinting improvements
* Advanced asset correlation
* More sophisticated prioritization
* PostgreSQL support
* API interface
* Web dashboard
* Plugin system
* Scheduled reconnaissance
* Export to security platforms

Automated exploitation is **not part of the initial architecture** and should not be introduced without a separate security and authorization design.

---

## 17. Architecture Acceptance Criteria

The architecture will be considered ready for implementation when:

* Core components have defined responsibilities.
* Reconnaissance modules have a common interface.
* External tool execution is isolated in the runner.
* Raw outputs can be parsed and normalized.
* Assets can be related through a common data model.
* Results can be persisted in SQLite.
* Reporting can operate from normalized data.
* Scope and safety controls exist before execution.
* Unit and integration testing locations are defined.

**Current status:** Architecture defined — implementation not yet started.

