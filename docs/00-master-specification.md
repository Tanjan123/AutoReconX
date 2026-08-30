# AutoReconX — Master Project Specification v1.0
**Project:** AutoReconX
**Full Name:**  Automated Reconnaissance & Attack Surface Mapping Framework
**Project Category:** Offensive Security / Reconnaissance / Security Automation
**Primary Language:** Python 3.12+
**Target OS:** Linux, primarily Kali/Debian-based systems
**Deployment:** Native + Docker
**Initial Database:** SQLite
**Future Database:** PostgreSQL
**License Target:** MIT
**Development Model:** Modular / plugin-oriented
**Current Phase:** Architecture & Requirements
**Version:** 1.0 Specification

________________________________________
1. Executive Summary
AutoReconX is a modular offensive-security reconnaissance framework designed to automate the repetitive stages of authorized reconnaissance and attack-surface discovery.
The framework will integrate established open-source security tools rather than attempting to replace them.
The core tools are:
•	Subfinder
•	dnsx
•	Naabu
•	Nmap
•	httpx
•	Katana
The framework's own value will come from:
•	scope validation
•	orchestration
•	execution management
•	output normalization
•	asset correlation
•	deduplication
•	provenance tracking
•	structured storage
•	asset classification
•	prioritization
•	scan comparison
•	reporting
The intended workflow is:
Authorized Target
       │
       ▼
 Scope Validation
       │
       ▼
 Passive Discovery
       │
       ▼
 Subdomain Discovery
       │
       ▼
 DNS Resolution
       │
       ▼
 Port Discovery
       │
       ▼
 Service Enumeration
       │
       ▼
 HTTP Probing
       │
       ▼
 Web Crawling
       │
       ▼
 Technology Identification
       │
       ▼
 Asset Correlation
       │
       ▼
 Attack-Surface Classification
       │
       ▼
 Priority Assessment
       │
       ▼
 Structured Database
       │
       ▼
 Professional Reports
The framework will not automatically exploit discovered systems.
Its purpose is:
Discover → enumerate → correlate → prioritize → report
________________________________________
2. Why Are We Building It?
Modern reconnaissance involves many specialized tools.
For example:
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
Each tool is good at a particular task.
The difficulty comes after the tools finish.
A tester might have:
subdomains.txt
resolved.txt
ports.txt
nmap.xml
httpx.json
urls.txt
The tester then manually attempts to understand the relationships.
AutoReconX will instead produce:
Domain
 ├── Subdomain
 │     ├── IP
 │     │    ├── Port
 │     │    │    └── Service
 │     │    └── Web Application
 │     │           ├── Technology
 │     │           └── Endpoint
 │     └── Metadata
 └── Provenance
This is the central engineering problem.
________________________________________
3. Project Vision
The long-term vision is:
Create an open-source reconnaissance intelligence platform that converts raw discovery results into a structured, correlated and prioritized representation of an authorized target's attack surface.
The project should eventually allow a penetration tester to answer:
What exists?
Assets.
Where is it?
DNS/IP/network location.
What is exposed?
Ports/services/web applications.
What is running?
Technologies and service metadata.
What changed?
Historical scan comparison.
What should I investigate first?
Prioritization.
________________________________________
4. Project Objectives
O1 — Automated reconnaissance
Provide a repeatable end-to-end reconnaissance workflow.
O2 — Tool orchestration
Integrate specialized security tools through controlled adapters.
O3 — Structured data
Convert heterogeneous tool output into common internal models.
O4 — Asset correlation
Create relationships between domains, hosts, ports, services, applications and endpoints.
O5 — Deduplication
Prevent duplicate assets when multiple sources discover the same object.
O6 — Provenance
Track where every observation came from.
O7 — Prioritization
Identify assets that deserve manual investigation.
O8 — Reporting
Generate professional machine-readable and human-readable reports.
O9 — Reproducibility
Allow scans to be reproduced using recorded configuration and tool versions.
O10 — Extensibility
Allow additional reconnaissance modules to be added without redesigning the framework.
________________________________________
5. Non-Goals
AutoReconX v1.0 will not be:
•	an exploitation framework
•	a password cracker
•	a credential attack framework
•	a malware platform
•	a persistence framework
•	a C2 framework
•	a privilege-escalation framework
•	a lateral-movement framework
•	a full vulnerability scanner
•	an automatic "AI hacker"
This is an important architectural boundary.
________________________________________
6. Security and Authorization Model
AutoReconX is intended exclusively for authorized testing.
Permitted environments include:
Owned systems
Authorized penetration tests
Authorized bug bounty targets
CTF environments
Intentionally vulnerable laboratories
Private research environments
The framework must not be marketed as providing authorization.
Authorization must exist independently of the software.
________________________________________
7. Methodology
The project will use established security-testing methodology.
For web reconnaissance, we will use the OWASP Web Security Testing Guide as a methodological reference. The current WSTG explicitly covers information gathering, server/framework fingerprinting, application entry points, architecture mapping and API testing. (OWASP Foundation)
The WSTG emphasizes testing that is:
•	consistent
•	reproducible
•	rigorous
•	documented
which fits the engineering goals of AutoReconX. (OWASP Foundation)
For network reconnaissance, Nmap's official documentation will be used.
________________________________________
8. Core Toolchain
8.1 Subfinder
Purpose
Passive subdomain discovery.
Subfinder is specifically designed for passive subdomain enumeration and supports multiple passive sources, JSON output and stdin/stdout integration. (GitHub)
AutoReconX role
Domain
 ↓
Subfinder
 ↓
Candidate subdomains
Important design decision
Subfinder will be treated as a discovery source, not as our database.
________________________________________
9. dnsx
Purpose
DNS resolution and record enumeration.
Current dnsx supports A, AAAA, CNAME, PTR, NS, MX, TXT, SRV and SOA queries, custom resolvers and wildcard handling. (GitHub)
AutoReconX role
Subdomains
    ↓
   dnsx
    ↓
Resolved assets
Important feature
Wildcard detection must be accounted for because wildcard DNS can create misleading discovery results.
________________________________________
10. Naabu
Purpose
Fast port discovery.
Naabu is a ProjectDiscovery port scanner designed for fast network port discovery and supports pipeline-style operation. Its current installation documentation requires libpcap on Linux. (GitHub)
AutoReconX role
Resolved hosts
      ↓
    Naabu
      ↓
Candidate open ports
Naabu provides breadth.
________________________________________
11. Nmap
Purpose
Detailed network/service enumeration.
Nmap remains our deeper enumeration engine.
It provides:
•	port states
•	service detection
•	version detection
•	NSE capabilities
•	multiple output formats
Nmap's documentation identifies XML as the preferred programmatic interface because it is structured, extensible and designed for parsing. (Nmap)
AutoReconX strategy
Naabu
 ↓
Fast port discovery
 ↓
Nmap
 ↓
Detailed enumeration
This avoids using Nmap for every discovery stage unnecessarily.
________________________________________
12. httpx
Purpose
HTTP service discovery and fingerprinting.
Current httpx supports numerous probes and structured output and is designed for HTTP reconnaissance workflows. (GitHub)
AutoReconX role
Hosts + ports
       ↓
     httpx
       ↓
HTTP services
       ↓
Metadata
Potential collected information:
URL
Scheme
Port
Status code
Title
Content type
Content length
Redirect
Server
TLS information
Technology indicators
________________________________________
13. Katana
Purpose
Web crawling and endpoint discovery.
The current Katana project supports standard and headless crawling, JavaScript parsing/crawling, scope control, known-file discovery and JSON output. (GitHub)
AutoReconX role
Live web application
        ↓
      Katana
        ↓
URLs
Endpoints
Parameters
JS-related discoveries
Katana will be used carefully because crawling is more active than passive discovery.
________________________________________
14. Why We Are Not Adding More Tools Yet
A common mistake in security projects is:
"More tools = better project."
No.
We want:
Clear responsibility
        ↓
Reliable module
        ↓
Normalized output
        ↓
Correlated intelligence
We deliberately aren't making these core v1 dependencies:
Nuclei
ffuf
Gobuster
Dirsearch
SQLMap
Metasploit
Hydra
Nikto
Some may become useful in later projects.
For example:
•	Nuclei → vulnerability validation
•	ffuf → content discovery
•	Burp → manual web testing
•	SQLMap → controlled SQLi validation
Those belong more naturally in WebStrike/BugHuntX.
________________________________________
15. Architecture
The architecture will have seven layers.
┌───────────────────────────────────────┐
│                 CLI                   │
└───────────────────┬───────────────────┘
                    │
┌───────────────────▼───────────────────┐
│          Scan / Job Controller        │
└───────────────────┬───────────────────┘
                    │
┌───────────────────▼───────────────────┐
│             Scope Engine              │
└───────────────────┬───────────────────┘
                    │
┌───────────────────▼───────────────────┐
│          Reconnaissance Modules       │
│ Subfinder | dnsx | Naabu | Nmap | ... │
└───────────────────┬───────────────────┘
                    │
┌───────────────────▼───────────────────┐
│          Normalization Layer          │
└───────────────────┬───────────────────┘
                    │
┌───────────────────▼───────────────────┐
│      Correlation / Intelligence       │
└───────────────────┬───────────────────┘
                    │
┌───────────────────▼───────────────────┐
│         Storage + Reporting           │
└───────────────────────────────────────┘
________________________________________
16. Layer 1 — CLI
The CLI is the user's interface.
Initial commands:
autoreconx --help
autoreconx version
autoreconx scan
autoreconx validate
autoreconx report
autoreconx status
autoreconx config
Example:
autoreconx scan \
  --target example.local \
  --profile standard
________________________________________
17. Layer 2 — Scan Controller
The controller manages the complete job.
Responsibilities:
•	initialize scan
•	load configuration
•	validate target
•	execute modules
•	manage dependencies
•	handle failures
•	record timing
•	save results
•	generate report
Conceptually:
Scan Job
 │
 ├── scope
 ├── configuration
 ├── modules
 ├── status
 ├── timestamps
 ├── results
 └── errors
________________________________________
18. Layer 3 — Scope Engine
This is one of our most important components.
Example:
scope:
  allowed:
    - "*.lab.local"

  excluded:
    - "production.lab.local"
    - "payments.lab.local"
The engine should determine:
Is target allowed?
       │
   ┌───┴───┐
   │       │
 YES       NO
   │       │
Scan     Reject
No active module should bypass this layer.
________________________________________
19. Layer 4 — Recon Modules
Each external tool becomes an adapter.
modules/
├── subfinder.py
├── dnsx.py
├── naabu.py
├── nmap.py
├── httpx.py
└── katana.py
Each adapter will implement a common interface.
________________________________________
20. Module Contract
Conceptually:
class ReconModule:
    def metadata(self):
        ...

    def validate(self, context):
        ...

    def build_command(self, context):
        ...

    def execute(self, context):
        ...

    def parse(self, output):
        ...

    def normalize(self, parsed_data):
        ...
The exact implementation will be finalized during the technical design phase.
________________________________________
21. Why Adapter Architecture?
Suppose we later add:
Amass
We shouldn't rewrite:
CLI
database
correlation
reporting
We should simply add:
amass.py
This is what makes the framework extensible.
________________________________________
22. Layer 5 — Normalization
Every external tool speaks its own format.
Our system should translate them into a common model.
For example:
Subfinder
   ↓
SubdomainObservation

dnsx
   ↓
DNSObservation

Naabu
   ↓
PortObservation

Nmap
   ↓
ServiceObservation

httpx
   ↓
WebObservation

Katana
   ↓
EndpointObservation
Then:
Observations
      ↓
Canonical Asset Model
________________________________________
23. Layer 6 — Correlation
This is the heart of AutoReconX.
Example:
api.lab.local
      │
      ▼
10.10.10.20
      │
 ┌────┴─────┐
 ▼          ▼
22/tcp     443/tcp
 │           │
SSH        HTTPS
             │
             ▼
       https://api.lab.local
             │
        ┌────┼────┐
        ▼    ▼    ▼
      /api /auth /docs
The framework should understand that these are not unrelated strings.
They represent one attack-surface graph.
________________________________________
24. Layer 7 — Storage
Initial database:
SQLite
Why?
•	zero external database server
•	simple deployment
•	easy testing
•	portable
•	sufficient for v1
•	excellent for a local CLI tool
Later:
PostgreSQL
when we introduce:
•	multiple users
•	web dashboard
•	scheduled scans
•	concurrent jobs
•	large datasets
________________________________________
25. Core Data Model
We will start with:
Scan
Domain
Subdomain
Host
IP
DNSRecord
Port
Service
WebApplication
Endpoint
Technology
Observation
AssetRelationship
Priority
________________________________________
26. Domain
Domain
------
id
name
scan_id
created_at
Example:
example.local
________________________________________
27. Subdomain
Subdomain
---------
id
domain_id
hostname
source
status
first_seen
last_seen
Example:
api.example.local
dev.example.local
admin.example.local
________________________________________
28. Host/IP
Host
----
id
hostname
ip
ipv6
asn
organization
We should not assume one hostname equals one IP.
One hostname can resolve to:
IP A
IP B
IP C
and one IP may host:
host1
host2
host3
Our model must support this.
________________________________________
29. Port
Port
----
id
host_id
number
protocol
state
source
________________________________________
30. Service
Service
-------
id
port_id
name
product
version
banner
confidence
source
Example:
443/tcp
HTTPS
nginx
version unknown
________________________________________
31. Web Application
WebApplication
--------------
id
host_id
scheme
port
url
status_code
title
server
content_type
________________________________________
32. Endpoint
Endpoint
--------
id
web_application_id
url
method
parameter
source
We should distinguish:
URL
from:
Endpoint
because a URL may contain a resource while an endpoint represents a logical application interface.
________________________________________
33. Technology
Technology
----------
id
name
category
version
confidence
source
Example:
nginx
web-server
unknown
high
httpx
________________________________________
34. Observation
This is another important model.
Instead of immediately treating everything as fact:
Observation
------------
id
asset_id
source
type
value
confidence
timestamp
raw_reference
Example:
Source:
httpx

Observation:
Server header indicates nginx

Confidence:
High
This preserves evidence.
________________________________________
35. Provenance
Every important discovery should answer:
Where did this information come from?
Example:
api.example.local

Sources:
- subfinder
- certificate transparency
- DNS resolution
This will help with:
•	debugging
•	duplicate handling
•	reporting
•	scan comparison
•	evidence quality
________________________________________
36. Deduplication
Example:
Subfinder → api.example.local
dnsx      → api.example.local
HTTPX     → api.example.local
Database result:
ONE asset

Sources:
Subfinder
dnsx
httpx
Not:
THREE assets
________________________________________
37. Scan Profiles
We'll support three initial profiles.
Passive
Subfinder
DNS
Passive metadata
Minimal active interaction.
________________________________________
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
________________________________________
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
 ↓
Reporting
________________________________________
38. Why Profiles Matter
Different assessments have different constraints.
For example:
Bug bounty
may have strict rate limits.
A lab may permit:
Full reconnaissance
An enterprise assessment may require:
Low-impact discovery
Therefore:
Reconnaissance intensity must be configurable.
________________________________________
39. Prioritization Engine
This is where AutoReconX starts becoming an intelligence platform.
It will not calculate vulnerability severity.
Instead it calculates:
Attack-surface investigation priority.
________________________________________
40. Priority Signals
Potential signals:
Administrative hostname
API hostname
Development hostname
Staging hostname
Authentication endpoint
Unusual exposed service
Multiple exposed ports
Newly discovered asset
Technology fingerprint
Sensitive path
Internet-facing service
________________________________________
41. Example
admin.example.local

Signals:
Administrative hostname     +30
Authentication page         +15
HTTPS exposed               +10
Unique application          +10
Newly discovered             +5

Priority:
70/100
This does not mean:
70% vulnerable.
It means:
High priority for manual investigation.
________________________________________
42. Confidence vs Priority
We must keep these separate.
Confidence
How confident are we that an observation is correct?
Priority
How important is it to investigate?
Example:
nginx detected
Confidence: 98%
Priority: 20
versus:
admin portal discovered
Confidence: 91%
Priority: 90
This distinction is important.
________________________________________
43. No Automatic Vulnerability Claims
AutoReconX should use language like:
Potentially interesting asset.
Not:
Vulnerable server.
For example:
Observation:
Apache server detected.

Recommendation:
Review version and configuration during manual assessment.

Status:
UNVERIFIED
This prevents the system from generating misleading findings.
________________________________________
44. Reporting
Three primary formats:
JSON
Markdown
HTML
________________________________________
45. JSON
Designed for:
•	APIs
•	future BugHuntX integration
•	machine processing
•	testing
•	automation
________________________________________
46. Markdown
Designed for:
•	GitHub
•	notes
•	assessment documentation
•	quick review
________________________________________
47. HTML
Designed for:
•	human review
•	demonstrations
•	portfolio screenshots
•	professional-looking reports
________________________________________
48. Report Structure
AUTORECONX RECONNAISSANCE REPORT

1. Executive Summary
2. Scope
3. Scan Configuration
4. Methodology
5. Tool Versions
6. Scan Timeline
7. Discovery Statistics
8. Domains & Subdomains
9. DNS Records
10. Hosts & IP Addresses
11. Open Ports
12. Services
13. Web Applications
14. Technologies
15. Endpoints
16. Interesting Assets
17. Priority Ranking
18. Observations
19. Errors / Limitations
20. Recommendations
________________________________________
49. Tool Version Recording
This is a feature I strongly recommend adding from the beginning.
Example:
Toolchain

AutoReconX: 0.1.0
Subfinder: x.x.x
dnsx: x.x.x
Naabu: x.x.x
Nmap: x.x
httpx: x.x.x
Katana: x.x.x
Why?
Because tools change.
For example, current Subfinder development/releases have already changed source behavior, including source additions/removals, while httpx and Katana continue receiving feature updates. (GitHub)
A report without tool versions is less reproducible.
________________________________________
50. Raw Output Preservation
Do not immediately discard external tool output.
Store:
results/
└── raw/
    ├── subfinder/
    ├── dnsx/
    ├── naabu/
    ├── nmap/
    ├── httpx/
    └── katana/
Then:
raw data
   ↓
parser
   ↓
normalized data
This makes parser debugging much easier.
________________________________________
51. Nmap Integration Decision
For programmatic processing:
Use XML.
Nmap's own documentation strongly recommends the XML interface for software integration because it is structured and extensible. (Nmap)
Therefore:
Nmap
 ↓
XML
 ↓
NmapParser
 ↓
Service Models
We will not parse human-readable Nmap terminal output.
________________________________________
52. Tool Execution Security
External commands must never be constructed through unsafe string concatenation.
Conceptually:
BAD
shell=True + untrusted target
Instead:
GOOD
argument list
+
validated scope
+
controlled executable
This protects AutoReconX itself from command injection through malformed input.
________________________________________
53. Logging
Use structured logs.
Example:
2026-08-30 22:00:01 INFO  Scan initialized
2026-08-30 22:00:02 INFO  Scope validated
2026-08-30 22:00:03 INFO  Subfinder started
2026-08-30 22:00:18 INFO  42 subdomains discovered
2026-08-30 22:00:19 INFO  DNS resolution started
...
Levels:
DEBUG
INFO
WARNING
ERROR
________________________________________
54. Error Handling
A single failed module should not necessarily destroy the entire scan.
Example:
Subfinder
    ✓

dnsx
    ✓

Naabu
    ✓

Nmap
    ⚠ partial failure

httpx
    ✓

Katana
    ✗ timeout
Final report:
Scan completed with warnings.

Successful modules: 5/6
Failed modules: Katana

Results may be incomplete.
________________________________________
55. Configuration
Initial configuration:
project:
  name: AutoReconX

scan:
  profile: standard
  timeout: 30
  concurrency: 10

scope:
  allowed: []
  excluded: []

tools:
  subfinder:
    binary: subfinder

  dnsx:
    binary: dnsx

  naabu:
    binary: naabu

  nmap:
    binary: nmap

  httpx:
    binary: httpx

  katana:
    binary: katana

output:
  directory: ./results
  formats:
    - json
    - markdown
    - html
Exact schema will be finalized before implementation.
________________________________________
56. Lab Environment
We will not start development by scanning public targets.
We'll create a controlled local lab.
Concept:
                Kali
                 │
                 │
           AutoReconX
                 │
                 ▼
          Docker Network
                 │
       ┌─────────┼─────────┐
       ▼         ▼         ▼
     Web01      API01     Linux01
Later we can add:
Web02
DNS01
Admin01
to create a richer attack surface.
________________________________________
57. Lab Requirements
The lab should intentionally provide:
•	multiple hostnames
•	DNS records
•	multiple IPs
•	several open ports
•	HTTP/HTTPS
•	different web technologies
•	APIs
•	redirects
•	JavaScript
•	robots.txt
•	sitemap
•	development/staging naming
•	intentionally interesting endpoints
This gives AutoReconX something meaningful to discover.
________________________________________
58. Testing Strategy
Testing will occur at three levels.
Unit tests
Test individual components.
ScopeValidator
NmapParser
DNSParser
Deduplicator
PriorityEngine
Integration tests
Test:
Module
 ↓
Parser
 ↓
Normalizer
 ↓
Database
End-to-end tests
Test:
Target
 ↓
AutoReconX
 ↓
Full pipeline
 ↓
Report
________________________________________
59. Acceptance Criteria
AutoReconX v1.0 will be considered complete only when:
Core
•	CLI works
•	configuration works
•	logging works
•	scope validation works
Recon
•	Subfinder integration
•	dnsx integration
•	Naabu integration
•	Nmap integration
•	httpx integration
•	Katana integration
Data
•	normalized models
•	deduplication
•	provenance
•	relationships
•	SQLite persistence
Intelligence
•	asset classification
•	priority scoring
•	confidence tracking
Reporting
•	JSON
•	Markdown
•	HTML
Engineering
•	unit tests
•	integration tests
•	E2E tests
•	Docker
•	CI
•	documentation
•	security policy
________________________________________
60. Performance Goals
We should measure rather than make arbitrary performance claims.
We'll record:
Total scan duration
Module execution duration
Assets/second
Memory consumption
CPU utilization
Database insertion time
Report generation time
We can then optimize based on evidence.
________________________________________
61. Reproducibility
Each scan should record:
Scan ID
Target
Profile
Configuration hash
Start time
End time
Tool versions
AutoReconX version
Module status
Example:
SCAN-20260830-001
This allows us to compare scans.
________________________________________
62. Scan Comparison — v1.x
After the basic version works, we can implement:
Scan A
   VS
Scan B
Output:
NEW ASSETS

+ dev.example.local

NEW PORTS

+ 8080/tcp

NEW TECHNOLOGY

+ FastAPI

REMOVED

- old-api.example.local
This is a very useful feature for attack-surface management.
________________________________________
63. Future API
Not v1.
But eventually:
FastAPI
   │
   ▼
AutoReconX API
   │
   ▼
Dashboard / BugHuntX
Possible endpoints:
POST /scans
GET /scans/{id}
GET /assets
GET /hosts
GET /services
GET /endpoints
GET /reports
________________________________________
64. Future Web Dashboard
Not initially.
Eventually:
┌──────────────────────────────────────┐
│             AUTORECONX               │
├──────────┬──────────┬───────────────┤
│ Assets   │ Hosts    │ Services      │
│ 824      │ 213      │ 641           │
├──────────┴──────────┴───────────────┤
│                                      │
│ Priority Attack Surface              │
│                                      │
│ admin       94                       │
│ api         91                       │
│ dev         87                       │
│ staging     81                       │
│                                      │
└──────────────────────────────────────┘
But this is deliberately postponed.
________________________________________
65. GitHub Repository
The final repository will look like:
autoreconx/
│
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── CODE_OF_CONDUCT.md
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
├── Makefile
│
├── docs/
│   ├── 00-master-specification.md
│   ├── 01-project-overview.md
│   ├── 02-requirements.md
│   ├── 03-threat-model.md
│   ├── 04-methodology.md
│   ├── 05-toolchain.md
│   ├── 06-architecture.md
│   ├── 07-data-model.md
│   ├── 08-scope-engine.md
│   ├── 09-scan-pipeline.md
│   ├── 10-modules.md
│   ├── 11-correlation.md
│   ├── 12-prioritization.md
│   ├── 13-reporting.md
│   ├── 14-testing.md
│   ├── 15-lab.md
│   ├── 16-security.md
│   └── 17-roadmap.md
│
├── src/
├── tests/
├── lab/
├── examples/
├── results/
│
└── .github/
    ├── workflows/
    ├── ISSUE_TEMPLATE/
    └── PULL_REQUEST_TEMPLATE.md
________________________________________
66. Documentation Standard
Every major technical decision should answer three questions:
What?
What did we implement?
Why?
Why did we choose this architecture?
Evidence?
What documentation/testing supports the decision?
This will make your GitHub much stronger during interviews.
________________________________________
67. GitHub Development Strategy
Use issues such as:
EPIC-01 Foundation

#001 Initialize Python project
#002 Implement CLI
#003 Implement configuration
#004 Implement logging
#005 Implement scope engine
Then:
EPIC-02 Recon Modules

#006 Subfinder adapter
#007 dnsx adapter
#008 Naabu adapter
#009 Nmap adapter
#010 httpx adapter
#011 Katana adapter
Then:
EPIC-03 Intelligence

#012 Asset models
#013 Normalization
#014 Deduplication
#015 Provenance
#016 Correlation
#017 Prioritization
Then:
EPIC-04 Reporting

#018 JSON
#019 Markdown
#020 HTML
#021 Scan statistics
________________________________________
68. Version 0.1 Definition
The first release should not try to do everything.
AutoReconX v0.1
CLI
 +
Scope
 +
Configuration
 +
Subfinder
 +
dnsx
 +
Normalization
 +
JSON
Success means:
autoreconx scan \
    --target lab.local \
    --profile passive
produces:
scan.json
containing structured:
domains
subdomains
DNS records
observations
sources
timestamps
If we can make that clean, tested and reliable, we have a solid foundation.
________________________________________
69. v0.2
Naabu
Nmap
Hosts
Ports
Services
SQLite
Deduplication
________________________________________
70. v0.3
httpx
Katana
Web applications
Endpoints
Technologies
________________________________________
71. v0.4
Correlation
Relationships
Asset classification
Priority engine
Confidence model
________________________________________
72. v0.5
HTML
Markdown
Scan comparison
Statistics
Improved CLI
________________________________________
73. v1.0
Complete testing
Docker
CI/CD
Security controls
Documentation
Lab
Release
________________________________________
74. Long-Term Architecture
Once all five of your offensive projects exist:
                    SECURITY PLATFORM
                           │
           ┌───────────────┴───────────────┐
           │                               │
        OFFENSIVE                       DEFENSIVE
           │                               │
     ┌─────┴─────┐                   ┌─────┴─────┐
     │           │                   │           │
AutoReconX   BugHuntX              Wazuh       AI SOC
     │           │                   │           │
     └─────┬─────┘                   └─────┬─────┘
           │                               │
           ▼                               ▼
       RedForge ────────────────► Security Validation
That's the eventual portfolio architecture—not something we'll prematurely build now.
________________________________________
75. Project Success Definition
AutoReconX succeeds if it demonstrates all of these:
Security knowledge
You understand reconnaissance methodology.
Tool knowledge
You understand what each tool does and does not do.
Programming
You can build security automation in Python.
Systems knowledge
You understand DNS, TCP/IP, HTTP and services.
Data engineering
You can normalize and correlate security data.
Security engineering
You can build scope controls and safe execution.
Software engineering
You can test, package, document and maintain a project.
Offensive thinking
You can recognize which parts of an attack surface deserve attention.
That combination is what makes this portfolio project worthwhile.
________________________________________
76. Final Architecture Decision
After reviewing the current tool capabilities, I would freeze the v1 architecture as:
                 ┌───────────────────────┐
                 │       AutoReconX      │
                 │    Python Framework   │
                 └───────────┬───────────┘
                             │
                   ┌─────────▼─────────┐
                   │   Scope Engine    │
                   └─────────┬─────────┘
                             │
                   ┌─────────▼─────────┐
                   │ Scan Coordinator  │
                   └─────────┬─────────┘
                             │
       ┌─────────┬───────────┼───────────┬──────────┐
       ▼         ▼           ▼           ▼          ▼
   Subfinder   dnsx        Naabu        Nmap      httpx
       │         │           │           │          │
       └─────────┴───────────┴───────────┴──────────┘
                             │
                             ▼
                          Katana
                             │
                             ▼
                  ┌────────────────────┐
                  │ Normalization      │
                  └─────────┬──────────┘
                            ▼
                  ┌────────────────────┐
                  │ Correlation Engine │
                  └─────────┬──────────┘
                            ▼
                       SQLite DB
                            │
                  ┌─────────┴─────────┐
                  ▼                   ▼
           Priority Engine       Reporting
                                  │
                       ┌──────────┼──────────┐
                       ▼          ▼          ▼
                      JSON      Markdown    HTML

