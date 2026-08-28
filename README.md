PHANTOM AI

Autonomous Security Assessment & Attack-Chain Analysis

"Python 3.11+" (https://img.shields.io/badge/python-3.11+-blue.svg)
"License" (https://img.shields.io/badge/license-MIT-green.svg)
"Status" (https://img.shields.io/badge/status-paused-orange.svg)
"Modules" (https://img.shields.io/badge/security%20modules-77%2B-purple.svg)

PHANTOM AI is an autonomous security assessment framework designed to move beyond traditional vulnerability scanning.

The project combines automated reconnaissance, 77+ specialized security modules, contextual analysis, evidence-based validation, exploitation proof, attack-chain analysis, attacker-intent reasoning, and multi-layer safety controls.

PHANTOM was developed as a solo engineering project and eventually grew from a vulnerability scanner into a broader security platform. Development is currently paused because the scope became too large to responsibly complete and maintain alone.

The repository is public for technical review, research, experimentation, learning, and potential collaboration.

---

What PHANTOM Tries to Solve

Traditional scanners tend to follow a relatively simple model:

Target
  ↓
Scanner
  ↓
Payloads
  ↓
Findings

PHANTOM was designed around a different model:

Target
  ↓
Discovery
  ↓
Attack Surface Model
  ↓
Decision / Prioritization
  ↓
Targeted Testing
  ↓
Evidence
  ↓
Validation
  ↓
Exploitability
  ↓
Attack Chains
  ↓
Impact / Attacker Intent
  ↓
Report
  ↺

The objective is not simply to find more vulnerabilities.

It is to determine:

- what is exposed
- what is actually vulnerable
- what can be proven
- what impact can be demonstrated
- what vulnerabilities can be combined
- what attack path should be investigated next
- what actions are authorized and safe

---

Architecture

┌──────────────────────────────────────────────────────────────────────┐
│                          PHANTOM AI CORE                              │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   CLI          API          Web UI          SDK                       │
│    │            │             │              │                        │
│    └────────────┴─────────────┴──────────────┘                        │
│                         │                                             │
│                         ▼                                             │
│              ┌──────────────────────┐                                 │
│              │   DECISION ENGINE     │                                 │
│              │  Strategic Control    │                                 │
│              └──────────┬───────────┘                                 │
│                         │                                             │
│                         ▼                                             │
│              ┌──────────────────────┐                                 │
│              │ ORCHESTRATION ENGINE │                                 │
│              └──────────┬───────────┘                                 │
│                         │                                             │
├─────────────────────────┼──────────────────────────────────────────────┤
│                         │                                             │
│        ┌────────────────┼────────────────┐                            │
│        ▼                ▼                ▼                            │
│   PHASE 0           PHASE 1          PHASE 2+                         │
│   Discovery         Intelligence     Security Testing                 │
│                                                                      │
│   Endpoint Map      Tech Intel       77+ Modules                      │
│   Target Class.     Domain Class.    Tool Integration                 │
│   Auth Context      Recommendations  Parallel Execution              │
│                                                                      │
├─────────────────────────┼──────────────────────────────────────────────┤
│                         ▼                                             │
│              ┌──────────────────────┐                                 │
│              │   EVIDENCE ENGINE    │                                 │
│              └──────────┬───────────┘                                 │
│                         ▼                                             │
│              ┌──────────────────────┐                                 │
│              │ VALIDATION PIPELINE  │                                 │
│              │     6 STAGES         │                                 │
│              └──────────┬───────────┘                                 │
│                         ▼                                             │
│              ┌──────────────────────┐                                 │
│              │  FINDING STATE MODEL │                                 │
│              └──────────┬───────────┘                                 │
│                         ▼                                             │
│              ┌──────────────────────┐                                 │
│              │ EXPLOIT PROOF ENGINE │                                 │
│              └──────────┬───────────┘                                 │
│                         ▼                                             │
│              ┌──────────────────────┐                                 │
│              │ ATTACK CHAIN ENGINE  │                                 │
│              └──────────┬───────────┘                                 │
│                         ▼                                             │
│              ┌──────────────────────┐                                 │
│              │ ATTACKER INTENT      │                                 │
│              │     ENGINE            │                                 │
│              └──────────┬───────────┘                                 │
│                         ▼                                             │
│                     REPORTING                                         │
│                                                                      │
├──────────────────────────────────────────────────────────────────────┤
│                       SHARED INFRASTRUCTURE                           │
│                                                                      │
│ Endpoint Map │ Payload Library │ Finding Store │ State Manager       │
│ HTTP Client  │ Rate Limiter    │ Scope Guard   │ Exploit Policy      │
│ Evidence     │ Network Safety  │ Audit Logger  │ Knowledge Base      │
└──────────────────────────────────────────────────────────────────────┘

---

Core Capabilities

1. Smart Reconnaissance

PHANTOM starts by building an understanding of the target.

Discovery can include:

- URL normalization
- endpoint discovery
- parameter extraction
- HTML and JavaScript analysis
- robots.txt and sitemap discovery
- API endpoint discovery
- technology fingerprinting
- server identification
- authentication surface identification
- business-domain classification

The result is centralized in an attack-surface model rather than being discarded by individual scanners.

---

2. Technology Intelligence

The intelligence layer identifies technologies and application characteristics using observable behavior such as:

- HTTP headers
- response characteristics
- error messages
- framework fingerprints
- JavaScript
- application behavior

Technology intelligence can be used to:

- prioritize relevant modules
- adapt testing strategies
- identify likely database technologies
- infer application architecture
- improve payload selection

Critical vulnerability classes can still be forced through the pipeline using a NEVER_SKIP_MODULES safeguard.

---

3. Authentication Context

PHANTOM can acquire and maintain authentication context so that security testing is not limited to anonymous functionality.

The authentication layer can work with:

- registration flows
- session cookies
- JWTs
- authenticated API requests
- controlled credential testing

Authentication state can then propagate into subsequent scanners.

A conceptual feedback loop is:

SQL Injection
      ↓
Credential Exposure
      ↓
Authentication Attempt
      ↓
Authenticated Context
      ↓
Restricted Endpoint Discovery
      ↓
Authorization Testing

This allows authentication to become part of attack-path reasoning rather than a separate feature.

---

4. 77+ Specialized Security Modules

PHANTOM contains a broad set of security testing modules.

Injection

- SQL Injection
- NoSQL Injection
- Command Injection
- SSTI
- XXE
- LFI/RFI
- LDAP Injection
- XPath Injection

Cross-Site Scripting

- Reflected XSS
- Stored XSS
- DOM XSS
- Client-Side Template Injection
- Prototype Pollution

Authentication & Session

- Authentication testing
- Session abuse
- JWT analysis
- OAuth testing
- 2FA bypass testing
- SAML security testing

Authorization

- IDOR
- BOLA
- RBAC/authorization testing
- ABAC context testing
- vertical/horizontal privilege escalation

Business Logic

- Business logic abuse
- Race conditions
- Rate-limit bypass
- Mass assignment
- Workflow/state-machine abuse

API Security

- REST API testing
- GraphQL testing
- WebSocket testing
- gRPC testing
- API gateway testing
- Webhook security

Infrastructure

- HTTP security headers
- CORS
- TLS/SSL
- DNS
- Port scanning
- Directory discovery
- CMS detection
- Cloud misconfiguration

Information Disclosure

- Secrets
- exposed configuration
- stack traces
- database errors
- version disclosure

Specialized Security Testing

- token binding
- session fixation
- client-side hardening
- concurrency testing
- resource exhaustion patterns

---

5. Creative / Adversarial Testing

PHANTOM also includes a higher-risk Creative Exploiter module designed to explore unexpected application behavior.

It combines several approaches:

Context Confusion

Testing whether parameters or assumptions from one application context can be abused in another.

Trust Boundary Probing

Testing exposed administrative functionality, role confusion and internal API boundaries.

Flow Disruption

Testing:

- HTTP method overrides
- content-type confusion
- request ordering
- malformed workflow transitions

Chaos Composition

Testing unusual combinations of parameters and malformed inputs.

Lazy Developer Exploitation

Testing predictable implementation mistakes such as:

- debug endpoints
- default credentials
- verbose errors
- undocumented functionality

---

6. Shared Attack Surface

A central Endpoint Map provides common application knowledge to modules.

Endpoints can be categorized as:

AUTH
PAYMENT
ADMIN
ACCOUNT
DATA
FEEDBACK
API_REST
API_GRAPHQL
WEBHOOK
...

This enables cross-module targeting.

A parameter discovered during reconnaissance, for example, can later become a target for multiple vulnerability classes instead of being lost between modules.

---

7. Six-Stage Validation Pipeline

A raw scanner result is not automatically considered a confirmed vulnerability.

PHANTOM applies a six-stage validation process:

Raw Finding
     ↓
1. Syntax Validation
     ↓
2. Duplicate Detection
     ↓
3. Context Validation
     ↓
4. Safe Replay
     ↓
5. Negative Control
     ↓
6. Confidence Gate
     ↓
Validated Finding

Syntax Validation

Checks structural integrity and required fields.

Duplicate Detection

Removes exact and near-duplicate findings.

Context Validation

Evaluates whether observed behavior is actually meaningful in context.

Safe Replay

Attempts to reproduce the original behavior.

Negative Control

Sends benign input to determine whether the same behavior occurs without the triggering condition.

Confidence Gate

Findings below the configured confidence threshold are discarded.

---

8. Finding State Machine

PHANTOM distinguishes detection from proof:

SUSPECTED
    ↓
DETECTED
    ↓
CONFIRMED
    ↓
EXPLOITABLE
    ↓
EXPLOITED

This allows reports to distinguish between:

- a heuristic suspicion
- a detected pattern
- a reproduced vulnerability
- demonstrated impact
- authorized exploitation

---

9. Evidence Engine

The Evidence Engine is designed to make security findings evidence-driven.

A finding can retain information such as:

- HTTP request
- HTTP response
- payload
- parameter
- reflection point
- reproduction result
- negative control
- authentication state
- technology context
- impact evidence
- confidence
- chain relationships
- authorization state

The goal is to prevent conclusions from being based purely on scanner claims.

---

10. Exploitation Proof Engine

For significant findings, PHANTOM attempts to answer four questions:

Can it be reproduced?

Does the same behavior occur again?

Can it be mutated?

Do alternative payloads preserve the vulnerability?

Can it escalate?

Does the vulnerability provide additional privileges or capabilities?

Can it chain?

Does the finding unlock additional attacks elsewhere in the application?

Specialized proof logic exists for multiple vulnerability classes including SQL injection, XSS, IDOR, business logic, sessions and CORS.

---

11. Attack Chain Analysis

PHANTOM does not treat vulnerabilities as isolated events.

It can analyze relationships between findings and identify potential attack paths.

Examples include:

SQLi
 ↓
Credential Access
 ↓
Authentication
 ↓
Administrative Access

IDOR
 ↓
Sensitive Object Access
 ↓
Mass Enumeration
 ↓
Data Theft

XSS
 ↓
Session / CSRF Abuse
 ↓
Account Takeover

SSRF
 ↓
Cloud Metadata
 ↓
Credential Exposure

XXE
 ↓
File Access / SSRF

Chain findings can be categorized according to the strength of their evidence, separating demonstrated relationships from inferred or speculative paths.

---

12. Attacker Intent Engine

PHANTOM also models attacker objectives rather than only vulnerability categories.

Supported high-level objectives include:

FINANCIAL_GAIN
DATA_THEFT
ACCOUNT_TAKEOVER
ADMIN_ACCESS
CODE_EXECUTION

The engine can reason over state transitions such as:

ANONYMOUS
    ↓
AUTHENTICATED
    ↓
USER
    ↓
ADMIN
    ↓
CODE EXECUTION

This helps prioritize vulnerabilities according to what they enable, not simply how they are categorized.

---

13. Decision Engine

The long-term architectural direction of PHANTOM is a dedicated Decision Engine.

Instead of simply executing every scanner in sequence, the system can reason over the current state:

Observe
  ↓
Evaluate
  ↓
Prioritize
  ↓
Execute Test
  ↓
Collect Evidence
  ↓
Update State
  ↓
Choose Next Action
  ↺

The intended question is:

«What is the highest-value security action to take next, given everything already discovered?»

This is the foundation for more autonomous security assessment.

---

14. Attack Surface Budget

Large targets may expose hundreds or thousands of endpoints and parameters.

Testing everything equally is inefficient.

PHANTOM therefore introduces the concept of an Attack Surface Budget to prioritize testing according to factors such as:

- endpoint sensitivity
- parameter importance
- technology relevance
- authentication boundaries
- previous findings
- exploitability
- potential impact
- testing cost

The goal is to spend testing effort where it is most likely to produce meaningful evidence.

---

15. Learning & Adaptive Intelligence

PHANTOM contains feedback mechanisms designed to improve future prioritization.

Learning signals can include:

- historical true/false-positive outcomes
- bounty acceptance or rejection
- bounty payouts
- successful attack chains
- real-world incident patterns
- payload performance

The system can use these outcomes to adjust confidence and attack-chain probabilities over time.

---

16. Safety Architecture

Autonomous security testing requires strict boundaries.

PHANTOM uses multiple protection layers:

Safety Levels

SAFE
CAUTIOUS
STANDARD
AGGRESSIVE

Safety Controls

- scope enforcement
- request rate limiting
- HTTP safety controls
- module-level safety restrictions
- exploit policy enforcement
- audit logging
- destructive-action restrictions

The system is designed to distinguish between discovering a vulnerability and being authorized to perform a potentially impactful exploitation action.

---

17. External Security Tools

PHANTOM can integrate with established security tooling such as:

- Nuclei
- Nmap
- Nikto
- Gobuster / ffuf
- sqlmap
- testssl
- Subfinder
- other environment-specific tools

The architectural goal is not simply to execute these independently, but to use their results as additional security intelligence.

---

18. Reporting

PHANTOM supports structured security reporting for different use cases.

HackerOne-style reports

- CWE
- CVSS
- proof status
- reproduction steps
- request/response evidence
- impact
- remediation

Professional Pentest Reports

- executive summaries
- technical findings
- PoCs
- remediation guidance
- compliance mappings

SARIF

Designed for integration with CI/CD and security tooling.

Additional Formats

- JSON
- HTML
- PDF
- Markdown

---

19. Compliance & Data Protection

PHANTOM also includes a GDPR/RGPD-oriented compliance layer covering areas such as:

- data minimization
- data retention
- right of access
- right to erasure
- data portability
- privacy by design
- processing records
- security of processing

PII handling includes patterns for information such as:

- emails
- telephone numbers
- payment card data
- IP addresses
- JWTs
- credentials
- NIF and other sensitive identifiers

Retention policies can be applied to scan data, logs, reports and compliance records.

---

20. Project Metrics

Current project scale:

Metric| Value
Security modules| 77+
Scanning subsystem| ~70,000 LOC
Validation stages| 6
Security modes| 4+
Major engines| 10+
Report formats| 5+
Attack-chain patterns| 13+
AI/analysis components| Multiple
External security tools| Multiple

These numbers describe the scope of the codebase, not a claim that every component is equally mature.

---

21. Project Structure

phantom/
│
├── .github/
├── ai_engine/
├── analysis/
├── cli/
├── compliance/
├── config/
├── core/
├── docs/
├── examples/
├── interactive/
├── pathfinder/
├── reconnaissance/
├── reporting/
├── retest/
├── safe_mode/
├── scanning/
├── scripts/
├── templates/
├── tests/
├── threat_modeling/
├── tools/
├── utils/
├── validation/
│
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── pytest.ini
│
├── PHANTOM_AUDIT.md
├── PHANTOM_CAPABILITIES.md
├── PENTEST_COVERAGE.md
├── GAP_ANALYSIS.md
└── README.md

---

22. Project Status

PHANTOM is currently paused.

The project began as an automated pentesting framework and gradually expanded into:

Reconnaissance
     +
Vulnerability Discovery
     +
Authentication Context
     +
Validation
     +
Evidence
     +
Exploitation Proof
     +
Attack-Chain Reasoning
     +
Attacker Intent
     +
Decision Making
     +
Safety Enforcement
     +
Enterprise Reporting

At that point, the scope had effectively become a complete security platform.

As a solo developer, I decided that continuing to expand the system without a larger engineering and security team would not be the right approach.

Rather than presenting an unfinished system as production-ready, I am publishing the codebase with its architecture, audits, limitations and development history available for inspection.

---

23. Known Limitations

PHANTOM is an advanced engineering/research project, not a finished commercial security platform.

Known areas for further work include:

- deeper integration between all external tools and modules
- more complete autonomous attack-chain execution
- broader authenticated workflow coverage
- additional external reconnaissance integrations
- HTTP/2 and HTTP/3 security testing
- mobile API testing
- container escape analysis
- WebAssembly analysis
- broader machine-learning-based anomaly detection
- coverage-guided fuzzing
- source-code correlation
- additional enterprise integrations
- larger-scale validation and benchmarking

The repository and accompanying audit documents should be treated as the source of truth for the current state of individual components.

---

24. Security & Responsible Use

PHANTOM is intended for authorized security testing only.

Only use it against systems where you have explicit permission to perform security testing.

Do not use the framework to:

- access systems without authorization
- disrupt services
- obtain unauthorized data
- deploy malware
- perform destructive actions
- conduct unauthorized credential attacks

Security researchers and contributors are expected to follow applicable laws, program rules and responsible disclosure practices.

---

25. Why This Repository Is Public

I am publishing PHANTOM primarily because the engineering work itself is worth examining.

The interesting part is not only the scanners.

It is the attempt to combine:

Attack Surface Mapping
        +
Security Testing
        +
Evidence
        +
Validation
        +
Reasoning
        +
Attack Chains
        +
Safety

into a single system.

The project is open for technical criticism, experimentation, research and potential collaboration.

Especially valuable feedback would come from:

- penetration testers
- red teamers
- AppSec engineers
- security researchers
- security-tooling engineers
- AI/agent engineers
- software architects

Don't just tell me what works. Tell me what is wrong.

---

License

MIT License.

See "LICENSE" (LICENSE) for details.

---

Acknowledgments

PHANTOM builds upon and integrates with the broader security tooling ecosystem, including:

- "Nuclei" (https://github.com/projectdiscovery/nuclei)
- "Nmap" (https://nmap.org/)
- "Ollama" (https://ollama.ai/)
- "ChromaDB" (https://www.trychroma.com/)
- "sqlmap" (https://sqlmap.org/)
- and other open-source security projects

---

Final Note

PHANTOM is ultimately an exploration of a question:

«What would a security testing system look like if it could maintain a model of an application, reason over evidence, understand attack paths, and continuously decide what should be tested next?»

This repository is one attempt at answering that question.│  └──────────┘ └──────────┘ └──────────┘ └──────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐   │
│  │ Rate Limiter│ │State Manager│ │  Knowledge Base     │   │
│  └─────────────┘ └─────────────┘ └─────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐   │
│  │   Ollama    │ │   ChromaDB  │ │     SQLite DB       │   │
│  └─────────────┘ └─────────────┘ └─────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.11+
- [Ollama](https://ollama.ai) for local LLM inference
- External tools: Nuclei, Nmap, Subfinder (optional)

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/ai-pentest.git
cd ai-pentest

# Run setup script
chmod +x scripts/setup.sh
./scripts/setup.sh

# Or manual installation
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Install External Tools

```bash
chmod +x scripts/install_tools.sh
./scripts/install_tools.sh
```

### Docker Setup

```bash
# Start all services
docker-compose up -d

# Run a scan
docker-compose run pentest scan example.com
```

## Usage

### Basic Scan

```bash
# Scan a domain
pentest scan example.com

# Scan with specific output format
pentest scan example.com -f html

# Scan without AI analysis
pentest scan example.com --no-ai

# Scan with additional scope
pentest scan example.com -s api.example.com -s admin.example.com
```

### Check Scan Status

```bash
# Check status
pentest status <scan-id>

# List recent scans
pentest list-scans
```

### View Configuration

```bash
pentest config
```

### Check Tools

```bash
pentest check-tools
```

## Configuration

Configuration is managed via `config/settings.yaml`:

```yaml
ai:
  provider: "ollama"
  model_name: "mistral"
  base_url: "http://localhost:11434"
  temperature: 0.3

rate_limits:
  requests_per_second: 10
  burst_limit: 20

scanning:
  nuclei_templates: "~/.nuclei-templates"
  severity_threshold: "low"

reporting:
  default_format: "pdf"
  company_name: "Your Company"
```

## Project Structure

```
petntesterai/
├── cli/                    # CLI interface
│   └── main.py            # Click commands
├── core/                   # Core modules
│   ├── config_manager.py  # Pydantic settings
│   ├── orchestrator.py    # Main pipeline
│   ├── auth_manager.py    # Target authorization
│   └── state_manager.py   # Checkpoint/resume
├── reconnaissance/         # Recon modules
│   ├── subdomain_enum.py
│   ├── port_scanner.py
│   ├── tech_detection.py
│   └── crawler.py
├── scanning/              # Vulnerability scanning
│   ├── vuln_scanner.py
│   └── modules/
│       ├── nuclei_runner.py
│       ├── header_security.py
│       ├── ssl_checker.py
│       └── cors_checker.py
├── ai_engine/             # AI components
│   ├── model_manager.py   # Ollama client
│   ├── analyzer.py        # Finding analysis
│   ├── false_positive_filter.py
│   ├── chain_detector.py
│   └── knowledge_base.py  # ChromaDB RAG
├── reporting/             # Report generation
│   └── report_generator.py
├── storage/               # Data persistence
│   ├── database.py        # SQLAlchemy models
│   └── encryption.py
├── utils/                 # Utilities
│   ├── logger.py          # Structlog setup
│   ├── rate_limiter.py
│   ├── validators.py
│   └── cvss_calculator.py
├── config/                # Configuration
│   └── settings.yaml
└── templates/             # Report templates
    └── professional.j2
```

## AI Capabilities

### False Positive Detection
Uses pattern matching and LLM analysis to identify likely false positives:
- Signature-based detection for common FP patterns
- Context-aware AI analysis for ambiguous cases
- Confidence scoring for findings

### Exploit Chain Detection
Identifies how multiple vulnerabilities can be combined:
- Pattern matching for known chains (SQLi + File Upload → RCE)
- AI-powered chain discovery
- Impact assessment for combined attacks

### Intelligent Prioritization
AI-driven severity adjustment based on:
- Business context and asset criticality
- Exploitability factors
- Real-world attack likelihood

## Development

### Running Tests

```bash
pytest tests/ -v
```

### Code Quality

```bash
# Format
black .
isort .

# Lint
ruff check .

# Type check
mypy .
```

## Security Considerations

⚠️ **Important**: Only use this tool against systems you have explicit permission to test.

- Always obtain written authorization before scanning
- The tool includes authorization checking (`pentest authorize`)
- Findings may contain sensitive information - handle reports securely
- Rate limiting is enabled by default to prevent service disruption

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## Acknowledgments

- [Nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanner
- [Ollama](https://ollama.ai) - Local LLM inference
- [ChromaDB](https://www.trychroma.com/) - Vector database
