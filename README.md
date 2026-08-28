PHANTOM AI

Autonomous Security Assessment & Attack-Chain Analysis

"Python 3.11+" (https://img.shields.io/badge/python-3.11+-blue.svg)
"License" (https://img.shields.io/badge/license-MIT-green.svg)
"Status" (https://img.shields.io/badge/status-paused-orange.svg)
"Security Modules" (https://img.shields.io/badge/security%20modules-77%2B-purple.svg)

PHANTOM AI is an autonomous security assessment framework designed to go beyond traditional vulnerability scanning.

It combines automated reconnaissance, 77+ specialized security modules, contextual analysis, evidence-based validation, exploitation proof, attack-chain analysis, attacker-intent reasoning, and multi-layer safety controls.

PHANTOM was developed as a solo engineering project and eventually evolved from a vulnerability scanner into a broader security platform. Development is currently paused because the scope became too large to responsibly complete and maintain alone.

The repository is public for technical review, research, experimentation, learning, and potential collaboration.

---

Overview

Traditional vulnerability scanners typically follow:

Target
  ↓
Scanner
  ↓
Payloads
  ↓
Findings

PHANTOM was designed around a broader security reasoning loop:

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
Reporting
  ↺

The objective is not simply to find more vulnerabilities.

PHANTOM attempts to determine:

- What is exposed?
- What is actually vulnerable?
- What can be proven?
- What impact can be demonstrated?
- What vulnerabilities can be combined?
- What should be tested next?
- What actions are authorized and safe?

---

Architecture

┌──────────────────────────────────────────────────────────────────────┐
│                           PHANTOM AI CORE                             │
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
│              │      6 STAGES        │                                 │
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
│              │ ENGINE               │                                 │
│              └──────────┬───────────┘                                 │
│                         ▼                                             │
│                      REPORTING                                        │
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

PHANTOM starts by building an understanding of the target before security testing.

Discovery includes:

- URL normalization
- Endpoint discovery
- Parameter extraction
- HTML and JavaScript analysis
- robots.txt and sitemap discovery
- API endpoint discovery
- Technology fingerprinting
- Server identification
- Authentication surface discovery
- Business-domain classification

The resulting information feeds a centralized attack-surface model used by subsequent testing stages.

---

2. Technology Intelligence

The intelligence layer identifies frameworks, servers, databases and application characteristics using observable behavior such as:

- HTTP headers
- response characteristics
- error messages
- framework fingerprints
- JavaScript
- application behavior

Technology intelligence is used to:

- prioritize relevant modules
- adapt testing strategies
- improve payload selection
- identify likely database technologies
- infer application architecture

Critical vulnerability classes can be preserved through the "NEVER_SKIP_MODULES" safeguard.

---

3. 77+ Security Modules

PHANTOM contains specialized modules covering a broad range of offensive security techniques.

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
- RBAC / authorization testing
- ABAC context testing
- Horizontal privilege escalation
- Vertical privilege escalation

Business Logic

- Business logic abuse
- Race conditions
- Rate-limit bypass
- Mass assignment
- Workflow and state-machine abuse

API Security

- REST APIs
- GraphQL
- WebSockets
- gRPC
- API gateways
- Webhooks

Infrastructure

- Security headers
- CORS
- SSL/TLS
- DNS
- Port scanning
- Directory discovery
- CMS detection
- Cloud misconfiguration

Information Disclosure

- Secrets
- Exposed configuration
- Stack traces
- Database errors
- Version disclosure

Specialized Testing

- Token binding
- Session fixation
- Client-side security
- Concurrency testing
- Resource exhaustion patterns

---

4. Shared Attack Surface

PHANTOM maintains a centralized Endpoint Map that allows modules to operate on shared application knowledge.

Endpoints can be classified as:

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

This allows discoveries from reconnaissance and other scanners to influence subsequent testing.

For example:

Parameter Discovery
        ↓
SQLi / XSS Testing
        ↓
Finding
        ↓
Authorization Testing

---

5. Authentication Context

Authentication is treated as part of the security assessment state.

PHANTOM can work with:

- registration flows
- session cookies
- JWTs
- authenticated API requests
- controlled credential testing

Authentication context can propagate into other modules.

A conceptual feedback loop:

SQL Injection
      ↓
Credential Exposure
      ↓
Authentication
      ↓
Authenticated Context
      ↓
Restricted Endpoint Discovery
      ↓
Authorization Testing

---

6. Six-Stage Validation Pipeline

A raw scanner result is not automatically considered a confirmed vulnerability.

PHANTOM applies:

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

This process is intended to reduce false positives and improve report reliability.

---

7. Finding State Machine

Findings are represented through explicit states:

SUSPECTED
    ↓
DETECTED
    ↓
CONFIRMED
    ↓
EXPLOITABLE
    ↓
EXPLOITED

This separates heuristic detection from reproduced behavior and demonstrated impact.

---

8. Evidence Engine

The Evidence Engine provides structured evidence for findings, including:

- HTTP requests
- HTTP responses
- payloads
- parameters
- reflection points
- reproduction results
- negative controls
- authentication state
- technology context
- impact evidence
- confidence
- chain relationships
- authorization state

The goal is to make security findings evidence-driven rather than scanner-driven.

---

9. Exploitation Proof Engine

For significant findings, PHANTOM attempts to answer:

Can it be reproduced?

Does the behavior occur again?

Can it be mutated?

Do alternative payloads preserve the vulnerability?

Can it escalate?

Can the finding provide additional privileges or capabilities?

Can it chain?

Does the finding unlock another attack path?

Specialized proof logic exists for multiple vulnerability classes including SQL Injection, XSS, IDOR, business logic, sessions and CORS.

---

10. Attack Chain Analysis

PHANTOM analyzes relationships between individual findings.

Examples:

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

Chains can distinguish between demonstrated relationships and inferred or speculative paths.

---

11. Attacker Intent Engine

PHANTOM also models higher-level attacker objectives.

Current intent categories include:

- Financial Gain
- Data Theft
- Account Takeover
- Administrative Access
- Code Execution

The system can reason over state transitions such as:

ANONYMOUS
    ↓
AUTHENTICATED
    ↓
USER
    ↓
ADMIN
    ↓
CODE EXECUTION

This allows prioritization based on what a vulnerability enables rather than only its vulnerability category.

---

12. Decision Engine

The Decision Engine is the strategic control layer of the architecture.

The intended model is:

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

Rather than blindly running every scanner against every endpoint, the long-term goal is to determine:

«What is the highest-value security action to take next, given everything already discovered?»

---

13. Attack Surface Budget

Large applications may contain hundreds or thousands of endpoints and parameters.

PHANTOM introduces an Attack Surface Budget to prioritize testing according to factors such as:

- endpoint sensitivity
- parameter importance
- technology relevance
- authentication boundaries
- existing findings
- exploitability
- potential impact
- testing cost

The goal is to spend testing effort where it is most likely to produce meaningful evidence.

---

14. Learning & Adaptive Intelligence

PHANTOM contains feedback mechanisms intended to improve future prioritization.

Potential learning signals include:

- historical true/false-positive outcomes
- bounty acceptance or rejection
- bounty payouts
- successful attack chains
- real-world incident patterns
- payload performance

These outcomes can be used to adjust confidence and attack-chain probabilities.

---

15. Safety Architecture

Autonomous security testing requires strict boundaries.

PHANTOM uses multiple safety layers.

Safety Levels

SAFE
CAUTIOUS
STANDARD
AGGRESSIVE

Controls

- Scope enforcement
- Rate limiting
- HTTP safety controls
- Module-level safety restrictions
- Exploit policy enforcement
- Audit logging
- Destructive-action restrictions

The architecture separates vulnerability discovery from potentially impactful exploitation.

---

16. External Security Tools

PHANTOM can integrate with established security tooling including:

- Nuclei
- Nmap
- Nikto
- Gobuster
- ffuf
- sqlmap
- testssl
- Subfinder

The architectural objective is to use external tools as additional sources of security intelligence rather than isolated utilities.

---

17. Reporting

PHANTOM supports multiple reporting workflows.

HackerOne-style Reports

- CWE
- CVSS
- proof status
- reproduction steps
- request/response evidence
- impact
- remediation

Client / Pentest Reports

- Executive summaries
- Technical findings
- Proof of concept
- Remediation guidance
- Compliance mappings

SARIF

Designed for integration with CI/CD and security tooling.

Other Formats

- JSON
- HTML
- PDF
- Markdown

---

18. GDPR / Data Protection

PHANTOM also includes a GDPR/RGPD-oriented compliance layer addressing:

- Data minimization
- Data retention
- Right of access
- Right to erasure
- Data portability
- Privacy by design
- Processing records
- Security of processing

PII detection and anonymization can cover data such as:

- Email addresses
- Telephone numbers
- Payment card data
- IP addresses
- JWTs
- Credentials
- NIF and other sensitive identifiers

---

19. Project Metrics

Metric| Value
Security modules| 77+
Scanning subsystem| ~70,000 LOC
Validation stages| 6
Security modes| 4+
Major engines| 10+
Report formats| 5+
Attack-chain patterns| 13+
AI / analysis components| Multiple
External security tools| Multiple

These metrics represent the scope of the codebase, not a claim that every component has the same level of maturity.

---

20. Project Structure

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

21. Project Status

PHANTOM is currently paused.

The project progressively evolved from an automated scanner into a much larger security platform combining:

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
Reporting

As a solo developer, I reached the point where completing and maintaining the entire platform to the standard I wanted was no longer realistic.

Rather than presenting an unfinished system as production-ready, I decided to make the codebase public with its architecture, audits, capabilities and known limitations available for inspection.

---

22. Known Limitations

PHANTOM is an advanced engineering/research project, not a finished commercial security platform.

Known areas for further development include:

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
- larger-scale testing and benchmarking

Individual components may therefore have different levels of maturity.

See the audit and gap-analysis documents in this repository for further details.

---

23. Responsible Use

PHANTOM is intended for authorized security testing only.

Only use it against systems where you have explicit permission to perform security testing.

Do not use the framework to:

- access systems without authorization
- disrupt services
- obtain unauthorized data
- deploy malware
- perform destructive actions
- conduct unauthorized attacks

Users are responsible for complying with applicable laws, security-program rules and responsible disclosure requirements.

---

24. Why This Repository Is Public

The purpose of publishing PHANTOM is not to present it as a finished commercial product.

The project is being released because the engineering work and architectural experimentation are worth examining.

The central idea was to combine:

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

into a single security assessment system.

The repository is open for:

- Technical review
- Security research
- Experimentation
- Learning
- Collaboration

Especially useful feedback would come from penetration testers, red teamers, AppSec engineers, security researchers, security-tooling engineers, AI/agent engineers and software architects.

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

PHANTOM is an exploration of a simple question:

«What would a security testing system look like if it could maintain a model of an application, reason over evidence, understand attack paths, and continuously decide what should be tested next?»

This repository is one attempt at answering that question.
