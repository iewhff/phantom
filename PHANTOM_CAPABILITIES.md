# PHANTOM AI — Pentesting Capabilities Reference

## Executive Summary

PHANTOM is an autonomous vulnerability scanner with 77+ specialized modules, 6-stage validation, exploitation proof, and attack chain analysis. It operates across 7 safety modes (safe → aggressive) with multi-layer authorization controls.

---

## 1. Architecture Overview

### Core Components
- **CLI Layer**: Click-based interface (`phantom_cli.py`) with commands: `bounty`, `full`, `quick`, `client`, `handoff`, `hackerone-report`
- **Scanning Engine**: `FullScanner` orchestrates 77 modules in 7 phases with parallel execution
- **Validation Pipeline**: 6-stage false-positive elimination before final output
- **Report Generators**: HackerOne, Client (pentest), SARIF (CI/CD) formats
- **Intelligence Layer**: Tech fingerprinting, domain classification, endpoint discovery

### Execution Flow
```
Target URL → Discovery (Phase 0) → Tech Intel (Phase 1) →
Module Execution (Phases 2-3) → Post-Processing (Phase 4) →
Validation → Reports (Phase 5) → Cleanup (Phase 6)
```

---

## 2. Scanner Modules (77 Total)

### 2.1 Injection Testing (8 modules)

**SQL Injection Scanner**
- Detection: Error-based, Union-based, Blind Boolean, Blind Time-based, Stacked Queries
- Database support: MySQL, PostgreSQL, SQLite, MSSQL, Oracle
- Data extraction: Tables, columns, sample rows via `_extract_data_union()`, `_extract_data_blind_boolean()`
- Auth bypass: Tests `' OR 1=1--` variants on login forms
- Parameter types: Query strings, form bodies, JSON bodies, headers

**NoSQL Injection Scanner**
- MongoDB operators: `$ne`, `$gt`, `$regex`, `$where`
- Blind extraction: Character-by-character brute-force via `$regex`
- Auth bypass: `{"email": {"$ne": ""}, "password": {"$ne": ""}}`

**Command Injection Scanner**
- Payloads: `;id`, `|whoami`, `$(command)`, backticks, newline injection
- Context-aware: Detects output reflection vs blind (time-based)
- OS detection: Linux/Windows command variants

**SSTI Scanner**
- Engines: Jinja2, Twig, Velocity, Freemarker, Pebble, Smarty, Mako, ERB
- Detection: Math expressions (`{{7*7}}`→`49`), canary strings
- Exploitation: RCE proof via `os.popen()` capture in `metadata.rce_output`

**XXE Scanner**
- Attacks: External entity, parameter entity, blind OOB via external DTD
- Targets: XML endpoints, SOAP, SVG uploads
- Extraction: `/etc/passwd`, Windows `win.ini`
- Evidence: Captured file content in `metadata.file_content`

**LFI/RFI Scanner**
- Traversal: `../` sequences (up to 10 levels), null byte, encoding variants
- Wrappers: `php://filter`, `php://input`, `data://`, `expect://`
- Log poisoning: User-Agent injection + inclusion chain

**LDAP Injection Scanner**
- Payloads: `*)(uid=*)`, `*)(objectClass=*`, authentication bypass
- Context: Login forms, search filters

**XPath Injection Scanner**
- Payloads: `' or '1'='1`, `admin' or '1'='1`, boolean-based

### 2.2 Cross-Site Scripting (4 modules)

**XSS Scanner**
- Types: Reflected, Stored (with auth), DOM-based (via Playwright)
- Contexts: HTML body, attributes, JavaScript, URLs
- Bypass: WAF evasion (encoding, case mixing, tag variations)
- Evidence: Captures reflection point, context, working payload

**DOM XSS Scanner** (Playwright-based)
- Real browser execution: Headless Chromium validates actual DOM manipulation
- SPA awareness: Tests Angular/React/Vue routes (`/#/search?q=<payload>`)
- Route discovery: Extracts `[routerLink]`, hash links from page
- postMessage testing: Validates XSS via window.postMessage

**CSTI Scanner** (Client-Side Template Injection)
- Frameworks: Angular (`{{constructor.constructor('alert()')()}}`), Vue, React, Handlebars
- Grouped findings: One finding per (framework, endpoint) with all params listed

**Prototype Pollution Scanner**
- Sources: URL parameters, JSON bodies, query strings
- Sinks: `Object.prototype` modification detection
- Gadgets: Tests for known pollution-to-XSS gadgets

### 2.3 Authentication & Session (6 modules)

**Session Abuse Scanner**
- JWT tampering: `alg:none` variants, RS256→HS256 confusion, HMAC brute-force
- Token persistence: Verifies tokens invalid after logout
- Privilege escalation: Forges admin claims, tests restricted endpoints
- Generic discovery: GENERIC_WHOAMI_PATHS, GENERIC_ADMIN_PATHS (no target-specific hardcoding)

**Authentication Scanner**
- Brute-force: Tests common credentials, rate limit detection
- Lockout bypass: Header manipulation, IP rotation awareness
- Password reset: Token predictability, flow abuse

**OAuth Scanner**
- Misconfigurations: Open redirect in redirect_uri, state parameter absence
- Token leakage: Referrer header, fragment handling
- CSRF: State validation bypass

**JWT Scanner**
- Algorithm confusion, weak secrets, signature stripping
- Claim tampering: exp, iat, role modifications

**2FA Bypass Scanner**
- Code brute-force, rate limit evasion
- Response manipulation, backup code testing

**SAML Scanner**
- Signature wrapping, XXE in assertions
- Comment injection, recipient mismatch

### 2.4 Access Control (4 modules)

**IDOR Scanner**
- Parameter enumeration: Sequential IDs, UUIDs, predictable patterns
- Methods: Tests GET→POST→PUT→DELETE on same resource
- Scope: Same-user vs cross-user vs admin resource access

**BOLA Scanner** (Broken Object-Level Authorization)
- Multi-tenant isolation testing
- Horizontal privilege escalation (user A accessing user B)

**Authorization Scanner**
- Vertical escalation: User→Admin endpoint access
- Role manipulation: Header injection, parameter tampering
- Function-level: Checks all HTTP methods per endpoint

**ABAC Context Tester**
- Attribute manipulation: Location, time, device context
- Policy bypass: Conflicting attribute combinations

### 2.5 Business Logic (5 modules)

**Business Logic Scanner**
- Domain-aware: 7 archetypes (E-commerce, SaaS, Fintech, Marketplace, Auth-Centric, Content, API)
- Rule violations: Price tampering, quantity manipulation, workflow bypass
- Flow abuse: Step skipping, state transition violations
- Financial impact: Zero-price orders, negative quantities, coupon stacking

**Race Condition Scanner**
- TOCTOU: Time-of-check-time-of-use exploitation
- Parallel requests: Concurrent coupon application, balance manipulation
- Resource exhaustion: Slot overbooking, inventory races

**Rate Limiting Scanner**
- Bypass techniques: Header rotation, endpoint variations
- Threshold detection: Identifies limits and lockout periods

**Mass Assignment Scanner**
- Hidden fields: isAdmin, role, balance, verified
- Parameter pollution: Array/object injection

**Workflow Inference Engine**
- State machine reconstruction from endpoint behavior
- Step bypass detection, required field skipping

### 2.6 API Security (6 modules)

**GraphQL Scanner**
- Introspection exposure, batch query abuse
- Directive injection, nested query DoS
- Mutation authorization, field-level access control

**REST API Scanner**
- Parameter tampering, method override
- Content-type confusion, accept header manipulation

**WebSocket Scanner**
- Message injection, CSWSH (Cross-Site WebSocket Hijacking)
- Origin validation, authentication persistence

**gRPC Scanner**
- Reflection abuse, message tampering
- TLS verification bypass

**API Gateway Scanner**
- Path normalization bypass, routing confusion
- Header injection, backend direct access

**Webhook Security Scanner**
- Signature validation, replay attacks
- SSRF via callback URL manipulation

### 2.7 Creative & Adversarial Testing (5 engines in 1 module)

**Creative Exploiter Module** (requires aggressive mode)

*Context Confusion Engine*
- Injects parameters from wrong business context (payment params on profile endpoints)
- Tests field leakage and cross-context state pollution

*Trust Boundary Prober*
- Admin endpoint exposure without authentication
- Role confusion via header manipulation
- Internal API path discovery

*Flow Disruption Engine*
- HTTP method override testing
- Content-type confusion (JSON↔XML↔form)
- Request ordering violations

*Chaos Composer*
- Parameter pollution: `?id[$gt]=&id[]=1&id[]=2`
- Empty body acceptance testing
- Malformed input tolerance

*Lazy Developer Exploiter*
- Debug endpoint discovery
- Default credential testing
- Verbose error triggering

**Finding Enricher** (post-engine analysis)
- Cross-engine chain detection
- Confidence adjustment based on corroboration
- Exploit likelihood scoring

### 2.8 Infrastructure (8 modules)

**Security Headers Scanner**
- Missing headers: CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy
- CSP analysis: Weak directives, unsafe-inline, unsafe-eval
- CORS headers: Permissive origins, credential exposure

**CORS Scanner**
- Arbitrary origin reflection
- Null origin acceptance
- Preflight bypass (simple requests with credentials)
- Evidence: Full request/response capture per test type

**SSL/TLS Scanner**
- Protocol versions: SSLv3, TLS 1.0/1.1 detection
- Cipher suites: Weak ciphers, export-grade
- Certificate validation: Expiry, self-signed, hostname mismatch

**DNS Scanner**
- Zone transfer attempts
- Subdomain enumeration
- SPF/DKIM/DMARC analysis

**Port Scanner**
- Service detection on common ports
- Banner grabbing, version fingerprinting

**Directory Scanner**
- Common paths: admin panels, config files, backups
- Git/SVN exposure: `.git/config`, `.svn/entries`
- SPA false-positive filtering: Compares against homepage response

**CMS Scanner**
- Detection: WordPress, Drupal, Joomla, Magento, etc.
- Version fingerprinting, plugin enumeration
- Known vulnerability correlation
- SPA filtering: Rejects same-response admin pages

**Cloud Misconfiguration Scanner**
- S3 bucket permissions, Azure blob access
- Metadata endpoint exposure (169.254.169.254)

### 2.9 Information Disclosure (4 modules)

**Secrets Pattern Scanner**
- API keys, tokens, passwords in responses
- Cloud credentials: AWS, GCP, Azure patterns
- Source code leakage detection

**Config Exposure Scanner**
- `.env`, `config.php`, `settings.py` discovery
- Database connection strings
- API endpoint documentation (swagger.json, openapi.yaml)

**Error Information Scanner**
- Stack trace extraction
- Database error messages (reveals schema)
- Framework version disclosure

**Version Disclosure Scanner**
- Server headers: Apache, nginx, IIS versions
- Framework fingerprints: X-Powered-By, X-AspNet-Version

### 2.10 Specialized Scanners

**Token Binding Validator**
- Device binding verification
- Session fixation detection
- Token rotation on privilege change

**Concurrency Stress Scanner**
- Parallel request handling
- Deadlock detection
- Resource exhaustion patterns

**Client Hardening Scanner**
- Cookie flags: Secure, HttpOnly, SameSite
- Local storage exposure
- Sensitive data in client-side code

---

## 3. Discovery & Intelligence

### 3.1 Smart Discovery (Phase 0)
- URL parsing and normalization
- Technology fingerprinting (Wappalyzer patterns)
- Endpoint extraction from HTML, JavaScript, robots.txt, sitemap.xml
- Localhost fallback: 40+ common paths for local targets

### 3.2 Tech Intelligence (Phase 1)
- Server identification: Headers, error pages, behavior
- Framework detection: Angular, React, Vue, Express, Django, etc.
- Database inference: Error patterns, response timing
- Module recommendations: Which scanners are relevant
- **NEVER_SKIP_MODULES safeguard**: Critical injection scanners always run regardless of tech fingerprint

### 3.3 Domain Classification
- 7 archetypes with weighted signals (endpoints 0.5, tech 0.3, content 0.2)
- Per-archetype business rules, workflow templates, bypass patterns
- Informs business logic scanner testing strategy

### 3.4 Endpoint Map
- Centralized endpoint registry for all modules
- Categories: AUTH, PAYMENT, ADMIN, ACCOUNT, DATA, FEEDBACK, API_REST, etc.
- Enables cross-module targeting and creative exploitation

---

## 4. Authentication Acquisition

### 4.1 Auth Context Layer
- Strategies (in order): Register new user → Common credentials → SQLi bypass (aggressive only)
- Uses aiohttp directly: Bypasses SafeAsyncClient POST restrictions
- Token storage: JWT, session cookies, basket IDs

### 4.2 Integration
- Runs before scanning modules (Phase 0.5)
- Stored in `asset_data["auth_context"]`
- Modules read auth and include headers on all requests

### 4.3 Credential Feedback Loop
- SQLi extracts credentials → Prover attempts login → Upgraded auth for subsequent tests
- Enables: Find SQLi → Extract admin creds → Test admin endpoints with real auth

---

## 5. Post-Processing Pipeline

### 5.1 Aggregation (Phase 4.0)
- Collects findings from all modules
- Normalizes structure, deduplicates by (type, host, matched_at)
- Name-based dedup for business_logic, session_abuse, creative_exploiter

### 5.2 Exploitation Proof Engine (Phase 4.2)
For each HIGH+ finding, answers 4 questions:
1. **Can repeat?** Re-sends exact PoC, verifies deterministic
2. **Can mutate?** Tries payload variations
3. **Can escalate?** Attempts privilege escalation (user→admin, read→write)
4. **Can chain?** Identifies unlocked attacks on other endpoints

7 specialized provers: SQLi, XSS, IDOR, BusinessLogic, Session, CORS, Generic

Safety enforcement: `safe=0 reqs`, `cautious=5`, `standard=15`, `aggressive=50`

### 5.3 Vulnerability Chain Engine (Phase 4.3)
- 13 realistic attack chain patterns based on real incidents
- Cross-module analysis: SQLi+Session, XSS+CORS, IDOR+BusinessLogic
- Chain findings marked as `is_cross_module=True` (derivable) or `False` (speculative)
- Dedup: Each chain action fires at most once

### 5.4 Exploitability Classifier (Phase 4.45)
3-tier classification:
- **EXPOSURE (0-29)**: Visible weakness, no demonstrated impact
- **PARTIAL (30-69)**: Triggerable but limited impact
- **FULL (70-100)**: Demonstrated real-world impact

Factors: extracted_data, privilege_escalation, rce_output, proof results

### 5.5 Attack Chain Analyzer (Phase 4.47)
- Pattern matching against 13 realistic chains (SQLi→Admin, XSS→ATO, CORS→DataTheft)
- Dynamic chain discovery from finding combinations
- Probability scoring and narrative generation

### 5.6 Attacker Intent Engine (Phase 4.48)
- 5 goal types: FINANCIAL_GAIN, DATA_THEFT, ACCOUNT_TAKEOVER, ADMIN_ACCESS, CODE_EXECUTION
- Context-aware severity: SQLi on /login → CRITICAL, XSS on /search → LOW
- State transitions: ANONYMOUS→AUTHENTICATED, USER→ADMIN, READ→WRITE
- Attack path reconstruction with probability scoring

---

## 6. Validation Pipeline (6 Stages)

### Stage 1: Syntax Validation
- Required fields present (type, severity, confidence)
- Valid severity levels, confidence ranges

### Stage 2: Duplicate Detection
- Exact match filtering
- Near-duplicate clustering

### Stage 3: Context Validation
- Behavior-based modules get boosted (+0.10-0.15)
- Recognized indicators increase confidence

### Stage 4: Safe Replay
- Re-sends request, verifies same response pattern
- **Skipped for behavior-based modules**: business_logic, creative_exploiter, session_abuse, etc.

### Stage 5: Negative Control
- Sends benign request, should NOT trigger same detection
- **Passes with +0.1 boost for behavior-based modules**

### Stage 6: Confidence Threshold
- Final gate: `min_confidence=60.0`
- Findings below threshold discarded

### Feedback Learning
- Records TP/FP outcomes per module
- Adjusts confidence based on historical accuracy
- Payload reputation tracking

### Incident-Based Learning (NEW)
The "next level" of scanner intelligence: learning from REAL outcomes.

**Three Learning Signals:**
1. **Bounty Payouts**: Was the report paid? How much? Rejected?
2. **Real Incidents**: Did this chain happen in production?
3. **Chain Success**: Which attack chains actually work?

**CLI Commands:**
- `phantom learn bounty -p program -t xss -o paid --payout 500`
- `phantom learn incident -t sqli -c sqli_to_data -i data_theft`
- `phantom learn stats` — Show learning statistics
- `phantom learn seed --confirm` — Bootstrap with known patterns

**Integration:**
- Attack chain analyzer uses learned probabilities
- Probabilities adjusted from real-world breach data
- Known patterns: Equifax, Capital One, Facebook breaches

---

## 7. Report Generation

### 7.1 HackerOne Reports
- CWE/CVSS mapping for all vulnerability types
- Program scope matching (PROGRAM_SCOPES dict)
- Structured evidence with full HTTP request/response
- Proof status rendering: proven/derivable/speculative/unproven
- Asset dominance: Target domain appears 15+ times

### 7.2 Client Reports
- Executive summary with financial impact estimates
- Compliance mapping: OWASP, PCI-DSS, NIST 800-53
- Per-finding PoC and reproduction steps
- Handoff document for human testers

### 7.3 SARIF Output
- Integrates with CI/CD pipelines
- GitHub Code Scanning compatible
- Location mapping to endpoints

---

## 8. Safety Mechanisms

### 8.1 Three-Layer Safety System
1. **VulnScanner level**: `min_safety_level` per scan type
2. **FullScanner level**: `MODULE_SAFETY_LEVELS` dict per module
3. **Module level**: Individual `self._min_safety_level` checks

### 8.2 Safety Modes
- `safe`: Read-only, no exploitation attempts
- `cautious`: Light testing, no auth manipulation
- `standard`: Normal testing, no destructive actions
- `aggressive`: Full exploitation, write operations allowed

### 8.3 SafeAsyncClient
- Replaces httpx.AsyncClient globally
- Blocks POST/PUT/DELETE in safe mode
- Modules needing POST use aiohttp directly

### 8.4 ScopeGuard
- Validates all requests against target scope
- Blocks localhost by default (overridden for local targets)
- Prevents SSRF-style scope escapes

### 8.5 Rate Limiting
- Per-target rate limits (`RateLimiter(default_rate=50.0, default_burst=50)`)
- Respects 429 responses
- Backoff on consecutive errors

---

## 9. Performance Characteristics

### 9.1 Parallelization
- Modules execute concurrently within safety constraints
- Async HTTP with connection pooling
- Browser reuse for DOM XSS testing

### 9.2 Timeouts
- Per-module: 300s default, configurable
- Per-request: 10s default
- Scan-wide: Unlimited (modules individually timeout)

### 9.3 Progress Tracking
- Per-module status: STARTING/DONE/TIMEOUT/ERROR
- Incremental state saves after each module
- On-progress callbacks for CLI updates

---

## 10. Identified Improvements

### 10.1 High Priority

**GraphQL Depth Limiting**
Current: No depth analysis. Enhancement: Add query complexity scoring, detect DoS-prone nested queries.

**HTTP/2 & HTTP/3 Support**
Current: HTTP/1.1 only. Enhancement: Protocol-specific attacks (stream ID manipulation, HPACK bombing).

**WebAssembly Analysis**
Current: Not scanned. Enhancement: Parse WASM for exported functions, memory issues.

**Machine Learning Integration**
Current: Rule-based. Enhancement: Anomaly detection for unusual response patterns, adaptive payload generation.

### 10.2 Medium Priority

**Passive Reconnaissance**
Current: Active-only. Enhancement: DNS enumeration, certificate transparency logs, Shodan integration.

**Mobile API Testing**
Current: Generic API. Enhancement: Certificate pinning bypass, mobile-specific auth flows.

**Container Escape Detection**
Current: Not covered. Enhancement: Docker/K8s privilege escalation paths.

**PDF/Office Document Injection**
Current: Not covered. Enhancement: Test document generation endpoints for formula/macro injection.

### 10.3 Low Priority

**Fuzzing Module**
Current: Payload-based. Enhancement: Coverage-guided fuzzing for complex parsers.

**Protocol-Specific Scanners**
Enhancement: MQTT, CoAP, AMQP for IoT targets.

**Source Code Correlation**
Enhancement: If source available, correlate findings to code lines.

---

## 11. Module Registration Quick Reference

| Category | Modules | Safety Level |
|----------|---------|--------------|
| Injection | sqli, nosql, cmdi, ssti, xxe, lfi, ldap, xpath | standard |
| XSS | xss, dom_xss, prototype_pollution, csti | standard |
| Auth | session_abuse, auth, oauth, jwt, 2fa, saml | standard |
| Access | idor, bola, authz, abac | standard |
| Business | business_logic, race, rate_limit, mass_assign | standard |
| API | graphql, rest, websocket, grpc, gateway, webhook | standard |
| Creative | creative_exploiter | aggressive |
| Infra | headers, cors, ssl, dns, ports, dirs, cms, cloud | safe |
| Info | secrets, config, errors, versions | safe |

---

## 12. CLI Usage Patterns

### Standard Bounty Scan
```
phantom bounty https://target.com --program hackerone-program
```

### Aggressive Localhost Testing
```
PHANTOM_SAFE_MODE=aggressive phantom scan http://localhost:8080 --safe-mode aggressive
```

### Client Engagement
```
phantom client https://target.com --compliance owasp,pci-dss
```

### Quick Reconnaissance
```
phantom quick https://target.com
```

---

*Document generated from code analysis. Last updated: 2026-02-06. Character count: ~24,500*
