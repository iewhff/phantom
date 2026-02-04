# PHANTOM AI CLI - Command Line Interface Guide

<div align="center">

```
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗        ║
║  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║        ║
║  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║        ║
║  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║        ║
║  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║        ║
║  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝        ║
║                                                                          ║
║            Professional Heuristic Automated Network                      ║
║            Threat Operations Module                                      ║
║                                                                          ║
║  v3.0.0 (Enterprise Edition)                                             ║
║  75+ Security Modules | 6-Stage Validation | Zero False Positives        ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
```

**Enterprise AI-Powered Penetration Testing Framework**

</div>

---

## 📋 Table of Contents

- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Commands Overview](#-commands-overview)
- [Scan Modes](#-scan-modes)
- [Safety Levels](#-safety-levels)
- [Output Formats](#-output-formats)
- [Module Categories](#-module-categories)
- [Command Reference](#-command-reference)
- [Examples](#-examples)
- [Configuration](#-configuration)
- [Troubleshooting](#-troubleshooting)

---

## 🚀 Installation

```bash
# Install from source
git clone https://github.com/iewhff/phantom.git
cd phantom
pip install -e .

# Verify installation
phantom --help
phantom version
```

---

## ⚡ Quick Start

```bash
# 1. Authorize a target (required for legal compliance)
phantom authorize example.com

# 2. Run a quick scan
phantom quick https://example.com

# 3. Run a full scan
phantom full https://example.com

# 4. Generate a report
phantom report PHANTOM_20260204_123456_abcd1234
```

---

## 📖 Commands Overview

| Command | Description | Use Case |
|---------|-------------|----------|
| `scan` | Standard security scan | General purpose scanning |
| `quick` | Fast scan (5 modules) | Quick security check |
| `full` | Comprehensive scan (75+ modules) | Full penetration test |
| `bounty` | Bug bounty optimized scan | Bug bounty hunting |
| `client` | Professional client engagement | Enterprise assessments |
| `recon` | Reconnaissance only (passive) | Information gathering |
| `chain` | Vulnerability chaining analysis | Attack path discovery |
| `waf-detect` | WAF detection & bypass strategies | WAF identification |
| `modules` | List available modules | Module discovery |
| `status` | Check scan status | Monitor progress |
| `list` | List previous scans | Scan history |
| `resume` | Resume interrupted scan | Continue scanning |
| `report` | Generate report from scan | Documentation |
| `authorize` | Authorize target for scanning | Legal compliance |
| `validate` | Re-validate findings | False positive elimination |
| `health` | Check system health | System diagnostics |
| `impact` | Business impact assessment | Risk analysis |
| `compliance` | Compliance framework mapping | Regulatory reporting |
| `presets` | Manage bug bounty presets | Configuration management |
| `update-kb` | Update knowledge base | Keep payloads current |
| `version` | Show version info | Version check |

---

## 🎯 Scan Modes

### Quick Mode (`phantom quick`)
```bash
phantom quick https://example.com
```
- **Modules:** 5 (headers, SSL, CORS, XSS, SQLi)
- **Duration:** ~2-5 minutes
- **Use Case:** Rapid security assessment

### Standard Mode (`phantom scan`)
```bash
phantom scan https://example.com
```
- **Modules:** Category-based (configurable)
- **Duration:** ~10-30 minutes
- **Use Case:** Balanced security testing

### Full Mode (`phantom full`)
```bash
phantom full https://example.com
```
- **Modules:** 75+ (all available)
- **Duration:** ~1-3 hours
- **Use Case:** Comprehensive penetration test

### Bounty Mode (`phantom bounty`)
```bash
phantom bounty https://api.target.com --platform hackerone
```
- **Modules:** High-value vulnerabilities (IDOR, SQLi, XSS, Auth, API)
- **Duration:** ~30-60 minutes
- **Use Case:** Bug bounty hunting

### Client Mode (`phantom client`)
```bash
phantom client https://client.com --client-name "ACME Corp"
```
- **Modules:** 47+ enterprise modules
- **Duration:** ~2-4 hours
- **Use Case:** Professional client engagements

---

## 🛡️ Safety Levels

| Level | Icon | Description | Use Case |
|-------|------|-------------|----------|
| `passive` | 🔒 | Observation only, no requests | Stealth reconnaissance |
| `safe` | 🛡️ | Non-destructive tests only | Production environments |
| `cautious` | ⚠️ | Limited active testing | Sensitive systems |
| `standard` | 🔧 | Balanced testing | General purpose |
| `aggressive` | ⚡ | Full exploitation attempts | Lab/authorized testing |

```bash
# Examples
phantom scan https://example.com -s passive    # Read-only
phantom scan https://example.com -s safe       # Default (recommended)
phantom scan https://example.com -s aggressive # Full testing (lab only!)
```

---

## 📄 Output Formats

| Format | Extension | Description |
|--------|-----------|-------------|
| `html` | `.html` | Interactive HTML report (default) |
| `json` | `.json` | Machine-readable JSON |
| `md` | `.md` | Markdown documentation |
| `pdf` | `.pdf` | Professional PDF report |
| `sarif` | `.sarif` | Static Analysis Results Format (CI/CD) |

```bash
# Examples
phantom scan https://example.com -f html
phantom scan https://example.com -f json -o results.json
phantom scan https://example.com -f sarif  # For CI/CD integration
```

---

## 📦 Module Categories

### 💉 Injection (11 modules)
```
sqli, xss, dom_xss, cmdi, xxe, nosql, ssti, ldap, crlf, lfi, ssrf
```

### 🔐 Authentication (8 modules)
```
auth, oauth, saml, mfa, authz, jwt, csrf, rate_limit
```

### 🌐 API (7 modules)
```
api, graphql, grpc, websocket, sse, idor, mass_assign
```

### 🏗️ Infrastructure (6 modules)
```
ssl, headers, cors, cloud, k8s, dns_rebind
```

### ⚡ Advanced (7 modules)
```
smuggling, cache, deser, prototype, rls_bypass, business, mobile
```

### 🔍 Discovery (7 modules)
```
cms, directory, nuclei, backend, 3rdparty, email, cred_verify
```

### ☁️ BaaS (3 modules)
```
supabase, firebase, appwrite
```

```bash
# Run specific category
phantom scan https://example.com -m injection
phantom scan https://example.com -m api

# Run specific modules
phantom scan https://example.com -m sqli,xss,idor

# Exclude modules
phantom scan https://example.com --exclude nuclei,directory
```

---

## 📚 Command Reference

### `phantom scan`
Execute PHANTOM AI security scan.

```bash
phantom scan <TARGET> [OPTIONS]

Options:
  -o, --output PATH          Output directory
  -f, --format FORMAT        Report format (pdf|html|json|md|sarif)
  -m, --modules TEXT         Modules to run (comma-separated or category)
  -s, --safe-mode LEVEL      Safety level (passive|safe|cautious|standard|aggressive)
  -r, --rate FLOAT           Requests per second [default: 2.0]
  -c, --concurrent INT       Concurrent modules [default: 3]
  --scope TEXT               Additional in-scope domains (multiple allowed)
  --exclude TEXT             Exclude specific modules (multiple allowed)
  --preset TEXT              Load bug bounty preset
  --no-recon                 Skip reconnaissance phase
  --no-tools                 Skip Linux tools integration
  --no-chain                 Skip vulnerability chaining
  --no-ai                    Skip AI validation
  --no-auth                  Skip authorization check
  --timeout INT              Overall scan timeout in seconds
```

**Examples:**
```bash
# Basic scan
phantom scan https://example.com

# Custom modules with safe mode
phantom scan https://api.target.com -m injection -s cautious

# Full scan with specific rate
phantom scan target.com -r 5.0 -c 5 --no-recon
```

---

### `phantom quick`
Fast PHANTOM AI scan (5 modules).

```bash
phantom quick <TARGET> [OPTIONS]

Options:
  -o, --output PATH     Output directory
  -f, --format FORMAT   Report format (html|json|md)
```

**Example:**
```bash
phantom quick https://example.com -f json
```

---

### `phantom full`
Comprehensive PHANTOM AI scan (all 75+ modules).

```bash
phantom full <TARGET> [OPTIONS]

Options:
  -o, --output PATH      Output directory
  -f, --format FORMAT    Report format (pdf|html|json|md|sarif)
  -s, --safe-mode LEVEL  Safety level (safe|cautious|standard)
```

**Example:**
```bash
phantom full https://example.com -s cautious -f sarif
```

---

### `phantom bounty`
Bug bounty optimized PHANTOM AI scan.

```bash
phantom bounty <TARGET> [OPTIONS]

Options:
  -o, --output PATH          Output directory
  -f, --format FORMAT        Report format (html|json|md)
  --platform PLATFORM        Bug bounty platform (hackerone|bugcrowd|intigriti|other)
  --program-tier TIER        Program tier (entry|standard|premium|enterprise|top_tier)
  -r, --rate FLOAT           Requests per second [default: 1.0]
  --estimate/--no-estimate   Show bounty estimates [default: True]
```

**Example:**
```bash
phantom bounty https://api.target.com --platform hackerone --program-tier premium
```

**Bounty Estimates by Vulnerability:**
| Vulnerability | Typical Range |
|--------------|---------------|
| IDOR/BOLA | $3,000 - $20,000+ |
| SQL Injection | $2,000 - $15,000 |
| XSS (Stored) | $500 - $5,000 |
| Authentication Bypass | $3,000 - $25,000 |
| SSRF | $1,000 - $10,000 |

---

### `phantom client`
Professional client engagement with PHANTOM AI.

```bash
phantom client <TARGET> [OPTIONS]

Options:
  -o, --output PATH           Output directory
  -f, --format FORMAT         Report format (pdf|html|json|md)
  --client-name TEXT          Client organization name
  --engagement-id TEXT        Engagement identifier
  -s, --safe-mode LEVEL       Safety level (safe|cautious|standard|aggressive)
  -r, --rate FLOAT            Requests per second [default: 10.0]
  -c, --concurrent INT        Concurrent modules [default: 5]
  --subdomains/--no-subdomains  Subdomain enumeration [default: True]
  --compliance FRAMEWORK      Compliance frameworks (pci-dss|hipaa|gdpr|nist|owasp|all)
```

**Example:**
```bash
phantom client https://client.com \
  --client-name "ACME Corporation" \
  --engagement-id "PEN-2026-001" \
  -s standard \
  --compliance all \
  -f pdf
```

---

### `phantom recon`
Passive reconnaissance only (no active testing).

```bash
phantom recon <TARGET> [OPTIONS]

Options:
  -o, --output PATH                  Output file
  --subdomains/--no-subdomains       Enumerate subdomains [default: True]
  --technologies/--no-technologies   Fingerprint technologies [default: True]
  --endpoints/--no-endpoints         Discover endpoints [default: True]
  --parameters/--no-parameters       Discover parameters [default: True]
  --waf/--no-waf                     Detect WAF [default: True]
```

**Example:**
```bash
phantom recon target.com --technologies --waf -o recon_results.json
```

---

### `phantom chain`
Analyze and visualize vulnerability chains.

```bash
phantom chain <SCAN_ID> [OPTIONS]

Options:
  -o, --output PATH     Output file for visualization
  -f, --format FORMAT   Visualization format (svg|html|dot|mermaid|json)
```

**Example:**
```bash
phantom chain PHANTOM_20260204_123456_abcd1234 -f svg -o chains.svg
```

---

### `phantom waf-detect`
Detect and identify Web Application Firewall.

```bash
phantom waf-detect <TARGET> [OPTIONS]

Options:
  --bypass/--no-bypass   Show bypass strategies [default: True]
```

**Example:**
```bash
phantom waf-detect https://target.com
```

**Supported WAF Detection:**
- Cloudflare
- AWS WAF
- Akamai
- Imperva
- F5 BIG-IP
- ModSecurity
- Sucuri
- Barracuda
- And 20+ more...

---

### `phantom modules`
List all available PHANTOM AI security modules.

```bash
phantom modules [OPTIONS]

Options:
  -c, --category TEXT   Filter by category
```

**Example:**
```bash
phantom modules                   # List all
phantom modules -c injection      # Filter by category
```

---

### `phantom status`
Check scan status.

```bash
phantom status [SCAN_ID]
```

**Examples:**
```bash
phantom status                    # Show all recent scans
phantom status PHANTOM_20260204   # Show specific scan
```

---

### `phantom list`
List previous scans.

```bash
phantom list [OPTIONS]

Options:
  -n, --limit INT   Number of scans to show [default: 20]
```

**Example:**
```bash
phantom list -n 50
```

---

### `phantom resume`
Resume an interrupted scan.

```bash
phantom resume <SCAN_ID>
```

**Example:**
```bash
phantom resume PHANTOM_20260204_123456_abcd1234
```

---

### `phantom report`
Generate report from completed scan.

```bash
phantom report <SCAN_ID> [OPTIONS]

Options:
  -o, --output PATH       Output file path
  -f, --format FORMAT     Report format (pdf|html|json|md|sarif)
  --compliance FRAMEWORK  Include compliance mapping (multiple allowed)
  --bounty/--no-bounty    Include bounty estimates [default: False]
```

**Example:**
```bash
phantom report PHANTOM_20260204_123456 \
  -f html \
  --compliance owasp \
  --bounty \
  -o final_report.html
```

---

### `phantom authorize`
Authorize a target for scanning.

```bash
phantom authorize <TARGET>
```

**Example:**
```bash
phantom authorize example.com
phantom authorize https://api.target.com
```

⚠️ **Legal Notice:** Only scan targets you have explicit written permission to test.

---

### `phantom validate`
Re-validate findings using the 6-stage pipeline.

```bash
phantom validate [FINDING_ID] [OPTIONS]

Options:
  --scan-id TEXT   Scan ID to validate findings from
```

**Example:**
```bash
phantom validate --scan-id PHANTOM_20260204_123456
```

**6-Stage Validation Pipeline:**
1. **Syntax Validation** - Verify payload structure
2. **Response Analysis** - Analyze server responses
3. **Behavior Verification** - Confirm vulnerability behavior
4. **Impact Assessment** - Evaluate actual impact
5. **Context Validation** - Check environmental factors
6. **AI Verification** - ML-based confirmation

---

### `phantom health`
Check PHANTOM AI system health.

```bash
phantom health
```

**Checks:**
- Core module availability
- Knowledge base status
- System resources
- Configuration validation

---

### `phantom impact`
Assess business impact of vulnerabilities.

```bash
phantom impact <SCAN_ID> [OPTIONS]

Options:
  --industry INDUSTRY   Industry context (finance|healthcare|technology|retail|government|other)
```

**Example:**
```bash
phantom impact PHANTOM_20260204_123456 --industry finance
```

**Output includes:**
- CVSS scores
- CIA triad impact (Confidentiality, Integrity, Availability)
- Financial risk estimates
- Regulatory implications

---

### `phantom compliance`
Generate compliance mapping report.

```bash
phantom compliance <SCAN_ID> [OPTIONS]

Options:
  -f, --framework FRAMEWORK   Compliance framework (cwe|owasp|pci-dss|nist|hipaa|gdpr|all)
  -o, --output PATH           Output report file
```

**Example:**
```bash
phantom compliance PHANTOM_20260204_123456 \
  -f owasp \
  -f pci-dss \
  -o compliance_report.json
```

**Supported Frameworks:**
| Framework | Description |
|-----------|-------------|
| CWE | Common Weakness Enumeration |
| OWASP | Open Web Application Security Project Top 10 |
| PCI-DSS | Payment Card Industry Data Security Standard |
| NIST | NIST 800-53 Security Controls |
| HIPAA | Health Insurance Portability and Accountability Act |
| GDPR | General Data Protection Regulation |

---

### `phantom presets`
Manage bug bounty presets.

```bash
phantom presets [OPTIONS]

Options:
  -l, --list     List available presets
  -s, --show     Show preset details
  -c, --create   Create new preset
```

**Examples:**
```bash
phantom presets --list
phantom presets --show hackerone-default
phantom presets --create my-program
```

**Built-in Presets:**
- `hackerone-default` - HackerOne optimized settings
- `bugcrowd-default` - Bugcrowd optimized settings
- `intigriti-default` - Intigriti optimized settings

---

### `phantom update-kb`
Update security knowledge base.

```bash
phantom update-kb [OPTIONS]

Options:
  --source SOURCE   Knowledge base source (all|cve|exploitdb|payloads|hacktricks)
```

**Example:**
```bash
phantom update-kb                    # Update all
phantom update-kb --source payloads  # Update specific source
```

---

### `phantom version`
Show PHANTOM AI version information.

```bash
phantom version
```

---

## 📝 Examples

### Basic Security Assessment
```bash
# Authorize and scan
phantom authorize example.com
phantom scan https://example.com -s safe -f html -o reports/
```

### Bug Bounty Workflow
```bash
# Quick recon
phantom recon target.com --technologies --waf

# Bounty-optimized scan
phantom bounty https://api.target.com \
  --platform hackerone \
  --program-tier premium \
  --estimate

# Analyze chains
phantom chain PHANTOM_20260204_123456 -f html -o chains.html
```

### Professional Engagement
```bash
# Full client assessment
phantom client https://client.com \
  --client-name "ACME Corp" \
  --engagement-id "PEN-2026-001" \
  -s standard \
  -r 10.0 \
  -c 5 \
  --compliance all \
  -f pdf

# Generate compliance report
phantom compliance PHANTOM_20260204_123456 \
  -f owasp \
  -f pci-dss \
  -f gdpr \
  -o compliance_report.json

# Impact assessment
phantom impact PHANTOM_20260204_123456 --industry finance
```

### CI/CD Integration
```bash
# SARIF output for GitHub/GitLab integration
phantom scan https://staging.example.com \
  -s safe \
  -f sarif \
  -o results.sarif \
  --no-auth

# Exit code based on findings
if phantom scan https://example.com -f json | jq '.summary.critical > 0'; then
  echo "Critical vulnerabilities found!"
  exit 1
fi
```

---

## ⚙️ Configuration

### Configuration File Location
```
~/.phantom/config.yaml
config/settings.yaml
config/phantom_config.yaml
```

### Environment Variables
```bash
PHANTOM_API_KEY=your_api_key
PHANTOM_RATE_LIMIT=10.0
PHANTOM_SAFE_MODE=safe
PHANTOM_OUTPUT_DIR=./reports
```

### Data Directories
```
~/.phantom/
├── scans/          # Saved scan states
├── reports/        # Generated reports
├── presets/        # Custom presets
├── knowledge/      # Knowledge base
└── logs/           # Pentest logs
```

---

## 🔧 Troubleshooting

### Common Issues

**Target not authorized:**
```bash
# Solution: Authorize the target first
phantom authorize example.com
```

**Module not found:**
```bash
# List available modules
phantom modules

# Check if PHANTOM AI is fully loaded
phantom health
```

**Rate limiting:**
```bash
# Reduce request rate
phantom scan https://example.com -r 0.5 -c 1
```

**WAF blocking:**
```bash
# Detect WAF and get bypass strategies
phantom waf-detect https://target.com
```

**Scan interrupted:**
```bash
# Resume the scan
phantom status                                   # Get scan ID
phantom resume PHANTOM_20260204_123456_abcd1234  # Resume
```

### Debug Mode
```bash
# Enable verbose output
phantom -v scan https://example.com

# Enable debug logging
phantom --debug scan https://example.com
```

### Get Help
```bash
# General help
phantom --help

# Command-specific help
phantom scan --help
phantom bounty --help
phantom client --help
```

---

## 📜 Legal Notice

⚠️ **IMPORTANT: Only use PHANTOM AI on systems you have explicit written authorization to test.**

Unauthorized access to computer systems is illegal in most jurisdictions. Always:

1. Obtain written permission before testing
2. Define clear scope boundaries
3. Follow responsible disclosure practices
4. Document all testing activities
5. Report findings securely

---

## 📞 Support

- **Documentation:** [docs/](./docs/)
- **GitHub Issues:** [github.com/iewhff/phantom/issues](https://github.com/iewhff/phantom/issues)
- **Email:** security@phantom-ai.dev

---

<div align="center">

**PHANTOM AI v3.0.0 Enterprise Edition**

*Professional Heuristic Automated Network Threat Operations Module*

75+ Security Modules | 6-Stage Validation | Zero False Positives

</div>
