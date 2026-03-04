# 🤖 PATHFINDER AI - Command Reference

> "Hi friends! I'm here to help you find vulnerabilities!" - Pathfinder

## Quick Start

```bash
# Install
pip install -e .

# Run a scan
pathfinder scan https://target.com

# Quick scan (5 modules) - "That was easy!"
pathfinder quick https://target.com

# Full scan (75+ modules) - "I love this job!"
pathfinder full https://target.com

# Bug bounty optimized - "High five, friend!"
pathfinder bounty https://target.com -u your_username -s "*.target.com"
```

## 🎮 Available Commands

### 🎯 `scan` - Execute Security Scan

The main scanning command with full control over modules and options.

```bash
pathfinder scan https://target.com [OPTIONS]

Options:
  -m, --modules TEXT      Modules to run (category or comma-separated)
  -e, --exclude TEXT      Modules to exclude
  -r, --rate INTEGER      Requests per second [default: 10]
  -c, --concurrent INT    Concurrent modules [default: 5]
  -t, --timeout INTEGER   Scan timeout in seconds [default: 300]
  -o, --output TEXT       Output file path
  -f, --format TEXT       Output format (json/sarif/html/md)
  --safe-mode TEXT        Safety level (safe/cautious/standard/aggressive)
  --no-ai                 Disable AI validation
  --include-subdomains    Include subdomain enumeration
```

**Examples:**
```bash
# Scan with specific modules
pathfinder scan https://api.target.com -m api,graphql,jwt

# Aggressive scan (requires authorization!)
pathfinder scan https://target.com --safe-mode aggressive

# Output to SARIF for CI/CD integration
pathfinder scan https://target.com -f sarif -o results.sarif
```

### ⚡ `quick` - Fast Scan

5 essential modules for quick security assessment.

```bash
pathfinder quick https://target.com
```

*"That was easy!"* 🤖

### 🔥 `full` - Comprehensive Scan

All 75+ security modules for thorough testing.

```bash
pathfinder full https://target.com --concurrent 10
```

*"I love this job!"* 🤖

### 🏆 `bounty` - Bug Bounty Mode

Optimized for bug bounty hunting with legal compliance.

```bash
pathfinder bounty https://target.com -u your_username -s "*.target.com"

Options:
  -u, --username TEXT     HackerOne/Platform username (required)
  -s, --scope TEXT        Scope pattern (required)
  -r, --rate INTEGER      Requests per second [default: 5]
  --safe-mode TEXT        Safety level [default: cautious]
```

*"High five, friend!"* 🤖💰

### 📋 `modules` - List Modules

Show all available security modules and categories.

```bash
pathfinder modules
```

### 🏥 `health` - System Check

Verify PATHFINDER AI is properly configured.

```bash
pathfinder health
```

*"I feel most alive when rapidly approaching my death!"* 🤖

## 🎨 Module Categories

| Category | Count | Description |
|----------|-------|-------------|
| `quick` | 5 | Fast essential checks |
| `web` | 11 | Core web vulnerabilities |
| `api` | 10 | API security testing |
| `injection` | 9 | All injection types |
| `auth` | 8 | Authentication/Authorization |
| `infra` | 8 | Infrastructure security |
| `advanced` | 6 | Advanced attacks |
| `standard` | 17 | Comprehensive web testing |
| `bounty` | 21 | Bug bounty optimized |
| `client` | 47+ | Full professional engagement |

## 🔒 Safety Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| `safe` | Read-only, no active testing | Initial recon |
| `cautious` | Safe payloads, rate limited | Bug bounty |
| `standard` | Standard testing | Regular scans |
| `aggressive` | Full testing (requires consent!) | Authorized pentests |

## 🛡️ Environment Variables

```bash
# Disable Tor proxy (for localhost scanning)
PATHFINDER_NO_TOR=1 pathfinder scan http://localhost:8080

# Disable circuit breaker (prevents auto-pause on rate limiting)
PATHFINDER_NO_CIRCUIT_BREAKER=1 pathfinder scan https://target.com

# Enable aggressive mode (requires authorization)
PATHFINDER_ALLOW_AGGRESSIVE=authorized pathfinder scan https://target.com --safe-mode aggressive

# Full unrestricted mode (I KNOW WHAT I'M DOING!)
PATHFINDER_UNRESTRICTED=i-understand-the-risks pathfinder scan https://target.com

# Debug validation pipeline
PATHFINDER_VALIDATION_DEBUG=1 pathfinder scan https://target.com

# Deterministic scanning (reproducible results)
PATHFINDER_DETERMINISTIC=1 pathfinder scan https://target.com

# FULL AGGRESSIVE LOCALHOST SCAN (all safeties off) 🔥
PATHFINDER_NO_TOR=1 PATHFINDER_NO_CIRCUIT_BREAKER=1 PATHFINDER_ALLOW_AGGRESSIVE=authorized PATHFINDER_UNRESTRICTED=i-understand-the-risks pathfinder scan http://localhost:80 --safe-mode aggressive -r 30 -c 10
```

## 🎯 Output Formats

| Format | Extension | Use Case |
|--------|-----------|----------|
| `json` | `.json` | Raw findings data |
| `sarif` | `.sarif` | CI/CD integration |
| `html` | `.html` | Client reports |
| `md` | `.md` | Documentation |

## 📝 Examples

### Basic Web Application Scan
```bash
pathfinder scan https://example.com
```

### API Security Focused
```bash
pathfinder scan https://api.example.com -m api,graphql,jwt,auth,idor
```

### Bug Bounty Workflow
```bash
# 1. Accept legal terms
pathfinder bounty https://bugcrowd.com -u hunter123 -s "*.bugcrowd.com"

# 2. Generate HackerOne reports
pathfinder hackerone-report reports/pathfinder_bugcrowd.json
```

### CI/CD Integration
```bash
pathfinder scan https://staging.example.com -f sarif -o security-results.sarif
```

### Localhost Testing
```bash
PATHFINDER_NO_TOR=1 pathfinder scan http://localhost:8080
```

## 🤖 Pathfinder Quotes

> "Who's ready to fly on a zipline? I AM!"

> "I just polished my grapple!"

> "High five, friend!" ✋

> "I'm coming for you, friend!"

> "I don't have to find a path. I AM a path!"

> "First we fight, then we drink! ...on second thought, I can't drink."

---

*Made with ❤️ by the Legends*

*"Who's ready to fly on a zipline? I AM!"* 🪝
