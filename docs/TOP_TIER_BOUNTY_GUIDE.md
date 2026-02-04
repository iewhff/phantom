# Top Tier Bug Bounty Guide - PetNTester AI v3.1

## Overview

This guide explains how to use PetNTester AI to find **high-value vulnerabilities** ($1,000-$50,000+) ethically and professionally.

---

## What Changed in v3.1 (Top Tier Edition)

| Feature | Purpose | Bounty Impact |
|---------|---------|---------------|
| **Headless Browser Engine** | Real DOM XSS detection | Confirms XSS with 0 false positives |
| **DOM XSS Scanner** | JavaScript execution testing | DOM XSS pays $500-$5,000 |
| **API Logic Profiler** | Role-based response comparison | IDOR/BAC pays $3,000-$20,000+ |
| **Auth Flow Analyzer** | OAuth/SAML/MFA analysis | Auth bugs pay $5,000-$50,000 |
| **Response Diff Visualizer** | Visual role comparison | Better reports = faster triage |

---

## Installation

```bash
# Base installation
pip install -e .

# For top tier features (headless browser)
pip install -e ".[browser]"
playwright install chromium
```

---

## The Top Tier Bounty Workflow

### Phase 1: Smart Reconnaissance

```python
# Don't scan everything. Be strategic.
pentest scan target.com --mode safe --modules recon,tech_detection,crawler
```

**What to look for:**
- `/api/` endpoints (REST, GraphQL)
- `/internal/`, `/admin/`, `/manage/` paths
- Multi-tenant indicators (`/org/{id}/`, `/tenant/{id}/`)
- ID patterns in URLs (numeric, UUID, ObjectId)

### Phase 2: Map the Attack Surface

Focus on these HIGH-VALUE endpoints:

| Endpoint Pattern | Why It's Valuable |
|------------------|-------------------|
| `/api/users/{id}` | IDOR candidate |
| `/api/organizations/{id}/*` | Multi-tenant isolation |
| `/api/admin/*` | Privilege escalation |
| `/api/export`, `/api/reports` | Data exfiltration |
| `/api/billing`, `/api/payments` | Financial impact |
| `/webhooks/*` | SSRF + data leaks |
| `/graphql` | Introspection + BAC |

### Phase 3: Role-Based Testing (THIS IS WHERE MONEY IS)

```python
from scanning.modules.api_logic_profiler import APILogicProfiler, RoleConfig, quick_role_comparison

# Configure different roles
roles = [
    {
        "name": "unauthenticated",
        "headers": {}
    },
    {
        "name": "user_a",
        "headers": {"Authorization": "Bearer token_user_a"}
    },
    {
        "name": "user_b",
        "headers": {"Authorization": "Bearer token_user_b"}
    },
    {
        "name": "admin",
        "headers": {"Authorization": "Bearer token_admin"}
    }
]

# Compare responses
result = await quick_role_comparison(
    "https://target.com/api/users/123",
    roles
)

# Check for differences
for diff in result["diffs"]:
    if diff["severity"] in ["CRITICAL", "HIGH"]:
        print(f"POTENTIAL BUG: {diff['description']}")
```

**What to look for:**
- User A can see User B's data (IDOR)
- Regular user gets admin fields (Data Leakage)
- Status 200 where 403 expected (BAC bypass)
- Different array lengths (Data Enumeration)

### Phase 4: DOM XSS Testing (Real Execution)

```python
from utils.headless_browser import create_browser, quick_dom_xss_test

# Quick test
results = await quick_dom_xss_test("https://target.com/search?q=test")

# Detailed test with auth flow analysis
async with create_browser() as browser:
    # Test DOM XSS
    xss_results = await browser.test_dom_xss(
        "https://target.com/dashboard",
        injection_points=["q", "redirect", "callback"]
    )

    # Analyze auth flow
    auth_result = await browser.analyze_auth_flow(
        "https://target.com/login"
    )

    # Check for token issues
    for vuln in auth_result.vulnerabilities:
        print(f"Auth Issue: {vuln['type']} - {vuln['description']}")
```

### Phase 5: Business Logic Testing

```bash
# Full business logic scan
pentest scan target.com --modules business_logic_scanner,api_logic_profiler

# Focus on race conditions
pentest scan target.com/api/transfer --modules business_logic_scanner --aggressive
```

**High-value business logic bugs:**
- Race conditions in payments
- State manipulation (draft → approved)
- Negative value attacks
- Idempotency key abuse
- Coupon/discount stacking

---

## Vulnerability to Payout Guide

| Vulnerability | Typical Payout | Detection Method |
|---------------|----------------|------------------|
| Reflected XSS | $100-500 | `xss_scanner` |
| **DOM XSS (Confirmed)** | **$500-5,000** | **`dom_xss_scanner`** |
| Info Disclosure | $100-500 | `api_scanner` |
| **IDOR** | **$1,000-10,000** | **`api_logic_profiler`** |
| **Broken Access Control** | **$2,000-15,000** | **`api_logic_profiler`** |
| **Auth Bypass** | **$5,000-50,000** | **`auth_scanner` + headless** |
| **Multi-tenant Isolation** | **$10,000-50,000+** | **`api_logic_profiler`** |
| Race Condition | $1,000-5,000 | `business_logic_scanner` |
| **Account Takeover Chain** | **$10,000-100,000** | **Multiple scanners** |

---

## How to Write a $10,000 Report

### Bad Report (Gets triaged as P4/Low)

```
Title: IDOR in user endpoint

I found IDOR in /api/users/123. By changing 123 to 124 I can see other user data.

Steps:
1. Go to /api/users/123
2. Change to /api/users/124
3. See other user data
```

### Good Report (Gets triaged as P1/Critical)

```
Title: Cross-Tenant Data Access via IDOR in User API - Full Account Data Exposure

## Summary
A Broken Object Level Authorization (BOLA) vulnerability in the `/api/v2/users/{id}`
endpoint allows any authenticated user to access complete profile data of any other
user across all tenants, including PII, payment methods, and internal identifiers.

## Impact
- **Data Exposed**: Full name, email, phone, address, payment_method_id, internal_user_id
- **Scope**: All 50,000+ users across all organizations
- **Regulatory**: GDPR Article 32 violation, potential $20M+ fine exposure
- **Business**: Complete customer database exfiltration possible

## Proof of Concept

### Setup
- User A (Org: Acme Corp): ID 12345, Token: `eyJ...A`
- User B (Org: Other Inc): ID 67890

### Request
```http
GET /api/v2/users/67890 HTTP/1.1
Host: api.target.com
Authorization: Bearer eyJ...A
```

### Response (User B's data exposed to User A)
```json
{
  "id": 67890,
  "email": "victim@other.com",
  "phone": "+1-555-0199",
  "address": "123 Secret St",
  "payment_method_id": "pm_live_xxx",
  "organization_id": 999,  // Different org!
  "internal_user_id": "usr_internal_67890"
}
```

## Attack Scenario
1. Attacker creates account in Organization A
2. Enumerates user IDs (sequential: 1, 2, 3... or predictable pattern)
3. Exfiltrates all user data across all organizations
4. Sells data / uses for targeted phishing

## Remediation
1. Implement object-level authorization check:
   ```python
   if user.organization_id != current_user.organization_id:
       raise PermissionDenied()
   ```
2. Use non-sequential, unpredictable IDs (UUID v4)
3. Add rate limiting on user endpoints

## References
- OWASP API1:2023 - Broken Object Level Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key
```

---

## Ethical Guidelines

### Always

- Stay within scope
- Respect rate limits (PetNTester does this automatically)
- Report vulnerabilities, don't exploit them
- Protect any data you access
- Follow responsible disclosure

### Never

- Access data beyond proving the vulnerability
- Test production systems without authorization
- Share vulnerabilities before they're fixed
- Use automated tools on systems that prohibit them
- Cause service disruption

---

## Quick Reference Commands

```bash
# Safe reconnaissance
pentest scan target.com --mode safe

# Full API security scan with role comparison
pentest scan target.com --modules api_logic_profiler,authorization_engine

# DOM XSS with headless browser
pentest scan target.com --modules dom_xss_scanner

# Business logic focus
pentest scan target.com --modules business_logic_scanner

# Generate HackerOne-ready report
pentest report --format hackerone --output report.md
```

---

## Files Added in v3.1

| File | Purpose |
|------|---------|
| `utils/headless_browser.py` | Playwright-based browser engine |
| `scanning/modules/dom_xss_scanner.py` | Real DOM XSS detection |
| `scanning/modules/api_logic_profiler.py` | Role-based response analysis |
| `tests/scanning/test_dom_xss_scanner.py` | Tests for DOM XSS |
| `tests/scanning/test_api_logic_profiler.py` | Tests for API profiler |

---

## Summary

**Stop scanning everything. Start hunting strategically.**

1. Use recon to find interesting endpoints
2. Use `api_logic_profiler` to compare roles
3. Use `dom_xss_scanner` for confirmed XSS
4. Use `auth_scanner` + headless for auth flows
5. Write professional reports

The difference between $100 and $10,000 is not the vulnerability - it's how you find it, prove it, and report it.

---

*PetNTester AI v3.1 - Top Tier Bounty Edition*
*Always hunt ethically. Always report responsibly.*
