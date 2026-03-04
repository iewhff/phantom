#!/usr/bin/env python3
"""
Attack Chain Demo - Demonstrates the Attack Chain Engine capabilities.
Run this script to see a full demo of attack chain analysis and visualization.
"""

import asyncio
import sys
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis import AttackChainEngine, ChainVisualizer, AttackChainDashboard


# Sample findings simulating real scan results
SAMPLE_FINDINGS = [
    # Reconnaissance Phase
    {
        "name": "Subdomain Enumeration - Dangling DNS",
        "severity": "HIGH",
        "cvss": 7.5,
        "cwe": "CWE-284",
        "owasp": "A05:2021",
        "description": "Subdomain pointing to unclaimed cloud resource allowing takeover",
        "matched_at": "https://dev.example.com",
        "evidence": ["CNAME record pointing to unclaimed S3 bucket: dev.s3.amazonaws.com"],
    },
    {
        "name": "GraphQL Introspection Enabled",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cwe": "CWE-200",
        "owasp": "A01:2021",
        "description": "GraphQL introspection exposes entire API schema",
        "matched_at": "https://api.example.com/graphql",
        "evidence": ["Full schema with 127 types and 89 queries exposed"],
    },

    # Initial Access Phase
    {
        "name": "JWT Algorithm Confusion - None Algorithm",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "cwe": "CWE-327",
        "owasp": "A02:2021",
        "description": "Server accepts JWT tokens with 'none' algorithm",
        "matched_at": "https://api.example.com/auth/verify",
        "evidence": ["Modified JWT accepted: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0..."],
    },
    {
        "name": "OAuth PKCE Bypass",
        "severity": "HIGH",
        "cvss": 8.1,
        "cwe": "CWE-287",
        "owasp": "A07:2021",
        "description": "OAuth flow accepts tokens without PKCE validation",
        "matched_at": "https://api.example.com/oauth/token",
        "evidence": ["Token issued without code_verifier parameter"],
    },

    # Execution Phase
    {
        "name": "SQL Injection - Union Based",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "description": "Union-based SQL injection allows database extraction",
        "matched_at": "https://api.example.com/products?id=1",
        "evidence": ["Payload: ' UNION SELECT 1,2,@@version--", "MySQL 8.0.28 detected"],
    },
    {
        "name": "Server-Side Template Injection (SSTI)",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cwe": "CWE-94",
        "owasp": "A03:2021",
        "description": "Jinja2 template injection leads to RCE",
        "matched_at": "https://api.example.com/render",
        "evidence": ["Payload: {{7*7}} rendered as 49", "OS command execution confirmed"],
    },

    # Privilege Escalation Phase
    {
        "name": "IDOR - User Profile Access",
        "severity": "HIGH",
        "cvss": 7.5,
        "cwe": "CWE-639",
        "owasp": "A01:2021",
        "description": "Can access any user profile by modifying ID parameter",
        "matched_at": "https://api.example.com/users/123",
        "evidence": ["Changed /users/123 to /users/1 (admin) - success"],
    },
    {
        "name": "Broken Function Level Authorization",
        "severity": "HIGH",
        "cvss": 7.2,
        "cwe": "CWE-285",
        "owasp": "A01:2021",
        "description": "Admin endpoints accessible to regular users",
        "matched_at": "https://api.example.com/admin/users",
        "evidence": ["Regular user token accepted on admin endpoint"],
    },

    # Credential Access Phase
    {
        "name": "Hardcoded API Key in Response",
        "severity": "HIGH",
        "cvss": 7.5,
        "cwe": "CWE-798",
        "owasp": "A02:2021",
        "description": "AWS API key exposed in API response",
        "matched_at": "https://api.example.com/config",
        "evidence": ["AKIA5XYZ... found in response body"],
    },
    {
        "name": "Session Token in URL",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cwe": "CWE-598",
        "owasp": "A02:2021",
        "description": "Session tokens passed in URL, exposed in logs/referrer",
        "matched_at": "https://app.example.com/dashboard?token=abc123",
        "evidence": ["Token visible in URL parameters"],
    },

    # Lateral Movement Phase
    {
        "name": "SSRF to Cloud Metadata",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "cwe": "CWE-918",
        "owasp": "A10:2021",
        "description": "SSRF allows access to cloud metadata service",
        "matched_at": "https://api.example.com/fetch?url=",
        "evidence": ["http://169.254.169.254/latest/meta-data/", "IAM credentials retrieved"],
    },
    {
        "name": "Kubernetes API Exposed",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cwe": "CWE-284",
        "owasp": "A01:2021",
        "description": "Kubernetes API server accessible without authentication",
        "matched_at": "https://k8s.example.com:6443/api/v1/pods",
        "evidence": ["Listed all pods in cluster", "Service account tokens exposed"],
    },

    # Collection Phase
    {
        "name": "Mass Assignment - PII Exposure",
        "severity": "HIGH",
        "cvss": 7.5,
        "cwe": "CWE-915",
        "owasp": "A04:2021",
        "description": "API returns all user fields including sensitive PII",
        "matched_at": "https://api.example.com/users/me",
        "evidence": ["SSN, credit card numbers, addresses in response"],
    },
    {
        "name": "Path Traversal to Config Files",
        "severity": "HIGH",
        "cvss": 7.5,
        "cwe": "CWE-22",
        "owasp": "A01:2021",
        "description": "Path traversal allows reading sensitive configuration",
        "matched_at": "https://api.example.com/download?file=../../../etc/passwd",
        "evidence": ["Successfully read /etc/passwd", "Database credentials in .env"],
    },

    # Defense Evasion
    {
        "name": "WAF Bypass via HTTP Parameter Pollution",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cwe": "CWE-235",
        "owasp": "A05:2021",
        "description": "WAF rules bypassed using parameter pollution",
        "matched_at": "https://api.example.com/search?q=test&q=<script>",
        "evidence": ["XSS payload bypassed WAF"],
    },
    {
        "name": "Rate Limit Bypass",
        "severity": "MEDIUM",
        "cvss": 5.0,
        "cwe": "CWE-770",
        "owasp": "A04:2021",
        "description": "Rate limiting bypassed via header manipulation",
        "matched_at": "https://api.example.com/login",
        "evidence": ["X-Forwarded-For rotation bypasses rate limit"],
    },

    # Impact Phase
    {
        "name": "Account Takeover Chain",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cwe": "CWE-287",
        "owasp": "A07:2021",
        "description": "Complete account takeover possible via password reset flaw",
        "matched_at": "https://api.example.com/reset-password",
        "evidence": ["Reset token predictable", "No email verification"],
    },
]


async def run_demo():
    """Run the attack chain analysis demo."""
    print("""
====================================================================
              ATTACK CHAIN ENGINE DEMO
====================================================================
    """)

    output_dir = Path("reports/demo")
    output_dir.mkdir(parents=True, exist_ok=True)

    engine = AttackChainEngine()
    visualizer = ChainVisualizer()

    # Analyze findings
    print("[1/4] Analyzing vulnerabilities...")
    chains = await engine.analyze_findings(SAMPLE_FINDINGS)
    print(f"       Found {len(chains)} attack chains")

    # Show ASCII report preview
    print("\n[2/4] Generating ASCII visualization...")
    for i, chain in enumerate(chains[:3], 1):
        print(f"\n[Chain {i}/{len(chains)}]")
        print(visualizer.generate_ascii(chain))
        print("-" * 70)

    if len(chains) > 3:
        print(f"\n       ... and {len(chains) - 3} more chains")

    # Executive summary
    print("\n[3/4] Executive summary...")
    summary = engine.get_executive_summary()
    print(f"  Total chains: {summary['total_chains']}")
    print(f"  Critical: {summary['critical_chains']}")
    print(f"  High priority: {summary['high_priority_chains']}")

    # Save reports
    print("\n[4/4] Saving reports...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # HTML report
    html_path = output_dir / f"demo_{timestamp}_report.html"
    html_path.write_text(visualizer.generate_html_report(chains, "example.com"), encoding="utf-8")
    print(f"  HTML report: {html_path}")

    # Dashboard
    dashboard = AttackChainDashboard()
    dashboard.set_data(chains, SAMPLE_FINDINGS)
    dash_path = output_dir / f"demo_{timestamp}_dashboard.html"
    dash_path.write_text(dashboard.generate_dashboard("example.com"), encoding="utf-8")
    print(f"  Dashboard:   {dash_path}")

    # JSON
    json_path = output_dir / f"demo_{timestamp}.json"
    json_path.write_text(visualizer.generate_json(chains), encoding="utf-8")
    print(f"  JSON export: {json_path}")

    print("\n  Open the HTML files in your browser to see interactive visualizations.")


if __name__ == "__main__":
    asyncio.run(run_demo())
