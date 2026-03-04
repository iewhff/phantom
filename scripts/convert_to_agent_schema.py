#!/usr/bin/env python3
"""
PHANTOM Output to Agent Schema Converter

Converts PHANTOM scan JSON output to the agent-compatible schema format.

Usage:
    python scripts/convert_to_agent_schema.py reports/phantom_scan.json -o agent_input.json
    python scripts/convert_to_agent_schema.py reports/phantom_scan.json  # prints to stdout
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Any


def convert_phantom_to_agent_schema(phantom_data: dict) -> dict:
    """Convert PHANTOM output to agent schema format."""

    # Extract target
    target_url = phantom_data.get("target", "")
    target = {
        "url": target_url,
        "domain": phantom_data.get("domain", "")
    }

    # Extract stack/technologies
    tech_data = phantom_data.get("technologies", {})
    stack = extract_stack(tech_data)

    # Convert findings
    findings = convert_findings(phantom_data.get("findings", []))

    # Add missing headers as finding if present in technologies
    headers_finding = extract_headers_finding(tech_data, target_url)
    if headers_finding:
        findings.insert(0, headers_finding)

    # Re-number findings
    for idx, finding in enumerate(findings, 1):
        finding["id"] = f"FIND-{idx:03d}"

    return {
        "target": target,
        "stack": stack,
        "findings": findings
    }


def extract_headers_finding(tech_data: dict, target_url: str) -> dict | None:
    """Extract missing security headers as a finding."""

    if not tech_data:
        return None

    security_headers = tech_data.get("security_headers", {})
    if not security_headers:
        return None

    missing = []
    present = []

    header_names = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Content-Type-Options": "X-Content-Type-Options",
        "X-Frame-Options": "X-Frame-Options",
        "X-XSS-Protection": "X-XSS-Protection",
        "Referrer-Policy": "Referrer-Policy",
        "Permissions-Policy": "Permissions-Policy",
    }

    for header, short_name in header_names.items():
        if security_headers.get(header) is True:
            present.append(short_name)
        else:
            missing.append(short_name)

    if not missing:
        return None

    # Determine severity based on what's missing
    severity = "LOW"
    critical_headers = ["HSTS", "CSP"]
    if any(h in missing for h in critical_headers):
        severity = "MEDIUM"

    evidence = [f"Missing: {h}" for h in missing]
    if present:
        evidence.append(f"Present: {', '.join(present)}")

    return {
        "id": "FIND-001",
        "category": "headers",
        "type": "missing_headers",
        "name": "Missing Security Headers",
        "severity": severity,
        "cwe": "CWE-693",
        "location": {
            "url": target_url,
            "endpoint": "/",
            "parameter": None,
            "method": "GET"
        },
        "evidence": evidence,
        "technical_details": {
            "missing_headers": missing,
            "present_headers": present
        },
        "poc": {
            "command": f'curl -I "{target_url}"',
            "response": f"Headers missing: {', '.join(missing)}"
        }
    }


def extract_stack(tech_data: dict) -> dict:
    """Extract stack information from PHANTOM technologies."""

    stack = {
        "technologies": [],
        "framework": None,
        "webserver": None,
        "cdn_waf": None,
        "cms": None
    }

    if not tech_data:
        return stack

    technologies = tech_data.get("technologies", [])

    for tech in technologies:
        name = tech.get("name", "")
        version = tech.get("version")
        category = tech.get("category", "").upper()

        # Add to technologies list with version if available
        if version and version != ".":
            stack["technologies"].append(f"{name}:{version}")
        else:
            stack["technologies"].append(name)

        # Categorize
        if category in ("JAVASCRIPT_FRAMEWORK", "FRAMEWORK"):
            if not stack["framework"]:
                # Normalize framework name
                framework_map = {
                    "next.js": "nextjs",
                    "react": "react",
                    "vue.js": "vue",
                    "vue": "vue",
                    "angular": "angular",
                    "nuxt.js": "nuxt",
                    "nuxt": "nuxt",
                    "express": "express",
                    "fastify": "fastify",
                    "django": "django",
                    "flask": "flask",
                    "laravel": "laravel",
                    "rails": "rails",
                    "spring": "spring",
                }
                stack["framework"] = framework_map.get(name.lower(), name.lower())

        elif category == "SERVER":
            if not stack["webserver"]:
                # Normalize webserver name
                webserver_map = {
                    "nginx": "nginx",
                    "apache": "apache",
                    "iis": "iis",
                    "caddy": "caddy",
                    "lighttpd": "lighttpd",
                }
                stack["webserver"] = webserver_map.get(name.lower(), name.lower())

        elif category in ("CDN", "WAF", "SECURITY"):
            if not stack["cdn_waf"]:
                stack["cdn_waf"] = name.lower()

        elif category == "CMS":
            if not stack["cms"]:
                stack["cms"] = name.lower()

    # Check WAF from separate field
    waf_data = tech_data.get("waf_detected")
    if waf_data and not stack["cdn_waf"]:
        stack["cdn_waf"] = waf_data

    # Check CDN from separate field
    cdn_data = tech_data.get("cdn_detected")
    if cdn_data and not stack["cdn_waf"]:
        stack["cdn_waf"] = cdn_data

    return stack


def convert_findings(findings: list) -> list:
    """Convert PHANTOM findings to agent schema format."""

    converted = []

    for idx, finding in enumerate(findings, 1):
        converted_finding = convert_single_finding(finding, idx)
        if converted_finding:
            converted.append(converted_finding)

    return converted


def convert_single_finding(finding: dict, idx: int) -> dict:
    """Convert a single PHANTOM finding to agent schema."""

    # Map PHANTOM vuln types to agent types
    type_mapping = {
        # Headers
        "missing_security_headers": "missing_headers",
        "security_headers": "missing_headers",
        "header_security": "missing_headers",

        # Injection
        "sql_injection": "sqli_error_based",
        "sqli": "sqli_error_based",
        "blind_sqli": "sqli_blind",
        "xss": "xss_reflected",
        "reflected_xss": "xss_reflected",
        "stored_xss": "xss_stored",
        "dom_xss": "xss_reflected",

        # Access Control
        "idor": "idor",
        "broken_access_control": "idor",
        "authorization": "idor",
        "rls_bypass": "rls_bypass",

        # Auth
        "rate_limit": "no_rate_limit",
        "no_rate_limiting": "no_rate_limit",
        "brute_force": "no_rate_limit",
        "user_enumeration": "user_enumeration",
        "weak_password": "weak_password",

        # CORS
        "cors": "cors_misconfigured",
        "cors_misconfiguration": "cors_misconfigured",

        # Config
        "directory_listing": "directory_listing",
        "information_disclosure": "sensitive_data_exposed",
        "info_disclosure": "sensitive_data_exposed",

        # JWT
        "jwt": "jwt_weak",
        "jwt_vulnerability": "jwt_weak",

        # Libraries
        "outdated_software": "outdated_library",
        "vulnerable_component": "outdated_library",
    }

    # Category mapping
    category_mapping = {
        "missing_headers": "headers",
        "sqli_error_based": "injection",
        "sqli_blind": "injection",
        "xss_reflected": "injection",
        "xss_stored": "injection",
        "idor": "access_control",
        "rls_bypass": "access_control",
        "no_rate_limit": "auth",
        "user_enumeration": "auth",
        "weak_password": "auth",
        "cors_misconfigured": "config",
        "directory_listing": "config",
        "sensitive_data_exposed": "info_disclosure",
        "jwt_weak": "crypto",
        "outdated_library": "config",
    }

    # Get finding type
    phantom_type = finding.get("type", finding.get("vuln_type", "")).lower().replace(" ", "_").replace("-", "_")
    agent_type = type_mapping.get(phantom_type, phantom_type)
    category = category_mapping.get(agent_type, "config")

    # Get location
    url = finding.get("url", finding.get("matched_at", ""))
    if not url:
        metadata = finding.get("metadata", {})
        url = metadata.get("url", metadata.get("endpoint", ""))

    endpoint = extract_endpoint(url)
    parameter = finding.get("parameter", finding.get("param"))
    method = finding.get("method", finding.get("http_method", "GET"))

    # Get evidence
    evidence = extract_evidence(finding)

    # Get technical details
    technical_details = extract_technical_details(finding, agent_type)

    # Get POC
    poc = extract_poc(finding)

    # Get CWE
    cwe = finding.get("cwe", finding.get("cwe_id"))
    if cwe and not cwe.startswith("CWE-"):
        cwe = f"CWE-{cwe}"

    return {
        "id": f"FIND-{idx:03d}",
        "category": category,
        "type": agent_type,
        "name": finding.get("name", finding.get("title", f"Finding {idx}")),
        "severity": finding.get("severity", "MEDIUM").upper(),
        "cwe": cwe,
        "location": {
            "url": url,
            "endpoint": endpoint,
            "parameter": parameter,
            "method": method
        },
        "evidence": evidence,
        "technical_details": technical_details,
        "poc": poc
    }


def extract_endpoint(url: str) -> str:
    """Extract endpoint path from URL."""
    if not url:
        return "/"

    from urllib.parse import urlparse
    parsed = urlparse(url)
    endpoint = parsed.path or "/"

    if parsed.query:
        endpoint += f"?{parsed.query}"

    return endpoint


def extract_evidence(finding: dict) -> list:
    """Extract evidence from PHANTOM finding."""

    evidence = []

    # Direct evidence field
    if "evidence" in finding:
        ev = finding["evidence"]
        if isinstance(ev, list):
            evidence.extend(ev)
        elif isinstance(ev, str):
            evidence.append(ev)
        elif isinstance(ev, dict):
            # Extract relevant fields from evidence dict
            for key in ["response", "data", "body", "headers", "value"]:
                if key in ev:
                    evidence.append(str(ev[key])[:500])

    # Proof field
    if "proof" in finding:
        proof = finding["proof"]
        if isinstance(proof, dict):
            if "response" in proof:
                evidence.append(proof["response"][:500])
            if "data_extracted" in proof:
                evidence.extend(proof["data_extracted"][:5])

    # Metadata
    metadata = finding.get("metadata", {})
    if "evidence" in metadata:
        ev = metadata["evidence"]
        if isinstance(ev, list):
            evidence.extend(ev[:5])
        elif isinstance(ev, str):
            evidence.append(ev)

    # Description as fallback
    if not evidence:
        desc = finding.get("description", "")
        if desc:
            evidence.append(desc)

    return evidence[:10]  # Limit to 10 items


def extract_technical_details(finding: dict, agent_type: str) -> dict:
    """Extract technical details based on finding type."""

    details = {}
    metadata = finding.get("metadata", {})

    if agent_type == "missing_headers":
        # Extract missing/present headers
        missing = []
        present = []

        if "missing_headers" in metadata:
            missing = metadata["missing_headers"]
        if "present_headers" in metadata:
            present = metadata["present_headers"]

        # Try to extract from evidence
        evidence = finding.get("evidence", {})
        if isinstance(evidence, dict):
            for header, value in evidence.items():
                if value in (False, None, "missing", "not present"):
                    missing.append(header)
                elif value:
                    present.append(header)

        details = {
            "missing_headers": missing,
            "present_headers": present
        }

    elif agent_type in ("sqli_error_based", "sqli_blind"):
        details = {
            "injection_type": "error_based" if "error" in agent_type else "blind",
            "database": metadata.get("database", metadata.get("db_type", "Unknown")),
            "vulnerable_param": finding.get("parameter", metadata.get("param"))
        }

    elif agent_type == "rls_bypass":
        details = {
            "table": metadata.get("table", metadata.get("resource")),
            "records_exposed": metadata.get("records_count", metadata.get("count", 0)),
            "fields_exposed": metadata.get("fields", metadata.get("columns", [])),
            "ownership_column": metadata.get("ownership_column", "user_id")
        }

    elif agent_type == "no_rate_limit":
        details = {
            "requests_tested": metadata.get("requests_sent", metadata.get("attempts", 50)),
            "blocked_at": metadata.get("blocked_at"),
            "endpoint_type": metadata.get("endpoint_type", "unknown")
        }

    elif agent_type == "idor":
        details = {
            "resource_type": metadata.get("resource_type", "unknown"),
            "attacker_id": metadata.get("attacker_id"),
            "victim_id": metadata.get("victim_id"),
            "data_accessed": metadata.get("data_accessed", [])
        }

    elif agent_type == "outdated_library":
        details = {
            "library": metadata.get("library", metadata.get("component")),
            "current_version": metadata.get("version", metadata.get("current_version")),
            "vulnerable_to": metadata.get("cves", metadata.get("vulnerabilities", [])),
            "fixed_version": metadata.get("fixed_version", metadata.get("patched_version"))
        }

    elif agent_type == "cors_misconfigured":
        details = {
            "allows_origin": metadata.get("acao", metadata.get("access_control_allow_origin")),
            "allows_credentials": metadata.get("acac", metadata.get("access_control_allow_credentials")),
            "tested_origin": metadata.get("tested_origin", "https://evil.com")
        }

    else:
        # Generic - copy relevant metadata
        for key in ["database", "table", "param", "method", "payload", "response_code"]:
            if key in metadata:
                details[key] = metadata[key]

    return details


def extract_poc(finding: dict) -> dict:
    """Extract POC command and response."""

    poc = {
        "command": "",
        "response": ""
    }

    # Direct POC field
    if "poc" in finding:
        poc_data = finding["poc"]
        if isinstance(poc_data, dict):
            poc["command"] = poc_data.get("command", poc_data.get("request", ""))
            poc["response"] = poc_data.get("response", poc_data.get("output", ""))
        elif isinstance(poc_data, str):
            poc["command"] = poc_data

    # Proof field
    if "proof" in finding:
        proof = finding["proof"]
        if isinstance(proof, dict):
            if not poc["command"] and "request" in proof:
                poc["command"] = proof["request"]
            if not poc["response"] and "response" in proof:
                poc["response"] = proof["response"]

    # Evidence field
    if "evidence" in finding and isinstance(finding["evidence"], dict):
        ev = finding["evidence"]
        if not poc["command"] and "request" in ev:
            poc["command"] = ev["request"]
        if not poc["response"] and "response" in ev:
            poc["response"] = ev["response"]

    # Metadata
    metadata = finding.get("metadata", {})
    if not poc["command"]:
        url = finding.get("url", metadata.get("url", ""))
        method = finding.get("method", "GET")
        if url:
            poc["command"] = f'curl -X {method} "{url}"'

    if not poc["response"]:
        poc["response"] = finding.get("description", "See evidence above")

    # Truncate long responses
    if len(poc["response"]) > 1000:
        poc["response"] = poc["response"][:1000] + "..."

    return poc


def main():
    parser = argparse.ArgumentParser(
        description="Convert PHANTOM scan output to agent schema format"
    )
    parser.add_argument("input", help="Input PHANTOM JSON file")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    parser.add_argument("--pretty", action="store_true", default=True,
                       help="Pretty print JSON (default: True)")

    args = parser.parse_args()

    # Read input
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: File not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(input_path) as f:
        phantom_data = json.load(f)

    # Convert
    agent_data = convert_phantom_to_agent_schema(phantom_data)

    # Output
    indent = 2 if args.pretty else None
    output_json = json.dumps(agent_data, indent=indent, ensure_ascii=False)

    if args.output:
        output_path = Path(args.output)
        output_path.write_text(output_json)
        print(f"Converted output saved to: {args.output}")
    else:
        print(output_json)


if __name__ == "__main__":
    main()
