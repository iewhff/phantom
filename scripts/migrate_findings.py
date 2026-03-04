#!/usr/bin/env python3
"""
Migration script to convert scanner modules to unified Finding class.

This script handles:
1. Import statement updates
2. Parameter renaming (matched_at -> endpoint, confidence -> confidence_score, cwe -> cwe_id)
3. Severity string to enum conversion
4. Adding scanner name to each finding
"""

import re
import sys
from pathlib import Path

# Scanner to VulnType mapping
SCANNER_VULN_TYPES = {
    "deserialization_scanner": ("VulnType.DESERIALIZATION", "VulnCategory.INJECTION"),
    "dns_rebinding_scanner": ("VulnType.DNS_REBINDING", "VulnCategory.INFRASTRUCTURE"),
    "crlf_scanner": ("VulnType.CRLF", "VulnCategory.INJECTION"),
    "cache_poisoning_scanner": ("VulnType.CACHE_POISONING", "VulnCategory.SERVER_SIDE"),
    "prototype_pollution_scanner": ("VulnType.PROTOTYPE_POLLUTION", "VulnCategory.CLIENT_SIDE"),
    "smuggling_scanner": ("VulnType.HTTP_SMUGGLING", "VulnCategory.SERVER_SIDE"),
    "open_redirect_scanner": ("VulnType.OPEN_REDIRECT", "VulnCategory.CLIENT_SIDE"),
    "race_condition_scanner": ("VulnType.RACE_CONDITION", "VulnCategory.BUSINESS_LOGIC"),
    "cookie_security_scanner": ("VulnType.COOKIE_SECURITY", "VulnCategory.CONFIGURATION"),
    "dom_xss_scanner": ("VulnType.XSS_DOM", "VulnCategory.CLIENT_SIDE"),
    "ldap_xpath_scanner": ("VulnType.LDAP_INJECTION", "VulnCategory.INJECTION"),
    "mfa_bypass_scanner": ("VulnType.MFA_BYPASS", "VulnCategory.AUTHENTICATION"),
    "api_scanner": ("VulnType.OTHER", "VulnCategory.API"),
    "graphql_advanced_scanner": ("VulnType.GRAPHQL_INTROSPECTION", "VulnCategory.API"),
    "sse_scanner": ("VulnType.OTHER", "VulnCategory.API"),
    "llm_security_scanner": ("VulnType.OTHER", "VulnCategory.API"),
    "cloud_scanner": ("VulnType.CLOUD_MISCONFIGURATION", "VulnCategory.INFRASTRUCTURE"),
    "websocket_scanner": ("VulnType.WEBSOCKET_VULNERABILITY", "VulnCategory.API"),
    "session_abuse_scanner": ("VulnType.INSECURE_SESSION", "VulnCategory.SESSION"),
    "authorization_engine": ("VulnType.BOLA", "VulnCategory.AUTHORIZATION"),
    "creative_exploiter": ("VulnType.OTHER", "VulnCategory.UNKNOWN"),
    "saml_scanner": ("VulnType.SAML_VULNERABILITY", "VulnCategory.AUTHENTICATION"),
    "oauth_scanner": ("VulnType.OAUTH_MISCONFIGURATION", "VulnCategory.AUTHENTICATION"),
    "dir_scanner": ("VulnType.DIRECTORY_LISTING", "VulnCategory.DISCLOSURE"),
    "mobile_api_scanner": ("VulnType.OTHER", "VulnCategory.API"),
    "nuclei_runner": ("VulnType.OTHER", "VulnCategory.UNKNOWN"),
    "email_security_scanner": ("VulnType.OTHER", "VulnCategory.CONFIGURATION"),
    "kubernetes_scanner": ("VulnType.KUBERNETES_VULNERABILITY", "VulnCategory.INFRASTRUCTURE"),
    "subdomain_takeover_scanner": ("VulnType.SUBDOMAIN_TAKEOVER", "VulnCategory.INFRASTRUCTURE"),
    "post_exploitation": ("VulnType.OTHER", "VulnCategory.UNKNOWN"),
    "rate_limit_scanner": ("VulnType.RATE_LIMIT_BYPASS", "VulnCategory.BUSINESS_LOGIC"),
    "logic_chain_scanner": ("VulnType.LOGIC_FLAW", "VulnCategory.BUSINESS_LOGIC"),
    "cms_scanner": ("VulnType.OTHER", "VulnCategory.DISCLOSURE"),
    "grpc_scanner": ("VulnType.GRPC_VULNERABILITY", "VulnCategory.API"),
    "communications_api_scanner": ("VulnType.OTHER", "VulnCategory.API"),
    "business_logic_scanner": ("VulnType.LOGIC_FLAW", "VulnCategory.BUSINESS_LOGIC"),
    "mass_assignment_scanner": ("VulnType.MASS_ASSIGNMENT", "VulnCategory.AUTHORIZATION"),
    "api_logic_profiler": ("VulnType.IDOR", "VulnCategory.AUTHORIZATION"),
    "stateful_flow_scanner": ("VulnType.WORKFLOW_BYPASS", "VulnCategory.BUSINESS_LOGIC"),
    "config_exposure_scanner": ("VulnType.INFO_DISCLOSURE", "VulnCategory.DISCLOSURE"),
    "file_upload_scanner": ("VulnType.FILE_UPLOAD", "VulnCategory.SERVER_SIDE"),
    "cache_deception_scanner": ("VulnType.CACHE_DECEPTION", "VulnCategory.SERVER_SIDE"),
    "host_header_scanner": ("VulnType.HOST_HEADER_INJECTION", "VulnCategory.CONFIGURATION"),
    "info_disclosure_scanner": ("VulnType.INFO_DISCLOSURE", "VulnCategory.DISCLOSURE"),
    "auth_bypass_scanner": ("VulnType.AUTH_BYPASS", "VulnCategory.AUTHENTICATION"),
    "auth_session_scanner": ("VulnType.INSECURE_SESSION", "VulnCategory.SESSION"),
    "auth_oauth_scanner": ("VulnType.OAUTH_MISCONFIGURATION", "VulnCategory.AUTHENTICATION"),
    "auth_login_scanner": ("VulnType.DEFAULT_CREDENTIALS", "VulnCategory.AUTHENTICATION"),
    "auth_privesc_scanner": ("VulnType.PRIVILEGE_ESCALATION", "VulnCategory.AUTHORIZATION"),
    "auth_jwt_scanner": ("VulnType.JWT_VULNERABILITY", "VulnCategory.AUTHENTICATION"),
    "defensive_evasion_scanner": ("VulnType.OTHER", "VulnCategory.UNKNOWN"),
    "permission_matrix_scanner": ("VulnType.BFLA", "VulnCategory.AUTHORIZATION"),
    "abac_context_tester": ("VulnType.BFLA", "VulnCategory.AUTHORIZATION"),
    "webhook_security_scanner": ("VulnType.OTHER", "VulnCategory.API"),
    "wasm_scanner": ("VulnType.OTHER", "VulnCategory.CLIENT_SIDE"),
    "integration_exploiter": ("VulnType.OTHER", "VulnCategory.UNKNOWN"),
    "token_binding_validator": ("VulnType.INSECURE_SESSION", "VulnCategory.SESSION"),
    "secrets_pattern_scanner": ("VulnType.INFO_DISCLOSURE", "VulnCategory.DISCLOSURE"),
    "workflow_inference_engine": ("VulnType.WORKFLOW_BYPASS", "VulnCategory.BUSINESS_LOGIC"),
    "client_hardening_scanner": ("VulnType.OTHER", "VulnCategory.CLIENT_SIDE"),
    "concurrency_stress_scanner": ("VulnType.RACE_CONDITION", "VulnCategory.BUSINESS_LOGIC"),
    "concurrency_state_modeler": ("VulnType.RACE_CONDITION", "VulnCategory.BUSINESS_LOGIC"),
    "graphql_subscription_scanner": ("VulnType.GRAPHQL_INJECTION", "VulnCategory.API"),
    "rsc_scanner": ("VulnType.OTHER", "VulnCategory.API"),
    "edge_function_scanner": ("VulnType.OTHER", "VulnCategory.INFRASTRUCTURE"),
    "grpc_web_scanner": ("VulnType.GRPC_VULNERABILITY", "VulnCategory.API"),
    "http3_scanner": ("VulnType.OTHER", "VulnCategory.INFRASTRUCTURE"),
    "webtransport_scanner": ("VulnType.OTHER", "VulnCategory.API"),
    "webrtc_scanner": ("VulnType.OTHER", "VulnCategory.CLIENT_SIDE"),
    "crypto_weakness_scanner": ("VulnType.SSL_TLS_ISSUE", "VulnCategory.CRYPTOGRAPHY"),
    "bun_deno_fingerprinter": ("VulnType.OTHER", "VulnCategory.DISCLOSURE"),
    "wasm_backend_scanner": ("VulnType.OTHER", "VulnCategory.SERVER_SIDE"),
    "ai_prompt_scanner": ("VulnType.OTHER", "VulnCategory.INJECTION"),
}


def get_scanner_name(filepath: Path) -> str:
    """Extract scanner name from filepath."""
    return filepath.stem


def migrate_file(filepath: Path) -> bool:
    """Migrate a single scanner file to unified Finding."""

    content = filepath.read_text()

    # Skip if already migrated
    if "from scanning.findings import Finding" in content:
        print(f"  Already migrated: {filepath.name}")
        return False

    # Skip if not using Finding from vuln_scanner
    if "from scanning.vuln_scanner import" not in content or "Finding" not in content:
        print(f"  No Finding import: {filepath.name}")
        return False

    scanner_name = get_scanner_name(filepath)
    vuln_info = SCANNER_VULN_TYPES.get(scanner_name, ("VulnType.OTHER", "VulnCategory.UNKNOWN"))
    default_vuln_type, default_category = vuln_info

    # Short scanner name for Finding.scanner field
    short_scanner = scanner_name.replace("_scanner", "").replace("_", "_")

    original = content

    # 1. Update import statement
    # Handle various import patterns
    content = re.sub(
        r'from scanning\.vuln_scanner import Finding, ScanModule',
        'from scanning.findings import Finding, VulnType, VulnCategory, Severity\nfrom scanning.vuln_scanner import ScanModule',
        content
    )
    content = re.sub(
        r'from scanning\.vuln_scanner import ScanModule, Finding',
        'from scanning.findings import Finding, VulnType, VulnCategory, Severity\nfrom scanning.vuln_scanner import ScanModule',
        content
    )
    content = re.sub(
        r'from scanning\.vuln_scanner import Finding',
        'from scanning.findings import Finding, VulnType, VulnCategory, Severity',
        content
    )

    # 2. Replace severity strings with enums
    content = re.sub(r'severity="CRITICAL"', 'severity=Severity.CRITICAL', content)
    content = re.sub(r'severity="HIGH"', 'severity=Severity.HIGH', content)
    content = re.sub(r'severity="MEDIUM"', 'severity=Severity.MEDIUM', content)
    content = re.sub(r'severity="LOW"', 'severity=Severity.LOW', content)
    content = re.sub(r'severity="INFO"', 'severity=Severity.INFO', content)

    # Also handle lowercase/mixed case
    content = re.sub(r"severity='CRITICAL'", 'severity=Severity.CRITICAL', content)
    content = re.sub(r"severity='HIGH'", 'severity=Severity.HIGH', content)
    content = re.sub(r"severity='MEDIUM'", 'severity=Severity.MEDIUM', content)
    content = re.sub(r"severity='LOW'", 'severity=Severity.LOW', content)
    content = re.sub(r"severity='INFO'", 'severity=Severity.INFO', content)

    # 3. Rename parameters
    content = re.sub(r'\bmatched_at=', 'endpoint=', content)
    content = re.sub(r'\bconfidence=', 'confidence_score=', content)
    content = re.sub(r'\bcwe=(["\'])', r'cwe_id=\1', content)

    # 4. Fix attribute accesses
    content = re.sub(r'\.matched_at\b', '.endpoint', content)

    # 5. Add scanner name - this is tricky, we'll do it for simple cases
    # Look for Finding( patterns and add scanner= if not present
    def add_scanner_field(match):
        finding_content = match.group(0)
        # Check if scanner= already exists
        if 'scanner=' in finding_content:
            return finding_content
        # Find the closing parenthesis and add scanner= before it
        # This is a simplistic approach - works for many cases
        return finding_content.rstrip(')') + f',\n                                scanner="{short_scanner}")'

    # Save changes
    if content != original:
        filepath.write_text(content)
        print(f"  Migrated: {filepath.name}")
        return True

    return False


def main():
    """Migrate all scanner modules."""

    modules_dir = Path("/home/artur/Secretária/petntesterai/scanning/modules")
    auth_dir = modules_dir / "auth"

    # Get all scanner files
    scanner_files = []

    for f in modules_dir.glob("*.py"):
        if f.name.startswith("__"):
            continue
        if f.name.endswith(".bak") or f.name.endswith(".backup"):
            continue
        if "backup" in f.name:
            continue
        scanner_files.append(f)

    for f in auth_dir.glob("*.py"):
        if f.name.startswith("__") or f.name == "auth_base.py":
            continue
        scanner_files.append(f)

    print(f"Found {len(scanner_files)} scanner files")

    migrated = 0
    for f in sorted(scanner_files):
        if migrate_file(f):
            migrated += 1

    print(f"\nMigrated {migrated} files")


if __name__ == "__main__":
    main()
