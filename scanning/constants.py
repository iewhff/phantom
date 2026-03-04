"""
PHANTOM AI - Scanning Constants

Centralized constants for all scanning modules.
Import from here instead of hardcoding magic numbers.

Usage:
    from scanning.constants import DEFAULT_TIMEOUT, MIN_CONFIDENCE
"""

# =============================================================================
# TIMEOUTS (seconds)
# =============================================================================

# Default HTTP request timeout
DEFAULT_REQUEST_TIMEOUT = 30.0

# Timeout for time-based blind injection detection
BLIND_DETECTION_TIMEOUT = 10.0

# Timeout for DNS resolution checks
DNS_TIMEOUT = 5.0

# Timeout for OOB callback verification
OOB_CALLBACK_TIMEOUT = 3.0

# Maximum wait for async operations
MAX_ASYNC_TIMEOUT = 120.0


# =============================================================================
# CONFIDENCE THRESHOLDS (0-100)
# =============================================================================

# Minimum confidence to include finding in results
MIN_CONFIDENCE = 60.0

# Low confidence (needs verification)
LOW_CONFIDENCE = 45.0

# Medium confidence (likely true positive)
MEDIUM_CONFIDENCE = 65.0

# High confidence (confirmed finding)
HIGH_CONFIDENCE = 85.0

# Very high confidence (proven exploitable)
VERY_HIGH_CONFIDENCE = 95.0


# =============================================================================
# FINDING LIMITS
# =============================================================================

# Maximum findings per module per scan
MAX_FINDINGS_PER_MODULE = 100

# Maximum findings per engine in creative exploiter
# AUDIT-FIX 2026-02-11: Increased from 3 to 10 - was limiting discovery too much
MAX_FINDINGS_PER_ENGINE = 10

# Maximum chain depth
MAX_CHAIN_DEPTH = 5

# Maximum duplicate findings before dedup
MAX_DUPLICATES_BEFORE_DEDUP = 10


# =============================================================================
# RATE LIMITS
# =============================================================================

# Default requests per second (safe mode)
SAFE_REQUESTS_PER_SECOND = 2

# Default requests per second (standard mode)
DEFAULT_REQUESTS_PER_SECOND = 10

# Aggressive requests per second
AGGRESSIVE_REQUESTS_PER_SECOND = 50

# Maximum burst size
DEFAULT_BURST_SIZE = 20


# =============================================================================
# RESPONSE SIZE LIMITS
# =============================================================================

# Maximum response body to analyze (bytes)
MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10 MB

# Maximum response to hash for dedup
MAX_HASH_SIZE = 64 * 1024  # 64 KB

# Minimum response length to consider meaningful
MIN_MEANINGFUL_RESPONSE = 50


# =============================================================================
# SEVERITY LEVELS (standardized)
# =============================================================================

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

# CVSS Score thresholds
CVSS_CRITICAL = 9.0
CVSS_HIGH = 7.0
CVSS_MEDIUM = 4.0
CVSS_LOW = 0.1


# =============================================================================
# SAFETY MODES
# =============================================================================

SAFETY_PASSIVE = "passive"
SAFETY_SAFE = "safe"
SAFETY_CAUTIOUS = "cautious"
SAFETY_STANDARD = "standard"
SAFETY_AGGRESSIVE = "aggressive"
SAFETY_UNRESTRICTED = "unrestricted"


# =============================================================================
# PAYLOAD LIMITS
# =============================================================================

# Maximum payloads per parameter
MAX_PAYLOADS_PER_PARAM = 50

# Maximum payload length
MAX_PAYLOAD_LENGTH = 8192

# Maximum number of parameters to test
MAX_PARAMS_TO_TEST = 100


# =============================================================================
# DISCOVERY LIMITS
# =============================================================================

# Maximum endpoints to discover
MAX_DISCOVERED_ENDPOINTS = 500

# Maximum forms to test
MAX_FORMS_TO_TEST = 50

# Maximum URL depth for crawling
MAX_CRAWL_DEPTH = 5

# Maximum pages to crawl
MAX_PAGES_TO_CRAWL = 100


# =============================================================================
# RETRY CONFIGURATION
# =============================================================================

# Default retry count
DEFAULT_RETRIES = 3

# Retry backoff factor (seconds)
RETRY_BACKOFF = 1.0

# Maximum retry delay
MAX_RETRY_DELAY = 30.0


# =============================================================================
# WORD-BASED CONFIDENCE MAPPING
# =============================================================================

WORD_CONFIDENCE_MAP = {
    "very high": 0.95,
    "high": 0.85,
    "medium": 0.65,
    "moderate": 0.65,
    "low": 0.45,
    "very low": 0.25,
}


def normalize_confidence(confidence: float | str) -> float:
    """
    Normalize confidence to float 0-1 range.

    Args:
        confidence: Can be float (0-100 or 0-1) or word string

    Returns:
        Float between 0 and 1
    """
    if isinstance(confidence, str):
        return WORD_CONFIDENCE_MAP.get(confidence.lower(), 0.5)

    if confidence > 1:
        return confidence / 100.0

    return confidence


def normalize_severity(severity: str) -> str:
    """
    Normalize severity to uppercase.

    Args:
        severity: Can be any case

    Returns:
        Uppercase severity string
    """
    return severity.upper() if severity else SEVERITY_MEDIUM


# =============================================================================
# VULNERABILITY TYPE NORMALIZATION
# Maps all scanner output variants to canonical types for chain matching
# =============================================================================

VULN_TYPE_ALIASES: dict[str, str] = {
    # SQLi variants → sqli
    "sql_injection": "sqli",
    "sqli": "sqli",
    "blind_sql_injection": "sqli_blind",
    "time_based_sqli": "sqli_blind",
    "sqli_blind": "sqli_blind",
    "error_based_sqli": "sqli",
    "union_based_sqli": "sqli",

    # XSS variants → xss
    "xss": "xss",
    "cross_site_scripting": "xss",
    "reflected_xss": "xss",
    "stored_xss": "xss",
    "template_injection_xss": "xss",
    "csti": "xss",
    "client_side_template_injection": "xss",

    # DOM XSS (separate trigger) → dom_xss
    "dom_xss": "dom_xss",
    "dom_based_xss": "dom_xss",

    # Command injection → cmdi
    "command_injection": "cmdi",
    "cmdi": "cmdi",
    "os_command_injection": "cmdi",
    "rce": "cmdi",
    "remote_code_execution": "cmdi",

    # File inclusion → lfi/rfi
    "local_file_inclusion": "lfi",
    "lfi": "lfi",
    "path_traversal": "lfi",
    "directory_traversal": "lfi",
    "remote_file_inclusion": "rfi",
    "rfi": "rfi",

    # SSRF → ssrf
    "ssrf": "ssrf",
    "server_side_request_forgery": "ssrf",
    "blind_ssrf": "ssrf",

    # XXE → xxe
    "xxe": "xxe",
    "xml_external_entity": "xxe",
    "xml_injection": "xxe",
    "xml_bomb": "xxe",
    "billion_laughs": "xxe",

    # SSTI → ssti
    "ssti": "ssti",
    "template_injection": "ssti",
    "server_side_template_injection": "ssti",

    # NoSQL injection → nosqli
    "nosql_injection": "nosqli",
    "nosqli": "nosqli",
    "mongodb_injection": "nosqli",

    # IDOR / Access Control → idor
    "idor": "idor",
    "insecure_direct_object_reference": "idor",
    "broken_access_control": "idor",
    "bac": "idor",
    "access_control": "idor",

    # Auth bypass → auth_bypass
    "authentication_bypass": "auth_bypass",
    "auth_bypass": "auth_bypass",
    "broken_authentication": "auth_bypass",
    "default_credentials": "auth_bypass",
    "weak_credentials": "auth_bypass",

    # Session abuse → session
    "session_abuse": "session",
    "session": "session",
    "jwt_replay": "session",
    "token_not_invalidated": "session",
    "session_fixation": "session",
    "jwt_weakness": "session",
    "jwt_vulnerability": "session",
    "jwt": "session",

    # Business logic → business_logic
    "business_logic": "business_logic",
    "price_manipulation": "business_logic",
    "workflow_bypass": "business_logic",
    "logic_flaw": "business_logic",

    # CSRF → csrf
    "csrf": "csrf",
    "cross_site_request_forgery": "csrf",

    # CORS → cors
    "cors": "cors",
    "cors_misconfiguration": "cors",
    "cors_wildcard": "cors",
    "cors_null": "cors",
    "cors_arbitrary": "cors",
    "cors_preflight": "cors",

    # Open redirect → open_redirect
    "open_redirect": "open_redirect",
    "url_redirect": "open_redirect",
    "redirect": "open_redirect",

    # Deserialization → deserialization
    "deserialization": "deserialization",
    "insecure_deserialization": "deserialization",

    # Info disclosure → info_disclosure
    "information_disclosure": "info_disclosure",
    "info_disclosure": "info_disclosure",
    "sensitive_data_exposure": "info_disclosure",

    # File upload → file_upload
    "file_upload": "file_upload",
    "unrestricted_file_upload": "file_upload",

    # Cloud-specific
    "aws_exposure": "aws_exposure",
    "aws_key_exposure": "aws_exposure",
    "aws_credential": "aws_exposure",
    "s3_misconfiguration": "s3_misconfig",
    "s3_bucket": "s3_misconfig",
    "cloud_metadata": "cloud_metadata",
    "metadata_exposure": "cloud_metadata",
    "api_key_exposure": "api_key",
    "api_key": "api_key",

    # Cache/CDN
    "cache_poisoning": "cache_poisoning",
    "web_cache": "cache_poisoning",
    "cloudfront_bypass": "cdn_bypass",
    "cdn_bypass": "cdn_bypass",
    "origin_bypass": "cdn_bypass",

    # Communications (Twilio/SendGrid)
    "phone_enumeration": "enumeration",
    "phone_number_enumeration": "enumeration",
    "user_enumeration": "enumeration",
    "account_enumeration": "enumeration",
    "email_enumeration": "enumeration",
    "sms_abuse": "sms_abuse",
    "sms_pumping": "sms_abuse",
    "toll_fraud": "sms_abuse",
    "twilio_credential": "credential_exposure",
    "sendgrid_key": "credential_exposure",
}

# Set of all canonical types (values from VULN_TYPE_ALIASES)
CANONICAL_VULN_TYPES: frozenset[str] = frozenset(set(VULN_TYPE_ALIASES.values()))


def normalize_vuln_type(raw_type: str) -> str:
    """
    Normalize vulnerability type to canonical form.

    Handles variations like:
    - "sql_injection" → "sqli"
    - "cross_site_scripting" → "xss"
    - "SQL Injection" → "sqli"
    - "command-injection" → "cmdi"

    Args:
        raw_type: Raw vulnerability type string from scanner

    Returns:
        Canonical type string (lowercase, normalized)
    """
    if not raw_type:
        return "unknown"

    # Normalize: lowercase, replace spaces/hyphens with underscores
    normalized = raw_type.lower().strip().replace(" ", "_").replace("-", "_")

    # Look up in aliases
    return VULN_TYPE_ALIASES.get(normalized, normalized)
