"""
Finding Deduplication - Cross-Module Finding Deduplication.

Handles deduplication of findings across scanner modules:
- Type normalization for consistent comparison
- Key generation based on vuln type, location, params
- Confidence-based resolution for duplicates

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

logger = logging.getLogger("phantom")


# Type normalization mappings for deduplication
# Groups related vulnerability types under canonical names
TYPE_NORMALIZATION: dict[str, str] = {
    # CORS variants
    "cors_wildcard": "cors",
    "cors_null": "cors",
    "cors_arbitrary": "cors",
    "cors_subdomain_inject": "cors",
    "cors_suffix_bypass": "cors",
    "cors_prefix_bypass": "cors",
    "cors_preflight": "cors",
    # Header variants
    "insecure_header": "header_config",
    "missing_browser_hardening": "missing_headers",
    "missing_security_header": "missing_headers",
    "security_header_missing": "missing_headers",
    # Session variants
    "jwt_weakness": "session",
    "jwt_vulnerability": "session",
    "token_not_invalidated": "session",
    "session_fixation": "session",
    # Auth variants
    "default_credentials": "auth_bypass",
    "weak_credentials": "auth_bypass",
    "broken_authentication": "auth_bypass",
    # Rate limit variants
    "rate_limit_bypass": "rate_limit",
    "rate_limiting_bypass": "rate_limit",
    "no_rate_limit": "rate_limit",
    # IDOR variants
    "bac": "idor",
    "broken_access_control": "idor",
    "access_control": "idor",
    # Creative exploiter findings
    "context_confusion": "creative_logic",
    "trust_boundary": "creative_logic",
    "flow_disruption": "creative_logic",
    "lazy_developer": "creative_logic",
    "chaos_composer": "creative_logic",
    # SAML variants
    "saml_vulnerability": "saml",
    "saml_metadata_exposed": "saml",
    "saml_certificate_exposure": "saml",
    "saml_encryption_weakness": "saml",
    "saml_xsw": "saml",
    "saml_replay": "saml",
    "saml_xxe": "saml",
    # OAuth variants
    "oauth_misconfiguration": "oauth",
    "oauth_redirect_bypass": "oauth",
    "oauth_csrf": "oauth",
    "oauth_pkce_bypass": "oauth",
    "oauth_scope_escalation": "oauth",
    "oauth_implicit_flow": "oauth",
    "oauth_token_leakage": "oauth",
    # WebSocket variants
    "websocket_vulnerability": "websocket",
    "websocket_hijacking": "websocket",
    "websocket_origin_bypass": "websocket",
    "websocket_injection": "websocket",
    # DNS rebinding variants
    "dns_rebinding": "dns_rebinding",
    "dns_rebind": "dns_rebinding",
    # CSRF variants
    "csrf_missing_token": "csrf",
    "csrf_token_bypass": "csrf",
    "csrf_samesite": "csrf",
    # Host header variants
    "host_header_injection": "host_header",
    "host_header_xfh": "host_header",
    "host_header_password_reset": "host_header",
    # Smuggling variants
    "http_smuggling": "smuggling",
    "http_request_smuggling": "smuggling",
    "request_splitting": "smuggling",
    # Info disclosure variants
    "info_disclosure": "info_disclosure",
    "information_disclosure": "info_disclosure",
    "sensitive_data_exposure": "info_disclosure",
}

# Types that need name in key (different logical issues at same endpoint)
NAME_BASED_TYPES: set[str] = {
    "business_logic", "session_abuse", "creative_exploiter", "creative_logic",
    "idor", "authorization", "access_control", "broken_access_control",
    "saml", "oauth", "websocket", "dns_rebinding",
}

# Types that need parameter in key (parameter-specific vulns)
PARAM_BASED_TYPES: set[str] = {
    "sql_injection", "sqli", "xss", "dom_xss", "ssti", "ssrf",
    "lfi", "xxe", "cmdi", "nosql", "crlf", "open_redirect",
}

# Types that need exploitation method in key
# Different exploitation vectors (e.g., UNION vs boolean-blind SQLi) are different findings
METHOD_BASED_TYPES: set[str] = {
    "sql_injection", "sqli", "nosql", "xxe", "cmdi", "lfi",
}

# Types where only host + name matters for deduplication (ignore endpoint path).
# These scanners spray common paths (e.g., /saml/acs, /saml/consume) and produce
# the same finding at each guessed endpoint. Dedup by host + name collapses them.
HOST_ONLY_DEDUP_TYPES: set[str] = {
    "saml", "saml_vulnerability",
    "csrf",
    "xxe",  # XXE via SAML — same test across SAML endpoints
}

# Types where HTTP method doesn't matter for deduplication
# Missing headers, SSL issues, CORS config are the same via GET or POST
HTTP_METHOD_AGNOSTIC_TYPES: set[str] = {
    "missing_headers", "header_config", "security_header_missing",
    "missing_browser_hardening", "insecure_header",
    "ssl", "ssl_config", "tls", "certificate",
    "cors", "cors_wildcard", "cors_null", "cors_arbitrary",
    "clickjacking", "x_frame_options",
    "csp", "content_security_policy",
    "hsts", "strict_transport_security",
    "info_disclosure", "information_disclosure", "sensitive_data_exposure",
}


def normalize_detection_method(detection_method: str) -> str:
    """Normalize detection method for consistent comparison.

    Groups similar detection methods to avoid false duplicates.

    Args:
        detection_method: Raw detection method string

    Returns:
        Normalized detection method
    """
    if not detection_method:
        return ""

    method = detection_method.lower().replace("-", "_").replace(" ", "_")

    # Group similar methods
    if "time" in method:
        return "time_blind"
    elif "boolean" in method or "bool" in method:
        return "boolean_blind"
    elif "union" in method:
        return "union_based"
    elif "error" in method:
        return "error_based"
    elif "oob" in method or "out_of_band" in method:
        return "oob"

    return method


def generate_dedup_key(
    finding: dict,
    normalize_type_func: Optional[Callable[[str], str]] = None,
) -> str:
    """Generate a deduplication key for a finding.

    Creates a unique key based on vulnerability type, location,
    and relevant context (params, methods, etc.).

    Args:
        finding: Finding dictionary
        normalize_type_func: Optional function to normalize vuln types

    Returns:
        Deduplication key string
    """
    finding_type = finding.get("vuln_type", finding.get("type", "unknown"))

    # First try local normalization, then external normalizer
    normalized_type = TYPE_NORMALIZATION.get(finding_type, finding_type)
    if normalize_type_func and normalized_type == finding_type:
        normalized_type = normalize_type_func(finding_type)

    host = finding.get("host", "")
    matched_at = finding.get("endpoint", finding.get("matched_at", finding.get("url", "")))
    name = finding.get("name", finding.get("title", ""))

    metadata = finding.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    param = (
        finding.get("parameter", "")
        or metadata.get("param_name")
        or metadata.get("parameter")
        or metadata.get("vulnerable_param", "")
    )
    method = (
        finding.get("method", "")
        or metadata.get("method")
        or metadata.get("http_method")
        or "GET"
    ).upper()

    # Get detection method for injection types
    detection_method = ""
    if normalized_type in METHOD_BASED_TYPES:
        detection_method = (
            metadata.get("detection_method", "")
            or metadata.get("technique", "")
            or metadata.get("injection_type", "")
            or ""
        )
        detection_method = normalize_detection_method(detection_method)

    # Determine whether to include HTTP method in key
    use_method_in_key = normalized_type not in HTTP_METHOD_AGNOSTIC_TYPES

    # Build key based on type characteristics
    # Host-only dedup: scanners that spray guessed paths get one finding per host+name
    if normalized_type in HOST_ONLY_DEDUP_TYPES and name:
        key = f"{normalized_type}:{name}:{host}"
    elif normalized_type in NAME_BASED_TYPES and name:
        if use_method_in_key:
            key = f"{method}:{normalized_type}:{name}:{host}:{matched_at}"
        else:
            key = f"{normalized_type}:{name}:{host}:{matched_at}"
    elif normalized_type in PARAM_BASED_TYPES and param:
        if detection_method:
            key = f"{method}:{normalized_type}:{param}:{detection_method}:{host}:{matched_at}"
        else:
            key = f"{method}:{normalized_type}:{param}:{host}:{matched_at}"
    else:
        if use_method_in_key:
            key = f"{method}:{normalized_type}:{host}:{matched_at}"
        else:
            # Method-agnostic key (headers, SSL, etc.)
            key = f"{normalized_type}:{host}:{matched_at}"

    return key


class FindingDeduplicator:
    """Deduplicates findings across scanner modules.

    Uses type normalization and key generation to identify duplicates,
    keeping the finding with highest confidence.
    """

    def __init__(
        self,
        normalize_confidence_func: Callable[[Any], float],
        normalize_type_func: Optional[Callable[[str], str]] = None,
    ):
        """Initialize the deduplicator.

        Args:
            normalize_confidence_func: Function to normalize confidence values
            normalize_type_func: Optional function to normalize vuln types
        """
        self.normalize_confidence = normalize_confidence_func
        self.normalize_type = normalize_type_func
        self._seen_keys: dict[str, tuple[int, dict]] = {}
        self._unique_findings: list[dict] = []
        self._duplicates_removed = 0

    def reset(self) -> None:
        """Reset the deduplicator state."""
        self._seen_keys.clear()
        self._unique_findings.clear()
        self._duplicates_removed = 0

    @property
    def duplicates_removed(self) -> int:
        """Get the number of duplicates removed."""
        return self._duplicates_removed

    @property
    def unique_findings(self) -> list[dict]:
        """Get the list of unique findings."""
        return self._unique_findings.copy()

    def process_finding(self, finding: dict) -> bool:
        """Process a single finding for deduplication.

        Args:
            finding: Finding dictionary

        Returns:
            True if finding was kept, False if it was a duplicate
        """
        try:
            key = generate_dedup_key(finding, self.normalize_type)
        except Exception as e:
            # Fallback to simple key to prevent finding loss
            logger.debug(f"Dedup key construction failed: {e}")
            key = f"fallback:{id(finding)}:{finding.get('id', hash(str(finding)) % 100000)}"

        current_confidence = self.normalize_confidence(finding.get("confidence_score", finding.get("confidence", 0)))

        if key not in self._seen_keys:
            idx = len(self._unique_findings)
            self._seen_keys[key] = (idx, finding)
            self._unique_findings.append(finding)
            return True
        else:
            # Duplicate found - keep the one with HIGHER confidence
            existing_idx, existing_finding = self._seen_keys[key]
            existing_confidence = self.normalize_confidence(
                existing_finding.get("confidence_score", existing_finding.get("confidence", 0))
            )

            if current_confidence > existing_confidence:
                # Replace with higher confidence finding
                self._unique_findings[existing_idx] = finding
                self._seen_keys[key] = (existing_idx, finding)
                finding_type = finding.get("vuln_type", finding.get("type", "unknown"))
                matched_at = finding.get("matched_at", "")
                logger.debug(
                    f"Dedup replaced {finding_type} at {matched_at}: "
                    f"conf {existing_confidence:.0f}% → {current_confidence:.0f}%"
                )
            else:
                logger.debug(
                    f"Dedup kept higher confidence for {finding.get('vuln_type', finding.get('type', 'unknown'))}: "
                    f"{existing_confidence:.0f}% vs {current_confidence:.0f}%"
                )

            self._duplicates_removed += 1
            return False

    def deduplicate(self, findings: list[dict]) -> list[dict]:
        """Deduplicate a list of findings.

        Args:
            findings: List of finding dictionaries

        Returns:
            List of unique findings
        """
        self.reset()

        for finding in findings:
            self.process_finding(finding)

        if self._duplicates_removed > 0:
            logger.info(f"Deduplicated {self._duplicates_removed} cross-module findings")

        return self._unique_findings


def deduplicate_findings(
    findings: list[dict],
    normalize_confidence_func: Callable[[Any], float],
    normalize_type_func: Optional[Callable[[str], str]] = None,
) -> tuple[list[dict], int]:
    """Convenience function to deduplicate findings.

    Args:
        findings: List of finding dictionaries
        normalize_confidence_func: Function to normalize confidence values
        normalize_type_func: Optional function to normalize vuln types

    Returns:
        Tuple of (unique_findings, duplicates_removed)
    """
    deduplicator = FindingDeduplicator(
        normalize_confidence_func=normalize_confidence_func,
        normalize_type_func=normalize_type_func,
    )
    unique = deduplicator.deduplicate(findings)
    return unique, deduplicator.duplicates_removed
