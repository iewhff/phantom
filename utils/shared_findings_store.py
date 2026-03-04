"""
Shared Findings Store - Inter-Module Communication

Enables real-time sharing of findings between scanner modules:
- When one scanner finds a vulnerability, others are informed immediately
- Modules can query what endpoints/parameters have known vulnerabilities
- Prevents duplicate testing and enables smarter targeting

Usage:
    from utils.shared_findings_store import SharedFindingsStore

    store = SharedFindingsStore.get_instance()

    # Add a finding (from within a scanner)
    store.add_finding({
        "type": "sql_injection",
        "endpoint": "/api/users",
        "parameter": "id",
        "severity": "CRITICAL"
    })

    # Check if endpoint has known vulns (from another scanner)
    if store.has_vulnerability("/api/users", "sql_injection"):
        # Skip SQLi testing - already found
        pass

    # Get all vulnerable parameters for an endpoint
    vuln_params = store.get_vulnerable_parameters("/api/users")

Author: PetNTester AI Enterprise
Version: 1.0.0
"""

from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from enum import Enum, auto

from utils.logger import get_logger

logger = get_logger(__name__)


class VulnType(Enum):
    """Vulnerability types for quick filtering."""
    # Injection vulnerabilities
    SQL_INJECTION = auto()
    NOSQL_INJECTION = auto()
    COMMAND_INJECTION = auto()
    LDAP_INJECTION = auto()
    XPATH_INJECTION = auto()
    CRLF_INJECTION = auto()

    # XSS variants
    XSS = auto()
    DOM_XSS = auto()

    # File-related
    LFI = auto()
    RFI = auto()
    FILE_UPLOAD = auto()
    XXE = auto()

    # Server-side
    SSRF = auto()
    SSTI = auto()
    DESERIALIZATION = auto()

    # Access control
    IDOR = auto()
    AUTH_BYPASS = auto()
    BROKEN_ACCESS_CONTROL = auto()

    # Session/Auth
    SESSION_ABUSE = auto()
    CSRF = auto()

    # Logic/Business
    BUSINESS_LOGIC = auto()
    RACE_CONDITION = auto()

    # Configuration
    CORS = auto()
    OPEN_REDIRECT = auto()
    INFO_DISCLOSURE = auto()
    SECURITY_MISCONFIG = auto()

    # Cloud/API
    CLOUD_MISCONFIGURATION = auto()
    API_ABUSE = auto()

    # Protocol/Transport (smuggling is an ENABLER, not terminal)
    HTTP_SMUGGLING = auto()
    REQUEST_SMUGGLING = auto()
    CACHE_POISONING = auto()
    DNS_REBINDING = auto()

    # Fallback
    OTHER = auto()


@dataclass
class ExtractedData:
    """
    THEME-4 FIX: Data extracted by one module that can be consumed by others.

    Examples:
    - SQLi extracts table names → IDOR enumerates those IDs
    - SQLi extracts credentials → Session tests login with creds
    - LFI reads /etc/passwd → Brute force with usernames
    - XSS found → Session chains token theft
    """
    data_type: str                      # "credentials", "table_names", "user_ids", "usernames", "config_values", "tokens"
    source_module: str                  # Module that extracted this data
    source_endpoint: str                # Endpoint where data was extracted
    values: List[Any] = field(default_factory=list)  # The actual extracted values
    context: Dict[str, Any] = field(default_factory=dict)  # Additional context
    timestamp: datetime = field(default_factory=datetime.now)
    consumed_by: List[str] = field(default_factory=list)  # Modules that used this data


@dataclass
class SharedFinding:
    """A finding shared between modules."""
    type: str
    endpoint: str
    parameter: Optional[str]
    severity: str
    module: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def vuln_type(self) -> VulnType:
        """Convert string type to VulnType enum."""
        mapping = {
            # SQL Injection
            "sql_injection": VulnType.SQL_INJECTION,
            "sqli": VulnType.SQL_INJECTION,
            "blind_sql_injection": VulnType.SQL_INJECTION,
            "blind_sqli": VulnType.SQL_INJECTION,
            "error_based_sqli": VulnType.SQL_INJECTION,
            "union_sqli": VulnType.SQL_INJECTION,
            "time_based_sqli": VulnType.SQL_INJECTION,

            # NoSQL Injection
            "nosql_injection": VulnType.NOSQL_INJECTION,
            "nosqli": VulnType.NOSQL_INJECTION,
            "mongodb_injection": VulnType.NOSQL_INJECTION,

            # XSS variants
            "xss": VulnType.XSS,
            "cross_site_scripting": VulnType.XSS,
            "reflected_xss": VulnType.XSS,
            "stored_xss": VulnType.XSS,
            "template_injection_xss": VulnType.XSS,
            "csti": VulnType.XSS,

            # DOM XSS (separate type)
            "dom_xss": VulnType.DOM_XSS,
            "dom_based_xss": VulnType.DOM_XSS,

            # Command Injection
            "command_injection": VulnType.COMMAND_INJECTION,
            "cmdi": VulnType.COMMAND_INJECTION,
            "os_command_injection": VulnType.COMMAND_INJECTION,
            "rce": VulnType.COMMAND_INJECTION,
            "remote_code_execution": VulnType.COMMAND_INJECTION,

            # File inclusion
            "lfi": VulnType.LFI,
            "local_file_inclusion": VulnType.LFI,
            "path_traversal": VulnType.LFI,
            "directory_traversal": VulnType.LFI,
            "rfi": VulnType.RFI,
            "remote_file_inclusion": VulnType.RFI,

            # File upload
            "file_upload": VulnType.FILE_UPLOAD,
            "unrestricted_file_upload": VulnType.FILE_UPLOAD,

            # SSRF
            "ssrf": VulnType.SSRF,
            "server_side_request_forgery": VulnType.SSRF,
            "blind_ssrf": VulnType.SSRF,

            # XXE
            "xxe": VulnType.XXE,
            "xml_external_entity": VulnType.XXE,
            "xml_injection": VulnType.XXE,

            # SSTI
            "ssti": VulnType.SSTI,
            "server_side_template_injection": VulnType.SSTI,
            "template_injection": VulnType.SSTI,

            # Deserialization
            "deserialization": VulnType.DESERIALIZATION,
            "insecure_deserialization": VulnType.DESERIALIZATION,

            # Access control
            "idor": VulnType.IDOR,
            "insecure_direct_object_reference": VulnType.IDOR,
            "broken_access_control": VulnType.BROKEN_ACCESS_CONTROL,
            "bac": VulnType.BROKEN_ACCESS_CONTROL,
            "access_control": VulnType.BROKEN_ACCESS_CONTROL,

            # Auth bypass
            "auth_bypass": VulnType.AUTH_BYPASS,
            "authentication_bypass": VulnType.AUTH_BYPASS,
            "broken_authentication": VulnType.AUTH_BYPASS,
            "default_credentials": VulnType.AUTH_BYPASS,

            # Session/JWT
            "session_abuse": VulnType.SESSION_ABUSE,
            "jwt_replay": VulnType.SESSION_ABUSE,
            "token_not_invalidated": VulnType.SESSION_ABUSE,
            "session_fixation": VulnType.SESSION_ABUSE,
            "jwt_weakness": VulnType.SESSION_ABUSE,

            # CSRF
            "csrf": VulnType.CSRF,
            "cross_site_request_forgery": VulnType.CSRF,

            # Business logic
            "business_logic": VulnType.BUSINESS_LOGIC,
            "price_manipulation": VulnType.BUSINESS_LOGIC,
            "workflow_bypass": VulnType.BUSINESS_LOGIC,
            "logic_flaw": VulnType.BUSINESS_LOGIC,

            # Race condition
            "race_condition": VulnType.RACE_CONDITION,
            "toctou": VulnType.RACE_CONDITION,

            # CORS
            "cors": VulnType.CORS,
            "cors_misconfiguration": VulnType.CORS,
            "cors_wildcard": VulnType.CORS,
            "cors_null": VulnType.CORS,
            "cors_arbitrary": VulnType.CORS,

            # Redirects
            "open_redirect": VulnType.OPEN_REDIRECT,
            "url_redirect": VulnType.OPEN_REDIRECT,

            # Info disclosure
            "information_disclosure": VulnType.INFO_DISCLOSURE,
            "info_disclosure": VulnType.INFO_DISCLOSURE,
            "sensitive_data_exposure": VulnType.INFO_DISCLOSURE,

            # Other injections
            "ldap_injection": VulnType.LDAP_INJECTION,
            "xpath_injection": VulnType.XPATH_INJECTION,
            "crlf_injection": VulnType.CRLF_INJECTION,

            # Security misconfiguration
            "security_misconfiguration": VulnType.SECURITY_MISCONFIG,
            "misconfiguration": VulnType.SECURITY_MISCONFIG,

            # Cloud
            "cloud_misconfiguration": VulnType.CLOUD_MISCONFIGURATION,
            "s3_misconfiguration": VulnType.CLOUD_MISCONFIGURATION,
            "aws_exposure": VulnType.CLOUD_MISCONFIGURATION,

            # API
            "api_abuse": VulnType.API_ABUSE,
            "graphql_injection": VulnType.API_ABUSE,
        }
        return mapping.get(self.type.lower(), VulnType.OTHER)


class SharedFindingsStore:
    """
    Thread-safe singleton store for sharing findings between modules.

    Features:
    - Real-time finding sharing
    - Query by endpoint, parameter, or vulnerability type
    - Track which parameters have been fully tested
    - Support for concurrent module execution
    """

    _instance: Optional["SharedFindingsStore"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "SharedFindingsStore":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._findings: List[SharedFinding] = []
        # Lazy initialization: asyncio.Lock() requires event loop, create on first use
        self._findings_lock: Optional[asyncio.Lock] = None

        # RLock for synchronous read methods (reentrant, thread-safe)
        self._sync_lock = threading.RLock()

        # Indexes for fast lookups
        self._by_endpoint: Dict[str, List[SharedFinding]] = {}
        self._by_parameter: Dict[str, List[SharedFinding]] = {}
        self._by_type: Dict[VulnType, List[SharedFinding]] = {}

        # Track tested items to avoid duplication
        self._tested_endpoints: Set[str] = set()
        self._tested_params: Dict[str, Set[str]] = {}  # endpoint -> set of params

        # Scan session ID for isolation
        self._session_id: Optional[str] = None

        # THEME-4 FIX: Extracted data storage for cross-module consumption
        self._extracted_data: List[ExtractedData] = []
        self._by_data_type: Dict[str, List[ExtractedData]] = {}

        self._initialized = True
        logger.debug("SharedFindingsStore initialized")

    @classmethod
    def get_instance(cls) -> "SharedFindingsStore":
        """Get singleton instance."""
        return cls()

    @classmethod
    def reset(cls) -> None:
        """Reset the store for a new scan session."""
        with cls._lock:
            if cls._instance:
                cls._instance._findings.clear()
                cls._instance._by_endpoint.clear()
                cls._instance._by_parameter.clear()
                cls._instance._by_type.clear()
                cls._instance._tested_endpoints.clear()
                cls._instance._tested_params.clear()
                cls._instance._session_id = None
                # THEME-4: Reset extracted data
                cls._instance._extracted_data.clear()
                cls._instance._by_data_type.clear()
                logger.debug("SharedFindingsStore reset for new session")

    def set_session(self, session_id: str) -> None:
        """Set the current scan session ID."""
        self._session_id = session_id

    async def add_finding(
        self,
        finding_dict: Dict[str, Any],
        module: str = "unknown"
    ) -> SharedFinding:
        """
        Add a finding to the shared store.

        Args:
            finding_dict: Finding dictionary with at least 'type' and 'endpoint'
            module: Name of the module that found this

        Returns:
            SharedFinding object created
        """
        # Lazy init: create lock on first use when event loop exists
        if self._findings_lock is None:
            self._findings_lock = asyncio.Lock()
        async with self._findings_lock:
            # Also acquire sync lock for thread safety with synchronous readers
            with self._sync_lock:
                # Normalize type: convert VulnType enum to string for consistent lookups
                raw_type = finding_dict.get("type", "unknown")
                if hasattr(raw_type, 'name'):
                    # It's an enum, use its name attribute (e.g., VulnType.SQL_INJECTION → "SQL_INJECTION")
                    normalized_type = raw_type.name.lower()
                elif hasattr(raw_type, 'value'):
                    # It might be an enum with a value
                    normalized_type = str(raw_type.value).lower()
                else:
                    # It's already a string
                    normalized_type = str(raw_type).lower()

                shared = SharedFinding(
                    type=normalized_type,
                    endpoint=finding_dict.get("endpoint", finding_dict.get("matched_at", "")),
                    parameter=finding_dict.get("parameter"),
                    severity=finding_dict.get("severity", "MEDIUM"),
                    module=module,
                    metadata=finding_dict.get("metadata", {})
                )

                self._findings.append(shared)

                # Update indexes
                endpoint = shared.endpoint
                if endpoint:
                    if endpoint not in self._by_endpoint:
                        self._by_endpoint[endpoint] = []
                    self._by_endpoint[endpoint].append(shared)

                param = shared.parameter
                if param:
                    param_key = f"{endpoint}:{param}"
                    if param_key not in self._by_parameter:
                        self._by_parameter[param_key] = []
                    self._by_parameter[param_key].append(shared)

                vuln_type = shared.vuln_type
                if vuln_type not in self._by_type:
                    self._by_type[vuln_type] = []
                self._by_type[vuln_type].append(shared)

                logger.debug(
                    f"SharedFindingsStore: Added {shared.type} at {endpoint}"
                    f"{f' param={param}' if param else ''} from {module}"
                )

                return shared

    def has_vulnerability(
        self,
        endpoint: str,
        vuln_type: Optional[str] = None
    ) -> bool:
        """
        Check if an endpoint has a known vulnerability.

        Args:
            endpoint: The endpoint path to check
            vuln_type: Optional - specific vulnerability type to check for

        Returns:
            True if vulnerability exists for this endpoint
        """
        with self._sync_lock:
            findings = self._by_endpoint.get(endpoint, [])
            if not findings:
                return False

            if vuln_type is None:
                return True

            vuln_type_lower = vuln_type.lower()
            return any(f.type.lower() == vuln_type_lower for f in findings)

    def has_parameter_vulnerability(
        self,
        endpoint: str,
        parameter: str,
        vuln_type: Optional[str] = None
    ) -> bool:
        """
        Check if a specific parameter has a known vulnerability.

        Args:
            endpoint: The endpoint path
            parameter: The parameter name
            vuln_type: Optional - specific vulnerability type

        Returns:
            True if vulnerability exists for this parameter
        """
        with self._sync_lock:
            param_key = f"{endpoint}:{parameter}"
            findings = self._by_parameter.get(param_key, [])
            if not findings:
                return False

            if vuln_type is None:
                return True

            vuln_type_lower = vuln_type.lower()
            return any(f.type.lower() == vuln_type_lower for f in findings)

    def get_vulnerable_parameters(self, endpoint: str) -> Dict[str, List[str]]:
        """
        Get all vulnerable parameters for an endpoint.

        Returns:
            Dict mapping parameter names to list of vulnerability types
        """
        with self._sync_lock:
            result: Dict[str, List[str]] = {}

            for finding in self._by_endpoint.get(endpoint, []):
                if finding.parameter:
                    if finding.parameter not in result:
                        result[finding.parameter] = []
                    if finding.type not in result[finding.parameter]:
                        result[finding.parameter].append(finding.type)

            return result

    def get_findings_by_type(self, vuln_type: VulnType) -> List[SharedFinding]:
        """Get all findings of a specific type."""
        with self._sync_lock:
            return list(self._by_type.get(vuln_type, []))

    def get_all_findings(self) -> List[SharedFinding]:
        """Get all shared findings."""
        with self._sync_lock:
            return list(self._findings)

    def get_critical_findings(self) -> List[SharedFinding]:
        """Get all CRITICAL severity findings."""
        with self._sync_lock:
            return [f for f in self._findings if f.severity.upper() == "CRITICAL"]

    def mark_endpoint_tested(self, endpoint: str, test_type: str) -> None:
        """Mark an endpoint as fully tested for a specific test type."""
        with self._sync_lock:
            key = f"{endpoint}:{test_type}"
            self._tested_endpoints.add(key)

    def is_endpoint_tested(self, endpoint: str, test_type: str) -> bool:
        """Check if an endpoint was already tested for a specific type."""
        with self._sync_lock:
            key = f"{endpoint}:{test_type}"
            return key in self._tested_endpoints

    def mark_parameter_tested(
        self,
        endpoint: str,
        parameter: str,
        test_type: str
    ) -> None:
        """Mark a parameter as fully tested."""
        with self._sync_lock:
            key = f"{endpoint}:{test_type}"
            if key not in self._tested_params:
                self._tested_params[key] = set()
            self._tested_params[key].add(parameter)

    def is_parameter_tested(
        self,
        endpoint: str,
        parameter: str,
        test_type: str
    ) -> bool:
        """Check if a parameter was already tested."""
        with self._sync_lock:
            key = f"{endpoint}:{test_type}"
            return parameter in self._tested_params.get(key, set())

    def get_statistics(self) -> Dict[str, Any]:
        """Get store statistics."""
        with self._sync_lock:
            by_type_counts = {
                vt.name: len(findings)
                for vt, findings in self._by_type.items()
            }

            by_severity = {}
            for f in self._findings:
                sev = f.severity.upper()
                by_severity[sev] = by_severity.get(sev, 0) + 1

            return {
                "total_findings": len(self._findings),
                "unique_endpoints": len(self._by_endpoint),
                "by_type": by_type_counts,
                "by_severity": by_severity,
                "tested_endpoints": len(self._tested_endpoints),
                "session_id": self._session_id,
            }

    def should_skip_test(
        self,
        endpoint: str,
        parameter: Optional[str],
        test_type: str,
        reason_log: bool = True
    ) -> bool:
        """
        Determine if a test should be skipped based on existing findings.

        This is the main method modules should call to check if testing
        should be skipped for efficiency.

        Args:
            endpoint: The endpoint to test
            parameter: The parameter to test (if applicable)
            test_type: Type of test (e.g., "sqli", "xss")
            reason_log: Whether to log the skip reason

        Returns:
            True if test should be skipped
        """
        # Check if already tested
        if parameter:
            if self.is_parameter_tested(endpoint, parameter, test_type):
                if reason_log:
                    logger.debug(
                        f"Skip {test_type} on {endpoint}:{parameter} - already tested"
                    )
                return True
        else:
            if self.is_endpoint_tested(endpoint, test_type):
                if reason_log:
                    logger.debug(
                        f"Skip {test_type} on {endpoint} - already tested"
                    )
                return True

        # Check if same vuln type already found (no need to find twice)
        if parameter:
            if self.has_parameter_vulnerability(endpoint, parameter, test_type):
                if reason_log:
                    logger.debug(
                        f"Skip {test_type} on {endpoint}:{parameter} - vulnerability already found"
                    )
                return True
        else:
            if self.has_vulnerability(endpoint, test_type):
                if reason_log:
                    logger.debug(
                        f"Skip {test_type} on {endpoint} - vulnerability already found"
                    )
                return True

        return False

    # =========================================================================
    # CROSS-MODULE QUERY METHODS - For chain detection and correlation
    # =========================================================================

    def get_findings_by_endpoint(self, endpoint: str) -> List[SharedFinding]:
        """
        Get all findings for a specific endpoint.

        Args:
            endpoint: The endpoint URL to query

        Returns:
            List of findings at this endpoint
        """
        with self._sync_lock:
            return list(self._by_endpoint.get(endpoint, []))

    def get_findings_from_module(self, module: str) -> List[SharedFinding]:
        """
        Get all findings from a specific scanner module.

        Args:
            module: Module name (e.g., "sqli", "xss", "ssrf")

        Returns:
            List of findings from this module
        """
        with self._sync_lock:
            return [f for f in self._findings if f.module == module]

    def get_findings_by_types(self, types: List[VulnType]) -> List[SharedFinding]:
        """
        Get findings matching ANY of the specified types.

        Args:
            types: List of VulnType values to match

        Returns:
            Combined list of findings for all types (deduplicated)
        """
        with self._sync_lock:
            result = []
            seen_ids = set()
            for vtype in types:
                for f in self._by_type.get(vtype, []):
                    # Use endpoint+type+param as unique identifier
                    fid = f"{f.endpoint}:{f.type}:{f.parameter or ''}"
                    if fid not in seen_ids:
                        seen_ids.add(fid)
                        result.append(f)
            return result

    def get_chainable_findings(self) -> List[SharedFinding]:
        """
        Get findings where proof engine suggests chaining is possible.

        Returns:
            List of findings with can_chain=True in metadata.proof
        """
        with self._sync_lock:
            return [
                f for f in self._findings
                if f.metadata.get("proof", {}).get("can_chain", False)
            ]

    def get_high_value_targets(self) -> List[str]:
        """
        Get endpoints with multiple vulnerability types - high value chain targets.

        Returns:
            List of endpoints with 2+ different vuln types
        """
        with self._sync_lock:
            endpoint_types: Dict[str, set] = {}
            for f in self._findings:
                if f.endpoint not in endpoint_types:
                    endpoint_types[f.endpoint] = set()
                endpoint_types[f.endpoint].add(f.vuln_type)

            return [
                ep for ep, types in endpoint_types.items()
                if len(types) >= 2
            ]

    def get_amplification_hints(self, current_module: str) -> List[Dict[str, Any]]:
        """
        Get hints for what additional testing to do based on other modules' findings.

        This enables CROSS-FINDING AMPLIFICATION - when one module finds something,
        other modules can get hints about what to test more deeply.

        Philosophy: "When you find something, what else should you test?"

        Example amplifications:
        - IDOR found → business_logic should retest with different user IDs
        - Auth bypass found → all modules should try the bypass
        - SQLi found → LFI/SSRF should test same endpoint
        - XSS found → session_abuse should test token theft

        Args:
            current_module: The module asking for hints

        Returns:
            List of hint dicts with: target_endpoint, reason, priority, suggested_tests
        """
        hints: List[Dict[str, Any]] = []

        # Amplification rules: finding_type → (modules_to_notify, reason)
        AMPLIFICATION_RULES: Dict[str, List[tuple]] = {
            "idor": [
                ("business", "IDOR found — test business logic with different user contexts"),
                ("session_abuse", "IDOR found — test session handling at this endpoint"),
                ("creative_exploiter", "IDOR found — explore trust boundary violations"),
            ],
            "auth_bypass": [
                ("authz", "Auth bypass found — test all admin endpoints with bypass"),
                ("idor", "Auth bypass found — retest IDOR with elevated access"),
                ("business", "Auth bypass found — test business logic without auth"),
            ],
            "sql_injection": [
                ("lfi", "SQLi found — test LFI on same endpoint (often co-occur)"),
                ("ssrf", "SQLi found — test SSRF on same endpoint"),
                ("session_abuse", "SQLi found — credentials may enable session attacks"),
            ],
            "sqli": [
                ("lfi", "SQLi found — test LFI on same endpoint"),
                ("ssrf", "SQLi found — test SSRF on same endpoint"),
            ],
            "xss": [
                ("cors", "XSS found — test CORS for data exfiltration chain"),
                ("session_abuse", "XSS found — test token theft scenarios"),
                ("csrf", "XSS found — XSS can deliver CSRF"),
            ],
            "dom_xss": [
                ("cors", "DOM XSS found — test CORS for cross-origin chain"),
                ("session_abuse", "DOM XSS found — test storage access"),
            ],
            "cors": [
                ("xss", "CORS misconfiguration — XSS would enable cross-origin data theft"),
                ("session_abuse", "CORS misconfiguration — test credential inclusion"),
            ],
            "session_abuse": [
                ("auth", "Session weakness — test auth flows for escalation"),
                ("creative_exploiter", "Session weakness — explore flow disruption"),
            ],
            "business_logic": [
                ("race", "Business logic flaw — test race conditions"),
                ("session_abuse", "Business logic flaw — test with different sessions"),
            ],
        }

        with self._sync_lock:
            for finding in self._findings:
                # Skip if this was from the current module
                if finding.module == current_module:
                    continue

                # Get amplification rules for this finding type
                finding_type = finding.type.lower()
                rules = AMPLIFICATION_RULES.get(finding_type, [])

                for target_module, reason in rules:
                    # Only give hints to relevant modules
                    if target_module == current_module:
                        hints.append({
                            "target_endpoint": finding.endpoint,
                            "trigger_type": finding_type,
                            "trigger_module": finding.module,
                            "trigger_severity": finding.severity,
                            "reason": reason,
                            "priority": 8 if finding.severity.upper() in ("HIGH", "CRITICAL") else 5,
                            "suggested_tests": [
                                f"Test {finding.endpoint} with context from {finding.module}",
                                f"Apply {finding_type} discovery to {current_module} payloads",
                            ],
                            "finding_metadata": finding.metadata,
                        })

        # Sort by priority (highest first)
        hints.sort(key=lambda h: h["priority"], reverse=True)

        # Limit to top 10 hints
        return hints[:10]

    def get_endpoints_with_severity(self, min_severity: str = "HIGH") -> List[str]:
        """
        Get endpoints that have at least one finding at or above the specified severity.

        Args:
            min_severity: Minimum severity level ("LOW", "MEDIUM", "HIGH", "CRITICAL")

        Returns:
            List of endpoint URLs
        """
        severity_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        min_level = severity_order.get(min_severity.upper(), 3)

        with self._sync_lock:
            result = set()
            for f in self._findings:
                f_level = severity_order.get(f.severity.upper(), 0)
                if f_level >= min_level and f.endpoint:
                    result.add(f.endpoint)
            return list(result)


    # =========================================================================
    # THEME-4: EXTRACTED DATA SHARING - Cross-module data consumption
    # =========================================================================

    async def add_extracted_data(
        self,
        data_type: str,
        values: List[Any],
        source_module: str,
        source_endpoint: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> ExtractedData:
        """
        Add extracted data for cross-module consumption.

        THEME-4 FIX: Enables feedback loops between modules.

        Args:
            data_type: Type of data ("credentials", "table_names", "user_ids", "usernames", "tokens", "config_values")
            values: The actual extracted values
            source_module: Module that extracted this data
            source_endpoint: Endpoint where data was extracted
            context: Additional context about the extraction

        Returns:
            ExtractedData object created

        Example:
            >>> # SQLi extracts credentials
            >>> await store.add_extracted_data(
            ...     data_type="credentials",
            ...     values=[{"username": "admin", "password_hash": "5f4dcc3b..."}],
            ...     source_module="sqli",
            ...     source_endpoint="/api/users?id=1",
            ...     context={"database": "mysql", "table": "users"}
            ... )
        """
        if self._findings_lock is None:
            self._findings_lock = asyncio.Lock()

        async with self._findings_lock:
            with self._sync_lock:
                extracted = ExtractedData(
                    data_type=data_type.lower(),
                    source_module=source_module,
                    source_endpoint=source_endpoint,
                    values=values,
                    context=context or {},
                )

                self._extracted_data.append(extracted)

                # Index by type
                if data_type not in self._by_data_type:
                    self._by_data_type[data_type] = []
                self._by_data_type[data_type].append(extracted)

                logger.info(
                    f"[THEME-4] {source_module} shared {len(values)} {data_type} "
                    f"from {source_endpoint}"
                )

                return extracted

    def get_extracted_credentials(self, consumer_module: str = "") -> List[Dict[str, Any]]:
        """
        Get credentials extracted by other modules (SQLi, LFI config reads, etc.).

        Args:
            consumer_module: Module consuming this data (for tracking)

        Returns:
            List of credential dicts with username, password/hash, source info
        """
        with self._sync_lock:
            results = []
            for data in self._by_data_type.get("credentials", []):
                for cred in data.values:
                    results.append({
                        **cred,
                        "_source_module": data.source_module,
                        "_source_endpoint": data.source_endpoint,
                        "_context": data.context,
                    })
                if consumer_module and consumer_module not in data.consumed_by:
                    data.consumed_by.append(consumer_module)

            if results:
                logger.debug(f"[THEME-4] {consumer_module or 'unknown'} consuming {len(results)} credentials")
            return results

    def get_extracted_user_ids(self, consumer_module: str = "") -> List[str]:
        """
        Get user IDs extracted by other modules (IDOR enumeration, SQLi, etc.).

        Args:
            consumer_module: Module consuming this data

        Returns:
            List of user ID strings
        """
        with self._sync_lock:
            results = []
            for data in self._by_data_type.get("user_ids", []):
                results.extend([str(v) for v in data.values])
                if consumer_module and consumer_module not in data.consumed_by:
                    data.consumed_by.append(consumer_module)

            if results:
                logger.debug(f"[THEME-4] {consumer_module or 'unknown'} consuming {len(results)} user_ids")
            return list(set(results))  # Deduplicate

    def get_extracted_usernames(self, consumer_module: str = "") -> List[str]:
        """
        Get usernames extracted by other modules (LFI /etc/passwd, SQLi, etc.).

        Args:
            consumer_module: Module consuming this data

        Returns:
            List of username strings
        """
        with self._sync_lock:
            results = []
            for data in self._by_data_type.get("usernames", []):
                results.extend([str(v) for v in data.values])
                if consumer_module and consumer_module not in data.consumed_by:
                    data.consumed_by.append(consumer_module)

            if results:
                logger.debug(f"[THEME-4] {consumer_module or 'unknown'} consuming {len(results)} usernames")
            return list(set(results))

    def get_extracted_table_names(self, consumer_module: str = "") -> List[str]:
        """
        Get database table names extracted by SQLi.

        Args:
            consumer_module: Module consuming this data

        Returns:
            List of table name strings
        """
        with self._sync_lock:
            results = []
            for data in self._by_data_type.get("table_names", []):
                results.extend([str(v) for v in data.values])
                if consumer_module and consumer_module not in data.consumed_by:
                    data.consumed_by.append(consumer_module)

            if results:
                logger.debug(f"[THEME-4] {consumer_module or 'unknown'} consuming {len(results)} table_names")
            return list(set(results))

    def get_extracted_tokens(self, consumer_module: str = "") -> List[Dict[str, Any]]:
        """
        Get tokens extracted by other modules (XSS token theft, session analysis, etc.).

        Args:
            consumer_module: Module consuming this data

        Returns:
            List of token dicts with token value, type, context
        """
        with self._sync_lock:
            results = []
            for data in self._by_data_type.get("tokens", []):
                for token in data.values:
                    # Build entry dict - handle both dict and string tokens
                    if isinstance(token, dict):
                        entry = dict(token)
                    else:
                        entry = {"token": token}
                    entry["_source_module"] = data.source_module
                    entry["_source_endpoint"] = data.source_endpoint
                    results.append(entry)
                if consumer_module and consumer_module not in data.consumed_by:
                    data.consumed_by.append(consumer_module)

            if results:
                logger.debug(f"[THEME-4] {consumer_module or 'unknown'} consuming {len(results)} tokens")
            return results

    def get_chain_opportunities(self, consumer_module: str = "") -> List[Dict[str, Any]]:
        """
        Get chain opportunities registered by other modules.

        THEME-4: XSS → Session theft, SQLi → credential usage, etc.

        Args:
            consumer_module: Module consuming this data

        Returns:
            List of chain opportunity dicts
        """
        with self._sync_lock:
            results = []
            for data in self._by_data_type.get("chain_opportunities", []):
                for opp in data.values:
                    # Build entry dict - handle both dict and string opportunities
                    if isinstance(opp, dict):
                        entry = dict(opp)
                    else:
                        entry = {"opportunity": opp}
                    entry["_source_module"] = data.source_module
                    entry["_source_endpoint"] = data.source_endpoint
                    entry["_context"] = data.context
                    results.append(entry)
                if consumer_module and consumer_module not in data.consumed_by:
                    data.consumed_by.append(consumer_module)

            return results

    def get_extracted_data_summary(self) -> Dict[str, Any]:
        """
        Get summary of all extracted data for reporting.

        Returns:
            Dict with counts and consumption stats
        """
        with self._sync_lock:
            summary = {
                "total_extractions": len(self._extracted_data),
                "by_type": {},
                "cross_module_consumption": [],
            }

            for data_type, items in self._by_data_type.items():
                total_values = sum(len(item.values) for item in items)
                consumers = set()
                for item in items:
                    consumers.update(item.consumed_by)

                summary["by_type"][data_type] = {
                    "count": len(items),
                    "total_values": total_values,
                    "sources": list(set(item.source_module for item in items)),
                    "consumed_by": list(consumers),
                }

                # Track successful cross-module consumption
                if consumers:
                    for item in items:
                        if item.consumed_by:
                            summary["cross_module_consumption"].append({
                                "type": data_type,
                                "source": item.source_module,
                                "consumers": item.consumed_by,
                                "values_count": len(item.values),
                            })

            return summary


# Convenience function for modules
def get_shared_findings() -> SharedFindingsStore:
    """Get the shared findings store instance."""
    return SharedFindingsStore.get_instance()
