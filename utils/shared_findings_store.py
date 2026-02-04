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
    SQL_INJECTION = auto()
    XSS = auto()
    COMMAND_INJECTION = auto()
    LFI = auto()
    RFI = auto()
    SSRF = auto()
    XXE = auto()
    IDOR = auto()
    AUTH_BYPASS = auto()
    OPEN_REDIRECT = auto()
    SSTI = auto()
    NOSQL_INJECTION = auto()
    LDAP_INJECTION = auto()
    XPATH_INJECTION = auto()
    CRLF_INJECTION = auto()
    OTHER = auto()


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
            "sql_injection": VulnType.SQL_INJECTION,
            "sqli": VulnType.SQL_INJECTION,
            "xss": VulnType.XSS,
            "cross_site_scripting": VulnType.XSS,
            "command_injection": VulnType.COMMAND_INJECTION,
            "cmdi": VulnType.COMMAND_INJECTION,
            "lfi": VulnType.LFI,
            "local_file_inclusion": VulnType.LFI,
            "rfi": VulnType.RFI,
            "remote_file_inclusion": VulnType.RFI,
            "ssrf": VulnType.SSRF,
            "xxe": VulnType.XXE,
            "idor": VulnType.IDOR,
            "insecure_direct_object_reference": VulnType.IDOR,
            "auth_bypass": VulnType.AUTH_BYPASS,
            "authentication_bypass": VulnType.AUTH_BYPASS,
            "open_redirect": VulnType.OPEN_REDIRECT,
            "ssti": VulnType.SSTI,
            "server_side_template_injection": VulnType.SSTI,
            "nosql_injection": VulnType.NOSQL_INJECTION,
            "nosqli": VulnType.NOSQL_INJECTION,
            "ldap_injection": VulnType.LDAP_INJECTION,
            "xpath_injection": VulnType.XPATH_INJECTION,
            "crlf_injection": VulnType.CRLF_INJECTION,
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
        self._findings_lock = asyncio.Lock()

        # Indexes for fast lookups
        self._by_endpoint: Dict[str, List[SharedFinding]] = {}
        self._by_parameter: Dict[str, List[SharedFinding]] = {}
        self._by_type: Dict[VulnType, List[SharedFinding]] = {}

        # Track tested items to avoid duplication
        self._tested_endpoints: Set[str] = set()
        self._tested_params: Dict[str, Set[str]] = {}  # endpoint -> set of params

        # Scan session ID for isolation
        self._session_id: Optional[str] = None

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
        async with self._findings_lock:
            shared = SharedFinding(
                type=finding_dict.get("type", "unknown"),
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
        return list(self._by_type.get(vuln_type, []))

    def get_all_findings(self) -> List[SharedFinding]:
        """Get all shared findings."""
        return list(self._findings)

    def get_critical_findings(self) -> List[SharedFinding]:
        """Get all CRITICAL severity findings."""
        return [f for f in self._findings if f.severity.upper() == "CRITICAL"]

    def mark_endpoint_tested(self, endpoint: str, test_type: str) -> None:
        """Mark an endpoint as fully tested for a specific test type."""
        key = f"{endpoint}:{test_type}"
        self._tested_endpoints.add(key)

    def is_endpoint_tested(self, endpoint: str, test_type: str) -> bool:
        """Check if an endpoint was already tested for a specific type."""
        key = f"{endpoint}:{test_type}"
        return key in self._tested_endpoints

    def mark_parameter_tested(
        self,
        endpoint: str,
        parameter: str,
        test_type: str
    ) -> None:
        """Mark a parameter as fully tested."""
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
        key = f"{endpoint}:{test_type}"
        return parameter in self._tested_params.get(key, set())

    def get_statistics(self) -> Dict[str, Any]:
        """Get store statistics."""
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


# Convenience function for modules
def get_shared_findings() -> SharedFindingsStore:
    """Get the shared findings store instance."""
    return SharedFindingsStore.get_instance()
