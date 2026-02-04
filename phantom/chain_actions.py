"""
PHANTOM AI - Chain Actions Engine
==================================

Enterprise vulnerability chain execution engine for demonstrating
real-world attack paths and impact.

Features:
- Vulnerability chain discovery and execution
- Attack path generation (A → B → C)
- Precondition verification
- Safe chain execution with rollback
- Impact demonstration without destruction
- Chain prioritization by impact
- Evidence collection for each step

Common Attack Chains:
- XSS → Session Hijacking → Account Takeover
- SSRF → AWS Metadata → Credential Leak → Cloud Compromise
- SQLi → Data Exfiltration → Privilege Escalation
- LFI → Source Code Leak → Credential Discovery → Database Access
- IDOR → PII Access → Account Enumeration

Author: PHANTOM AI Team
Version: 3.0.0
"""

from __future__ import annotations

import re
import json
import hashlib
import asyncio
import time
import logging
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Tuple, Callable, Type
from collections import defaultdict
from abc import ABC, abstractmethod

import httpx

logger = logging.getLogger("phantom.chain_actions")


# =============================================================================
# ENUMS AND CONSTANTS
# =============================================================================

class ChainActionType(Enum):
    """Types of chain actions."""
    # Discovery actions
    DISCOVER_ENDPOINT = "discover_endpoint"
    DISCOVER_PARAMETER = "discover_parameter"
    DISCOVER_CREDENTIAL = "discover_credential"
    DISCOVER_TOKEN = "discover_token"

    # Exploitation actions
    EXTRACT_DATA = "extract_data"
    EXTRACT_CREDENTIAL = "extract_credential"
    EXTRACT_TOKEN = "extract_token"
    EXTRACT_SOURCE = "extract_source"

    # Access actions
    AUTHENTICATE = "authenticate"
    ELEVATE_PRIVILEGE = "elevate_privilege"
    ACCESS_RESOURCE = "access_resource"
    BYPASS_CONTROL = "bypass_control"

    # Impact actions
    DEMONSTRATE_IMPACT = "demonstrate_impact"
    COLLECT_EVIDENCE = "collect_evidence"


class ChainPriority(Enum):
    """Priority levels for vulnerability chains."""
    CRITICAL = 10    # RCE chains, full compromise
    HIGH = 8         # Credential extraction, data access
    MEDIUM = 5       # Access control bypass
    LOW = 3          # Information disclosure
    INFO = 1         # Informational only


class ChainState(Enum):
    """State of a chain execution."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class VulnCategory(Enum):
    """Vulnerability categories for chaining."""
    INJECTION = "injection"      # SQLi, CMDi, etc.
    XSS = "xss"                  # Cross-site scripting
    SSRF = "ssrf"                # Server-side request forgery
    LFI = "lfi"                  # Local file inclusion
    IDOR = "idor"                # Insecure direct object reference
    AUTH_BYPASS = "auth_bypass"  # Authentication bypass
    AUTHZ_BYPASS = "authz_bypass"  # Authorization bypass
    INFO_DISCLOSURE = "info_disclosure"  # Information disclosure
    CREDENTIAL_LEAK = "credential_leak"  # Credential leakage
    SESSION_ATTACK = "session"   # Session-related attacks
    CONFIG_ISSUE = "config"      # Configuration issues


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class ChainVulnerability:
    """A vulnerability that can be part of a chain."""
    id: str
    category: VulnCategory
    title: str
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: str = ""
    severity: str = "medium"
    exploitable: bool = True
    extracted_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "category": self.category.value,
            "title": self.title,
            "url": self.url,
            "parameter": self.parameter,
            "severity": self.severity,
            "exploitable": self.exploitable,
            "extracted_data": self.extracted_data,
        }


@dataclass
class ChainAction:
    """A single action in a vulnerability chain."""
    action_type: ChainActionType
    source_vuln: ChainVulnerability
    target_vuln: Optional[ChainVulnerability] = None
    description: str = ""
    preconditions: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)
    evidence: str = ""
    success: bool = False
    execution_time_ms: float = 0.0
    rollback_data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "action_type": self.action_type.value,
            "source_vuln": self.source_vuln.id,
            "target_vuln": self.target_vuln.id if self.target_vuln else None,
            "description": self.description,
            "preconditions": self.preconditions,
            "postconditions": self.postconditions,
            "evidence": self.evidence,
            "success": self.success,
            "execution_time_ms": round(self.execution_time_ms, 2),
        }


@dataclass
class VulnerabilityChain:
    """A complete vulnerability chain."""
    id: str
    title: str
    description: str
    priority: ChainPriority
    vulnerabilities: List[ChainVulnerability]
    actions: List[ChainAction]
    state: ChainState = ChainState.PENDING
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    total_impact_score: float = 0.0
    evidence_collected: List[str] = field(default_factory=list)
    rollback_stack: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "priority": self.priority.name,
            "vulnerability_count": len(self.vulnerabilities),
            "action_count": len(self.actions),
            "state": self.state.value,
            "total_impact_score": round(self.total_impact_score, 2),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "actions": [a.to_dict() for a in self.actions],
            "evidence_collected": self.evidence_collected,
        }

    def get_chain_path(self) -> str:
        """Get human-readable chain path."""
        if not self.vulnerabilities:
            return ""
        return " → ".join(v.category.value.upper() for v in self.vulnerabilities)


@dataclass
class ChainExecutionResult:
    """Result of chain execution."""
    chain: VulnerabilityChain
    success: bool
    completed_actions: int
    failed_actions: int
    total_execution_time_ms: float
    impact_demonstrated: bool
    evidence: List[str]
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "chain_id": self.chain.id,
            "chain_title": self.chain.title,
            "chain_path": self.chain.get_chain_path(),
            "success": self.success,
            "completed_actions": self.completed_actions,
            "failed_actions": self.failed_actions,
            "total_execution_time_ms": round(self.total_execution_time_ms, 2),
            "impact_demonstrated": self.impact_demonstrated,
            "evidence_count": len(self.evidence),
        }


# =============================================================================
# CHAIN TEMPLATES
# =============================================================================

class ChainTemplate:
    """Templates for common attack chains."""

    # Chain templates: source_category → (target_categories, priority, description)
    CHAIN_TEMPLATES: Dict[VulnCategory, List[Tuple[VulnCategory, ChainPriority, str]]] = {
        VulnCategory.XSS: [
            (VulnCategory.SESSION_ATTACK, ChainPriority.HIGH, "XSS to Session Hijacking"),
            (VulnCategory.CREDENTIAL_LEAK, ChainPriority.HIGH, "XSS to Credential Theft"),
            (VulnCategory.AUTHZ_BYPASS, ChainPriority.MEDIUM, "XSS to Authorization Bypass"),
        ],
        VulnCategory.SSRF: [
            (VulnCategory.CREDENTIAL_LEAK, ChainPriority.CRITICAL, "SSRF to Cloud Credential Leak"),
            (VulnCategory.INFO_DISCLOSURE, ChainPriority.HIGH, "SSRF to Internal Network Discovery"),
            (VulnCategory.LFI, ChainPriority.HIGH, "SSRF to Local File Read"),
        ],
        VulnCategory.INJECTION: [
            (VulnCategory.CREDENTIAL_LEAK, ChainPriority.CRITICAL, "SQLi to Credential Extraction"),
            (VulnCategory.AUTH_BYPASS, ChainPriority.CRITICAL, "SQLi to Authentication Bypass"),
            (VulnCategory.INFO_DISCLOSURE, ChainPriority.HIGH, "SQLi to Data Exfiltration"),
        ],
        VulnCategory.LFI: [
            (VulnCategory.CREDENTIAL_LEAK, ChainPriority.CRITICAL, "LFI to Credential Discovery"),
            (VulnCategory.INFO_DISCLOSURE, ChainPriority.HIGH, "LFI to Source Code Leak"),
            (VulnCategory.CONFIG_ISSUE, ChainPriority.HIGH, "LFI to Configuration Leak"),
        ],
        VulnCategory.IDOR: [
            (VulnCategory.INFO_DISCLOSURE, ChainPriority.HIGH, "IDOR to PII Access"),
            (VulnCategory.AUTHZ_BYPASS, ChainPriority.HIGH, "IDOR to Privilege Escalation"),
            (VulnCategory.CREDENTIAL_LEAK, ChainPriority.MEDIUM, "IDOR to Credential Access"),
        ],
        VulnCategory.AUTH_BYPASS: [
            (VulnCategory.AUTHZ_BYPASS, ChainPriority.CRITICAL, "Auth Bypass to Admin Access"),
            (VulnCategory.INFO_DISCLOSURE, ChainPriority.HIGH, "Auth Bypass to Data Access"),
        ],
        VulnCategory.INFO_DISCLOSURE: [
            (VulnCategory.CREDENTIAL_LEAK, ChainPriority.HIGH, "Info Disclosure to Credential Discovery"),
            (VulnCategory.AUTH_BYPASS, ChainPriority.MEDIUM, "Info Disclosure to Auth Bypass"),
        ],
        VulnCategory.CREDENTIAL_LEAK: [
            (VulnCategory.AUTH_BYPASS, ChainPriority.CRITICAL, "Credential Leak to Account Takeover"),
            (VulnCategory.AUTHZ_BYPASS, ChainPriority.CRITICAL, "Credential Leak to Privilege Escalation"),
        ],
    }

    # Multi-step chain templates
    COMPLEX_CHAINS: List[Tuple[List[VulnCategory], ChainPriority, str]] = [
        (
            [VulnCategory.XSS, VulnCategory.SESSION_ATTACK, VulnCategory.AUTHZ_BYPASS],
            ChainPriority.CRITICAL,
            "XSS → Session Hijack → Admin Takeover"
        ),
        (
            [VulnCategory.SSRF, VulnCategory.CREDENTIAL_LEAK, VulnCategory.AUTH_BYPASS],
            ChainPriority.CRITICAL,
            "SSRF → AWS Creds → Cloud Compromise"
        ),
        (
            [VulnCategory.INJECTION, VulnCategory.CREDENTIAL_LEAK, VulnCategory.AUTH_BYPASS],
            ChainPriority.CRITICAL,
            "SQLi → Credentials → Account Takeover"
        ),
        (
            [VulnCategory.LFI, VulnCategory.INFO_DISCLOSURE, VulnCategory.CREDENTIAL_LEAK, VulnCategory.AUTH_BYPASS],
            ChainPriority.CRITICAL,
            "LFI → Source → Creds → Takeover"
        ),
        (
            [VulnCategory.IDOR, VulnCategory.INFO_DISCLOSURE, VulnCategory.CREDENTIAL_LEAK],
            ChainPriority.HIGH,
            "IDOR → PII → Credential Discovery"
        ),
    ]

    @classmethod
    def get_possible_chains(
        cls,
        source_category: VulnCategory,
    ) -> List[Tuple[VulnCategory, ChainPriority, str]]:
        """Get possible chain targets for a source vulnerability."""
        return cls.CHAIN_TEMPLATES.get(source_category, [])

    @classmethod
    def get_complex_chains_for(
        cls,
        starting_category: VulnCategory,
    ) -> List[Tuple[List[VulnCategory], ChainPriority, str]]:
        """Get complex chains starting with given category."""
        return [
            chain for chain in cls.COMPLEX_CHAINS
            if chain[0][0] == starting_category
        ]


# =============================================================================
# ACTION EXECUTORS
# =============================================================================

class BaseActionExecutor(ABC):
    """Base class for chain action executors."""

    @abstractmethod
    async def execute(
        self,
        action: ChainAction,
        context: Dict[str, Any],
        http_client: httpx.AsyncClient,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Execute the action.

        Args:
            action: The action to execute
            context: Execution context with extracted data
            http_client: HTTP client for requests

        Returns:
            (success, evidence, extracted_data)
        """
        pass

    @abstractmethod
    async def rollback(
        self,
        action: ChainAction,
        rollback_data: Dict[str, Any],
        http_client: httpx.AsyncClient,
    ) -> bool:
        """
        Rollback the action.

        Args:
            action: The action to rollback
            rollback_data: Data needed for rollback
            http_client: HTTP client

        Returns:
            True if rollback successful
        """
        pass


class ExtractDataExecutor(BaseActionExecutor):
    """Executor for data extraction actions."""

    # Patterns to extract from responses
    EXTRACTION_PATTERNS = {
        "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "phone": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
        "credit_card": r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
        "api_key": r'(?i)(api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_-]{20,})["\']?',
        "aws_key": r'AKIA[0-9A-Z]{16}',
        "password_hash": r'\$2[aby]?\$\d{1,2}\$[./A-Za-z0-9]{53}',
        "jwt": r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
        "internal_ip": r'\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b',
        "username": r'(?i)(username|user|login)["\s:=]+["\']?([a-zA-Z0-9_.-]+)["\']?',
    }

    async def execute(
        self,
        action: ChainAction,
        context: Dict[str, Any],
        http_client: httpx.AsyncClient,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Execute data extraction."""
        response_text = context.get("last_response", "")
        extracted = {}

        for data_type, pattern in self.EXTRACTION_PATTERNS.items():
            matches = re.findall(pattern, response_text)
            if matches:
                # Handle tuple matches from groups
                if isinstance(matches[0], tuple):
                    matches = [m[-1] for m in matches]
                extracted[data_type] = list(set(matches))[:10]  # Limit to 10

        if extracted:
            evidence = f"Extracted {len(extracted)} data types: {list(extracted.keys())}"
            return True, evidence, extracted

        return False, "No sensitive data patterns found", {}

    async def rollback(
        self,
        action: ChainAction,
        rollback_data: Dict[str, Any],
        http_client: httpx.AsyncClient,
    ) -> bool:
        """Rollback is not needed for extraction (read-only)."""
        return True


class ExtractCredentialExecutor(BaseActionExecutor):
    """Executor for credential extraction actions."""

    CREDENTIAL_PATTERNS = {
        "password": [
            r'(?i)password["\s:=]+["\']?([^\s"\'<>]{4,})["\']?',
            r'(?i)passwd["\s:=]+["\']?([^\s"\'<>]{4,})["\']?',
            r'(?i)pwd["\s:=]+["\']?([^\s"\'<>]{4,})["\']?',
        ],
        "api_key": [
            r'(?i)api[_-]?key["\s:=]+["\']?([a-zA-Z0-9_-]{16,})["\']?',
            r'(?i)secret[_-]?key["\s:=]+["\']?([a-zA-Z0-9_-]{16,})["\']?',
        ],
        "token": [
            r'(?i)token["\s:=]+["\']?([a-zA-Z0-9_.-]{20,})["\']?',
            r'(?i)bearer\s+([a-zA-Z0-9_.-]+)',
        ],
        "aws": [
            r'(AKIA[0-9A-Z]{16})',
            r'(?i)aws[_-]?secret[_-]?access[_-]?key["\s:=]+["\']?([a-zA-Z0-9/+=]{40})["\']?',
        ],
        "database": [
            r'(?i)(?:mysql|postgres|mongodb)://([^@\s]+)@',
            r'(?i)db[_-]?password["\s:=]+["\']?([^\s"\'<>]+)["\']?',
        ],
    }

    async def execute(
        self,
        action: ChainAction,
        context: Dict[str, Any],
        http_client: httpx.AsyncClient,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Execute credential extraction."""
        response_text = context.get("last_response", "")
        credentials = {}

        for cred_type, patterns in self.CREDENTIAL_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, response_text)
                if matches:
                    if cred_type not in credentials:
                        credentials[cred_type] = []
                    credentials[cred_type].extend(matches[:5])

        if credentials:
            # Mask sensitive values for evidence
            masked = {k: f"[{len(v)} found]" for k, v in credentials.items()}
            evidence = f"Credentials extracted: {masked}"
            return True, evidence, {"credentials": credentials}

        return False, "No credentials found in response", {}

    async def rollback(
        self,
        action: ChainAction,
        rollback_data: Dict[str, Any],
        http_client: httpx.AsyncClient,
    ) -> bool:
        """Rollback is not needed for extraction (read-only)."""
        return True


class AccessResourceExecutor(BaseActionExecutor):
    """Executor for resource access actions."""

    async def execute(
        self,
        action: ChainAction,
        context: Dict[str, Any],
        http_client: httpx.AsyncClient,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Execute resource access."""
        target_url = action.source_vuln.url
        credentials = context.get("credentials", {})

        headers = {}
        cookies = {}

        # Apply extracted tokens
        if "token" in credentials:
            headers["Authorization"] = f"Bearer {credentials['token'][0]}"

        # Apply extracted session
        if "session" in context:
            cookies["session"] = context["session"]

        try:
            response = await http_client.get(
                target_url,
                headers=headers,
                cookies=cookies,
                timeout=10.0,
            )

            if response.status_code == 200:
                evidence = f"Successfully accessed {target_url} with extracted credentials"
                return True, evidence, {"response": response.text[:500]}

            elif response.status_code in [401, 403]:
                return False, f"Access denied: {response.status_code}", {}

            else:
                return False, f"Unexpected response: {response.status_code}", {}

        except Exception as e:
            return False, f"Access failed: {str(e)}", {}

    async def rollback(
        self,
        action: ChainAction,
        rollback_data: Dict[str, Any],
        http_client: httpx.AsyncClient,
    ) -> bool:
        """Rollback is not applicable for read access."""
        return True


class DemonstrateImpactExecutor(BaseActionExecutor):
    """Executor for impact demonstration actions."""

    async def execute(
        self,
        action: ChainAction,
        context: Dict[str, Any],
        http_client: httpx.AsyncClient,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Demonstrate impact without causing damage."""
        vuln = action.source_vuln
        extracted = context.get("extracted_data", {})

        impact_points = []

        # Calculate impact based on extracted data
        if "credentials" in extracted:
            creds = extracted["credentials"]
            if "password" in creds:
                impact_points.append("Password credentials exposed")
            if "aws" in creds:
                impact_points.append("AWS credentials exposed - potential cloud compromise")
            if "api_key" in creds:
                impact_points.append("API keys exposed - potential API abuse")

        if "email" in extracted:
            impact_points.append(f"{len(extracted['email'])} email addresses exposed")

        if "credit_card" in extracted:
            impact_points.append("Payment card data exposed - PCI DSS violation")

        if "internal_ip" in extracted:
            impact_points.append("Internal network information disclosed")

        if impact_points:
            evidence = "Impact demonstrated: " + "; ".join(impact_points)
            return True, evidence, {"impact_points": impact_points}

        return False, "Could not demonstrate significant impact", {}

    async def rollback(
        self,
        action: ChainAction,
        rollback_data: Dict[str, Any],
        http_client: httpx.AsyncClient,
    ) -> bool:
        """No rollback needed for read-only demonstration."""
        return True


# =============================================================================
# CHAIN DISCOVERY
# =============================================================================

class ChainDiscovery:
    """Discovers possible vulnerability chains."""

    def __init__(self):
        self.templates = ChainTemplate()

    def discover_chains(
        self,
        vulnerabilities: List[ChainVulnerability],
        max_chains: int = 10,
    ) -> List[VulnerabilityChain]:
        """
        Discover possible chains from a list of vulnerabilities.

        Args:
            vulnerabilities: List of discovered vulnerabilities
            max_chains: Maximum chains to return

        Returns:
            List of discovered chains
        """
        chains: List[VulnerabilityChain] = []

        # Group vulnerabilities by category
        by_category: Dict[VulnCategory, List[ChainVulnerability]] = defaultdict(list)
        for vuln in vulnerabilities:
            by_category[vuln.category].append(vuln)

        # Find simple two-step chains
        for source_cat, source_vulns in by_category.items():
            possible_targets = self.templates.get_possible_chains(source_cat)

            for target_cat, priority, description in possible_targets:
                if target_cat in by_category:
                    for source in source_vulns:
                        for target in by_category[target_cat]:
                            chain = self._create_chain(
                                [source, target],
                                priority,
                                description,
                            )
                            chains.append(chain)

        # Find complex multi-step chains
        for chain_template, priority, description in self.templates.COMPLEX_CHAINS:
            chain_vulns = []
            all_present = True

            for cat in chain_template:
                if cat in by_category:
                    chain_vulns.append(by_category[cat][0])
                else:
                    all_present = False
                    break

            if all_present and len(chain_vulns) >= 2:
                chain = self._create_chain(chain_vulns, priority, description)
                chains.append(chain)

        # Sort by priority and limit
        chains.sort(key=lambda c: c.priority.value, reverse=True)
        return chains[:max_chains]

    def _create_chain(
        self,
        vulns: List[ChainVulnerability],
        priority: ChainPriority,
        description: str,
    ) -> VulnerabilityChain:
        """Create a chain from vulnerabilities."""
        chain_id = hashlib.md5(
            "|".join(v.id for v in vulns).encode()
        ).hexdigest()[:8]

        # Create actions between vulnerabilities
        actions = []
        for i in range(len(vulns) - 1):
            source = vulns[i]
            target = vulns[i + 1]

            action = ChainAction(
                action_type=self._get_action_type(source.category, target.category),
                source_vuln=source,
                target_vuln=target,
                description=f"Chain {source.category.value} to {target.category.value}",
                preconditions=[f"{source.category.value} exploitable"],
                postconditions=[f"{target.category.value} data available"],
            )
            actions.append(action)

        # Add final impact action
        if vulns:
            actions.append(ChainAction(
                action_type=ChainActionType.DEMONSTRATE_IMPACT,
                source_vuln=vulns[-1],
                description="Demonstrate chain impact",
            ))

        return VulnerabilityChain(
            id=chain_id,
            title=description,
            description=f"Chain: {' → '.join(v.category.value for v in vulns)}",
            priority=priority,
            vulnerabilities=vulns,
            actions=actions,
        )

    def _get_action_type(
        self,
        source_cat: VulnCategory,
        target_cat: VulnCategory,
    ) -> ChainActionType:
        """Determine action type based on source and target categories."""
        if target_cat == VulnCategory.CREDENTIAL_LEAK:
            return ChainActionType.EXTRACT_CREDENTIAL
        elif target_cat == VulnCategory.INFO_DISCLOSURE:
            return ChainActionType.EXTRACT_DATA
        elif target_cat in [VulnCategory.AUTH_BYPASS, VulnCategory.AUTHZ_BYPASS]:
            return ChainActionType.BYPASS_CONTROL
        elif target_cat == VulnCategory.SESSION_ATTACK:
            return ChainActionType.EXTRACT_TOKEN
        else:
            return ChainActionType.ACCESS_RESOURCE


# =============================================================================
# CHAIN EXECUTOR
# =============================================================================

class ChainExecutor:
    """Executes vulnerability chains safely."""

    VERSION = "3.0.0"

    def __init__(self):
        """Initialize the chain executor."""
        self.executors: Dict[ChainActionType, BaseActionExecutor] = {
            ChainActionType.EXTRACT_DATA: ExtractDataExecutor(),
            ChainActionType.EXTRACT_CREDENTIAL: ExtractCredentialExecutor(),
            ChainActionType.ACCESS_RESOURCE: AccessResourceExecutor(),
            ChainActionType.DEMONSTRATE_IMPACT: DemonstrateImpactExecutor(),
        }

        self._http_client: Optional[httpx.AsyncClient] = None
        self._stats = {
            "chains_executed": 0,
            "chains_successful": 0,
            "actions_executed": 0,
            "actions_successful": 0,
        }

        logger.info(f"ChainExecutor v{self.VERSION} initialized")

    async def execute_chain(
        self,
        chain: VulnerabilityChain,
        initial_context: Optional[Dict[str, Any]] = None,
        stop_on_failure: bool = False,
    ) -> ChainExecutionResult:
        """
        Execute a vulnerability chain.

        Args:
            chain: The chain to execute
            initial_context: Initial execution context
            stop_on_failure: Stop chain if an action fails

        Returns:
            ChainExecutionResult with execution details
        """
        start_time = time.time()
        context = initial_context or {}
        completed_actions = 0
        failed_actions = 0
        evidence: List[str] = []

        # Initialize HTTP client
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                verify=False,
            )

        chain.state = ChainState.RUNNING
        chain.start_time = start_time

        logger.info(f"Executing chain: {chain.title} ({len(chain.actions)} actions)")

        try:
            for action in chain.actions:
                action_start = time.time()

                executor = self.executors.get(action.action_type)
                if not executor:
                    logger.warning(f"No executor for action type: {action.action_type}")
                    action.success = False
                    failed_actions += 1
                    continue

                # Execute action
                try:
                    success, action_evidence, extracted = await executor.execute(
                        action, context, self._http_client
                    )

                    action.success = success
                    action.evidence = action_evidence
                    action.execution_time_ms = (time.time() - action_start) * 1000

                    if success:
                        completed_actions += 1
                        evidence.append(action_evidence)
                        context.update(extracted)
                        context["extracted_data"] = context.get("extracted_data", {})
                        context["extracted_data"].update(extracted)

                        # Store rollback data
                        action.rollback_data = {"context_before": context.copy()}
                        chain.rollback_stack.append({
                            "action": action,
                            "data": action.rollback_data,
                        })
                    else:
                        failed_actions += 1
                        if stop_on_failure:
                            logger.info(f"Chain stopped due to failure: {action_evidence}")
                            break

                except Exception as e:
                    logger.error(f"Action execution error: {e}")
                    action.success = False
                    failed_actions += 1
                    if stop_on_failure:
                        break

                self._stats["actions_executed"] += 1
                if action.success:
                    self._stats["actions_successful"] += 1

        except Exception as e:
            logger.error(f"Chain execution error: {e}")
            chain.state = ChainState.FAILED
            return ChainExecutionResult(
                chain=chain,
                success=False,
                completed_actions=completed_actions,
                failed_actions=failed_actions,
                total_execution_time_ms=(time.time() - start_time) * 1000,
                impact_demonstrated=False,
                evidence=evidence,
                error_message=str(e),
            )

        # Determine success
        chain.end_time = time.time()
        chain.evidence_collected = evidence
        success = completed_actions > 0 and failed_actions == 0
        impact_demonstrated = any(
            a.action_type == ChainActionType.DEMONSTRATE_IMPACT and a.success
            for a in chain.actions
        )

        chain.state = ChainState.COMPLETED if success else ChainState.FAILED

        self._stats["chains_executed"] += 1
        if success:
            self._stats["chains_successful"] += 1

        logger.info(
            f"Chain complete: {completed_actions} succeeded, "
            f"{failed_actions} failed, impact: {impact_demonstrated}"
        )

        return ChainExecutionResult(
            chain=chain,
            success=success,
            completed_actions=completed_actions,
            failed_actions=failed_actions,
            total_execution_time_ms=(time.time() - start_time) * 1000,
            impact_demonstrated=impact_demonstrated,
            evidence=evidence,
        )

    async def rollback_chain(
        self,
        chain: VulnerabilityChain,
    ) -> bool:
        """
        Rollback a chain execution.

        Args:
            chain: The chain to rollback

        Returns:
            True if rollback successful
        """
        logger.info(f"Rolling back chain: {chain.title}")

        success = True
        while chain.rollback_stack:
            rollback_item = chain.rollback_stack.pop()
            action = rollback_item["action"]
            data = rollback_item["data"]

            executor = self.executors.get(action.action_type)
            if executor:
                try:
                    rollback_success = await executor.rollback(
                        action, data, self._http_client
                    )
                    if not rollback_success:
                        success = False
                except Exception as e:
                    logger.error(f"Rollback error: {e}")
                    success = False

        chain.state = ChainState.ROLLED_BACK
        return success

    def get_statistics(self) -> Dict[str, Any]:
        """Get executor statistics."""
        return {
            "version": self.VERSION,
            "chains_executed": self._stats["chains_executed"],
            "chains_successful": self._stats["chains_successful"],
            "actions_executed": self._stats["actions_executed"],
            "actions_successful": self._stats["actions_successful"],
            "success_rate": (
                self._stats["chains_successful"] / self._stats["chains_executed"]
                if self._stats["chains_executed"] > 0 else 0
            ),
        }

    async def close(self) -> None:
        """Close resources."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None


# =============================================================================
# MAIN CHAIN ENGINE
# =============================================================================

class ChainActionsEngine:
    """
    PHANTOM AI Chain Actions Engine.

    Discovers, prioritizes, and executes vulnerability chains
    to demonstrate real-world attack impact.
    """

    VERSION = "3.0.0"

    def __init__(self):
        """Initialize the chain engine."""
        self.discovery = ChainDiscovery()
        self.executor = ChainExecutor()
        self._discovered_chains: List[VulnerabilityChain] = []

        logger.info(f"ChainActionsEngine v{self.VERSION} initialized")

    async def analyze_and_chain(
        self,
        vulnerabilities: List[ChainVulnerability],
        execute: bool = True,
        max_chains: int = 5,
    ) -> List[ChainExecutionResult]:
        """
        Analyze vulnerabilities and execute chains.

        Args:
            vulnerabilities: List of discovered vulnerabilities
            execute: Whether to execute the chains
            max_chains: Maximum chains to execute

        Returns:
            List of execution results
        """
        # Discover chains
        self._discovered_chains = self.discovery.discover_chains(
            vulnerabilities, max_chains=max_chains
        )

        logger.info(f"Discovered {len(self._discovered_chains)} chains")

        if not execute:
            return []

        # Execute chains
        results = []
        for chain in self._discovered_chains[:max_chains]:
            result = await self.executor.execute_chain(chain)
            results.append(result)

        return results

    def get_discovered_chains(self) -> List[VulnerabilityChain]:
        """Get discovered chains."""
        return self._discovered_chains

    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics."""
        return {
            "version": self.VERSION,
            "discovered_chains": len(self._discovered_chains),
            "executor": self.executor.get_statistics(),
        }

    async def close(self) -> None:
        """Close resources."""
        await self.executor.close()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_vulnerability(
    id: str,
    category: str,
    title: str,
    url: str,
    **kwargs,
) -> ChainVulnerability:
    """Create a ChainVulnerability with minimal parameters."""
    cat = VulnCategory(category) if category in [c.value for c in VulnCategory] else VulnCategory.INFO_DISCLOSURE
    return ChainVulnerability(id=id, category=cat, title=title, url=url, **kwargs)


async def analyze_chains(
    vulnerabilities: List[ChainVulnerability],
    execute: bool = True,
) -> List[ChainExecutionResult]:
    """Convenience function to analyze and execute chains."""
    engine = ChainActionsEngine()
    try:
        return await engine.analyze_and_chain(vulnerabilities, execute=execute)
    finally:
        await engine.close()


# =============================================================================
# MODULE TEST
# =============================================================================

if __name__ == "__main__":
    import asyncio

    async def test_chain_engine():
        """Test the chain engine."""
        print("=" * 60)
        print("PHANTOM AI - Chain Actions Engine Test")
        print("=" * 60)

        # Create test vulnerabilities
        vulns = [
            ChainVulnerability(
                id="vuln-001",
                category=VulnCategory.INJECTION,
                title="SQL Injection in login",
                url="https://example.com/login",
                parameter="username",
                severity="critical",
            ),
            ChainVulnerability(
                id="vuln-002",
                category=VulnCategory.CREDENTIAL_LEAK,
                title="Password hash disclosure",
                url="https://example.com/api/users",
                severity="critical",
            ),
            ChainVulnerability(
                id="vuln-003",
                category=VulnCategory.AUTH_BYPASS,
                title="Authentication bypass",
                url="https://example.com/admin",
                severity="critical",
            ),
            ChainVulnerability(
                id="vuln-004",
                category=VulnCategory.XSS,
                title="Stored XSS in comments",
                url="https://example.com/comments",
                parameter="body",
                severity="high",
            ),
            ChainVulnerability(
                id="vuln-005",
                category=VulnCategory.SESSION_ATTACK,
                title="Session fixation",
                url="https://example.com/login",
                severity="high",
            ),
        ]

        # Create engine
        engine = ChainActionsEngine()

        print(f"\n✅ ChainActionsEngine v{engine.VERSION} created")

        # Discover chains (without executing)
        print(f"\n🔍 Discovering chains from {len(vulns)} vulnerabilities...")

        discovered = engine.discovery.discover_chains(vulns, max_chains=10)

        print(f"\n📊 Discovered {len(discovered)} chains:")
        for chain in discovered[:5]:
            print(f"\n   🔗 {chain.title}")
            print(f"      Path: {chain.get_chain_path()}")
            print(f"      Priority: {chain.priority.name}")
            print(f"      Steps: {len(chain.actions)}")

        # Get statistics
        stats = engine.get_statistics()
        print(f"\n📈 Statistics:")
        print(f"   Version: {stats['version']}")
        print(f"   Discovered: {stats['discovered_chains']}")

        await engine.close()

        print("\n" + "=" * 60)
        print("✅ Chain Actions Engine test complete!")
        print("=" * 60)

    asyncio.run(test_chain_engine())
