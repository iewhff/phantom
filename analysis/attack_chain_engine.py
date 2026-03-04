"""
Attack Chain Engine - Vulnerability Chain Analysis.
Links isolated vulnerabilities into real attack chains showing business impact.
"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from collections import defaultdict
from urllib.parse import urlparse

from utils.logger import get_logger

logger = get_logger(__name__)

# Maximum chains to emit — prevents combinatorial explosion
MAX_CHAINS = 50


class AttackPhase(Enum):
    """MITRE ATT&CK inspired attack phases."""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class ImpactType(Enum):
    """Business impact categories."""
    DATA_BREACH = "data_breach"
    FINANCIAL_LOSS = "financial_loss"
    SERVICE_DISRUPTION = "service_disruption"
    REPUTATION_DAMAGE = "reputation_damage"
    COMPLIANCE_VIOLATION = "compliance_violation"
    RANSOMWARE = "ransomware"
    SUPPLY_CHAIN = "supply_chain"
    ACCOUNT_TAKEOVER = "account_takeover"


@dataclass
class ChainNode:
    """A single node in an attack chain."""
    id: str
    name: str
    description: str
    phase: AttackPhase
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cvss: float
    cwe: str
    owasp: str
    endpoint: str
    evidence: list[str]
    finding_ref: Optional[str] = None
    technique_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "phase": self.phase.value,
            "severity": self.severity,
            "cvss": self.cvss,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "endpoint": self.endpoint,
            "evidence": self.evidence,
            "finding_ref": self.finding_ref,
            "technique_id": self.technique_id,
        }


@dataclass
class AttackChain:
    """A complete attack chain from initial access to impact."""
    id: str
    name: str
    description: str
    nodes: list[ChainNode]
    edges: list[tuple[str, str]]
    total_cvss: float
    max_severity: str
    impact_type: ImpactType
    business_impact: str
    likelihood: str  # HIGH, MEDIUM, LOW
    exploitability: str  # EASY, MODERATE, DIFFICULT
    remediation_priority: int  # 1-10
    estimated_time_to_exploit: str
    unique_endpoints: int = 0
    phase_depth: int = 0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": self.edges,
            "total_cvss": self.total_cvss,
            "max_severity": self.max_severity,
            "impact_type": self.impact_type.value,
            "business_impact": self.business_impact,
            "likelihood": self.likelihood,
            "exploitability": self.exploitability,
            "remediation_priority": self.remediation_priority,
            "estimated_time_to_exploit": self.estimated_time_to_exploit,
            "unique_endpoints": self.unique_endpoints,
            "phase_depth": self.phase_depth,
        }


# Phases that logically connect to any endpoint (not bound to same host)
_UNIVERSAL_CONNECTOR_PHASES = frozenset({
    AttackPhase.CREDENTIAL_ACCESS,
    AttackPhase.DEFENSE_EVASION,
    AttackPhase.LATERAL_MOVEMENT,
    AttackPhase.EXFILTRATION,
    AttackPhase.IMPACT,
})

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

_PHASE_ORDER = [
    AttackPhase.RECONNAISSANCE,
    AttackPhase.INITIAL_ACCESS,
    AttackPhase.EXECUTION,
    AttackPhase.PERSISTENCE,
    AttackPhase.PRIVILEGE_ESCALATION,
    AttackPhase.DEFENSE_EVASION,
    AttackPhase.CREDENTIAL_ACCESS,
    AttackPhase.DISCOVERY,
    AttackPhase.LATERAL_MOVEMENT,
    AttackPhase.COLLECTION,
    AttackPhase.EXFILTRATION,
    AttackPhase.IMPACT,
]


class AttackChainEngine:
    """
    Engine that analyzes vulnerabilities and builds attack chains.

    Features:
    - Automatic chain detection from findings
    - MITRE ATT&CK mapping
    - Business impact analysis
    - Executive summary generation
    """

    # Vulnerability keyword → attack phase mapping
    VULN_PHASE_MAP = {
        # Reconnaissance
        "information_disclosure": AttackPhase.RECONNAISSANCE,
        "directory_listing": AttackPhase.RECONNAISSANCE,
        "version_disclosure": AttackPhase.RECONNAISSANCE,
        "subdomain": AttackPhase.RECONNAISSANCE,
        "dns": AttackPhase.RECONNAISSANCE,
        "metadata": AttackPhase.RECONNAISSANCE,
        "introspection": AttackPhase.RECONNAISSANCE,
        "fingerprint": AttackPhase.RECONNAISSANCE,
        "enumeration": AttackPhase.RECONNAISSANCE,

        # Initial Access
        "sqli": AttackPhase.INITIAL_ACCESS,
        "sql injection": AttackPhase.INITIAL_ACCESS,
        "authentication_bypass": AttackPhase.INITIAL_ACCESS,
        "default_credentials": AttackPhase.INITIAL_ACCESS,
        "jwt": AttackPhase.INITIAL_ACCESS,
        "oauth": AttackPhase.INITIAL_ACCESS,
        "saml": AttackPhase.INITIAL_ACCESS,
        "sso": AttackPhase.INITIAL_ACCESS,
        "login": AttackPhase.INITIAL_ACCESS,
        "mfa_bypass": AttackPhase.INITIAL_ACCESS,
        "phishing": AttackPhase.INITIAL_ACCESS,
        "open_redirect": AttackPhase.INITIAL_ACCESS,

        # Execution
        "rce": AttackPhase.EXECUTION,
        "command_injection": AttackPhase.EXECUTION,
        "code_injection": AttackPhase.EXECUTION,
        "ssti": AttackPhase.EXECUTION,
        "deserialization": AttackPhase.EXECUTION,
        "xxe": AttackPhase.EXECUTION,
        "xss": AttackPhase.EXECUTION,
        "prototype_pollution": AttackPhase.EXECUTION,

        # Privilege Escalation
        "idor": AttackPhase.PRIVILEGE_ESCALATION,
        "privilege": AttackPhase.PRIVILEGE_ESCALATION,
        "vertical_access": AttackPhase.PRIVILEGE_ESCALATION,
        "admin": AttackPhase.PRIVILEGE_ESCALATION,
        "authorization": AttackPhase.PRIVILEGE_ESCALATION,
        "rbac": AttackPhase.PRIVILEGE_ESCALATION,
        "mass_assignment": AttackPhase.PRIVILEGE_ESCALATION,

        # Credential Access
        "credential": AttackPhase.CREDENTIAL_ACCESS,
        "password": AttackPhase.CREDENTIAL_ACCESS,
        "api_key": AttackPhase.CREDENTIAL_ACCESS,
        "token": AttackPhase.CREDENTIAL_ACCESS,
        "secret": AttackPhase.CREDENTIAL_ACCESS,
        "hardcoded": AttackPhase.CREDENTIAL_ACCESS,

        # Defense Evasion
        "waf_bypass": AttackPhase.DEFENSE_EVASION,
        "rate_limit_bypass": AttackPhase.DEFENSE_EVASION,
        "smuggling": AttackPhase.DEFENSE_EVASION,
        "cache_poisoning": AttackPhase.DEFENSE_EVASION,
        "crlf": AttackPhase.DEFENSE_EVASION,

        # Lateral Movement
        "ssrf": AttackPhase.LATERAL_MOVEMENT,
        "dns_rebinding": AttackPhase.LATERAL_MOVEMENT,
        "internal": AttackPhase.LATERAL_MOVEMENT,
        "kubernetes": AttackPhase.LATERAL_MOVEMENT,
        "container": AttackPhase.LATERAL_MOVEMENT,

        # Collection
        "data_exposure": AttackPhase.COLLECTION,
        "sensitive_data": AttackPhase.COLLECTION,
        "pii": AttackPhase.COLLECTION,
        "file_read": AttackPhase.COLLECTION,
        "lfi": AttackPhase.COLLECTION,
        "path_traversal": AttackPhase.COLLECTION,
        "file_upload": AttackPhase.COLLECTION,

        # Exfiltration
        "exfiltration": AttackPhase.EXFILTRATION,
        "data_leak": AttackPhase.EXFILTRATION,
        "export": AttackPhase.EXFILTRATION,

        # Impact
        "dos": AttackPhase.IMPACT,
        "ransomware": AttackPhase.IMPACT,
        "defacement": AttackPhase.IMPACT,
        "destruction": AttackPhase.IMPACT,
        "account_takeover": AttackPhase.IMPACT,
    }

    # Chain patterns that commonly lead to critical impact
    CRITICAL_CHAIN_PATTERNS = [
        # Auth bypass → Data access
        (["authentication_bypass", "jwt", "oauth", "saml", "mfa_bypass"],
         ["idor", "data_exposure", "pii"]),

        # Injection → RCE
        (["sqli", "ssti", "command_injection", "deserialization"],
         ["rce", "code_injection"]),

        # SSRF → Internal access → Data
        (["ssrf", "dns_rebinding"],
         ["internal", "kubernetes", "metadata"],
         ["credential", "secret", "data_exposure"]),

        # Info disclosure → Exploitation
        (["information_disclosure", "introspection", "version_disclosure"],
         ["sqli", "rce", "authentication_bypass"]),

        # Privilege escalation chain
        (["authentication_bypass", "jwt"],
         ["idor", "authorization"],
         ["admin", "privilege"]),

        # XSS → Account takeover
        (["xss", "dom_xss", "reflected_xss"],
         ["session", "cookie", "token"],
         ["account_takeover", "privilege"]),

        # File upload → RCE
        (["file_upload", "unrestricted_upload"],
         ["rce", "code_injection", "command_injection"]),

        # CORS → Data theft
        (["cors", "permissive_cors"],
         ["credential", "token", "data_exposure"]),

        # Open redirect → OAuth token theft
        (["open_redirect"],
         ["oauth", "token", "session"]),

        # LFI → Credential access → Lateral movement
        (["lfi", "path_traversal", "file_read"],
         ["credential", "secret", "api_key"],
         ["ssrf", "internal", "lateral_movement"]),
    ]

    # MITRE ATT&CK technique mapping
    MITRE_MAP = {
        "sql injection": "T1190",
        "sqli": "T1190",
        "command injection": "T1059",
        "rce": "T1059",
        "remote code execution": "T1059",
        "deserialization": "T1059.007",
        "xss": "T1059.007",
        "cross-site scripting": "T1059.007",
        "ssti": "T1059",
        "template injection": "T1059",
        "xxe": "T1611",
        "xml external entity": "T1611",
        "credential": "T1552",
        "password": "T1552.001",
        "hardcoded": "T1552.001",
        "api_key": "T1552.004",
        "token": "T1528",
        "ssrf": "T1090",
        "server-side request": "T1090",
        "idor": "T1078",
        "privilege": "T1068",
        "authentication bypass": "T1078.001",
        "brute force": "T1110",
        "data exfil": "T1041",
        "lfi": "T1005",
        "path traversal": "T1005",
        "local file inclusion": "T1005",
        "file upload": "T1105",
        "unrestricted upload": "T1105",
        "cors": "T1557",
        "clickjacking": "T1185",
        "open redirect": "T1566.002",
        "subdomain takeover": "T1584.001",
        "prototype pollution": "T1059",
        "race condition": "T1499",
        "cache poisoning": "T1557.003",
        "crlf": "T1059",
        "http smuggling": "T1090.002",
        "session fixation": "T1563",
        "session hijacking": "T1563",
        "mfa bypass": "T1111",
        "graphql": "T1595.002",
        "introspection": "T1595.002",
        "container escape": "T1611",
        "cloud metadata": "T1552.005",
        "kubernetes": "T1609",
        "oauth": "T1550.001",
        "saml": "T1550.001",
        "jwt": "T1550.001",
        "dos": "T1499",
        "denial of service": "T1499",
        "account takeover": "T1078",
    }

    # OWASP Top 10 keyword mapping
    OWASP_MAP = {
        "injection": "A03:2021-Injection",
        "sqli": "A03:2021-Injection",
        "sql injection": "A03:2021-Injection",
        "xss": "A03:2021-Injection",
        "cross-site scripting": "A03:2021-Injection",
        "command": "A03:2021-Injection",
        "xxe": "A03:2021-Injection",
        "ssti": "A03:2021-Injection",
        "ldap": "A03:2021-Injection",
        "xpath": "A03:2021-Injection",
        "nosql": "A03:2021-Injection",
        "crlf": "A03:2021-Injection",

        "authentication": "A07:2021-Auth Failures",
        "jwt": "A07:2021-Auth Failures",
        "oauth": "A07:2021-Auth Failures",
        "saml": "A07:2021-Auth Failures",
        "mfa": "A07:2021-Auth Failures",
        "session": "A07:2021-Auth Failures",
        "credential": "A07:2021-Auth Failures",
        "brute force": "A07:2021-Auth Failures",

        "access control": "A01:2021-Broken Access Control",
        "idor": "A01:2021-Broken Access Control",
        "authorization": "A01:2021-Broken Access Control",
        "privilege": "A01:2021-Broken Access Control",
        "cors": "A01:2021-Broken Access Control",
        "open redirect": "A01:2021-Broken Access Control",
        "path traversal": "A01:2021-Broken Access Control",

        "crypto": "A02:2021-Cryptographic Failures",
        "ssl": "A02:2021-Cryptographic Failures",
        "tls": "A02:2021-Cryptographic Failures",
        "encryption": "A02:2021-Cryptographic Failures",

        "misconfiguration": "A05:2021-Security Misconfiguration",
        "header": "A05:2021-Security Misconfiguration",
        "default": "A05:2021-Security Misconfiguration",
        "clickjacking": "A05:2021-Security Misconfiguration",

        "component": "A06:2021-Vulnerable Components",
        "cve": "A06:2021-Vulnerable Components",
        "outdated": "A06:2021-Vulnerable Components",

        "deserialization": "A08:2021-Data Integrity Failures",
        "prototype pollution": "A08:2021-Data Integrity Failures",

        "logging": "A09:2021-Security Logging Failures",

        "ssrf": "A10:2021-SSRF",
        "server-side request": "A10:2021-SSRF",
    }

    def __init__(self):
        self.chains: list[AttackChain] = []
        self.findings: list[dict] = []
        self.nodes: dict[str, ChainNode] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def detect_chains(
        self,
        findings: list[dict],
        assets: list | None = None,
    ) -> list[AttackChain]:
        """
        Detect attack chains from scan findings.

        This is the primary entry point used by the orchestrator.

        Args:
            findings: Vulnerability findings from scanners.
            assets: Discovered assets (reserved for future use).

        Returns:
            List of detected attack chains sorted by priority.
        """
        _ = assets  # reserved for future asset-aware chaining
        return self.analyze(findings)

    async def analyze_findings(self, findings: list[dict]) -> list[AttackChain]:
        """Async wrapper kept for backward compatibility."""
        return self.analyze(findings)

    def analyze(self, findings: list[dict]) -> list[AttackChain]:
        """
        Core synchronous analysis — no I/O, pure computation.

        Args:
            findings: List of vulnerability findings from scanners.

        Returns:
            List of detected attack chains sorted by priority.
        """
        self.findings = findings
        self.chains = []
        self.nodes = {}

        if not findings:
            return []

        # Step 1: Convert findings to chain nodes
        self._create_nodes_from_findings(findings)

        # Step 2: Detect chains based on phase progression
        self._detect_chains()

        # Step 3: Detect chains based on known patterns
        self._detect_pattern_chains()

        # Step 4: Remove subset chains (short fragments of longer ones)
        self._prune_subset_chains()

        # Step 5: Calculate blast-radius metrics
        self._calculate_chain_metrics()

        # Step 6: Sort by priority (descending), then total CVSS (descending)
        self.chains.sort(
            key=lambda c: (c.remediation_priority, c.total_cvss),
            reverse=True,
        )

        logger.info(f"Detected {len(self.chains)} attack chains from {len(findings)} findings")

        return self.chains

    # ------------------------------------------------------------------
    # Node creation
    # ------------------------------------------------------------------

    def _create_nodes_from_findings(self, findings: list[dict]) -> None:
        """Convert vulnerability findings to chain nodes."""
        for finding in findings:
            node_id = self._generate_node_id(finding)

            phase = self._determine_phase(finding)
            owasp = self._map_to_owasp(finding)

            evidence_raw = finding.get("evidence", [])
            if isinstance(evidence_raw, str):
                evidence_raw = [evidence_raw]

            node = ChainNode(
                id=node_id,
                name=finding.get("name", "Unknown Vulnerability"),
                description=finding.get("description", ""),
                phase=phase,
                severity=finding.get("severity", "MEDIUM").upper(),
                cvss=float(finding.get("cvss", 5.0)),
                cwe=finding.get("cwe", "CWE-Unknown"),
                owasp=owasp,
                endpoint=finding.get("matched_at", finding.get("url", "Unknown")),
                evidence=evidence_raw,
                finding_ref=finding.get("id"),
                technique_id=self._map_to_mitre(finding),
            )

            self.nodes[node_id] = node

    @staticmethod
    def _generate_node_id(finding: dict) -> str:
        """Generate unique node ID from finding."""
        data = f"{finding.get('name', '')}{finding.get('matched_at', finding.get('url', ''))}"
        return hashlib.md5(data.encode()).hexdigest()[:12]

    def _determine_phase(self, finding: dict) -> AttackPhase:
        """Determine the attack phase for a finding."""
        # Respect finding-provided phase if present
        provided_phase = finding.get("attack_phase") or finding.get("phase")
        if provided_phase:
            try:
                return AttackPhase(provided_phase)
            except ValueError:
                pass

        name_lower = finding.get("name", "").lower()
        desc_lower = finding.get("description", "").lower()
        combined = f"{name_lower} {desc_lower}"

        for keyword, phase in self.VULN_PHASE_MAP.items():
            if keyword in combined:
                return phase

        severity = finding.get("severity", "MEDIUM").upper()
        if severity == "CRITICAL":
            return AttackPhase.EXECUTION
        elif severity == "HIGH":
            return AttackPhase.PRIVILEGE_ESCALATION
        return AttackPhase.DISCOVERY

    def _map_to_owasp(self, finding: dict) -> str:
        """Map finding to OWASP Top 10 category."""
        # Respect finding-provided OWASP value
        provided = finding.get("owasp", "")
        if provided and provided.startswith("A"):
            return provided

        name_lower = finding.get("name", "").lower()

        for keyword, owasp in self.OWASP_MAP.items():
            if keyword in name_lower:
                return owasp

        return "A05:2021-Security Misconfiguration"

    def _map_to_mitre(self, finding: dict) -> Optional[str]:
        """Map finding to MITRE ATT&CK technique."""
        name_lower = finding.get("name", "").lower()

        for keyword, technique in self.MITRE_MAP.items():
            if keyword in name_lower:
                return technique

        return None

    # ------------------------------------------------------------------
    # Chain detection — phase progression
    # ------------------------------------------------------------------

    def _detect_chains(self) -> None:
        """Detect attack chains by walking phase order."""
        nodes_by_phase: dict[AttackPhase, list[ChainNode]] = defaultdict(list)
        for node in self.nodes.values():
            nodes_by_phase[node.phase].append(node)

        self._find_chains_recursive([], _PHASE_ORDER, nodes_by_phase, 0)

    def _find_chains_recursive(
        self,
        current_chain: list[ChainNode],
        phase_order: list[AttackPhase],
        nodes_by_phase: dict,
        phase_idx: int,
    ) -> None:
        """Recursively find attack chains with early termination."""
        # Stop if we already have enough chains
        if len(self.chains) >= MAX_CHAINS:
            return

        if phase_idx >= len(phase_order):
            if len(current_chain) >= 2:
                self._create_chain_from_nodes(current_chain)
            return

        current_phase = phase_order[phase_idx]
        phase_nodes = nodes_by_phase.get(current_phase, [])

        if phase_nodes:
            for node in phase_nodes:
                if len(self.chains) >= MAX_CHAINS:
                    return
                if self._can_connect(current_chain, node):
                    self._find_chains_recursive(
                        current_chain + [node], phase_order, nodes_by_phase, phase_idx + 1
                    )

        # Also try skipping this phase
        self._find_chains_recursive(current_chain, phase_order, nodes_by_phase, phase_idx + 1)

    def _can_connect(self, chain: list[ChainNode], node: ChainNode) -> bool:
        """Check if a node can logically connect to the current chain."""
        if not chain:
            return True

        last_node = chain[-1]

        # Universal connector phases don't require endpoint proximity
        if node.phase in _UNIVERSAL_CONNECTOR_PHASES:
            return True
        if last_node.phase in _UNIVERSAL_CONNECTOR_PHASES:
            return True

        # Otherwise require same host/domain
        return self._same_host(last_node.endpoint, node.endpoint)

    @staticmethod
    def _same_host(ep1: str, ep2: str) -> bool:
        """Check if two endpoints share the same host."""
        if not ep1 or not ep2 or ep1 == "Unknown" or ep2 == "Unknown":
            return True  # Can't determine — allow

        try:
            host1 = urlparse(ep1).hostname or ""
            host2 = urlparse(ep2).hostname or ""
        except Exception:
            return True

        if not host1 or not host2:
            return True

        # Exact match or same base domain (api.example.com ↔ app.example.com)
        if host1 == host2:
            return True

        parts1 = host1.rsplit(".", 2)
        parts2 = host2.rsplit(".", 2)
        if len(parts1) >= 2 and len(parts2) >= 2:
            return parts1[-2:] == parts2[-2:]

        return False

    # ------------------------------------------------------------------
    # Chain detection — pattern-based
    # ------------------------------------------------------------------

    def _detect_pattern_chains(self) -> None:
        """Detect chains based on known attack patterns."""
        for pattern in self.CRITICAL_CHAIN_PATTERNS:
            if len(self.chains) >= MAX_CHAINS:
                return
            self._match_pattern(pattern)

    def _match_pattern(self, pattern: tuple) -> None:
        """Match a specific attack pattern across nodes."""
        matched_nodes: list[list[ChainNode]] = []

        for stage_keywords in pattern:
            stage_nodes = []
            for node in self.nodes.values():
                combined = f"{node.name.lower()} {node.description.lower()}"
                if any(kw in combined for kw in stage_keywords):
                    stage_nodes.append(node)

            if stage_nodes:
                matched_nodes.append(stage_nodes)
            else:
                return  # Pattern incomplete — skip

        if len(matched_nodes) >= 2:
            chain_nodes = [nodes[0] for nodes in matched_nodes]
            self._create_chain_from_nodes(chain_nodes)

    # ------------------------------------------------------------------
    # Chain creation & dedup
    # ------------------------------------------------------------------

    def _create_chain_from_nodes(self, nodes: list[ChainNode]) -> None:
        """Create an AttackChain from a list of nodes, with dedup."""
        if len(nodes) < 2:
            return
        if len(self.chains) >= MAX_CHAINS:
            return

        node_ids = frozenset(n.id for n in nodes)

        # Exact duplicate check
        for existing in self.chains:
            existing_ids = frozenset(n.id for n in existing.nodes)
            if node_ids == existing_ids:
                return

        chain_id = hashlib.md5("".join(n.id for n in nodes).encode()).hexdigest()[:8]

        total_cvss = sum(n.cvss for n in nodes)
        max_severity = self._get_max_severity([n.severity for n in nodes])
        impact_type = self._determine_impact_type(nodes)
        business_impact = self._generate_business_impact(nodes, impact_type)
        likelihood = self._calculate_likelihood(nodes)
        exploitability = self._calculate_exploitability(nodes)
        priority = self._calculate_priority(total_cvss, max_severity, likelihood)
        time_estimate = self._estimate_exploit_time(exploitability)
        edges = [(nodes[i].id, nodes[i + 1].id) for i in range(len(nodes) - 1)]
        chain_name = self._generate_chain_name(nodes, impact_type)

        chain = AttackChain(
            id=chain_id,
            name=chain_name,
            description=self._generate_chain_description(nodes),
            nodes=nodes,
            edges=edges,
            total_cvss=total_cvss,
            max_severity=max_severity,
            impact_type=impact_type,
            business_impact=business_impact,
            likelihood=likelihood,
            exploitability=exploitability,
            remediation_priority=priority,
            estimated_time_to_exploit=time_estimate,
        )

        self.chains.append(chain)

    def _prune_subset_chains(self) -> None:
        """Remove chains that are strict subsets of longer chains."""
        if len(self.chains) <= 1:
            return

        chain_id_sets = [frozenset(n.id for n in c.nodes) for c in self.chains]
        keep = []

        for i, (chain, ids) in enumerate(zip(self.chains, chain_id_sets)):
            is_subset = False
            for j, other_ids in enumerate(chain_id_sets):
                if i != j and ids < other_ids:  # strict subset
                    is_subset = True
                    break
            if not is_subset:
                keep.append(chain)

        self.chains = keep

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    @staticmethod
    def _get_max_severity(severities: list[str]) -> str:
        """Get the maximum severity from a list."""
        return max(severities, key=lambda s: _SEVERITY_ORDER.get(s.upper(), 0)).upper()

    @staticmethod
    def _determine_impact_type(nodes: list[ChainNode]) -> ImpactType:
        """Determine the business impact type of a chain."""
        phases = {n.phase for n in nodes}
        names = " ".join(n.name.lower() for n in nodes)

        if AttackPhase.EXFILTRATION in phases or "data" in names or "pii" in names:
            return ImpactType.DATA_BREACH
        if "account" in names or "takeover" in names:
            return ImpactType.ACCOUNT_TAKEOVER
        if "ransomware" in names or "encrypt" in names:
            return ImpactType.RANSOMWARE
        if AttackPhase.IMPACT in phases or "dos" in names:
            return ImpactType.SERVICE_DISRUPTION
        if "compliance" in names or "gdpr" in names:
            return ImpactType.COMPLIANCE_VIOLATION
        if "financial" in names or "payment" in names:
            return ImpactType.FINANCIAL_LOSS
        if AttackPhase.CREDENTIAL_ACCESS in phases:
            return ImpactType.ACCOUNT_TAKEOVER
        if AttackPhase.COLLECTION in phases:
            return ImpactType.DATA_BREACH
        return ImpactType.DATA_BREACH

    @staticmethod
    def _generate_business_impact(nodes: list[ChainNode], impact_type: ImpactType) -> str:
        """Generate business impact description."""
        impact_descriptions = {
            ImpactType.DATA_BREACH: "Exposição de dados sensíveis de clientes/empresa, possível multa LGPD/GDPR até 4% do faturamento global",
            ImpactType.FINANCIAL_LOSS: "Perda financeira direta através de fraude, manipulação de transações ou roubo de fundos",
            ImpactType.SERVICE_DISRUPTION: "Indisponibilidade de serviços críticos, perda de receita e impacto na reputação",
            ImpactType.REPUTATION_DAMAGE: "Dano à reputação da marca, perda de confiança de clientes e parceiros",
            ImpactType.COMPLIANCE_VIOLATION: "Violação de requisitos regulatórios (PCI-DSS, HIPAA, SOX), auditorias e penalidades",
            ImpactType.RANSOMWARE: "Criptografia de dados críticos, extorsão financeira, paralisação operacional",
            ImpactType.SUPPLY_CHAIN: "Comprometimento de parceiros/fornecedores, propagação de ataque",
            ImpactType.ACCOUNT_TAKEOVER: "Acesso não autorizado a contas de usuários, fraude de identidade",
        }

        base_impact = impact_descriptions.get(impact_type, "Impacto de segurança significativo")
        endpoint = nodes[-1].endpoint if nodes else "sistema"
        return f"{base_impact}. Endpoint afetado: {endpoint}"

    @staticmethod
    def _calculate_likelihood(nodes: list[ChainNode]) -> str:
        """Calculate likelihood of exploitation."""
        avg_cvss = sum(n.cvss for n in nodes) / len(nodes)
        if avg_cvss >= 8.0:
            return "HIGH"
        elif avg_cvss >= 5.0:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _calculate_exploitability(nodes: list[ChainNode]) -> str:
        """Calculate exploitability of the chain."""
        chain_length = len(nodes)
        avg_cvss = sum(n.cvss for n in nodes) / len(nodes)

        if chain_length <= 2 and avg_cvss >= 7.0:
            return "EASY"
        elif chain_length <= 3 and avg_cvss >= 5.0:
            return "MODERATE"
        return "DIFFICULT"

    @staticmethod
    def _calculate_priority(total_cvss: float, max_severity: str, likelihood: str) -> int:
        """Calculate remediation priority (1-10, higher = more urgent)."""
        score = 0
        score += min(4, int(total_cvss / 5))
        score += {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}.get(max_severity, 0)
        score += {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(likelihood, 0)
        return min(10, max(1, score))

    @staticmethod
    def _estimate_exploit_time(exploitability: str) -> str:
        """Estimate time to exploit the chain."""
        return {
            "EASY": "< 1 hora",
            "MODERATE": "1-4 horas",
            "DIFFICULT": "4-24 horas",
        }.get(exploitability, "Variável")

    @staticmethod
    def _generate_chain_name(nodes: list[ChainNode], impact_type: ImpactType) -> str:
        """Generate a descriptive chain name."""
        first_phase = nodes[0].phase.value.replace("_", " ").title()
        impact = impact_type.value.replace("_", " ").title()
        return f"{first_phase} \u2192 {impact}"

    @staticmethod
    def _generate_chain_description(nodes: list[ChainNode]) -> str:
        """Generate chain description."""
        steps = [f"{i + 1}. {n.name}" for i, n in enumerate(nodes)]
        return "Cadeia de ataque: " + " \u2192 ".join(steps)

    def _calculate_chain_metrics(self) -> None:
        """Calculate blast-radius metrics for each chain."""
        for chain in self.chains:
            endpoints = {n.endpoint for n in chain.nodes if n.endpoint and n.endpoint != "Unknown"}
            phases = {n.phase for n in chain.nodes}
            chain.unique_endpoints = len(endpoints)
            chain.phase_depth = len(phases)

    # ------------------------------------------------------------------
    # Executive summary & export
    # ------------------------------------------------------------------

    def get_executive_summary(self) -> dict:
        """Generate executive summary of all chains."""
        if not self.chains:
            return {
                "total_chains": 0,
                "critical_chains": 0,
                "high_priority_chains": 0,
                "summary": "Nenhuma cadeia de ataque detectada.",
            }

        critical_chains = [c for c in self.chains if c.max_severity == "CRITICAL"]
        high_priority = [c for c in self.chains if c.remediation_priority >= 7]

        impact_counts: dict[str, int] = defaultdict(int)
        for chain in self.chains:
            impact_counts[chain.impact_type.value] += 1

        avg_cvss = sum(c.total_cvss for c in self.chains) / len(self.chains)

        return {
            "total_chains": len(self.chains),
            "critical_chains": len(critical_chains),
            "high_priority_chains": len(high_priority),
            "average_chain_cvss": round(avg_cvss, 1),
            "impact_distribution": dict(impact_counts),
            "top_chain": self.chains[0].to_dict() if self.chains else None,
            "summary": self._generate_executive_text(),
        }

    def _generate_executive_text(self) -> str:
        """Generate executive summary text."""
        if not self.chains:
            return "Nenhuma cadeia de ataque crítica identificada."

        critical = len([c for c in self.chains if c.max_severity == "CRITICAL"])
        high = len([c for c in self.chains if c.max_severity == "HIGH"])
        top_chain = self.chains[0]

        return f"""\
RESUMO EXECUTIVO DE SEGURANÇA
=============================

Foram identificadas {len(self.chains)} cadeias de ataque potenciais:
- {critical} cadeias de severidade CRÍTICA
- {high} cadeias de severidade ALTA

CADEIA DE MAIOR RISCO:
{top_chain.name}
- Impacto: {top_chain.business_impact}
- Probabilidade: {top_chain.likelihood}
- Tempo estimado para exploração: {top_chain.estimated_time_to_exploit}
- Prioridade de correção: {top_chain.remediation_priority}/10

RECOMENDAÇÃO IMEDIATA:
Focar na correção das vulnerabilidades que compõem as cadeias críticas,
começando pelos pontos de entrada (Initial Access)."""

    def export_chains(self, format: str = "json") -> str:
        """Export chains in various formats."""
        if format == "json":
            return json.dumps([c.to_dict() for c in self.chains], indent=2, ensure_ascii=False)
        elif format == "summary":
            return self._generate_executive_text()
        else:
            raise ValueError(f"Unknown format: {format}")
