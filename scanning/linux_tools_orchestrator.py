"""
Linux Tools Orchestrator - Enterprise Edition

Intelligent orchestration of external security tools:
- nmap: Port scanning and service detection
- nuclei: Template-based vulnerability scanning
- nikto: Web server scanning
- gobuster/ffuf: Directory and file brute-forcing
- sqlmap: Advanced SQL injection exploitation
- arjun: Parameter discovery
- wfuzz: Fuzzing

Features:
- Tool chaining: nmap results → trigger nikto/nuclei
- Result parsing and normalization
- Rate limiting respect
- Timeout management
- Finding integration with internal scanners

Usage:
    from scanning.linux_tools_orchestrator import LinuxToolsOrchestrator

    orchestrator = LinuxToolsOrchestrator(settings)
    findings = await orchestrator.run_intelligent_scan(target)
"""

import asyncio
import json
import os
import re
import shutil
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from utils.logger import get_logger
from utils.exploit_policy_engine import get_exploit_policy, ExploitMode, OperationType

logger = get_logger(__name__)


class ToolStatus(Enum):
    """Tool execution status."""
    SUCCESS = auto()
    TIMEOUT = auto()
    ERROR = auto()
    NOT_INSTALLED = auto()
    SKIPPED = auto()


@dataclass
class ToolResult:
    """Result from a tool execution."""
    tool: str
    status: ToolStatus
    findings: List[Dict[str, Any]]
    raw_output: str
    triggers_for: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    error: Optional[str] = None


@dataclass
class ToolConfig:
    """Configuration for a security tool."""
    name: str
    command_template: str
    timeout: int = 300
    parser: str = "_parse_generic"
    requires: Optional[str] = None  # Condition for execution
    wordlists: Dict[str, str] = field(default_factory=dict)
    severity_map: Dict[str, str] = field(default_factory=dict)


class LinuxToolsOrchestrator:
    """
    Orchestrator for external security tools.

    Implements intelligent tool chaining:
    - Results from one tool trigger relevant follow-up tools
    - Findings are normalized to internal format
    - Rate limits and ethics are respected
    """

    # Tool chain definitions: what triggers what
    # NOTE: Only list ACTUAL tools that exist in this orchestrator
    # Removed phantom tools (mysql_scanner, postgres_scanner, etc.) that don't exist
    TOOL_CHAINS: Dict[str, Dict[str, List[str]]] = {
        "nmap": {
            # HTTP services trigger web scanning tools
            "http": ["nikto", "nuclei", "gobuster", "ffuf"],
            "https": ["nikto", "nuclei", "gobuster", "ffuf", "testssl", "sslscan"],
            # Database ports - only log for now, no dedicated DB scanners yet
            # "mysql": [],  # TODO: Add mysql_scanner when implemented
            # "postgresql": [],  # TODO: Add postgres_scanner when implemented
            # "mongodb": [],  # TODO: Add mongodb_scanner when implemented
            # "redis": [],  # TODO: Add redis_scanner when implemented
            # "ssh": [],  # TODO: Add ssh_audit when implemented
            # "ftp": [],  # TODO: Add ftp_scanner when implemented
            # "smb": [],  # TODO: Add smb_scanner when implemented
        },
        "nuclei": {
            # CVE findings trigger exploit verification
            "cve": ["exploit_verifier"],  # Verify if public exploits exist
            "misconfig": [],
            "exposure": [],
        },
        "gobuster": {
            # Directory discovery can trigger parameter discovery and security scanning
            "admin": ["nikto"],  # Admin panels should be scanned for vulns
            "api": ["arjun"],  # API endpoints should trigger param discovery
            "backup": ["nuclei"],  # Backup files may have known vulns
            "config": ["nuclei"],  # Config files may expose sensitive data
        },
        "nikto": {
            # Nikto findings are informational
            "outdated": [],
            "misconfig": [],
        },
        "arjun": {
            # Parameter discovery informs internal scanners via asset_data
            # Not external tools - internal scanners pick up from asset_data["tool_discovered_params"]
            "parameters": [],
        },
        "ffuf": {
            # Similar to gobuster
            "api": ["arjun"],
        },
        "httpx": {
            # Tech detection can trigger appropriate tools
            "http": ["nikto", "nuclei"],
        },
        "masscan": {
            # Fast port scan triggers nmap for service detection
            "http": ["nmap_fast"],
            "https": ["nmap_fast"],
        },
    }

    # Tool configurations
    TOOL_CONFIGS: Dict[str, ToolConfig] = {
        "nmap": ToolConfig(
            name="nmap",
            command_template="nmap -sV -sC --open -oX {output} {target}",
            timeout=600,
            parser="_parse_nmap_xml",
        ),
        "nmap_fast": ToolConfig(
            name="nmap_fast",
            command_template="nmap -F -sV -oX {output} {target}",
            timeout=120,
            parser="_parse_nmap_xml",
        ),
        "nmap_vuln": ToolConfig(
            name="nmap_vuln",
            command_template="nmap --script vuln -oX {output} {target}",
            timeout=900,
            parser="_parse_nmap_xml",
        ),
        "nuclei": ToolConfig(
            name="nuclei",
            command_template="nuclei -u {target} -json -o {output} -severity medium,high,critical -silent",
            timeout=600,
            parser="_parse_nuclei_json",
            severity_map={
                "critical": "CRITICAL",
                "high": "HIGH",
                "medium": "MEDIUM",
                "low": "LOW",
                "info": "INFO",
            },
        ),
        "nuclei_full": ToolConfig(
            name="nuclei_full",
            command_template="nuclei -u {target} -json -o {output} -silent",
            timeout=1200,
            parser="_parse_nuclei_json",
        ),
        "nikto": ToolConfig(
            name="nikto",
            command_template="nikto -h {target} -Format json -o {output}",
            timeout=600,
            parser="_parse_nikto_json",
        ),
        "gobuster": ToolConfig(
            name="gobuster",
            command_template="gobuster dir -u {target} -w {wordlist} -o {output} -q --no-error",
            timeout=300,
            parser="_parse_gobuster",
            wordlists={
                "default": "/usr/share/wordlists/dirb/common.txt",
                "big": "/usr/share/wordlists/dirb/big.txt",
                "api": "/usr/share/wordlists/SecLists/Discovery/Web-Content/api-endpoints.txt",
            },
        ),
        "ffuf": ToolConfig(
            name="ffuf",
            command_template="ffuf -u {target}/FUZZ -w {wordlist} -o {output} -of json -mc 200,301,302,403,500 -s",
            timeout=300,
            parser="_parse_ffuf_json",
            wordlists={
                "default": "/usr/share/wordlists/dirb/common.txt",
                "api": "/usr/share/wordlists/SecLists/Discovery/Web-Content/api-endpoints.txt",
            },
        ),
        # SECURITY: sqlmap commands are SAFE by default
        # NO --dbs, --tables, --dump, --os-shell, --file-read
        # These require explicit consent via ExploitPolicyEngine
        "sqlmap": ToolConfig(
            name="sqlmap",
            # SAFE: Detection only - no data extraction
            command_template="sqlmap -u {target} --batch --level=2 --risk=1 --output-dir={output} --technique=BEUSTQ",
            timeout=900,
            parser="_parse_sqlmap",
            requires="parameter",
        ),
        "sqlmap_verify": ToolConfig(
            name="sqlmap_verify",
            # SAFE: Verification - confirms SQLi, no data extraction
            command_template="sqlmap -u {target} --batch --level=3 --risk=2 --output-dir={output}",
            timeout=1200,
            parser="_parse_sqlmap",
            requires="sqli_detected",
        ),
        # ============================================================
        # REMOVED DANGEROUS TOOLS - DETECTION ONLY POLICY
        # ============================================================
        # The following tools are INTENTIONALLY NOT AVAILABLE:
        # - sqlmap_deep: --level=5 --risk=3 (too aggressive)
        # - sqlmap_enumerate: --dbs (extracts database names)
        # - sqlmap_dump: --dump (extracts data)
        # - sqlmap_shell: --os-shell (command execution)
        # - sqlmap_file: --file-read (file extraction)
        #
        # PetNTester AI is a DETECTION tool, not an EXPLOITATION tool.
        # These capabilities are intentionally disabled.
        # Manual exploitation requires separate authorization.
        # ============================================================
        "arjun": ToolConfig(
            name="arjun",
            command_template="arjun -u {target} -oJ {output}",
            timeout=300,
            parser="_parse_arjun_json",
        ),
        "wfuzz": ToolConfig(
            name="wfuzz",
            command_template="wfuzz -c -z file,{wordlist} --hc 404 -f {output},json {target}/FUZZ",
            timeout=300,
            parser="_parse_wfuzz_json",
            wordlists={
                "default": "/usr/share/wordlists/dirb/common.txt",
            },
        ),
        "whatweb": ToolConfig(
            name="whatweb",
            command_template="whatweb -a 3 --log-json={output} {target}",
            timeout=120,
            parser="_parse_whatweb_json",
        ),
        "sslscan": ToolConfig(
            name="sslscan",
            command_template="sslscan --xml={output} {target}",
            timeout=120,
            parser="_parse_sslscan_xml",
        ),
        "testssl": ToolConfig(
            name="testssl",
            command_template="testssl.sh --jsonfile={output} {target}",
            timeout=300,
            parser="_parse_testssl_json",
        ),
        "httpx": ToolConfig(
            name="httpx",
            command_template="httpx -u {target} -json -o {output} -silent -tech-detect -status-code -title -follow-redirects",
            timeout=120,
            parser="_parse_httpx_json",
        ),
        "masscan": ToolConfig(
            name="masscan",
            command_template="masscan {target} -p1-65535 --rate=1000 -oJ {output}",
            timeout=600,
            parser="_parse_masscan_json",
        ),
        # ============================================================
        # EXPLOIT VERIFICATION - Triggered by CVE detections
        # ============================================================
        "exploit_verifier": ToolConfig(
            name="exploit_verifier",
            # Uses searchsploit (ExploitDB) to check for known exploits
            # SAFE: Only searches for exploits, does NOT execute them
            command_template="searchsploit --json --cve {cve_id} > {output} 2>/dev/null || echo '{{\"RESULTS_EXPLOIT\": []}}'",
            timeout=60,
            parser="_parse_exploit_verifier",
            requires="cve_detected",  # Only runs when CVE is detected
        ),
    }

    # Common ports and their associated services
    PORT_SERVICE_MAP: Dict[int, str] = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        445: "smb",
        993: "imaps",
        995: "pop3s",
        1433: "mssql",
        1521: "oracle",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        6379: "redis",
        8080: "http",
        8443: "https",
        27017: "mongodb",
    }

    def __init__(self, settings: Optional[Any] = None):
        """Initialize the orchestrator."""
        self.settings = settings
        self.temp_dir = Path(tempfile.mkdtemp(prefix="pentest_tools_"))
        self.available_tools: Set[str] = set()
        self._detect_available_tools()

        # Track executed tools to avoid duplicates
        self.executed_tools: Set[str] = set()
        self.all_findings: List[Dict[str, Any]] = []

    def _detect_available_tools(self) -> None:
        """Detect which tools are installed on the system."""
        tool_binaries = {
            "nmap": "nmap",
            "nuclei": "nuclei",
            "nikto": "nikto",
            "gobuster": "gobuster",
            "ffuf": "ffuf",
            "sqlmap": "sqlmap",
            "arjun": "arjun",
            "wfuzz": "wfuzz",
            "whatweb": "whatweb",
            "sslscan": "sslscan",
            "testssl": "testssl.sh",
            "httpx": "httpx",
            "masscan": "masscan",
            "exploit_verifier": "searchsploit",  # ExploitDB search tool
        }

        # Also check ~/.local/bin for user-installed tools
        local_bin = Path.home() / ".local" / "bin"
        if local_bin.exists():
            os.environ["PATH"] = f"{local_bin}:{os.environ.get('PATH', '')}"

        for tool, binary in tool_binaries.items():
            if shutil.which(binary):
                self.available_tools.add(tool)
                logger.debug(f"Tool available: {tool}")
            else:
                logger.debug(f"Tool not found: {tool}")

        logger.info(f"Available external tools: {len(self.available_tools)}/{len(tool_binaries)}")

    def is_tool_available(self, tool: str) -> bool:
        """Check if a tool is available."""
        # Also check variants (nmap_fast, nuclei_full, etc.)
        base_tool = tool.split("_")[0]
        return base_tool in self.available_tools

    async def run_intelligent_scan(
        self,
        target: str,
        tools: Optional[List[str]] = None,
        depth: int = 2,
    ) -> List[Dict[str, Any]]:
        """
        Run intelligent scan with tool chaining.

        Args:
            target: Target URL or hostname
            tools: Initial tools to run (default: ["nmap"])
            depth: Chain depth (how many levels of chaining)

        Returns:
            List of findings from all tools
        """
        self.executed_tools = set()
        self.all_findings = []

        # Start with initial tools
        tools_to_run = tools or ["nmap"]
        if self._is_web_target(target) and not tools:
            # For web targets, run comprehensive discovery + scanning tools
            # - nuclei/nikto: vulnerability scanning
            # - gobuster/ffuf: directory discovery (if available)
            # - arjun: parameter discovery (critical for injection testing)
            # - httpx: tech fingerprinting
            # - testssl/sslscan: TLS analysis (if HTTPS)
            tools_to_run = ["nuclei", "nikto"]

            # Add directory discovery (prefer gobuster, fallback to ffuf)
            if "gobuster" in self.available_tools:
                tools_to_run.append("gobuster")
            elif "ffuf" in self.available_tools:
                tools_to_run.append("ffuf")

            # Add parameter discovery - critical for injection testing
            if "arjun" in self.available_tools:
                tools_to_run.append("arjun")

            # Add tech fingerprinting
            if "httpx" in self.available_tools:
                tools_to_run.append("httpx")

            # Add TLS analysis for HTTPS targets
            if target.startswith("https://"):
                if "testssl" in self.available_tools:
                    tools_to_run.append("testssl")
                elif "sslscan" in self.available_tools:
                    tools_to_run.append("sslscan")

            logger.info(f"   Web target detected - running tools: {tools_to_run}")

        current_depth = 0
        while tools_to_run and current_depth < depth:
            next_tools = []

            for tool in tools_to_run:
                if tool in self.executed_tools:
                    continue

                result = await self._run_tool(tool, target)
                self.executed_tools.add(tool)

                if result.status == ToolStatus.SUCCESS:
                    self.all_findings.extend(result.findings)
                    next_tools.extend(result.triggers_for)
                    logger.info(f"  ✓ {tool}: {len(result.findings)} findings, triggers: {result.triggers_for}")
                elif result.status == ToolStatus.NOT_INSTALLED:
                    logger.debug(f"  ⏭ {tool}: not installed")
                else:
                    logger.warning(f"  ✗ {tool}: {result.error}")

            tools_to_run = [t for t in set(next_tools) if t not in self.executed_tools]
            current_depth += 1

        return self.all_findings

    async def run_single_tool(
        self,
        tool: str,
        target: str,
        **kwargs
    ) -> ToolResult:
        """Run a single tool without chaining."""
        return await self._run_tool(tool, target, **kwargs)

    async def _run_tool(
        self,
        tool: str,
        target: str,
        wordlist: Optional[str] = None,
        **kwargs
    ) -> ToolResult:
        """Execute a single tool and parse results."""
        import time

        # SECURITY: Check exploit policy before running tool
        policy = get_exploit_policy()
        operation = kwargs.get("operation", "detect")

        # Map tool to default operation if not specified
        tool_default_ops = {
            "sqlmap": "detect",
            "sqlmap_deep": "verify",
            "nuclei": "scan",
            "nmap": "scan",
            "gobuster": "dir",
            "ffuf": "dir",
            "arjun": "discover",
            "nikto": "scan",
            "exploit_verifier": "verify",  # Only verifies, doesn't exploit
        }
        if operation == "detect":
            operation = tool_default_ops.get(tool, "detect")

        if not policy.can_execute(tool, target, operation):
            logger.warning(f"🚫 Policy blocked: {tool}.{operation} on {target}")
            return ToolResult(
                tool=tool,
                status=ToolStatus.SKIPPED,
                findings=[],
                raw_output="",
                error=f"Blocked by exploit policy (mode: {policy.get_mode().value})",
            )

        if not self.is_tool_available(tool):
            return ToolResult(
                tool=tool,
                status=ToolStatus.NOT_INSTALLED,
                findings=[],
                raw_output="",
                error=f"Tool '{tool}' not installed",
            )

        # Special handling for exploit_verifier: extract CVE IDs from previous findings
        if tool == "exploit_verifier":
            return await self._run_exploit_verifier(target)

        config = self.TOOL_CONFIGS.get(tool)
        if not config:
            # Use base tool config if variant not found
            base_tool = tool.split("_")[0]
            config = self.TOOL_CONFIGS.get(base_tool)
            if not config:
                return ToolResult(
                    tool=tool,
                    status=ToolStatus.ERROR,
                    findings=[],
                    raw_output="",
                    error=f"No configuration for tool '{tool}'",
                )

        # Prepare output file
        output_file = self.temp_dir / f"{tool}_{hash(target) % 100000}.out"

        # Prepare wordlist if needed
        if "{wordlist}" in config.command_template:
            if wordlist:
                wl = wordlist
            else:
                wl = config.wordlists.get("default", "/usr/share/wordlists/dirb/common.txt")
            if not Path(wl).exists():
                wl = "/usr/share/wordlists/dirb/common.txt"  # Fallback

        # Build command
        command = config.command_template.format(
            target=target,
            output=str(output_file),
            wordlist=wl if "{wordlist}" in config.command_template else "",
            **kwargs
        )

        logger.debug(f"Running: {command}")
        start_time = time.time()

        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=config.timeout
            )

            execution_time = time.time() - start_time

            # Parse output
            parser = getattr(self, config.parser, self._parse_generic)
            findings, triggers = await parser(output_file, target, config)

            return ToolResult(
                tool=tool,
                status=ToolStatus.SUCCESS,
                findings=findings,
                raw_output=stdout.decode() if stdout else "",
                triggers_for=triggers,
                execution_time=execution_time,
            )

        except asyncio.TimeoutError:
            return ToolResult(
                tool=tool,
                status=ToolStatus.TIMEOUT,
                findings=[],
                raw_output="",
                triggers_for=[],
                execution_time=config.timeout,
                error=f"Timeout after {config.timeout}s",
            )
        except Exception as e:
            return ToolResult(
                tool=tool,
                status=ToolStatus.ERROR,
                findings=[],
                raw_output="",
                triggers_for=[],
                execution_time=time.time() - start_time,
                error=str(e),
            )

    def _is_web_target(self, target: str) -> bool:
        """Check if target is a web URL."""
        return target.startswith("http://") or target.startswith("https://")

    # ================================================
    # Tool-specific parsers
    # ================================================

    async def _parse_nmap_xml(
        self,
        output_file: Path,
        target: str,
        config: ToolConfig
    ) -> Tuple[List[Dict], List[str]]:
        """Parse nmap XML output."""
        findings = []
        triggers = []

        if not output_file.exists():
            return findings, triggers

        try:
            tree = ET.parse(output_file)
            root = tree.getroot()

            for host in root.findall(".//host"):
                # Get host address
                addr_elem = host.find("address")
                host_addr = addr_elem.get("addr") if addr_elem is not None else target

                for port in host.findall(".//port"):
                    port_id = port.get("portid")
                    protocol = port.get("protocol", "tcp")

                    state_elem = port.find("state")
                    state = state_elem.get("state") if state_elem is not None else "unknown"

                    if state != "open":
                        continue

                    service_elem = port.find("service")
                    service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                    service_product = service_elem.get("product", "") if service_elem is not None else ""
                    service_version = service_elem.get("version", "") if service_elem is not None else ""

                    # Create finding
                    findings.append({
                        "type": "open_port",
                        "name": f"Open Port: {port_id}/{protocol} ({service_name})",
                        "severity": self._get_port_severity(int(port_id), service_name),
                        "matched_at": f"{host_addr}:{port_id}",
                        "description": f"Open {protocol} port {port_id} running {service_name}",
                        "metadata": {
                            "port": int(port_id),
                            "protocol": protocol,
                            "service": service_name,
                            "product": service_product,
                            "version": service_version,
                            "tool": "nmap",
                        },
                    })

                    # Determine triggers based on service
                    service_key = self._normalize_service(service_name, int(port_id))
                    if service_key in self.TOOL_CHAINS.get("nmap", {}):
                        triggers.extend(self.TOOL_CHAINS["nmap"][service_key])

                    # Parse script results
                    for script in port.findall(".//script"):
                        script_id = script.get("id", "")
                        script_output = script.get("output", "")

                        if "vuln" in script_id.lower() or "cve" in script_output.lower():
                            findings.append({
                                "type": "nmap_script_vuln",
                                "name": f"Nmap Script: {script_id}",
                                "severity": "HIGH" if "cve" in script_output.lower() else "MEDIUM",
                                "matched_at": f"{host_addr}:{port_id}",
                                "description": script_output[:500],
                                "metadata": {
                                    "script_id": script_id,
                                    "tool": "nmap",
                                },
                            })

        except ET.ParseError as e:
            logger.warning(f"Failed to parse nmap XML: {e}")
        except Exception as e:
            logger.warning(f"Error parsing nmap output: {e}")

        return findings, list(set(triggers))

    async def _parse_nuclei_json(
        self,
        output_file: Path,
        target: str,
        config: ToolConfig
    ) -> Tuple[List[Dict], List[str]]:
        """Parse nuclei JSON lines output."""
        findings = []
        triggers = []

        if not output_file.exists():
            return findings, triggers

        try:
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        result = json.loads(line)

                        template_id = result.get("template-id", result.get("templateID", "unknown"))
                        severity = result.get("info", {}).get("severity", "medium")
                        matched_at = result.get("matched-at", result.get("matched", target))

                        # Map severity
                        mapped_severity = config.severity_map.get(severity.lower(), "MEDIUM")

                        findings.append({
                            "type": "nuclei_finding",
                            "name": result.get("info", {}).get("name", template_id),
                            "severity": mapped_severity,
                            "matched_at": matched_at,
                            "description": result.get("info", {}).get("description", ""),
                            "metadata": {
                                "template_id": template_id,
                                "tags": result.get("info", {}).get("tags", []),
                                "reference": result.get("info", {}).get("reference", []),
                                "matcher_name": result.get("matcher-name", ""),
                                "extracted_results": result.get("extracted-results", []),
                                "curl_command": result.get("curl-command", ""),
                                "tool": "nuclei",
                            },
                        })

                        # Determine triggers
                        tags = result.get("info", {}).get("tags", [])
                        if "cve" in tags or any("CVE-" in str(t) for t in tags):
                            triggers.extend(self.TOOL_CHAINS.get("nuclei", {}).get("cve", []))
                        if "misconfig" in tags:
                            triggers.extend(self.TOOL_CHAINS.get("nuclei", {}).get("misconfig", []))

                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            logger.warning(f"Error parsing nuclei output: {e}")

        return findings, list(set(triggers))

    async def _parse_nikto_json(
        self,
        output_file: Path,
        target: str,
        config: ToolConfig
    ) -> Tuple[List[Dict], List[str]]:
        """Parse nikto JSON output."""
        findings = []
        triggers = []

        if not output_file.exists():
            return findings, triggers

        try:
            with open(output_file, 'r') as f:
                content = f.read()

            # Nikto output can be a JSON array
            if content.strip().startswith('['):
                results = json.loads(content)
            else:
                # Or individual JSON objects
                results = [json.loads(line) for line in content.strip().split('\n') if line.strip()]

            for result in results:
                vulnerabilities = result.get("vulnerabilities", [])

                for vuln in vulnerabilities:
                    osvdb_id = vuln.get("OSVDB", "")
                    description = vuln.get("msg", vuln.get("message", ""))
                    url = vuln.get("url", target)

                    # Determine severity
                    severity = "MEDIUM"
                    if any(kw in description.lower() for kw in ["critical", "remote code", "injection"]):
                        severity = "CRITICAL"
                    elif any(kw in description.lower() for kw in ["high", "vulnerability", "password"]):
                        severity = "HIGH"
                    elif any(kw in description.lower() for kw in ["outdated", "version"]):
                        severity = "MEDIUM"
                        triggers.extend(self.TOOL_CHAINS.get("nikto", {}).get("outdated", []))

                    findings.append({
                        "type": "nikto_finding",
                        "name": f"Nikto: {description[:80]}",
                        "severity": severity,
                        "matched_at": url,
                        "description": description,
                        "metadata": {
                            "osvdb": osvdb_id,
                            "method": vuln.get("method", "GET"),
                            "tool": "nikto",
                        },
                    })

        except json.JSONDecodeError:
            # Try parsing as text output
            await self._parse_nikto_text(output_file, target, findings)
        except Exception as e:
            logger.warning(f"Error parsing nikto output: {e}")

        return findings, list(set(triggers))

    async def _parse_nikto_text(
        self,
        output_file: Path,
        target: str,
        findings: List[Dict]
    ) -> None:
        """Parse nikto text output as fallback."""
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    # Look for + lines which indicate findings
                    if line.startswith("+ "):
                        findings.append({
                            "type": "nikto_finding",
                            "name": f"Nikto: {line[2:60]}...",
                            "severity": "MEDIUM",
                            "matched_at": target,
                            "description": line[2:].strip(),
                            "metadata": {"tool": "nikto"},
                        })
        except Exception:
            pass

    async def _parse_gobuster(
        self,
        output_file: Path,
        target: str,
        config: ToolConfig
    ) -> Tuple[List[Dict], List[str]]:
        """Parse gobuster output."""
        findings = []
        triggers = []

        if not output_file.exists():
            return findings, triggers

        try:
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    # Parse: /path (Status: 200) [Size: 1234]
                    match = re.match(r'(/[^\s]*)\s+\(Status:\s*(\d+)\)', line)
                    if match:
                        path = match.group(1)
                        status = int(match.group(2))

                        severity = "INFO"
                        if status in [200, 301, 302]:
                            severity = "LOW"

                        # Check for interesting paths
                        interesting = self._is_interesting_path(path)
                        if interesting:
                            severity = "MEDIUM"
                            for category, keywords in [
                                ("admin", ["admin", "dashboard", "manage"]),
                                ("api", ["api", "rest", "graphql"]),
                                ("backup", ["backup", ".bak", ".old", ".zip"]),
                                ("config", ["config", "settings", ".env"]),
                            ]:
                                if any(kw in path.lower() for kw in keywords):
                                    triggers.extend(self.TOOL_CHAINS.get("gobuster", {}).get(category, []))

                        findings.append({
                            "type": "directory_found",
                            "name": f"Directory: {path}",
                            "severity": severity,
                            "matched_at": f"{target.rstrip('/')}{path}",
                            "description": f"Directory/file found with status {status}",
                            "metadata": {
                                "path": path,
                                "status_code": status,
                                "interesting": interesting,
                                "tool": "gobuster",
                            },
                        })

        except Exception as e:
            logger.warning(f"Error parsing gobuster output: {e}")

        return findings, list(set(triggers))

    async def _parse_ffuf_json(
        self,
        output_file: Path,
        target: str,
        config: ToolConfig
    ) -> Tuple[List[Dict], List[str]]:
        """Parse ffuf JSON output."""
        findings = []
        triggers = []

        if not output_file.exists():
            return findings, triggers

        try:
            with open(output_file, 'r') as f:
                data = json.load(f)

            for result in data.get("results", []):
                url = result.get("url", "")
                status = result.get("status", 0)
                length = result.get("length", 0)
                input_val = result.get("input", {}).get("FUZZ", "")

                severity = "INFO"
                if status in [200, 301, 302]:
                    severity = "LOW"
                if self._is_interesting_path(input_val):
                    severity = "MEDIUM"

                findings.append({
                    "type": "ffuf_finding",
                    "name": f"Found: /{input_val}",
                    "severity": severity,
                    "matched_at": url,
                    "metadata": {
                        "status_code": status,
                        "content_length": length,
                        "input": input_val,
                        "tool": "ffuf",
                    },
                })

        except Exception as e:
            logger.warning(f"Error parsing ffuf output: {e}")

        return findings, triggers

    async def _parse_arjun_json(
        self,
        output_file: Path,
        target: str,
        config: ToolConfig
    ) -> Tuple[List[Dict], List[str]]:
        """Parse arjun JSON output."""
        findings = []
        triggers = []

        if not output_file.exists():
            return findings, triggers

        try:
            with open(output_file, 'r') as f:
                data = json.load(f)

            for url, params in data.items():
                if params:
                    findings.append({
                        "type": "parameter_discovery",
                        "name": f"Parameters found: {', '.join(params[:5])}",
                        "severity": "INFO",
                        "matched_at": url,
                        "description": f"Discovered {len(params)} parameters",
                        "metadata": {
                            "parameters": params,
                            "tool": "arjun",
                        },
                    })

                    # Trigger injection scanners
                    if params:
                        triggers.extend(self.TOOL_CHAINS.get("arjun", {}).get("parameters", []))

        except Exception as e:
            logger.warning(f"Error parsing arjun output: {e}")

        return findings, triggers

    async def _parse_sqlmap(
        self,
        output_file: Path,
        target: str,
        config: ToolConfig
    ) -> Tuple[List[Dict], List[str]]:
        """Parse sqlmap output directory."""
        findings = []
        triggers = []

        output_dir = Path(output_file)
        if not output_dir.exists():
            return findings, triggers

        try:
            # Look for log file
            for log_file in output_dir.rglob("log"):
                with open(log_file, 'r') as f:
                    content = f.read()

                    # Check for injection confirmation
                    if "is vulnerable" in content.lower():
                        findings.append({
                            "type": "sql_injection",
                            "name": "SQLmap: SQL Injection Confirmed",
                            "severity": "CRITICAL",
                            "matched_at": target,
                            "description": "SQLmap confirmed SQL injection vulnerability",
                            "metadata": {
                                "tool": "sqlmap",
                                "log_excerpt": content[:1000],
                            },
                        })

                        # Check for database type
                        db_match = re.search(r"back-end DBMS: (.+)", content)
                        if db_match:
                            findings[-1]["metadata"]["database"] = db_match.group(1)

        except Exception as e:
            logger.warning(f"Error parsing sqlmap output: {e}")

        return findings, triggers

    async def _parse_wfuzz_json(
        self,
        output_file: Path,
        target: str,
        config: ToolConfig
    ) -> Tuple[List[Dict], List[str]]:
        """Parse wfuzz JSON output."""
        findings = []
        triggers = []

        if not output_file.exists():
            return findings, triggers

        try:
            with open(output_file, 'r') as f:
                data = json.load(f)

            for result in data:
                url = result.get("url", "")
                code = result.get("code", 0)
                payload = result.get("payload", "")

                if code in [200, 301, 302, 403]:
                    findings.append({
                        "type": "wfuzz_finding",
                        "name": f"Found: {payload}",
                        "severity": "LOW",
                        "matched_at": url,
                        "metadata": {
                            "status_code": code,
                            "payload": payload,
                            "tool": "wfuzz",
                        },
                    })

        except Exception as e:
            logger.warning(f"Error parsing wfuzz output: {e}")

        return findings, triggers

    async def _parse_whatweb_json(
        self,
        output_file: Path,
        target: str,
        config: ToolConfig
    ) -> Tuple[List[Dict], List[str]]:
        """Parse whatweb JSON output."""
        findings = []
        triggers = []

        if not output_file.exists():
            return findings, triggers

        try:
            with open(output_file, 'r') as f:
                data = json.load(f)

            for entry in data if isinstance(data, list) else [data]:
                plugins = entry.get("plugins", {})

                for plugin_name, plugin_data in plugins.items():
                    version = plugin_data.get("version", [""])[0] if plugin_data.get("version") else ""

                    findings.append({
                        "type": "technology_detected",
                        "name": f"Technology: {plugin_name}",
                        "severity": "INFO",
                        "matched_at": target,
                        "metadata": {
                            "technology": plugin_name,
                            "version": version,
                            "tool": "whatweb",
                        },
                    })

        except Exception as e:
            logger.warning(f"Error parsing whatweb output: {e}")

        return findings, triggers

    async def _parse_sslscan_xml(
        self,
        output_file: Path,
        target: str,
        config: ToolConfig
    ) -> Tuple[List[Dict], List[str]]:
        """Parse sslscan XML output."""
        findings = []
        triggers = []

        if not output_file.exists():
            return findings, triggers

        try:
            tree = ET.parse(output_file)
            root = tree.getroot()

            # Check for weak ciphers
            for cipher in root.findall(".//cipher"):
                status = cipher.get("status", "")
                if status == "accepted":
                    cipher_name = cipher.get("cipher", "")
                    bits = cipher.get("bits", "")

                    if int(bits or 0) < 128 or "RC4" in cipher_name or "DES" in cipher_name:
                        findings.append({
                            "type": "weak_ssl_cipher",
                            "name": f"Weak SSL Cipher: {cipher_name}",
                            "severity": "MEDIUM",
                            "matched_at": target,
                            "metadata": {
                                "cipher": cipher_name,
                                "bits": bits,
                                "tool": "sslscan",
                            },
                        })

            # Check for SSL/TLS versions
            for protocol in root.findall(".//protocol"):
                if protocol.get("enabled") == "1":
                    version = protocol.get("type", "") + " " + protocol.get("version", "")
                    if "SSLv" in version or "TLSv1.0" in version or "TLSv1.1" in version:
                        findings.append({
                            "type": "deprecated_ssl",
                            "name": f"Deprecated Protocol: {version}",
                            "severity": "MEDIUM",
                            "matched_at": target,
                            "metadata": {
                                "protocol": version,
                                "tool": "sslscan",
                            },
                        })

        except Exception as e:
            logger.warning(f"Error parsing sslscan output: {e}")

        return findings, triggers

    async def _parse_testssl_json(
        self,
        output_file: Path,
        target: str,
        config: ToolConfig
    ) -> Tuple[List[Dict], List[str]]:
        """Parse testssl JSON output."""
        findings = []
        triggers = []

        if not output_file.exists():
            return findings, triggers

        try:
            with open(output_file, 'r') as f:
                data = json.load(f)

            for finding in data.get("findings", []):
                severity = finding.get("severity", "INFO")
                if severity in ["CRITICAL", "HIGH", "MEDIUM"]:
                    findings.append({
                        "type": "ssl_vulnerability",
                        "name": finding.get("id", "SSL Issue"),
                        "severity": severity,
                        "matched_at": target,
                        "description": finding.get("finding", ""),
                        "metadata": {
                            "tool": "testssl",
                        },
                    })

        except Exception as e:
            logger.warning(f"Error parsing testssl output: {e}")

        return findings, triggers

    async def _parse_httpx_json(
        self,
        output_file: Path,
        target: str,
        config: ToolConfig
    ) -> Tuple[List[Dict], List[str]]:
        """Parse httpx JSON output."""
        findings = []
        triggers = []

        if not output_file.exists():
            return findings, triggers

        try:
            with open(output_file, 'r') as f:
                for line in f:
                    if not line.strip():
                        continue
                    data = json.loads(line)

                    url = data.get("url", "")
                    status_code = data.get("status_code", 0)
                    title = data.get("title", "")
                    tech = data.get("tech", [])
                    webserver = data.get("webserver", "")

                    findings.append({
                        "type": "http_probe",
                        "name": f"HTTP Probe: {url}",
                        "severity": "INFO",
                        "matched_at": url,
                        "metadata": {
                            "status_code": status_code,
                            "title": title,
                            "technologies": tech,
                            "webserver": webserver,
                            "tool": "httpx",
                        },
                    })

                    # Trigger follow-up tools based on technologies
                    if tech:
                        triggers.extend(["nuclei", "nikto"])

        except Exception as e:
            logger.warning(f"Error parsing httpx output: {e}")

        return findings, triggers

    async def _parse_masscan_json(
        self,
        output_file: Path,
        target: str,
        config: ToolConfig
    ) -> Tuple[List[Dict], List[str]]:
        """Parse masscan JSON output."""
        findings = []
        triggers = []

        if not output_file.exists():
            return findings, triggers

        try:
            with open(output_file, 'r') as f:
                content = f.read()
                # Masscan JSON has trailing comma issues, fix it
                content = re.sub(r',\s*\]', ']', content)
                data = json.loads(content)

            for entry in data:
                ip = entry.get("ip", "")
                for port_info in entry.get("ports", []):
                    port = port_info.get("port", 0)
                    proto = port_info.get("proto", "tcp")
                    status = port_info.get("status", "")

                    if status == "open":
                        service = self.PORT_SERVICE_MAP.get(port, "unknown")
                        severity = self._get_port_severity(port, service)

                        findings.append({
                            "type": "open_port",
                            "name": f"Open Port: {port}/{proto}",
                            "severity": severity,
                            "matched_at": f"{ip}:{port}",
                            "metadata": {
                                "ip": ip,
                                "port": port,
                                "protocol": proto,
                                "service": service,
                                "tool": "masscan",
                            },
                        })

                        # Trigger follow-up tools
                        if service in ["http", "https"]:
                            triggers.extend(["nikto", "nuclei", "gobuster"])
                        elif service in self.TOOL_CHAINS.get("nmap", {}):
                            triggers.extend(self.TOOL_CHAINS["nmap"].get(service, []))

        except Exception as e:
            logger.warning(f"Error parsing masscan output: {e}")

        return findings, triggers

    async def _parse_exploit_verifier(
        self,
        output_file: Path,
        target: str,
        config: ToolConfig
    ) -> Tuple[List[Dict], List[str]]:
        """
        Parse searchsploit/ExploitDB JSON output.

        Identifies known public exploits for detected CVEs.
        SAFE: Only identifies exploits, does NOT download or execute them.
        """
        findings = []
        triggers = []

        if not output_file.exists():
            return findings, triggers

        try:
            with open(output_file, 'r') as f:
                content = f.read()

            # Handle empty or error output
            if not content.strip() or content.strip() == '{"RESULTS_EXPLOIT": []}':
                return findings, triggers

            data = json.loads(content)
            exploits = data.get("RESULTS_EXPLOIT", [])

            for exploit in exploits:
                exploit_id = exploit.get("EDB-ID", "unknown")
                title = exploit.get("Title", "Unknown Exploit")
                path = exploit.get("Path", "")
                date = exploit.get("Date", "")
                exploit_type = exploit.get("Type", "")
                platform = exploit.get("Platform", "")

                # Determine severity based on exploit type
                severity = "HIGH"
                if "remote" in exploit_type.lower() or "rce" in title.lower():
                    severity = "CRITICAL"
                elif "dos" in exploit_type.lower() or "denial" in title.lower():
                    severity = "MEDIUM"
                elif "local" in exploit_type.lower():
                    severity = "MEDIUM"

                findings.append({
                    "type": "exploit_available",
                    "name": f"Public Exploit: {title[:80]}",
                    "severity": severity,
                    "matched_at": target,
                    "description": (
                        f"A public exploit (EDB-ID: {exploit_id}) exists for this vulnerability. "
                        f"Type: {exploit_type}, Platform: {platform}. "
                        f"This increases the risk as exploitation is readily available."
                    ),
                    "metadata": {
                        "edb_id": exploit_id,
                        "title": title,
                        "path": path,
                        "date": date,
                        "type": exploit_type,
                        "platform": platform,
                        "tool": "exploit_verifier",
                        "source": "ExploitDB",
                    },
                })

            if exploits:
                logger.info(f"[ExploitVerifier] Found {len(exploits)} public exploits for {target}")

        except json.JSONDecodeError:
            # searchsploit might not output valid JSON, try text parsing
            try:
                with open(output_file, 'r') as f:
                    for line in f:
                        if "exploit" in line.lower() and "|" in line:
                            parts = line.strip().split("|")
                            if len(parts) >= 2:
                                findings.append({
                                    "type": "exploit_available",
                                    "name": f"Public Exploit Found",
                                    "severity": "HIGH",
                                    "matched_at": target,
                                    "description": line.strip(),
                                    "metadata": {"tool": "exploit_verifier", "source": "ExploitDB"},
                                })
            except Exception:
                pass
        except Exception as e:
            logger.warning(f"Error parsing exploit_verifier output: {e}")

        return findings, triggers

    async def _parse_generic(
        self,
        output_file: Path,
        target: str,
        config: ToolConfig
    ) -> Tuple[List[Dict], List[str]]:
        """Generic parser for tools without specific parsers."""
        findings = []
        triggers = []

        if not output_file.exists():
            return findings, triggers

        try:
            with open(output_file, 'r') as f:
                content = f.read()

            if content.strip():
                findings.append({
                    "type": f"{config.name}_output",
                    "name": f"{config.name.capitalize()} Output",
                    "severity": "INFO",
                    "matched_at": target,
                    "description": f"Raw output from {config.name}",
                    "metadata": {
                        "raw_output": content[:5000],
                        "tool": config.name,
                    },
                })

        except Exception as e:
            logger.warning(f"Error parsing {config.name} output: {e}")

        return findings, triggers

    # ================================================
    # Special Tool Handlers
    # ================================================

    async def _run_exploit_verifier(self, target: str) -> ToolResult:
        """
        Run exploit verification for all CVEs found in previous findings.

        Extracts CVE IDs from nuclei and other scanner findings, then queries
        ExploitDB via searchsploit to check for known public exploits.

        SAFE: Only searches for exploit information, does NOT download or execute.
        """
        import time
        start_time = time.time()

        result = ToolResult(
            tool="exploit_verifier",
            status=ToolStatus.SUCCESS,
            findings=[],
            raw_output="",
            triggers_for=[],
        )

        # Extract CVE IDs from all previous findings
        cve_ids = self._extract_cve_ids_from_findings()

        if not cve_ids:
            logger.debug("[ExploitVerifier] No CVE IDs found in previous findings")
            result.raw_output = "No CVEs to verify"
            return result

        logger.info(f"[ExploitVerifier] Checking {len(cve_ids)} CVEs for public exploits")

        # Query searchsploit for each CVE
        for cve_id in cve_ids[:20]:  # Limit to 20 CVEs to avoid timeout
            try:
                output_file = self.temp_dir / f"exploit_{cve_id.replace('-', '_')}.json"

                # Run searchsploit with JSON output
                cmd = f'searchsploit --json --cve "{cve_id}" 2>/dev/null'

                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=30  # 30 seconds per CVE
                )

                output = stdout.decode('utf-8', errors='ignore')

                if output.strip():
                    # Write to temp file for parser
                    with open(output_file, 'w') as f:
                        f.write(output)

                    # Parse the output
                    config = self.TOOL_CONFIGS.get("exploit_verifier")
                    findings, _ = await self._parse_exploit_verifier(
                        output_file, f"{target} (CVE: {cve_id})", config
                    )

                    # Add CVE context to findings
                    for finding in findings:
                        finding["metadata"]["cve_id"] = cve_id
                        result.findings.append(finding)

                    # Cleanup temp file
                    try:
                        output_file.unlink()
                    except Exception:
                        pass

            except asyncio.TimeoutError:
                logger.debug(f"[ExploitVerifier] Timeout checking {cve_id}")
            except Exception as e:
                logger.debug(f"[ExploitVerifier] Error checking {cve_id}: {e}")

        result.execution_time = time.time() - start_time

        if result.findings:
            logger.info(f"[ExploitVerifier] Found {len(result.findings)} public exploits")
        else:
            logger.info("[ExploitVerifier] No public exploits found for detected CVEs")

        return result

    def _extract_cve_ids_from_findings(self) -> List[str]:
        """Extract unique CVE IDs from all findings."""
        cve_ids = set()
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

        for finding in self.all_findings:
            # Check in metadata tags
            tags = finding.get("metadata", {}).get("tags", [])
            for tag in tags:
                if isinstance(tag, str):
                    matches = cve_pattern.findall(tag.upper())
                    cve_ids.update(matches)

            # Check in references
            refs = finding.get("metadata", {}).get("reference", [])
            for ref in refs:
                if isinstance(ref, str):
                    matches = cve_pattern.findall(ref.upper())
                    cve_ids.update(matches)

            # Check in template_id
            template_id = finding.get("metadata", {}).get("template_id", "")
            if template_id:
                matches = cve_pattern.findall(template_id.upper())
                cve_ids.update(matches)

            # Check in description
            desc = finding.get("description", "")
            if desc:
                matches = cve_pattern.findall(desc.upper())
                cve_ids.update(matches)

            # Check in name
            name = finding.get("name", "")
            if name:
                matches = cve_pattern.findall(name.upper())
                cve_ids.update(matches)

        return list(cve_ids)

    # ================================================
    # Helper methods
    # ================================================

    def _normalize_service(self, service_name: str, port: int) -> str:
        """Normalize service name."""
        service_name = service_name.lower()

        # Use port to determine service if name is generic
        if service_name in ["unknown", "tcpwrapped"]:
            return self.PORT_SERVICE_MAP.get(port, "unknown")

        # Map common variations
        mappings = {
            "http-proxy": "http",
            "https-proxy": "https",
            "ssl/http": "https",
            "http-alt": "http",
            "mariadb": "mysql",
            "postgres": "postgresql",
            "ms-sql": "mssql",
            "ms-sql-s": "mssql",
            "microsoft-ds": "smb",
            "netbios-ssn": "smb",
        }

        return mappings.get(service_name, service_name)

    def _get_port_severity(self, port: int, service: str) -> str:
        """Determine severity based on port/service."""
        critical_services = ["mysql", "postgresql", "mssql", "mongodb", "redis", "memcached"]
        high_services = ["ssh", "ftp", "telnet", "smb", "rdp", "vnc"]

        if service.lower() in critical_services:
            return "HIGH"
        if service.lower() in high_services:
            return "MEDIUM"
        if port < 1024:
            return "LOW"
        return "INFO"

    def _is_interesting_path(self, path: str) -> bool:
        """Check if a path is interesting for further investigation."""
        interesting_patterns = [
            "admin", "dashboard", "manage", "config", "settings",
            "api", "rest", "graphql", "v1", "v2",
            "backup", ".bak", ".old", ".zip", ".sql",
            "upload", "files", "documents",
            "login", "auth", "signin", "register",
            "debug", "test", "dev", "staging",
            "wp-", "joomla", "drupal", "magento",
            ".git", ".svn", ".env", ".htaccess",
            "phpmyadmin", "adminer", "phpinfo",
        ]

        path_lower = path.lower()
        return any(pattern in path_lower for pattern in interesting_patterns)

    def cleanup(self) -> None:
        """Clean up temporary files."""
        import shutil
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception:
            pass

    def get_statistics(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        return {
            "available_tools": list(self.available_tools),
            "executed_tools": list(self.executed_tools),
            "total_findings": len(self.all_findings),
            "findings_by_severity": {
                severity: len([f for f in self.all_findings if f.get("severity") == severity])
                for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            },
        }

    def __del__(self):
        """Cleanup on deletion."""
        self.cleanup()
