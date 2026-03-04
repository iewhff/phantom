"""
Nuclei template scanner runner - Enhanced Edition.
Executes Nuclei templates against targets with intelligent template selection.

Features:
- Technology-aware template selection
- CVE-specific scanning based on detected tech versions
- Vulnerability chaining support
- Custom and community template support
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from scanning.findings import Finding, VulnType
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from scanning.scan_context import ScanContext

if TYPE_CHECKING:
    from core.config_manager import Settings
    from utils.rate_limiter import RateLimiter

logger = get_logger(__name__)

# Technology to template mapping for targeted scanning
TECH_TEMPLATE_MAP = {
    # CMS
    "wordpress": ["http/cves/wordpress/", "http/vulnerabilities/wordpress/"],
    "drupal": ["http/cves/drupal/", "http/vulnerabilities/drupal/"],
    "joomla": ["http/cves/joomla/", "http/vulnerabilities/joomla/"],
    "magento": ["http/cves/magento/", "http/vulnerabilities/magento/"],
    # Frameworks
    "laravel": ["http/cves/laravel/", "http/vulnerabilities/laravel/"],
    "django": ["http/cves/django/", "http/vulnerabilities/django/"],
    "spring": ["http/cves/spring/", "http/vulnerabilities/spring/"],
    "rails": ["http/cves/rails/", "http/vulnerabilities/rails/"],
    # Web servers
    "nginx": ["http/cves/nginx/", "http/vulnerabilities/nginx/"],
    "apache": ["http/cves/apache/", "http/vulnerabilities/apache/"],
    "iis": ["http/cves/iis/", "http/vulnerabilities/iis/"],
    "tomcat": ["http/cves/tomcat/", "http/vulnerabilities/tomcat/"],
    # Languages
    "php": ["http/cves/php/", "http/vulnerabilities/php/"],
    "java": ["http/cves/java/", "http/vulnerabilities/java/"],
    "nodejs": ["http/cves/nodejs/", "http/vulnerabilities/nodejs/"],
    # Databases
    "mysql": ["network/cves/mysql/"],
    "postgresql": ["network/cves/postgresql/"],
    "mongodb": ["network/cves/mongodb/"],
    "redis": ["network/cves/redis/"],
    # Cloud/Infrastructure
    "aws": ["http/exposures/aws/", "cloud/aws/"],
    "azure": ["http/exposures/azure/", "cloud/azure/"],
    "kubernetes": ["http/exposures/kubernetes/", "kubernetes/"],
    "docker": ["http/exposures/docker/", "http/cves/docker/"],
    # Other
    "jenkins": ["http/cves/jenkins/", "http/vulnerabilities/jenkins/"],
    "gitlab": ["http/cves/gitlab/", "http/vulnerabilities/gitlab/"],
    "grafana": ["http/cves/grafana/", "http/vulnerabilities/grafana/"],
    "elasticsearch": ["http/cves/elasticsearch/", "http/vulnerabilities/elasticsearch/"],
}


def _find_nuclei_binary() -> str:
    """Find nuclei binary - check local tools dir first, then system PATH."""
    # Check local tools directory first
    project_root = Path(__file__).parent.parent.parent
    local_nuclei = project_root / "tools" / "nuclei"
    if local_nuclei.exists() and os.access(local_nuclei, os.X_OK):
        logger.debug(f"[nuclei] Using local binary: {local_nuclei}")
        return str(local_nuclei)
    
    # Fallback to system PATH
    import shutil
    system_nuclei = shutil.which("nuclei")
    if system_nuclei:
        logger.debug(f"[nuclei] Using system binary: {system_nuclei}")
        return system_nuclei
    
    # Not found
    return "nuclei"


class NucleiRunner(ScanModule):
    """
    Runs Nuclei vulnerability scanner.
    
    Features:
    - Template-based scanning
    - Severity filtering
    - Rate limiting support
    - JSON output parsing
    - Auto-detection of local or system binary
    """
    
    name = "nuclei"
    
    # Severity to CVSS mapping
    SEVERITY_CVSS = {
        "critical": 9.5,
        "high": 7.5,
        "medium": 5.0,
        "low": 3.0,
        "info": 0.0,
    }
    
    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        # Always use auto-detect to find the binary correctly
        self.nuclei_path = _find_nuclei_binary()
        logger.debug(f"[nuclei] Binary path: {self.nuclei_path}")

        # Get module config
        # BUG-FIX: Handle both dict and object settings
        module_config = settings.scanning.modules.get("nuclei", {}) if hasattr(settings, 'scanning') else {}
        self.templates_path = module_config.get(
            "templates_path",
            "~/.nuclei-templates"
        )
        self.severity_filter = module_config.get(
            "severity",
            ["critical", "high", "medium"]
        )
        self.exclude_tags = module_config.get(
            "exclude_tags",
            ["dos", "fuzz"]
        )
        # Technology-aware scanning
        self.detected_technologies: list[str] = []
        self.use_tech_templates = module_config.get("use_tech_templates", True)

    def set_technologies(self, technologies: list[str]) -> None:
        """Set detected technologies for targeted template selection."""
        self.detected_technologies = [t.lower() for t in technologies]
        logger.debug(f"[nuclei] Technologies set: {self.detected_technologies}")

    def _get_tech_specific_templates(self) -> list[str]:
        """Get template directories based on detected technologies."""
        templates = []

        for tech in self.detected_technologies:
            # Direct match
            if tech in TECH_TEMPLATE_MAP:
                templates.extend(TECH_TEMPLATE_MAP[tech])
            else:
                # Partial match
                for key, paths in TECH_TEMPLATE_MAP.items():
                    if key in tech or tech in key:
                        templates.extend(paths)

        # Deduplicate while preserving order
        seen = set()
        unique_templates = []
        for t in templates:
            if t not in seen:
                seen.add(t)
                unique_templates.append(t)

        return unique_templates
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """Run Nuclei scan on host with technology-aware template selection."""

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        logger.info(f"[nuclei] Starting enhanced scan on {host}")

        # Set detected technologies for targeted scanning
        technologies = []
        if isinstance(asset_data, dict):
            # Removed invalid type check; ensure block logic
                technologies = asset_data.get("technologies", [])
        if technologies:
            self.set_technologies(technologies)
            logger.info(f"[nuclei] Targeting technologies: {technologies[:5]}")

        # Build targets (host + discovered URLs)
        targets = self._build_targets(host, asset_data)
        
        # Build command - get rate limit from RateLimiter
        rate_limit = getattr(rate_limiter, 'default_rate', 10)
        cmd = self._build_command(host, rate_limit)
        
        # Execute
        findings = []
        info_items = []
        
        try:
            result = await self._execute(cmd, targets)
            
            for item in result:
                finding = self._parse_result(item, host)
                
                if finding.severity == "INFO":
                    info_items.append(finding.to_dict())
                else:
                    findings.append(finding.to_dict())
            
            logger.info(f"[nuclei] Found {len(findings)} vulnerabilities on {host}")
            
        except Exception as e:
            logger.error(f"[nuclei] Scan failed for {host}: {e}")
        
        return {"findings": findings, "info": info_items}
    
    def _build_targets(
        self,
        host: str,
        asset_data: dict[str, Any],
    ) -> list[str]:
        """Build target list for Nuclei."""
        targets = set()
        
        # Add host with protocols
        targets.add(f"https://{host}")
        targets.add(f"http://{host}")
        
        # Add discovered URLs
        urls = []
        if isinstance(asset_data, dict):
            urls = asset_data.get("urls", [])
        for url in urls[:100]:  # Limit to first 100 URLs
            targets.add(url)
        
        return list(targets)
    
    def _build_command(self, host: str, rate_limit: int) -> list[str]:
        """Build Nuclei command with technology-aware template selection."""
        # Include info severity to get technology detections and exposures
        severities = list(self.severity_filter)
        if "info" not in [s.lower() for s in severities]:
            severities.append("info")

        cmd = [
            self.nuclei_path,
            "-severity", ",".join(severities),
            "-jsonl",  # JSON Lines output (v3.x format)
            "-silent",
            "-no-color",
            "-rate-limit", str(max(rate_limit, 50)),  # At least 50 rps
            "-timeout", "15",
            "-retries", "2",
            "-nc",  # No color
        ]

        # Add technology-specific templates if available
        tech_templates = []
        if self.use_tech_templates and self.detected_technologies:
            tech_templates = self._get_tech_specific_templates()
            logger.info(f"[nuclei] Using {len(tech_templates)} tech-specific templates")

        if tech_templates:
            # Use technology-specific templates + general templates
            for template in tech_templates:
                cmd.extend(["-t", template])
            # Also include general vulnerability checks
            cmd.extend(["-t", "http/vulnerabilities/generic/"])
            cmd.extend(["-t", "http/misconfiguration/"])
            cmd.extend(["-t", "http/exposures/"])
        else:
            # Use default template directories for faster/better results
            cmd.extend([
                "-t", "http/vulnerabilities/",
                "-t", "http/misconfiguration/",
                "-t", "http/exposures/",
                "-t", "http/technologies/",
            ])

        # Exclude tags
        if self.exclude_tags:
            cmd.extend(["-exclude-tags", ",".join(self.exclude_tags)])

        return cmd
    
    async def _execute(
        self,
        cmd: list[str],
        targets: list[str],
    ) -> list[dict]:
        """Execute Nuclei scan."""
        # Create targets file
        import tempfile

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(targets))
            targets_file = f.name

        try:
            cmd.extend(["-list", targets_file])

            logger.debug(f"[nuclei] Executing: {' '.join(cmd)}")
            logger.debug(f"[nuclei] Targets ({len(targets)}): {targets[:5]}...")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.settings.timeouts.vuln_scan,
            )

            # Log stderr if any issues
            stderr_text = stderr.decode("utf-8", errors="replace").strip()
            if stderr_text:
                # Log first 1000 chars of stderr for debugging
                logger.info(f"[nuclei] Output: {stderr_text[:1000]}")

            # Check return code (0=success, 1=no results found but no error)
            if proc.returncode not in (0, 1):
                logger.warning(f"[nuclei] Process exited with code {proc.returncode}")

            # Parse JSON lines
            results = []
            stdout_text = stdout.decode("utf-8", errors="replace")
            logger.debug(f"[nuclei] stdout length: {len(stdout_text)} chars")

            for line in stdout_text.split('\n'):
                if not line.strip():
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

            logger.debug(f"[nuclei] Parsed {len(results)} results")
            return results

        finally:
            import os
            os.unlink(targets_file)
    
    def _parse_result(self, result: dict, host: str) -> Finding:
        """Parse Nuclei result to Finding."""
        info = result.get("info", {})
        severity = info.get("severity", "info").upper()
        
        # Extract CVSS
        metadata = info.get("metadata", {})
        # Removed invalid type check; ensure block logic
        cvss = metadata.get("cvss-score")
        if cvss is None:
            cvss = self.SEVERITY_CVSS.get(severity.lower(), 0.0)
        
        return Finding(
            id=result.get("template-id", ""),
            vuln_type=VulnType.OTHER,
            name=info.get("name", "Unknown"),
            severity=severity,
            description=info.get("description", ""),
            host=host,
            endpoint=result.get("matched-at", ""),
            evidence=result.get("extracted-results", []),
            cvss_score=float(cvss),
            confidence_score=90,  # Nuclei templates are well-tested
            cwe_id=info.get("classification", {}).get("cwe-id", ""),
            remediation=info.get("remediation", ""),
            references=info.get("reference", []),
            metadata={
                "template": result.get("template-id"),
                "matcher_name": result.get("matcher-name"),
                "curl_command": result.get("curl-command"),
                "tags": info.get("tags", []),
            },
        )
