"""
Directory and file bruteforce scanner module - Enhanced with gobuster/ffuf.

Features:
- Internal directory/file scanning with wordlists
- gobuster integration for fast directory brute-forcing
- ffuf integration as alternative/fallback
- Intelligent tool selection based on availability
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

import httpx

from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from scanning.scan_context import ScanContext
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from utils.http_client import (
    is_brute_force_allowed,
    is_bug_bounty_mode,
    create_protected_client,
    get_configured_ssl_verify,
)
from utils.scan_client import get_scan_client

if TYPE_CHECKING:
    from core.config_manager import Settings
    from scanning.linux_tools_orchestrator import LinuxToolsOrchestrator

logger = get_logger(__name__)

# Flag to track if orchestrator is available
_ORCHESTRATOR_AVAILABLE = True
try:
    from scanning.linux_tools_orchestrator import LinuxToolsOrchestrator, ToolStatus
except ImportError:
    _ORCHESTRATOR_AVAILABLE = False
    logger.debug("LinuxToolsOrchestrator not available - gobuster/ffuf integration disabled")


class DirectoryScanner(ScanModule):
    """
    Directory and file discovery scanner.
    
    Tests for:
    - Common directories and files
    - Backup files
    - Config files
    - Git/SVN exposure
    - Admin panels
    - Sensitive files
    """
    
    name = "directory_scanner"
    
    # Common directories
    DIRECTORIES = [
        # Admin panels
        "admin/", "administrator/", "admin.php", "admin.asp", "admincp/",
        "wp-admin/", "phpmyadmin/", "cpanel/", "webmin/", "manager/",
        "controlpanel/", "adminpanel/", "admin_area/", "siteadmin/",
        
        # API endpoints
        "api/", "api/v1/", "api/v2/", "rest/", "graphql/", "swagger/",
        
        # Config and backup
        "config/", "conf/", "backup/", "backups/", "bak/", "old/",
        "temp/", "tmp/", "test/", "testing/", "dev/", "development/",
        
        # Common directories
        "assets/", "static/", "media/", "uploads/", "files/", "images/",
        "includes/", "inc/", "libs/", "lib/", "vendor/", "node_modules/",
        
        # Version control
        ".git/", ".svn/", ".hg/", ".bzr/", "CVS/",
        
        # Server directories
        "cgi-bin/", "scripts/", "bin/", "logs/", "log/",
        
        # CMS specific
        "wp-content/", "wp-includes/", "sites/default/", "components/",
        "modules/", "themes/", "templates/", "plugins/",
    ]
    
    # Sensitive files
    SENSITIVE_FILES = [
        # Config files
        "config.php", "configuration.php", "config.inc.php", "config.yml",
        "config.json", "settings.php", "settings.py", "settings.json",
        "database.yml", "database.php", ".env", ".env.local", ".env.production",
        "web.config", "app.config", "wp-config.php", "local.xml",
        
        # Backup files
        "backup.sql", "database.sql", "dump.sql", "db.sql", "data.sql",
        "backup.zip", "backup.tar.gz", "www.zip", "site.zip",
        "web.zip", "html.zip", "public.zip",
        
        # Log files
        "error.log", "access.log", "debug.log", "app.log",
        "error_log", "access_log",
        
        # Version control
        ".git/config", ".git/HEAD", ".gitignore", ".svn/entries",
        
        # Server files
        "server-status", "server-info", "phpinfo.php", "info.php",
        "test.php", "info.cfm", ".htaccess", ".htpasswd", "robots.txt",
        "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
        
        # Credentials
        "id_rsa", "id_rsa.pub", "authorized_keys", ".ssh/id_rsa",
        "credentials.xml", "secrets.yml", "secrets.json",
        
        # Readme/docs that might leak info
        "README.md", "README.txt", "CHANGELOG.md", "CHANGELOG.txt",
        "LICENSE", "INSTALL.txt", "UPGRADE.txt",
    ]
    
    # Backup extensions to try
    BACKUP_EXTENSIONS = [
        ".bak", ".backup", ".old", ".orig", ".save", ".swp", ".swo",
        "~", ".copy", ".tmp", ".temp", ".1", ".2",
    ]
    
    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0

        # BUG BOUNTY SAFETY: Check if brute force (directory enumeration) is allowed
        self._brute_force_allowed = is_brute_force_allowed()
        self._bug_bounty_mode = is_bug_bounty_mode()

        # External tool integration
        self._orchestrator: Any = None
        self._use_external_tools = getattr(settings, 'use_linux_tools', True)

        if self._bug_bounty_mode and not self._brute_force_allowed:
            logger.info(
                "🛡️ DirectoryScanner: Brute force DISABLED in bug bounty mode - "
                "will only check critical paths, not full enumeration"
            )

    def _get_orchestrator(self) -> Any:
        """Get or create the Linux tools orchestrator."""
        if not _ORCHESTRATOR_AVAILABLE or not self._use_external_tools:
            return None

        if self._orchestrator is None:
            try:
                self._orchestrator = LinuxToolsOrchestrator(self.settings)
            except Exception as e:
                logger.debug(f"Failed to initialize orchestrator: {e}")
                return None

        return self._orchestrator

    async def _run_external_directory_scan(
        self,
        base_url: str,
    ) -> list[dict[str, Any]]:
        """
        Run external tools (gobuster, ffuf) for fast directory discovery.

        These tools are much faster than Python-based scanning:
        - gobuster: Fast directory/file brute-forcing in Go
        - ffuf: Fast web fuzzer, good alternative to gobuster

        Returns list of discovered paths with metadata.
        """
        discovered = []
        orchestrator = self._get_orchestrator()

        if not orchestrator:
            logger.debug("[DirScanner] External tools not available")
            return discovered

        # Try gobuster first (generally faster)
        if orchestrator.is_tool_available("gobuster"):
            logger.info(f"[DirScanner] Running gobuster on {base_url}")
            try:
                result = await orchestrator.run_single_tool("gobuster", base_url)
                if result.status == ToolStatus.SUCCESS:
                    for finding in result.findings:
                        if finding.get("type") == "directory_found":
                            discovered.append({
                                "path": finding.get("metadata", {}).get("path", ""),
                                "status": finding.get("metadata", {}).get("status_code", 0),
                                "tool": "gobuster",
                                "interesting": finding.get("metadata", {}).get("interesting", False),
                            })
                    logger.info(f"[DirScanner] gobuster found {len(discovered)} paths")
            except Exception as e:
                logger.debug(f"[DirScanner] gobuster error: {e}")

        # Try ffuf as complement or fallback
        if not discovered and orchestrator.is_tool_available("ffuf"):
            logger.info(f"[DirScanner] Running ffuf on {base_url}")
            try:
                result = await orchestrator.run_single_tool("ffuf", base_url)
                if result.status == ToolStatus.SUCCESS:
                    for finding in result.findings:
                        if finding.get("type") == "ffuf_finding":
                            discovered.append({
                                "path": "/" + finding.get("metadata", {}).get("input", ""),
                                "status": finding.get("metadata", {}).get("status_code", 0),
                                "tool": "ffuf",
                                "interesting": False,
                            })
                    logger.info(f"[DirScanner] ffuf found {len(discovered)} paths")
            except Exception as e:
                logger.debug(f"[DirScanner] ffuf error: {e}")

        return discovered

    def _convert_external_findings(
        self,
        external_results: list[dict[str, Any]],
        base_url: str,
    ) -> list[dict[str, Any]]:
        """Convert external tool results to Finding objects."""
        findings = []

        # Group by sensitivity
        sensitive_paths = []
        admin_paths = []
        api_paths = []

        for result in external_results:
            path = result.get("path", "")
            path_lower = path.lower()

            if any(s in path_lower for s in ["admin", "manager", "dashboard", "cpanel"]):
                admin_paths.append(path)
            elif any(s in path_lower for s in ["api", "rest", "graphql", "v1", "v2"]):
                api_paths.append(path)
            elif any(s in path_lower for s in ["backup", "config", ".git", ".env", "secret"]):
                sensitive_paths.append(path)

        # Create findings for interesting discoveries
        if sensitive_paths:
            findings.append(Finding(
                vuln_type=VulnType.DIRECTORY_LISTING,
                name="Sensitive Paths Discovered (External Tool)",
                severity=Severity.MEDIUM,
                description=f"External tool discovered {len(sensitive_paths)} potentially sensitive paths.",
                host=base_url,
                endpoint=base_url,
                evidence=sensitive_paths[:10],
                cvss_score=5.0,
                cwe_id="CWE-538",
                remediation="Review and restrict access to sensitive directories.",
                metadata={"discovered_by": "gobuster/ffuf", "paths": sensitive_paths},
                confidence_score=85,
            ).to_dict())

        if admin_paths:
            findings.append(Finding(
                vuln_type=VulnType.DIRECTORY_LISTING,
                name="Admin Panels Discovered (External Tool)",
                severity=Severity.LOW,
                description=f"External tool discovered {len(admin_paths)} admin-related paths.",
                host=base_url,
                endpoint=base_url,
                evidence=admin_paths[:10],
                cvss_score=3.0,
                cwe_id="CWE-200",
                remediation="Ensure admin panels are properly protected.",
                metadata={"discovered_by": "gobuster/ffuf", "paths": admin_paths},
                confidence_score=75,
            ).to_dict())

        return findings

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """
        Scan for hidden directories and files.

        OPTIMIZATION: External tools (gobuster/ffuf) are MUCH faster than Python:
        - gobuster/ffuf: ~1000 requests/second
        - Python httpx: ~10-50 requests/second

        When external tools succeed, we SKIP internal directory brute force
        to avoid duplicate work. We only run targeted checks not covered by tools.
        """
        findings: list[dict[str, Any]] = []

        base_url = f"https://{host}" if not host.startswith("http") else host

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._ctx.log_context_status()
        self._auth_headers = self._ctx.auth_headers
        if self._ctx.has_auth:
            logger.info(f"[DIR] Using authenticated session ({self._ctx.auth_method})")

        # Track if external tools provided comprehensive coverage
        external_comprehensive = False
        external_paths_found: set[str] = set()

        # DEF-2 FIX: In bounty mode, still check high-value paths, not just VCS
        # Full brute force is disabled, but critical paths should always be tested
        if not self._brute_force_allowed:
            logger.info(
                f"🛡️ DirectoryScanner: Running in smart-limited mode for {host}"
            )
            # Check VCS exposures
            vcs_findings = await self._check_version_control(base_url, rate_limiter)
            findings.extend(vcs_findings)

            # DEF-2 FIX: Also check high-value paths (admin panels, backups, configs)
            # These are critical for bug bounty and not "brute force" in volume terms
            high_value_paths = [
                "/admin", "/administrator", "/wp-admin", "/manage", "/manager",
                "/backup", "/backups", "/db", "/database", "/sql",
                "/config", "/configuration", "/settings", "/setup",
                "/debug", "/phpinfo.php", "/info.php", "/test.php",
                "/.htaccess", "/.htpasswd", "/web.config",
                "/server-status", "/server-info",
                "/actuator", "/actuator/env", "/actuator/health", "/actuator/configprops",
                "/api/debug", "/api/config", "/api/internal",
            ]
            high_value_findings = await self._check_paths_quick(
                base_url, high_value_paths, rate_limiter
            )
            findings.extend(high_value_findings)

            return {
                "module": self.name,
                "findings": findings,
                "limited_mode": True,
                "high_value_checked": len(high_value_paths),
            }

        # Run external tools first (faster and more comprehensive)
        if self._use_external_tools:
            external_results = await self._run_external_directory_scan(base_url)
            if external_results:
                external_findings = self._convert_external_findings(external_results, base_url)
                findings.extend(external_findings)
                logger.info(f"[DirScanner] External tools found {len(external_results)} paths")

                # Track what external tools found for deduplication
                external_paths_found = {r.get("path", "").lower() for r in external_results}

                # External tools ran wordlist of 4000+ entries
                # If they found 5+ paths, they successfully scanned
                external_comprehensive = len(external_results) >= 5

        # OPTIMIZATION: Skip internal brute force if external tools were comprehensive
        # External tools (gobuster/ffuf) already tested our DIRECTORIES wordlist
        # Running Python-based brute force would be:
        # - 100x slower
        # - Testing same paths
        # - Duplicate findings

        if external_comprehensive:
            logger.info(
                f"[DirScanner] External tools comprehensive ({len(external_results)} paths) - "
                "skipping redundant internal directory brute force"
            )

            # Only run checks NOT covered by gobuster/ffuf:
            # 1. VCS exposure (.git/HEAD parsing) - tools find path but don't verify content
            # 2. Backup files (index.php.bak) - tools may not have this wordlist
            # 3. Sensitive file content analysis - tools don't analyze responses

            # Check version control exposure (verify content, not just existence)
            vcs_findings = await self._check_version_control(base_url, rate_limiter)
            findings.extend(vcs_findings)

            # Check backup files (specific patterns tools might miss)
            backup_findings = await self._check_backup_files(base_url, asset_data, rate_limiter)
            findings.extend(backup_findings)

            # Scan for sensitive files NOT in standard wordlists
            # Only check files not already found by external tools
            sensitive_not_found = [
                f for f in self.SENSITIVE_FILES
                if f.lower() not in external_paths_found
                and "/" + f.lower() not in external_paths_found
            ]
            if sensitive_not_found:
                # Prioritize by risk level and limit to 30
                risk_priority = {
                    ".env": 100,
                    ".git": 95,
                    "secret": 90,
                    "private": 85,
                    "password": 80,
                    "config": 75,
                    "backup": 70,
                    "credentials": 90,
                    "key": 85,
                }

                def get_risk(filename: str) -> int:
                    return max((score for p, score in risk_priority.items() if p in filename.lower()), default=50)

                critical_files = sorted(sensitive_not_found, key=get_risk, reverse=True)[:30]
                if critical_files:
                    file_findings = await self._scan_specific_files(
                        base_url, critical_files, rate_limiter
                    )
                    findings.extend(file_findings)

        else:
            # External tools not available - run full internal scan
            logger.info("[DirScanner] Running full internal directory scan")

            # Scan directories (internal brute force)
            dir_findings = await self._scan_directories(base_url, rate_limiter)
            findings.extend(dir_findings)

            # Scan sensitive files
            file_findings = await self._scan_files(base_url, rate_limiter)
            findings.extend(file_findings)

            # Check version control exposure
            vcs_findings = await self._check_version_control(base_url, rate_limiter)
            findings.extend(vcs_findings)

            # Check backup files
            backup_findings = await self._check_backup_files(base_url, asset_data, rate_limiter)
            findings.extend(backup_findings)

        return {
            "module": self.name,
            "findings": findings,
            "external_comprehensive": external_comprehensive,
        }
    
    async def _scan_directories(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Scan for common directories with SPA detection to avoid false positives."""
        findings = []
        found_dirs = []

        # Use protected client with proper SSL settings
        # FIX: Pass auth headers for authenticated directory discovery
        ssl_verify = get_configured_ssl_verify()
        client = create_protected_client(
            timeout=self.timeout,
            verify_ssl=ssl_verify,
            follow_redirects=False,
            custom_headers=self._auth_headers if hasattr(self, "_auth_headers") else {},
        )

        async with client:
            # Get baseline response for SPA detection
            baseline_response = None
            await rate_limiter.acquire()
            try:
                import secrets
                random_path = f"/_phantom_baseline_{secrets.token_hex(8)}/"
                baseline_url = urljoin(base_url, random_path)
                baseline_resp = await client.get(baseline_url)
                if baseline_resp.status_code == 200:
                    # Likely a SPA - all routes return same HTML
                    baseline_response = baseline_resp.text
                    logger.debug(f"[DirScanner] SPA detected - baseline response {len(baseline_response)} bytes")
            except (httpx.HTTPError, httpx.TimeoutException) as e:
                logger.debug(f"[DirScanner] Baseline fetch failed: {e}")

            for directory in self.DIRECTORIES:
                await rate_limiter.acquire()

                url = urljoin(base_url, directory)

                try:
                    response = await client.get(url)

                    # Directory found
                    if response.status_code == 200:
                        content = response.text

                        # SPA false positive check
                        if baseline_response and self._is_same_response(content, baseline_response):
                            logger.debug(f"[DirScanner] Skipping directory {directory} - SPA shell response")
                            continue

                        found_dirs.append({
                            "path": directory,
                            "status": response.status_code,
                            "size": len(content),
                        })

                        # Check for directory listing
                        if self._is_directory_listing(content):
                            findings.append(Finding(
                                vuln_type=VulnType.DIRECTORY_LISTING,
                                name="Directory Listing Enabled",
                                severity=Severity.MEDIUM,
                                description=f"Directory listing is enabled at /{directory}. "
                                           f"This exposes the file structure.",
                                host=base_url,
                                endpoint=url,
                                evidence=["Directory listing detected"],
                                cvss_score=5.3,
                                cwe_id="CWE-548",
                                remediation="Disable directory listing in web server configuration.",
                                confidence_score=85,
                            ).to_dict())

                    elif response.status_code == 403:
                        # Exists but forbidden
                        found_dirs.append({
                            "path": directory,
                            "status": 403,
                            "size": 0,
                        })

                except Exception as e:
                    logger.debug(f"Directory scan error for {url}: {e}")
        
        # Report found directories
        if found_dirs:
            sensitive_dirs = [d for d in found_dirs if any(
                s in d["path"].lower() for s in ["admin", "backup", "config", "git", "svn"]
            )]
            
            if sensitive_dirs:
                findings.append(Finding(
                    vuln_type=VulnType.DIRECTORY_LISTING,
                    name="Sensitive Directories Found",
                    severity=Severity.LOW,
                    description=f"Found {len(sensitive_dirs)} potentially sensitive directories.",
                    host=base_url,
                    endpoint=base_url,
                    evidence=[f"{d['path']} (HTTP {d['status']})" for d in sensitive_dirs],
                    cvss_score=3.7,
                    cwe_id="CWE-200",
                    remediation="Restrict access to sensitive directories. "
                               "Remove unnecessary files and folders.",
                    confidence_score=75,
                ).to_dict())
        
        return findings
    
    def _is_directory_listing(self, content: str) -> bool:
        """Check if response contains directory listing."""
        indicators = [
            "Index of /",
            "Directory listing for",
            "[To Parent Directory]",
            "<title>Directory listing",
            'href="../"',
            "Parent Directory",
        ]
        
        return any(indicator in content for indicator in indicators)
    
    async def _scan_specific_files(
        self,
        base_url: str,
        files: list[str],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Scan for specific files only (used when external tools covered most).

        This is an optimized version that only checks files not found by
        external tools, avoiding duplicate requests.
        Includes SPA detection and content validation to avoid false positives.
        """
        findings = []

        # FIX: Pass auth headers for authenticated directory discovery
        ssl_verify = get_configured_ssl_verify()
        client = create_protected_client(
            timeout=self.timeout,
            verify_ssl=ssl_verify,
            follow_redirects=False,
            custom_headers=self._auth_headers if hasattr(self, "_auth_headers") else {},
        )

        async with client:
            # Get baseline response for SPA detection
            baseline_response = None
            await rate_limiter.acquire()
            try:
                import secrets
                random_path = f"/_phantom_baseline_{secrets.token_hex(8)}.txt"
                baseline_url = urljoin(base_url, random_path)
                baseline_resp = await client.get(baseline_url)
                if baseline_resp.status_code == 200:
                    baseline_response = baseline_resp.text
            except (httpx.HTTPError, httpx.TimeoutException) as e:
                logger.debug(f"[DirScanner] Baseline fetch failed: {e}")

            for filename in files:
                await rate_limiter.acquire()

                url = urljoin(base_url, filename)

                try:
                    response = await client.get(url)

                    if response.status_code == 200:
                        content = response.text

                        # SPA false positive check
                        if baseline_response and self._is_same_response(content, baseline_response):
                            logger.debug(f"[DirScanner] Skipping {filename} - SPA shell response")
                            continue

                        # Content validation
                        if not self._validate_file_content(filename, content):
                            logger.debug(f"[DirScanner] Skipping {filename} - content validation failed")
                            continue

                        severity = self._assess_file_severity(filename, content)
                        confidence = {"CRITICAL": 95, "HIGH": 90, "MEDIUM": 85, "LOW": 75}.get(severity, 80)

                        findings.append(Finding(
                            vuln_type=VulnType.INFO_DISCLOSURE,
                            name=f"Sensitive File Exposed: {filename}",
                            severity=severity,
                            description=f"Sensitive file '{filename}' is publicly accessible.",
                            host=base_url,
                            endpoint=url,
                            evidence=[
                                f"File: {filename}",
                                f"Size: {len(content)} bytes",
                                f"Content verified: true",
                            ],
                            cvss_score=self._severity_to_cvss(severity),
                            cwe_id="CWE-200",
                            remediation="Remove sensitive files from web root.",
                            confidence_score=confidence,
                        ).to_dict())

                except Exception as e:
                    logger.debug(f"Specific file scan error for {url}: {e}")

        return findings

    async def _scan_files(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Scan for sensitive files with SPA detection to avoid false positives."""
        findings = []

        async with get_scan_client(
            timeout=self.timeout,
            verify_ssl=False,
            follow_redirects=False,
            custom_headers=self._auth_headers if hasattr(self, "_auth_headers") else {},
        ) as client:
            # Get baseline response for SPA detection
            # Request a random path that shouldn't exist
            baseline_response = None
            await rate_limiter.acquire()
            try:
                import secrets
                random_path = f"/_phantom_baseline_{secrets.token_hex(8)}.txt"
                baseline_url = urljoin(base_url, random_path)
                baseline_resp = await client.get(baseline_url)
                if baseline_resp.status_code == 200:
                    # SPA detected - all routes return same HTML
                    baseline_response = baseline_resp.text
                    logger.debug(f"[DirScanner] SPA detected - baseline response {len(baseline_response)} bytes")
            except (httpx.HTTPError, httpx.TimeoutException) as e:
                logger.debug(f"[DirScanner] Baseline fetch failed: {e}")

            for filename in self.SENSITIVE_FILES:
                await rate_limiter.acquire()

                url = urljoin(base_url, filename)

                try:
                    response = await client.get(url)

                    if response.status_code == 200:
                        content = response.text

                        # SPA false positive check: if response matches baseline, skip
                        if baseline_response and self._is_same_response(content, baseline_response):
                            logger.debug(f"[DirScanner] Skipping {filename} - SPA shell response")
                            continue

                        # Content validation: verify response looks like the expected file type
                        if not self._validate_file_content(filename, content):
                            logger.debug(f"[DirScanner] Skipping {filename} - content doesn't match expected type")
                            continue

                        severity = self._assess_file_severity(filename, content)
                        confidence = {"CRITICAL": 95, "HIGH": 90, "MEDIUM": 85, "LOW": 75}.get(severity, 80)

                        findings.append(Finding(
                            vuln_type=VulnType.INFO_DISCLOSURE,
                            name=f"Sensitive File Exposed: {filename}",
                            severity=severity,
                            description=f"Sensitive file '{filename}' is publicly accessible.",
                            host=base_url,
                            endpoint=url,
                            evidence=[
                                f"File: {filename}",
                                f"Size: {len(content)} bytes",
                                f"Content verified: true",
                            ],
                            cvss_score=self._severity_to_cvss(severity),
                            cwe_id="CWE-200",
                            remediation="Remove sensitive files from web root. "
                                       "Restrict access through web server configuration.",
                            confidence_score=confidence,
                        ).to_dict())

                except Exception as e:
                    logger.debug(f"File scan error for {url}: {e}")

        return findings

    def _is_same_response(self, content1: str, content2: str) -> bool:
        """Check if two responses are essentially the same (SPA detection).

        Uses structural hash comparison to handle dynamic content like
        nonces, timestamps, and CSRF tokens that change between requests.
        """
        import hashlib
        import re

        # Quick length check with larger tolerance for dynamic content
        if abs(len(content1) - len(content2)) > 2000:
            return False

        # Extract structural HTML (remove dynamic values)
        def extract_structure(html: str) -> str:
            """Remove dynamic content, keep HTML structure."""
            # Remove nonces, timestamps, CSRF tokens
            s = re.sub(r'nonce="[^"]*"', 'nonce=""', html)
            s = re.sub(r'csrf[_-]?token[^"]*"[^"]*"', 'csrf=""', s, flags=re.I)
            s = re.sub(r'\d{10,}', '', s)  # Unix timestamps
            s = re.sub(r'[a-f0-9]{32,}', '', s)  # Long hashes/IDs
            # Remove script/style content (often has dynamic values)
            s = re.sub(r'<script[^>]*>.*?</script>', '<script></script>', s, flags=re.DOTALL | re.I)
            s = re.sub(r'<style[^>]*>.*?</style>', '<style></style>', s, flags=re.DOTALL | re.I)
            # Keep only tag structure
            return re.sub(r'>\\s+<', '><', s)

        struct1 = extract_structure(content1)
        struct2 = extract_structure(content2)

        # Hash comparison
        hash1 = hashlib.sha256(struct1.encode('utf-8', errors='ignore')).hexdigest()
        hash2 = hashlib.sha256(struct2.encode('utf-8', errors='ignore')).hexdigest()

        return hash1 == hash2

    def _is_login_or_error_page(self, content: str, status_code: int = 200) -> bool:
        """Check if response is a login page or error page (not real content)."""
        if status_code >= 400:
            return True

        content_lower = content.lower()

        # Login page indicators
        login_indicators = [
            "login", "sign in", "signin", "log in", "authenticate",
            "username", "password", "forgot password", "remember me",
        ]
        login_form_count = sum(1 for ind in login_indicators if ind in content_lower)
        if login_form_count >= 3:
            return True

        # Password input field is a strong indicator
        if '<input' in content_lower and 'type="password"' in content_lower:
            return True
        if '<input' in content_lower and "type='password'" in content_lower:
            return True

        return False

    def _validate_file_content(self, filename: str, content: str) -> bool:
        """Validate that file content matches expected type to avoid false positives."""
        filename_lower = filename.lower()
        content_lower = content.lower()

        # HTML/SPA detection - these are NOT real config/backup files
        html_indicators = ["<!doctype html", "<html", "<head>", "<body>", "<script", "ng-app", "react", "vue"]
        is_html = any(ind in content_lower for ind in html_indicators)

        # .env files should have KEY=value patterns
        if ".env" in filename_lower:
            if is_html:
                return False
            # Real .env files have patterns like KEY=value or KEY="value"
            import re
            env_pattern = re.compile(r'^[A-Z_][A-Z0-9_]*\s*=', re.MULTILINE)
            return bool(env_pattern.search(content))

        # SQL files should have SQL keywords
        if filename_lower.endswith(".sql"):
            if is_html:
                return False
            sql_keywords = ["select ", "insert ", "create ", "drop ", "alter ", "update ", "delete "]
            return any(kw in content_lower for kw in sql_keywords)

        # PHP config files should have PHP code
        if filename_lower.endswith(".php"):
            if is_html and "<?php" not in content_lower:
                return False
            return "<?php" in content_lower or "<?=" in content_lower

        # Config files (yml, json, xml)
        if any(filename_lower.endswith(ext) for ext in [".yml", ".yaml", ".json", ".xml"]):
            if is_html:
                return False
            # YAML should have key: value patterns
            if filename_lower.endswith((".yml", ".yaml")):
                return ":" in content and not is_html
            # JSON should start with { or [
            if filename_lower.endswith(".json"):
                stripped = content.strip()
                return stripped.startswith(("{", "["))
            # XML should have <?xml or <root tags
            if filename_lower.endswith(".xml"):
                return "<?xml" in content_lower or content.strip().startswith("<")

        # Log files
        if filename_lower.endswith(".log") or "log" in filename_lower:
            if is_html:
                return False
            # Logs typically have timestamps or log levels
            log_patterns = ["error", "warning", "info", "debug", "[", "timestamp", "exception"]
            return any(p in content_lower for p in log_patterns)

        # Git files
        if ".git/" in filename_lower:
            if is_html:
                return False
            if "HEAD" in filename:
                return "ref:" in content_lower or content.strip().startswith(("refs/", "commit"))
            if "config" in filename:
                return "[core]" in content or "[remote" in content
            return True  # Other git files

        # htaccess/htpasswd
        if filename_lower in [".htaccess", ".htpasswd"]:
            if is_html:
                return False
            if ".htaccess" in filename_lower:
                return any(d in content for d in ["RewriteRule", "Deny", "Allow", "Options", "DirectoryIndex"])
            if ".htpasswd" in filename_lower:
                return ":" in content and len(content.split(":")) >= 2

        # Key files
        if "id_rsa" in filename_lower or "private" in filename_lower:
            if is_html:
                return False
            return "-----BEGIN" in content

        # Default: if it looks like HTML, it's probably not the real file
        if is_html:
            return False

        return True
    
    def _assess_file_severity(self, filename: str, content: str) -> str:
        """Assess severity based on file type and content."""
        # Critical files
        critical_indicators = [
            ("password", "HIGH"),
            ("secret", "HIGH"),
            ("api_key", "HIGH"),
            ("apikey", "HIGH"),
            ("private_key", "CRITICAL"),
            ("BEGIN RSA PRIVATE", "CRITICAL"),
            ("BEGIN OPENSSH PRIVATE", "CRITICAL"),
            ("AWS_ACCESS_KEY", "CRITICAL"),
            ("AWS_SECRET", "CRITICAL"),
        ]
        
        for indicator, severity in critical_indicators:
            if indicator.lower() in content.lower():
                return severity
        
        # File-based severity
        critical_files = [".env", "config.php", "wp-config.php", "database.yml"]
        high_files = ["backup.sql", "dump.sql", ".htpasswd", "id_rsa"]
        
        if any(f in filename for f in critical_files):
            return "CRITICAL"
        if any(f in filename for f in high_files):
            return "HIGH"
        if ".git" in filename or ".svn" in filename:
            return "HIGH"
        
        return "MEDIUM"
    
    def _severity_to_cvss(self, severity: str) -> float:
        """Convert severity to CVSS score."""
        mapping = {
            "CRITICAL": 9.8,
            "HIGH": 7.5,
            "MEDIUM": 5.3,
            "LOW": 3.7,
        }
        return mapping.get(severity, 5.0)
    
    async def _check_version_control(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Check for exposed version control repositories."""
        findings = []

        # Each entry: (path, display_name, required_indicator)
        # indicator MUST be non-empty to avoid FP on SPAs that return HTML for any path
        vcs_checks = [
            (".git/HEAD", "Git repository", "refs/heads/"),
            (".git/config", "Git config", "[core]"),
            (".svn/entries", "SVN repository", "svn"),
            (".hg/store", "Mercurial repository", "fncache"),
            (".bzr/README", "Bazaar repository", "Bazaar"),
        ]

        async with get_scan_client(
            timeout=self.timeout,
            verify_ssl=False,
            follow_redirects=False,
            custom_headers=self._auth_headers if hasattr(self, "_auth_headers") else {},
        ) as client:
            # Fetch homepage once for SPA detection
            try:
                await rate_limiter.acquire()
                homepage = await client.get(base_url)
                homepage_text = homepage.text
            except (httpx.HTTPError, httpx.TimeoutException) as e:
                logger.debug(f"[DirScanner] Homepage fetch failed: {e}")
                homepage_text = ""

            for path, vcs_type, indicator in vcs_checks:
                await rate_limiter.acquire()

                url = urljoin(base_url, path)

                try:
                    response = await client.get(url)

                    if response.status_code == 200:
                        # SPA detection: if response is the same as homepage, skip
                        if homepage_text and self._is_same_response(response.text, homepage_text):
                            logger.debug(f"VCS check {path}: SPA fallback (same as homepage)")
                            continue

                        # Reject HTML responses — real VCS files are never HTML
                        # Check full response, not just first 500 chars (may have wrapped content)
                        content_lower = response.text.lower()
                        html_indicators = ["<!doctype html", "<html", "</html>", "<head>", "<body>"]
                        if any(ind in content_lower for ind in html_indicators):
                            # But allow if VCS indicator is also present (wrapped in HTML)
                            if indicator and indicator.lower() in content_lower:
                                logger.debug(f"VCS check {path}: HTML with VCS content - still valid!")
                            else:
                                logger.debug(f"VCS check {path}: HTML response (not a VCS file)")
                                continue

                        if indicator and indicator in response.text:
                            findings.append(Finding(
                                vuln_type=VulnType.SOURCE_CODE_DISCLOSURE,
                                name=f"{vcs_type} Exposed",
                                severity=Severity.HIGH,
                                description=f"{vcs_type} is publicly accessible. "
                                           f"Source code and history can be downloaded.",
                                host=base_url,
                                endpoint=url,
                                evidence=[
                                    f"Path: {path}",
                                    f"Content preview: {response.text[:100]}...",
                                ],
                                cvss_score=7.5,
                                cwe_id="CWE-527",
                                remediation=f"Remove {vcs_type.split()[0]} folder from web root. "
                                           f"Block access via web server configuration.",
                                references=[
                                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces"
                                ],
                                confidence_score=90,
                            ).to_dict())

                except Exception as e:
                    logger.debug(f"VCS check error for {url}: {e}")

        return findings

    async def _check_paths_quick(
        self,
        base_url: str,
        paths: list[str],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """DEF-2 FIX: Quick check for high-value paths in bounty mode.

        This is not full brute-force - just checks critical paths that are
        commonly exposed and have high security impact.
        """
        findings = []

        async with get_scan_client(
            timeout=self.timeout,
            verify_ssl=False,
            follow_redirects=False,
            custom_headers=self._auth_headers if hasattr(self, "_auth_headers") else {},
        ) as client:
            # Get homepage for SPA detection
            try:
                await rate_limiter.acquire()
                homepage = await client.get(base_url)
                homepage_text = homepage.text
                homepage_hash = hash(homepage_text[:1000])
            except Exception:
                homepage_text = ""
                homepage_hash = 0

            for path in paths:
                await rate_limiter.acquire()
                url = urljoin(base_url, path)

                try:
                    response = await client.get(url)

                    # Skip non-200 responses (404, 403, 500)
                    if response.status_code != 200:
                        continue

                    # SPA detection: same content as homepage
                    if homepage_text and hash(response.text[:1000]) == homepage_hash:
                        continue

                    # Skip if it's just an HTML error page
                    content_lower = response.text.lower()
                    if "<html" in content_lower:
                        # Check if it has meaningful content (not just error)
                        if "not found" in content_lower or "error" in content_lower:
                            continue
                        # Admin panels, config pages in HTML are valid findings
                        admin_indicators = ["login", "password", "admin", "dashboard", "config"]
                        if not any(ind in content_lower for ind in admin_indicators):
                            continue

                    # Found something interesting!
                    severity = "HIGH" if any(s in path for s in ["/admin", "/config", "/backup", "/actuator/env"]) else "MEDIUM"

                    findings.append({
                        "type": "directory_exposure",
                        "name": f"Sensitive Path Exposed: {path}",
                        "severity": severity,
                        "description": f"The path {path} returned accessible content (status 200).",
                        "host": urlparse(base_url).netloc,
                        "matched_at": url,
                        "evidence": [
                            f"URL: {url}",
                            f"Status: {response.status_code}",
                            f"Content-Length: {len(response.text)}",
                            f"Content-Type: {response.headers.get('content-type', 'unknown')}",
                        ],
                        "confidence": 75.0,
                        "cvss_score": 5.3 if severity == "MEDIUM" else 7.5,
                        "cwe": "CWE-200",
                        "remediation": f"Restrict access to {path} or remove if not needed.",
                    })

                except Exception as e:
                    logger.debug(f"[DirScanner] Quick check failed for {path}: {e}")

        return findings

    async def _check_backup_files(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Check for backup files of known pages."""
        findings = []
        
        # Get known PHP/ASP files from asset data
        known_files = []
        urls = []
        if isinstance(asset_data, dict):
            # Removed invalid type check; ensure block logic
                urls = asset_data.get("urls", [])
        
        for url in urls:
            if any(ext in url for ext in [".php", ".asp", ".aspx", ".jsp"]):
                path = url.split("?")[0]
                if "/" in path:
                    filename = path.rsplit("/", 1)[-1]
                    known_files.append(filename)
        
        # Also check common files
        known_files.extend(["index.php", "config.php", "admin.php", "login.php"])
        known_files = list(set(known_files))[:30]  # Increased limit

        # Use all backup extensions, prioritized by likelihood
        backup_extensions = [
            ".bak", ".backup", ".old", ".orig",  # Most common
            ".save", "~", ".swp", ".swo",        # vim/emacs
            ".copy", ".tmp", ".temp",            # Temporary files
            "_backup", "_old", "_bak",           # Suffix variations
        ]

        async with get_scan_client(
            timeout=self.timeout,
            verify_ssl=False,
            follow_redirects=False,
            custom_headers=self._auth_headers if hasattr(self, "_auth_headers") else {},
        ) as client:
            for filename in known_files:
                for ext in backup_extensions:  # All extensions
                    await rate_limiter.acquire()
                    
                    backup_file = filename + ext
                    url = urljoin(base_url, backup_file)
                    
                    try:
                        response = await client.get(url)
                        
                        if response.status_code == 200:
                            # Check if it's actual source code
                            content = response.text
                            
                            if any(ind in content for ind in ["<?php", "<%", "<?=", "import ", "def "]):
                                findings.append(Finding(
                                    vuln_type=VulnType.BACKUP_FILE,
                                    name=f"Backup File Exposed: {backup_file}",
                                    severity=Severity.HIGH,
                                    description=f"Backup file '{backup_file}' contains source code.",
                                    host=base_url,
                                    endpoint=url,
                                    evidence=[
                                        f"File: {backup_file}",
                                        f"Size: {len(content)} bytes",
                                        f"Contains source code indicators",
                                    ],
                                    cvss_score=7.5,
                                    cwe_id="CWE-530",
                                    remediation="Remove backup files from web server. "
                                               "Configure web server to block backup extensions.",
                                    confidence_score=90,
                                ).to_dict())
                                
                    except Exception as e:
                        logger.debug(f"Backup file check error for {url}: {e}")
        
        return findings
