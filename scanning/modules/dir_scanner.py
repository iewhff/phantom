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
from urllib.parse import urljoin

import httpx

from scanning.vuln_scanner import Finding, ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from utils.http_client import (
    is_brute_force_allowed,
    is_bug_bounty_mode,
    create_protected_client,
    get_configured_ssl_verify,
)

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
    
    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.timeout = settings.timeouts.request_timeout

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
                type="directory",
                name="Sensitive Paths Discovered (External Tool)",
                severity="MEDIUM",
                description=f"External tool discovered {len(sensitive_paths)} potentially sensitive paths.",
                host=base_url,
                matched_at=base_url,
                evidence=sensitive_paths[:10],
                cvss_score=5.0,
                cwe="CWE-538",
                remediation="Review and restrict access to sensitive directories.",
                metadata={"discovered_by": "gobuster/ffuf", "paths": sensitive_paths},
            ).to_dict())

        if admin_paths:
            findings.append(Finding(
                type="directory",
                name="Admin Panels Discovered (External Tool)",
                severity="LOW",
                description=f"External tool discovered {len(admin_paths)} admin-related paths.",
                host=base_url,
                matched_at=base_url,
                evidence=admin_paths[:10],
                cvss_score=3.0,
                cwe="CWE-200",
                remediation="Ensure admin panels are properly protected.",
                metadata={"discovered_by": "gobuster/ffuf", "paths": admin_paths},
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

        # Track if external tools provided comprehensive coverage
        external_comprehensive = False
        external_paths_found: set[str] = set()

        # BUG BOUNTY SAFETY: Limit scanning when brute force is disabled
        if not self._brute_force_allowed:
            logger.info(
                f"🛡️ DirectoryScanner: Running in limited mode for {host}"
            )
            # Only check for critical exposures (git, env files, etc.)
            vcs_findings = await self._check_version_control(base_url, rate_limiter)
            findings.extend(vcs_findings)
            return {
                "module": self.name,
                "findings": findings,
                "limited_mode": True,
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
                # Reduce to most critical only
                critical_files = [
                    f for f in sensitive_not_found
                    if any(c in f.lower() for c in [".env", "config", "secret", "backup", ".git"])
                ][:10]  # Limit to 10 most critical
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
        """Scan for common directories."""
        findings = []
        found_dirs = []

        # Use protected client with proper SSL settings
        ssl_verify = get_configured_ssl_verify()
        client = create_protected_client(
            timeout=self.timeout,
            verify_ssl=ssl_verify,
            follow_redirects=False,
        )

        async with client:
            for directory in self.DIRECTORIES:
                await rate_limiter.acquire()
                
                url = urljoin(base_url, directory)
                
                try:
                    response = await client.get(url)
                    
                    # Directory found
                    if response.status_code == 200:
                        found_dirs.append({
                            "path": directory,
                            "status": response.status_code,
                            "size": len(response.text),
                        })
                        
                        # Check for directory listing
                        if self._is_directory_listing(response.text):
                            findings.append(Finding(
                                type="directory",
                                name="Directory Listing Enabled",
                                severity="MEDIUM",
                                description=f"Directory listing is enabled at /{directory}. "
                                           f"This exposes the file structure.",
                                host=base_url,
                                matched_at=url,
                                evidence=["Directory listing detected"],
                                cvss_score=5.3,
                                cwe="CWE-548",
                                remediation="Disable directory listing in web server configuration.",
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
                    type="directory",
                    name="Sensitive Directories Found",
                    severity="LOW",
                    description=f"Found {len(sensitive_dirs)} potentially sensitive directories.",
                    host=base_url,
                    matched_at=base_url,
                    evidence=[f"{d['path']} (HTTP {d['status']})" for d in sensitive_dirs],
                    cvss_score=3.7,
                    cwe="CWE-200",
                    remediation="Restrict access to sensitive directories. "
                               "Remove unnecessary files and folders.",
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
        """
        findings = []

        ssl_verify = get_configured_ssl_verify()
        client = create_protected_client(
            timeout=self.timeout,
            verify_ssl=ssl_verify,
            follow_redirects=False,
        )

        async with client:
            for filename in files:
                await rate_limiter.acquire()

                url = urljoin(base_url, filename)

                try:
                    response = await client.get(url)

                    if response.status_code == 200:
                        severity = self._assess_file_severity(filename, response.text)

                        findings.append(Finding(
                            type="sensitive_file",
                            name=f"Sensitive File Exposed: {filename}",
                            severity=severity,
                            description=f"Sensitive file '{filename}' is publicly accessible.",
                            host=base_url,
                            matched_at=url,
                            evidence=[
                                f"File: {filename}",
                                f"Size: {len(response.text)} bytes",
                            ],
                            cvss_score=self._severity_to_cvss(severity),
                            cwe="CWE-200",
                            remediation="Remove sensitive files from web root.",
                        ).to_dict())

                except Exception as e:
                    logger.debug(f"Specific file scan error for {url}: {e}")

        return findings

    async def _scan_files(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Scan for sensitive files."""
        findings = []

        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=False,
            follow_redirects=False,
        ) as client:
            for filename in self.SENSITIVE_FILES:
                await rate_limiter.acquire()
                
                url = urljoin(base_url, filename)
                
                try:
                    response = await client.get(url)
                    
                    if response.status_code == 200:
                        severity = self._assess_file_severity(filename, response.text)
                        
                        findings.append(Finding(
                            type="sensitive_file",
                            name=f"Sensitive File Exposed: {filename}",
                            severity=severity,
                            description=f"Sensitive file '{filename}' is publicly accessible.",
                            host=base_url,
                            matched_at=url,
                            evidence=[
                                f"File: {filename}",
                                f"Size: {len(response.text)} bytes",
                            ],
                            cvss_score=self._severity_to_cvss(severity),
                            cwe="CWE-200",
                            remediation="Remove sensitive files from web root. "
                                       "Restrict access through web server configuration.",
                        ).to_dict())
                        
                except Exception as e:
                    logger.debug(f"File scan error for {url}: {e}")
        
        return findings
    
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
        
        vcs_checks = [
            (".git/HEAD", "Git repository", "refs/heads/"),
            (".git/config", "Git config", "[core]"),
            (".svn/entries", "SVN repository", "svn"),
            (".hg/store", "Mercurial repository", ""),
            (".bzr/README", "Bazaar repository", ""),
        ]
        
        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=False,
            follow_redirects=False,
        ) as client:
            for path, vcs_type, indicator in vcs_checks:
                await rate_limiter.acquire()
                
                url = urljoin(base_url, path)
                
                try:
                    response = await client.get(url)
                    
                    if response.status_code == 200:
                        if not indicator or indicator in response.text:
                            findings.append(Finding(
                                type="vcs_exposure",
                                name=f"{vcs_type} Exposed",
                                severity="HIGH",
                                description=f"{vcs_type} is publicly accessible. "
                                           f"Source code and history can be downloaded.",
                                host=base_url,
                                matched_at=url,
                                evidence=[
                                    f"Path: {path}",
                                    f"Content preview: {response.text[:100]}...",
                                ],
                                cvss_score=7.5,
                                cwe="CWE-527",
                                remediation=f"Remove {vcs_type.split()[0]} folder from web root. "
                                           f"Block access via web server configuration.",
                                references=[
                                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces"
                                ],
                            ).to_dict())
                            
                except Exception as e:
                    logger.debug(f"VCS check error for {url}: {e}")
        
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
        urls = asset_data.get("urls", [])
        
        for url in urls:
            if any(ext in url for ext in [".php", ".asp", ".aspx", ".jsp"]):
                path = url.split("?")[0]
                if "/" in path:
                    filename = path.rsplit("/", 1)[-1]
                    known_files.append(filename)
        
        # Also check common files
        known_files.extend(["index.php", "config.php", "admin.php", "login.php"])
        known_files = list(set(known_files))[:20]
        
        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=False,
            follow_redirects=False,
        ) as client:
            for filename in known_files:
                for ext in self.BACKUP_EXTENSIONS[:5]:
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
                                    type="backup_file",
                                    name=f"Backup File Exposed: {backup_file}",
                                    severity="HIGH",
                                    description=f"Backup file '{backup_file}' contains source code.",
                                    host=base_url,
                                    matched_at=url,
                                    evidence=[
                                        f"File: {backup_file}",
                                        f"Size: {len(content)} bytes",
                                        f"Contains source code indicators",
                                    ],
                                    cvss_score=7.5,
                                    cwe="CWE-530",
                                    remediation="Remove backup files from web server. "
                                               "Configure web server to block backup extensions.",
                                ).to_dict())
                                
                    except Exception as e:
                        logger.debug(f"Backup file check error for {url}: {e}")
        
        return findings
