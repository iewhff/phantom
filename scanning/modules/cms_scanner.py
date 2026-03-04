"""
CMS Security Scanner module.
Detects and tests CMS-specific vulnerabilities.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin


from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from utils.scan_client import get_scan_client
from scanning.scan_context import ScanContext

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class CMSScanner(ScanModule):
    """
    CMS Security scanner.
    
    Detects and tests:
    - WordPress vulnerabilities
    - Joomla vulnerabilities
    - Drupal vulnerabilities
    - Common CMS misconfigurations
    - Plugin/theme vulnerabilities
    """
    
    name = "cms_scanner"
    
    # CMS detection patterns
    CMS_SIGNATURES = {
        "wordpress": {
            "paths": [
                "/wp-login.php",
                "/wp-admin/",
                "/wp-content/",
                "/wp-includes/",
                "/xmlrpc.php",
            ],
            "meta": ["generator.*wordpress", "wp-content", "wp-includes"],
            "headers": ["x-powered-by.*php"],
        },
        "joomla": {
            "paths": [
                "/administrator/",
                "/components/",
                "/modules/",
                "/templates/",
                "/configuration.php",
            ],
            "meta": ["generator.*joomla", "joomla"],
            "headers": [],
        },
        "drupal": {
            "paths": [
                "/user/login",
                "/node/",
                "/sites/default/",
                "/modules/",
                "/themes/",
            ],
            "meta": ["generator.*drupal", "drupal"],
            "headers": ["x-drupal-cache", "x-generator.*drupal"],
        },
        "magento": {
            "paths": [
                "/admin/",
                "/skin/",
                "/js/mage/",
                "/downloader/",
            ],
            "meta": ["magento", "mage"],
            "headers": [],
        },
        "shopify": {
            "paths": [],
            "meta": ["shopify"],
            "headers": ["x-shopify-stage"],
        },
    }
    
    # WordPress specific vulnerabilities
    WP_VULNS = {
        "user_enumeration": [
            "/?author=1",
            "/wp-json/wp/v2/users",
            "/wp-json/wp/v2/users/?per_page=100",
        ],
        "xmlrpc": "/xmlrpc.php",
        "readme": "/readme.html",
        "debug_log": "/wp-content/debug.log",
        "uploads_listing": "/wp-content/uploads/",
        "config_backup": [
            "/wp-config.php.bak",
            "/wp-config.php.old",
            "/wp-config.php~",
            "/wp-config.bak",
            "/wp-config.old",
        ],
    }
    
    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """Scan for CMS vulnerabilities."""

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        findings: list[dict[str, Any]] = []
        
        base_url = f"https://{host}" if not host.startswith("http") else host
        
        # Detect CMS
        detected_cms = await self._detect_cms(base_url, rate_limiter)
        
        if not detected_cms:
            return {
                "module": self.name,
                "findings": [],
                "cms_detected": None,
            }
        
        logger.info(f"Detected CMS: {detected_cms}")
        
        # Run CMS-specific tests
        if detected_cms == "wordpress":
            wp_findings = await self._scan_wordpress(base_url, rate_limiter)
            findings.extend(wp_findings)
            
        elif detected_cms == "joomla":
            joomla_findings = await self._scan_joomla(base_url, rate_limiter)
            findings.extend(joomla_findings)
            
        elif detected_cms == "drupal":
            drupal_findings = await self._scan_drupal(base_url, rate_limiter)
            findings.extend(drupal_findings)
        
        # Generic CMS checks
        generic_findings = await self._generic_cms_checks(base_url, detected_cms, rate_limiter)
        findings.extend(generic_findings)
        
        return {
            "module": self.name,
            "findings": findings,
            "cms_detected": detected_cms,
        }
    
    async def _detect_cms(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> str | None:
        """Detect which CMS is running."""
        
        async with get_scan_client(
            timeout=self.timeout,
            verify_ssl=False,
            follow_redirects=True,
        ) as client:
            await rate_limiter.acquire()

            try:
                response = await client.get(base_url)
                content = response.text.lower()
                headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            except Exception as e:
                logger.debug(f"CMS detection error: {e}")
                return None
            
            # Check each CMS
            for cms, signatures in self.CMS_SIGNATURES.items():
                # Check meta tags
                for pattern in signatures.get("meta", []):
                    if re.search(pattern, content):
                        return cms
                
                # Check headers
                for pattern in signatures.get("headers", []):
                    for header, value in headers.items():
                        if re.search(pattern, f"{header}: {value}"):
                            return cms
            
            # Check paths — require CMS-specific content, not just status code
            _CMS_PATH_VALIDATORS: dict[str, list[str]] = {
                "wordpress": ["wp-content", "wp-includes", "wp-login", "wordpress"],
                "joomla": ["joomla", "com_content", "josession", "/administrator/"],
                "drupal": ["drupal", "sites/default", 'data-drupal', "drupalSettings"],
                "magento": ["magento", "mage/", "varien", "skin/frontend", "/downloader/"],
                "shopify": ["shopify", "cdn.shopify"],
            }
            for cms, signatures in self.CMS_SIGNATURES.items():
                for path in signatures.get("paths", [])[:2]:
                    await rate_limiter.acquire()

                    try:
                        url = urljoin(base_url, path)
                        path_response = await client.get(url)

                        if path_response.status_code in [200, 301, 302, 403]:
                            # FIX 2026-03-02: ALL paths need body validation, not just /admin/.
                            # Non-CMS apps can return 200/301/302 for /skin/, /js/mage/, etc.
                            # (SPAs serve 200 for everything; reverse proxies may redirect.)
                            body_lower = path_response.text.lower()
                            validators = _CMS_PATH_VALIDATORS.get(cms, [])
                            if any(v in body_lower for v in validators):
                                return cms

                    except Exception:
                        continue
        
        return None
    
    async def _scan_wordpress(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Scan WordPress-specific vulnerabilities."""
        findings = []
        
        async with get_scan_client(
            timeout=self.timeout,
            verify_ssl=False,
            follow_redirects=True,
        ) as client:

            # Check user enumeration
            for enum_path in self.WP_VULNS["user_enumeration"]:
                await rate_limiter.acquire()
                
                url = urljoin(base_url, enum_path)
                
                try:
                    response = await client.get(url)
                    
                    if response.status_code == 200:
                        if "wp-json" in enum_path:
                            try:
                                users = response.json()
                                if isinstance(users, list) and len(users) > 0:
                                    usernames = [u.get("slug", u.get("name", "unknown")) for u in users[:5]]
                                    
                                    findings.append(Finding(
                                        vuln_type=VulnType.INFO_DISCLOSURE,
                                        name="WordPress User Enumeration via REST API",
                                        severity=Severity.MEDIUM,
                                        description="WordPress REST API exposes user information, "
                                                   "allowing enumeration of valid usernames.",
                                        host=base_url,
                                        endpoint=url,
                                        evidence=[
                                            f"Users found: {usernames}",
                                            f"Endpoint: {enum_path}",
                                        ],
                                        cvss_score=5.3,
                                        cwe_id="CWE-200",
                                        remediation="Disable REST API user endpoint or require authentication. "
                                                   "Use security plugins like WordFence.",
                                        confidence_score=85,
                                    ).to_dict())
                                    break
                            except Exception:
                                pass
                        elif "author=" in enum_path:
                            if "author" in response.text.lower():
                                findings.append(Finding(
                                    vuln_type=VulnType.INFO_DISCLOSURE,
                                    name="WordPress User Enumeration via Author Parameter",
                                    severity=Severity.LOW,
                                    description="WordPress allows user enumeration via author parameter.",
                                    host=base_url,
                                    endpoint=url,
                                    evidence=[f"Endpoint: {enum_path}"],
                                    cvss_score=3.7,
                                    cwe_id="CWE-200",
                                    remediation="Block author enumeration requests.",
                                    confidence_score=75,
                                ).to_dict())
                                break
                                
                except Exception as e:
                    logger.debug(f"WP user enum error: {e}")
            
            # Check XML-RPC
            await rate_limiter.acquire()
            xmlrpc_url = urljoin(base_url, self.WP_VULNS["xmlrpc"])
            
            try:
                # Test with XML-RPC method
                xmlrpc_test = """<?xml version="1.0"?>
                <methodCall>
                    <methodName>system.listMethods</methodName>
                </methodCall>"""
                
                response = await client.post(
                    xmlrpc_url,
                    content=xmlrpc_test,
                    headers={"Content-Type": "application/xml"},
                )
                
                if response.status_code == 200 and "<methodResponse>" in response.text:
                    # Check for dangerous methods
                    dangerous_methods = [
                        "wp.getUsersBlogs",
                        "pingback.ping",
                        "system.multicall",
                    ]
                    
                    found_methods = [m for m in dangerous_methods if m in response.text]
                    
                    severity = "HIGH" if "system.multicall" in response.text else "MEDIUM"
                    
                    findings.append(Finding(
                        vuln_type=VulnType.INFO_DISCLOSURE,
                        name="WordPress XML-RPC Enabled",
                        severity=severity,
                        description="XML-RPC is enabled and can be used for brute force attacks, "
                                   "DDoS amplification (pingback), or credential attacks.",
                        host=base_url,
                        endpoint=xmlrpc_url,
                        evidence=[
                            "XML-RPC endpoint active",
                            f"Dangerous methods: {found_methods}" if found_methods else "",
                        ],
                        cvss_score=7.5 if severity == "HIGH" else 5.3,
                        cwe_id="CWE-288",
                        remediation="Disable XML-RPC if not needed. "
                                   "Block xmlrpc.php via web server or security plugin.",
                        confidence_score=90 if severity == "HIGH" else 85,
                    ).to_dict())
                    
            except Exception as e:
                logger.debug(f"XML-RPC check error: {e}")
            
            # Check debug log
            await rate_limiter.acquire()
            debug_url = urljoin(base_url, self.WP_VULNS["debug_log"])
            
            try:
                response = await client.get(debug_url)
                
                if response.status_code == 200 and "PHP" in response.text:
                    findings.append(Finding(
                        vuln_type=VulnType.INFO_DISCLOSURE,
                        name="WordPress Debug Log Exposed",
                        severity=Severity.HIGH,
                        description="WordPress debug.log is publicly accessible. "
                                   "May contain sensitive information, paths, and errors.",
                        host=base_url,
                        endpoint=debug_url,
                        evidence=["Debug log accessible"],
                        cvss_score=7.5,
                        cwe_id="CWE-532",
                        remediation="Remove debug.log from production. "
                                   "Disable WP_DEBUG in production.",
                        confidence_score=95,
                    ).to_dict())
                    
            except Exception as e:
                logger.debug(f"Debug log check error: {e}")
            
            # Check config backups
            for backup_path in self.WP_VULNS["config_backup"]:
                await rate_limiter.acquire()
                
                url = urljoin(base_url, backup_path)
                
                try:
                    response = await client.get(url)
                    
                    if response.status_code == 200:
                        if "DB_PASSWORD" in response.text or "DB_NAME" in response.text:
                            findings.append(Finding(
                                vuln_type=VulnType.INFO_DISCLOSURE,
                                name="WordPress Config Backup Exposed",
                                severity=Severity.CRITICAL,
                                description=f"WordPress configuration backup '{backup_path}' is accessible. "
                                           f"Contains database credentials and secret keys.",
                                host=base_url,
                                endpoint=url,
                                evidence=["Config backup contains credentials"],
                                cvss_score=9.8,
                                cwe_id="CWE-530",
                                remediation="Remove backup files immediately. "
                                           "Change all credentials.",
                                confidence_score=95,
                            ).to_dict())
                            break
                            
                except Exception as e:
                    logger.debug(f"Config backup check error: {e}")
            
            # Check WordPress version
            await rate_limiter.acquire()
            readme_url = urljoin(base_url, self.WP_VULNS["readme"])
            
            try:
                response = await client.get(readme_url)
                
                if response.status_code == 200:
                    version_match = re.search(r'Version\s*([\d.]+)', response.text)
                    
                    if version_match:
                        version = version_match.group(1)
                        
                        findings.append(Finding(
                            vuln_type=VulnType.INFO_DISCLOSURE,
                            name="WordPress Version Disclosure",
                            severity=Severity.LOW,
                            description=f"WordPress version {version} detected via readme.html.",
                            host=base_url,
                            endpoint=readme_url,
                            evidence=[f"Version: {version}"],
                            cvss_score=3.7,
                            cwe_id="CWE-200",
                            remediation="Remove readme.html or restrict access.",
                            confidence_score=75,
                        ).to_dict())
                        
            except Exception as e:
                logger.debug(f"Readme check error: {e}")
        
        return findings
    
    async def _scan_joomla(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Scan Joomla-specific vulnerabilities."""
        findings = []
        
        joomla_checks = [
            ("/administrator/manifests/files/joomla.xml", "Version disclosure"),
            ("/language/en-GB/en-GB.xml", "Version via language file"),
            ("/configuration.php.bak", "Config backup"),
            ("/configuration.php~", "Config backup"),
            ("/configuration.php.old", "Config backup"),
        ]
        
        async with get_scan_client(
            timeout=self.timeout,
            verify_ssl=False,
            follow_redirects=True,
        ) as client:
            for path, check_name in joomla_checks:
                await rate_limiter.acquire()
                
                url = urljoin(base_url, path)
                
                try:
                    response = await client.get(url)
                    
                    if response.status_code == 200:
                        if "configuration.php" in path:
                            if "$" in response.text or "class JConfig" in response.text:
                                findings.append(Finding(
                                    vuln_type=VulnType.INFO_DISCLOSURE,
                                    name="Joomla Config Backup Exposed",
                                    severity=Severity.CRITICAL,
                                    description="Joomla configuration backup is accessible.",
                                    host=base_url,
                                    endpoint=url,
                                    evidence=[f"Path: {path}"],
                                    cvss_score=9.8,
                                    cwe_id="CWE-530",
                                    remediation="Remove backup files.",
                                    confidence_score=95,
                                ).to_dict())
                        else:
                            version_match = re.search(r'<version>([\d.]+)</version>', response.text)
                            if version_match:
                                findings.append(Finding(
                                    vuln_type=VulnType.INFO_DISCLOSURE,
                                    name="Joomla Version Disclosure",
                                    severity=Severity.LOW,
                                    description=f"Joomla version {version_match.group(1)} detected.",
                                    host=base_url,
                                    endpoint=url,
                                    evidence=[f"Version: {version_match.group(1)}"],
                                    cvss_score=3.7,
                                    cwe_id="CWE-200",
                                    remediation="Remove version information from public files.",
                                    confidence_score=75,
                                ).to_dict())
                                
                except Exception as e:
                    logger.debug(f"Joomla check error: {e}")
        
        return findings
    
    async def _scan_drupal(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Scan Drupal-specific vulnerabilities."""
        findings = []
        
        drupal_checks = [
            "/CHANGELOG.txt",
            "/core/CHANGELOG.txt",
            "/INSTALL.txt",
            "/UPDATE.txt",
            "/sites/default/settings.php.bak",
        ]
        
        async with get_scan_client(
            timeout=self.timeout,
            verify_ssl=False,
            follow_redirects=True,
        ) as client:
            for path in drupal_checks:
                await rate_limiter.acquire()
                
                url = urljoin(base_url, path)
                
                try:
                    response = await client.get(url)
                    
                    if response.status_code == 200:
                        if "CHANGELOG" in path:
                            version_match = re.search(r'Drupal\s*([\d.]+)', response.text)
                            if version_match:
                                findings.append(Finding(
                                    vuln_type=VulnType.INFO_DISCLOSURE,
                                    name="Drupal Version Disclosure",
                                    severity=Severity.LOW,
                                    description=f"Drupal version {version_match.group(1)} detected.",
                                    host=base_url,
                                    endpoint=url,
                                    evidence=[f"Version: {version_match.group(1)}"],
                                    cvss_score=3.7,
                                    cwe_id="CWE-200",
                                    remediation="Remove CHANGELOG.txt from production.",
                                    confidence_score=75,
                                ).to_dict())
                        elif "settings.php" in path:
                            findings.append(Finding(
                                vuln_type=VulnType.INFO_DISCLOSURE,
                                name="Drupal Settings Backup Exposed",
                                severity=Severity.CRITICAL,
                                description="Drupal settings backup is accessible.",
                                host=base_url,
                                endpoint=url,
                                evidence=[f"Path: {path}"],
                                cvss_score=9.8,
                                cwe_id="CWE-530",
                                remediation="Remove backup files.",
                                confidence_score=95,
                            ).to_dict())
                            
                except Exception as e:
                    logger.debug(f"Drupal check error: {e}")
        
        return findings
    
    async def _generic_cms_checks(
        self,
        base_url: str,
        cms: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Generic CMS security checks."""
        findings = []
        
        admin_paths = {
            "wordpress": "/wp-admin/",
            "joomla": "/administrator/",
            "drupal": "/user/login",
            "magento": "/admin/",
        }
        
        admin_path = admin_paths.get(cms, "/admin/")
        
        async with get_scan_client(
            timeout=self.timeout,
            verify_ssl=False,
            follow_redirects=False,
        ) as client:
            # Fetch homepage for SPA detection
            try:
                await rate_limiter.acquire()
                homepage = await client.get(base_url)
                homepage_text = homepage.text
            except Exception:
                homepage_text = ""

            await rate_limiter.acquire()

            url = urljoin(base_url, admin_path)

            try:
                response = await client.get(url)

                # Check if admin is accessible without auth
                if response.status_code == 200:
                    resp_text = response.text.lower()

                    # CMS content verification: response must contain CMS-specific markers
                    _CMS_ADMIN_MARKERS: dict[str, list[str]] = {
                        "wordpress": ["wp-admin", "wp-content", "wordpress", "wp-login"],
                        "joomla": ["joomla", "com_login", "administrator"],
                        "drupal": ["drupal", "user/login", "drupal.settings"],
                        "magento": ["magento", "mage/", "varien", "skin/frontend", "adminhtml"],
                    }
                    markers = _CMS_ADMIN_MARKERS.get(cms, [])
                    has_cms_content = any(m in resp_text for m in markers)

                    if not has_cms_content:
                        logger.debug(
                            f"CMS admin check {admin_path}: no {cms} markers in response, skipping"
                        )

                    # SPA detection: if response matches homepage, it's a SPA fallback
                    elif homepage_text and abs(len(response.text) - len(homepage_text)) < 100:
                        hp_start = homepage_text[:500].strip()
                        rp_start = response.text[:500].strip()
                        if hp_start == rp_start:
                            logger.debug(f"CMS admin check {admin_path}: SPA fallback")
                        elif "login" not in resp_text and "password" not in resp_text:
                            findings.append(Finding(
                                vuln_type=VulnType.INFO_DISCLOSURE,
                                name=f"{cms.title()} Admin Panel Accessible",
                                severity=Severity.MEDIUM,
                                description="CMS admin panel is accessible without authentication.",
                                host=base_url,
                                endpoint=url,
                                evidence=["Admin panel returned 200 without login form"],
                                cvss_score=5.3,
                                cwe_id="CWE-306",
                                remediation="Require authentication for admin access. "
                                           "Implement IP restrictions.",
                                confidence_score=85,
                            ).to_dict())
                    elif "login" not in resp_text and "password" not in resp_text:
                        findings.append(Finding(
                            vuln_type=VulnType.INFO_DISCLOSURE,
                            name=f"{cms.title()} Admin Panel Accessible",
                            severity=Severity.MEDIUM,
                            description="CMS admin panel is accessible without authentication.",
                            host=base_url,
                            endpoint=url,
                            evidence=["Admin panel returned 200 without login form"],
                            cvss_score=5.3,
                            cwe_id="CWE-306",
                            remediation="Require authentication for admin access. "
                                       "Implement IP restrictions.",
                            confidence_score=85,
                        ).to_dict())

            except Exception as e:
                logger.debug(f"Admin check error: {e}")
        
        return findings
