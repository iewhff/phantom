"""
Subdomain Takeover Scanner v1.0 - DNS Hijacking Detection

IMPORTANT FOR BUG BOUNTY:
This scanner tests ONLY subdomains that are ALREADY IN SCOPE.
It does NOT discover new domains - it checks if known subdomains
have dangling DNS records that could allow hijacking.

Use case: You have a list of in-scope subdomains from the program
and want to check if any have vulnerable DNS configurations.

Detects vulnerable subdomains that can be hijacked due to:
1. Dangling DNS records (CNAME to unclaimed services)
2. Expired/abandoned cloud resources
3. Misconfigured DNS delegations

Bug Bounty Value: $100 - $2,000 per finding
Common in: Large programs with many subdomains

Supported Services:
- AWS (S3, CloudFront, Elastic Beanstalk, ELB)
- Azure (Blob, CDN, Websites, Traffic Manager)
- GitHub Pages
- Heroku
- Shopify
- Zendesk
- Fastly
- Ghost
- Surge.sh
- Pantheon
- And 40+ more services

CWE Coverage:
- CWE-284: Improper Access Control
- CWE-923: Improper Restriction of Communication Channel

Author: PetNTester AI
Version: 1.0.0
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

import httpx

from scanning.findings import Finding, VulnType
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from utils.http_client import create_protected_client, get_configured_ssl_verify
from scanning.scan_context import ScanContext

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)

# Version
TAKEOVER_SCANNER_VERSION = "1.0.0"


@dataclass
class TakeoverCandidate:
    """A potential subdomain takeover candidate."""
    subdomain: str
    cname: str
    service: str
    confidence: int
    evidence: list[str] = field(default_factory=list)
    fingerprint_matched: bool = False
    dns_vulnerable: bool = False


class ServiceFingerprints:
    """
    Fingerprints for detecting subdomain takeover vulnerabilities.

    Each entry contains:
    - cname_patterns: CNAME patterns that indicate this service
    - fingerprints: Response content that indicates unclaimed resource
    - nxdomain: Whether NXDOMAIN response indicates vulnerability
    """

    SERVICES = {
        # AWS Services
        "aws_s3": {
            "cname_patterns": [".s3.amazonaws.com", ".s3-website", "s3."],
            "fingerprints": [
                "NoSuchBucket",
                "The specified bucket does not exist",
            ],
            "nxdomain": True,
            "severity": "HIGH",
        },
        "aws_cloudfront": {
            "cname_patterns": [".cloudfront.net"],
            "fingerprints": [
                "Bad request",
                "ERROR: The request could not be satisfied",
            ],
            "nxdomain": False,
            "severity": "MEDIUM",
        },
        "aws_elasticbeanstalk": {
            "cname_patterns": [".elasticbeanstalk.com"],
            "fingerprints": [],
            "nxdomain": True,
            "severity": "HIGH",
        },
        "aws_elb": {
            "cname_patterns": [".elb.amazonaws.com"],
            "fingerprints": [],
            "nxdomain": True,
            "severity": "MEDIUM",
        },

        # Azure Services
        "azure_blob": {
            "cname_patterns": [".blob.core.windows.net"],
            "fingerprints": [
                "BlobNotFound",
                "The specified container does not exist",
                "ResourceNotFound",
            ],
            "nxdomain": True,
            "severity": "HIGH",
        },
        "azure_websites": {
            "cname_patterns": [".azurewebsites.net", ".azure-mobile.net"],
            "fingerprints": [
                "404 Web Site not found",
                "Error 404 - Web app not found",
            ],
            "nxdomain": True,
            "severity": "HIGH",
        },
        "azure_cloudapp": {
            "cname_patterns": [".cloudapp.net", ".cloudapp.azure.com"],
            "fingerprints": [],
            "nxdomain": True,
            "severity": "MEDIUM",
        },
        "azure_trafficmanager": {
            "cname_patterns": [".trafficmanager.net"],
            "fingerprints": [],
            "nxdomain": True,
            "severity": "HIGH",
        },

        # GitHub
        "github_pages": {
            "cname_patterns": [".github.io", "github.map.fastly.net"],
            "fingerprints": [
                "There isn't a GitHub Pages site here",
                "For root URLs (like http://example.com/) you must provide",
            ],
            "nxdomain": False,
            "severity": "MEDIUM",
        },

        # Heroku
        "heroku": {
            "cname_patterns": [".herokuapp.com", ".herokussl.com"],
            "fingerprints": [
                "No such app",
                "no-such-app.herokuapp.com",
                "herokucdn.com/error-pages/no-such-app.html",
            ],
            "nxdomain": True,
            "severity": "HIGH",
        },

        # Shopify
        "shopify": {
            "cname_patterns": [".myshopify.com", "shops.myshopify.com"],
            "fingerprints": [
                "Sorry, this shop is currently unavailable",
                "Only one step left!",
            ],
            "nxdomain": False,
            "severity": "HIGH",
        },

        # Zendesk
        "zendesk": {
            "cname_patterns": [".zendesk.com", "zendesk-eu.com"],
            "fingerprints": [
                "Help Center Closed",
                "Zendesk doesn't know this",
            ],
            "nxdomain": False,
            "severity": "MEDIUM",
        },

        # Fastly
        "fastly": {
            "cname_patterns": [".fastly.net", ".fastlylb.net", "global-ssl.fastly.net"],
            "fingerprints": [
                "Fastly error: unknown domain",
            ],
            "nxdomain": False,
            "severity": "MEDIUM",
        },

        # Pantheon
        "pantheon": {
            "cname_patterns": [".pantheonsite.io", ".pantheon.io"],
            "fingerprints": [
                "The gods are wise, but do not know of the site",
                "404 error unknown site!",
            ],
            "nxdomain": False,
            "severity": "MEDIUM",
        },

        # Tumblr
        "tumblr": {
            "cname_patterns": [".tumblr.com", "domains.tumblr.com"],
            "fingerprints": [
                "There's nothing here.",
                "Whatever you were looking for doesn't currently exist",
            ],
            "nxdomain": False,
            "severity": "LOW",
        },

        # WordPress.com
        "wordpress": {
            "cname_patterns": [".wordpress.com"],
            "fingerprints": [
                "Do you want to register",
            ],
            "nxdomain": False,
            "severity": "MEDIUM",
        },

        # Surge.sh
        "surge": {
            "cname_patterns": [".surge.sh"],
            "fingerprints": [
                "project not found",
            ],
            "nxdomain": True,
            "severity": "MEDIUM",
        },

        # Ghost
        "ghost": {
            "cname_patterns": [".ghost.io"],
            "fingerprints": [
                "The thing you were looking for is no longer here",
            ],
            "nxdomain": True,
            "severity": "MEDIUM",
        },

        # Cargo
        "cargo": {
            "cname_patterns": [".cargo.site", "cargocollective.com"],
            "fingerprints": [
                "404 Not Found",
            ],
            "nxdomain": True,
            "severity": "LOW",
        },

        # Feedpress
        "feedpress": {
            "cname_patterns": [".feedpress.me", "redirect.feedpress.me"],
            "fingerprints": [
                "The feed has not been found",
            ],
            "nxdomain": True,
            "severity": "LOW",
        },

        # Help Scout
        "helpscout": {
            "cname_patterns": [".helpscoutdocs.com"],
            "fingerprints": [
                "No settings were found for this company",
            ],
            "nxdomain": True,
            "severity": "MEDIUM",
        },

        # Helpjuice
        "helpjuice": {
            "cname_patterns": [".helpjuice.com"],
            "fingerprints": [
                "We could not find what you're looking for",
            ],
            "nxdomain": True,
            "severity": "MEDIUM",
        },

        # Intercom
        "intercom": {
            "cname_patterns": [".intercom.help", "custom.intercom.help"],
            "fingerprints": [
                "This page is reserved for",
                "Uh oh. That page doesn't exist",
            ],
            "nxdomain": False,
            "severity": "MEDIUM",
        },

        # JetBrains YouTrack
        "youtrack": {
            "cname_patterns": [".myjetbrains.com"],
            "fingerprints": [
                "is not a registered InCloud YouTrack",
            ],
            "nxdomain": True,
            "severity": "MEDIUM",
        },

        # Kinsta
        "kinsta": {
            "cname_patterns": [".kinsta.cloud"],
            "fingerprints": [
                "No Site For Domain",
            ],
            "nxdomain": True,
            "severity": "MEDIUM",
        },

        # LaunchRock
        "launchrock": {
            "cname_patterns": [".launchrock.com"],
            "fingerprints": [
                "It looks like you may have taken a wrong turn",
            ],
            "nxdomain": True,
            "severity": "LOW",
        },

        # Netlify
        "netlify": {
            "cname_patterns": [".netlify.app", ".netlify.com"],
            "fingerprints": [
                "Not Found - Request ID",
            ],
            "nxdomain": False,
            "severity": "MEDIUM",
        },

        # Ngrok
        "ngrok": {
            "cname_patterns": [".ngrok.io"],
            "fingerprints": [
                "Tunnel .*.ngrok.io not found",
                "ngrok.io not found",
            ],
            "nxdomain": True,
            "severity": "LOW",
        },

        # ReadMe
        "readme": {
            "cname_patterns": [".readme.io"],
            "fingerprints": [
                "Project doesnt exist",
            ],
            "nxdomain": True,
            "severity": "MEDIUM",
        },

        # SmartJobBoard
        "smartjobboard": {
            "cname_patterns": [".smartjobboard.com"],
            "fingerprints": [
                "This job board website is either expired",
            ],
            "nxdomain": True,
            "severity": "LOW",
        },

        # Smugmug
        "smugmug": {
            "cname_patterns": [".smugmug.com"],
            "fingerprints": [],
            "nxdomain": True,
            "severity": "LOW",
        },

        # StatusPage
        "statuspage": {
            "cname_patterns": [".statuspage.io"],
            "fingerprints": [
                "You are being redirected",
                "StatusPage 404",
            ],
            "nxdomain": True,
            "severity": "MEDIUM",
        },

        # Strikingly
        "strikingly": {
            "cname_patterns": [".s.strikinglydns.com"],
            "fingerprints": [
                "page not found",
            ],
            "nxdomain": True,
            "severity": "MEDIUM",
        },

        # Tilda
        "tilda": {
            "cname_patterns": [".tilda.ws"],
            "fingerprints": [
                "Please renew your subscription",
            ],
            "nxdomain": True,
            "severity": "MEDIUM",
        },

        # Unbounce
        "unbounce": {
            "cname_patterns": [".unbouncepages.com"],
            "fingerprints": [
                "The requested URL was not found on this server",
            ],
            "nxdomain": True,
            "severity": "MEDIUM",
        },

        # Uptimerobot
        "uptimerobot": {
            "cname_patterns": [".uptimerobot.com"],
            "fingerprints": [
                "page not found",
            ],
            "nxdomain": True,
            "severity": "LOW",
        },

        # UserVoice
        "uservoice": {
            "cname_patterns": [".uservoice.com"],
            "fingerprints": [
                "This UserVoice subdomain is currently available",
            ],
            "nxdomain": True,
            "severity": "MEDIUM",
        },

        # Webflow
        "webflow": {
            "cname_patterns": [".webflow.io", ".proxy-ssl.webflow.com"],
            "fingerprints": [
                "The page you are looking for doesn't exist",
            ],
            "nxdomain": True,
            "severity": "MEDIUM",
        },

        # Wishpond
        "wishpond": {
            "cname_patterns": [".wishpond.com"],
            "fingerprints": [
                "https://www.wishpond.com/404?campaign=true",
            ],
            "nxdomain": True,
            "severity": "LOW",
        },

        # Worksites
        "worksites": {
            "cname_patterns": [".worksites.net"],
            "fingerprints": [
                "Hello! Sorry, but the website you're looking",
            ],
            "nxdomain": True,
            "severity": "LOW",
        },

        # Wix
        "wix": {
            "cname_patterns": [".wixsite.com", ".wix.com"],
            "fingerprints": [
                "Error ConnectYourDomain",
            ],
            "nxdomain": False,
            "severity": "MEDIUM",
        },
    }


class SubdomainTakeoverScanner(ScanModule):
    """
    Subdomain Takeover Scanner - DNS Hijacking Detection.

    Identifies subdomains vulnerable to takeover due to:
    - Dangling CNAME records pointing to unclaimed cloud services
    - Expired or misconfigured third-party services
    - NXDOMAIN responses from claimed CNAMEs

    Bug Bounty Priority: Medium
    Typical Payout: $100 - $2,000 per finding
    Effort: Low (automated detection)
    """

    name = "subdomain_takeover_scanner"
    version = TAKEOVER_SCANNER_VERSION

    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
        self.findings: list[dict[str, Any]] = []
        self.candidates: list[TakeoverCandidate] = []
        self._ssl_verify = get_configured_ssl_verify()

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """Execute subdomain takeover scan."""

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        self.findings = []
        self.candidates = []

        # Get subdomains from asset data
        if isinstance(asset_data, dict):
            subdomains = asset_data.get("subdomains", [])

        # Also include the main host
        if host not in subdomains:
            subdomains = [host] + list(subdomains)

        logger.info(
            f"Subdomain Takeover Scanner v{self.version} starting "
            f"on {len(subdomains)} subdomains"
        )

        # FIX: Pass auth headers for authenticated subdomain testing
        client = create_protected_client(
            timeout=self.timeout,
            verify_ssl=self._ssl_verify,
            follow_redirects=False,
            custom_headers=self._auth_headers,
        )

        async with client:
            # Phase 1: Check CNAME records and identify candidates
            await self._check_cname_records(subdomains, rate_limiter)

            # Phase 2: Verify candidates with HTTP fingerprinting
            await self._verify_candidates(client, rate_limiter)

        logger.info(
            f"Subdomain takeover scan complete. "
            f"Found {len(self.findings)} vulnerabilities"
        )

        return {
            "module": self.name,
            "version": self.version,
            "findings": self.findings,
            "candidates_checked": len(self.candidates),
        }

    async def _check_cname_records(
        self,
        subdomains: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Check CNAME records for takeover candidates."""
        for subdomain in subdomains[:500]:  # Limit to prevent abuse
            await rate_limiter.acquire()

            try:
                # Resolve CNAME
                cname = await self._resolve_cname(subdomain)

                if cname:
                    # Check against known vulnerable services
                    service = self._identify_service(cname)

                    if service:
                        candidate = TakeoverCandidate(
                            subdomain=subdomain,
                            cname=cname,
                            service=service,
                            confidence_score=30,
                            evidence=[f"CNAME points to {service} service: {cname}"],
                        )
                        self.candidates.append(candidate)
                        logger.debug(
                            f"Takeover candidate: {subdomain} -> {cname} ({service})"
                        )

            except Exception as e:
                logger.debug(f"CNAME check error for {subdomain}: {e}")

    async def _resolve_cname(self, domain: str) -> Optional[str]:
        """Resolve CNAME record for a domain."""
        try:
            # Use socket for basic DNS resolution
            # For production, consider using dnspython for CNAME lookup
            result = socket.gethostbyname_ex(domain)

            # Check if there's an alias (CNAME)
            if result[1]:
                return result[1][0]

            return None

        except socket.gaierror as e:
            # NXDOMAIN - could indicate vulnerability
            if e.errno == socket.EAI_NONAME:
                return "NXDOMAIN"
            return None
        except Exception:
            return None

    def _identify_service(self, cname: str) -> Optional[str]:
        """Identify the cloud service from CNAME."""
        cname_lower = cname.lower()

        for service_name, config in ServiceFingerprints.SERVICES.items():
            for pattern in config["cname_patterns"]:
                if pattern in cname_lower:
                    return service_name

        return None

    async def _verify_candidates(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Verify takeover candidates with HTTP fingerprinting."""
        for candidate in self.candidates:
            await rate_limiter.acquire()

            service_config = ServiceFingerprints.SERVICES.get(candidate.service, {})
            fingerprints = service_config.get("fingerprints", [])
            severity = service_config.get("severity", "MEDIUM")

            # Check for NXDOMAIN vulnerability
            if candidate.cname == "NXDOMAIN":
                if service_config.get("nxdomain", False):
                    candidate.dns_vulnerable = True
                    candidate.confidence += 40
                    candidate.evidence.append("DNS returns NXDOMAIN (unclaimed)")

            # HTTP fingerprint check
            try:
                for protocol in ["https", "http"]:
                    url = f"{protocol}://{candidate.subdomain}"

                    try:
                        response = await client.get(url, timeout=10.0)
                        content = response.text.lower()

                        # Check fingerprints
                        for fingerprint in fingerprints:
                            if fingerprint.lower() in content:
                                candidate.fingerprint_matched = True
                                candidate.confidence += 50
                                candidate.evidence.append(
                                    f"Fingerprint matched: '{fingerprint}'"
                                )
                                break

                        if candidate.fingerprint_matched:
                            break

                    except httpx.ConnectError:
                        # Connection refused might indicate unclaimed resource
                        candidate.confidence += 10
                        candidate.evidence.append("Connection refused (possible unclaimed)")

                    except Exception:
                        pass

            except Exception as e:
                logger.debug(f"HTTP verification error for {candidate.subdomain}: {e}")

            # Report if vulnerable
            if candidate.confidence >= 50:
                self._add_finding(candidate, severity)

    def _add_finding(self, candidate: TakeoverCandidate, severity: str) -> None:
        """Add a takeover finding."""
        service_display = candidate.service.replace("_", " ").title()

        finding = Finding(
            vuln_type=VulnType.SUBDOMAIN_TAKEOVER,
            name=f"Subdomain Takeover - {service_display}",
            severity=severity,
            description=(
                f"The subdomain '{candidate.subdomain}' is vulnerable to takeover. "
                f"The CNAME record points to '{candidate.cname}' ({service_display}), "
                f"but the target resource appears to be unclaimed. An attacker could "
                f"register this resource and serve malicious content under the "
                f"target's domain, enabling phishing, cookie theft, and reputation damage."
            ),
            host=candidate.subdomain,
            endpoint=candidate.subdomain,
            evidence=candidate.evidence + [
                f"Confidence: {candidate.confidence}%",
                f"CNAME Target: {candidate.cname}",
                f"Service: {service_display}",
                f"DNS Vulnerable: {candidate.dns_vulnerable}",
                f"Fingerprint Matched: {candidate.fingerprint_matched}",
            ],
            cvss_score=7.5 if severity == "HIGH" else 5.3,
            cwe_id="CWE-284",
            remediation=self._get_remediation(candidate),
            references=[
                "https://github.com/EdOverflow/can-i-take-over-xyz",
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
                "https://portswigger.net/web-security/host-header/subdomain-takeover",
            ],
        )

        self.findings.append(finding.to_dict())

        logger.info(
            f"Subdomain Takeover Found [{severity}]: "
            f"{candidate.subdomain} -> {candidate.service}"
        )

    def _get_remediation(self, candidate: TakeoverCandidate) -> str:
        """Get remediation advice."""
        return f"""
1. IMMEDIATE: Remove the dangling CNAME record for '{candidate.subdomain}'
   - The CNAME currently points to: {candidate.cname}
   - Either claim the resource or delete the DNS record

2. If the service is still needed:
   - Reclaim the resource on {candidate.service.replace('_', ' ').title()}
   - Verify the resource is properly configured

3. If the service is no longer needed:
   - Delete the CNAME record from DNS
   - Document the change in your DNS management system

4. Prevention:
   - Implement DNS monitoring for dangling records
   - Review DNS records when decommissioning services
   - Use infrastructure-as-code to track DNS changes
   - Set up alerts for unclaimed cloud resources

5. Audit your DNS:
   - Review all CNAME records pointing to third-party services
   - Verify each target resource is actively claimed
   - Remove records for deprecated services
"""


# Export
__all__ = ["SubdomainTakeoverScanner", "TAKEOVER_SCANNER_VERSION"]
