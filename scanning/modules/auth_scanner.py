"""
Authentication and Session Security Scanner - ENTERPRISE EDITION v2.0

Enterprise-grade authentication vulnerability scanner with advanced testing
for modern authentication mechanisms including OAuth, SAML, JWT, and session management.

This module serves as the main orchestrator, delegating to specialized sub-scanners:
- auth_login_scanner: Default credentials, brute force, account enumeration
- auth_session_scanner: Cookie security, session fixation
- auth_jwt_scanner: JWT vulnerabilities (alg:none, key confusion, weak secrets)
- auth_oauth_scanner: OAuth 2.0 / OpenID Connect security
- auth_bypass_scanner: Authentication bypass techniques
- auth_privesc_scanner: Privilege escalation, IDOR, role manipulation

Features:
- Default credential testing with smart form detection
- Brute force protection assessment
- Session management security (cookies, tokens)
- JWT vulnerability analysis (alg:none, key confusion, claim tampering)
- OAuth 2.0 / OpenID Connect security testing
- Session fixation / hijacking detection
- Privilege escalation testing (IDOR, role manipulation)
- MFA bypass techniques
- Password reset flow vulnerabilities
- Account enumeration detection

CWE Coverage:
- CWE-287: Improper Authentication
- CWE-306: Missing Authentication for Critical Function
- CWE-307: Improper Restriction of Excessive Authentication Attempts
- CWE-384: Session Fixation
- CWE-613: Insufficient Session Expiration
- CWE-614: Sensitive Cookie in HTTPS Without 'Secure' Attribute
- CWE-798: Use of Hard-coded Credentials
- CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
- CWE-327: Use of Broken Crypto Algorithm (JWT)
- CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)
- CWE-269: Improper Privilege Management
- CWE-640: Weak Password Recovery Mechanism

Author: PetNTester AI Enterprise
Version: 2.0.0-enterprise
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

# Import sub-scanners
from .auth.auth_bypass_scanner import AuthBypassScanner
from .auth.auth_jwt_scanner import JWTScanner
from .auth.auth_login_scanner import LoginScanner
from .auth.auth_oauth_scanner import OAuthScanner
from .auth.auth_privesc_scanner import PrivilegeEscalationScanner
from .auth.auth_session_scanner import SessionScanner

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class AuthScanner(ScanModule):
    """
    Authentication Security Scanner - ENTERPRISE EDITION v2.0

    Comprehensive authentication vulnerability testing including:
    - Default/weak credentials with smart form detection
    - Session management security analysis
    - JWT vulnerability assessment (alg:none, key confusion, claim tampering)
    - OAuth 2.0 / OpenID Connect security testing
    - Privilege escalation (IDOR, role manipulation)
    - MFA bypass techniques
    - Password reset flow vulnerabilities
    - Account enumeration detection
    - Brute force protection assessment

    CWE Coverage: CWE-287, CWE-306, CWE-307, CWE-327, CWE-384, CWE-613,
                  CWE-614, CWE-639, CWE-640, CWE-798, CWE-1004, CWE-269
    """

    name = "auth_scanner"
    version = "2.0-enterprise"

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.timeout = settings.timeouts.request_timeout

        # Initialize sub-scanners
        self.login_scanner = LoginScanner(settings)
        self.session_scanner = SessionScanner(settings)
        self.jwt_scanner = JWTScanner(settings)
        self.oauth_scanner = OAuthScanner(settings)
        self.bypass_scanner = AuthBypassScanner(settings)
        self.privesc_scanner = PrivilegeEscalationScanner(settings)

        # Track partial findings for timeout recovery
        self._partial_findings: list[dict[str, Any]] = []

    def get_partial_findings(self) -> list[dict[str, Any]]:
        """Return partial findings collected so far (for timeout recovery)."""
        return self._partial_findings.copy()

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """
        Comprehensive authentication security scan - ENTERPRISE EDITION.

        Performs:
        1. Login page discovery and default credential testing
        2. Brute force protection assessment
        3. Session management analysis
        4. JWT vulnerability testing
        5. OAuth 2.0 security assessment
        6. Authentication bypass attempts
        7. Privilege escalation testing (IDOR)
        8. MFA bypass detection
        9. Password reset flow analysis
        10. Account enumeration detection
        """
        findings: list[dict[str, Any]] = []
        self._partial_findings = []

        base_url = f"https://{host}" if not host.startswith("http") else host
        logger.info(f"🔐 Auth Scanner ENTERPRISE starting for {base_url}")

        def extend_findings(new_findings: list[dict[str, Any]]) -> None:
            """Helper to extend findings and track for partial recovery."""
            findings.extend(new_findings)
            self._partial_findings.extend(new_findings)

        # ====================================================================
        # PHASE 1: Login Discovery & Default Credentials
        # ====================================================================
        try:
            login_findings = await self.login_scanner.scan(
                base_url, asset_data, rate_limiter
            )
            extend_findings(login_findings)
        except Exception as e:
            logger.error(f"Login scanner error: {e}")

        # Get discovered login pages for session testing
        login_pages = self.login_scanner.get_discovered_login_pages()

        # ====================================================================
        # PHASE 2: Session Management
        # ====================================================================
        try:
            session_findings = await self.session_scanner.scan(
                base_url, asset_data, rate_limiter, login_pages
            )
            extend_findings(session_findings)
        except Exception as e:
            logger.error(f"Session scanner error: {e}")

        # ====================================================================
        # PHASE 3: JWT Vulnerabilities
        # ====================================================================
        try:
            jwt_findings = await self.jwt_scanner.scan(
                base_url, asset_data, rate_limiter
            )
            extend_findings(jwt_findings)
        except Exception as e:
            logger.error(f"JWT scanner error: {e}")

        # ====================================================================
        # PHASE 4: OAuth 2.0 Security
        # ====================================================================
        try:
            oauth_findings = await self.oauth_scanner.scan(
                base_url, asset_data, rate_limiter
            )
            extend_findings(oauth_findings)
        except Exception as e:
            logger.error(f"OAuth scanner error: {e}")

        # ====================================================================
        # PHASE 5: Authentication Bypass
        # ====================================================================
        try:
            bypass_findings = await self.bypass_scanner.scan(
                base_url, asset_data, rate_limiter
            )
            extend_findings(bypass_findings)
        except Exception as e:
            logger.error(f"Auth bypass scanner error: {e}")

        # ====================================================================
        # PHASE 6: Privilege Escalation / IDOR
        # ====================================================================
        try:
            privesc_findings = await self.privesc_scanner.scan(
                base_url, asset_data, rate_limiter
            )
            extend_findings(privesc_findings)
        except Exception as e:
            logger.error(f"Privilege escalation scanner error: {e}")

        logger.info(f"✅ Auth Scanner ENTERPRISE complete: {len(findings)} findings")

        return {
            "module": self.name,
            "version": self.version,
            "findings": findings,
            "sessions_analyzed": len(self.session_scanner.get_detected_sessions()),
            "oauth_detected": self.oauth_scanner.get_oauth_config() is not None,
            "login_pages_found": len(login_pages),
        }
