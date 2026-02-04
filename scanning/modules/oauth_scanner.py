"""
OAuth/OpenID Connect Security Scanner.
Tests for OAuth 2.0 and OIDC vulnerabilities.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import httpx

from scanning.vuln_scanner import Finding, ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class OAuthScanner(ScanModule):
    """
    OAuth 2.0 and OpenID Connect Security Scanner.
    
    Tests for:
    - Authorization code interception
    - Redirect URI validation bypass
    - State parameter vulnerabilities
    - PKCE bypass
    - Token leakage
    - Scope manipulation
    - Implicit flow vulnerabilities
    - JWT algorithm confusion (none, RS256→HS256)
    - CSRF in OAuth flow
    - Open redirect via OAuth
    - Token fixation
    - Refresh token abuse
    """
    
    name = "oauth_scanner"
    
    # Common OAuth endpoints
    OAUTH_ENDPOINTS = [
        "/oauth/authorize",
        "/oauth2/authorize",
        "/oauth/token",
        "/oauth2/token",
        "/authorize",
        "/auth",
        "/login/oauth",
        "/api/oauth/authorize",
        "/connect/authorize",
        "/openid/authorize",
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/oauth/userinfo",
        "/userinfo",
        "/oauth/jwks",
        "/jwks.json",
        "/.well-known/jwks.json",
    ]
    
    # Redirect URI bypass payloads
    REDIRECT_BYPASS_PAYLOADS = [
        # Subdomain tricks
        "https://evil.com#@legitimate.com",
        "https://legitimate.com.evil.com",
        "https://legitimate.com@evil.com",
        "https://evil.com\\@legitimate.com",
        "https://evil.com%40legitimate.com",
        # Path manipulation
        "https://legitimate.com/callback/../../../evil.com",
        "https://legitimate.com/callback/..;/evil",
        "https://legitimate.com/callback#evil.com",
        "https://legitimate.com/callback?next=evil.com",
        # Protocol manipulation
        "javascript:alert(document.domain)//",
        "data:text/html,<script>alert(1)</script>",
        "//evil.com",
        "///evil.com",
        "/\\evil.com",
        # Unicode/encoding tricks
        "https://legitimate.com%2f%2fevil.com",
        "https://legitimate。com",  # Unicode dot
        "https://legitımate.com",   # Turkish i
        # Localhost/internal
        "http://localhost/callback",
        "http://127.0.0.1/callback",
        "http://[::1]/callback",
    ]
    
    # JWT algorithm confusion
    JWT_ALG_PAYLOADS = [
        {"alg": "none"},
        {"alg": "None"},
        {"alg": "NONE"},
        {"alg": "nOnE"},
        {"alg": "HS256"},  # When expecting RS256
        {"alg": "HS384"},
        {"alg": "HS512"},
    ]
    
    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.timeout = settings.timeouts.request_timeout
        self.discovered_config: dict[str, Any] = {}
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Scan for OAuth/OIDC vulnerabilities."""
        findings: list[Finding] = []
        
        base_url = f"https://{host}" if not host.startswith("http") else host
        
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            # Discover OAuth configuration
            config = await self._discover_oauth_config(client, base_url, rate_limiter)
            self.discovered_config = config
            
            if not config:
                logger.info(f"No OAuth configuration found for {host}")
                return findings
            
            # Test redirect URI validation
            redirect_findings = await self._test_redirect_uri_bypass(
                client, base_url, config, rate_limiter
            )
            findings.extend(redirect_findings)
            
            # Test state parameter
            state_findings = await self._test_state_parameter(
                client, base_url, config, rate_limiter
            )
            findings.extend(state_findings)
            
            # Test PKCE bypass
            pkce_findings = await self._test_pkce_bypass(
                client, base_url, config, rate_limiter
            )
            findings.extend(pkce_findings)
            
            # Test scope manipulation
            scope_findings = await self._test_scope_manipulation(
                client, base_url, config, rate_limiter
            )
            findings.extend(scope_findings)
            
            # Test JWT vulnerabilities
            jwt_findings = await self._test_jwt_vulnerabilities(
                client, base_url, config, rate_limiter
            )
            findings.extend(jwt_findings)
            
            # Test implicit flow
            implicit_findings = await self._test_implicit_flow(
                client, base_url, config, rate_limiter
            )
            findings.extend(implicit_findings)
            
            # Test token leakage
            leakage_findings = await self._test_token_leakage(
                client, base_url, config, rate_limiter
            )
            findings.extend(leakage_findings)
            
            # Test CSRF in OAuth
            csrf_findings = await self._test_oauth_csrf(
                client, base_url, config, rate_limiter
            )
            findings.extend(csrf_findings)
        
        return findings
    
    async def _discover_oauth_config(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """Discover OAuth/OIDC configuration."""
        config = {
            "authorization_endpoint": None,
            "token_endpoint": None,
            "userinfo_endpoint": None,
            "jwks_uri": None,
            "response_types_supported": [],
            "grant_types_supported": [],
            "scopes_supported": [],
        }
        
        # Try well-known endpoints
        well_known_paths = [
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
        ]
        
        for path in well_known_paths:
            await rate_limiter.acquire()
            try:
                url = urljoin(base_url, path)
                response = await client.get(url)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        config.update({
                            "authorization_endpoint": data.get("authorization_endpoint"),
                            "token_endpoint": data.get("token_endpoint"),
                            "userinfo_endpoint": data.get("userinfo_endpoint"),
                            "jwks_uri": data.get("jwks_uri"),
                            "response_types_supported": data.get("response_types_supported", []),
                            "grant_types_supported": data.get("grant_types_supported", []),
                            "scopes_supported": data.get("scopes_supported", []),
                            "issuer": data.get("issuer"),
                        })
                        config["discovered_via"] = path
                        logger.info(f"OAuth config discovered at {path}")
                        return config
                    except json.JSONDecodeError:
                        pass
            except Exception as e:
                logger.debug(f"Error checking {path}: {e}")
        
        # Probe common OAuth endpoints
        for path in self.OAUTH_ENDPOINTS:
            await rate_limiter.acquire()
            try:
                url = urljoin(base_url, path)
                response = await client.get(url, follow_redirects=False)
                
                if response.status_code in [200, 302, 400, 401]:
                    if "authorize" in path:
                        config["authorization_endpoint"] = url
                    elif "token" in path:
                        config["token_endpoint"] = url
                    elif "userinfo" in path:
                        config["userinfo_endpoint"] = url
                    elif "jwks" in path:
                        config["jwks_uri"] = url
            except Exception as e:
                logger.debug(f"Error probing {path}: {e}")
        
        return config
    
    async def _test_redirect_uri_bypass(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        config: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for redirect URI validation bypass."""
        findings = []
        
        auth_endpoint = config.get("authorization_endpoint")
        if not auth_endpoint:
            return findings
        
        # Get a baseline valid redirect
        baseline_redirect = f"{base_url}/callback"
        
        for payload in self.REDIRECT_BYPASS_PAYLOADS:
            await rate_limiter.acquire()
            
            try:
                params = {
                    "response_type": "code",
                    "client_id": "test_client",
                    "redirect_uri": payload,
                    "scope": "openid",
                    "state": secrets.token_urlsafe(16),
                }
                
                response = await client.get(
                    auth_endpoint,
                    params=params,
                    follow_redirects=False
                )
                
                # Check if redirect was accepted
                if response.status_code in [302, 303, 307]:
                    location = response.headers.get("location", "")
                    
                    # Check if our malicious redirect was used
                    if any(bad in location.lower() for bad in ["evil.com", "javascript:", "data:"]):
                        findings.append(Finding(
                            name="OAuth Redirect URI Bypass",
                            severity="CRITICAL",
                            confidence="HIGH",
                            description=f"OAuth redirect_uri validation can be bypassed allowing token theft",
                            matched_at=auth_endpoint,
                            evidence=[
                                f"Payload: {payload}",
                                f"Response redirected to: {location[:200]}",
                            ],
                            cwe="CWE-601",
                            cvss_score=9.1,
                            remediation="Implement strict redirect URI validation with exact matching. "
                                       "Do not allow wildcards or pattern matching in redirect URIs.",
                        ))
                        break  # One finding is enough
                
                # Check for open redirect indicators
                if response.status_code == 200:
                    if "invalid_redirect" not in response.text.lower() and \
                       "error" not in response.text.lower()[:500]:
                        # Might be accepting the redirect
                        findings.append(Finding(
                            name="Potential OAuth Redirect URI Bypass",
                            severity="HIGH",
                            confidence="MEDIUM",
                            description="OAuth endpoint may accept arbitrary redirect URIs",
                            matched_at=auth_endpoint,
                            evidence=[
                                f"Payload: {payload}",
                                f"No explicit error returned",
                            ],
                            cwe="CWE-601",
                            remediation="Review redirect URI validation logic.",
                        ))
                        
            except Exception as e:
                logger.debug(f"Error testing redirect bypass: {e}")
        
        return findings
    
    async def _test_state_parameter(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        config: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for state parameter vulnerabilities (CSRF)."""
        findings = []
        
        auth_endpoint = config.get("authorization_endpoint")
        if not auth_endpoint:
            return findings
        
        await rate_limiter.acquire()
        
        try:
            # Test without state parameter
            params = {
                "response_type": "code",
                "client_id": "test_client",
                "redirect_uri": f"{base_url}/callback",
                "scope": "openid",
            }
            
            response = await client.get(
                auth_endpoint,
                params=params,
                follow_redirects=False
            )
            
            # If request proceeds without state, it's vulnerable to CSRF
            if response.status_code in [200, 302, 303, 307]:
                if "state" not in response.text.lower() or \
                   "required" not in response.text.lower():
                    findings.append(Finding(
                        name="OAuth CSRF - Missing State Parameter",
                        severity="HIGH",
                        confidence="HIGH",
                        description="OAuth flow accepts requests without state parameter, "
                                   "enabling CSRF attacks on the authorization flow",
                        matched_at=auth_endpoint,
                        evidence=[
                            "Request without state parameter was accepted",
                            f"Response status: {response.status_code}",
                        ],
                        cwe="CWE-352",
                        cvss_score=7.5,
                        remediation="Require and validate state parameter in all OAuth flows. "
                                   "Use cryptographically secure random values.",
                    ))
            
            # Test with predictable state
            weak_states = ["123", "state", "test", "1", "abc"]
            for weak_state in weak_states:
                await rate_limiter.acquire()
                
                params["state"] = weak_state
                response = await client.get(
                    auth_endpoint,
                    params=params,
                    follow_redirects=False
                )
                
                if response.status_code in [200, 302]:
                    findings.append(Finding(
                        name="OAuth Weak State Parameter Accepted",
                        severity="MEDIUM",
                        confidence="MEDIUM",
                        description="OAuth accepts predictable state values",
                        matched_at=auth_endpoint,
                        evidence=[f"Weak state '{weak_state}' was accepted"],
                        cwe="CWE-330",
                        remediation="Validate state parameter entropy and binding to user session.",
                    ))
                    break
                    
        except Exception as e:
            logger.debug(f"Error testing state parameter: {e}")
        
        return findings
    
    async def _test_pkce_bypass(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        config: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for PKCE bypass vulnerabilities."""
        findings = []
        
        token_endpoint = config.get("token_endpoint")
        auth_endpoint = config.get("authorization_endpoint")
        
        if not token_endpoint:
            return findings
        
        await rate_limiter.acquire()
        
        try:
            # Test token endpoint without code_verifier when PKCE was used
            data = {
                "grant_type": "authorization_code",
                "code": "test_authorization_code",
                "redirect_uri": f"{base_url}/callback",
                "client_id": "test_client",
                # Intentionally omitting code_verifier
            }
            
            response = await client.post(token_endpoint, data=data)
            
            # Check if PKCE is enforced
            if response.status_code != 400:
                response_text = response.text.lower()
                if "code_verifier" not in response_text and \
                   "pkce" not in response_text:
                    findings.append(Finding(
                        name="OAuth PKCE Not Enforced",
                        severity="HIGH",
                        confidence="MEDIUM",
                        description="Token endpoint does not require PKCE code_verifier, "
                                   "making authorization codes vulnerable to interception",
                        matched_at=token_endpoint,
                        evidence=[
                            "Token request without code_verifier did not fail",
                            f"Response: {response.text[:200]}",
                        ],
                        cwe="CWE-287",
                        cvss_score=7.4,
                        remediation="Enforce PKCE for all public clients and consider for confidential clients.",
                    ))
            
            # Test with mismatched code_verifier
            await rate_limiter.acquire()
            
            # Generate valid PKCE pair
            code_verifier = secrets.token_urlsafe(32)
            code_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).rstrip(b'=').decode()
            
            # Use different verifier
            data["code_verifier"] = "wrong_verifier_value"
            
            response = await client.post(token_endpoint, data=data)
            
            if response.status_code == 200:
                findings.append(Finding(
                    name="OAuth PKCE Validation Bypass",
                    severity="CRITICAL",
                    confidence="HIGH",
                    description="Token endpoint accepts invalid code_verifier values",
                    matched_at=token_endpoint,
                    evidence=["Invalid code_verifier was accepted"],
                    cwe="CWE-287",
                    cvss_score=9.1,
                    remediation="Properly validate code_verifier against stored code_challenge.",
                ))
                
        except Exception as e:
            logger.debug(f"Error testing PKCE: {e}")
        
        return findings
    
    async def _test_scope_manipulation(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        config: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for scope manipulation vulnerabilities."""
        findings = []
        
        auth_endpoint = config.get("authorization_endpoint")
        if not auth_endpoint:
            return findings
        
        # Elevated scopes to test
        elevated_scopes = [
            "admin",
            "admin:read",
            "admin:write",
            "user:admin",
            "scope:admin",
            "all",
            "*",
            "root",
            "superuser",
            "system",
            "internal",
            "offline_access",
            "read:users",
            "write:users",
            "delete:users",
        ]
        
        for scope in elevated_scopes:
            await rate_limiter.acquire()
            
            try:
                params = {
                    "response_type": "code",
                    "client_id": "test_client",
                    "redirect_uri": f"{base_url}/callback",
                    "scope": f"openid {scope}",
                    "state": secrets.token_urlsafe(16),
                }
                
                response = await client.get(
                    auth_endpoint,
                    params=params,
                    follow_redirects=False
                )
                
                # If elevated scope is accepted without explicit consent/error
                if response.status_code in [200, 302]:
                    if "invalid_scope" not in response.text.lower() and \
                       "unauthorized" not in response.text.lower():
                        findings.append(Finding(
                            name="OAuth Scope Escalation",
                            severity="HIGH",
                            confidence="MEDIUM",
                            description=f"OAuth endpoint accepts elevated scope '{scope}'",
                            matched_at=auth_endpoint,
                            evidence=[
                                f"Scope '{scope}' was accepted",
                                f"Response status: {response.status_code}",
                            ],
                            cwe="CWE-269",
                            cvss_score=7.5,
                            remediation="Implement strict scope validation against allowed scopes per client.",
                        ))
                        
            except Exception as e:
                logger.debug(f"Error testing scope {scope}: {e}")
        
        return findings
    
    async def _test_jwt_vulnerabilities(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        config: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for JWT algorithm confusion and other JWT attacks."""
        findings = []
        
        jwks_uri = config.get("jwks_uri")
        userinfo_endpoint = config.get("userinfo_endpoint")
        
        # Test algorithm confusion attacks
        for alg_payload in self.JWT_ALG_PAYLOADS:
            # Create JWT with manipulated algorithm
            header = base64.urlsafe_b64encode(
                json.dumps(alg_payload).encode()
            ).rstrip(b'=').decode()
            
            payload = base64.urlsafe_b64encode(
                json.dumps({
                    "sub": "admin",
                    "iat": 1700000000,
                    "exp": 2000000000,
                    "admin": True,
                }).encode()
            ).rstrip(b'=').decode()
            
            # For 'none' algorithm, signature is empty
            if alg_payload.get("alg", "").lower() == "none":
                malicious_jwt = f"{header}.{payload}."
            else:
                malicious_jwt = f"{header}.{payload}.fakesignature"
            
            if userinfo_endpoint:
                await rate_limiter.acquire()
                
                try:
                    response = await client.get(
                        userinfo_endpoint,
                        headers={"Authorization": f"Bearer {malicious_jwt}"}
                    )
                    
                    if response.status_code == 200:
                        findings.append(Finding(
                            name=f"JWT Algorithm Confusion - {alg_payload.get('alg')}",
                            severity="CRITICAL",
                            confidence="HIGH",
                            description=f"Server accepts JWT with '{alg_payload.get('alg')}' algorithm",
                            matched_at=userinfo_endpoint,
                            evidence=[
                                f"Malicious JWT accepted",
                                f"Algorithm: {alg_payload.get('alg')}",
                            ],
                            cwe="CWE-327",
                            cvss_score=9.8,
                            remediation="Explicitly verify JWT algorithm against expected value. "
                                       "Never accept 'none' algorithm in production.",
                        ))
                        break
                        
                except Exception as e:
                    logger.debug(f"Error testing JWT alg {alg_payload}: {e}")
        
        # Check if JWKS is exposed
        if jwks_uri:
            await rate_limiter.acquire()
            
            try:
                response = await client.get(jwks_uri)
                
                if response.status_code == 200:
                    jwks_data = response.json()
                    
                    # Check for weak keys
                    for key in jwks_data.get("keys", []):
                        if key.get("kty") == "RSA":
                            # Check key size if 'n' is available
                            n = key.get("n", "")
                            if len(n) < 300:  # Roughly indicates < 2048 bits
                                findings.append(Finding(
                                    name="Weak RSA Key in JWKS",
                                    severity="HIGH",
                                    confidence="MEDIUM",
                                    description="JWKS contains potentially weak RSA key",
                                    matched_at=jwks_uri,
                                    evidence=[f"Key ID: {key.get('kid')}"],
                                    cwe="CWE-326",
                                    remediation="Use RSA keys of at least 2048 bits.",
                                ))
                                
            except Exception as e:
                logger.debug(f"Error checking JWKS: {e}")
        
        return findings
    
    async def _test_implicit_flow(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        config: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for implicit flow vulnerabilities."""
        findings = []
        
        auth_endpoint = config.get("authorization_endpoint")
        response_types = config.get("response_types_supported", [])
        
        if not auth_endpoint:
            return findings
        
        # Check if implicit flow is supported
        implicit_types = ["token", "id_token", "token id_token"]
        
        for response_type in implicit_types:
            await rate_limiter.acquire()
            
            try:
                params = {
                    "response_type": response_type,
                    "client_id": "test_client",
                    "redirect_uri": f"{base_url}/callback",
                    "scope": "openid",
                    "state": secrets.token_urlsafe(16),
                    "nonce": secrets.token_urlsafe(16),
                }
                
                response = await client.get(
                    auth_endpoint,
                    params=params,
                    follow_redirects=False
                )
                
                if response.status_code in [200, 302]:
                    if "unsupported_response_type" not in response.text.lower():
                        findings.append(Finding(
                            name="OAuth Implicit Flow Enabled",
                            severity="MEDIUM",
                            confidence="HIGH",
                            description=f"OAuth implicit flow ({response_type}) is enabled. "
                                       "Implicit flow exposes tokens in URL fragments.",
                            matched_at=auth_endpoint,
                            evidence=[
                                f"Response type '{response_type}' is supported",
                            ],
                            cwe="CWE-522",
                            cvss_score=5.3,
                            remediation="Disable implicit flow and use authorization code flow with PKCE.",
                        ))
                        break
                        
            except Exception as e:
                logger.debug(f"Error testing implicit flow: {e}")
        
        return findings
    
    async def _test_token_leakage(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        config: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for token leakage vulnerabilities."""
        findings = []
        
        auth_endpoint = config.get("authorization_endpoint")
        if not auth_endpoint:
            return findings
        
        await rate_limiter.acquire()
        
        try:
            # Test if tokens appear in URL (via GET)
            params = {
                "response_type": "code",
                "client_id": "test_client",
                "redirect_uri": f"{base_url}/callback",
                "scope": "openid",
                "state": secrets.token_urlsafe(16),
            }
            
            response = await client.get(
                auth_endpoint,
                params=params,
                follow_redirects=False
            )
            
            # Check for token in referrer
            if response.status_code == 200:
                # Check if there are external resources that could leak via Referer
                external_patterns = [
                    r'src=["\']https?://[^/]*(?!{})'.format(re.escape(urlparse(base_url).netloc)),
                    r'href=["\']https?://[^/]*(?!{})'.format(re.escape(urlparse(base_url).netloc)),
                ]
                
                for pattern in external_patterns:
                    if re.search(pattern, response.text):
                        findings.append(Finding(
                            name="Potential Token Leakage via Referrer",
                            severity="MEDIUM",
                            confidence="MEDIUM",
                            description="OAuth page includes external resources that may leak tokens via Referer header",
                            matched_at=auth_endpoint,
                            evidence=["External resources found on OAuth page"],
                            cwe="CWE-200",
                            remediation="Use Referrer-Policy header to prevent token leakage.",
                        ))
                        break
                
                # Check for missing Referrer-Policy
                if "referrer-policy" not in [h.lower() for h in response.headers.keys()]:
                    findings.append(Finding(
                        name="Missing Referrer-Policy on OAuth Endpoint",
                        severity="LOW",
                        confidence="HIGH",
                        description="OAuth endpoint missing Referrer-Policy header",
                        matched_at=auth_endpoint,
                        evidence=["Referrer-Policy header not set"],
                        cwe="CWE-200",
                        remediation="Set Referrer-Policy: no-referrer or same-origin.",
                    ))
                    
        except Exception as e:
            logger.debug(f"Error testing token leakage: {e}")
        
        return findings
    
    async def _test_oauth_csrf(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        config: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for CSRF vulnerabilities in OAuth flow."""
        findings = []
        
        token_endpoint = config.get("token_endpoint")
        if not token_endpoint:
            return findings
        
        await rate_limiter.acquire()
        
        try:
            # Test token endpoint without proper origin/referer validation
            headers = {
                "Origin": "https://evil.com",
                "Referer": "https://evil.com/attack",
            }
            
            data = {
                "grant_type": "authorization_code",
                "code": "test_code",
                "redirect_uri": f"{base_url}/callback",
                "client_id": "test_client",
            }
            
            response = await client.post(
                token_endpoint,
                data=data,
                headers=headers
            )
            
            # If request from different origin is processed
            if response.status_code != 403:
                # Check CORS headers
                cors_origin = response.headers.get("access-control-allow-origin", "")
                
                if cors_origin == "*" or "evil.com" in cors_origin:
                    findings.append(Finding(
                        name="OAuth Token Endpoint CORS Misconfiguration",
                        severity="HIGH",
                        confidence="HIGH",
                        description="Token endpoint allows requests from arbitrary origins",
                        matched_at=token_endpoint,
                        evidence=[
                            f"CORS header: {cors_origin}",
                            "Request from evil.com origin was processed",
                        ],
                        cwe="CWE-346",
                        cvss_score=7.5,
                        remediation="Restrict CORS to specific trusted origins only.",
                    ))
                    
        except Exception as e:
            logger.debug(f"Error testing OAuth CSRF: {e}")
        
        return findings
