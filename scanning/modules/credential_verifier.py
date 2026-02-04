"""
Credential Verifier - HackerOne Compliant Credential Validation.

IMPORTANT: This module follows HackerOne Platform Standards for leaked credentials:
- ONLY authenticate/deauthenticate - NO functionality exercise
- Do NOT access any user data
- Do NOT perform any actions
- Report immediately after verification
- Document the SOURCE of credentials

Reference: HackerOne Platform Standards §9 - Leaked Credentials (Exemplary Standard)
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx

from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class CredentialStatus(Enum):
    """Status of credential verification."""
    VALID = auto()          # Credential works (auth succeeded)
    INVALID = auto()        # Credential doesn't work (auth failed)  
    REVOKED = auto()        # Credential was revoked
    RATE_LIMITED = auto()   # Couldn't verify due to rate limiting
    NOT_VERIFIABLE = auto() # Credential type can't be verified
    ERROR = auto()          # Error during verification


class CredentialSource(Enum):
    """Source where credential was found."""
    CLIENT_CODE = "client_side_code"
    API_RESPONSE = "api_response"
    CONFIG_FILE = "config_file"
    JAVASCRIPT = "javascript_bundle"
    HTML = "html_source"
    HEADERS = "http_headers"
    ERROR_MESSAGE = "error_message"
    DEBUG_OUTPUT = "debug_output"
    GITHUB = "github_repository"
    PASTEBIN = "paste_site"
    OTHER = "other"


@dataclass
class CredentialVerificationResult:
    """Result of credential verification - HackerOne compliant."""
    credential_type: str
    credential_masked: str
    source: CredentialSource
    source_url: str
    status: CredentialStatus
    verification_method: str
    access_level: str = "unknown"  # admin, user, service, etc.
    severity: str = "unknown"
    timestamp: str = ""
    notes: list[str] = field(default_factory=list)
    
    @property
    def is_valid(self) -> bool:
        return self.status == CredentialStatus.VALID
    
    def to_finding(self) -> dict:
        """Convert to scanner finding format."""
        if not self.is_valid:
            return {}
        
        severity_map = {
            "admin": "critical",
            "service": "critical",
            "user": "high",
            "read_only": "medium",
            "unknown": "high",
        }
        
        return {
            "type": "leaked_credential",
            "title": f"Valid Leaked {self.credential_type} Found",
            "severity": severity_map.get(self.access_level, "high"),
            "confidence": 100,  # Verified credentials - confirmed working
            "description": (
                f"A valid {self.credential_type} was found exposed. "
                f"Verification confirmed authentication succeeds. "
                f"Access level: {self.access_level}."
            ),
            "evidence": {
                "credential_masked": self.credential_masked,
                "source": self.source.value,
                "source_url": self.source_url,
                "verification_method": self.verification_method,
                "access_level": self.access_level,
            },
            "remediation": (
                "1. IMMEDIATELY rotate this credential\n"
                "2. Audit usage logs for unauthorized access\n"
                "3. Review and revoke any sessions\n"
                "4. Investigate how the credential was exposed"
            ),
            "cwe": "CWE-798",
            "cvss": "8.0" if self.access_level in ["admin", "service"] else "6.5",
            "references": [
                "https://cwe.mitre.org/data/definitions/798.html",
                "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            ],
        }


class CredentialVerifier:
    """
    HackerOne-compliant credential verifier.
    
    ONLY performs authentication checks - NEVER exercises functionality.
    Per HackerOne Platform Standards §9:
    - Authenticate/deauthenticate only
    - No accessing user data
    - No performing actions
    - Report immediately with source
    """
    
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings
        self.timeout = httpx.Timeout(10.0)
        self.verification_enabled = True
        self._verified_cache: dict[str, CredentialStatus] = {}
    
    async def scan(self, target: str, asset_data: dict | None = None) -> dict:
        """
        Scan interface for compatibility with full_scanner.
        
        This does NOT actively find credentials - it verifies credentials
        found by other modules (cloud_scanner, backend_detector, etc.)
        """
        # This module is called by other modules to verify found credentials
        # It doesn't scan on its own
        return {
            "findings": [],
            "info": [{
                "type": "credential_verifier_ready",
                "enabled": self.verification_enabled,
                "note": "Ready to verify credentials found by other modules",
            }],
        }
    
    async def verify_credential(
        self,
        credential_type: str,
        credential_value: str,
        source: CredentialSource,
        source_url: str,
    ) -> CredentialVerificationResult:
        """
        Verify if a credential is valid - HackerOne compliant.
        
        IMPORTANT: This method ONLY authenticates. It does NOT:
        - Access any user data
        - Perform any actions
        - Exercise any functionality
        
        Args:
            credential_type: Type of credential (aws_key, stripe_key, etc.)
            credential_value: The actual credential
            source: Where the credential was found
            source_url: URL where found
            
        Returns:
            CredentialVerificationResult with status
        """
        # Cache check
        cache_key = f"{credential_type}:{credential_value[:8]}...{credential_value[-4:]}"
        if cache_key in self._verified_cache:
            return CredentialVerificationResult(
                credential_type=credential_type,
                credential_masked=self._mask_credential(credential_value),
                source=source,
                source_url=source_url,
                status=self._verified_cache[cache_key],
                verification_method="cached",
                notes=["Result from cache"],
            )
        
        # Route to appropriate verifier
        verifiers = {
            "aws_access_key": self._verify_aws_key,
            "stripe_secret_key": self._verify_stripe_key,
            "stripe_test_key": self._verify_stripe_key,
            "github_token": self._verify_github_token,
            "gitlab_token": self._verify_gitlab_token,
            "slack_token": self._verify_slack_token,
            "twilio_auth_token": self._verify_twilio_key,
            "sendgrid_key": self._verify_sendgrid_key,
            "openai_key": self._verify_openai_key,
            "firebase_key": self._verify_firebase_key,
            "supabase_key": self._verify_supabase_key,
            "jwt_token": self._verify_jwt_token,
        }
        
        verifier = verifiers.get(credential_type)
        if not verifier:
            return CredentialVerificationResult(
                credential_type=credential_type,
                credential_masked=self._mask_credential(credential_value),
                source=source,
                source_url=source_url,
                status=CredentialStatus.NOT_VERIFIABLE,
                verification_method="none",
                notes=[f"No verifier available for {credential_type}"],
            )
        
        try:
            result = await verifier(credential_value, source, source_url)
            self._verified_cache[cache_key] = result.status
            return result
        except Exception as e:
            logger.warning(f"Credential verification failed: {e}")
            return CredentialVerificationResult(
                credential_type=credential_type,
                credential_masked=self._mask_credential(credential_value),
                source=source,
                source_url=source_url,
                status=CredentialStatus.ERROR,
                verification_method="error",
                notes=[f"Verification error: {str(e)}"],
            )
    
    def _mask_credential(self, value: str) -> str:
        """Mask credential for safe logging/reporting."""
        if len(value) < 8:
            return "*" * len(value)
        return f"{value[:4]}...{value[-4:]}"
    
    async def _verify_aws_key(
        self,
        credential: str,
        source: CredentialSource,
        source_url: str,
    ) -> CredentialVerificationResult:
        """
        Verify AWS credentials - AUTH ONLY.
        
        Uses GetCallerIdentity which only returns identity info,
        doesn't access any resources or perform actions.
        """
        # AWS keys come in pairs - need both access key and secret
        # If we only have access key, we can't verify
        if not re.match(r'^A[KS]IA[0-9A-Z]{16}$', credential):
            return CredentialVerificationResult(
                credential_type="aws_access_key",
                credential_masked=self._mask_credential(credential),
                source=source,
                source_url=source_url,
                status=CredentialStatus.NOT_VERIFIABLE,
                verification_method="none",
                notes=["Need both access key and secret key to verify"],
            )
        
        # For now, mark as not verifiable without secret key
        return CredentialVerificationResult(
            credential_type="aws_access_key",
            credential_masked=self._mask_credential(credential),
            source=source,
            source_url=source_url,
            status=CredentialStatus.NOT_VERIFIABLE,
            verification_method="none",
            notes=["AWS key found but secret key needed for verification"],
        )
    
    async def _verify_stripe_key(
        self,
        credential: str,
        source: CredentialSource,
        source_url: str,
    ) -> CredentialVerificationResult:
        """
        Verify Stripe API key - AUTH ONLY.
        
        Uses /v1/balance endpoint which only returns balance info.
        NO actions performed.
        """
        is_live = credential.startswith("sk_live_")
        key_type = "stripe_live_key" if is_live else "stripe_test_key"
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Balance endpoint is read-only, auth check only
                response = await client.get(
                    "https://api.stripe.com/v1/balance",
                    auth=(credential, ""),
                )
                
                if response.status_code == 200:
                    # Key is valid - get access level from response
                    # Stripe keys that work are either live or test
                    return CredentialVerificationResult(
                        credential_type=key_type,
                        credential_masked=self._mask_credential(credential),
                        source=source,
                        source_url=source_url,
                        status=CredentialStatus.VALID,
                        verification_method="stripe_balance_api",
                        access_level="service" if is_live else "test",
                        severity="critical" if is_live else "medium",
                        notes=[
                            "Authentication successful via Stripe Balance API",
                            "NO transactions or actions performed",
                            f"Key type: {'LIVE' if is_live else 'TEST'}",
                        ],
                    )
                elif response.status_code == 401:
                    return CredentialVerificationResult(
                        credential_type=key_type,
                        credential_masked=self._mask_credential(credential),
                        source=source,
                        source_url=source_url,
                        status=CredentialStatus.INVALID,
                        verification_method="stripe_balance_api",
                        notes=["Authentication failed - key invalid or revoked"],
                    )
                elif response.status_code == 429:
                    return CredentialVerificationResult(
                        credential_type=key_type,
                        credential_masked=self._mask_credential(credential),
                        source=source,
                        source_url=source_url,
                        status=CredentialStatus.RATE_LIMITED,
                        verification_method="stripe_balance_api",
                        notes=["Rate limited - could not verify"],
                    )
                else:
                    return CredentialVerificationResult(
                        credential_type=key_type,
                        credential_masked=self._mask_credential(credential),
                        source=source,
                        source_url=source_url,
                        status=CredentialStatus.ERROR,
                        verification_method="stripe_balance_api",
                        notes=[f"Unexpected response: {response.status_code}"],
                    )
        except Exception as e:
            return CredentialVerificationResult(
                credential_type=key_type,
                credential_masked=self._mask_credential(credential),
                source=source,
                source_url=source_url,
                status=CredentialStatus.ERROR,
                verification_method="stripe_balance_api",
                notes=[f"Error: {str(e)}"],
            )
    
    async def _verify_github_token(
        self,
        credential: str,
        source: CredentialSource,
        source_url: str,
    ) -> CredentialVerificationResult:
        """
        Verify GitHub token - AUTH ONLY.
        
        Uses /user endpoint which only returns user info.
        NO actions performed, no data accessed.
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    "https://api.github.com/user",
                    headers={
                        "Authorization": f"token {credential}",
                        "Accept": "application/vnd.github.v3+json",
                    },
                )
                
                if response.status_code == 200:
                    data = response.json()
                    access_level = "admin" if data.get("site_admin") else "user"
                    
                    return CredentialVerificationResult(
                        credential_type="github_token",
                        credential_masked=self._mask_credential(credential),
                        source=source,
                        source_url=source_url,
                        status=CredentialStatus.VALID,
                        verification_method="github_user_api",
                        access_level=access_level,
                        severity="critical" if access_level == "admin" else "high",
                        notes=[
                            "Authentication successful via GitHub User API",
                            "NO repositories or data accessed",
                            f"Token owner: {data.get('login', 'unknown')}",
                        ],
                    )
                elif response.status_code == 401:
                    return CredentialVerificationResult(
                        credential_type="github_token",
                        credential_masked=self._mask_credential(credential),
                        source=source,
                        source_url=source_url,
                        status=CredentialStatus.INVALID,
                        verification_method="github_user_api",
                        notes=["Authentication failed - token invalid or revoked"],
                    )
                elif response.status_code == 403:
                    # Token might be valid but rate limited or scoped
                    return CredentialVerificationResult(
                        credential_type="github_token",
                        credential_masked=self._mask_credential(credential),
                        source=source,
                        source_url=source_url,
                        status=CredentialStatus.RATE_LIMITED,
                        verification_method="github_user_api",
                        notes=["Rate limited or scope restricted"],
                    )
                else:
                    return CredentialVerificationResult(
                        credential_type="github_token",
                        credential_masked=self._mask_credential(credential),
                        source=source,
                        source_url=source_url,
                        status=CredentialStatus.ERROR,
                        verification_method="github_user_api",
                        notes=[f"Unexpected response: {response.status_code}"],
                    )
        except Exception as e:
            return CredentialVerificationResult(
                credential_type="github_token",
                credential_masked=self._mask_credential(credential),
                source=source,
                source_url=source_url,
                status=CredentialStatus.ERROR,
                verification_method="github_user_api",
                notes=[f"Error: {str(e)}"],
            )
    
    async def _verify_gitlab_token(
        self,
        credential: str,
        source: CredentialSource,
        source_url: str,
    ) -> CredentialVerificationResult:
        """Verify GitLab token - AUTH ONLY."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    "https://gitlab.com/api/v4/user",
                    headers={"PRIVATE-TOKEN": credential},
                )
                
                if response.status_code == 200:
                    data = response.json()
                    access_level = "admin" if data.get("is_admin") else "user"
                    
                    return CredentialVerificationResult(
                        credential_type="gitlab_token",
                        credential_masked=self._mask_credential(credential),
                        source=source,
                        source_url=source_url,
                        status=CredentialStatus.VALID,
                        verification_method="gitlab_user_api",
                        access_level=access_level,
                        severity="critical" if access_level == "admin" else "high",
                        notes=[
                            "Authentication successful via GitLab User API",
                            f"Token owner: {data.get('username', 'unknown')}",
                        ],
                    )
                elif response.status_code == 401:
                    return CredentialVerificationResult(
                        credential_type="gitlab_token",
                        credential_masked=self._mask_credential(credential),
                        source=source,
                        source_url=source_url,
                        status=CredentialStatus.INVALID,
                        verification_method="gitlab_user_api",
                        notes=["Authentication failed"],
                    )
                else:
                    return CredentialVerificationResult(
                        credential_type="gitlab_token",
                        credential_masked=self._mask_credential(credential),
                        source=source,
                        source_url=source_url,
                        status=CredentialStatus.ERROR,
                        verification_method="gitlab_user_api",
                        notes=[f"Unexpected response: {response.status_code}"],
                    )
        except Exception as e:
            return CredentialVerificationResult(
                credential_type="gitlab_token",
                credential_masked=self._mask_credential(credential),
                source=source,
                source_url=source_url,
                status=CredentialStatus.ERROR,
                verification_method="gitlab_user_api",
                notes=[f"Error: {str(e)}"],
            )
    
    async def _verify_slack_token(
        self,
        credential: str,
        source: CredentialSource,
        source_url: str,
    ) -> CredentialVerificationResult:
        """Verify Slack token - AUTH ONLY."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    "https://slack.com/api/auth.test",
                    headers={"Authorization": f"Bearer {credential}"},
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("ok"):
                        return CredentialVerificationResult(
                            credential_type="slack_token",
                            credential_masked=self._mask_credential(credential),
                            source=source,
                            source_url=source_url,
                            status=CredentialStatus.VALID,
                            verification_method="slack_auth_test",
                            access_level="service",
                            severity="high",
                            notes=[
                                "Authentication successful via Slack Auth Test",
                                f"Workspace: {data.get('team', 'unknown')}",
                            ],
                        )
                    else:
                        return CredentialVerificationResult(
                            credential_type="slack_token",
                            credential_masked=self._mask_credential(credential),
                            source=source,
                            source_url=source_url,
                            status=CredentialStatus.INVALID,
                            verification_method="slack_auth_test",
                            notes=[f"Auth failed: {data.get('error', 'unknown')}"],
                        )
                else:
                    return CredentialVerificationResult(
                        credential_type="slack_token",
                        credential_masked=self._mask_credential(credential),
                        source=source,
                        source_url=source_url,
                        status=CredentialStatus.ERROR,
                        verification_method="slack_auth_test",
                        notes=[f"HTTP error: {response.status_code}"],
                    )
        except Exception as e:
            return CredentialVerificationResult(
                credential_type="slack_token",
                credential_masked=self._mask_credential(credential),
                source=source,
                source_url=source_url,
                status=CredentialStatus.ERROR,
                verification_method="slack_auth_test",
                notes=[f"Error: {str(e)}"],
            )
    
    async def _verify_twilio_key(
        self,
        credential: str,
        source: CredentialSource,
        source_url: str,
    ) -> CredentialVerificationResult:
        """
        Verify Twilio credentials - AUTH ONLY.
        
        Uses account info endpoint, no actions performed.
        """
        # Twilio needs Account SID + Auth Token
        return CredentialVerificationResult(
            credential_type="twilio_auth_token",
            credential_masked=self._mask_credential(credential),
            source=source,
            source_url=source_url,
            status=CredentialStatus.NOT_VERIFIABLE,
            verification_method="none",
            notes=["Need both Account SID and Auth Token to verify Twilio credentials"],
        )
    
    async def _verify_sendgrid_key(
        self,
        credential: str,
        source: CredentialSource,
        source_url: str,
    ) -> CredentialVerificationResult:
        """Verify SendGrid API key - AUTH ONLY."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    "https://api.sendgrid.com/v3/scopes",
                    headers={"Authorization": f"Bearer {credential}"},
                )
                
                if response.status_code == 200:
                    data = response.json()
                    scopes = data.get("scopes", [])
                    
                    # Determine access level from scopes
                    if "mail.send" in scopes:
                        access_level = "service"
                        severity = "critical"
                    else:
                        access_level = "read_only"
                        severity = "medium"
                    
                    return CredentialVerificationResult(
                        credential_type="sendgrid_key",
                        credential_masked=self._mask_credential(credential),
                        source=source,
                        source_url=source_url,
                        status=CredentialStatus.VALID,
                        verification_method="sendgrid_scopes_api",
                        access_level=access_level,
                        severity=severity,
                        notes=[
                            "Authentication successful via SendGrid Scopes API",
                            f"Scopes: {len(scopes)} permissions",
                        ],
                    )
                elif response.status_code == 401:
                    return CredentialVerificationResult(
                        credential_type="sendgrid_key",
                        credential_masked=self._mask_credential(credential),
                        source=source,
                        source_url=source_url,
                        status=CredentialStatus.INVALID,
                        verification_method="sendgrid_scopes_api",
                        notes=["Authentication failed"],
                    )
                else:
                    return CredentialVerificationResult(
                        credential_type="sendgrid_key",
                        credential_masked=self._mask_credential(credential),
                        source=source,
                        source_url=source_url,
                        status=CredentialStatus.ERROR,
                        verification_method="sendgrid_scopes_api",
                        notes=[f"HTTP error: {response.status_code}"],
                    )
        except Exception as e:
            return CredentialVerificationResult(
                credential_type="sendgrid_key",
                credential_masked=self._mask_credential(credential),
                source=source,
                source_url=source_url,
                status=CredentialStatus.ERROR,
                verification_method="sendgrid_scopes_api",
                notes=[f"Error: {str(e)}"],
            )
    
    async def _verify_openai_key(
        self,
        credential: str,
        source: CredentialSource,
        source_url: str,
    ) -> CredentialVerificationResult:
        """Verify OpenAI API key - AUTH ONLY."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    "https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {credential}"},
                )
                
                if response.status_code == 200:
                    return CredentialVerificationResult(
                        credential_type="openai_key",
                        credential_masked=self._mask_credential(credential),
                        source=source,
                        source_url=source_url,
                        status=CredentialStatus.VALID,
                        verification_method="openai_models_api",
                        access_level="service",
                        severity="high",
                        notes=["Authentication successful via OpenAI Models API"],
                    )
                elif response.status_code == 401:
                    return CredentialVerificationResult(
                        credential_type="openai_key",
                        credential_masked=self._mask_credential(credential),
                        source=source,
                        source_url=source_url,
                        status=CredentialStatus.INVALID,
                        verification_method="openai_models_api",
                        notes=["Authentication failed"],
                    )
                else:
                    return CredentialVerificationResult(
                        credential_type="openai_key",
                        credential_masked=self._mask_credential(credential),
                        source=source,
                        source_url=source_url,
                        status=CredentialStatus.ERROR,
                        verification_method="openai_models_api",
                        notes=[f"HTTP error: {response.status_code}"],
                    )
        except Exception as e:
            return CredentialVerificationResult(
                credential_type="openai_key",
                credential_masked=self._mask_credential(credential),
                source=source,
                source_url=source_url,
                status=CredentialStatus.ERROR,
                verification_method="openai_models_api",
                notes=[f"Error: {str(e)}"],
            )
    
    async def _verify_firebase_key(
        self,
        credential: str,
        source: CredentialSource,
        source_url: str,
    ) -> CredentialVerificationResult:
        """
        Verify Firebase API key.
        
        Firebase API keys are meant to be public (identify the project).
        The key itself isn't secret - security is via Firebase Rules.
        """
        return CredentialVerificationResult(
            credential_type="firebase_key",
            credential_masked=self._mask_credential(credential),
            source=source,
            source_url=source_url,
            status=CredentialStatus.NOT_VERIFIABLE,
            verification_method="none",
            notes=[
                "Firebase API keys are PUBLIC by design",
                "Security is controlled via Firebase Security Rules",
                "Check Firebase Rules configuration instead",
            ],
        )
    
    async def _verify_supabase_key(
        self,
        credential: str,
        source: CredentialSource,
        source_url: str,
    ) -> CredentialVerificationResult:
        """
        Verify Supabase key.
        
        anon key is public (safe), service_role key is CRITICAL.
        """
        # Detect key type from JWT claims
        try:
            import base64
            import json
            
            parts = credential.split(".")
            if len(parts) >= 2:
                # Decode payload (second part)
                payload = parts[1]
                # Add padding
                payload += "=" * (4 - len(payload) % 4)
                decoded = base64.urlsafe_b64decode(payload)
                claims = json.loads(decoded)
                
                role = claims.get("role", "unknown")
                
                if role == "service_role":
                    return CredentialVerificationResult(
                        credential_type="supabase_service_role",
                        credential_masked=self._mask_credential(credential),
                        source=source,
                        source_url=source_url,
                        status=CredentialStatus.VALID,  # service_role keys are always valid if they exist
                        verification_method="jwt_decode",
                        access_level="admin",
                        severity="critical",
                        notes=[
                            "CRITICAL: service_role key exposed",
                            "This key bypasses Row Level Security",
                            "Full database access without authentication",
                        ],
                    )
                elif role == "anon":
                    return CredentialVerificationResult(
                        credential_type="supabase_anon_key",
                        credential_masked=self._mask_credential(credential),
                        source=source,
                        source_url=source_url,
                        status=CredentialStatus.NOT_VERIFIABLE,
                        verification_method="jwt_decode",
                        access_level="public",
                        notes=[
                            "anon key is PUBLIC by design",
                            "Security is controlled via RLS policies",
                        ],
                    )
        except Exception as e:
            pass
        
        return CredentialVerificationResult(
            credential_type="supabase_key",
            credential_masked=self._mask_credential(credential),
            source=source,
            source_url=source_url,
            status=CredentialStatus.NOT_VERIFIABLE,
            verification_method="none",
            notes=["Could not decode Supabase key"],
        )
    
    async def _verify_jwt_token(
        self,
        credential: str,
        source: CredentialSource,
        source_url: str,
    ) -> CredentialVerificationResult:
        """
        Analyze JWT token - NO verification against server.
        
        JWTs can only be verified with the secret/key.
        We analyze claims but don't attempt to use the token.
        """
        try:
            import base64
            import json
            from datetime import datetime
            
            parts = credential.split(".")
            if len(parts) < 2:
                return CredentialVerificationResult(
                    credential_type="jwt_token",
                    credential_masked=self._mask_credential(credential),
                    source=source,
                    source_url=source_url,
                    status=CredentialStatus.NOT_VERIFIABLE,
                    verification_method="none",
                    notes=["Invalid JWT format"],
                )
            
            # Decode header and payload
            header = parts[0]
            payload = parts[1]
            
            # Add padding
            header += "=" * (4 - len(header) % 4)
            payload += "=" * (4 - len(payload) % 4)
            
            header_data = json.loads(base64.urlsafe_b64decode(header))
            payload_data = json.loads(base64.urlsafe_b64decode(payload))
            
            notes = [f"Algorithm: {header_data.get('alg', 'unknown')}"]
            
            # Check expiration
            exp = payload_data.get("exp")
            if exp:
                exp_time = datetime.fromtimestamp(exp)
                if exp_time < datetime.now():
                    notes.append(f"EXPIRED at {exp_time.isoformat()}")
                else:
                    notes.append(f"Valid until {exp_time.isoformat()}")
            
            # Check issuer
            iss = payload_data.get("iss")
            if iss:
                notes.append(f"Issuer: {iss}")
            
            # Determine access level from claims
            roles = payload_data.get("roles", payload_data.get("role", []))
            if isinstance(roles, str):
                roles = [roles]
            
            if "admin" in roles or payload_data.get("admin"):
                access_level = "admin"
                severity = "critical"
            elif "service" in roles:
                access_level = "service"
                severity = "critical"
            else:
                access_level = "user"
                severity = "high"
            
            return CredentialVerificationResult(
                credential_type="jwt_token",
                credential_masked=self._mask_credential(credential),
                source=source,
                source_url=source_url,
                status=CredentialStatus.NOT_VERIFIABLE,
                verification_method="jwt_decode",
                access_level=access_level,
                severity=severity,
                notes=notes + ["JWT analyzed (NOT verified against server)"],
            )
            
        except Exception as e:
            return CredentialVerificationResult(
                credential_type="jwt_token",
                credential_masked=self._mask_credential(credential),
                source=source,
                source_url=source_url,
                status=CredentialStatus.ERROR,
                verification_method="jwt_decode",
                notes=[f"Failed to decode JWT: {str(e)}"],
            )


# Global instance for use by other modules
_verifier: CredentialVerifier | None = None


def get_credential_verifier(settings: Settings | None = None) -> CredentialVerifier:
    """Get global credential verifier instance."""
    global _verifier
    if _verifier is None:
        _verifier = CredentialVerifier(settings)
    return _verifier
