"""
Third-Party Keys Scanner - Discovers and validates third-party service keys.

Covers SecureDev checklist phase:
- FASE 10: Third-Party Key Discovery (Stripe, Sentry, PostHog, etc.)

Tests for exposed:
- Payment processors (Stripe, PayPal)
- Analytics (Google Analytics, PostHog, Mixpanel)
- Error tracking (Sentry, Bugsnag)
- CDN/Cloud (AWS, GCP, Azure)
- Communication (Twilio, SendGrid)
- Social (Facebook, Google OAuth)
"""

from __future__ import annotations

import asyncio
import json
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


class KeySeverity(Enum):
    """Severity based on key type."""
    CRITICAL = auto()  # Secret keys that should never be public
    HIGH = auto()       # Keys with write/admin access
    MEDIUM = auto()     # Publishable keys that might leak info
    LOW = auto()        # Public/safe keys
    INFO = auto()       # Just informational


@dataclass
class DiscoveredKey:
    """A discovered third-party key."""
    service: str
    key_type: str
    key_value: str
    severity: KeySeverity
    is_valid: bool | None = None
    description: str = ""
    remediation: str = ""
    
    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "key_type": self.key_type,
            "key_value": f"{self.key_value[:20]}...{self.key_value[-4:]}" if len(self.key_value) > 30 else "REDACTED",
            "severity": self.severity.name,
            "is_valid": self.is_valid,
            "description": self.description,
            "remediation": self.remediation,
        }


@dataclass 
class ThirdPartyScanResult:
    """Result of third-party key discovery."""
    keys_discovered: list[DiscoveredKey] = field(default_factory=list)
    validated_keys: list[DiscoveredKey] = field(default_factory=list)
    
    @property
    def critical_count(self) -> int:
        return sum(1 for k in self.keys_discovered if k.severity == KeySeverity.CRITICAL)
    
    @property
    def has_secret_exposure(self) -> bool:
        return any(
            k.severity == KeySeverity.CRITICAL and k.is_valid 
            for k in self.validated_keys
        )


class ThirdPartyScanner:
    """
    Scanner for third-party service keys.
    
    Discovers and optionally validates keys for:
    - Payment: Stripe, PayPal, Square
    - Analytics: Google Analytics, PostHog, Mixpanel, Amplitude
    - Error Tracking: Sentry, Bugsnag, Rollbar
    - Cloud: AWS, GCP, Azure, DigitalOcean
    - Communication: Twilio, SendGrid, Mailgun
    - Social: Facebook, Google, GitHub OAuth
    - CDN: Cloudflare, Fastly
    - Database: MongoDB Atlas connection strings
    """
    
    # Key patterns with severity
    KEY_PATTERNS = {
        # Payment - CRITICAL if secret
        "stripe_publishable": {
            "pattern": re.compile(r'pk_(live|test)_[A-Za-z0-9]{24,}'),
            "severity": KeySeverity.MEDIUM,
            "description": "Stripe publishable key (safe to expose)",
        },
        "stripe_secret": {
            "pattern": re.compile(r'sk_(live|test)_[A-Za-z0-9]{24,}'),
            "severity": KeySeverity.CRITICAL,
            "description": "Stripe SECRET key - can make charges!",
            "remediation": "Rotate immediately in Stripe dashboard",
        },
        "stripe_restricted": {
            "pattern": re.compile(r'rk_(live|test)_[A-Za-z0-9]{24,}'),
            "severity": KeySeverity.HIGH,
            "description": "Stripe restricted key",
        },
        "paypal_client": {
            "pattern": re.compile(r'AY[A-Za-z0-9]{60,}'),
            "severity": KeySeverity.MEDIUM,
            "description": "PayPal client ID",
        },
        "paypal_secret": {
            "pattern": re.compile(r'EL[A-Za-z0-9]{60,}'),
            "severity": KeySeverity.CRITICAL,
            "description": "PayPal secret key",
        },
        "square_access": {
            "pattern": re.compile(r'sq0[a-z]{3}-[A-Za-z0-9_-]{22,}'),
            "severity": KeySeverity.HIGH,
            "description": "Square access token",
        },
        
        # Error Tracking
        "sentry_dsn": {
            "pattern": re.compile(r'https://[a-f0-9]+@o\d+\.ingest\.sentry\.io/\d+'),
            "severity": KeySeverity.MEDIUM,
            "description": "Sentry DSN - can send error reports",
        },
        "sentry_auth": {
            "pattern": re.compile(r'[a-f0-9]{64}', flags=re.IGNORECASE),
            "severity": KeySeverity.HIGH,
            "context": "sentry",
            "description": "Sentry auth token",
        },
        "bugsnag_key": {
            "pattern": re.compile(r'[a-f0-9]{32}', flags=re.IGNORECASE),
            "severity": KeySeverity.MEDIUM,
            "context": "bugsnag",
            "description": "Bugsnag API key",
        },
        
        # Analytics
        "google_analytics": {
            "pattern": re.compile(r'UA-\d+-\d+'),
            "severity": KeySeverity.LOW,
            "description": "Google Analytics UA ID",
        },
        "google_analytics_4": {
            "pattern": re.compile(r'G-[A-Z0-9]{10,}'),
            "severity": KeySeverity.LOW,
            "description": "Google Analytics 4 ID",
        },
        "posthog_key": {
            "pattern": re.compile(r'phc_[A-Za-z0-9]{32,}'),
            "severity": KeySeverity.MEDIUM,
            "description": "PostHog project key",
        },
        "mixpanel_token": {
            "pattern": re.compile(r'[a-f0-9]{32}', flags=re.IGNORECASE),
            "severity": KeySeverity.MEDIUM,
            "context": "mixpanel",
            "description": "Mixpanel token",
        },
        "amplitude_key": {
            "pattern": re.compile(r'[a-f0-9]{32}', flags=re.IGNORECASE),
            "severity": KeySeverity.MEDIUM,
            "context": "amplitude",
            "description": "Amplitude API key",
        },
        
        # Cloud Providers - CRITICAL
        "aws_access_key": {
            "pattern": re.compile(r'AKIA[A-Z0-9]{16}'),
            "severity": KeySeverity.CRITICAL,
            "description": "AWS Access Key ID",
            "remediation": "Rotate in AWS IAM immediately",
        },
        "aws_secret_key": {
            "pattern": re.compile(r'[A-Za-z0-9/+=]{40}'),
            "severity": KeySeverity.CRITICAL,
            "context": "aws",
            "description": "AWS Secret Access Key",
        },
        "gcp_api_key": {
            "pattern": re.compile(r'AIza[A-Za-z0-9_-]{35}'),
            "severity": KeySeverity.HIGH,
            "description": "Google Cloud API key",
        },
        "azure_connection": {
            "pattern": re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+'),
            "severity": KeySeverity.CRITICAL,
            "description": "Azure Storage connection string",
        },
        "digitalocean_token": {
            "pattern": re.compile(r'dop_v1_[a-f0-9]{64}'),
            "severity": KeySeverity.CRITICAL,
            "description": "DigitalOcean personal access token",
        },
        
        # Communication
        "twilio_sid": {
            "pattern": re.compile(r'AC[a-f0-9]{32}'),
            "severity": KeySeverity.HIGH,
            "description": "Twilio Account SID",
        },
        "twilio_auth": {
            "pattern": re.compile(r'[a-f0-9]{32}', flags=re.IGNORECASE),
            "severity": KeySeverity.CRITICAL,
            "context": "twilio",
            "description": "Twilio Auth Token",
        },
        "sendgrid_key": {
            "pattern": re.compile(r'SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,}'),
            "severity": KeySeverity.CRITICAL,
            "description": "SendGrid API key",
        },
        "mailgun_key": {
            "pattern": re.compile(r'key-[a-f0-9]{32}'),
            "severity": KeySeverity.CRITICAL,
            "description": "Mailgun API key",
        },
        
        # OAuth / Social
        "facebook_app_secret": {
            "pattern": re.compile(r'[a-f0-9]{32}', flags=re.IGNORECASE),
            "severity": KeySeverity.CRITICAL,
            "context": "facebook",
            "description": "Facebook App Secret",
        },
        "github_token": {
            "pattern": re.compile(r'gh[pousr]_[A-Za-z0-9]{36,}'),
            "severity": KeySeverity.CRITICAL,
            "description": "GitHub personal access token",
        },
        "github_oauth_secret": {
            "pattern": re.compile(r'[a-f0-9]{40}', flags=re.IGNORECASE),
            "severity": KeySeverity.CRITICAL,
            "context": "github",
            "description": "GitHub OAuth client secret",
        },
        "slack_webhook": {
            "pattern": re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
            "severity": KeySeverity.MEDIUM,
            "description": "Slack webhook URL",
        },
        "slack_token": {
            "pattern": re.compile(r'xox[baprs]-[A-Za-z0-9-]+'),
            "severity": KeySeverity.CRITICAL,
            "description": "Slack API token",
        },
        "discord_webhook": {
            "pattern": re.compile(r'https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+'),
            "severity": KeySeverity.MEDIUM,
            "description": "Discord webhook URL",
        },
        "discord_bot_token": {
            "pattern": re.compile(r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}'),
            "severity": KeySeverity.CRITICAL,
            "description": "Discord bot token",
        },
        
        # Database
        "mongodb_uri": {
            "pattern": re.compile(r'mongodb\+srv://[^:]+:[^@]+@[^/]+'),
            "severity": KeySeverity.CRITICAL,
            "description": "MongoDB connection string with credentials",
        },
        "postgres_uri": {
            "pattern": re.compile(r'postgres(ql)?://[^:]+:[^@]+@[^/]+'),
            "severity": KeySeverity.CRITICAL,
            "description": "PostgreSQL connection string with credentials",
        },
        "redis_url": {
            "pattern": re.compile(r'redis://[^:]+:[^@]+@[^/]+'),
            "severity": KeySeverity.CRITICAL,
            "description": "Redis URL with credentials",
        },
        
        # CDN / Security
        "cloudflare_api": {
            "pattern": re.compile(r'[a-f0-9]{37}', flags=re.IGNORECASE),
            "severity": KeySeverity.HIGH,
            "context": "cloudflare",
            "description": "Cloudflare API key",
        },
        
        # JWT / Generic
        "jwt_secret": {
            "pattern": re.compile(r'["\']?(?:jwt|secret|token)[_]?(?:secret|key)?["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', re.IGNORECASE),
            "severity": KeySeverity.CRITICAL,
            "description": "JWT secret key",
        },
        "private_key": {
            "pattern": re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
            "severity": KeySeverity.CRITICAL,
            "description": "Private key exposed",
        },
    }
    
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings
        self.timeout = httpx.Timeout(10.0)
        self.result = ThirdPartyScanResult()
    
    async def scan(
        self, 
        content: str,
        target_url: str = "",
        validate_keys: bool = True
    ) -> ThirdPartyScanResult:
        """
        Scan content for third-party keys.
        
        Args:
            content: HTML/JS content to scan
            target_url: Target URL for context
            validate_keys: Whether to validate discovered keys
        """
        logger.info("🔑 FASE 10: Third-Party Key Discovery")
        
        # Scan for all key patterns
        for key_name, config in self.KEY_PATTERNS.items():
            pattern = config["pattern"]
            context = config.get("context")
            
            # If key needs context, check if context exists
            if context and context.lower() not in content.lower():
                continue
            
            matches = pattern.findall(content)
            
            for match in set(matches):
                # For tuple matches (from groups), get the value
                if isinstance(match, tuple):
                    match = match[0] if match else ""
                
                if not match or len(match) < 10:
                    continue
                
                discovered = DiscoveredKey(
                    service=key_name.split("_")[0].title(),
                    key_type=key_name,
                    key_value=match,
                    severity=config["severity"],
                    description=config.get("description", ""),
                    remediation=config.get("remediation", "Rotate this key immediately"),
                )
                
                self.result.keys_discovered.append(discovered)
                
                log_level = "critical" if discovered.severity == KeySeverity.CRITICAL else "warning"
                getattr(logger, log_level)(
                    f"🚨 Found {discovered.key_type}: {match[:20]}..."
                )
        
        # Validate critical keys
        if validate_keys and self.result.keys_discovered:
            await self._validate_keys()
        
        logger.info(f"✅ Discovery complete: {len(self.result.keys_discovered)} keys found")
        logger.info(f"   Critical: {self.result.critical_count}")
        
        return self.result
    
    async def _validate_keys(self) -> None:
        """Validate discovered keys by testing them."""
        logger.info("🔍 Validating discovered keys...")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            tasks = []
            
            for key in self.result.keys_discovered:
                if key.severity in [KeySeverity.CRITICAL, KeySeverity.HIGH]:
                    task = self._validate_key(client, key)
                    tasks.append(task)
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _validate_key(self, client: httpx.AsyncClient, key: DiscoveredKey) -> None:
        """Validate a single key."""
        try:
            if key.key_type == "stripe_secret":
                is_valid = await self._validate_stripe(client, key.key_value)
            elif key.key_type == "sendgrid_key":
                is_valid = await self._validate_sendgrid(client, key.key_value)
            elif key.key_type == "twilio_sid":
                # Need auth token too, skip for now
                is_valid = None
            elif key.key_type == "github_token":
                is_valid = await self._validate_github(client, key.key_value)
            elif key.key_type == "slack_token":
                is_valid = await self._validate_slack(client, key.key_value)
            elif key.key_type == "aws_access_key":
                # Need secret key too, mark as needs investigation
                is_valid = None
            else:
                is_valid = None
            
            key.is_valid = is_valid
            
            if is_valid:
                self.result.validated_keys.append(key)
                logger.critical(f"⚠️ CONFIRMED VALID: {key.key_type}")
                
        except Exception as e:
            logger.debug(f"Validation error for {key.key_type}: {e}")
            key.is_valid = None
    
    async def _validate_stripe(self, client: httpx.AsyncClient, key: str) -> bool:
        """Validate Stripe secret key."""
        try:
            response = await client.get(
                "https://api.stripe.com/v1/balance",
                auth=(key, "")
            )
            return response.status_code == 200
        except Exception:
            return False
    
    async def _validate_sendgrid(self, client: httpx.AsyncClient, key: str) -> bool:
        """Validate SendGrid API key."""
        try:
            response = await client.get(
                "https://api.sendgrid.com/v3/user/profile",
                headers={"Authorization": f"Bearer {key}"}
            )
            return response.status_code == 200
        except Exception:
            return False
    
    async def _validate_github(self, client: httpx.AsyncClient, token: str) -> bool:
        """Validate GitHub token."""
        try:
            response = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {token}"}
            )
            return response.status_code == 200
        except Exception:
            return False
    
    async def _validate_slack(self, client: httpx.AsyncClient, token: str) -> bool:
        """Validate Slack token."""
        try:
            response = await client.get(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {token}"}
            )
            if response.status_code == 200:
                return response.json().get("ok", False)
            return False
        except Exception:
            return False


async def scan_third_party(
    target: str,
    settings: Settings | None = None
) -> ThirdPartyScanResult:
    """
    Convenience function to scan a target for third-party keys.
    """
    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0), verify=False) as client:
        # Fetch main page
        response = await client.get(target)
        content = response.text
        
        # Fetch JS bundles
        script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
        scripts = script_pattern.findall(content)
        
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for script in scripts[:10]:
            if any(p in script for p in ['main', 'app', 'bundle', 'chunk', 'index']):
                url = script if script.startswith('http') else f"{base_url}/{script.lstrip('/')}"
                try:
                    js_response = await client.get(url)
                    content += js_response.text
                except Exception:
                    pass
    
    scanner = ThirdPartyScanner(settings)
    return await scanner.scan(content, target)
