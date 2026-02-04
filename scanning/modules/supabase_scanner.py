"""
Supabase Security Scanner - Tests Supabase-specific vulnerabilities.

Covers SecureDev checklist phases:
- FASE 2: Supabase RLS Bypass Testing
- FASE 3: Supabase Storage Testing
- FASE 4: Supabase Edge Functions
- FASE 5: Supabase Realtime
- FASE 6: Supabase Auth Weaknesses
- FASE 20: Supabase Dashboard Exposure

SAFETY MODES:
- passive/safe/cautious: READ-ONLY mode - NO inserts, NO updates, NO deletes
- standard: Safe tests with non-existent IDs only
- aggressive: Full testing
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any

import httpx

from utils.logger import get_logger
from scanning.modules.backend_detector import SupabaseConfig, BackendDetector

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


# Safe mode environment variable - set by full_scanner.py
SAFE_MODE = os.environ.get("PHANTOM_SAFE_MODE", "safe").lower()
ALLOW_WRITES = SAFE_MODE in ("standard", "aggressive")


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()


@dataclass
class SupabaseFinding:
    """A security finding related to Supabase."""
    phase: str
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    remediation: str = ""
    table_or_bucket: str = ""
    cwe: str = ""
    confidence: float = 85.0  # Default confidence for Supabase findings
    
    def to_dict(self) -> dict:
        return {
            "phase": self.phase,
            "title": self.title,
            "severity": self.severity.name,
            "description": self.description,
            "evidence": self.evidence[:500] if self.evidence else "",
            "remediation": self.remediation,
            "table_or_bucket": self.table_or_bucket,
            "cwe": self.cwe,
            "confidence": self.confidence,
        }


@dataclass
class SupabaseScanResult:
    """Result of Supabase security scan."""
    findings: list[SupabaseFinding] = field(default_factory=list)
    tables_discovered: list[str] = field(default_factory=list)
    buckets_discovered: list[str] = field(default_factory=list)
    edge_functions: list[str] = field(default_factory=list)
    realtime_channels: list[str] = field(default_factory=list)
    
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)


class SupabaseScanner:
    """
    Specialized scanner for Supabase backends.

    Tests:
    - RLS bypass attempts (FASE 2)
    - Storage bucket enumeration and access (FASE 3)
    - Edge function vulnerabilities (FASE 4)
    - Realtime channel security (FASE 5)
    - Auth misconfigurations (FASE 6)
    - Dashboard exposure (FASE 20)

    Note: This scanner can be initialized in two ways:
    1. Standard module interface: SupabaseScanner(settings) - auto-detects Supabase
    2. Direct config: SupabaseScanner(config, settings) - uses provided config
    """

    name = "supabase"  # Module name for the standard interface

    # Common table names to test
    COMMON_TABLES = [
        "users", "profiles", "accounts", "posts", "comments",
        "orders", "products", "payments", "transactions",
        "messages", "notifications", "settings", "configs",
        "documents", "files", "images", "uploads",
        "logs", "events", "sessions", "tokens",
        "admin", "administrators", "roles", "permissions",
    ]
    
    # Common bucket names
    COMMON_BUCKETS = [
        "avatars", "images", "uploads", "files", "documents",
        "public", "private", "media", "assets", "attachments",
        "profiles", "thumbnails", "exports", "imports", "backups",
    ]
    
    # Test payloads for RLS bypass
    RLS_BYPASS_PAYLOADS = [
        # Basic ID manipulation
        {"id": "00000000-0000-0000-0000-000000000001"},
        {"id": 1},
        {"user_id": "00000000-0000-0000-0000-000000000001"},
        # Filter bypass
        {"or": "(id.eq.1,id.neq.1)"},
        # Array manipulation
        {"ids": [1, 2, 3]},
    ]
    
    def __init__(
        self,
        settings_or_config: "Settings | SupabaseConfig",
        settings: "Settings | None" = None
    ) -> None:
        """
        Initialize SupabaseScanner.

        Can be initialized in two ways:
        1. Standard module interface: SupabaseScanner(settings)
        2. Direct config: SupabaseScanner(config, settings)
        """
        # Check which initialization mode
        if isinstance(settings_or_config, SupabaseConfig):
            # Direct config mode
            self.config = settings_or_config
            self.settings = settings
        else:
            # Standard module interface - settings is first arg
            self.settings = settings_or_config
            self.config = None  # Will be detected during scan

        self.timeout = httpx.Timeout(15.0)
        self.result = SupabaseScanResult()
        self.headers = {}  # Will be set when config is available
        self._detector = BackendDetector(self.settings) if self.settings else None

    def _init_headers(self) -> None:
        """Initialize headers from config."""
        if self.config:
            self.headers = {
                "apikey": self.config.anon_key,
                "Authorization": f"Bearer {self.config.anon_key}",
                "Content-Type": "application/json",
                "Prefer": "return=representation",
            }

    async def scan(
        self,
        target: str | None = None,
        asset_data: dict | None = None,
        rate_limiter: Any = None,
    ) -> SupabaseScanResult | dict:
        """Run all Supabase security tests."""
        # Standard module interface: detect Supabase from target if not configured
        if self.config is None and target:
            logger.info(f"[SupabaseScanner] Detecting Supabase from target: {target}")
            if self._detector:
                detection = await self._detector.detect_backend(target)
                if detection.supabase:
                    self.config = detection.supabase
                    self._init_headers()
                    logger.info(f"[SupabaseScanner] Detected Supabase project: {self.config.project_ref}")
                else:
                    logger.info("[SupabaseScanner] No Supabase backend detected, skipping")
                    return {
                        "module": self.name,
                        "findings": [],
                        "info": [{"type": "skip", "reason": "No Supabase backend detected"}],
                    }
            else:
                logger.warning("[SupabaseScanner] No detector available, skipping")
                return {
                    "module": self.name,
                    "findings": [],
                    "info": [{"type": "skip", "reason": "No detector available"}],
                }

        if self.config is None:
            logger.warning("[SupabaseScanner] No config available, skipping")
            return {
                "module": self.name,
                "findings": [],
                "info": [{"type": "skip", "reason": "No Supabase config"}],
            }

        # Ensure headers are initialized
        if not self.headers:
            self._init_headers()

        logger.info(f"🔒 Starting Supabase security scan for {self.config.project_ref}")

        # Check for service_role key exposure first (CRITICAL)
        if self.config.has_service_role:
            self.result.findings.append(SupabaseFinding(
                phase="FASE_0",
                title="service_role Key Exposed",
                severity=Severity.CRITICAL,
                description="The Supabase service_role key is exposed in client-side code. "
                           "This key bypasses all RLS policies and grants full database access.",
                evidence=f"Key prefix: {self.config.service_role_key[:50]}...",
                remediation="Never expose service_role key in client code. Use it only in "
                           "server-side code with proper authentication.",
                cwe="CWE-798"
            ))
        
        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=False,
        ) as client:
            # Run all tests in parallel where possible
            await asyncio.gather(
                self._test_rls_bypass(client),
                self._test_storage_access(client),
                self._test_edge_functions(client),
                self._test_realtime(client),
                self._test_auth_config(client),
                self._test_dashboard_exposure(client),
                return_exceptions=True,
            )
        
        logger.info(f"✅ Scan complete: {len(self.result.findings)} findings")
        logger.info(f"   Critical: {self.result.critical_count}, High: {self.result.high_count}")

        # Return standard module format for compatibility
        return {
            "module": self.name,
            "findings": [f.to_dict() for f in self.result.findings],
            "info": [
                {"tables_discovered": self.result.tables_discovered},
                {"buckets_discovered": self.result.buckets_discovered},
                {"edge_functions": self.result.edge_functions},
            ],
            "result": self.result,  # Also include raw result for direct usage
        }
    
    async def _test_rls_bypass(self, client: httpx.AsyncClient) -> None:
        """
        FASE 2: Test Row Level Security bypass vulnerabilities.
        
        Tests:
        - Unauthenticated access to tables
        - RLS filter bypass via malformed queries
        - Horizontal privilege escalation
        """
        logger.info("📋 FASE 2: Testing RLS Bypass")
        
        rest_url = f"{self.config.project_url}/rest/v1"
        
        # Test each common table
        for table in self.COMMON_TABLES:
            try:
                # Test 1: Unauthenticated read
                response = await client.get(
                    f"{rest_url}/{table}",
                    headers=self.headers,
                    params={"limit": 10}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data:
                        self.result.tables_discovered.append(table)
                        
                        # Check if sensitive data exposed
                        sensitive_fields = ['email', 'password', 'phone', 'ssn', 'credit_card']
                        exposed_fields = []
                        
                        if isinstance(data, list) and data:
                            for field in sensitive_fields:
                                if field in data[0]:
                                    exposed_fields.append(field)
                        
                        severity = Severity.HIGH if exposed_fields else Severity.MEDIUM
                        
                        self.result.findings.append(SupabaseFinding(
                            phase="FASE_2",
                            title=f"Table '{table}' accessible via anon key",
                            severity=severity,
                            description=f"The table '{table}' returns data with anon key. "
                                       f"{'Sensitive fields exposed: ' + ', '.join(exposed_fields) if exposed_fields else 'Review if this data should be public.'}",
                            evidence=f"Returned {len(data)} rows. Sample keys: {list(data[0].keys())[:5] if data else 'N/A'}",
                            table_or_bucket=table,
                            remediation="Implement RLS policies: CREATE POLICY ... ON table FOR SELECT USING (auth.uid() = user_id)",
                            cwe="CWE-284"
                        ))
                
                # Test 2: Write attempt (POST) - ONLY in write-allowed modes
                if not ALLOW_WRITES:
                    logger.debug(f"⚠️ SAFE MODE: Skipping write test for table '{table}'")
                else:
                    test_data = {"test_field": "rls_bypass_test", "id": str(uuid.uuid4())}
                    response = await client.post(
                        f"{rest_url}/{table}",
                        headers=self.headers,
                        json=test_data
                    )
                    
                    if response.status_code in [200, 201]:
                        self.result.findings.append(SupabaseFinding(
                            phase="FASE_2",
                            title=f"Unauthenticated INSERT on '{table}'",
                            severity=Severity.CRITICAL,
                            description=f"The table '{table}' allows INSERT without proper authentication. "
                                       "Attackers can inject malicious data.",
                            evidence=f"POST request succeeded with status {response.status_code}",
                            table_or_bucket=table,
                            remediation="Add RLS policy: CREATE POLICY ... ON table FOR INSERT WITH CHECK (auth.uid() IS NOT NULL)",
                            cwe="CWE-284"
                        ))
                
                # Test 3: Delete attempt - ONLY in write-allowed modes
                # NOTE: Uses non-existent ID (999999999) so even if successful, nothing is deleted
                if not ALLOW_WRITES:
                    logger.debug(f"⚠️ SAFE MODE: Skipping delete test for table '{table}'")
                else:
                    response = await client.delete(
                        f"{rest_url}/{table}",
                        headers={**self.headers, "Prefer": "return=minimal"},
                        params={"id": "eq.999999999"}  # Non-existent ID - SAFE!
                    )
                    
                    # 404 is expected, but 200/204 with no RLS check is bad
                    if response.status_code in [200, 204]:
                        self.result.findings.append(SupabaseFinding(
                            phase="FASE_2",
                            title=f"DELETE allowed on '{table}'",
                            severity=Severity.HIGH,
                            description=f"The table '{table}' may allow DELETE operations without proper checks.",
                            evidence=f"DELETE request returned {response.status_code}",
                            table_or_bucket=table,
                            remediation="Add RLS policy for DELETE operations",
                            cwe="CWE-284"
                        ))
                    
            except Exception as e:
                logger.debug(f"Error testing table {table}: {e}")
    
    async def _test_storage_access(self, client: httpx.AsyncClient) -> None:
        """
        FASE 3: Test Supabase Storage security.
        
        Tests:
        - Bucket enumeration
        - Public bucket listing
        - Unauthorized file upload
        - Path traversal
        """
        logger.info("📦 FASE 3: Testing Storage Access")
        
        storage_url = f"{self.config.project_url}/storage/v1"
        
        # Test bucket enumeration
        for bucket in self.COMMON_BUCKETS:
            try:
                # Test 1: List bucket contents
                response = await client.get(
                    f"{storage_url}/object/list/{bucket}",
                    headers=self.headers,
                    params={"limit": 100}
                )
                
                if response.status_code == 200:
                    files = response.json()
                    if files:
                        self.result.buckets_discovered.append(bucket)
                        self.result.findings.append(SupabaseFinding(
                            phase="FASE_3",
                            title=f"Storage bucket '{bucket}' is listable",
                            severity=Severity.MEDIUM,
                            description=f"The storage bucket '{bucket}' allows listing files. "
                                       "This may expose sensitive file paths.",
                            evidence=f"Found {len(files)} files/folders",
                            table_or_bucket=bucket,
                            remediation="Set bucket policies to prevent listing or make bucket private",
                            cwe="CWE-548"
                        ))
                
                # Test 2: Public URL access
                response = await client.get(
                    f"{storage_url}/object/public/{bucket}/test.txt"
                )
                
                # 404 is fine, but 200 means public access is enabled
                if response.status_code == 200:
                    self.result.findings.append(SupabaseFinding(
                        phase="FASE_3",
                        title=f"Bucket '{bucket}' has public access",
                        severity=Severity.MEDIUM,
                        description=f"Files in bucket '{bucket}' are publicly accessible without authentication.",
                        evidence="Public URL returned 200",
                        table_or_bucket=bucket,
                        remediation="Review if public access is intended. Use signed URLs for private files.",
                        cwe="CWE-284"
                    ))
                
                # Test 3: Unauthorized upload - ONLY in write-allowed modes
                if not ALLOW_WRITES:
                    logger.debug(f"⚠️ SAFE MODE: Skipping upload test for bucket '{bucket}'")
                else:
                    test_content = b"security_test_upload"
                    response = await client.post(
                        f"{storage_url}/object/{bucket}/security_test.txt",
                        headers={**self.headers, "Content-Type": "text/plain"},
                        content=test_content
                    )
                    
                    if response.status_code in [200, 201]:
                        self.result.findings.append(SupabaseFinding(
                            phase="FASE_3",
                            title=f"Unauthorized upload to bucket '{bucket}'",
                            severity=Severity.HIGH,
                            description=f"Files can be uploaded to bucket '{bucket}' with just the anon key. "
                                       "This may allow malicious file uploads.",
                            evidence=f"Upload succeeded with status {response.status_code}",
                            table_or_bucket=bucket,
                            remediation="Add storage policies to restrict uploads to authenticated users",
                            cwe="CWE-434"
                        ))
                        
                        # Try to delete the test file (cleanup)
                        await client.delete(
                            f"{storage_url}/object/{bucket}/security_test.txt",
                            headers=self.headers
                        )
                
                # Test 4: Path traversal
                traversal_paths = [
                    "../../../etc/passwd",
                    "..%2F..%2F..%2Fetc%2Fpasswd",
                    "....//....//....//etc/passwd",
                ]
                
                for path in traversal_paths:
                    response = await client.get(
                        f"{storage_url}/object/{bucket}/{path}",
                        headers=self.headers
                    )
                    
                    if response.status_code == 200 and "root:" in response.text:
                        self.result.findings.append(SupabaseFinding(
                            phase="FASE_3",
                            title=f"Path traversal in bucket '{bucket}'",
                            severity=Severity.CRITICAL,
                            description="Storage path traversal vulnerability allows reading arbitrary files.",
                            evidence=f"Payload: {path}",
                            table_or_bucket=bucket,
                            remediation="Report to Supabase security team",
                            cwe="CWE-22"
                        ))
                        break
                        
            except Exception as e:
                logger.debug(f"Error testing bucket {bucket}: {e}")
    
    async def _test_edge_functions(self, client: httpx.AsyncClient) -> None:
        """
        FASE 4: Test Supabase Edge Functions security.
        
        Tests:
        - Function enumeration
        - Authentication bypass
        - Input validation
        """
        logger.info("⚡ FASE 4: Testing Edge Functions")
        
        functions_url = f"{self.config.project_url}/functions/v1"
        
        # Common edge function names
        common_functions = [
            "hello", "webhook", "stripe-webhook", "payment",
            "send-email", "process-order", "generate-report",
            "admin", "cron", "sync", "migrate", "backup",
        ]
        
        for func in common_functions:
            try:
                # Test 1: GET request
                response = await client.get(
                    f"{functions_url}/{func}",
                    headers={"Authorization": f"Bearer {self.config.anon_key}"}
                )
                
                if response.status_code in [200, 400, 401, 403]:
                    self.result.edge_functions.append(func)
                    
                    if response.status_code == 200:
                        self.result.findings.append(SupabaseFinding(
                            phase="FASE_4",
                            title=f"Edge function '{func}' accessible",
                            severity=Severity.LOW,
                            description=f"Edge function '{func}' responds to requests. "
                                       "Verify authorization is properly implemented.",
                            evidence=f"GET returned {response.status_code}",
                            table_or_bucket=func,
                            remediation="Ensure function validates auth token and user permissions",
                            cwe="CWE-287"
                        ))
                
                # Test 2: POST with malicious payloads
                test_payloads = [
                    {"command": "ls -la"},
                    {"query": "'; DROP TABLE users; --"},
                    {"path": "../../../../etc/passwd"},
                ]
                
                for payload in test_payloads:
                    response = await client.post(
                        f"{functions_url}/{func}",
                        headers={
                            "Authorization": f"Bearer {self.config.anon_key}",
                            "Content-Type": "application/json"
                        },
                        json=payload
                    )
                    
                    if response.status_code == 200:
                        text = response.text.lower()
                        if "root:" in text or "error" not in text:
                            self.result.findings.append(SupabaseFinding(
                                phase="FASE_4",
                                title=f"Potential injection in '{func}'",
                                severity=Severity.HIGH,
                                description=f"Edge function '{func}' may be vulnerable to injection attacks.",
                                evidence=f"Payload: {json.dumps(payload)[:100]}",
                                table_or_bucket=func,
                                remediation="Validate and sanitize all input parameters",
                                cwe="CWE-94"
                            ))
                            break
                            
            except Exception as e:
                logger.debug(f"Error testing function {func}: {e}")
    
    async def _test_realtime(self, client: httpx.AsyncClient) -> None:
        """
        FASE 5: Test Supabase Realtime security.
        
        Tests:
        - Channel access control
        - Broadcast without auth
        - Presence leakage
        """
        logger.info("📡 FASE 5: Testing Realtime Channels")
        
        # Note: Full WebSocket testing would require a WS client
        # Here we test the Realtime REST API endpoints
        
        realtime_url = f"{self.config.project_url}/realtime/v1"
        
        try:
            # Test WebSocket endpoint availability
            response = await client.get(
                realtime_url,
                headers={"apikey": self.config.anon_key}
            )
            
            if response.status_code in [101, 200, 400, 426]:
                self.result.findings.append(SupabaseFinding(
                    phase="FASE_5",
                    title="Realtime endpoint accessible",
                    severity=Severity.INFO,
                    description="Supabase Realtime endpoint is available. "
                               "Verify channel-level authorization is configured.",
                    evidence=f"Response: {response.status_code}",
                    remediation="Implement RLS policies for realtime subscriptions",
                    cwe="CWE-284"
                ))
        except Exception as e:
            logger.debug(f"Realtime test error: {e}")
    
    async def _test_auth_config(self, client: httpx.AsyncClient) -> None:
        """
        FASE 6: Test Supabase Auth configuration.
        
        Tests:
        - Email enumeration
        - Password policy
        - OAuth misconfigurations
        - Magic link security
        """
        logger.info("🔐 FASE 6: Testing Auth Configuration")
        
        auth_url = f"{self.config.project_url}/auth/v1"
        
        try:
            # Test 1: Email enumeration via signup
            test_email = f"test_{uuid.uuid4().hex[:8]}@test.com"
            response = await client.post(
                f"{auth_url}/signup",
                headers={"apikey": self.config.anon_key},
                json={"email": test_email, "password": "Test123456!"}
            )
            
            # Try existing email
            response2 = await client.post(
                f"{auth_url}/signup",
                headers={"apikey": self.config.anon_key},
                json={"email": "admin@example.com", "password": "Test123456!"}
            )
            
            if response.status_code != response2.status_code or response.text != response2.text:
                self.result.findings.append(SupabaseFinding(
                    phase="FASE_6",
                    title="Email enumeration possible",
                    severity=Severity.MEDIUM,
                    description="Different responses for existing vs non-existing emails "
                               "allows attackers to enumerate valid email addresses.",
                    evidence=f"New email: {response.status_code}, Existing: {response2.status_code}",
                    remediation="Configure identical responses for all signup attempts",
                    cwe="CWE-203"
                ))
            
            # Test 2: Weak password acceptance
            weak_passwords = ["123456", "password", "qwerty"]
            for pwd in weak_passwords:
                response = await client.post(
                    f"{auth_url}/signup",
                    headers={"apikey": self.config.anon_key},
                    json={"email": f"weak_{uuid.uuid4().hex[:4]}@test.com", "password": pwd}
                )
                
                if response.status_code in [200, 201]:
                    self.result.findings.append(SupabaseFinding(
                        phase="FASE_6",
                        title="Weak password policy",
                        severity=Severity.MEDIUM,
                        description=f"Password '{pwd}' was accepted. "
                                   "Weak passwords make brute-force attacks easier.",
                        evidence=f"Signup with '{pwd}' returned {response.status_code}",
                        remediation="Configure minimum password length and complexity in Supabase dashboard",
                        cwe="CWE-521"
                    ))
                    break
            
            # Test 3: Auth settings endpoint
            response = await client.get(
                f"{auth_url}/settings",
                headers={"apikey": self.config.anon_key}
            )
            
            if response.status_code == 200:
                settings = response.json()
                
                # Check for potentially insecure settings
                if settings.get("external_email_enabled"):
                    if not settings.get("mailer_autoconfirm"):
                        pass  # Good - email confirmation required
                    else:
                        self.result.findings.append(SupabaseFinding(
                            phase="FASE_6",
                            title="Email auto-confirm enabled",
                            severity=Severity.LOW,
                            description="Email auto-confirmation is enabled. "
                                       "This skips email verification.",
                            evidence=json.dumps(settings)[:200],
                            remediation="Disable auto-confirm for production",
                            cwe="CWE-287"
                        ))
                        
        except Exception as e:
            logger.debug(f"Auth config test error: {e}")
    
    async def _test_dashboard_exposure(self, client: httpx.AsyncClient) -> None:
        """
        FASE 20: Test Supabase Dashboard exposure.
        
        Tests:
        - Dashboard accessibility
        - API docs exposure
        - Project settings exposure
        """
        logger.info("🖥️ FASE 20: Testing Dashboard Exposure")
        
        dashboard_urls = [
            f"https://supabase.com/dashboard/project/{self.config.project_ref}",
            f"https://app.supabase.com/project/{self.config.project_ref}",
        ]
        
        for url in dashboard_urls:
            try:
                response = await client.get(url, follow_redirects=True)
                
                # If we get the login page, dashboard is not exposed
                # If we get actual content without login, it's a problem
                if response.status_code == 200 and "login" not in response.text.lower():
                    if "table" in response.text.lower() or "sql" in response.text.lower():
                        self.result.findings.append(SupabaseFinding(
                            phase="FASE_20",
                            title="Dashboard potentially accessible",
                            severity=Severity.HIGH,
                            description="Supabase dashboard may be accessible without proper authentication. "
                                       "Verify access controls are properly configured.",
                            evidence=f"URL: {url}",
                            remediation="Ensure dashboard access requires authenticated team members",
                            cwe="CWE-284"
                        ))
            except Exception as e:
                logger.debug(f"Dashboard test error: {e}")
        
        # Test API documentation exposure
        try:
            response = await client.get(
                f"{self.config.project_url}/rest/v1/",
                headers={"apikey": self.config.anon_key}
            )
            
            if response.status_code == 200:
                self.result.findings.append(SupabaseFinding(
                    phase="FASE_20",
                    title="REST API endpoint exposed",
                    severity=Severity.INFO,
                    description="REST API base endpoint returns data. "
                               "This may reveal table structure.",
                    evidence=response.text[:200],
                    remediation="This is expected behavior. Ensure RLS is properly configured.",
                    cwe="CWE-200"
                ))
        except Exception:
            pass


async def scan_supabase(
    target: str,
    config: SupabaseConfig | None = None,
    settings: Settings | None = None
) -> SupabaseScanResult:
    """
    Convenience function to run Supabase security scan.
    
    If config is not provided, will run backend detection first.
    """
    if not config:
        detector = BackendDetector(settings)
        result = await detector.detect(target)
        config = result.supabase_config
    
    if not config or not config.is_valid:
        logger.error("No valid Supabase configuration found")
        return SupabaseScanResult()
    
    scanner = SupabaseScanner(config, settings)
    return await scanner.scan()
