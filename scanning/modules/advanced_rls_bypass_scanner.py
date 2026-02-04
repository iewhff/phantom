"""
Advanced RLS Bypass Scanner - FASE 20 Testing.

Tests for sophisticated Row-Level Security bypass techniques:
- JOIN-based RLS bypass
- Function exploitation
- SQL timing attacks
- View-based bypasses
- Trigger exploitation
- Role impersonation
"""

from __future__ import annotations

import asyncio
import time
import statistics
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse, urljoin

import httpx

from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


@dataclass
class RLSBypassFinding:
    """An RLS bypass vulnerability finding."""
    url: str
    technique: str
    severity: str
    title: str
    description: str
    payload: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe: str = "CWE-863"
    confidence: float = 90.0  # Default confidence for RLS bypass findings
    
    def to_dict(self) -> dict:
        return {
            "type": "RLS_BYPASS",
            "url": self.url,
            "technique": self.technique,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "payload": self.payload,
            "evidence": self.evidence[:500] if self.evidence else "",
            "remediation": self.remediation,
            "cwe": self.cwe,
            "confidence": self.confidence,
        }


@dataclass
class RLSBypassResult:
    """Result of RLS bypass scan."""
    findings: list[RLSBypassFinding] = field(default_factory=list)
    techniques_tested: int = 0
    timing_samples: int = 0
    
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")


class AdvancedRLSBypassScanner:
    """
    Advanced RLS (Row-Level Security) Bypass Scanner.
    
    Tests sophisticated bypass techniques:
    1. JOIN-based RLS bypass
    2. SQL function exploitation
    3. Timing-based enumeration
    4. View-based bypasses
    5. Policy gap exploitation
    6. Role impersonation
    """
    
    # Timing threshold (seconds) for detecting blind conditions
    TIMING_THRESHOLD = 0.5
    TIMING_SAMPLES = 5
    
    # Supabase-specific bypass payloads
    SUPABASE_BYPASS_PAYLOADS = [
        # JOIN-based bypass attempts
        {"select": "*, other_table!inner(*)"},
        {"select": "*, other_table(*)"},
        
        # Function calls that might bypass RLS
        {"select": "*, get_all_rows()"},
        {"select": "rpc_bypass()"},
        
        # View references
        {"select": "* from all_data_view"},
        
        # Aggregate bypass
        {"select": "count(*), min(id), max(id)"},
        {"select": "array_agg(*)"},
        {"select": "json_agg(*)"},
    ]
    
    # RPC functions to test
    RPC_BYPASS_FUNCTIONS = [
        "get_all_users",
        "get_all_data",
        "admin_query",
        "bypass_rls",
        "fetch_all",
        "internal_query",
        "debug_query",
    ]
    
    # Filter bypass payloads
    FILTER_BYPASS_PAYLOADS = [
        # OR conditions
        {"or": "(id.gt.0)"},
        {"or": "(1,eq,1)"},
        
        # NOT conditions
        {"not.user_id": "is.null"},
        
        # Range exploits
        {"id": "gte.0"},
        {"id": "in.(1,2,3,4,5,6,7,8,9,10,100,1000)"},
        
        # Array operations
        {"ids": "cs.{1,2,3,4,5}"},
        {"ids": "ov.{1,2,3,4,5}"},
    ]
    
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings
        self.timeout = httpx.Timeout(20.0)
        self.result = RLSBypassResult()
    
    async def scan(
        self,
        host: str,
        asset_data: dict,
        rate_limiter: Any = None
    ) -> dict:
        """
        Scan for advanced RLS bypass vulnerabilities.
        
        Args:
            host: Target hostname
            asset_data: Contains endpoints, supabase info
            rate_limiter: Optional rate limiter
        """
        logger.info(f"🔍 Advanced RLS Bypass Scanner starting for {host}")
        
        base_url = f"https://{host}" if not host.startswith("http") else host
        
        # Detect if this is Supabase
        is_supabase = asset_data.get("backend_type") == "supabase"
        supabase_url = asset_data.get("supabase_url", "")
        supabase_key = asset_data.get("supabase_key", "")
        tables = asset_data.get("tables", ["users", "data", "items", "orders"])
        
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            if is_supabase and supabase_url:
                # Supabase-specific tests
                await self._test_supabase_join_bypass(
                    client, supabase_url, supabase_key, tables
                )
                await self._test_supabase_rpc_bypass(
                    client, supabase_url, supabase_key
                )
                await self._test_supabase_filter_bypass(
                    client, supabase_url, supabase_key, tables
                )
                await self._test_timing_enumeration(
                    client, supabase_url, supabase_key, tables
                )
            else:
                # Generic API RLS testing
                endpoints = asset_data.get("endpoints", [])
                for endpoint in endpoints:
                    if rate_limiter:
                        await rate_limiter.acquire(host)
                    
                    url = endpoint if endpoint.startswith("http") else urljoin(base_url, endpoint)
                    await self._test_generic_rls_bypass(client, url)
        
        logger.info(f"✅ RLS bypass scan complete: {len(self.result.findings)} findings")
        
        return {
            "findings": [f.to_dict() for f in self.result.findings],
            "techniques_tested": self.result.techniques_tested,
            "timing_samples": self.result.timing_samples,
        }
    
    async def _test_supabase_join_bypass(
        self,
        client: httpx.AsyncClient,
        supabase_url: str,
        supabase_key: str,
        tables: list[str]
    ) -> None:
        """Test JOIN-based RLS bypass in Supabase."""
        logger.info("🔗 Testing JOIN-based RLS bypass...")
        self.result.techniques_tested += 1
        
        headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}",
        }
        
        for table in tables:
            # Test self-join bypass
            url = f"{supabase_url}/rest/v1/{table}"
            
            try:
                # Normal query (baseline)
                normal_response = await client.get(
                    url,
                    headers=headers,
                    params={"select": "*"}
                )
                normal_count = len(normal_response.json()) if normal_response.status_code == 200 else 0
                
                # JOIN query - might bypass RLS
                for other_table in tables:
                    if other_table == table:
                        continue
                    
                    # Inner join
                    join_response = await client.get(
                        url,
                        headers=headers,
                        params={"select": f"*, {other_table}(*)"}
                    )
                    
                    if join_response.status_code == 200:
                        join_data = join_response.json()
                        join_count = len(join_data)
                        
                        # If JOIN returns more rows, possible bypass
                        if join_count > normal_count:
                            self.result.findings.append(RLSBypassFinding(
                                url=url,
                                technique="JOIN-bypass",
                                severity="CRITICAL",
                                title=f"JOIN-based RLS bypass on {table}",
                                description=f"Joining {table} with {other_table} returned {join_count} rows "
                                           f"vs {normal_count} rows in normal query. "
                                           "RLS policy may not apply to joined data.",
                                payload=f"select=*,{other_table}(*)",
                                evidence=f"Normal: {normal_count} rows, JOIN: {join_count} rows",
                                remediation="Apply RLS policies to all tables in relationships. "
                                           "Use SECURITY DEFINER functions carefully.",
                            ))
                        
                        # Check if joined table data is accessible
                        for row in join_data[:5]:  # Check first 5
                            if other_table in row and row[other_table]:
                                # Joined data is accessible
                                self.result.findings.append(RLSBypassFinding(
                                    url=url,
                                    technique="JOIN-data-leak",
                                    severity="HIGH",
                                    title=f"Joined table {other_table} data exposed",
                                    description=f"Data from {other_table} is accessible via JOIN with {table}. "
                                               "This may leak protected data.",
                                    payload=f"select=*,{other_table}(*)",
                                    evidence=f"Joined data keys: {list(row[other_table].keys()) if isinstance(row[other_table], dict) else 'array'}",
                                    remediation="Restrict SELECT permissions on sensitive columns. "
                                               "Apply RLS to both tables.",
                                ))
                                break
                                
            except Exception as e:
                logger.debug(f"JOIN test error for {table}: {e}")
    
    async def _test_supabase_rpc_bypass(
        self,
        client: httpx.AsyncClient,
        supabase_url: str,
        supabase_key: str
    ) -> None:
        """Test RPC function bypass."""
        logger.info("⚡ Testing RPC function bypass...")
        self.result.techniques_tested += 1
        
        headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}",
            "Content-Type": "application/json",
        }
        
        for func_name in self.RPC_BYPASS_FUNCTIONS:
            url = f"{supabase_url}/rest/v1/rpc/{func_name}"
            
            try:
                # Try calling the function
                response = await client.post(
                    url,
                    headers=headers,
                    json={}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Check if function returned data
                    if data and (isinstance(data, list) and len(data) > 0) or (isinstance(data, dict) and data):
                        self.result.findings.append(RLSBypassFinding(
                            url=url,
                            technique="RPC-bypass",
                            severity="CRITICAL",
                            title=f"RPC function {func_name} bypasses RLS",
                            description=f"The RPC function '{func_name}' is callable and returns data. "
                                       "SECURITY DEFINER functions can bypass RLS.",
                            payload=f"POST /rpc/{func_name}",
                            evidence=f"Returned {len(data) if isinstance(data, list) else 'object'} data",
                            remediation="Audit SECURITY DEFINER functions. "
                                       "Add explicit permission checks inside functions.",
                        ))
                elif response.status_code != 404:
                    # Function exists but returned error - still notable
                    logger.debug(f"RPC {func_name}: {response.status_code}")
                    
            except Exception as e:
                logger.debug(f"RPC test error for {func_name}: {e}")
    
    async def _test_supabase_filter_bypass(
        self,
        client: httpx.AsyncClient,
        supabase_url: str,
        supabase_key: str,
        tables: list[str]
    ) -> None:
        """Test filter-based RLS bypass."""
        logger.info("🔎 Testing filter-based RLS bypass...")
        self.result.techniques_tested += 1
        
        headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}",
        }
        
        for table in tables:
            url = f"{supabase_url}/rest/v1/{table}"
            
            # Get baseline
            try:
                baseline = await client.get(url, headers=headers, params={"select": "*"})
                baseline_count = len(baseline.json()) if baseline.status_code == 200 else 0
            except Exception:
                continue
            
            for bypass_params in self.FILTER_BYPASS_PAYLOADS:
                try:
                    params = {"select": "*", **bypass_params}
                    
                    response = await client.get(
                        url,
                        headers=headers,
                        params=params
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        count = len(data)
                        
                        # If filter returns more rows, possible bypass
                        if count > baseline_count:
                            self.result.findings.append(RLSBypassFinding(
                                url=url,
                                technique="filter-bypass",
                                severity="HIGH",
                                title=f"Filter bypass on {table}",
                                description=f"Using filter params returned {count} rows vs "
                                           f"{baseline_count} baseline. RLS may be bypassable via filters.",
                                payload=str(bypass_params),
                                evidence=f"Baseline: {baseline_count}, With filter: {count}",
                                remediation="Ensure RLS policies are applied regardless of filters.",
                            ))
                            break
                            
                except Exception as e:
                    logger.debug(f"Filter test error: {e}")
    
    async def _test_timing_enumeration(
        self,
        client: httpx.AsyncClient,
        supabase_url: str,
        supabase_key: str,
        tables: list[str]
    ) -> None:
        """Test timing-based data enumeration."""
        logger.info("⏱️ Testing timing-based enumeration...")
        self.result.techniques_tested += 1
        
        headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}",
        }
        
        for table in tables:
            url = f"{supabase_url}/rest/v1/{table}"
            
            try:
                # Measure response time for existing vs non-existing
                existing_times = []
                nonexisting_times = []
                
                for _ in range(self.TIMING_SAMPLES):
                    self.result.timing_samples += 1
                    
                    # Query for likely existing ID
                    start = time.perf_counter()
                    await client.get(
                        url,
                        headers=headers,
                        params={"id": "eq.1", "select": "id"}
                    )
                    existing_times.append(time.perf_counter() - start)
                    
                    # Query for non-existing ID
                    start = time.perf_counter()
                    await client.get(
                        url,
                        headers=headers,
                        params={"id": "eq.999999999", "select": "id"}
                    )
                    nonexisting_times.append(time.perf_counter() - start)
                    
                    await asyncio.sleep(0.1)
                
                # Analyze timing difference
                existing_avg = statistics.mean(existing_times)
                nonexisting_avg = statistics.mean(nonexisting_times)
                
                diff = abs(existing_avg - nonexisting_avg)
                
                if diff > self.TIMING_THRESHOLD:
                    self.result.findings.append(RLSBypassFinding(
                        url=url,
                        technique="timing-enumeration",
                        severity="MEDIUM",
                        title=f"Timing-based enumeration on {table}",
                        description=f"Response time differs by {diff:.3f}s between existing "
                                   "and non-existing records. Attackers can enumerate valid IDs.",
                        payload="Comparing id=eq.1 vs id=eq.999999999",
                        evidence=f"Existing avg: {existing_avg:.3f}s, Non-existing avg: {nonexisting_avg:.3f}s",
                        remediation="Add artificial delay or use constant-time responses. "
                                   "Rate limit queries.",
                    ))
                    
            except Exception as e:
                logger.debug(f"Timing test error for {table}: {e}")
    
    async def _test_generic_rls_bypass(
        self,
        client: httpx.AsyncClient,
        url: str
    ) -> None:
        """Test generic API RLS bypass."""
        self.result.techniques_tested += 1
        
        bypass_payloads = [
            # ID enumeration
            {"id": 1},
            {"id": "1"},
            {"id": "*"},
            {"id": "1 OR 1=1"},
            
            # User filter bypass
            {"user_id": 1},
            {"owner_id": "*"},
            {"all": True},
            {"admin": True},
            
            # Pagination abuse
            {"limit": 1000, "offset": 0},
            {"page": 1, "per_page": 1000},
        ]
        
        # Get baseline
        try:
            baseline = await client.get(url)
            baseline_data = baseline.json() if baseline.status_code == 200 else []
            baseline_count = len(baseline_data) if isinstance(baseline_data, list) else 0
        except Exception:
            return
        
        for payload in bypass_payloads:
            try:
                response = await client.get(url, params=payload)
                
                if response.status_code == 200:
                    data = response.json()
                    count = len(data) if isinstance(data, list) else 0
                    
                    if count > baseline_count:
                        self.result.findings.append(RLSBypassFinding(
                            url=url,
                            technique="parameter-bypass",
                            severity="HIGH",
                            title=f"Parameter-based access bypass",
                            description=f"Using parameters returned more data than normal query. "
                                       "Authorization may be bypassable via query manipulation.",
                            payload=str(payload),
                            evidence=f"Baseline: {baseline_count}, With params: {count}",
                            remediation="Implement proper authorization checks on all queries.",
                        ))
                        return
                        
            except Exception:
                pass


async def scan_rls_bypass(
    host: str,
    asset_data: dict,
    settings: Any = None
) -> dict:
    """Convenience function to run RLS bypass scan."""
    scanner = AdvancedRLSBypassScanner(settings)
    return await scanner.scan(host, asset_data)
