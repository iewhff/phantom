"""
SecureDev Scan Orchestrator - Decision Tree Based Security Testing.

Implements the SecureDev Security Scan Checklist with conditional execution:
- FASE 0: Backend Detection (MANDATORY)
- Based on backend type, executes appropriate phases
- Integrates external tools (nmap, nuclei, sqlmap, etc.)
- Avoids unnecessary tests based on detected technology
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from utils.logger import get_logger
from scanning.modules.backend_detector import (
    BackendDetector,
    BackendDetectionResult,
    BackendType,
)
from scanning.modules.supabase_scanner import SupabaseScanner, SupabaseScanResult
from scanning.modules.firebase_scanner import FirebaseScanner, FirebaseScanResult
from scanning.modules.third_party_scanner import ThirdPartyScanner, ThirdPartyScanResult
from scanning.modules.csrf_scanner import CSRFScanner, CSRFScanResult
from scanning.modules.mass_assignment_scanner import MassAssignmentScanner
from scanning.modules.advanced_rls_bypass_scanner import AdvancedRLSBypassScanner, RLSBypassResult
from scanning.modules.linux_tools_wrapper import LinuxToolsWrapper, LinuxToolsResult

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class PhaseStatus(Enum):
    """Status of a scan phase."""
    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    SKIPPED = auto()
    FAILED = auto()


@dataclass
class PhaseResult:
    """Result of a single scan phase."""
    phase_id: str
    phase_name: str
    status: PhaseStatus
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    duration_seconds: float = 0.0
    skip_reason: str = ""
    details: dict = field(default_factory=dict)


@dataclass
class SecureDevScanResult:
    """Complete scan result following SecureDev checklist."""
    target: str
    backend_type: BackendType
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: datetime | None = None
    phases: list[PhaseResult] = field(default_factory=list)
    total_findings: int = 0
    total_critical: int = 0
    total_high: int = 0
    backend_config: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "backend_type": self.backend_type.name,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_minutes": (
                (self.completed_at - self.started_at).total_seconds() / 60
                if self.completed_at else 0
            ),
            "summary": {
                "total_findings": self.total_findings,
                "critical": self.total_critical,
                "high": self.total_high,
                "phases_run": len([p for p in self.phases if p.status == PhaseStatus.COMPLETED]),
                "phases_skipped": len([p for p in self.phases if p.status == PhaseStatus.SKIPPED]),
            },
            "phases": [
                {
                    "id": p.phase_id,
                    "name": p.phase_name,
                    "status": p.status.name,
                    "findings": p.findings_count,
                    "critical": p.critical_count,
                    "duration_sec": round(p.duration_seconds, 2),
                    "skip_reason": p.skip_reason,
                }
                for p in self.phases
            ],
            "backend_config": self.backend_config,
        }


class ExternalTool:
    """Wrapper for external security tools."""
    
    TOOLS = {
        "nmap": {
            "check": "nmap --version",
            "install": "sudo apt install nmap",
        },
        "nikto": {
            "check": "nikto -Version",
            "install": "sudo apt install nikto",
        },
        "sqlmap": {
            "check": "sqlmap --version",
            "install": "pip install sqlmap",
        },
        "nuclei": {
            "check": "nuclei -version",
            "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        },
        "subfinder": {
            "check": "subfinder -version",
            "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        },
        "ffuf": {
            "check": "ffuf -V",
            "install": "go install github.com/ffuf/ffuf/v2@latest",
        },
        "testssl": {
            "check": "testssl.sh --version",
            "install": "git clone https://github.com/drwetter/testssl.sh.git",
        },
    }
    
    @classmethod
    def is_available(cls, tool_name: str) -> bool:
        """Check if a tool is available."""
        return shutil.which(tool_name) is not None
    
    @classmethod
    def get_available_tools(cls) -> list[str]:
        """Get list of available tools."""
        return [name for name in cls.TOOLS if cls.is_available(name)]
    
    @classmethod
    def get_missing_tools(cls) -> dict[str, str]:
        """Get missing tools with install commands."""
        return {
            name: config["install"]
            for name, config in cls.TOOLS.items()
            if not cls.is_available(name)
        }
    
    @classmethod
    async def run_nmap(cls, target: str, ports: str = "1-1000") -> dict:
        """Run nmap scan."""
        if not cls.is_available("nmap"):
            return {"error": "nmap not installed"}
        
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmap", "-sV", "-sC", "-p", ports, "-oX", "-", target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            return {"output": stdout.decode("utf-8", errors="replace"), "error": stderr.decode("utf-8", errors="replace")}
        except asyncio.TimeoutError:
            return {"error": "nmap timeout"}
        except Exception as e:
            return {"error": str(e)}
    
    @classmethod
    async def run_nuclei(cls, target: str, tags: str = "cve,osint,tech") -> dict:
        """Run nuclei scan."""
        if not cls.is_available("nuclei"):
            return {"error": "nuclei not installed"}
        
        try:
            proc = await asyncio.create_subprocess_exec(
                "nuclei", "-u", target, "-tags", tags, "-json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
            
            findings = []
            for line in stdout.decode("utf-8", errors="replace").split("\n"):
                if line.strip():
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            
            return {"findings": findings, "count": len(findings)}
        except asyncio.TimeoutError:
            return {"error": "nuclei timeout"}
        except Exception as e:
            return {"error": str(e)}
    
    @classmethod
    async def run_sqlmap(cls, target: str, options: list[str] | None = None) -> dict:
        """Run sqlmap scan."""
        if not cls.is_available("sqlmap"):
            return {"error": "sqlmap not installed"}
        
        cmd = ["sqlmap", "-u", target, "--batch", "--random-agent"]
        if options:
            cmd.extend(options)
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
            return {"output": stdout.decode("utf-8", errors="replace"), "error": stderr.decode("utf-8", errors="replace")}
        except asyncio.TimeoutError:
            return {"error": "sqlmap timeout"}
        except Exception as e:
            return {"error": str(e)}


class SecureDevOrchestrator:
    """
    Main orchestrator for SecureDev security scans.
    
    Decision Tree:
    
    1. FASE 0: Backend Detection (ALWAYS)
       └── Determines: Supabase | Firebase | Custom API
    
    2. Based on Backend Type:
       
       SUPABASE:
       ├── FASE 2: RLS Bypass Testing
       ├── FASE 3: Storage Security
       ├── FASE 4: Edge Functions
       ├── FASE 5: Realtime Channels
       ├── FASE 6: Auth Configuration
       └── FASE 20: Dashboard Exposure
       
       FIREBASE:
       ├── F1: Auth Enumeration
       ├── F2: Firestore Rules
       ├── F3: RTDB Rules
       └── F4: Storage Rules
       
       CUSTOM API:
       ├── C1: REST API Security
       ├── C2: GraphQL Security
       ├── C3: Authentication Flow
       └── C4: Rate Limiting
    
    3. COMMON PHASES (All Backends):
       ├── FASE 7: Auth Token Analysis
       ├── FASE 10: Third-Party Keys
       ├── FASE 11: OAuth Flows
       ├── FASE 12: JS Bundle Analysis
       ├── FASE 13: Network Analysis
       ├── FASE 15: External Tools (nmap, nuclei)
       └── FASE 19: SSL/TLS Testing
    """
    
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings
        self.result: SecureDevScanResult | None = None
        
        # Phase registry
        self._phases: dict[str, Callable] = {
            # Common phases
            "0": self._phase_0_backend_detection,
            "7": self._phase_7_token_analysis,
            "10": self._phase_10_third_party,
            "12": self._phase_12_js_analysis,
            "14": self._phase_14_mass_assignment,
            "15": self._phase_15_external_tools,
            "19": self._phase_19_ssl_tls,
            "CSRF": self._phase_csrf_testing,
            # EXTRA phases (Universal - always run)
            "XSS": self._phase_xss_testing,
            "SQLI": self._phase_sqli_testing,
            "HEADERS": self._phase_headers_testing,
            
            # Supabase phases
            "2": self._phase_2_supabase_rls,
            "3": self._phase_3_supabase_storage,
            "4": self._phase_4_supabase_functions,
            "5": self._phase_5_supabase_realtime,
            "6": self._phase_6_supabase_auth,
            "20": self._phase_20_supabase_dashboard,
            "20-ADV": self._phase_20_advanced_rls,
            
            # Firebase phases
            "F1": self._phase_f1_firebase_auth,
            "F2": self._phase_f2_firestore,
            "F3": self._phase_f3_rtdb,
            "F4": self._phase_f4_storage,
            
            # Custom API phases
            "C1": self._phase_c1_rest_api,
            "C2": self._phase_c2_graphql,
            "C3": self._phase_c3_auth_flow,
            "C4": self._phase_c4_rate_limit,
        }
    
    async def scan(self, target: str) -> SecureDevScanResult:
        """
        Execute full SecureDev security scan.
        
        Args:
            target: Target URL to scan
            
        Returns:
            Complete scan result
        """
        logger.info("=" * 60)
        logger.info("🛡️ SecureDev Security Scan Starting")
        logger.info(f"   Target: {target}")
        logger.info("=" * 60)
        
        # Initialize result
        self.result = SecureDevScanResult(
            target=target,
            backend_type=BackendType.UNKNOWN,
        )
        
        # Normalize URL
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        # FASE 0: Backend Detection (MANDATORY)
        backend_result = await self._run_phase("0", "Backend Detection", target)
        
        if not backend_result or not hasattr(backend_result, 'backend_type'):
            # FN-FIX: Don't abort - continue with generic backend type
            logger.warning("Backend detection failed - continuing with GENERIC backend type")
            from scanning.modules.backend_detector import BackendType
            class GenericBackendResult:
                backend_type = BackendType.GENERIC
                supabase_config = None
                firebase_config = None
                def get_applicable_phases(self):
                    return ["1", "2", "3", "4", "5", "6"]  # All phases
            backend_result = GenericBackendResult()
        
        self.result.backend_type = backend_result.backend_type
        
        # Store backend config for reference
        if backend_result.supabase_config:
            self.result.backend_config = {
                "type": "supabase",
                "project_ref": backend_result.supabase_config.project_ref,
                "has_service_role": backend_result.supabase_config.has_service_role,
            }
        elif backend_result.firebase_config:
            self.result.backend_config = {
                "type": "firebase",
                "project_id": backend_result.firebase_config.project_id,
            }
        
        # Get applicable phases
        applicable = backend_result.get_applicable_phases()
        logger.info(f"📋 Applicable phases for {self.result.backend_type.name}: {applicable}")
        
        # Execute applicable phases
        for phase_id in applicable:
            if phase_id == "0":
                continue  # Already done
            
            phase_name = self._get_phase_name(phase_id)
            
            if phase_id in self._phases:
                await self._run_phase(
                    phase_id, 
                    phase_name, 
                    target,
                    backend_result=backend_result
                )
            else:
                logger.warning(f"⚠️ Phase {phase_id} not implemented yet")
                self.result.phases.append(PhaseResult(
                    phase_id=phase_id,
                    phase_name=phase_name,
                    status=PhaseStatus.SKIPPED,
                    skip_reason="Not implemented",
                ))
        
        # Finalize result
        self.result.completed_at = datetime.now()
        self._calculate_totals()
        
        # Summary
        self._print_summary()
        
        return self.result
    
    async def _run_phase(
        self, 
        phase_id: str, 
        phase_name: str, 
        target: str,
        **kwargs
    ) -> Any:
        """Run a single phase with error handling and timing."""
        logger.info(f"\n{'='*50}")
        logger.info(f"📌 FASE {phase_id}: {phase_name}")
        logger.info(f"{'='*50}")
        
        start_time = datetime.now()
        
        try:
            handler = self._phases.get(phase_id)
            if not handler:
                raise NotImplementedError(f"Phase {phase_id} not implemented")
            
            result = await handler(target, **kwargs)
            
            duration = (datetime.now() - start_time).total_seconds()
            
            # Extract findings count from result
            findings_count = 0
            critical_count = 0
            high_count = 0
            
            if hasattr(result, 'findings'):
                findings_count = len(result.findings)
                if hasattr(result, 'critical_count'):
                    critical_count = result.critical_count
                if hasattr(result, 'high_count'):
                    high_count = result.high_count
            elif hasattr(result, 'keys_discovered'):
                findings_count = len(result.keys_discovered)
                critical_count = result.critical_count
            
            phase_result = PhaseResult(
                phase_id=phase_id,
                phase_name=phase_name,
                status=PhaseStatus.COMPLETED,
                findings_count=findings_count,
                critical_count=critical_count,
                high_count=high_count,
                duration_seconds=duration,
            )
            
            self.result.phases.append(phase_result)
            logger.info(f"✅ Phase {phase_id} completed: {findings_count} findings in {duration:.1f}s")
            
            return result
            
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            
            self.result.phases.append(PhaseResult(
                phase_id=phase_id,
                phase_name=phase_name,
                status=PhaseStatus.FAILED,
                duration_seconds=duration,
                skip_reason=str(e),
            ))
            
            logger.error(f"❌ Phase {phase_id} failed: {e}")
            return None
    
    def _get_phase_name(self, phase_id: str) -> str:
        """Get human-readable phase name."""
        names = {
            "0": "Backend Detection",
            "2": "Supabase RLS Bypass",
            "3": "Supabase Storage",
            "4": "Supabase Edge Functions",
            "5": "Supabase Realtime",
            "6": "Supabase Auth Config",
            "7": "Token Analysis",
            "10": "Third-Party Keys",
            "12": "JS Bundle Analysis",
            "14": "Mass Assignment Testing",
            "15": "External Tools (nmap/nuclei)",
            "19": "SSL/TLS Testing",
            "20": "Dashboard Exposure",
            "20-ADV": "Advanced RLS Bypass",
            "CSRF": "CSRF Testing",
            "XSS": "XSS Testing (EXTRA-1)",
            "SQLI": "SQL Injection Testing (EXTRA-2)",
            "HEADERS": "Security Headers",
            "F1": "Firebase Auth",
            "F2": "Firestore Rules",
            "F3": "RTDB Rules",
            "F4": "Firebase Storage",
            "C1": "REST API Security",
            "C2": "GraphQL Security",
            "C3": "Auth Flow",
            "C4": "Rate Limiting",
        }
        return names.get(phase_id, f"Phase {phase_id}")
    
    def _calculate_totals(self) -> None:
        """Calculate total findings from all phases."""
        for phase in self.result.phases:
            self.result.total_findings += phase.findings_count
            self.result.total_critical += phase.critical_count
            self.result.total_high += phase.high_count
    
    def _print_summary(self) -> None:
        """Print scan summary."""
        logger.info("\n" + "=" * 60)
        logger.info("📊 SCAN SUMMARY")
        logger.info("=" * 60)
        logger.info(f"   Target: {self.result.target}")
        logger.info(f"   Backend: {self.result.backend_type.name}")
        logger.info(f"   Duration: {(self.result.completed_at - self.result.started_at).total_seconds() / 60:.1f} minutes")
        logger.info("-" * 40)
        logger.info(f"   Total Findings: {self.result.total_findings}")
        logger.info(f"   🔴 Critical: {self.result.total_critical}")
        logger.info(f"   🟠 High: {self.result.total_high}")
        logger.info("-" * 40)
        
        completed = len([p for p in self.result.phases if p.status == PhaseStatus.COMPLETED])
        skipped = len([p for p in self.result.phases if p.status == PhaseStatus.SKIPPED])
        failed = len([p for p in self.result.phases if p.status == PhaseStatus.FAILED])
        
        logger.info(f"   Phases Completed: {completed}")
        logger.info(f"   Phases Skipped: {skipped}")
        logger.info(f"   Phases Failed: {failed}")
        logger.info("=" * 60)
    
    # Phase implementations
    
    async def _phase_0_backend_detection(self, target: str, **kwargs) -> BackendDetectionResult:
        """FASE 0: Detect backend type."""
        detector = BackendDetector(self.settings)
        return await detector.detect(target)
    
    async def _phase_2_supabase_rls(self, target: str, **kwargs) -> SupabaseScanResult:
        """FASE 2: Supabase RLS bypass testing."""
        backend_result = kwargs.get('backend_result')
        if not backend_result or not backend_result.supabase_config:
            return SupabaseScanResult()
        
        scanner = SupabaseScanner(backend_result.supabase_config, self.settings)
        # Only run RLS tests
        await scanner._test_rls_bypass(
            await self._get_client()
        )
        return scanner.result
    
    async def _phase_3_supabase_storage(self, target: str, **kwargs) -> SupabaseScanResult:
        """FASE 3: Supabase storage testing."""
        backend_result = kwargs.get('backend_result')
        if not backend_result or not backend_result.supabase_config:
            return SupabaseScanResult()
        
        scanner = SupabaseScanner(backend_result.supabase_config, self.settings)
        await scanner._test_storage_access(await self._get_client())
        return scanner.result
    
    async def _phase_4_supabase_functions(self, target: str, **kwargs) -> SupabaseScanResult:
        """FASE 4: Supabase edge functions testing."""
        backend_result = kwargs.get('backend_result')
        if not backend_result or not backend_result.supabase_config:
            return SupabaseScanResult()
        
        scanner = SupabaseScanner(backend_result.supabase_config, self.settings)
        await scanner._test_edge_functions(await self._get_client())
        return scanner.result
    
    async def _phase_5_supabase_realtime(self, target: str, **kwargs) -> SupabaseScanResult:
        """FASE 5: Supabase realtime testing."""
        backend_result = kwargs.get('backend_result')
        if not backend_result or not backend_result.supabase_config:
            return SupabaseScanResult()
        
        scanner = SupabaseScanner(backend_result.supabase_config, self.settings)
        await scanner._test_realtime(await self._get_client())
        return scanner.result
    
    async def _phase_6_supabase_auth(self, target: str, **kwargs) -> SupabaseScanResult:
        """FASE 6: Supabase auth configuration testing."""
        backend_result = kwargs.get('backend_result')
        if not backend_result or not backend_result.supabase_config:
            return SupabaseScanResult()
        
        scanner = SupabaseScanner(backend_result.supabase_config, self.settings)
        await scanner._test_auth_config(await self._get_client())
        return scanner.result
    
    async def _phase_7_token_analysis(self, target: str, **kwargs) -> dict:
        """FASE 7: JWT/Token analysis."""
        # Placeholder - integrate with existing JWT scanner
        return {"findings": [], "tokens_found": 0}
    
    async def _phase_10_third_party(self, target: str, **kwargs) -> ThirdPartyScanResult:
        """FASE 10: Third-party key discovery."""
        import httpx
        
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0), verify=False) as client:
            response = await client.get(target)
            content = response.text
        
        scanner = ThirdPartyScanner(self.settings)
        return await scanner.scan(content, target)
    
    async def _phase_12_js_analysis(self, target: str, **kwargs) -> dict:
        """FASE 12: JavaScript bundle analysis."""
        # Placeholder - integrate with existing JS analyzer
        return {"findings": [], "bundles_analyzed": 0}
    
    async def _phase_15_external_tools(self, target: str, **kwargs) -> dict:
        """FASE 15: Run external security tools."""
        logger.info("🔧 Running Linux security tools...")
        
        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.netloc
        
        # Use the new LinuxToolsWrapper
        wrapper = LinuxToolsWrapper(self.settings)
        
        # Get discovered endpoints from previous phases
        asset_data = kwargs.get("asset_data", {})
        
        result = await wrapper.run_all(
            target,
            asset_data,
            tools=["nmap", "nikto", "nuclei", "gobuster"]
        )
        
        # Also track available/missing tools
        available_tools = LinuxToolsWrapper.get_available_tools()
        
        return {
            "findings": result.get("findings", []),
            "tools_run": result.get("tools_run", []),
            "tools_failed": result.get("tools_failed", []),
            "tools_missing": result.get("tools_missing", []),
            "available_tools": available_tools,
        }
    
    async def _phase_19_ssl_tls(self, target: str, **kwargs) -> dict:
        """FASE 19: SSL/TLS testing."""
        # Placeholder - integrate with SSL scanner
        return {"findings": [], "certificate_info": {}}
    
    async def _phase_20_supabase_dashboard(self, target: str, **kwargs) -> SupabaseScanResult:
        """FASE 20: Supabase dashboard exposure."""
        backend_result = kwargs.get('backend_result')
        if not backend_result or not backend_result.supabase_config:
            return SupabaseScanResult()
        
        scanner = SupabaseScanner(backend_result.supabase_config, self.settings)
        await scanner._test_dashboard_exposure(await self._get_client())
        return scanner.result
    
    async def _phase_f1_firebase_auth(self, target: str, **kwargs) -> FirebaseScanResult:
        """F1: Firebase auth enumeration."""
        backend_result = kwargs.get('backend_result')
        if not backend_result or not backend_result.firebase_config:
            return FirebaseScanResult()
        
        scanner = FirebaseScanner(backend_result.firebase_config, self.settings)
        await scanner._test_auth_enumeration(await self._get_client())
        return scanner.result
    
    async def _phase_f2_firestore(self, target: str, **kwargs) -> FirebaseScanResult:
        """F2: Firestore rules testing."""
        backend_result = kwargs.get('backend_result')
        if not backend_result or not backend_result.firebase_config:
            return FirebaseScanResult()
        
        scanner = FirebaseScanner(backend_result.firebase_config, self.settings)
        await scanner._test_firestore_rules(await self._get_client())
        return scanner.result
    
    async def _phase_f3_rtdb(self, target: str, **kwargs) -> FirebaseScanResult:
        """F3: Realtime Database rules testing."""
        backend_result = kwargs.get('backend_result')
        if not backend_result or not backend_result.firebase_config:
            return FirebaseScanResult()
        
        scanner = FirebaseScanner(backend_result.firebase_config, self.settings)
        await scanner._test_rtdb_rules(await self._get_client())
        return scanner.result
    
    async def _phase_f4_storage(self, target: str, **kwargs) -> FirebaseScanResult:
        """F4: Firebase storage rules testing."""
        backend_result = kwargs.get('backend_result')
        if not backend_result or not backend_result.firebase_config:
            return FirebaseScanResult()
        
        scanner = FirebaseScanner(backend_result.firebase_config, self.settings)
        await scanner._test_storage_rules(await self._get_client())
        return scanner.result
    
    async def _phase_c1_rest_api(self, target: str, **kwargs) -> dict:
        """C1: Custom REST API security testing."""
        # Placeholder - integrate with existing API scanner
        return {"findings": [], "endpoints_tested": 0}
    
    async def _phase_c2_graphql(self, target: str, **kwargs) -> dict:
        """C2: GraphQL security testing."""
        # Placeholder - integrate with existing GraphQL scanner
        return {"findings": [], "introspection_enabled": False}
    
    async def _phase_c3_auth_flow(self, target: str, **kwargs) -> dict:
        """C3: Authentication flow testing."""
        # Placeholder
        return {"findings": []}
    
    async def _phase_c4_rate_limit(self, target: str, **kwargs) -> dict:
        """C4: Rate limiting testing."""
        # Placeholder
        return {"findings": [], "rate_limited": False}
    
    async def _phase_14_mass_assignment(self, target: str, **kwargs) -> dict:
        """FASE 14: Mass Assignment / Object Injection testing."""
        logger.info("🔍 Testing for Mass Assignment vulnerabilities...")
        
        # Get discovered endpoints
        asset_data = kwargs.get("asset_data", {})
        
        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.netloc
        
        scanner = MassAssignmentScanner(self.settings)
        result = await scanner.scan(host, asset_data)
        
        return result
    
    async def _phase_csrf_testing(self, target: str, **kwargs) -> dict:
        """CSRF Testing Phase."""
        logger.info("🔍 Testing for CSRF vulnerabilities...")
        
        # Get discovered forms and endpoints
        asset_data = kwargs.get("asset_data", {})
        
        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.netloc
        
        scanner = CSRFScanner(self.settings)
        result = await scanner.scan(host, asset_data)
        
        return result
    
    async def _phase_20_advanced_rls(self, target: str, **kwargs) -> dict:
        """FASE 20-ADV: Advanced RLS Bypass Testing."""
        logger.info("🔍 Testing for advanced RLS bypass techniques...")
        
        backend_result = kwargs.get('backend_result')
        
        asset_data = {
            "backend_type": "supabase" if backend_result and backend_result.supabase_config else "unknown",
        }
        
        # Add Supabase-specific data if available
        if backend_result and backend_result.supabase_config:
            config = backend_result.supabase_config
            if isinstance(data, dict):
                asset_data["supabase_url"] = f"https://{config.project_ref}.supabase.co"
            if isinstance(data, dict):
                asset_data["supabase_key"] = config.anon_key or ""
            if isinstance(data, dict):
                asset_data["tables"] = ["users", "profiles", "data", "items", "orders", "payments"]
        
        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.netloc
        
        scanner = AdvancedRLSBypassScanner(self.settings)
        result = await scanner.scan(host, asset_data)
        
        return result
    
    async def _phase_xss_testing(self, target: str, **kwargs) -> dict:
        """EXTRA-1: XSS Testing (Universal - always run)."""
        logger.info("🔍 Testing for XSS vulnerabilities...")
        
        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.netloc
        
        # Get asset data from previous phases
        asset_data = kwargs.get("asset_data", {"endpoints": [target]})
        
        try:
            from scanning.modules.xss_scanner import XSSScanner
            from utils.rate_limiter import RateLimiter
            
            scanner = XSSScanner(self.settings)
            rate_limiter = RateLimiter(settings=self.settings, default_rate=10.0, default_burst=20)
            
            result = await scanner.scan(host, asset_data, rate_limiter)
            
            findings = result.get("findings", [])
            return {
                "findings": findings,
                "critical_count": len([f for f in findings if f.get("severity") == "CRITICAL"]),
                "high_count": len([f for f in findings if f.get("severity") == "HIGH"]),
            }
        except Exception as e:
            logger.warning(f"XSS scanner error: {e}")
            return {"findings": [], "error": str(e)}
    
    async def _phase_sqli_testing(self, target: str, **kwargs) -> dict:
        """EXTRA-2: SQL Injection Testing (Universal - always run)."""
        logger.info("🔍 Testing for SQL Injection vulnerabilities...")
        
        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.netloc
        
        # Get asset data from previous phases
        asset_data = kwargs.get("asset_data", {"endpoints": [target]})
        
        try:
            from scanning.modules.sqli_scanner import SQLiScanner
            from utils.rate_limiter import RateLimiter
            
            scanner = SQLiScanner(self.settings)
            rate_limiter = RateLimiter(settings=self.settings, default_rate=5.0, default_burst=10)
            
            result = await scanner.scan(host, asset_data, rate_limiter)
            
            findings = result.get("findings", [])
            return {
                "findings": findings,
                "critical_count": len([f for f in findings if f.get("severity") == "CRITICAL"]),
                "high_count": len([f for f in findings if f.get("severity") == "HIGH"]),
            }
        except Exception as e:
            logger.warning(f"SQLi scanner error: {e}")
            return {"findings": [], "error": str(e)}
    
    async def _phase_headers_testing(self, target: str, **kwargs) -> dict:
        """FASE 7: Security Headers Testing (Universal - always run)."""
        logger.info("🔍 Testing security headers...")
        
        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.netloc
        
        try:
            from scanning.modules.header_security import HeaderSecurityScanner
            from utils.rate_limiter import RateLimiter
            
            scanner = HeaderSecurityScanner(self.settings)
            rate_limiter = RateLimiter(settings=self.settings, default_rate=10.0, default_burst=20)
            
            result = await scanner.scan(host, {"endpoints": [target]}, rate_limiter)
            
            findings = result.get("findings", [])
            return {
                "findings": findings,
                "critical_count": 0,
                "high_count": len([f for f in findings if f.get("severity") == "HIGH"]),
            }
        except Exception as e:
            logger.warning(f"Header scanner error: {e}")
            return {"findings": [], "error": str(e)}
    
    async def _get_client(self):
        """Get HTTP client."""
        import httpx
        return httpx.AsyncClient(timeout=httpx.Timeout(15.0), verify=False)


async def run_securedev_scan(target: str, settings: Settings | None = None) -> SecureDevScanResult:
    """
    Convenience function to run SecureDev scan.
    
    Usage:
        result = await run_securedev_scan("https://example.com")
    """
    orchestrator = SecureDevOrchestrator(settings)
    return await orchestrator.scan(target)
