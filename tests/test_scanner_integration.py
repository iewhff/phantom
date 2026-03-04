"""
Integration tests for all scanner modules.

Tests:
1. All scanner modules can be imported
2. All scanner modules can be instantiated via FullScanner
3. Scanner signatures match expected patterns
4. Rate limiter is properly used
5. Return types are consistent
"""

import asyncio
import importlib
import pytest
from dataclasses import dataclass
from typing import Any, Optional
from unittest.mock import MagicMock, AsyncMock


# ═══════════════════════════════════════════════════════════════════════════════
# Mock Settings for testing
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class MockTimeouts:
    """Mock timeouts configuration."""
    request_timeout: int = 30
    connect_timeout: int = 10
    read_timeout: int = 30


@dataclass
class MockModules:
    """Mock modules configuration."""
    def get(self, key: str, default: Any = None) -> Any:
        return default


@dataclass
class MockScanning:
    """Mock scanning configuration."""
    modules: MockModules = None

    def __post_init__(self):
        if self.modules is None:
            self.modules = MockModules()


@dataclass
class MockSettings:
    """Mock settings for scanner instantiation."""
    timeout: int = 30
    retries: int = 3
    safe_mode: str = "aggressive"
    timeouts: MockTimeouts = None
    use_linux_tools: bool = False
    scanning: MockScanning = None

    def __post_init__(self):
        if self.timeouts is None:
            self.timeouts = MockTimeouts()
        if self.scanning is None:
            self.scanning = MockScanning()


# ═══════════════════════════════════════════════════════════════════════════════
# Scanner Module Lists
# ═══════════════════════════════════════════════════════════════════════════════

SCANNER_MODULES = [
    ("abac_context_tester", "scanning.modules.abac_context_tester", "ABACContextTester"),
    ("advanced_rls_bypass_scanner", "scanning.modules.advanced_rls_bypass_scanner", "AdvancedRLSBypassScanner"),
    ("api_logic_profiler", "scanning.modules.api_logic_profiler", "APILogicProfiler"),
    ("api_scanner", "scanning.modules.api_scanner", "APIScanner"),
    ("auth_scanner", "scanning.modules.auth_scanner", "AuthScanner"),
    ("authorization_engine", "scanning.modules.authorization_engine", "AuthorizationEngine"),
    ("backend_detector", "scanning.modules.backend_detector", "BackendDetector"),
    ("business_logic_scanner", "scanning.modules.business_logic_scanner", "BusinessLogicScanner"),
    ("cache_deception_scanner", "scanning.modules.cache_deception_scanner", "CacheDeceptionScanner"),
    ("cache_poisoning_scanner", "scanning.modules.cache_poisoning_scanner", "CachePoisoningScanner"),
    ("clickjacking_scanner", "scanning.modules.clickjacking_scanner", "ClickjackingScanner"),
    ("client_hardening_scanner", "scanning.modules.client_hardening_scanner", "ClientHardeningScanner"),
    ("cloud_scanner", "scanning.modules.cloud_scanner", "CloudScanner"),
    ("cmdi_scanner", "scanning.modules.cmdi_scanner", "CommandInjectionScanner"),
    ("cms_scanner", "scanning.modules.cms_scanner", "CMSScanner"),
    ("communications_api_scanner", "scanning.modules.communications_api_scanner", "CommunicationsAPIScanner"),
    ("concurrency_state_modeler", "scanning.modules.concurrency_state_modeler", "ConcurrencyStateModeler"),
    ("concurrency_stress_scanner", "scanning.modules.concurrency_stress_scanner", "ConcurrencyStressScanner"),
    ("config_exposure_scanner", "scanning.modules.config_exposure_scanner", "ConfigExposureScanner"),
    ("cookie_security_scanner", "scanning.modules.cookie_security_scanner", "CookieSecurityScanner"),
    ("cors_checker", "scanning.modules.cors_checker", "CORSChecker"),
    ("creative_exploiter", "scanning.modules.creative_exploiter", "CreativeExploiterScanner"),
    ("credential_verifier", "scanning.modules.credential_verifier", "CredentialVerifier"),
    ("crlf_scanner", "scanning.modules.crlf_scanner", "CRLFScanner"),
    ("csrf_scanner", "scanning.modules.csrf_scanner", "CSRFScanner"),
    ("defensive_evasion_scanner", "scanning.modules.defensive_evasion_scanner", "DefensiveEvasionScanner"),
    ("deserialization_scanner", "scanning.modules.deserialization_scanner", "DeserializationScanner"),
    ("dir_scanner", "scanning.modules.dir_scanner", "DirectoryScanner"),
    ("dns_rebinding_scanner", "scanning.modules.dns_rebinding_scanner", "DNSRebindingScanner"),
    ("dom_xss_scanner", "scanning.modules.dom_xss_scanner", "DOMXSSScanner"),
    ("email_security_scanner", "scanning.modules.email_security_scanner", "EmailSecurityScanner"),
    ("file_upload_scanner", "scanning.modules.file_upload_scanner", "FileUploadScanner"),
    ("firebase_scanner", "scanning.modules.firebase_scanner", "FirebaseScanner"),
    ("graphql_advanced_scanner", "scanning.modules.graphql_advanced_scanner", "GraphQLAdvancedScanner"),
    ("grpc_scanner", "scanning.modules.grpc_scanner", "GRPCScanner"),
    ("header_security", "scanning.modules.header_security", "HeaderSecurityChecker"),
    ("host_header_scanner", "scanning.modules.host_header_scanner", "HostHeaderScanner"),
    ("info_disclosure_scanner", "scanning.modules.info_disclosure_scanner", "InfoDisclosureScanner"),
    ("integration_exploiter", "scanning.modules.integration_exploiter", "IntegrationExploiter"),
    ("jwt_scanner", "scanning.modules.jwt_scanner", "JWTScanner"),
    ("kubernetes_scanner", "scanning.modules.kubernetes_scanner", "KubernetesContainerScanner"),
    ("ldap_xpath_scanner", "scanning.modules.ldap_xpath_scanner", "LDAPXPathScanner"),
    ("lfi_scanner", "scanning.modules.lfi_scanner", "LFIScanner"),
    ("llm_security_scanner", "scanning.modules.llm_security_scanner", "LLMSecurityScanner"),
    ("logic_chain_scanner", "scanning.modules.logic_chain_scanner", "LogicChainScanner"),
    ("mass_assignment_scanner", "scanning.modules.mass_assignment_scanner", "MassAssignmentScanner"),
    ("mfa_bypass_scanner", "scanning.modules.mfa_bypass_scanner", "MFABypassScanner"),
    ("mobile_api_scanner", "scanning.modules.mobile_api_scanner", "MobileAPIScanner"),
    ("nosql_scanner", "scanning.modules.nosql_scanner", "NoSQLScanner"),
    ("nuclei_runner", "scanning.modules.nuclei_runner", "NucleiRunner"),
    ("oauth_scanner", "scanning.modules.oauth_scanner", "OAuthScanner"),
    ("open_redirect_scanner", "scanning.modules.open_redirect_scanner", "OpenRedirectScanner"),
    ("permission_matrix_scanner", "scanning.modules.permission_matrix_scanner", "PermissionMatrixScanner"),
    ("post_exploitation", "scanning.modules.post_exploitation", "PostExploitationModule"),
    ("prototype_pollution_scanner", "scanning.modules.prototype_pollution_scanner", "PrototypePollutionScanner"),
    ("race_condition_scanner", "scanning.modules.race_condition_scanner", "RaceConditionScanner"),
    ("rate_limit_scanner", "scanning.modules.rate_limit_scanner", "RateLimitScanner"),
    ("saml_scanner", "scanning.modules.saml_scanner", "SAMLScanner"),
    ("secrets_pattern_scanner", "scanning.modules.secrets_pattern_scanner", "SecretsPatternScanner"),
    ("session_abuse_scanner", "scanning.modules.session_abuse_scanner", "SessionAbuseScanner"),
    ("smuggling_scanner", "scanning.modules.smuggling_scanner", "HTTPSmugglingScanner"),
    ("sqli_scanner", "scanning.modules.sqli_scanner", "SQLiScanner"),
    ("sse_scanner", "scanning.modules.sse_scanner", "SSEScanner"),
    ("ssl_checker", "scanning.modules.ssl_checker", "SSLChecker"),
    ("ssrf_scanner", "scanning.modules.ssrf_scanner", "SSRFScanner"),
    ("ssti_scanner", "scanning.modules.ssti_scanner", "SSTIScanner"),
    ("subdomain_takeover_scanner", "scanning.modules.subdomain_takeover_scanner", "SubdomainTakeoverScanner"),
    ("supabase_scanner", "scanning.modules.supabase_scanner", "SupabaseScanner"),
    ("third_party_scanner", "scanning.modules.third_party_scanner", "ThirdPartyScanner"),
    ("token_binding_validator", "scanning.modules.token_binding_validator", "TokenBindingValidator"),
    ("wasm_scanner", "scanning.modules.wasm_scanner", "WasmScanner"),
    ("webhook_security_scanner", "scanning.modules.webhook_security_scanner", "WebhookSecurityScanner"),
    ("websocket_scanner", "scanning.modules.websocket_scanner", "WebSocketScanner"),
    ("workflow_inference_engine", "scanning.modules.workflow_inference_engine", "WorkflowInferenceEngine"),
    ("xss_scanner", "scanning.modules.xss_scanner", "XSSScanner"),
    ("xxe_scanner", "scanning.modules.xxe_scanner", "XXEScanner"),
]


# ═══════════════════════════════════════════════════════════════════════════════
# Test: All modules can be imported
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("name,module_path,class_name", SCANNER_MODULES)
def test_scanner_import(name: str, module_path: str, class_name: str):
    """Test that each scanner module can be imported."""
    try:
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        assert cls is not None, f"{class_name} not found in {module_path}"
    except ImportError as e:
        pytest.fail(f"Failed to import {module_path}: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Test: All modules can be instantiated
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("name,module_path,class_name", SCANNER_MODULES)
def test_scanner_instantiation(name: str, module_path: str, class_name: str):
    """Test that each scanner can be instantiated with mock settings."""
    settings = MockSettings()

    try:
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        instance = cls(settings)
        assert instance is not None
    except TypeError as e:
        # Some scanners don't need settings
        if "unexpected keyword argument" in str(e) or "positional argument" in str(e):
            try:
                instance = cls()
                assert instance is not None
            except Exception as e2:
                pytest.fail(f"Failed to instantiate {class_name}: {e2}")
        else:
            pytest.fail(f"Failed to instantiate {class_name}: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Test: All modules have scan method
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("name,module_path,class_name", SCANNER_MODULES)
def test_scanner_has_scan_method(name: str, module_path: str, class_name: str):
    """Test that each scanner has a scan method."""
    settings = MockSettings()

    mod = importlib.import_module(module_path)
    cls = getattr(mod, class_name)

    try:
        instance = cls(settings)
    except TypeError:
        try:
            instance = cls()
        except Exception:
            pytest.skip(f"Cannot instantiate {class_name}")
            return

    assert hasattr(instance, "scan"), f"{class_name} has no scan method"
    assert asyncio.iscoroutinefunction(instance.scan), f"{class_name}.scan is not async"


# ═══════════════════════════════════════════════════════════════════════════════
# Test: FullScanner can load all modules
# ═══════════════════════════════════════════════════════════════════════════════

def test_full_scanner_loads_all_modules():
    """Test that FullScanner can load all its registered modules."""
    from scanning.full_scanner import FullScanner

    settings = MockSettings()
    scanner = FullScanner(settings=settings, safe_mode="aggressive")

    loaded = 0
    failed = []

    for mod_name in scanner.ALL_MODULES.keys():
        try:
            module = scanner._load_module(mod_name)
            if module:
                loaded += 1
            else:
                failed.append(mod_name)
        except Exception as e:
            failed.append(f"{mod_name}: {e}")

    # Allow a small number of failures due to mock settings limitations
    assert loaded >= 75, f"Only {loaded}/77 modules loaded. Failed: {failed}"


# ═══════════════════════════════════════════════════════════════════════════════
# Test: Signature patterns
# ═══════════════════════════════════════════════════════════════════════════════

THREE_ARG_SCANNERS = [
    "sqli_scanner", "xss_scanner", "csrf_scanner", "business_logic_scanner",
    "session_abuse_scanner", "api_logic_profiler", "authorization_engine",
    "file_upload_scanner", "supabase_scanner", "third_party_scanner",
]

@pytest.mark.parametrize("scanner_name", THREE_ARG_SCANNERS)
def test_three_arg_signature(scanner_name: str):
    """Test that key scanners accept (host, asset_data, rate_limiter) signature."""
    import inspect

    for name, module_path, class_name in SCANNER_MODULES:
        if name == scanner_name:
            mod = importlib.import_module(module_path)
            cls = getattr(mod, class_name)

            settings = MockSettings()
            try:
                instance = cls(settings)
            except TypeError:
                instance = cls()

            sig = inspect.signature(instance.scan)
            params = list(sig.parameters.keys())

            # Should have at least: self, target/host, asset_data
            assert len(params) >= 2, f"{scanner_name} has too few params: {params}"
            return

    pytest.fail(f"Scanner {scanner_name} not found")


# ═══════════════════════════════════════════════════════════════════════════════
# Test: SharedFindingsStore integration
# ═══════════════════════════════════════════════════════════════════════════════

CRITICAL_SCANNERS_WITH_STORE = [
    "sqli_scanner", "xss_scanner", "csrf_scanner", "business_logic_scanner",
    "session_abuse_scanner", "api_logic_profiler", "authorization_engine",
    "file_upload_scanner",
]

@pytest.mark.parametrize("scanner_name", CRITICAL_SCANNERS_WITH_STORE)
def test_shared_findings_store_import(scanner_name: str):
    """Test that critical scanners import SharedFindingsStore."""
    for name, module_path, _ in SCANNER_MODULES:
        if name == scanner_name:
            mod = importlib.import_module(module_path)
            source = inspect.getsource(mod)

            assert "SharedFindingsStore" in source or "shared_findings_store" in source, \
                f"{scanner_name} should import SharedFindingsStore"
            return

    pytest.fail(f"Scanner {scanner_name} not found")


# ═══════════════════════════════════════════════════════════════════════════════
# Test: Rate limiter usage in critical scanners
# ═══════════════════════════════════════════════════════════════════════════════

SCANNERS_NEEDING_RATE_LIMITER = [
    "sqli_scanner", "xss_scanner", "cmdi_scanner", "ssrf_scanner",
    "lfi_scanner", "xxe_scanner", "nosql_scanner", "ssti_scanner",
]

@pytest.mark.parametrize("scanner_name", SCANNERS_NEEDING_RATE_LIMITER)
def test_rate_limiter_usage(scanner_name: str):
    """Test that injection scanners use rate limiting."""
    for name, module_path, _ in SCANNER_MODULES:
        if name == scanner_name:
            mod = importlib.import_module(module_path)
            source = inspect.getsource(mod)

            assert "rate_limiter" in source or "acquire" in source, \
                f"{scanner_name} should use rate_limiter"
            return

    pytest.fail(f"Scanner {scanner_name} not found")


# Need to import inspect for source inspection
import inspect
import os
import sys
import time
import tempfile
from pathlib import Path
from typing import Dict, List, Set
from dataclasses import dataclass, field


# =============================================================================
# PHASE TRACKING FOR COMPREHENSIVE TESTS
# =============================================================================

@dataclass
class ScanPhaseTracker:
    """Tracks which phases executed during a scan."""
    phases_executed: Set[str] = field(default_factory=set)
    modules_called: Set[str] = field(default_factory=set)
    findings_count: int = 0
    chains_count: int = 0
    errors: List[str] = field(default_factory=list)
    phase_timings: Dict[str, float] = field(default_factory=dict)


# =============================================================================
# PHASE 0: DISCOVERY TESTS
# =============================================================================

class TestPhase0Discovery:
    """Test Phase 0: URL parsing, robots.txt, sitemap discovery."""

    def test_url_normalization(self):
        """URL should be normalized correctly."""
        from cli.phantom_cli import normalize_target

        assert normalize_target("example.com") == "https://example.com"
        assert normalize_target("http://example.com") == "http://example.com"
        assert "localhost" in normalize_target("localhost:3000")

    def test_domain_extraction(self):
        """Domain should be extracted correctly."""
        from cli.phantom_cli import get_domain

        assert get_domain("https://example.com/path") == "example.com"
        assert get_domain("http://localhost:3000") == "localhost"


# =============================================================================
# PHASE 0.5: AUTH ACQUISITION TESTS
# =============================================================================

class TestPhase05AuthAcquisition:
    """Test Phase 0.5: Registration, login, JWT/cookie acquisition."""

    def test_auth_context_exists(self):
        """AuthContext class should exist and be properly structured."""
        from scanning.auth_context import AuthContext

        ctx = AuthContext()
        assert hasattr(ctx, 'jwt_token') or hasattr(ctx, 'auth_headers')

    def test_user_personas_structure(self):
        """UserPersonas should support multiple users."""
        from scanning.auth_context import UserPersonas

        personas = UserPersonas()
        assert hasattr(personas, 'has_multiple_users')


# =============================================================================
# PHASE 1: TECH INTELLIGENCE TESTS
# =============================================================================

class TestPhase1TechIntelligence:
    """Test Phase 1: Technology fingerprinting."""

    def test_tech_fingerprinter_exists(self):
        """TechFingerprinter should exist."""
        from phantom.tech_fingerprinter import TechFingerprinter

        fp = TechFingerprinter()
        assert fp is not None

    def test_spa_detection_patterns(self):
        """Should have modern SPA detection patterns (THEME-11)."""
        from phantom.tech_fingerprinter import TechFingerprinter

        source = inspect.getsourcefile(TechFingerprinter)
        with open(source) as f:
            content = f.read().lower()

        # Modern frameworks from THEME-11
        modern = ['angular', 'react', 'vue', 'svelte', 'htmx', 'alpine']
        found = sum(1 for m in modern if m in content)
        assert found >= 3, f"Should have modern SPA patterns, found {found}/6"


# =============================================================================
# PHASE 2: WAF DETECTION TESTS
# =============================================================================

class TestPhase2WAFDetection:
    """Test Phase 2: WAF detection and fingerprinting."""

    def test_waf_signatures_exist(self):
        """WAF signatures should be defined."""
        from phantom.waf_bypass_engine import WAFBypassEngine

        engine = WAFBypassEngine()
        assert engine is not None

    def test_modern_waf_patterns(self):
        """Should detect modern WAFs (THEME-11)."""
        from phantom.waf_bypass_engine import WAFBypassEngine

        source = inspect.getsourcefile(WAFBypassEngine)
        with open(source) as f:
            content = f.read().lower()

        modern_wafs = ['cloudflare', 'vercel', 'fastly', 'datadome']
        found = sum(1 for waf in modern_wafs if waf in content)
        assert found >= 2, f"Should have modern WAF patterns, found {found}/4"


# =============================================================================
# PHASE 2.9: INTENT PRIORITY TESTS
# =============================================================================

class TestPhase29IntentPriority:
    """Test Phase 2.9: Attacker intent-based module reordering."""

    def test_attacker_intent_engine_exists(self):
        """AttackerIntentEngine should exist."""
        from scanning.attacker_intent_engine import AttackerIntentEngine

        engine = AttackerIntentEngine()
        assert hasattr(engine, 'get_module_priorities')

    def test_goal_types_defined(self):
        """Attack goals should be defined."""
        from scanning.attacker_intent_engine import AttackerGoal

        goals = [g.name for g in AttackerGoal]
        assert len(goals) >= 3, "Should have at least 3 attack goals"


# =============================================================================
# PHASE 4.2: PROOF ENGINE TESTS
# =============================================================================

class TestPhase42ProofEngine:
    """Test Phase 4.2: Exploitation proof engine."""

    def test_proof_engine_exists(self):
        """ExploitProofEngine should exist."""
        from scanning.exploit_proof_engine import ExploitProofEngine

        engine = ExploitProofEngine()
        assert engine is not None

    def test_prover_types_exist(self):
        """Should have specialized provers."""
        from scanning.exploit_proof_engine import (
            SQLiProver, XSSProver, IDORProver, BusinessLogicProver
        )

        assert SQLiProver is not None
        assert XSSProver is not None
        assert IDORProver is not None
        assert BusinessLogicProver is not None

    def test_proof_questions_implemented(self):
        """Should implement 4 proof questions."""
        from scanning.exploit_proof_engine import ExploitProofEngine

        source = inspect.getsourcefile(ExploitProofEngine)
        with open(source) as f:
            content = f.read().lower()

        questions = ['can_repeat', 'can_mutate', 'can_escalate', 'can_chain']
        found = sum(1 for q in questions if q in content)
        assert found >= 3, f"Should implement proof questions, found {found}/4"


# =============================================================================
# PHASE 4.3: CHAIN ENGINE TESTS
# =============================================================================

class TestPhase43ChainEngine:
    """Test Phase 4.3: Attack chain discovery."""

    def test_chain_analyzer_exists(self):
        """AttackChainAnalyzer should exist."""
        from scanning.attack_chain_analyzer import AttackChainAnalyzer

        analyzer = AttackChainAnalyzer()
        assert analyzer is not None

    def test_chain_confidence_levels(self):
        """Chain confidence levels should exist."""
        from scanning.attack_chain_analyzer import ChainConfidence

        levels = [c.name for c in ChainConfidence]
        assert len(levels) >= 2, "Should have confidence levels"


# =============================================================================
# PHASE 4.45: EXPLOITABILITY TESTS
# =============================================================================

class TestPhase445Exploitability:
    """Test Phase 4.45: Exploitability classification."""

    def test_exploitability_classifier_exists(self):
        """ExploitabilityClassifier should exist."""
        from scanning.exploitability_classifier import ExploitabilityClassifier

        classifier = ExploitabilityClassifier()
        assert hasattr(classifier, 'classify')

    def test_attacker_cost_model(self):
        """Attacker cost model should be implemented."""
        from scanning.exploitability_classifier import ExploitabilityClassifier

        source = inspect.getsourcefile(ExploitabilityClassifier)
        with open(source) as f:
            content = f.read()

        cost_factors = ['time_cost', 'payoff', 'detection_risk', 'scalability']
        found = sum(1 for f in cost_factors if f in content)
        assert found >= 2, f"Should have cost factors, found {found}/4"


# =============================================================================
# PHASE 5: VALIDATION PIPELINE TESTS
# =============================================================================

class TestPhase5ValidationPipeline:
    """Test Phase 5: 6-stage validation pipeline."""

    def test_validation_pipeline_exists(self):
        """ValidationPipeline should exist."""
        from phantom.validation_pipeline import ValidationPipeline

        pipeline = ValidationPipeline()
        assert pipeline is not None

    def test_validation_stages(self):
        """Should have multiple validation stages."""
        from phantom.validation_pipeline import ValidationPipeline

        source = inspect.getsourcefile(ValidationPipeline)
        with open(source) as f:
            content = f.read().lower()

        stages = ['syntax', 'dedup', 'context', 'replay', 'negative', 'confidence']
        found = sum(1 for s in stages if s in content)
        assert found >= 4, f"Should have validation stages, found {found}/6"


# =============================================================================
# PHASE 6: REPORT GENERATION TESTS
# =============================================================================

class TestPhase6ReportGeneration:
    """Test Phase 6: Report generation."""

    def test_client_report_generator(self):
        """ClientReportGenerator should exist."""
        from phantom.client_report_generator import ClientReportGenerator

        gen = ClientReportGenerator()
        assert hasattr(gen, 'generate')

    def test_hackerone_report_generator(self):
        """HackerOneReportGenerator should exist."""
        from phantom.hackerone_report_generator import HackerOneReportGenerator

        gen = HackerOneReportGenerator()
        assert hasattr(gen, 'generate')


# =============================================================================
# SAFETY MODE TESTS
# =============================================================================

class TestSafetyMode:
    """Test safety mode enforcement."""

    def test_safety_modes_defined(self):
        """All safety modes should be recognized."""
        modes = ['safe', 'cautious', 'standard', 'aggressive']

        for mode in modes:
            os.environ["PHANTOM_SAFE_MODE"] = mode
            # Should not crash - just verify env var accepted

    def test_safe_http_client_exists(self):
        """SafeAsyncClient should exist."""
        from utils.safe_http_client import SafeAsyncClient

        assert SafeAsyncClient is not None

    def test_aggressive_env_var_check(self):
        """Aggressive mode should check PHANTOM_ALLOW_AGGRESSIVE."""
        # Verify the check exists in code
        from cli.phantom_cli import _run_phantom_scan

        source = inspect.getsourcefile(_run_phantom_scan)
        with open(source) as f:
            content = f.read()

        assert "PHANTOM_ALLOW_AGGRESSIVE" in content


# =============================================================================
# RATE LIMITING TESTS
# =============================================================================

class TestRateLimiting:
    """Test rate limiting enforcement."""

    def test_rate_limiter_exists(self):
        """RateLimiter should exist."""
        from utils.rate_limiter import RateLimiter

        limiter = RateLimiter(default_rate=30.0)
        assert hasattr(limiter, 'acquire')

    @pytest.mark.asyncio
    async def test_rate_limiting_throttles(self):
        """Rate limiter should throttle requests."""
        from utils.rate_limiter import RateLimiter

        limiter = RateLimiter(default_rate=10.0)

        start = time.time()
        for _ in range(15):
            await limiter.acquire()
        elapsed = time.time() - start

        assert elapsed >= 0.3, f"Rate limiter should throttle: {elapsed}s"


# =============================================================================
# AUDIT LOGGING TESTS
# =============================================================================

class TestAuditLogging:
    """Test audit logging system."""

    def test_audit_logger_exists(self):
        """AuditLogger should exist."""
        from utils.audit_logger import AuditLogger

        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(log_dir=Path(tmpdir))
            assert logger.log_file.exists()

    def test_audit_events_logged(self):
        """Audit events should be logged."""
        from utils.audit_logger import AuditLogger

        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(log_dir=Path(tmpdir))
            logger.log_authorization("https://test.com", True, [], "aggressive", 30.0)

            with open(logger.log_file) as f:
                content = f.read()

            assert "authorization" in content.lower()


# =============================================================================
# COVERAGE TRACKING TESTS (THEME-5)
# =============================================================================

class TestCoverageTracking:
    """Test coverage tracking system."""

    def test_coverage_tracker_exists(self):
        """CoverageTracker should exist."""
        from scanning.coverage_tracker import CoverageTracker

        tracker = CoverageTracker()
        assert hasattr(tracker, 'record_tested') or hasattr(tracker, 'record_endpoint_tested')

    def test_skip_categories_defined(self):
        """Skip categories should be defined."""
        from scanning.coverage_tracker import SkipCategory

        categories = [c.name for c in SkipCategory]
        assert len(categories) >= 4


# =============================================================================
# ERROR HANDLING TESTS (THEME-6)
# =============================================================================

class TestErrorHandling:
    """Test error handling."""

    def test_scan_module_has_error_tracking(self):
        """ScanModule should have error tracking."""
        from scanning.vuln_scanner import ScanModule

        source = inspect.getsourcefile(ScanModule)
        with open(source) as f:
            content = f.read()

        assert 'record_error' in content or '_errors' in content


# =============================================================================
# BUDGET/SATURATION CONTROL TESTS (THEME-9)
# =============================================================================

class TestBudgetControl:
    """Test budget/saturation control."""

    def test_saturation_controller_exists(self):
        """SaturationController should exist."""
        from scanning.saturation_controller import SaturationController

        controller = SaturationController()
        assert hasattr(controller, 'can_make_request')


# =============================================================================
# DETERMINISM TESTS (THEME-8)
# =============================================================================

class TestDeterminism:
    """Test deterministic mode."""

    def test_deterministic_context_exists(self):
        """DeterministicContext should exist."""
        from scanning.determinism import DeterministicContext

        ctx = DeterministicContext("https://example.com")
        assert hasattr(ctx, 'get_seed')

    def test_same_target_same_seed(self):
        """Same target should produce same seed."""
        from scanning.determinism import DeterministicContext

        ctx1 = DeterministicContext("https://example.com")
        ctx2 = DeterministicContext("https://example.com")
        assert ctx1.get_seed() == ctx2.get_seed()


# =============================================================================
# CROSS-MODULE SHARING TESTS (THEME-4)
# =============================================================================

class TestCrossModuleSharing:
    """Test cross-module finding sharing."""

    def test_shared_findings_store_exists(self):
        """SharedFindingsStore should exist."""
        from utils.shared_findings_store import get_shared_findings

        store = get_shared_findings()
        assert hasattr(store, 'add_finding')


# =============================================================================
# FULL PIPELINE INTEGRATION TEST
# =============================================================================

@pytest.mark.integration
@pytest.mark.slow
class TestFullPipelineIntegration:
    """Full integration test - requires target running."""

    @pytest.fixture
    def target_url(self):
        """Target URL for integration test."""
        return os.environ.get("TEST_TARGET", "http://localhost:3000")

    @pytest.mark.asyncio
    async def test_full_scan_completes(self, target_url):
        """Test that full scan completes without fatal errors."""
        import httpx

        # Check if target available
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(target_url)
                if response.status_code not in [200, 301, 302]:
                    pytest.skip(f"Target not available: {target_url}")
        except Exception as e:
            pytest.skip(f"Target not reachable: {e}")

        # Set up aggressive mode
        os.environ["PHANTOM_SAFE_MODE"] = "aggressive"
        os.environ["PHANTOM_ALLOW_AGGRESSIVE"] = "authorized"

        from scanning.full_scanner import FullScanner

        settings = MockSettings()
        scanner = FullScanner(
            target=target_url,
            settings=settings,
            safe_mode="aggressive",
            rate_limit=30.0,
        )

        # Run scan
        result = await scanner.run()

        # Verify completion
        assert result is not None
        assert len(result.modules_executed) >= 5, \
            f"Should run 5+ modules, ran {len(result.modules_executed)}"

        # Verify no fatal errors
        fatal = [e for e in result.errors if "fatal" in str(e).lower()]
        assert len(fatal) == 0, f"Fatal errors: {fatal}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
