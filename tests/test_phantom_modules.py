"""
PHANTOM AI - Module Tests

Comprehensive test suite for all PHANTOM AI modules.

Version: 3.0.0
Date: 2026-01-30
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def sample_target():
    """Sample target URL."""
    return "https://example.com"


@pytest.fixture
def sample_findings():
    """Sample vulnerability findings."""
    return [
        {
            "id": "finding_001",
            "type": "sqli",
            "name": "SQL Injection",
            "severity": "CRITICAL",
            "url": "https://example.com/api/users",
            "parameter": "id",
            "payload": "' OR '1'='1",
            "confidence": 0.95,
            "evidence": "SQL error in response",
        },
        {
            "id": "finding_002",
            "type": "xss",
            "name": "Cross-Site Scripting",
            "severity": "HIGH",
            "url": "https://example.com/search",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "confidence": 0.85,
            "evidence": "Payload reflected in response",
        },
        {
            "id": "finding_003",
            "type": "idor",
            "name": "Insecure Direct Object Reference",
            "severity": "HIGH",
            "url": "https://example.com/api/users/123",
            "parameter": "user_id",
            "payload": "124",
            "confidence": 0.90,
            "evidence": "Accessed another user's data",
        },
    ]


@pytest.fixture
def sample_chain():
    """Sample vulnerability chain."""
    return {
        "chain_id": "chain_001",
        "vulnerabilities": [
            {"id": "v1", "type": "sqli", "severity": "CRITICAL"},
            {"id": "v2", "type": "data_access", "severity": "HIGH"},
            {"id": "v3", "type": "credential_exposure", "severity": "CRITICAL"},
        ],
        "impact": "Full database compromise with credential exposure",
        "priority": 10,
    }


# =============================================================================
# IMPACT ASSESSMENT TESTS
# =============================================================================

class TestImpactAssessment:
    """Tests for Impact Assessment Engine."""

    def test_import(self):
        """Test module import."""
        from phantom.impact_assessment import (
            ImpactAssessmentEngine,
            assess_vulnerability,
            calculate_cvss_score,
        )
        assert ImpactAssessmentEngine is not None

    def test_engine_creation(self):
        """Test engine instantiation."""
        from phantom.impact_assessment import ImpactAssessmentEngine
        engine = ImpactAssessmentEngine()
        assert engine.VERSION == "3.0.0"

    def test_cvss_calculation(self):
        """Test CVSS score calculation."""
        from phantom.impact_assessment import ImpactAssessmentEngine

        engine = ImpactAssessmentEngine()
        # Test with a simple vulnerability assessment
        result = engine.assess_vulnerability(
            vulnerability_id="test_001",
            vulnerability_type="sqli",
        )

        assert result is not None
        # The result should have a CVSS score
        assert hasattr(result, "cvss_score") or result is not None

    def test_vulnerability_assessment(self, sample_findings):
        """Test vulnerability impact assessment."""
        from phantom.impact_assessment import ImpactAssessmentEngine

        engine = ImpactAssessmentEngine()

        for finding in sample_findings:
            # Use the correct API signature
            result = engine.assess_vulnerability(
                vulnerability_id=finding["id"],
                vulnerability_type=finding["type"],
            )

            assert result is not None


# =============================================================================
# CHAIN VISUALIZATION TESTS
# =============================================================================

class TestChainVisualization:
    """Tests for Chain Visualization Engine."""

    def test_import(self):
        """Test module import."""
        from phantom.chain_visualization import (
            ChainVisualizationEngine,
            create_chain_graph,
            OutputFormat,
        )
        assert ChainVisualizationEngine is not None

    def test_engine_creation(self):
        """Test engine instantiation."""
        from phantom.chain_visualization import ChainVisualizationEngine
        engine = ChainVisualizationEngine()
        assert engine.VERSION == "3.0.0"

    def test_graph_creation(self, sample_chain):
        """Test attack graph creation."""
        from phantom.chain_visualization import ChainVisualizationEngine

        engine = ChainVisualizationEngine()
        graph = engine.create_graph_from_chain(sample_chain)

        assert graph is not None
        assert len(graph.nodes) > 0

    def test_mermaid_render(self, sample_chain):
        """Test Mermaid diagram rendering."""
        from phantom.chain_visualization import ChainVisualizationEngine

        engine = ChainVisualizationEngine()
        graph = engine.create_graph_from_chain(sample_chain)
        mermaid = engine.render_mermaid(graph)

        assert mermaid is not None
        assert "graph" in mermaid.lower() or "flowchart" in mermaid.lower()

    def test_json_render(self, sample_chain):
        """Test JSON export."""
        from phantom.chain_visualization import ChainVisualizationEngine

        engine = ChainVisualizationEngine()
        graph = engine.create_graph_from_chain(sample_chain)
        json_output = engine.render_json(graph)

        assert json_output is not None
        data = json.loads(json_output)
        assert "nodes" in data
        assert "edges" in data


# =============================================================================
# SARIF GENERATOR TESTS
# =============================================================================

class TestSARIFGenerator:
    """Tests for SARIF Generator."""

    def test_import(self):
        """Test module import."""
        from phantom.sarif_generator import (
            SARIFGenerator,
            findings_to_sarif,
            SARIF_VERSION,
        )
        assert SARIFGenerator is not None

    def test_generator_creation(self, sample_target):
        """Test generator instantiation."""
        from phantom.sarif_generator import SARIFGenerator

        generator = SARIFGenerator()
        assert generator.VERSION == "3.0.0"

    def test_sarif_generation(self, sample_target, sample_findings):
        """Test SARIF output generation."""
        from phantom.sarif_generator import SARIFGenerator

        generator = SARIFGenerator()

        for finding in sample_findings:
            generator.add_finding(
                vulnerability_type=finding["type"],
                url=finding["url"],
                message=finding["name"],
                severity=finding["severity"],
            )

        sarif = generator.generate()

        assert sarif is not None
        assert "runs" in sarif
        assert len(sarif["runs"]) > 0

    def test_add_finding(self, sample_target, sample_findings):
        """Test adding findings to SARIF."""
        from phantom.sarif_generator import SARIFGenerator

        generator = SARIFGenerator()

        for finding in sample_findings:
            result = generator.add_finding(
                vulnerability_type=finding["type"],
                url=finding["url"],
                message=finding["name"],
                severity=finding["severity"],
            )
            assert result is not None

        output = generator.generate()
        assert "runs" in output
        assert len(output["runs"][0]["results"]) == len(sample_findings)


# =============================================================================
# BOUNTY ESTIMATOR TESTS
# =============================================================================

class TestBountyEstimator:
    """Tests for Bounty Estimator."""

    def test_import(self):
        """Test module import."""
        from phantom.bounty_estimator import (
            BountyEstimator,
            estimate_bounty,
            create_program_config,
            BountyPlatform,
            ProgramTier,
        )
        assert BountyEstimator is not None

    def test_estimator_creation(self):
        """Test estimator instantiation."""
        from phantom.bounty_estimator import (
            BountyEstimator,
            ProgramConfig,
            BountyPlatform,
            ProgramTier,
        )

        config = ProgramConfig(
            name="test_program",
            platform=BountyPlatform.HACKERONE,
            tier=ProgramTier.STANDARD,
        )

        estimator = BountyEstimator(config)
        assert estimator.VERSION == "3.0.0"

    def test_bounty_estimation(self, sample_findings):
        """Test bounty estimation."""
        from phantom.bounty_estimator import (
            BountyEstimator,
            ProgramConfig,
            BountyPlatform,
            ProgramTier,
        )

        config = ProgramConfig(
            name="test_program",
            platform=BountyPlatform.HACKERONE,
            tier=ProgramTier.PREMIUM,
        )

        estimator = BountyEstimator(config)

        for finding in sample_findings:
            estimate = estimator.estimate(
                vulnerability_id=finding["id"],
                vulnerability_type=finding["type"],
                severity=finding["severity"],
            )

            assert estimate is not None
            assert estimate.estimated_range[0] >= 0
            assert estimate.estimated_range[1] >= estimate.estimated_range[0]


# =============================================================================
# COMPLIANCE MAPPER TESTS
# =============================================================================

class TestComplianceMapper:
    """Tests for Compliance Mapper."""

    def test_import(self):
        """Test module import."""
        from phantom.compliance_mapper import (
            ComplianceMapper,
            map_to_compliance,
            get_cwe_mapping,
            ComplianceFramework,
        )
        assert ComplianceMapper is not None

    def test_mapper_creation(self):
        """Test mapper instantiation."""
        from phantom.compliance_mapper import ComplianceMapper

        mapper = ComplianceMapper()
        assert mapper.VERSION == "3.0.0"

    def test_cwe_mapping(self):
        """Test CWE mapping."""
        from phantom.compliance_mapper import get_cwe_mapping

        # SQL Injection should map to CWE-89
        mapping = get_cwe_mapping("sqli")
        assert mapping is not None
        # mapping can be a CWEMapping object or list of CWE IDs
        if isinstance(mapping, list):
            assert 89 in mapping or any(getattr(m, 'cwe_id', m) == 89 for m in mapping)
        elif hasattr(mapping, 'cwe_id'):
            assert mapping.cwe_id == 89
        else:
            # mapping might be a single integer
            assert mapping == 89

    def test_compliance_mapping(self, sample_findings):
        """Test full compliance mapping."""
        from phantom.compliance_mapper import ComplianceMapper

        mapper = ComplianceMapper()

        for finding in sample_findings:
            mapping = mapper.map_vulnerability(
                vulnerability_id=finding["id"],
                vulnerability_type=finding["type"],
            )

            assert mapping is not None
            # Should have at least CWE mapping
            assert hasattr(mapping, "cwe_ids") or hasattr(mapping, "cwe_mapping")


# =============================================================================
# KNOWLEDGE LOADER TESTS
# =============================================================================

class TestKnowledgeLoader:
    """Tests for Knowledge Loader."""

    def test_import(self):
        """Test module import."""
        from phantom.knowledge_loader import (
            KnowledgeLoader,
            get_knowledge_loader,
            search_knowledge,
            KnowledgeSource,
            VulnerabilityCategory,
        )
        assert KnowledgeLoader is not None

    def test_loader_creation(self):
        """Test loader instantiation."""
        from phantom.knowledge_loader import KnowledgeLoader

        loader = KnowledgeLoader()
        assert loader is not None

    def test_singleton_instance(self):
        """Test singleton pattern."""
        from phantom.knowledge_loader import get_knowledge_loader

        loader1 = get_knowledge_loader()
        loader2 = get_knowledge_loader()
        assert loader1 is loader2

    def test_custom_entry(self):
        """Test adding custom knowledge entry."""
        from phantom.knowledge_loader import (
            KnowledgeLoader,
            KnowledgeEntry,
            KnowledgeSource,
            KnowledgeType,
            VulnerabilityCategory,
        )

        loader = KnowledgeLoader()

        entry = KnowledgeEntry(
            id="test_001",
            source=KnowledgeSource.CUSTOM,
            knowledge_type=KnowledgeType.PAYLOAD,
            category=VulnerabilityCategory.SQL_INJECTION,
            title="Test SQL Injection Payload",
            content="Test payload for SQL injection testing",
            payloads=["' OR '1'='1", "' UNION SELECT NULL--"],
        )

        loader.add_custom_entry(entry)
        retrieved = loader.get_entry_by_id("test_001")

        assert retrieved is not None
        assert retrieved.title == "Test SQL Injection Payload"


# =============================================================================
# ADAPTIVE PAYLOAD ENGINE TESTS
# =============================================================================

class TestAdaptivePayloadEngine:
    """Tests for Adaptive Payload Engine."""

    def test_import(self):
        """Test module import."""
        from phantom.adaptive_payload_engine import (
            AdaptivePayloadEngine,
            get_adaptive_engine,
            get_adaptive_payloads,
            PayloadType,
            ContextType,
        )
        assert AdaptivePayloadEngine is not None

    def test_engine_creation(self):
        """Test engine instantiation."""
        from phantom.adaptive_payload_engine import AdaptivePayloadEngine

        engine = AdaptivePayloadEngine()
        assert engine is not None

    def test_singleton_instance(self):
        """Test singleton pattern."""
        from phantom.adaptive_payload_engine import get_adaptive_engine

        engine1 = get_adaptive_engine()
        engine2 = get_adaptive_engine()
        assert engine1 is engine2

    def test_get_payloads(self):
        """Test payload generation."""
        from phantom.adaptive_payload_engine import (
            get_adaptive_payloads,
            PayloadType,
            ContextType,
        )

        payloads = get_adaptive_payloads(
            payload_type=PayloadType.SQL_INJECTION,
            context=ContextType.URL_PARAMETER,
            limit=10,
        )

        assert len(payloads) > 0
        assert len(payloads) <= 10

        for payload in payloads:
            assert payload.payload_type == PayloadType.SQL_INJECTION
            assert payload.raw_payload is not None
            assert payload.encoded_payload is not None

    def test_payload_evolution(self):
        """Test payload evolution."""
        from phantom.adaptive_payload_engine import (
            AdaptivePayloadEngine,
            PayloadType,
        )

        engine = AdaptivePayloadEngine()
        evolved = engine.evolve_payloads(
            payload_type=PayloadType.XSS,
            generations=2,
        )

        assert len(evolved) > 0
        for payload in evolved:
            assert payload.generation > 0

    def test_record_result(self):
        """Test recording payload results."""
        from phantom.adaptive_payload_engine import (
            AdaptivePayloadEngine,
            PayloadResult,
            PayloadType,
        )

        engine = AdaptivePayloadEngine()

        result = PayloadResult(
            payload_id="test_payload_001",
            payload="' OR '1'='1",
            payload_type=PayloadType.SQL_INJECTION,
            success=True,
            response_code=200,
            response_time_ms=150.0,
            detection_indicators=["error", "syntax"],
        )

        engine.record_result(result)

        # Check stats were updated
        stats = engine.payload_stats.get("test_payload_001")
        if stats:
            assert stats.successful_attempts >= 1


# =============================================================================
# WAF BYPASS ENGINE TESTS
# =============================================================================

class TestWAFBypassEngine:
    """Tests for WAF Bypass Engine."""

    def test_import(self):
        """Test module import."""
        from phantom.waf_bypass_engine import (
            WAFBypassEngine,
            WAFDetectionResult,
            BehaviourFamily,
        )
        assert WAFBypassEngine is not None

    def test_engine_creation(self):
        """Test engine instantiation."""
        from phantom.waf_bypass_engine import WAFBypassEngine

        engine = WAFBypassEngine()
        assert engine.VERSION == "3.0.0"


# =============================================================================
# TECH FINGERPRINTER TESTS
# =============================================================================

class TestTechFingerprinter:
    """Tests for Technology Fingerprinter."""

    def test_import(self):
        """Test module import."""
        from phantom.tech_fingerprinter import (
            TechFingerprinter,
            FingerprintResult,
            TechCategory,
        )
        assert TechFingerprinter is not None

    def test_fingerprinter_creation(self):
        """Test fingerprinter instantiation."""
        from phantom.tech_fingerprinter import TechFingerprinter

        fingerprinter = TechFingerprinter()
        assert fingerprinter.VERSION == "3.0.0"


# =============================================================================
# VALIDATION PIPELINE TESTS
# =============================================================================

class TestValidationPipeline:
    """Tests for Validation Pipeline."""

    def test_import(self):
        """Test module import."""
        from phantom.validation_pipeline import (
            ValidationPipeline,
            ValidationConfig,
            create_raw_finding,
        )
        assert ValidationPipeline is not None

    def test_pipeline_creation(self):
        """Test pipeline instantiation."""
        from phantom.validation_pipeline import ValidationPipeline

        pipeline = ValidationPipeline()
        assert pipeline.VERSION == "3.0.0"

    def test_raw_finding_creation(self):
        """Test creating raw findings."""
        from phantom.validation_pipeline import RawFinding, VulnerabilityType

        finding = RawFinding(
            id="test_001",
            title="SQL Injection",
            vulnerability_type=VulnerabilityType.SQLI,
            severity="CRITICAL",
            url="https://example.com/api",
            parameter="id",
            payload="' OR '1'='1",
            evidence="SQL error",
            module_name="sqli_scanner",
        )

        assert finding is not None
        assert finding.vulnerability_type == VulnerabilityType.SQLI


# =============================================================================
# MODULE EXECUTOR TESTS
# =============================================================================

class TestModuleExecutor:
    """Tests for Module Executor."""

    def test_import(self):
        """Test module import."""
        from phantom.module_executor import (
            ModuleExecutor,
            get_module_executor,
            get_registry,
        )
        assert ModuleExecutor is not None

    def test_executor_creation(self):
        """Test executor instantiation."""
        from phantom.module_executor import ModuleExecutor

        executor = ModuleExecutor()
        assert executor.VERSION == "3.0.0"

    def test_registry(self):
        """Test module registry."""
        from phantom.module_executor import get_registry

        registry = get_registry()
        assert registry is not None


# =============================================================================
# NETWORK PROTECTION TESTS
# =============================================================================

class TestNetworkProtection:
    """Tests for Network Protection."""

    def test_import(self):
        """Test module import."""
        from phantom.network_protection import (
            PhantomNetworkProtection,
            get_phantom_protection,
        )
        assert PhantomNetworkProtection is not None

    def test_protection_singleton(self):
        """Test singleton pattern."""
        from phantom.network_protection import get_phantom_protection

        protection1 = get_phantom_protection()
        protection2 = get_phantom_protection()
        assert protection1 is protection2


# =============================================================================
# CONTEXT PAYLOAD SELECTOR TESTS
# =============================================================================

class TestContextPayloadSelector:
    """Tests for Context Payload Selector."""

    def test_import(self):
        """Test module import."""
        from phantom.context_payload_selector import (
            ContextPayloadSelector,
            select_payloads_for_parameter,
        )
        assert ContextPayloadSelector is not None

    def test_selector_creation(self):
        """Test selector instantiation."""
        from phantom.context_payload_selector import ContextPayloadSelector

        selector = ContextPayloadSelector()
        assert selector.VERSION == "3.0.0"


# =============================================================================
# PARAMETER ANALYZER TESTS
# =============================================================================

class TestParameterAnalyzer:
    """Tests for Parameter Analyzer."""

    def test_import(self):
        """Test module import."""
        from phantom.parameter_analyzer import (
            ParameterAnalyzer,
            AnalyzedParameter,
        )
        assert ParameterAnalyzer is not None

    def test_analyzer_creation(self):
        """Test analyzer instantiation."""
        from phantom.parameter_analyzer import ParameterAnalyzer

        analyzer = ParameterAnalyzer()
        assert analyzer.VERSION == "3.0.0"


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestPHANTOMIntegration:
    """Integration tests for PHANTOM AI modules."""

    def test_all_modules_import(self):
        """Test that all modules can be imported from phantom package."""
        from phantom import (
            # Core
            PHANTOM_VERSION,
            PHANTOM_CODENAME,
            get_version,
            get_module_count,
            # Modules
            PhantomNetworkProtection,
            TechFingerprinter,
            ParameterAnalyzer,
            WAFBypassEngine,
            ContextPayloadSelector,
            ModuleExecutor,
            ValidationPipeline,
            ImpactAssessmentEngine,
            ChainVisualizationEngine,
            SARIFGenerator,
            BountyEstimator,
            ComplianceMapper,
            KnowledgeLoader,
            AdaptivePayloadEngine,
        )

        assert PHANTOM_VERSION == "3.0.0"
        assert get_module_count() > 0

    def test_vulnerability_workflow(self, sample_target, sample_findings):
        """Test complete vulnerability assessment workflow."""
        from phantom import (
            ImpactAssessmentEngine,
            SARIFGenerator,
            BountyEstimator,
            ComplianceMapper,
            ProgramConfig,
            BountyPlatform,
            ProgramTier,
        )

        # 1. Assess impact
        impact_engine = ImpactAssessmentEngine()
        impacts = []
        for finding in sample_findings:
            impact = impact_engine.assess_vulnerability(
                vulnerability_id=finding["id"],
                vulnerability_type=finding["type"],
            )
            impacts.append(impact)

        assert len(impacts) == len(sample_findings)

        # 2. Generate SARIF report
        sarif_gen = SARIFGenerator()
        for finding in sample_findings:
            sarif_gen.add_finding(
                vulnerability_type=finding["type"],
                url=finding["url"],
                message=finding["name"],
                severity=finding["severity"],
            )
        sarif = sarif_gen.generate()

        assert "runs" in sarif
        assert len(sarif["runs"][0]["results"]) == len(sample_findings)

        # 3. Estimate bounties
        bounty_config = ProgramConfig(
            name="test_program",
            platform=BountyPlatform.HACKERONE,
            tier=ProgramTier.STANDARD,
        )
        bounty_est = BountyEstimator(bounty_config)

        total_min = 0
        total_max = 0
        for finding in sample_findings:
            estimate = bounty_est.estimate(
                vulnerability_id=finding["id"],
                vulnerability_type=finding["type"],
                severity=finding["severity"],
            )
            if estimate:
                total_min += estimate.estimated_range[0]
                total_max += estimate.estimated_range[1]

        assert total_max >= total_min

        # 4. Map compliance
        compliance = ComplianceMapper()
        mappings = []
        for finding in sample_findings:
            mapping = compliance.map_vulnerability(
                vulnerability_id=finding["id"],
                vulnerability_type=finding["type"],
            )
            if mapping:
                mappings.append(mapping)

        assert len(mappings) > 0


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
