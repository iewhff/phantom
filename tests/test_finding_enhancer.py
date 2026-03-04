"""
Tests for the scanning/finding_enhancer/ module.

Tests FindingValidator, FindingEnricher, and related components.
"""

import pytest
import time
from unittest.mock import Mock

from scanning.finding_enhancer import (
    # Validator
    ValidationResult,
    FindingValidator,
    validate_finding,
    filter_low_confidence,
    is_finding_valid,
    get_confidence_level,
    # Enricher
    VULN_TYPE_SEVERITY,
    CONFIDENCE_BOOST_THRESHOLD,
    EnrichmentData,
    FindingEnricher,
    calculate_severity,
    enrich_finding,
    add_finding_id,
    add_timestamp,
    link_evidence,
)


# ═══════════════════════════════════════════════════════════════════════════════
# ValidationResult Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestValidationResult:
    """Tests for ValidationResult dataclass."""

    def test_valid_result(self):
        """Test valid result."""
        result = ValidationResult(is_valid=True, confidence=85.0)
        assert result.is_valid is True
        assert result.confidence == 85.0
        assert result.discard_reason is None
        assert result.should_discard is False

    def test_invalid_result(self):
        """Test invalid result."""
        result = ValidationResult(
            is_valid=False,
            confidence=30.0,
            discard_reason="Low confidence",
        )
        assert result.is_valid is False
        assert result.should_discard is True
        assert result.discard_reason == "Low confidence"

    def test_add_warning(self):
        """Test adding warnings."""
        result = ValidationResult(is_valid=True, confidence=50.0)
        result.add_warning("Low confidence finding")
        assert len(result.warnings) == 1
        assert "Low confidence" in result.warnings[0]


# ═══════════════════════════════════════════════════════════════════════════════
# FindingValidator Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestFindingValidator:
    """Tests for FindingValidator class."""

    def test_init(self):
        """Test validator initialization."""
        validator = FindingValidator(min_confidence=70.0)
        assert validator.min_confidence == 70.0
        assert validator.validated_count == 0
        assert validator.discarded_count == 0

    def test_validate_high_confidence_dict(self):
        """Test validating high confidence dict finding."""
        validator = FindingValidator(min_confidence=60.0)
        finding = {"type": "xss", "confidence": 85}

        result = validator.validate(finding)

        assert result.is_valid is True
        assert result.confidence == 85.0
        assert validator.validated_count == 1

    def test_validate_low_confidence_dict(self):
        """Test validating low confidence dict finding."""
        validator = FindingValidator(min_confidence=60.0)
        finding = {"type": "xss", "confidence": 40}

        result = validator.validate(finding)

        assert result.is_valid is False
        assert "Low confidence" in result.discard_reason
        assert validator.discarded_count == 1

    def test_validate_string_confidence(self):
        """Test validating string confidence."""
        validator = FindingValidator(min_confidence=60.0)
        finding = {"type": "sqli", "confidence": "high"}

        result = validator.validate(finding)

        assert result.is_valid is True
        assert result.confidence == 85.0  # "high" maps to 0.85 * 100

    def test_validate_and_mark_discard(self):
        """Test validate_and_mark adds discard flags."""
        validator = FindingValidator(min_confidence=80.0)
        finding = {"type": "xss", "confidence": 50}

        marked = validator.validate_and_mark(finding)

        assert marked["_discarded"] is True
        assert "_discard_reason" in marked

    def test_validate_and_mark_valid(self):
        """Test validate_and_mark doesn't add flags for valid."""
        validator = FindingValidator(min_confidence=60.0)
        finding = {"type": "xss", "confidence": 85}

        marked = validator.validate_and_mark(finding)

        assert "_discarded" not in marked

    def test_reset_stats(self):
        """Test reset_stats clears counters."""
        validator = FindingValidator()
        validator._validated = 10
        validator._discarded = 5

        validator.reset_stats()

        assert validator.validated_count == 0
        assert validator.discarded_count == 0

    def test_get_stats(self):
        """Test get_stats returns statistics."""
        validator = FindingValidator(min_confidence=70.0)
        validator._validated = 5
        validator._discarded = 2

        stats = validator.get_stats()

        assert stats["validated"] == 5
        assert stats["discarded"] == 2
        assert stats["min_confidence"] == 70.0


class TestValidatorFunctions:
    """Tests for validator convenience functions."""

    def test_validate_finding(self):
        """Test validate_finding function."""
        finding = {"type": "sqli", "confidence": 90}
        result = validate_finding(finding)
        assert result.is_valid is True

    def test_filter_low_confidence(self):
        """Test filter_low_confidence function."""
        findings = [
            {"type": "xss", "confidence": 90},
            {"type": "sqli", "confidence": 40},
            {"type": "lfi", "confidence": 75},
        ]

        valid, removed = filter_low_confidence(findings, min_confidence=60.0)

        assert len(valid) == 2
        assert removed == 1

    def test_is_finding_valid(self):
        """Test is_finding_valid function."""
        assert is_finding_valid({"confidence": 85}) is True
        assert is_finding_valid({"confidence": 30}) is False

    def test_get_confidence_level(self):
        """Test get_confidence_level function."""
        assert get_confidence_level(95) == "high"
        assert get_confidence_level(70) == "medium"
        assert get_confidence_level(50) == "low"
        assert get_confidence_level(20) == "very_low"


# ═══════════════════════════════════════════════════════════════════════════════
# Severity Calculation Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSeverityCalculation:
    """Tests for severity calculation."""

    def test_vuln_type_severity_mapping(self):
        """Test vulnerability type to severity mapping."""
        assert VULN_TYPE_SEVERITY["cmdi"] == "CRITICAL"
        assert VULN_TYPE_SEVERITY["sqli"] == "CRITICAL"
        assert VULN_TYPE_SEVERITY["xss"] == "HIGH"
        assert VULN_TYPE_SEVERITY["csrf"] == "MEDIUM"
        assert VULN_TYPE_SEVERITY["info_disclosure"] == "LOW"

    def test_calculate_severity_basic(self):
        """Test basic severity calculation."""
        assert calculate_severity("sqli") == "CRITICAL"
        assert calculate_severity("xss") == "HIGH"
        assert calculate_severity("csrf") == "MEDIUM"

    def test_calculate_severity_with_boost(self):
        """Test severity boost with high confidence + proof."""
        # HIGH with high confidence + proof should boost to CRITICAL
        severity = calculate_severity(
            vuln_type="xss",
            confidence=95.0,
            has_proof=True,
        )
        assert severity == "CRITICAL"

    def test_calculate_severity_no_boost_low_confidence(self):
        """Test no boost with low confidence."""
        severity = calculate_severity(
            vuln_type="xss",
            confidence=60.0,
            has_proof=True,
        )
        assert severity == "HIGH"  # No boost

    def test_calculate_severity_unknown_type(self):
        """Test unknown type defaults to MEDIUM."""
        severity = calculate_severity("unknown_vuln")
        assert severity == "MEDIUM"


# ═══════════════════════════════════════════════════════════════════════════════
# EnrichmentData Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestEnrichmentData:
    """Tests for EnrichmentData dataclass."""

    def test_default_values(self):
        """Test default values."""
        data = EnrichmentData()
        assert data.finding_id is None
        assert data.scan_id is None
        assert data.custom == {}

    def test_custom_values(self):
        """Test custom values."""
        data = EnrichmentData(
            finding_id="f-123",
            module_name="xss_scanner",
            severity="HIGH",
        )
        assert data.finding_id == "f-123"
        assert data.module_name == "xss_scanner"
        assert data.severity == "HIGH"


# ═══════════════════════════════════════════════════════════════════════════════
# FindingEnricher Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestFindingEnricher:
    """Tests for FindingEnricher class."""

    def test_init(self):
        """Test enricher initialization."""
        enricher = FindingEnricher(scan_id="scan-123", target="https://example.com")
        assert enricher.scan_id == "scan-123"
        assert enricher.target == "https://example.com"
        assert enricher.enriched_count == 0

    def test_enrich_adds_id(self):
        """Test enrich adds finding ID."""
        enricher = FindingEnricher()
        finding = {"type": "xss", "confidence": 85}

        enriched = enricher.enrich(finding)

        assert "metadata" in enriched
        assert "finding_id" in enriched["metadata"]
        assert enricher.scan_id in enriched["metadata"]["finding_id"]

    def test_enrich_adds_timestamp(self):
        """Test enrich adds timestamp."""
        enricher = FindingEnricher()
        finding = {"type": "xss", "confidence": 85}

        enriched = enricher.enrich(finding)

        assert "timestamp" in enriched["metadata"]
        assert "discovered_at" in enriched["metadata"]

    def test_enrich_adds_module_name(self):
        """Test enrich adds module name."""
        enricher = FindingEnricher()
        finding = {"type": "xss", "confidence": 85}

        enriched = enricher.enrich(finding, module_name="xss_scanner")

        assert enriched["metadata"]["module_name"] == "xss_scanner"
        assert enriched["module"] == "xss_scanner"

    def test_enrich_normalizes_type(self):
        """Test enrich normalizes vuln type."""
        enricher = FindingEnricher()
        finding = {"type": "sql_injection", "confidence": 90}

        enriched = enricher.enrich(finding)

        assert enriched["metadata"]["normalized_type"] == "sqli"
        assert enriched["metadata"]["original_type"] == "sql_injection"

    def test_enrich_calculates_severity(self):
        """Test enrich calculates severity."""
        enricher = FindingEnricher()
        finding = {"type": "sqli", "confidence": 90}

        enriched = enricher.enrich(finding)

        assert enriched["severity"] == "CRITICAL"
        assert enriched["metadata"]["severity_auto_calculated"] is True

    def test_enrich_adds_confidence_level(self):
        """Test enrich adds confidence level."""
        enricher = FindingEnricher()
        finding = {"type": "xss", "confidence": 90}

        enriched = enricher.enrich(finding)

        assert enriched["metadata"]["confidence_level"] == "high"

    def test_enrich_batch(self):
        """Test enrich_batch processes multiple findings."""
        enricher = FindingEnricher()
        findings = [
            {"type": "xss", "confidence": 85},
            {"type": "sqli", "confidence": 90},
        ]

        enriched = enricher.enrich_batch(findings, module_name="test")

        assert len(enriched) == 2
        assert enricher.enriched_count == 2

    def test_enrich_preserves_existing_metadata(self):
        """Test enrich preserves existing metadata."""
        enricher = FindingEnricher()
        finding = {
            "type": "xss",
            "confidence": 85,
            "metadata": {"custom_key": "custom_value"},
        }

        enriched = enricher.enrich(finding)

        assert enriched["metadata"]["custom_key"] == "custom_value"
        assert "finding_id" in enriched["metadata"]

    def test_get_stats(self):
        """Test get_stats returns statistics."""
        enricher = FindingEnricher(scan_id="test", target="https://test.com")
        enricher._enriched = 5

        stats = enricher.get_stats()

        assert stats["enriched"] == 5
        assert stats["scan_id"] == "test"
        assert stats["target"] == "https://test.com"


class TestEnricherFunctions:
    """Tests for enricher convenience functions."""

    def test_enrich_finding(self):
        """Test enrich_finding function."""
        finding = {"type": "xss", "confidence": 85}

        enriched = enrich_finding(finding, module_name="test")

        assert "metadata" in enriched
        assert "finding_id" in enriched["metadata"]

    def test_add_finding_id(self):
        """Test add_finding_id function."""
        finding = {"type": "xss"}

        finding_id = add_finding_id(finding)

        assert finding_id.startswith("f-")
        assert finding["metadata"]["finding_id"] == finding_id

    def test_add_timestamp(self):
        """Test add_timestamp function."""
        finding = {"type": "xss"}

        before = time.time()
        timestamp = add_timestamp(finding)
        after = time.time()

        assert before <= timestamp <= after
        assert finding["metadata"]["timestamp"] == timestamp

    def test_link_evidence(self):
        """Test link_evidence function."""
        finding = {"type": "xss"}

        link_evidence(finding, evidence_id="ev-123", evidence_path="/path/to/evidence")

        assert finding["metadata"]["evidence_id"] == "ev-123"
        assert finding["metadata"]["proof_available"] is True
        assert finding["metadata"]["evidence_path"] == "/path/to/evidence"


# ═══════════════════════════════════════════════════════════════════════════════
# Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestFindingEnhancerIntegration:
    """Integration tests for finding enhancer."""

    def test_validate_then_enrich(self):
        """Test validation followed by enrichment."""
        validator = FindingValidator(min_confidence=60.0)
        enricher = FindingEnricher(scan_id="int-test")

        finding = {"type": "sqli", "confidence": 90}

        # Validate
        result = validator.validate(finding)
        assert result.is_valid is True

        # Enrich
        enriched = enricher.enrich(finding, module_name="sqli_scanner")

        assert "finding_id" in enriched["metadata"]
        assert enriched["severity"] == "CRITICAL"
        assert enriched["metadata"]["confidence_level"] == "high"

    def test_filter_and_enrich_batch(self):
        """Test filtering and enriching a batch."""
        findings = [
            {"type": "xss", "confidence": 90},
            {"type": "sqli", "confidence": 30},  # Will be filtered
            {"type": "lfi", "confidence": 75},
        ]

        # Filter
        valid, removed = filter_low_confidence(findings, min_confidence=60.0)
        assert len(valid) == 2
        assert removed == 1

        # Enrich
        enricher = FindingEnricher()
        enriched = enricher.enrich_batch(valid)

        assert len(enriched) == 2
        for e in enriched:
            assert "finding_id" in e["metadata"]
            assert "timestamp" in e["metadata"]

    def test_full_pipeline_simulation(self):
        """Test simulating full finding pipeline."""
        scan_id = "pipeline-test"
        target = "https://vulnerable.com"

        # Create components
        validator = FindingValidator(min_confidence=50.0)
        enricher = FindingEnricher(scan_id=scan_id, target=target)

        # Raw findings from scanner
        raw_findings = [
            {"type": "sql_injection", "confidence": 95, "matched_at": "/api/users"},
            {"type": "cross_site_scripting", "confidence": 85, "matched_at": "/search"},
            {"type": "info_disclosure", "confidence": 40, "matched_at": "/debug"},  # Low conf
        ]

        processed = []
        for finding in raw_findings:
            # Validate
            marked = validator.validate_and_mark(finding)
            if marked.get("_discarded"):
                continue

            # Enrich
            enriched = enricher.enrich(marked, module_name="test_scanner")
            processed.append(enriched)

        # Verify results
        assert len(processed) == 2
        assert validator.validated_count == 2
        assert validator.discarded_count == 1
        assert enricher.enriched_count == 2

        # Check enrichment
        sqli = processed[0]
        assert sqli["metadata"]["normalized_type"] == "sqli"
        assert sqli["severity"] == "CRITICAL"

        xss = processed[1]
        assert xss["metadata"]["normalized_type"] == "xss"
        assert xss["severity"] == "HIGH"
