"""
Tests for the scanning/result_processor/ module.

Tests FindingDeduplicator, FindingSharer, and related components.
"""

import pytest
from unittest.mock import AsyncMock, Mock

from scanning.result_processor import (
    # Deduplication
    TYPE_NORMALIZATION,
    NAME_BASED_TYPES,
    PARAM_BASED_TYPES,
    METHOD_BASED_TYPES,
    HTTP_METHOD_AGNOSTIC_TYPES,
    normalize_detection_method,
    generate_dedup_key,
    FindingDeduplicator,
    deduplicate_findings,
    # Sharing
    EARLY_SHARE_THRESHOLD,
    VALIDATED_SHARE_THRESHOLD,
    share_findings_early,
    share_validated_findings,
    FindingSharer,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Deduplication Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestTypeNormalization:
    """Tests for TYPE_NORMALIZATION mappings."""

    def test_cors_variants_normalized(self):
        """Test CORS variants map to 'cors'."""
        assert TYPE_NORMALIZATION["cors_wildcard"] == "cors"
        assert TYPE_NORMALIZATION["cors_null"] == "cors"
        assert TYPE_NORMALIZATION["cors_arbitrary"] == "cors"
        assert TYPE_NORMALIZATION["cors_subdomain_inject"] == "cors"

    def test_header_variants_normalized(self):
        """Test header variants map correctly."""
        assert TYPE_NORMALIZATION["insecure_header"] == "header_config"
        assert TYPE_NORMALIZATION["missing_browser_hardening"] == "missing_headers"
        assert TYPE_NORMALIZATION["missing_security_header"] == "missing_headers"

    def test_session_variants_normalized(self):
        """Test session variants map to 'session'."""
        assert TYPE_NORMALIZATION["jwt_weakness"] == "session"
        assert TYPE_NORMALIZATION["jwt_vulnerability"] == "session"
        assert TYPE_NORMALIZATION["session_fixation"] == "session"

    def test_idor_variants_normalized(self):
        """Test IDOR variants map to 'idor'."""
        assert TYPE_NORMALIZATION["bac"] == "idor"
        assert TYPE_NORMALIZATION["broken_access_control"] == "idor"
        assert TYPE_NORMALIZATION["access_control"] == "idor"


class TestNameBasedTypes:
    """Tests for NAME_BASED_TYPES set."""

    def test_business_logic_types(self):
        """Test business logic types are name-based."""
        assert "business_logic" in NAME_BASED_TYPES
        assert "session_abuse" in NAME_BASED_TYPES
        assert "creative_exploiter" in NAME_BASED_TYPES

    def test_access_control_types(self):
        """Test access control types are name-based."""
        assert "idor" in NAME_BASED_TYPES
        assert "authorization" in NAME_BASED_TYPES
        assert "broken_access_control" in NAME_BASED_TYPES


class TestParamBasedTypes:
    """Tests for PARAM_BASED_TYPES set."""

    def test_injection_types(self):
        """Test injection types are param-based."""
        assert "sql_injection" in PARAM_BASED_TYPES
        assert "sqli" in PARAM_BASED_TYPES
        assert "xss" in PARAM_BASED_TYPES
        assert "nosql" in PARAM_BASED_TYPES

    def test_file_types(self):
        """Test file-related types are param-based."""
        assert "lfi" in PARAM_BASED_TYPES
        assert "ssrf" in PARAM_BASED_TYPES


class TestMethodBasedTypes:
    """Tests for METHOD_BASED_TYPES set."""

    def test_injection_types_need_method(self):
        """Test injection types need detection method in key."""
        assert "sql_injection" in METHOD_BASED_TYPES
        assert "sqli" in METHOD_BASED_TYPES
        assert "nosql" in METHOD_BASED_TYPES
        assert "xxe" in METHOD_BASED_TYPES


class TestHTTPMethodAgnosticTypes:
    """Tests for HTTP_METHOD_AGNOSTIC_TYPES set."""

    def test_header_types_agnostic(self):
        """Test header types are HTTP method agnostic."""
        assert "missing_headers" in HTTP_METHOD_AGNOSTIC_TYPES
        assert "header_config" in HTTP_METHOD_AGNOSTIC_TYPES
        assert "insecure_header" in HTTP_METHOD_AGNOSTIC_TYPES

    def test_ssl_types_agnostic(self):
        """Test SSL types are HTTP method agnostic."""
        assert "ssl" in HTTP_METHOD_AGNOSTIC_TYPES
        assert "ssl_config" in HTTP_METHOD_AGNOSTIC_TYPES
        assert "tls" in HTTP_METHOD_AGNOSTIC_TYPES

    def test_cors_types_agnostic(self):
        """Test CORS types are HTTP method agnostic."""
        assert "cors" in HTTP_METHOD_AGNOSTIC_TYPES
        assert "cors_wildcard" in HTTP_METHOD_AGNOSTIC_TYPES


class TestNormalizeDetectionMethod:
    """Tests for normalize_detection_method function."""

    def test_empty_string(self):
        """Test empty string returns empty."""
        assert normalize_detection_method("") == ""

    def test_time_based_normalization(self):
        """Test time-based methods normalize to 'time_blind'."""
        assert normalize_detection_method("time_based") == "time_blind"
        assert normalize_detection_method("time-blind-5s") == "time_blind"
        assert normalize_detection_method("TIME DELAY") == "time_blind"

    def test_boolean_normalization(self):
        """Test boolean methods normalize to 'boolean_blind'."""
        assert normalize_detection_method("boolean_blind") == "boolean_blind"
        assert normalize_detection_method("bool-based") == "boolean_blind"

    def test_union_normalization(self):
        """Test union methods normalize to 'union_based'."""
        assert normalize_detection_method("union_select") == "union_based"
        assert normalize_detection_method("UNION-BASED") == "union_based"

    def test_error_normalization(self):
        """Test error methods normalize to 'error_based'."""
        assert normalize_detection_method("error_based") == "error_based"
        assert normalize_detection_method("error-based") == "error_based"

    def test_oob_normalization(self):
        """Test OOB methods normalize to 'oob'."""
        assert normalize_detection_method("oob_exfil") == "oob"
        assert normalize_detection_method("out_of_band") == "oob"

    def test_unknown_method_passthrough(self):
        """Test unknown methods pass through normalized."""
        assert normalize_detection_method("custom_method") == "custom_method"


class TestGenerateDedupKey:
    """Tests for generate_dedup_key function."""

    def test_basic_finding(self):
        """Test basic finding generates key with method."""
        finding = {
            "type": "xss",
            "host": "example.com",
            "matched_at": "/search",
            "metadata": {"param_name": "q"},
        }
        key = generate_dedup_key(finding)
        assert "xss" in key
        assert "example.com" in key
        assert "/search" in key
        assert "q" in key

    def test_name_based_type(self):
        """Test name-based type includes name in key."""
        finding = {
            "type": "business_logic",
            "name": "Price Manipulation",
            "host": "shop.com",
            "matched_at": "/checkout",
        }
        key = generate_dedup_key(finding)
        assert "business_logic" in key
        assert "Price Manipulation" in key

    def test_param_based_type(self):
        """Test param-based type includes param in key."""
        finding = {
            "type": "sqli",
            "host": "app.com",
            "matched_at": "/users",
            "metadata": {"parameter": "id"},
        }
        key = generate_dedup_key(finding)
        assert "sqli" in key
        assert "id" in key

    def test_method_based_type_includes_detection(self):
        """Test injection type includes detection method."""
        finding = {
            "type": "sqli",
            "host": "app.com",
            "matched_at": "/users",
            "metadata": {
                "param_name": "id",
                "detection_method": "time_based",
            },
        }
        key = generate_dedup_key(finding)
        assert "sqli" in key
        assert "time_blind" in key

    def test_http_method_agnostic(self):
        """Test HTTP method agnostic types exclude method."""
        finding = {
            "type": "missing_headers",
            "host": "site.com",
            "matched_at": "/",
            "metadata": {"method": "POST"},
        }
        key = generate_dedup_key(finding)
        # POST should NOT be in key for agnostic type
        assert "POST" not in key

    def test_type_normalization(self):
        """Test type normalization is applied."""
        finding = {
            "type": "cors_wildcard",
            "host": "api.com",
            "matched_at": "/data",
        }
        key = generate_dedup_key(finding)
        # Should normalize to "cors"
        assert "cors" in key

    def test_external_normalizer(self):
        """Test external normalizer is used."""
        finding = {
            "type": "custom_type",
            "host": "test.com",
            "matched_at": "/test",
        }

        def custom_normalizer(t: str) -> str:
            return "normalized_type"

        key = generate_dedup_key(finding, normalize_type_func=custom_normalizer)
        assert "normalized_type" in key


class TestFindingDeduplicator:
    """Tests for FindingDeduplicator class."""

    def normalize_confidence(self, conf):
        """Simple confidence normalizer for tests."""
        if isinstance(conf, (int, float)):
            return float(conf)
        return 50.0

    def test_init(self):
        """Test deduplicator initialization."""
        dedup = FindingDeduplicator(
            normalize_confidence_func=self.normalize_confidence
        )
        assert dedup.duplicates_removed == 0
        assert len(dedup.unique_findings) == 0

    def test_reset(self):
        """Test reset clears state."""
        dedup = FindingDeduplicator(
            normalize_confidence_func=self.normalize_confidence
        )
        dedup._duplicates_removed = 5
        dedup._unique_findings = [{"test": True}]

        dedup.reset()

        assert dedup.duplicates_removed == 0
        assert len(dedup.unique_findings) == 0

    def test_process_unique_finding(self):
        """Test processing unique finding returns True."""
        dedup = FindingDeduplicator(
            normalize_confidence_func=self.normalize_confidence
        )
        finding = {"type": "xss", "host": "test.com", "matched_at": "/", "confidence": 80}

        result = dedup.process_finding(finding)

        assert result is True
        assert len(dedup.unique_findings) == 1

    def test_process_duplicate_finding(self):
        """Test processing duplicate finding returns False."""
        dedup = FindingDeduplicator(
            normalize_confidence_func=self.normalize_confidence
        )
        finding1 = {"type": "xss", "host": "test.com", "matched_at": "/", "confidence": 80}
        finding2 = {"type": "xss", "host": "test.com", "matched_at": "/", "confidence": 70}

        dedup.process_finding(finding1)
        result = dedup.process_finding(finding2)

        assert result is False
        assert dedup.duplicates_removed == 1
        assert len(dedup.unique_findings) == 1

    def test_keeps_higher_confidence(self):
        """Test deduplicator keeps higher confidence finding."""
        dedup = FindingDeduplicator(
            normalize_confidence_func=self.normalize_confidence
        )
        finding1 = {"type": "xss", "host": "test.com", "matched_at": "/", "confidence": 60}
        finding2 = {"type": "xss", "host": "test.com", "matched_at": "/", "confidence": 90}

        dedup.process_finding(finding1)
        dedup.process_finding(finding2)

        assert len(dedup.unique_findings) == 1
        assert dedup.unique_findings[0]["confidence"] == 90

    def test_deduplicate_list(self):
        """Test deduplicating a list of findings."""
        dedup = FindingDeduplicator(
            normalize_confidence_func=self.normalize_confidence
        )
        findings = [
            {"type": "xss", "host": "a.com", "matched_at": "/1", "confidence": 80},
            {"type": "sqli", "host": "b.com", "matched_at": "/2", "confidence": 85},
            {"type": "xss", "host": "a.com", "matched_at": "/1", "confidence": 70},  # dup
        ]

        result = dedup.deduplicate(findings)

        assert len(result) == 2
        assert dedup.duplicates_removed == 1


class TestDeduplicateFindingsFunction:
    """Tests for deduplicate_findings convenience function."""

    def normalize_confidence(self, conf):
        """Simple confidence normalizer for tests."""
        if isinstance(conf, (int, float)):
            return float(conf)
        return 50.0

    def test_returns_tuple(self):
        """Test function returns tuple of (findings, count)."""
        findings = [
            {"type": "xss", "host": "test.com", "matched_at": "/", "confidence": 80},
        ]

        result, removed = deduplicate_findings(
            findings, self.normalize_confidence
        )

        assert isinstance(result, list)
        assert isinstance(removed, int)
        assert len(result) == 1
        assert removed == 0

    def test_deduplication(self):
        """Test function deduplicates correctly."""
        findings = [
            {"type": "xss", "host": "test.com", "matched_at": "/", "confidence": 80},
            {"type": "xss", "host": "test.com", "matched_at": "/", "confidence": 60},
        ]

        result, removed = deduplicate_findings(
            findings, self.normalize_confidence
        )

        assert len(result) == 1
        assert removed == 1


# ═══════════════════════════════════════════════════════════════════════════════
# Sharing Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSharingThresholds:
    """Tests for sharing thresholds."""

    def test_early_threshold_value(self):
        """Test early share threshold is 50%."""
        assert EARLY_SHARE_THRESHOLD == 50.0

    def test_validated_threshold_value(self):
        """Test validated share threshold is 60%."""
        assert VALIDATED_SHARE_THRESHOLD == 60.0

    def test_early_lower_than_validated(self):
        """Test early threshold is lower than validated."""
        assert EARLY_SHARE_THRESHOLD < VALIDATED_SHARE_THRESHOLD


class TestShareFindingsEarly:
    """Tests for share_findings_early function."""

    @pytest.fixture
    def mock_store(self):
        """Create mock shared store."""
        store = AsyncMock()
        store.add_finding = AsyncMock()
        return store

    def normalize_confidence(self, conf):
        """Simple confidence normalizer."""
        if isinstance(conf, (int, float)):
            return float(conf)
        return 50.0

    @pytest.mark.asyncio
    async def test_empty_findings(self, mock_store):
        """Test empty findings returns 0."""
        count = await share_findings_early(
            findings=[],
            shared_store=mock_store,
            normalize_confidence_func=self.normalize_confidence,
        )
        assert count == 0
        mock_store.add_finding.assert_not_called()

    @pytest.mark.asyncio
    async def test_shares_high_confidence(self, mock_store):
        """Test shares findings above threshold."""
        findings = [
            {"type": "xss", "confidence": 70, "module": "xss_scanner"},
        ]

        count = await share_findings_early(
            findings=findings,
            shared_store=mock_store,
            normalize_confidence_func=self.normalize_confidence,
        )

        assert count == 1
        mock_store.add_finding.assert_called_once()

    @pytest.mark.asyncio
    async def test_skips_low_confidence(self, mock_store):
        """Test skips findings below threshold."""
        findings = [
            {"type": "xss", "confidence": 30, "module": "xss_scanner"},
        ]

        count = await share_findings_early(
            findings=findings,
            shared_store=mock_store,
            normalize_confidence_func=self.normalize_confidence,
        )

        assert count == 0
        mock_store.add_finding.assert_not_called()

    @pytest.mark.asyncio
    async def test_marks_early_share(self, mock_store):
        """Test marks findings with _early_share flag."""
        findings = [
            {"type": "xss", "confidence": 70, "module": "xss_scanner"},
        ]

        await share_findings_early(
            findings=findings,
            shared_store=mock_store,
            normalize_confidence_func=self.normalize_confidence,
        )

        call_args = mock_store.add_finding.call_args
        shared_finding = call_args[1]["finding"] if "finding" in call_args[1] else call_args[0][0]
        assert shared_finding.get("_early_share") is True


class TestShareValidatedFindings:
    """Tests for share_validated_findings function."""

    @pytest.fixture
    def mock_store(self):
        """Create mock shared store."""
        store = AsyncMock()
        store.add_finding = AsyncMock()
        return store

    @pytest.fixture
    def mock_audit(self):
        """Create mock audit logger."""
        return Mock()

    def normalize_confidence(self, conf):
        """Simple confidence normalizer."""
        if isinstance(conf, (int, float)):
            return float(conf)
        return 50.0

    @pytest.mark.asyncio
    async def test_empty_findings(self, mock_store):
        """Test empty findings returns 0."""
        count = await share_validated_findings(
            findings=[],
            shared_store=mock_store,
            normalize_confidence_func=self.normalize_confidence,
        )
        assert count == 0

    @pytest.mark.asyncio
    async def test_shares_above_threshold(self, mock_store):
        """Test shares findings above validated threshold."""
        findings = [
            {"type": "sqli", "confidence": 80, "module": "sqli_scanner"},
        ]

        count = await share_validated_findings(
            findings=findings,
            shared_store=mock_store,
            normalize_confidence_func=self.normalize_confidence,
        )

        assert count == 1
        mock_store.add_finding.assert_called_once()

    @pytest.mark.asyncio
    async def test_skips_below_threshold(self, mock_store):
        """Test skips findings below validated threshold."""
        findings = [
            {"type": "sqli", "confidence": 55, "module": "sqli_scanner"},
        ]

        count = await share_validated_findings(
            findings=findings,
            shared_store=mock_store,
            normalize_confidence_func=self.normalize_confidence,
        )

        assert count == 0
        mock_store.add_finding.assert_not_called()

    @pytest.mark.asyncio
    async def test_logs_to_audit(self, mock_store, mock_audit):
        """Test logs to audit logger when provided."""
        findings = [
            {
                "type": "sqli",
                "confidence": 85,
                "module": "sqli_scanner",
                "url": "https://test.com/api",
                "severity": "HIGH",
            },
        ]

        await share_validated_findings(
            findings=findings,
            shared_store=mock_store,
            normalize_confidence_func=self.normalize_confidence,
            audit_logger=mock_audit,
        )

        mock_audit.log_vulnerability_found.assert_called_once()


class TestFindingSharer:
    """Tests for FindingSharer class."""

    @pytest.fixture
    def mock_store(self):
        """Create mock shared store."""
        store = AsyncMock()
        store.add_finding = AsyncMock()
        return store

    def normalize_confidence(self, conf):
        """Simple confidence normalizer."""
        if isinstance(conf, (int, float)):
            return float(conf)
        return 50.0

    def test_init(self, mock_store):
        """Test sharer initialization."""
        sharer = FindingSharer(
            shared_store=mock_store,
            normalize_confidence_func=self.normalize_confidence,
        )

        assert sharer.early_shared_count == 0
        assert sharer.validated_shared_count == 0
        assert sharer.early_threshold == EARLY_SHARE_THRESHOLD
        assert sharer.validated_threshold == VALIDATED_SHARE_THRESHOLD

    def test_custom_thresholds(self, mock_store):
        """Test custom threshold configuration."""
        sharer = FindingSharer(
            shared_store=mock_store,
            normalize_confidence_func=self.normalize_confidence,
            early_threshold=40.0,
            validated_threshold=70.0,
        )

        assert sharer.early_threshold == 40.0
        assert sharer.validated_threshold == 70.0

    def test_reset_stats(self, mock_store):
        """Test reset_stats clears counters."""
        sharer = FindingSharer(
            shared_store=mock_store,
            normalize_confidence_func=self.normalize_confidence,
        )
        sharer._early_shared = 5
        sharer._validated_shared = 3

        sharer.reset_stats()

        assert sharer.early_shared_count == 0
        assert sharer.validated_shared_count == 0

    @pytest.mark.asyncio
    async def test_share_early(self, mock_store):
        """Test share_early method."""
        sharer = FindingSharer(
            shared_store=mock_store,
            normalize_confidence_func=self.normalize_confidence,
        )
        findings = [
            {"type": "xss", "confidence": 60, "module": "xss"},
        ]

        count = await sharer.share_early(findings)

        assert count == 1
        assert sharer.early_shared_count == 1

    @pytest.mark.asyncio
    async def test_share_validated(self, mock_store):
        """Test share_validated method."""
        sharer = FindingSharer(
            shared_store=mock_store,
            normalize_confidence_func=self.normalize_confidence,
        )
        findings = [
            {"type": "sqli", "confidence": 85, "module": "sqli"},
        ]

        count = await sharer.share_validated(findings)

        assert count == 1
        assert sharer.validated_shared_count == 1

    def test_get_stats(self, mock_store):
        """Test get_stats returns statistics."""
        sharer = FindingSharer(
            shared_store=mock_store,
            normalize_confidence_func=self.normalize_confidence,
        )
        sharer._early_shared = 10
        sharer._validated_shared = 5

        stats = sharer.get_stats()

        assert stats["early_shared"] == 10
        assert stats["validated_shared"] == 5
        assert stats["early_threshold"] == EARLY_SHARE_THRESHOLD
        assert stats["validated_threshold"] == VALIDATED_SHARE_THRESHOLD
