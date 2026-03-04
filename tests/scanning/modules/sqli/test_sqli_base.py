"""
Tests for SQLi scanner base types and constants.

Tests cover:
- Enums (ConfidenceLevel, DetectionMethod, WAFType, DatabaseType)
- Dataclasses (ResponseFingerprint, ResponseCluster, InjectionContext, SQLiEvidence)
- Helper functions (is_spa_response)
- Payload sets validation
"""

import pytest
from unittest.mock import MagicMock

from scanning.modules.sqli.sqli_base import (
    # Enums
    ConfidenceLevel,
    DetectionMethod,
    WAFType,
    DatabaseType,
    # Dataclasses
    ResponseFingerprint,
    ResponseCluster,
    InjectionContext,
    SQLiEvidence,
    SQLiResult,
    # Functions
    is_spa_response,
    # Constants
    ERROR_PAYLOADS,
    BOOLEAN_PAYLOADS,
    TIME_PAYLOADS,
    UNION_TEMPLATES,
    WAF_BYPASS_PAYLOADS,
    INJECTABLE_HEADERS,
    SPA_INDICATORS,
    FP_INDICATORS,
    MAX_FINDINGS_PER_ENDPOINT,
    MAX_FINDINGS_PER_PARAM,
    MAX_INTELLIGENT_PAYLOADS,
)


class TestConfidenceLevel:
    """Tests for ConfidenceLevel enum."""

    def test_confidence_values(self):
        """Verify confidence level values are ordered correctly."""
        assert ConfidenceLevel.DEFINITE.value == 100
        assert ConfidenceLevel.VERY_HIGH.value == 95
        assert ConfidenceLevel.HIGH.value == 90
        assert ConfidenceLevel.MEDIUM_HIGH.value == 85
        assert ConfidenceLevel.MEDIUM.value == 75
        assert ConfidenceLevel.LOW.value == 50
        assert ConfidenceLevel.UNCERTAIN.value == 25

    def test_confidence_ordering(self):
        """Verify confidences are properly ordered."""
        levels = [
            ConfidenceLevel.UNCERTAIN,
            ConfidenceLevel.LOW,
            ConfidenceLevel.MEDIUM,
            ConfidenceLevel.MEDIUM_HIGH,
            ConfidenceLevel.HIGH,
            ConfidenceLevel.VERY_HIGH,
            ConfidenceLevel.DEFINITE,
        ]
        values = [l.value for l in levels]
        assert values == sorted(values)


class TestDetectionMethod:
    """Tests for DetectionMethod enum."""

    def test_all_methods_present(self):
        """Verify all detection methods are defined."""
        methods = {m.name for m in DetectionMethod}
        expected = {
            "ERROR_BASED",
            "BOOLEAN_BLIND",
            "TIME_BLIND",
            "UNION_BASED",
            "STACKED_QUERIES",
            "OUT_OF_BAND",
            "SECOND_ORDER",
        }
        assert methods == expected

    def test_unique_values(self):
        """Verify all detection methods have unique values."""
        values = [m.value for m in DetectionMethod]
        assert len(values) == len(set(values))


class TestWAFType:
    """Tests for WAFType enum."""

    def test_common_wafs_present(self):
        """Verify common WAFs are defined."""
        waf_names = {w.name for w in WAFType}
        common_wafs = {
            "CLOUDFLARE",
            "AWS_WAF",
            "AKAMAI",
            "MODSECURITY",
            "UNKNOWN",
            "NONE",
        }
        assert common_wafs.issubset(waf_names)

    def test_from_base_conversion(self):
        """Test WAFType.from_base conversion works."""
        from utils.scanner_helpers import WAFType as BaseWAFType

        # Test known mapping
        result = WAFType.from_base(BaseWAFType.CLOUDFLARE)
        assert result == WAFType.CLOUDFLARE

        # Test NONE mapping
        result = WAFType.from_base(BaseWAFType.NONE)
        assert result == WAFType.NONE


class TestDatabaseType:
    """Tests for DatabaseType enum."""

    def test_common_databases_present(self):
        """Verify common databases are defined."""
        db_names = {d.name for d in DatabaseType}
        expected = {
            "MYSQL",
            "POSTGRESQL",
            "MSSQL",
            "ORACLE",
            "SQLITE",
            "MARIADB",
            "UNKNOWN",
        }
        assert db_names == expected

    def test_database_values_lowercase(self):
        """Verify database values are lowercase strings."""
        for db in DatabaseType:
            assert db.value == db.value.lower()


class TestResponseFingerprint:
    """Tests for ResponseFingerprint dataclass."""

    def _mock_response(self, status_code: int, content: str, headers: dict = None):
        """Create a mock HTTP response."""
        mock = MagicMock()
        mock.status_code = status_code
        mock.text = content
        mock.headers = headers or {}
        return mock

    def test_from_response_basic(self):
        """Test basic ResponseFingerprint creation."""
        response = self._mock_response(200, "<html><title>Test</title></html>")

        fp = ResponseFingerprint.from_response(response, 0.15)

        assert fp.status_code == 200
        assert fp.content_length == len("<html><title>Test</title></html>")
        assert fp.response_time == 0.15
        assert fp.title == "Test"
        assert fp.word_count > 0

    def test_from_response_with_form(self):
        """Test ResponseFingerprint detects forms."""
        response = self._mock_response(
            200,
            "<html><form action='test'><input type='text'></form></html>"
        )

        fp = ResponseFingerprint.from_response(response, 0.1)

        assert fp.has_form is True

    def test_from_response_with_table(self):
        """Test ResponseFingerprint detects tables."""
        response = self._mock_response(
            200,
            "<html><table><tr><td>data</td></tr></table></html>"
        )

        fp = ResponseFingerprint.from_response(response, 0.1)

        assert fp.has_table is True

    def test_from_response_redirect(self):
        """Test ResponseFingerprint captures redirect."""
        response = self._mock_response(302, "", {"location": "/login"})

        fp = ResponseFingerprint.from_response(response, 0.1)

        assert fp.redirect_location == "/login"

    def test_similarity_score_identical(self):
        """Test similarity score for identical fingerprints."""
        response1 = self._mock_response(200, "<html>Test content</html>")
        response2 = self._mock_response(200, "<html>Test content</html>")

        fp1 = ResponseFingerprint.from_response(response1, 0.1)
        fp2 = ResponseFingerprint.from_response(response2, 0.1)

        score = fp1.similarity_score(fp2)
        assert score >= 90  # Near identical

    def test_similarity_score_different_status(self):
        """Test similarity score with different status codes."""
        response1 = self._mock_response(200, "<html>Test</html>")
        response2 = self._mock_response(500, "<html>Test</html>")

        fp1 = ResponseFingerprint.from_response(response1, 0.1)
        fp2 = ResponseFingerprint.from_response(response2, 0.1)

        score = fp1.similarity_score(fp2)
        # Same content but different status - should be lower
        assert score < 90

    def test_similarity_score_different_content(self):
        """Test similarity score with completely different content."""
        response1 = self._mock_response(200, "<html>Page A with lots of content</html>")
        response2 = self._mock_response(200, "<html>Page B</html>")

        fp1 = ResponseFingerprint.from_response(response1, 0.1)
        fp2 = ResponseFingerprint.from_response(response2, 0.1)

        score = fp1.similarity_score(fp2)
        assert score < 80  # Different content


class TestResponseCluster:
    """Tests for ResponseCluster dataclass."""

    def _mock_response(self, status_code: int, content: str):
        """Create a mock HTTP response."""
        mock = MagicMock()
        mock.status_code = status_code
        mock.text = content
        mock.headers = {}
        return mock

    def test_empty_cluster(self):
        """Test empty cluster behavior."""
        cluster = ResponseCluster()

        assert cluster.fingerprints == []
        assert cluster.avg_length == 0.0
        assert cluster.avg_time == 0.0

    def test_add_fingerprint(self):
        """Test adding fingerprint to cluster."""
        cluster = ResponseCluster()
        response = self._mock_response(200, "Test content here")
        fp = ResponseFingerprint.from_response(response, 0.15)

        cluster.add(fp)

        assert len(cluster.fingerprints) == 1
        assert cluster.avg_length == len("Test content here")
        assert cluster.avg_time == 0.15

    def test_cluster_statistics(self):
        """Test cluster calculates correct statistics."""
        cluster = ResponseCluster()

        for i in range(3):
            response = self._mock_response(200, "A" * (100 + i * 10))
            fp = ResponseFingerprint.from_response(response, 0.1 + i * 0.05)
            cluster.add(fp)

        assert len(cluster.fingerprints) == 3
        assert cluster.avg_length == 110  # (100 + 110 + 120) / 3
        assert abs(cluster.avg_time - 0.15) < 0.01  # (0.1 + 0.15 + 0.2) / 3

    def test_is_anomalous_length(self):
        """Test anomaly detection based on length."""
        cluster = ResponseCluster()

        # Add similar fingerprints
        for _ in range(3):
            response = self._mock_response(200, "X" * 1000)
            fp = ResponseFingerprint.from_response(response, 0.1)
            cluster.add(fp)

        # Create anomalous fingerprint with very different length
        anomalous_response = self._mock_response(200, "X" * 500)
        anomalous_fp = ResponseFingerprint.from_response(anomalous_response, 0.1)

        assert cluster.is_anomalous(anomalous_fp, threshold=0.3) is True

    def test_is_anomalous_time(self):
        """Test anomaly detection based on response time."""
        cluster = ResponseCluster()

        # Add fast responses
        for _ in range(3):
            response = self._mock_response(200, "X" * 100)
            fp = ResponseFingerprint.from_response(response, 0.1)
            cluster.add(fp)

        # Create very slow response (4x slower = 300% deviation > 2.0 threshold)
        slow_response = self._mock_response(200, "X" * 100)
        slow_fp = ResponseFingerprint.from_response(slow_response, 0.4)

        # Should be anomalous (4x baseline = 300% deviation > 2.0 threshold)
        assert cluster.is_anomalous(slow_fp) is True


class TestInjectionContext:
    """Tests for InjectionContext dataclass."""

    def test_basic_creation(self):
        """Test basic InjectionContext creation."""
        ctx = InjectionContext(
            url="https://example.com/search",
            method="GET",
            param_name="q",
            param_value="test",
            param_type="query",
        )

        assert ctx.url == "https://example.com/search"
        assert ctx.method == "GET"
        assert ctx.param_name == "q"
        assert ctx.param_value == "test"
        assert ctx.param_type == "query"

    def test_with_extra_params(self):
        """Test InjectionContext with extra params."""
        ctx = InjectionContext(
            url="https://example.com/api",
            method="POST",
            param_name="id",
            param_value="1",
            param_type="body",
            content_type="application/json",
            extra_params={"page": "1", "limit": "10"},
        )

        assert ctx.content_type == "application/json"
        assert ctx.extra_params == {"page": "1", "limit": "10"}


class TestSQLiEvidence:
    """Tests for SQLiEvidence dataclass."""

    def test_basic_creation(self):
        """Test basic SQLiEvidence creation."""
        evidence = SQLiEvidence(
            detection_method=DetectionMethod.ERROR_BASED,
            payload="' OR '1'='1",
            original_value="test",
            response_status=200,
            response_length=5000,
            response_time=0.15,
            error_message="MySQL syntax error",
            db_type=DatabaseType.MYSQL,
        )

        assert evidence.detection_method == DetectionMethod.ERROR_BASED
        assert evidence.payload == "' OR '1'='1"
        assert evidence.db_type == DatabaseType.MYSQL

    def test_to_dict(self):
        """Test SQLiEvidence serialization."""
        evidence = SQLiEvidence(
            detection_method=DetectionMethod.TIME_BLIND,
            payload="' AND SLEEP(5)--",
            original_value="1",
            response_status=200,
            response_length=1000,
            response_time=5.2,
            db_type=DatabaseType.MYSQL,
            waf_bypassed=True,
            waf_type=WAFType.CLOUDFLARE,
        )

        data = evidence.to_dict()

        assert data["detection_method"] == "TIME_BLIND"
        assert data["payload"] == "' AND SLEEP(5)--"
        assert data["db_type"] == "mysql"
        assert data["waf_bypassed"] is True
        assert data["waf_type"] == "cloudflare"


class TestSQLiResult:
    """Tests for SQLiResult dataclass."""

    def test_not_found(self):
        """Test SQLiResult for not found case."""
        result = SQLiResult(found=False, confidence=0)

        assert result.found is False
        assert result.confidence == 0
        assert result.evidence is None

    def test_found_with_evidence(self):
        """Test SQLiResult with evidence."""
        evidence = SQLiEvidence(
            detection_method=DetectionMethod.ERROR_BASED,
            payload="'",
            original_value="",
            response_status=500,
            response_length=1000,
            response_time=0.1,
        )
        result = SQLiResult(found=True, confidence=95, evidence=evidence)

        assert result.found is True
        assert result.confidence == 95
        assert result.evidence is not None


class TestIsSPAResponse:
    """Tests for is_spa_response helper function."""

    def test_non_html_rejected(self):
        """Test that non-HTML content types are rejected."""
        assert is_spa_response("application/json", "{}", 100) is False
        assert is_spa_response("text/plain", "hello", 100) is False

    def test_small_body_rejected(self):
        """Test that very small bodies are rejected."""
        body = '<div data-reactroot="">app</div>'
        assert is_spa_response("text/html", body, len(body)) is False

    def test_large_body_rejected(self):
        """Test that very large bodies are rejected."""
        body = "x" * 200000
        assert is_spa_response("text/html", body, len(body)) is False

    def test_react_spa_detected(self):
        """Test React SPA detection."""
        # Note: is_spa_response requires body_length >= 500
        body = '''
        <html>
        <head><title>React App</title></head>
        <body>
            <div id="root" data-reactroot="">Loading...</div>
            <script src="/static/js/main.js"></script>
            <!-- Padding to meet minimum body length requirement -->
            <div class="content">
                Lorem ipsum dolor sit amet, consectetur adipiscing elit.
                Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
                Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.
            </div>
        </body>
        </html>
        '''
        assert is_spa_response("text/html", body, len(body)) is True

    def test_angular_spa_detected(self):
        """Test Angular SPA detection."""
        # Note: is_spa_response requires body_length >= 500
        body = '''
        <html ng-app="myApp" ng-version="17.0.0">
        <body>
            <app-root></app-root>
            <script src="/main.js"></script>
            <!-- Padding to meet minimum body length requirement -->
            <div class="content">
                Lorem ipsum dolor sit amet, consectetur adipiscing elit.
                Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
                Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.
            </div>
        </body>
        </html>
        '''
        assert is_spa_response("text/html", body, len(body)) is True

    def test_vue_spa_detected(self):
        """Test Vue SPA detection."""
        # Note: is_spa_response requires body_length >= 500
        body = '''
        <html>
        <head><title>Vue App</title></head>
        <body>
            <div id="app" data-v-app="">
                <div data-v-12345="">Content</div>
            </div>
            <!-- Padding to meet minimum body length requirement -->
            <div class="content">
                Lorem ipsum dolor sit amet, consectetur adipiscing elit.
                Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
            </div>
        </body>
        </html>
        '''
        assert is_spa_response("text/html", body, len(body)) is True

    def test_nextjs_spa_detected(self):
        """Test Next.js SPA detection."""
        # Note: is_spa_response requires body_length >= 500
        body = '''
        <html>
        <head><title>Next App</title></head>
        <body>
            <div id="__next">
                <main>Content</main>
            </div>
            <script>window.__INITIAL_STATE__={}</script>
            <!-- Padding to meet minimum body length requirement -->
            <div class="content">
                Lorem ipsum dolor sit amet, consectetur adipiscing elit.
                Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
            </div>
        </body>
        </html>
        '''
        assert is_spa_response("text/html", body, len(body)) is True

    def test_regular_html_not_detected(self):
        """Test regular HTML is not detected as SPA."""
        body = '''
        <html>
        <head><title>Regular Page</title></head>
        <body>
            <h1>Hello World</h1>
            <p>This is a regular HTML page.</p>
            <form action="/submit"><input type="text"></form>
        </body>
        </html>
        '''
        assert is_spa_response("text/html", body, len(body)) is False


class TestPayloadSets:
    """Tests for payload set constants."""

    def test_error_payloads_format(self):
        """Test ERROR_PAYLOADS have correct format."""
        assert len(ERROR_PAYLOADS) > 0
        for payload, name, confidence in ERROR_PAYLOADS:
            assert isinstance(payload, str)
            assert isinstance(name, str)
            assert isinstance(confidence, int)
            assert 0 <= confidence <= 100

    def test_boolean_payloads_format(self):
        """Test BOOLEAN_PAYLOADS have correct format (true/false pairs)."""
        assert len(BOOLEAN_PAYLOADS) > 0
        for true_payload, false_payload, name in BOOLEAN_PAYLOADS:
            assert isinstance(true_payload, str)
            assert isinstance(false_payload, str)
            assert isinstance(name, str)
            # True and false should be different
            assert true_payload != false_payload

    def test_time_payloads_format(self):
        """Test TIME_PAYLOADS have correct format."""
        assert len(TIME_PAYLOADS) > 0
        delay_count = 0
        for payload, db_type, name in TIME_PAYLOADS:
            assert isinstance(payload, str)
            assert isinstance(db_type, str)
            assert isinstance(name, str)
            # Most should have delay placeholder (some like BENCHMARK don't)
            if "{delay}" in payload:
                delay_count += 1
        # At least 80% should have delay placeholder
        assert delay_count / len(TIME_PAYLOADS) >= 0.8

    def test_union_templates_have_columns(self):
        """Test UNION_TEMPLATES have columns placeholder."""
        assert len(UNION_TEMPLATES) > 0
        for template in UNION_TEMPLATES:
            assert "{columns}" in template

    def test_injectable_headers_common_ones(self):
        """Test INJECTABLE_HEADERS contains common headers."""
        common = {"User-Agent", "Referer", "X-Forwarded-For"}
        assert common.issubset(set(INJECTABLE_HEADERS))

    def test_spa_indicators_comprehensive(self):
        """Test SPA_INDICATORS covers major frameworks."""
        indicators_str = " ".join(SPA_INDICATORS)
        # React
        assert "react" in indicators_str.lower()
        # Angular
        assert "ng-app" in indicators_str or "angular" in indicators_str.lower()
        # Vue
        assert "vue" in indicators_str.lower() or "data-v-" in indicators_str

    def test_fp_indicators_no_false_positive_sources(self):
        """Test FP_INDICATORS doesn't block legitimate SQL errors."""
        # "Invalid input" was removed because it blocks legitimate SQL errors
        fp_lower = [fp.lower() for fp in FP_INDICATORS]
        assert "invalid input" not in fp_lower


class TestConstants:
    """Tests for performance constants."""

    def test_max_findings_reasonable(self):
        """Test MAX_FINDINGS constants are reasonable."""
        assert MAX_FINDINGS_PER_ENDPOINT >= 1
        assert MAX_FINDINGS_PER_PARAM >= 1
        # Endpoint should allow at least as many as per-param
        assert MAX_FINDINGS_PER_ENDPOINT >= MAX_FINDINGS_PER_PARAM

    def test_max_intelligent_payloads_reasonable(self):
        """Test MAX_INTELLIGENT_PAYLOADS is reasonable."""
        # Should be enough to detect but not spam
        assert 10 <= MAX_INTELLIGENT_PAYLOADS <= 100
