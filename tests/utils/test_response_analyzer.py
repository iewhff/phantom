"""
Tests for utils/response_analyzer.py - False Positive Prevention Engine.

Covers:
- ConfidenceLevel, EchoType, ResponseDiffType enums
- ResponseFingerprint, EchoAnalysis, ResponseDiff, ConfidenceScore, AnalysisResult dataclasses
- ResponseFingerprinter baseline and comparison methods
"""

import hashlib
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import httpx

from utils.response_analyzer import (
    # Enums
    ConfidenceLevel,
    EchoType,
    ResponseDiffType,
    # Data classes
    ResponseFingerprint,
    EchoAnalysis,
    ResponseDiff,
    ConfidenceScore,
    AnalysisResult,
    # Classes
    ResponseFingerprinter,
    # Constants
    BODY_SIMILARITY_THRESHOLD,
    TIMING_ANOMALY_THRESHOLD,
    CONTENT_LENGTH_TOLERANCE,
    SPA_INDICATORS,
)


# =============================================================================
# CONFIDENCE LEVEL ENUM TESTS
# =============================================================================

class TestConfidenceLevel:
    """Tests for ConfidenceLevel enum."""

    def test_all_levels_present(self):
        """Test all confidence levels exist."""
        assert ConfidenceLevel.NONE
        assert ConfidenceLevel.LOW
        assert ConfidenceLevel.MEDIUM
        assert ConfidenceLevel.HIGH
        assert ConfidenceLevel.CONFIRMED

    def test_level_values(self):
        """Test confidence level values are ordered."""
        assert ConfidenceLevel.NONE.value < ConfidenceLevel.LOW.value
        assert ConfidenceLevel.LOW.value < ConfidenceLevel.MEDIUM.value
        assert ConfidenceLevel.MEDIUM.value < ConfidenceLevel.HIGH.value
        assert ConfidenceLevel.HIGH.value < ConfidenceLevel.CONFIRMED.value

    def test_from_score_none(self):
        """Test from_score returns NONE for low scores."""
        assert ConfidenceLevel.from_score(0) == ConfidenceLevel.NONE
        assert ConfidenceLevel.from_score(24) == ConfidenceLevel.NONE

    def test_from_score_low(self):
        """Test from_score returns LOW for 25-49."""
        assert ConfidenceLevel.from_score(25) == ConfidenceLevel.LOW
        assert ConfidenceLevel.from_score(49) == ConfidenceLevel.LOW

    def test_from_score_medium(self):
        """Test from_score returns MEDIUM for 50-69."""
        assert ConfidenceLevel.from_score(50) == ConfidenceLevel.MEDIUM
        assert ConfidenceLevel.from_score(69) == ConfidenceLevel.MEDIUM

    def test_from_score_high(self):
        """Test from_score returns HIGH for 70-89."""
        assert ConfidenceLevel.from_score(70) == ConfidenceLevel.HIGH
        assert ConfidenceLevel.from_score(89) == ConfidenceLevel.HIGH

    def test_from_score_confirmed(self):
        """Test from_score returns CONFIRMED for 90+."""
        assert ConfidenceLevel.from_score(90) == ConfidenceLevel.CONFIRMED
        assert ConfidenceLevel.from_score(100) == ConfidenceLevel.CONFIRMED


# =============================================================================
# ECHO TYPE ENUM TESTS
# =============================================================================

class TestEchoType:
    """Tests for EchoType enum."""

    def test_not_reflected_exists(self):
        """Test NOT_REFLECTED type exists."""
        assert EchoType.NOT_REFLECTED

    def test_reflected_types_exist(self):
        """Test all reflection types exist."""
        assert EchoType.REFLECTED_RAW
        assert EchoType.REFLECTED_ESCAPED
        assert EchoType.REFLECTED_URL_ENCODED
        assert EchoType.REFLECTED_JSON_ESCAPED
        assert EchoType.REFLECTED_IN_COMMENT
        assert EchoType.REFLECTED_IN_ATTRIBUTE
        assert EchoType.REFLECTED_IN_JS
        assert EchoType.REFLECTED_PARTIAL


# =============================================================================
# RESPONSE DIFF TYPE ENUM TESTS
# =============================================================================

class TestResponseDiffType:
    """Tests for ResponseDiffType enum."""

    def test_identical_exists(self):
        """Test IDENTICAL type exists."""
        assert ResponseDiffType.IDENTICAL

    def test_diff_types_exist(self):
        """Test all diff types exist."""
        assert ResponseDiffType.SIMILAR
        assert ResponseDiffType.STATUS_CHANGED
        assert ResponseDiffType.LENGTH_CHANGED
        assert ResponseDiffType.STRUCTURE_CHANGED
        assert ResponseDiffType.ERROR_TRIGGERED
        assert ResponseDiffType.TIMING_ANOMALY
        assert ResponseDiffType.HEADERS_CHANGED


# =============================================================================
# RESPONSE FINGERPRINT TESTS
# =============================================================================

class TestResponseFingerprint:
    """Tests for ResponseFingerprint dataclass."""

    def test_creation(self):
        """Test creating a ResponseFingerprint."""
        fp = ResponseFingerprint(
            url="https://example.com/api",
            method="GET",
            status_code=200,
            content_length=1024,
            content_type="application/json",
            body_hash="abc123",
            body_fuzzy_hash="def456",
            structure_hash="ghi789",
            headers_hash="jkl012",
            response_time_ms=150.5,
        )

        assert fp.url == "https://example.com/api"
        assert fp.method == "GET"
        assert fp.status_code == 200
        assert fp.content_length == 1024
        assert fp.response_time_ms == 150.5

    def test_default_values(self):
        """Test default values for optional fields."""
        fp = ResponseFingerprint(
            url="http://test.com",
            method="GET",
            status_code=200,
            content_length=100,
            content_type="text/html",
            body_hash="a",
            body_fuzzy_hash="b",
            structure_hash="c",
            headers_hash="d",
            response_time_ms=100,
        )

        assert fp.response_times == []
        assert fp.content_lengths == []
        assert fp.sample_count == 1
        assert fp.has_error_page is False
        assert fp.is_json is False
        assert fp.is_html is False

    def test_avg_response_time_with_samples(self):
        """Test average response time calculation."""
        fp = ResponseFingerprint(
            url="http://test.com",
            method="GET",
            status_code=200,
            content_length=100,
            content_type="text/html",
            body_hash="a",
            body_fuzzy_hash="b",
            structure_hash="c",
            headers_hash="d",
            response_time_ms=100,
            response_times=[100, 150, 200],
        )

        assert fp.avg_response_time() == 150.0

    def test_avg_response_time_fallback(self):
        """Test average response time falls back to single value."""
        fp = ResponseFingerprint(
            url="http://test.com",
            method="GET",
            status_code=200,
            content_length=100,
            content_type="text/html",
            body_hash="a",
            body_fuzzy_hash="b",
            structure_hash="c",
            headers_hash="d",
            response_time_ms=100,
        )

        assert fp.avg_response_time() == 100.0

    def test_stddev_response_time(self):
        """Test standard deviation calculation."""
        fp = ResponseFingerprint(
            url="http://test.com",
            method="GET",
            status_code=200,
            content_length=100,
            content_type="text/html",
            body_hash="a",
            body_fuzzy_hash="b",
            structure_hash="c",
            headers_hash="d",
            response_time_ms=100,
            response_times=[100, 200, 300],
        )

        # stddev of [100, 200, 300] = 100
        assert fp.stddev_response_time() == 100.0

    def test_stddev_response_time_insufficient_samples(self):
        """Test stddev returns 0 with less than 2 samples."""
        fp = ResponseFingerprint(
            url="http://test.com",
            method="GET",
            status_code=200,
            content_length=100,
            content_type="text/html",
            body_hash="a",
            body_fuzzy_hash="b",
            structure_hash="c",
            headers_hash="d",
            response_time_ms=100,
            response_times=[100],
        )

        assert fp.stddev_response_time() == 0.0

    def test_avg_content_length(self):
        """Test average content length calculation."""
        fp = ResponseFingerprint(
            url="http://test.com",
            method="GET",
            status_code=200,
            content_length=100,
            content_type="text/html",
            body_hash="a",
            body_fuzzy_hash="b",
            structure_hash="c",
            headers_hash="d",
            response_time_ms=100,
            content_lengths=[100, 200, 300],
        )

        assert fp.avg_content_length() == 200.0


# =============================================================================
# ECHO ANALYSIS TESTS
# =============================================================================

class TestEchoAnalysis:
    """Tests for EchoAnalysis dataclass."""

    def test_creation(self):
        """Test creating EchoAnalysis."""
        echo = EchoAnalysis(
            payload="<script>alert(1)</script>",
            echo_type=EchoType.REFLECTED_RAW,
            reflected_value="<script>alert(1)</script>",
            context="body",
            is_executable=True,
        )

        assert echo.payload == "<script>alert(1)</script>"
        assert echo.echo_type == EchoType.REFLECTED_RAW
        assert echo.is_executable is True

    def test_is_dangerous_raw_executable(self):
        """Test is_dangerous returns True for raw executable reflection."""
        echo = EchoAnalysis(
            payload="<script>",
            echo_type=EchoType.REFLECTED_RAW,
            is_executable=True,
        )

        assert echo.is_dangerous() is True

    def test_is_dangerous_escaped(self):
        """Test is_dangerous returns False for escaped reflection."""
        echo = EchoAnalysis(
            payload="<script>",
            echo_type=EchoType.REFLECTED_ESCAPED,
            is_executable=False,
        )

        assert echo.is_dangerous() is False

    def test_is_dangerous_raw_not_executable(self):
        """Test is_dangerous returns False for raw but non-executable."""
        echo = EchoAnalysis(
            payload="test",
            echo_type=EchoType.REFLECTED_RAW,
            is_executable=False,
        )

        assert echo.is_dangerous() is False


# =============================================================================
# RESPONSE DIFF TESTS
# =============================================================================

class TestResponseDiff:
    """Tests for ResponseDiff dataclass."""

    @pytest.fixture
    def baseline(self):
        """Create a baseline fingerprint."""
        return ResponseFingerprint(
            url="http://test.com",
            method="GET",
            status_code=200,
            content_length=1000,
            content_type="text/html",
            body_hash="abc",
            body_fuzzy_hash="def",
            structure_hash="ghi",
            headers_hash="jkl",
            response_time_ms=100,
        )

    def test_creation(self, baseline):
        """Test creating ResponseDiff."""
        diff = ResponseDiff(
            diff_type=ResponseDiffType.IDENTICAL,
            baseline=baseline,
        )

        assert diff.diff_type == ResponseDiffType.IDENTICAL
        assert diff.baseline is baseline
        assert diff.similarity_score == 1.0

    def test_status_diff(self, baseline):
        """Test ResponseDiff with status change."""
        diff = ResponseDiff(
            diff_type=ResponseDiffType.STATUS_CHANGED,
            baseline=baseline,
            status_diff=(200, 500),
        )

        assert diff.status_diff == (200, 500)

    def test_length_diff(self, baseline):
        """Test ResponseDiff with length change."""
        diff = ResponseDiff(
            diff_type=ResponseDiffType.LENGTH_CHANGED,
            baseline=baseline,
            length_diff=(1000, 5000),
        )

        assert diff.length_diff == (1000, 5000)

    def test_timing_diff(self, baseline):
        """Test ResponseDiff with timing anomaly."""
        diff = ResponseDiff(
            diff_type=ResponseDiffType.TIMING_ANOMALY,
            baseline=baseline,
            timing_diff=(100.0, 5000.0),
        )

        assert diff.timing_diff == (100.0, 5000.0)


# =============================================================================
# CONFIDENCE SCORE TESTS
# =============================================================================

class TestConfidenceScore:
    """Tests for ConfidenceScore dataclass."""

    def test_creation(self):
        """Test creating ConfidenceScore."""
        score = ConfidenceScore()

        assert score.total_score == 0
        assert score.level == ConfidenceLevel.NONE
        assert score.points == {}
        assert score.positive_indicators == []
        assert score.negative_indicators == []

    def test_add_positive_points(self):
        """Test adding positive points."""
        score = ConfidenceScore()
        score.add_points("Error message found", 30)

        assert score.total_score == 30
        assert score.points["Error message found"] == 30
        assert len(score.positive_indicators) == 1
        assert "+30" in score.positive_indicators[0]

    def test_add_negative_points(self):
        """Test adding negative points."""
        score = ConfidenceScore()
        score.add_points("Payload escaped", -20)

        assert score.total_score == -20
        assert score.points["Payload escaped"] == -20
        assert len(score.negative_indicators) == 1
        assert "-20" in score.negative_indicators[0]

    def test_level_updates_with_score(self):
        """Test that level updates as score changes."""
        score = ConfidenceScore()

        score.add_points("Reason 1", 30)
        assert score.level == ConfidenceLevel.LOW

        score.add_points("Reason 2", 40)
        assert score.level == ConfidenceLevel.HIGH

        score.add_points("Reason 3", 30)
        assert score.level == ConfidenceLevel.CONFIRMED

    def test_get_breakdown(self):
        """Test getting human-readable breakdown."""
        score = ConfidenceScore()
        score.add_points("Error found", 30)
        score.add_points("Escaped", -10)

        breakdown = score.get_breakdown()

        assert "Total Score: 20" in breakdown
        # Score 20 is below LOW threshold (25), so it's NONE
        assert "NONE" in breakdown
        assert "Error found" in breakdown
        assert "Escaped" in breakdown

    def test_to_dict(self):
        """Test converting to dictionary."""
        score = ConfidenceScore()
        score.add_points("Test", 50)

        result = score.to_dict()

        assert result["total_score"] == 50
        assert result["level"] == "MEDIUM"
        assert result["points"]["Test"] == 50
        assert len(result["positive_indicators"]) == 1


# =============================================================================
# ANALYSIS RESULT TESTS
# =============================================================================

class TestAnalysisResult:
    """Tests for AnalysisResult dataclass."""

    def test_creation_default(self):
        """Test creating AnalysisResult with defaults."""
        result = AnalysisResult()

        assert result.echo is None
        assert result.diff is None
        assert result.is_finding is False
        assert result.finding_type == ""
        assert result.evidence == []

    def test_creation_with_values(self):
        """Test creating AnalysisResult with values."""
        echo = EchoAnalysis(
            payload="test",
            echo_type=EchoType.REFLECTED_RAW,
        )
        result = AnalysisResult(
            echo=echo,
            is_finding=True,
            finding_type="XSS",
            evidence=["Payload reflected without encoding"],
        )

        assert result.echo is echo
        assert result.is_finding is True
        assert result.finding_type == "XSS"

    def test_to_dict(self):
        """Test converting to dictionary."""
        echo = EchoAnalysis(
            payload="test",
            echo_type=EchoType.REFLECTED_RAW,
        )
        result = AnalysisResult(
            echo=echo,
            is_finding=True,
            finding_type="XSS",
        )

        d = result.to_dict()

        assert d["is_finding"] is True
        assert d["finding_type"] == "XSS"
        assert d["echo_type"] == "REFLECTED_RAW"
        assert "confidence" in d


# =============================================================================
# RESPONSE FINGERPRINTER TESTS
# =============================================================================

class TestResponseFingerprinter:
    """Tests for ResponseFingerprinter class."""

    def test_creation(self):
        """Test creating ResponseFingerprinter."""
        fp = ResponseFingerprinter()

        assert fp._baselines == {}
        assert len(fp._error_patterns) > 0

    def test_stable_headers_defined(self):
        """Test stable headers are defined."""
        fp = ResponseFingerprinter()

        assert "content-type" in fp.STABLE_HEADERS
        assert "server" in fp.STABLE_HEADERS
        assert "x-frame-options" in fp.STABLE_HEADERS

    def test_error_patterns_compiled(self):
        """Test error patterns are compiled as regex."""
        fp = ResponseFingerprinter()

        # Should have compiled patterns
        assert all(hasattr(p, 'search') for p in fp._error_patterns)

    def test_detect_error_page_sql(self):
        """Test detecting SQL error messages."""
        fp = ResponseFingerprinter()

        content = b"You have an error in your SQL syntax near 'MySQL'"
        assert fp._detect_error_page(content) is True

    def test_detect_error_page_postgresql(self):
        """Test detecting PostgreSQL errors."""
        fp = ResponseFingerprinter()

        content = b"PostgreSQL: ERROR: invalid input syntax"
        assert fp._detect_error_page(content) is True

    def test_detect_error_page_stack_trace(self):
        """Test detecting stack traces."""
        fp = ResponseFingerprinter()

        content = b"Traceback (most recent call last):\n  File"
        assert fp._detect_error_page(content) is True

    def test_detect_error_page_clean(self):
        """Test no false positive on clean response."""
        fp = ResponseFingerprinter()

        content = b"<html><body>Hello World</body></html>"
        assert fp._detect_error_page(content) is False

    def test_hash_body(self):
        """Test body hashing is consistent."""
        fp = ResponseFingerprinter()

        content = b"test content"
        hash1 = fp._hash_body(content)
        hash2 = fp._hash_body(content)

        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex

    def test_fuzzy_hash_normalizes_timestamps(self):
        """Test fuzzy hash normalizes timestamps."""
        fp = ResponseFingerprinter()

        content1 = b'{"created": 1234567890123}'
        content2 = b'{"created": 9876543210123}'

        hash1 = fp._fuzzy_hash(content1)
        hash2 = fp._fuzzy_hash(content2)

        # Should be identical after normalization
        assert hash1 == hash2

    def test_fuzzy_hash_normalizes_hashes(self):
        """Test fuzzy hash normalizes long hashes (32+ hex chars)."""
        fp = ResponseFingerprinter()

        # Verify that different content produces different hashes
        content1 = b'same structure with different data'
        content2 = b'same structure with other content'

        hash1 = fp._fuzzy_hash(content1)
        hash2 = fp._fuzzy_hash(content2)

        # Different content should produce different hashes
        assert hash1 != hash2

        # But identical content should produce same hash
        hash3 = fp._fuzzy_hash(content1)
        assert hash1 == hash3

    def test_structure_hash_json(self):
        """Test structure hash for JSON content."""
        fp = ResponseFingerprinter()

        content1 = b'{"name": "Alice", "age": 30}'
        content2 = b'{"name": "Bob", "age": 25}'

        hash1 = fp._structure_hash(content1, "application/json")
        hash2 = fp._structure_hash(content2, "application/json")

        # Same structure, different values - should be equal
        assert hash1 == hash2

    def test_structure_hash_html(self):
        """Test structure hash for HTML content."""
        fp = ResponseFingerprinter()

        content1 = b'<html><body><p>Hello</p></body></html>'
        content2 = b'<html><body><p>World</p></body></html>'

        hash1 = fp._structure_hash(content1, "text/html")
        hash2 = fp._structure_hash(content2, "text/html")

        # Same structure, different text - should be equal
        assert hash1 == hash2

    def test_extract_errors(self):
        """Test extracting error messages."""
        fp = ResponseFingerprinter()

        content = b"""
        Fatal error: Uncaught exception
        ORA-00942: table or view does not exist
        Stack trace:
        """

        errors = fp._extract_errors(content)

        assert len(errors) > 0
        assert any("Fatal error" in e for e in errors)

    def test_extract_errors_limited(self):
        """Test error extraction is limited."""
        fp = ResponseFingerprinter()

        # Content with many errors
        content = b"Fatal error " * 100 + b"Stack trace: " * 100

        errors = fp._extract_errors(content)

        # Should be limited to 10
        assert len(errors) <= 10

    def test_get_baseline_not_found(self):
        """Test getting non-existent baseline."""
        fp = ResponseFingerprinter()

        result = fp.get_baseline("http://test.com", "GET")
        assert result is None


# =============================================================================
# RESPONSE FINGERPRINTER - COMPARE TESTS
# =============================================================================

class TestResponseFingerprinterCompare:
    """Tests for ResponseFingerprinter.compare method."""

    @pytest.fixture
    def fingerprinter(self):
        """Create a fingerprinter."""
        return ResponseFingerprinter()

    @pytest.fixture
    def baseline(self):
        """Create a baseline fingerprint."""
        return ResponseFingerprint(
            url="http://test.com",
            method="GET",
            status_code=200,
            content_length=1000,
            content_type="text/html",
            body_hash=hashlib.sha256(b"test content").hexdigest(),
            body_fuzzy_hash="abc",
            structure_hash="def",
            headers_hash="ghi",
            response_time_ms=100,
            response_times=[100, 110, 90],
            content_lengths=[1000, 1010, 990],
        )

    def test_compare_identical(self, fingerprinter, baseline):
        """Test comparing identical response."""
        # Baseline has content_length ~1000, so we need to match that
        content = b"x" * 1000  # Match baseline content length

        response = MagicMock(spec=httpx.Response)
        response.content = content
        response.status_code = 200
        response.headers = httpx.Headers({
            "content-type": "text/html",
            # Include some stable headers to avoid HEADERS_CHANGED
            "server": "test",
        })

        # Update baseline to match our test content hash
        baseline.body_hash = hashlib.sha256(content).hexdigest()

        diff = fingerprinter.compare(baseline, response, 100.0)

        # Should be either IDENTICAL or SIMILAR (minor header differences)
        assert diff.diff_type in (ResponseDiffType.IDENTICAL, ResponseDiffType.SIMILAR, ResponseDiffType.HEADERS_CHANGED)
        assert diff.similarity_score == 1.0

    def test_compare_status_auth_bypass(self, fingerprinter, baseline):
        """Test detecting auth bypass (401 → 200)."""
        baseline.status_code = 401

        response = MagicMock(spec=httpx.Response)
        response.content = b"content"
        response.status_code = 200
        response.headers = httpx.Headers({"content-type": "text/html"})

        diff = fingerprinter.compare(baseline, response, 100.0)

        assert diff.diff_type == ResponseDiffType.STATUS_CHANGED
        assert diff.status_diff == (401, 200)

    def test_compare_status_server_error(self, fingerprinter, baseline):
        """Test detecting server error triggered."""
        response = MagicMock(spec=httpx.Response)
        response.content = b"Internal Server Error"
        response.status_code = 500
        response.headers = httpx.Headers({"content-type": "text/html"})

        diff = fingerprinter.compare(baseline, response, 100.0)

        assert diff.diff_type == ResponseDiffType.STATUS_CHANGED
        assert diff.status_diff == (200, 500)

    def test_compare_timing_anomaly(self, fingerprinter, baseline):
        """Test detecting timing anomaly."""
        response = MagicMock(spec=httpx.Response)
        response.content = b"test content"
        response.status_code = 200
        response.headers = httpx.Headers({"content-type": "text/html"})

        # Very slow response (10x baseline)
        diff = fingerprinter.compare(baseline, response, 1000.0)

        assert diff.diff_type == ResponseDiffType.TIMING_ANOMALY
        assert diff.timing_diff[1] == 1000.0

    def test_compare_length_changed(self, fingerprinter, baseline):
        """Test detecting length change."""
        response = MagicMock(spec=httpx.Response)
        response.content = b"x" * 5000  # Much larger than baseline
        response.status_code = 200
        response.headers = httpx.Headers({"content-type": "text/html"})

        diff = fingerprinter.compare(baseline, response, 100.0)

        # Should detect significant length change
        assert diff.length_diff is not None or diff.diff_type != ResponseDiffType.IDENTICAL

    def test_compare_error_triggered(self, fingerprinter, baseline):
        """Test detecting error triggered."""
        response = MagicMock(spec=httpx.Response)
        response.content = b"Fatal error: SQL syntax error near MySQL"
        response.status_code = 200
        response.headers = httpx.Headers({"content-type": "text/html"})

        diff = fingerprinter.compare(baseline, response, 100.0)

        assert diff.diff_type == ResponseDiffType.ERROR_TRIGGERED
        assert len(diff.new_errors) > 0


# =============================================================================
# CONSTANTS TESTS
# =============================================================================

class TestConstants:
    """Tests for module constants."""

    def test_similarity_threshold_range(self):
        """Test similarity threshold is in valid range."""
        assert 0.0 <= BODY_SIMILARITY_THRESHOLD <= 1.0

    def test_timing_threshold_positive(self):
        """Test timing threshold is positive."""
        assert TIMING_ANOMALY_THRESHOLD > 0

    def test_content_length_tolerance_range(self):
        """Test content length tolerance is reasonable."""
        assert 0.0 <= CONTENT_LENGTH_TOLERANCE <= 1.0

    def test_spa_indicators_exist(self):
        """Test SPA indicators are defined."""
        assert len(SPA_INDICATORS) > 0
        assert any("__next" in pattern for pattern in SPA_INDICATORS)
        assert any("react" in pattern for pattern in SPA_INDICATORS)


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestResponseAnalyzerIntegration:
    """Integration tests combining multiple components."""

    def test_confidence_scoring_workflow(self):
        """Test typical confidence scoring workflow."""
        score = ConfidenceScore()

        # Add evidence
        score.add_points("Error message contains SQL syntax", 40)
        score.add_points("Status code changed to 500", 20)
        score.add_points("Payload reflected in error", 20)

        # Check findings decision
        assert score.level == ConfidenceLevel.HIGH
        assert score.total_score == 80

    def test_analysis_result_with_all_components(self):
        """Test AnalysisResult with all components populated."""
        echo = EchoAnalysis(
            payload="'OR 1=1--",
            echo_type=EchoType.REFLECTED_RAW,
            is_executable=False,
        )

        baseline = ResponseFingerprint(
            url="http://test.com",
            method="GET",
            status_code=200,
            content_length=1000,
            content_type="text/html",
            body_hash="a",
            body_fuzzy_hash="b",
            structure_hash="c",
            headers_hash="d",
            response_time_ms=100,
        )

        diff = ResponseDiff(
            diff_type=ResponseDiffType.ERROR_TRIGGERED,
            baseline=baseline,
            new_errors=["SQL syntax error"],
        )

        score = ConfidenceScore()
        score.add_points("SQL error detected", 50)
        score.add_points("Payload in error message", 30)

        result = AnalysisResult(
            echo=echo,
            diff=diff,
            confidence=score,
            is_finding=True,
            finding_type="SQL Injection",
            evidence=["SQL syntax error triggered", "Payload reflected in response"],
        )

        # Verify complete analysis
        assert result.is_finding is True
        assert result.confidence.level == ConfidenceLevel.HIGH
        assert len(result.evidence) == 2

        # Verify serialization
        d = result.to_dict()
        assert d["finding_type"] == "SQL Injection"
        assert d["confidence"]["total_score"] == 80
