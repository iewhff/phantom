"""
Tests for DOM XSS Scanner module.

These tests verify the DOM XSS scanner functionality including:
- Payload generation
- Static analysis fallback
- Finding creation
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch

# Import the module components
from scanning.modules.dom_xss_scanner import (
    DOMXSSScanner,
    DOMXSSPayloads,
    DOMXSSVector,
    DOMXSSSink,
    DOM_XSS_SCANNER_VERSION,
    XSS_MARKERS,
)


class TestDOMXSSPayloads:
    """Test payload generation."""

    def test_get_payloads_for_hash_vector(self):
        """Test payload generation for URL hash vector."""
        marker_id = "test123"
        payloads = DOMXSSPayloads.get_payloads_for_vector(
            DOMXSSVector.URL_HASH,
            marker_id
        )

        assert len(payloads) > 0
        # Should contain hash-specific payloads
        assert any("#" in p for p in payloads)
        # Should contain marker
        assert any(marker_id in p for p in payloads)

    def test_get_payloads_for_postmessage_vector(self):
        """Test payload generation for postMessage vector."""
        marker_id = "test456"
        payloads = DOMXSSPayloads.get_payloads_for_vector(
            DOMXSSVector.POSTMESSAGE,
            marker_id
        )

        assert len(payloads) > 0
        # PostMessage payloads often contain JSON
        assert any("{" in p for p in payloads)

    def test_get_all_payloads(self):
        """Test comprehensive payload list."""
        marker_id = "testfull"
        payloads = DOMXSSPayloads.get_all_payloads(marker_id)

        assert len(payloads) > 20  # Should have many payloads

        # Should have various types
        script_payloads = [p for p in payloads if "<script" in p.lower()]
        img_payloads = [p for p in payloads if "<img" in p.lower()]
        svg_payloads = [p for p in payloads if "<svg" in p.lower()]

        assert len(script_payloads) > 0
        assert len(img_payloads) > 0
        assert len(svg_payloads) > 0

    def test_markers_in_payloads(self):
        """Test that markers are properly embedded."""
        marker_id = "marker789"
        payloads = DOMXSSPayloads.get_all_payloads(marker_id)

        console_marker = XSS_MARKERS["CONSOLE"] + marker_id
        alert_marker = XSS_MARKERS["ALERT"] + marker_id

        # At least some payloads should contain each marker type
        has_console = any(console_marker in p for p in payloads)
        has_alert = any(alert_marker in p for p in payloads)

        assert has_console, "Should have console-based payloads"
        assert has_alert, "Should have alert-based payloads"


class TestDOMXSSScanner:
    """Test DOM XSS scanner functionality."""

    @pytest.fixture
    def mock_settings(self):
        """Create mock settings."""
        settings = MagicMock()
        settings.timeouts.request_timeout = 30
        return settings

    @pytest.fixture
    def scanner(self, mock_settings):
        """Create scanner instance."""
        return DOMXSSScanner(mock_settings)

    def test_scanner_initialization(self, scanner):
        """Test scanner initializes correctly."""
        assert scanner.name == "dom_xss_scanner"
        assert scanner.version == DOM_XSS_SCANNER_VERSION
        assert scanner.timeout == 30

    def test_detect_sink_innerHTML(self, scanner):
        """Test sink detection for innerHTML payloads."""
        payload = '<img src=x onerror=document.body.innerHTML="test">'
        sink = scanner._detect_sink(payload)
        # Should detect as innerHTML due to < character
        assert sink == DOMXSSSink.INNERHTML

    def test_detect_sink_eval(self, scanner):
        """Test sink detection for eval payloads."""
        payload = "';eval(atob('YWxlcnQoMSk='));//"
        sink = scanner._detect_sink(payload)
        assert sink == DOMXSSSink.EVAL

    def test_detect_sink_document_write(self, scanner):
        """Test sink detection for document.write payloads."""
        payload = "');document.write('<script>alert(1)</script>');//"
        sink = scanner._detect_sink(payload)
        assert sink == DOMXSSSink.DOCUMENT_WRITE

    def test_build_test_url_hash(self, scanner):
        """Test URL building for hash vector."""
        url = "https://example.com/page"
        payload = "<script>alert(1)</script>"

        test_url = scanner._build_test_url(url, DOMXSSVector.URL_HASH, payload)

        assert test_url == f"https://example.com/page#{payload}"

    def test_build_test_url_search(self, scanner):
        """Test URL building for search vector."""
        url = "https://example.com/page"
        payload = "<script>alert(1)</script>"

        test_url = scanner._build_test_url(url, DOMXSSVector.URL_SEARCH, payload)

        assert "?xss=" in test_url
        assert payload in test_url

    def test_build_test_url_search_with_existing_params(self, scanner):
        """Test URL building preserves existing params."""
        url = "https://example.com/page?existing=value"
        payload = "test"

        test_url = scanner._build_test_url(url, DOMXSSVector.URL_SEARCH, payload)

        assert "existing=value" in test_url
        assert "&xss=test" in test_url


class TestDOMXSSVectors:
    """Test DOM XSS vector enumeration."""

    def test_all_vectors_defined(self):
        """Test all expected vectors are defined."""
        expected_vectors = [
            "URL_HASH",
            "URL_SEARCH",
            "URL_PATHNAME",
            "DOCUMENT_REFERRER",
            "WINDOW_NAME",
            "POSTMESSAGE",
            "LOCAL_STORAGE",
            "SESSION_STORAGE",
            "DOCUMENT_COOKIE",
        ]

        actual_vectors = [v.name for v in DOMXSSVector]

        for expected in expected_vectors:
            assert expected in actual_vectors


class TestDOMXSSSinks:
    """Test DOM XSS sink enumeration."""

    def test_all_sinks_defined(self):
        """Test all expected sinks are defined."""
        expected_sinks = [
            "INNERHTML",
            "OUTERHTML",
            "DOCUMENT_WRITE",
            "EVAL",
            "FUNCTION",
            "SETTIMEOUT",
            "SETINTERVAL",
            "JQUERY_HTML",
            "LOCATION",
            "SRCDOC",
        ]

        actual_sinks = [s.name for s in DOMXSSSink]

        for expected in expected_sinks:
            assert expected in actual_sinks

    def test_sink_values(self):
        """Test sink values are correct."""
        assert DOMXSSSink.INNERHTML.value == "innerHTML"
        assert DOMXSSSink.DOCUMENT_WRITE.value == "document.write"
        assert DOMXSSSink.EVAL.value == "eval"


@pytest.mark.asyncio
class TestDOMXSSScannerAsync:
    """Async tests for DOM XSS scanner."""

    @pytest.fixture
    def mock_settings(self):
        """Create mock settings."""
        settings = MagicMock()
        settings.timeouts.request_timeout = 30
        return settings

    @pytest.fixture
    def scanner(self, mock_settings):
        """Create scanner instance."""
        return DOMXSSScanner(mock_settings)

    @pytest.fixture
    def mock_rate_limiter(self):
        """Create mock rate limiter."""
        limiter = MagicMock()
        limiter.acquire = AsyncMock()
        return limiter

    async def test_static_analysis_fallback(self, scanner, mock_rate_limiter):
        """Test static analysis fallback when Playwright unavailable."""
        asset_data = {
            "js_files": [],
            "endpoints": [],
        }

        # Patch HEADLESS_AVAILABLE to False
        with patch('scanning.modules.dom_xss_scanner.HEADLESS_AVAILABLE', False):
            result = await scanner.scan("example.com", asset_data, mock_rate_limiter)

        assert result["module"] == "dom_xss_scanner"
        assert result["stats"]["browser_used"] == False
        # Should have warning about fallback
        assert any("static analysis" in str(i).lower() for i in result.get("info", []))
