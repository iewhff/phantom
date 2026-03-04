"""
Tests for utils/negative_control.py

Comprehensive tests for the Negative Control Payload System.
Tests cover:
- PayloadCategory enum
- SignalType enum
- PayloadPair dataclass
- ControlTestResult dataclass
- NegativeControlBatch dataclass
- NegativeControlPayloads class
- NegativeControlEngine class
- SmartPayloadSelector class
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from utils.negative_control import (
    # Enums
    PayloadCategory,
    SignalType,
    # Dataclasses
    PayloadPair,
    ControlTestResult,
    NegativeControlBatch,
    # Classes
    NegativeControlPayloads,
    NegativeControlEngine,
    SmartPayloadSelector,
)


class TestPayloadCategory:
    """Tests for PayloadCategory enum."""

    def test_all_categories_present(self):
        """Test that all payload categories are defined."""
        categories = {c.name for c in PayloadCategory}
        expected = {
            "SQLI_BOOLEAN",
            "SQLI_ERROR",
            "SQLI_TIME",
            "XSS",
            "CMDI",
            "SSRF",
            "LFI",
            "SSTI",
            "NOSQL",
            "XXEPATH",
        }
        assert categories == expected

    def test_unique_values(self):
        """Test that all categories have unique values."""
        values = [c.value for c in PayloadCategory]
        assert len(values) == len(set(values))


class TestSignalType:
    """Tests for SignalType enum."""

    def test_all_signal_types_present(self):
        """Test that all signal types are defined."""
        types = {t.name for t in SignalType}
        expected = {
            "NO_SIGNAL",
            "WEAK_SIGNAL",
            "STRONG_SIGNAL",
            "CONFIRMED",
        }
        assert types == expected

    def test_signal_ordering(self):
        """Test signal types are in order of severity."""
        # NO_SIGNAL < WEAK_SIGNAL < STRONG_SIGNAL < CONFIRMED
        assert SignalType.NO_SIGNAL.value < SignalType.WEAK_SIGNAL.value
        assert SignalType.WEAK_SIGNAL.value < SignalType.STRONG_SIGNAL.value
        assert SignalType.STRONG_SIGNAL.value < SignalType.CONFIRMED.value


class TestPayloadPair:
    """Tests for PayloadPair dataclass."""

    def test_creation(self):
        """Test PayloadPair creation."""
        pair = PayloadPair(
            category=PayloadCategory.SQLI_BOOLEAN,
            malicious="' OR '1'='1",
            innocent="' OR '1'='2",
            description="Classic OR-based boolean injection",
            expected_behavior="Malicious returns more data",
        )

        assert pair.category == PayloadCategory.SQLI_BOOLEAN
        assert "1'='1" in pair.malicious
        assert "1'='2" in pair.innocent
        assert pair.expected_delay_ms == 0  # Default

    def test_with_indicators(self):
        """Test PayloadPair with indicator fields."""
        pair = PayloadPair(
            category=PayloadCategory.XSS,
            malicious="<script>alert(1)</script>",
            innocent="&lt;script&gt;alert(1)&lt;/script&gt;",
            description="Basic XSS test",
            expected_behavior="Script executes vs escaped",
            malicious_indicator="<script>",
        )

        assert pair.malicious_indicator == "<script>"
        assert pair.innocent_indicator is None

    def test_time_based_pair(self):
        """Test time-based PayloadPair."""
        pair = PayloadPair(
            category=PayloadCategory.SQLI_TIME,
            malicious="' AND SLEEP(5)--",
            innocent="' AND SLEEP(0)--",
            description="MySQL SLEEP",
            expected_behavior="5 second delay",
            expected_delay_ms=5000,
        )

        assert pair.expected_delay_ms == 5000

    def test_to_dict(self):
        """Test PayloadPair to_dict method."""
        pair = PayloadPair(
            category=PayloadCategory.CMDI,
            malicious="; echo TEST",
            innocent="; echo ",
            description="Command injection",
            expected_behavior="TEST appears in output",
        )

        d = pair.to_dict()

        assert d["category"] == "cmdi"
        assert d["malicious"] == "; echo TEST"
        assert "description" in d


class TestControlTestResult:
    """Tests for ControlTestResult dataclass."""

    def test_creation(self):
        """Test ControlTestResult creation."""
        pair = PayloadPair(
            category=PayloadCategory.SQLI_BOOLEAN,
            malicious="' OR '1'='1",
            innocent="' OR '1'='2",
            description="Test",
            expected_behavior="Test",
        )

        result = ControlTestResult(
            payload_pair=pair,
            malicious_response="<html>User found</html>",
            innocent_response="<html>No user</html>",
            malicious_status=200,
            innocent_status=200,
            malicious_time_ms=100.5,
            innocent_time_ms=95.2,
            signal_type=SignalType.STRONG_SIGNAL,
            confidence=0.75,
            differences={"length_diff_ratio": 0.3},
        )

        assert result.signal_type == SignalType.STRONG_SIGNAL
        assert result.confidence == 0.75

    def test_is_signal(self):
        """Test is_signal method."""
        pair = PayloadPair(
            category=PayloadCategory.XSS,
            malicious="<script>",
            innocent="&lt;script&gt;",
            description="Test",
            expected_behavior="Test",
        )

        strong_result = ControlTestResult(
            payload_pair=pair,
            malicious_response="test",
            innocent_response="test",
            malicious_status=200,
            innocent_status=200,
            malicious_time_ms=100,
            innocent_time_ms=100,
            signal_type=SignalType.STRONG_SIGNAL,
            confidence=0.8,
            differences={},
        )

        confirmed_result = ControlTestResult(
            payload_pair=pair,
            malicious_response="test",
            innocent_response="test",
            malicious_status=200,
            innocent_status=200,
            malicious_time_ms=100,
            innocent_time_ms=100,
            signal_type=SignalType.CONFIRMED,
            confidence=0.95,
            differences={},
        )

        weak_result = ControlTestResult(
            payload_pair=pair,
            malicious_response="test",
            innocent_response="test",
            malicious_status=200,
            innocent_status=200,
            malicious_time_ms=100,
            innocent_time_ms=100,
            signal_type=SignalType.WEAK_SIGNAL,
            confidence=0.3,
            differences={},
        )

        assert strong_result.is_signal() is True
        assert confirmed_result.is_signal() is True
        assert weak_result.is_signal() is False

    def test_is_noise(self):
        """Test is_noise method."""
        pair = PayloadPair(
            category=PayloadCategory.LFI,
            malicious="../../etc/passwd",
            innocent="../../etc/nonexistent",
            description="Test",
            expected_behavior="Test",
        )

        noise_result = ControlTestResult(
            payload_pair=pair,
            malicious_response="Error",
            innocent_response="Error",
            malicious_status=404,
            innocent_status=404,
            malicious_time_ms=50,
            innocent_time_ms=50,
            signal_type=SignalType.NO_SIGNAL,
            confidence=0.0,
            differences={"content_identical": True},
        )

        assert noise_result.is_noise() is True

    def test_to_dict(self):
        """Test ControlTestResult to_dict method."""
        pair = PayloadPair(
            category=PayloadCategory.SSTI,
            malicious="{{7*7}}",
            innocent="{{7*'7'}}",
            description="Test",
            expected_behavior="Test",
        )

        result = ControlTestResult(
            payload_pair=pair,
            malicious_response="49",
            innocent_response="7777777",
            malicious_status=200,
            innocent_status=200,
            malicious_time_ms=50.123,
            innocent_time_ms=48.456,
            signal_type=SignalType.CONFIRMED,
            confidence=0.95,
            differences={"indicator_found": "49"},
        )

        d = result.to_dict()

        assert d["signal_type"] == "CONFIRMED"
        assert d["confidence"] == 0.95
        assert d["malicious_time_ms"] == 50.12  # Rounded


class TestNegativeControlBatch:
    """Tests for NegativeControlBatch dataclass."""

    def test_creation(self):
        """Test NegativeControlBatch creation."""
        batch = NegativeControlBatch(
            url="https://example.com/search",
            parameter="q",
            results=[],
            overall_signal=SignalType.NO_SIGNAL,
            overall_confidence=0.0,
            vulnerability_confirmed=False,
        )

        assert batch.url == "https://example.com/search"
        assert batch.parameter == "q"

    def test_get_signals(self):
        """Test get_signals method."""
        pair = PayloadPair(
            category=PayloadCategory.SQLI_BOOLEAN,
            malicious="test",
            innocent="test",
            description="Test",
            expected_behavior="Test",
        )

        results = [
            ControlTestResult(
                payload_pair=pair,
                malicious_response="a",
                innocent_response="b",
                malicious_status=200,
                innocent_status=200,
                malicious_time_ms=100,
                innocent_time_ms=100,
                signal_type=SignalType.NO_SIGNAL,
                confidence=0.0,
                differences={},
            ),
            ControlTestResult(
                payload_pair=pair,
                malicious_response="a",
                innocent_response="b",
                malicious_status=200,
                innocent_status=200,
                malicious_time_ms=100,
                innocent_time_ms=100,
                signal_type=SignalType.STRONG_SIGNAL,
                confidence=0.8,
                differences={},
            ),
            ControlTestResult(
                payload_pair=pair,
                malicious_response="a",
                innocent_response="b",
                malicious_status=200,
                innocent_status=200,
                malicious_time_ms=100,
                innocent_time_ms=100,
                signal_type=SignalType.CONFIRMED,
                confidence=0.95,
                differences={},
            ),
        ]

        batch = NegativeControlBatch(
            url="https://example.com/",
            parameter="id",
            results=results,
            overall_signal=SignalType.CONFIRMED,
            overall_confidence=0.85,
            vulnerability_confirmed=True,
        )

        signals = batch.get_signals()
        noise = batch.get_noise()

        assert len(signals) == 2  # STRONG_SIGNAL and CONFIRMED
        assert len(noise) == 1  # NO_SIGNAL

    def test_to_dict(self):
        """Test NegativeControlBatch to_dict method."""
        batch = NegativeControlBatch(
            url="https://example.com/api",
            parameter="user_id",
            results=[],
            overall_signal=SignalType.WEAK_SIGNAL,
            overall_confidence=0.35,
            vulnerability_confirmed=False,
        )

        d = batch.to_dict()

        assert d["url"] == "https://example.com/api"
        assert d["parameter"] == "user_id"
        assert d["overall_signal"] == "WEAK_SIGNAL"
        assert d["overall_confidence"] == 0.35
        assert d["vulnerability_confirmed"] is False


class TestNegativeControlPayloads:
    """Tests for NegativeControlPayloads class."""

    def test_sqli_boolean_pairs_exist(self):
        """Test SQLi boolean pairs exist."""
        pairs = NegativeControlPayloads.SQLI_BOOLEAN_PAIRS

        assert len(pairs) >= 5
        assert all(p.category == PayloadCategory.SQLI_BOOLEAN for p in pairs)

    def test_sqli_time_pairs_exist(self):
        """Test SQLi time-based pairs exist."""
        pairs = NegativeControlPayloads.SQLI_TIME_PAIRS

        assert len(pairs) >= 3
        assert all(p.category == PayloadCategory.SQLI_TIME for p in pairs)
        assert all(p.expected_delay_ms > 0 for p in pairs)

    def test_sqli_error_pairs_exist(self):
        """Test SQLi error-based pairs exist."""
        pairs = NegativeControlPayloads.SQLI_ERROR_PAIRS

        assert len(pairs) >= 2
        assert all(p.category == PayloadCategory.SQLI_ERROR for p in pairs)

    def test_xss_pairs_exist(self):
        """Test XSS pairs exist."""
        pairs = NegativeControlPayloads.XSS_PAIRS

        assert len(pairs) >= 3
        assert all(p.category == PayloadCategory.XSS for p in pairs)

    def test_cmdi_pairs_exist(self):
        """Test command injection pairs exist."""
        pairs = NegativeControlPayloads.CMDI_PAIRS

        assert len(pairs) >= 4
        assert all(p.category == PayloadCategory.CMDI for p in pairs)

    def test_ssrf_pairs_exist(self):
        """Test SSRF pairs exist."""
        pairs = NegativeControlPayloads.SSRF_PAIRS

        assert len(pairs) >= 3
        assert all(p.category == PayloadCategory.SSRF for p in pairs)

    def test_lfi_pairs_exist(self):
        """Test LFI pairs exist."""
        pairs = NegativeControlPayloads.LFI_PAIRS

        assert len(pairs) >= 3
        assert all(p.category == PayloadCategory.LFI for p in pairs)

    def test_ssti_pairs_exist(self):
        """Test SSTI pairs exist."""
        pairs = NegativeControlPayloads.SSTI_PAIRS

        assert len(pairs) >= 3
        assert all(p.category == PayloadCategory.SSTI for p in pairs)

    def test_nosql_pairs_exist(self):
        """Test NoSQL injection pairs exist."""
        pairs = NegativeControlPayloads.NOSQL_PAIRS

        assert len(pairs) >= 3
        assert all(p.category == PayloadCategory.NOSQL for p in pairs)

    def test_xpath_pairs_exist(self):
        """Test XPath injection pairs exist."""
        pairs = NegativeControlPayloads.XPATH_PAIRS

        assert len(pairs) >= 2
        assert all(p.category == PayloadCategory.XXEPATH for p in pairs)

    def test_get_all_pairs(self):
        """Test get_all_pairs returns all pairs."""
        all_pairs = NegativeControlPayloads.get_all_pairs()

        # Should have pairs from all categories
        categories = {p.category for p in all_pairs}
        assert PayloadCategory.SQLI_BOOLEAN in categories
        assert PayloadCategory.XSS in categories
        assert PayloadCategory.CMDI in categories
        assert len(all_pairs) >= 30  # Should have many pairs

    def test_get_pairs_by_category(self):
        """Test get_pairs_by_category method."""
        sqli_pairs = NegativeControlPayloads.get_pairs_by_category(
            PayloadCategory.SQLI_BOOLEAN
        )
        xss_pairs = NegativeControlPayloads.get_pairs_by_category(
            PayloadCategory.XSS
        )

        assert all(p.category == PayloadCategory.SQLI_BOOLEAN for p in sqli_pairs)
        assert all(p.category == PayloadCategory.XSS for p in xss_pairs)

    def test_malicious_differs_from_innocent(self):
        """Test that malicious and innocent payloads differ."""
        all_pairs = NegativeControlPayloads.get_all_pairs()

        for pair in all_pairs:
            assert pair.malicious != pair.innocent, (
                f"Malicious should differ from innocent: {pair.description}"
            )

    def test_pairs_have_descriptions(self):
        """Test all pairs have descriptions."""
        all_pairs = NegativeControlPayloads.get_all_pairs()

        for pair in all_pairs:
            assert len(pair.description) > 0
            assert len(pair.expected_behavior) > 0


class TestNegativeControlEngine:
    """Tests for NegativeControlEngine class."""

    def test_creation(self):
        """Test NegativeControlEngine creation."""
        engine = NegativeControlEngine(
            timeout=10.0,
            follow_redirects=False,
            max_redirects=3,
        )

        assert engine.timeout == 10.0
        assert engine.follow_redirects is False
        assert engine.max_redirects == 3

    def test_default_values(self):
        """Test NegativeControlEngine default values."""
        engine = NegativeControlEngine()

        assert engine.timeout == 15.0
        assert engine.follow_redirects is True
        assert engine.max_redirects == 5

    def test_thresholds(self):
        """Test engine threshold constants."""
        assert NegativeControlEngine.LENGTH_DIFF_THRESHOLD == 0.1  # 10%
        assert NegativeControlEngine.TIME_DIFF_THRESHOLD_MS == 2500  # 2.5s
        assert NegativeControlEngine.STATUS_DIFF_SIGNIFICANT is True

    def test_analyze_difference_status_diff(self):
        """Test _analyze_difference with status code difference."""
        engine = NegativeControlEngine()
        pair = PayloadPair(
            category=PayloadCategory.SQLI_BOOLEAN,
            malicious="test",
            innocent="test",
            description="Test",
            expected_behavior="Test",
        )

        differences, signal_type, confidence = engine._analyze_difference(
            malicious_response="Success",
            innocent_response="Error",
            malicious_status=200,
            innocent_status=500,
            malicious_time=100.0,
            innocent_time=100.0,
            pair=pair,
        )

        assert "status_diff" in differences
        assert differences["status_diff"]["malicious"] == 200
        assert differences["status_diff"]["innocent"] == 500

    def test_analyze_difference_time_based(self):
        """Test _analyze_difference with time-based payload."""
        engine = NegativeControlEngine()
        pair = PayloadPair(
            category=PayloadCategory.SQLI_TIME,
            malicious="SLEEP(5)",
            innocent="SLEEP(0)",
            description="Time delay",
            expected_behavior="5 second delay",
            expected_delay_ms=5000,
        )

        # Use different responses to avoid identical content penalty (-50 points)
        differences, signal_type, confidence = engine._analyze_difference(
            malicious_response="OK after delay",
            innocent_response="OK",
            malicious_status=200,
            innocent_status=200,
            malicious_time=5200.0,  # 5.2 seconds
            innocent_time=100.0,    # 0.1 seconds
            pair=pair,
        )

        assert differences.get("time_based_confirmed") is True
        # With time_based_confirmed (+50) and content_different (+15), total = 65 = CONFIRMED
        assert signal_type in {SignalType.STRONG_SIGNAL, SignalType.CONFIRMED}

    def test_analyze_difference_length_diff(self):
        """Test _analyze_difference with content length difference."""
        engine = NegativeControlEngine()
        pair = PayloadPair(
            category=PayloadCategory.SQLI_BOOLEAN,
            malicious="' OR '1'='1",
            innocent="' OR '1'='2",
            description="Boolean test",
            expected_behavior="Different result sets",
        )

        short_content = "No data"
        long_content = "User data: " + "x" * 1000

        differences, signal_type, confidence = engine._analyze_difference(
            malicious_response=long_content,
            innocent_response=short_content,
            malicious_status=200,
            innocent_status=200,
            malicious_time=100.0,
            innocent_time=100.0,
            pair=pair,
        )

        assert "length_diff_ratio" in differences
        assert differences["length_diff_ratio"] > 0.1

    def test_analyze_difference_identical_content(self):
        """Test _analyze_difference with identical content (noise)."""
        engine = NegativeControlEngine()
        pair = PayloadPair(
            category=PayloadCategory.XSS,
            malicious="<script>",
            innocent="&lt;script&gt;",
            description="XSS test",
            expected_behavior="Script vs escaped",
        )

        identical = "Sanitized output"

        differences, signal_type, confidence = engine._analyze_difference(
            malicious_response=identical,
            innocent_response=identical,
            malicious_status=200,
            innocent_status=200,
            malicious_time=50.0,
            innocent_time=50.0,
            pair=pair,
        )

        assert differences.get("content_identical") is True
        assert signal_type == SignalType.NO_SIGNAL

    def test_analyze_difference_indicator_found(self):
        """Test _analyze_difference with indicator found."""
        engine = NegativeControlEngine()
        pair = PayloadPair(
            category=PayloadCategory.CMDI,
            malicious="; echo INJECTED",
            innocent="; echo ",
            description="Command injection",
            expected_behavior="INJECTED appears",
            malicious_indicator="INJECTED",
        )

        differences, signal_type, confidence = engine._analyze_difference(
            malicious_response="Output: INJECTED",
            innocent_response="Output: ",
            malicious_status=200,
            innocent_status=200,
            malicious_time=100.0,
            innocent_time=100.0,
            pair=pair,
        )

        assert differences.get("indicator_found") == "INJECTED"
        assert signal_type in {SignalType.STRONG_SIGNAL, SignalType.CONFIRMED}

    def test_aggregate_results_empty(self):
        """Test _aggregate_results with empty list."""
        engine = NegativeControlEngine()

        signal, confidence, confirmed = engine._aggregate_results([])

        assert signal == SignalType.NO_SIGNAL
        assert confidence == 0.0
        assert confirmed is False

    def test_aggregate_results_multiple_strong(self):
        """Test _aggregate_results with multiple strong signals."""
        engine = NegativeControlEngine()
        pair = PayloadPair(
            category=PayloadCategory.SQLI_BOOLEAN,
            malicious="test",
            innocent="test",
            description="Test",
            expected_behavior="Test",
        )

        results = [
            ControlTestResult(
                payload_pair=pair,
                malicious_response="a",
                innocent_response="b",
                malicious_status=200,
                innocent_status=200,
                malicious_time_ms=100,
                innocent_time_ms=100,
                signal_type=SignalType.STRONG_SIGNAL,
                confidence=0.7,
                differences={},
            ),
            ControlTestResult(
                payload_pair=pair,
                malicious_response="a",
                innocent_response="b",
                malicious_status=200,
                innocent_status=200,
                malicious_time_ms=100,
                innocent_time_ms=100,
                signal_type=SignalType.STRONG_SIGNAL,
                confidence=0.8,
                differences={},
            ),
        ]

        signal, confidence, confirmed = engine._aggregate_results(results)

        assert signal == SignalType.CONFIRMED  # 2+ strong signals = confirmed
        assert confirmed is True


class TestSmartPayloadSelector:
    """Tests for SmartPayloadSelector class."""

    def test_select_for_numeric_param(self):
        """Test selecting pairs for numeric parameter."""
        selector = SmartPayloadSelector()

        pairs = selector.select_pairs_for_parameter(
            param_type="number",
            is_numeric=True,
            is_reflected=False,
        )

        # Should include numeric SQLi pairs
        assert len(pairs) > 0
        assert any(p.category == PayloadCategory.SQLI_BOOLEAN for p in pairs)

    def test_select_for_reflected_param(self):
        """Test selecting pairs for reflected parameter."""
        selector = SmartPayloadSelector()

        pairs = selector.select_pairs_for_parameter(
            param_type="string",
            is_numeric=False,
            is_reflected=True,
        )

        # Should include XSS pairs for reflected
        assert any(p.category == PayloadCategory.XSS for p in pairs)

    def test_select_for_url_param(self):
        """Test selecting pairs for URL-type parameter."""
        selector = SmartPayloadSelector()

        pairs = selector.select_pairs_for_parameter(
            param_type="url",
            is_numeric=False,
            is_reflected=False,
        )

        # Should include SSRF pairs
        assert any(p.category == PayloadCategory.SSRF for p in pairs)

    def test_select_for_path_param(self):
        """Test selecting pairs for path-type parameter."""
        selector = SmartPayloadSelector()

        pairs = selector.select_pairs_for_parameter(
            param_type="path",
            is_numeric=False,
            is_reflected=False,
        )

        # Should include LFI pairs
        assert any(p.category == PayloadCategory.LFI for p in pairs)

    def test_select_for_filename_param(self):
        """Test selecting pairs for filename-type parameter."""
        selector = SmartPayloadSelector()

        pairs = selector.select_pairs_for_parameter(
            param_type="filename",
            is_numeric=False,
            is_reflected=False,
        )

        # Should include LFI pairs
        assert any(p.category == PayloadCategory.LFI for p in pairs)

    def test_select_for_command_param(self):
        """Test selecting pairs for command-type parameter."""
        selector = SmartPayloadSelector()

        pairs = selector.select_pairs_for_parameter(
            param_type="command",
            is_numeric=False,
            is_reflected=False,
        )

        # Should include command injection pairs
        assert any(p.category == PayloadCategory.CMDI for p in pairs)

    def test_select_for_header_location(self):
        """Test selecting pairs for header injection."""
        selector = SmartPayloadSelector()

        pairs = selector.select_pairs_for_parameter(
            param_type="unknown",
            is_numeric=False,
            is_reflected=False,
            location="header",
        )

        # Should include command injection pairs
        assert any(p.category == PayloadCategory.CMDI for p in pairs)

    def test_select_for_template_context(self):
        """Test selecting pairs for template context."""
        selector = SmartPayloadSelector()

        pairs = selector.select_pairs_for_parameter(
            param_type="string",
            is_numeric=False,
            is_reflected=True,  # Reflected = possible SSTI
        )

        # Should include SSTI pairs when reflected
        assert any(p.category == PayloadCategory.SSTI for p in pairs)

    def test_always_includes_sqli(self):
        """Test SQLi is always included."""
        selector = SmartPayloadSelector()

        pairs = selector.select_pairs_for_parameter(
            param_type="unknown",
            is_numeric=False,
            is_reflected=False,
        )

        # SQLi should always be tested
        sqli_categories = {PayloadCategory.SQLI_BOOLEAN, PayloadCategory.SQLI_TIME}
        assert any(p.category in sqli_categories for p in pairs)

    def test_always_includes_time_based(self):
        """Test time-based SQLi is always included."""
        selector = SmartPayloadSelector()

        pairs = selector.select_pairs_for_parameter(
            param_type="string",
            is_numeric=False,
            is_reflected=False,
        )

        # Should include at least one time-based pair
        assert any(p.category == PayloadCategory.SQLI_TIME for p in pairs)


class TestPayloadPairQuality:
    """Tests for payload pair quality and coverage."""

    def test_boolean_pairs_are_logical_opposites(self):
        """Test boolean SQLi pairs are logical opposites."""
        pairs = NegativeControlPayloads.SQLI_BOOLEAN_PAIRS

        for pair in pairs:
            # Malicious should be TRUE condition, innocent FALSE
            malicious = pair.malicious.lower()
            innocent = pair.innocent.lower()

            # Common patterns: '1'='1 vs '1'='2, 1=1 vs 1=2
            if "'1'='1" in malicious:
                assert "'1'='2" in innocent
            elif "1=1" in malicious:
                assert "1=2" in innocent or "'1'='2" in innocent

    def test_time_pairs_have_matching_structure(self):
        """Test time-based pairs have matching structure."""
        pairs = NegativeControlPayloads.SQLI_TIME_PAIRS

        for pair in pairs:
            # Both should use same function, different delay
            malicious = pair.malicious.lower()
            innocent = pair.innocent.lower()

            if "sleep" in malicious:
                assert "sleep" in innocent
            if "waitfor" in malicious:
                assert "waitfor" in innocent
            if "pg_sleep" in malicious:
                assert "pg_sleep" in innocent

    def test_xss_pairs_escaped_vs_unescaped(self):
        """Test XSS pairs contrast escaped vs unescaped."""
        pairs = NegativeControlPayloads.XSS_PAIRS

        for pair in pairs:
            malicious = pair.malicious
            innocent = pair.innocent

            # Innocent should be escaped or neutered version
            if "<script>" in malicious:
                assert "<script>" not in innocent or "void" in innocent

    def test_all_pairs_have_expected_delay_for_time_based(self):
        """Test all time-based pairs have expected_delay_ms set."""
        time_pairs = (
            NegativeControlPayloads.SQLI_TIME_PAIRS +
            [p for p in NegativeControlPayloads.CMDI_PAIRS if p.expected_delay_ms > 0]
        )

        for pair in NegativeControlPayloads.SQLI_TIME_PAIRS:
            assert pair.expected_delay_ms > 0, (
                f"Time-based pair should have expected_delay_ms: {pair.description}"
            )


class TestEngineEdgeCases:
    """Tests for engine edge cases."""

    def test_analyze_null_malicious_response(self):
        """Test handling of null malicious response (timeout)."""
        engine = NegativeControlEngine()
        pair = PayloadPair(
            category=PayloadCategory.SQLI_TIME,
            malicious="SLEEP(5)",
            innocent="SLEEP(0)",
            description="Time test",
            expected_behavior="Timeout on malicious",
            expected_delay_ms=5000,
        )

        differences, signal_type, confidence = engine._analyze_difference(
            malicious_response=None,  # Timeout
            innocent_response="OK",
            malicious_status=0,
            innocent_status=200,
            malicious_time=15000.0,  # Timed out
            innocent_time=100.0,
            pair=pair,
        )

        assert differences.get("malicious_timeout") is True
        # Timeout on time-based = likely vulnerable
        assert signal_type in {SignalType.STRONG_SIGNAL, SignalType.CONFIRMED}

    def test_analyze_null_innocent_response(self):
        """Test handling of null innocent response."""
        engine = NegativeControlEngine()
        pair = PayloadPair(
            category=PayloadCategory.SQLI_BOOLEAN,
            malicious="test",
            innocent="test",
            description="Test",
            expected_behavior="Test",
        )

        differences, signal_type, confidence = engine._analyze_difference(
            malicious_response="OK",
            innocent_response=None,  # Unexpected timeout
            malicious_status=200,
            innocent_status=0,
            malicious_time=100.0,
            innocent_time=15000.0,
            pair=pair,
        )

        assert differences.get("innocent_timeout") is True

    def test_analyze_both_null_responses(self):
        """Test handling when both responses are null."""
        engine = NegativeControlEngine()
        pair = PayloadPair(
            category=PayloadCategory.CMDI,
            malicious="test",
            innocent="test",
            description="Test",
            expected_behavior="Test",
        )

        differences, signal_type, confidence = engine._analyze_difference(
            malicious_response=None,
            innocent_response=None,
            malicious_status=0,
            innocent_status=0,
            malicious_time=15000.0,
            innocent_time=15000.0,
            pair=pair,
        )

        # Both null = inconclusive
        assert isinstance(signal_type, SignalType)


class TestVersionConstants:
    """Tests for version constants."""

    def test_payloads_version(self):
        """Test NegativeControlPayloads version."""
        assert hasattr(NegativeControlPayloads, "VERSION")
        assert isinstance(NegativeControlPayloads.VERSION, str)

    def test_engine_version(self):
        """Test NegativeControlEngine version."""
        assert hasattr(NegativeControlEngine, "VERSION")
        assert isinstance(NegativeControlEngine.VERSION, str)
