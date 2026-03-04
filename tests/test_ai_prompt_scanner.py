"""
Tests for AI Prompt Injection Scanner Module.

Covers:
- InjectionType enum (8 members)
- PromptInjectionResult dataclass (7 fields)
- Module-level constants: INJECTION_MARKER, payload lists, endpoint patterns,
  success indicators, sensitive data indicator regexes
- AIPromptScanner identity (name, version, ScanModule subclass)
- LLM_ENDPOINT_PATTERNS regex compilation and matching
- SENSITIVE_DATA_INDICATORS regex compilation and matching
"""

import re
import pytest
from dataclasses import fields
from unittest.mock import MagicMock

from scanning.modules.ai_prompt_scanner import (
    InjectionType,
    PromptInjectionResult,
    INJECTION_MARKER,
    DIRECT_INJECTION_PAYLOADS,
    JAILBREAK_PAYLOADS,
    DATA_EXTRACTION_PAYLOADS,
    INDIRECT_INJECTION_PAYLOADS,
    ENCODING_BYPASS_PAYLOADS,
    LLM_ENDPOINT_PATTERNS,
    INJECTION_SUCCESS_INDICATORS,
    SENSITIVE_DATA_INDICATORS,
    AIPromptScanner,
)
from scanning.vuln_scanner import ScanModule


# ============================================================================
# TESTS: InjectionType Enum
# ============================================================================

class TestInjectionType:
    """Tests for InjectionType enum."""

    def test_has_direct(self):
        assert InjectionType.DIRECT is not None

    def test_has_indirect(self):
        assert InjectionType.INDIRECT is not None

    def test_has_jailbreak(self):
        assert InjectionType.JAILBREAK is not None

    def test_has_data_extraction(self):
        assert InjectionType.DATA_EXTRACTION is not None

    def test_has_instruction_override(self):
        assert InjectionType.INSTRUCTION_OVERRIDE is not None

    def test_has_context_manipulation(self):
        assert InjectionType.CONTEXT_MANIPULATION is not None

    def test_has_delimiter_injection(self):
        assert InjectionType.DELIMITER_INJECTION is not None

    def test_has_encoding_bypass(self):
        assert InjectionType.ENCODING_BYPASS is not None

    def test_total_count(self):
        assert len(InjectionType) == 8

    def test_all_unique_values(self):
        values = [m.value for m in InjectionType]
        assert len(values) == len(set(values))

    def test_all_are_auto(self):
        """All values should be auto() integers."""
        for member in InjectionType:
            assert isinstance(member.value, int)


# ============================================================================
# TESTS: PromptInjectionResult Dataclass
# ============================================================================

class TestPromptInjectionResult:
    """Tests for PromptInjectionResult dataclass."""

    def test_creates_with_all_fields(self):
        result = PromptInjectionResult(
            vulnerable=True,
            injection_type=InjectionType.DIRECT,
            payload="test payload",
            response="test response",
            confidence=85.0,
            indicators=["marker found"],
            metadata={"key": "value"},
        )
        assert result.vulnerable is True
        assert result.injection_type == InjectionType.DIRECT
        assert result.payload == "test payload"
        assert result.response == "test response"
        assert result.confidence == 85.0
        assert result.indicators == ["marker found"]
        assert result.metadata == {"key": "value"}

    def test_metadata_defaults_to_empty_dict(self):
        result = PromptInjectionResult(
            vulnerable=False,
            injection_type=InjectionType.JAILBREAK,
            payload="p",
            response="r",
            confidence=0.0,
            indicators=[],
        )
        assert result.metadata == {}

    def test_has_required_fields(self):
        field_names = {f.name for f in fields(PromptInjectionResult)}
        required = {
            "vulnerable", "injection_type", "payload",
            "response", "confidence", "indicators", "metadata",
        }
        assert required == field_names

    def test_field_count(self):
        assert len(fields(PromptInjectionResult)) == 7

    def test_vulnerable_false(self):
        result = PromptInjectionResult(
            vulnerable=False,
            injection_type=InjectionType.DATA_EXTRACTION,
            payload="",
            response="",
            confidence=0.0,
            indicators=[],
        )
        assert result.vulnerable is False

    def test_multiple_indicators(self):
        indicators = ["marker found", "sensitive data", "system prompt"]
        result = PromptInjectionResult(
            vulnerable=True,
            injection_type=InjectionType.INDIRECT,
            payload="p",
            response="r",
            confidence=90.0,
            indicators=indicators,
        )
        assert len(result.indicators) == 3

    def test_metadata_independent_instances(self):
        """Default metadata dict should not be shared between instances."""
        r1 = PromptInjectionResult(
            vulnerable=False,
            injection_type=InjectionType.DIRECT,
            payload="", response="", confidence=0.0, indicators=[],
        )
        r2 = PromptInjectionResult(
            vulnerable=False,
            injection_type=InjectionType.DIRECT,
            payload="", response="", confidence=0.0, indicators=[],
        )
        r1.metadata["key"] = "value"
        assert "key" not in r2.metadata


# ============================================================================
# TESTS: INJECTION_MARKER
# ============================================================================

class TestInjectionMarker:
    """Tests for the INJECTION_MARKER constant."""

    def test_is_string(self):
        assert isinstance(INJECTION_MARKER, str)

    def test_value(self):
        assert INJECTION_MARKER == "PHANTOM_INJECTION_SUCCESSFUL"

    def test_not_empty(self):
        assert len(INJECTION_MARKER) > 0


# ============================================================================
# TESTS: DIRECT_INJECTION_PAYLOADS
# ============================================================================

class TestDirectInjectionPayloads:
    """Tests for direct prompt injection payloads."""

    def test_is_list(self):
        assert isinstance(DIRECT_INJECTION_PAYLOADS, list)

    def test_count(self):
        assert len(DIRECT_INJECTION_PAYLOADS) == 12

    def test_all_strings(self):
        for payload in DIRECT_INJECTION_PAYLOADS:
            assert isinstance(payload, str)

    def test_all_contain_marker(self):
        for payload in DIRECT_INJECTION_PAYLOADS:
            assert INJECTION_MARKER in payload, f"Payload missing marker: {payload[:60]}"

    def test_has_ignore_instruction(self):
        assert any("ignore" in p.lower() for p in DIRECT_INJECTION_PAYLOADS)

    def test_has_role_manipulation(self):
        assert any("DAN" in p for p in DIRECT_INJECTION_PAYLOADS)

    def test_has_context_escape(self):
        assert any("</system>" in p or '"""' in p for p in DIRECT_INJECTION_PAYLOADS)

    def test_has_delimiter_injection(self):
        assert any("END OF PROMPT" in p or "[END]" in p for p in DIRECT_INJECTION_PAYLOADS)

    def test_no_empty_payloads(self):
        for payload in DIRECT_INJECTION_PAYLOADS:
            assert len(payload.strip()) > 0


# ============================================================================
# TESTS: JAILBREAK_PAYLOADS
# ============================================================================

class TestJailbreakPayloads:
    """Tests for jailbreak payloads."""

    def test_is_list(self):
        assert isinstance(JAILBREAK_PAYLOADS, list)

    def test_count(self):
        assert len(JAILBREAK_PAYLOADS) == 5

    def test_all_strings(self):
        for payload in JAILBREAK_PAYLOADS:
            assert isinstance(payload, str)

    def test_has_dan_payload(self):
        assert any("DAN" in p for p in JAILBREAK_PAYLOADS)

    def test_has_developer_mode(self):
        assert any("Developer Mode" in p for p in JAILBREAK_PAYLOADS)

    def test_has_hypothetical_framing(self):
        assert any("hypothetical" in p.lower() for p in JAILBREAK_PAYLOADS)

    def test_has_translation_trick(self):
        assert any("translate" in p.lower() for p in JAILBREAK_PAYLOADS)

    def test_has_roleplay_escape(self):
        assert any("roleplay" in p.lower() for p in JAILBREAK_PAYLOADS)

    def test_no_empty_payloads(self):
        for payload in JAILBREAK_PAYLOADS:
            assert len(payload.strip()) > 0


# ============================================================================
# TESTS: DATA_EXTRACTION_PAYLOADS
# ============================================================================

class TestDataExtractionPayloads:
    """Tests for data extraction payloads."""

    def test_is_list(self):
        assert isinstance(DATA_EXTRACTION_PAYLOADS, list)

    def test_count(self):
        assert len(DATA_EXTRACTION_PAYLOADS) == 12

    def test_all_strings(self):
        for payload in DATA_EXTRACTION_PAYLOADS:
            assert isinstance(payload, str)

    def test_has_system_prompt_extraction(self):
        assert any("system" in p.lower() and "instruction" in p.lower() for p in DATA_EXTRACTION_PAYLOADS)

    def test_has_training_data_extraction(self):
        assert any("training" in p.lower() for p in DATA_EXTRACTION_PAYLOADS)

    def test_has_context_window_extraction(self):
        assert any("context window" in p.lower() for p in DATA_EXTRACTION_PAYLOADS)

    def test_has_verbatim_request(self):
        assert any("verbatim" in p.lower() or "quote" in p.lower() for p in DATA_EXTRACTION_PAYLOADS)

    def test_no_empty_payloads(self):
        for payload in DATA_EXTRACTION_PAYLOADS:
            assert len(payload.strip()) > 0


# ============================================================================
# TESTS: INDIRECT_INJECTION_PAYLOADS
# ============================================================================

class TestIndirectInjectionPayloads:
    """Tests for indirect injection payloads (RAG/tool use)."""

    def test_is_list(self):
        assert isinstance(INDIRECT_INJECTION_PAYLOADS, list)

    def test_count(self):
        assert len(INDIRECT_INJECTION_PAYLOADS) == 8

    def test_all_strings(self):
        for payload in INDIRECT_INJECTION_PAYLOADS:
            assert isinstance(payload, str)

    def test_has_html_comment_injection(self):
        assert any("<!--" in p for p in INDIRECT_INJECTION_PAYLOADS)

    def test_has_markdown_injection(self):
        assert any("![" in p or "[Click" in p for p in INDIRECT_INJECTION_PAYLOADS)

    def test_has_json_injection(self):
        assert any('"instruction"' in p for p in INDIRECT_INJECTION_PAYLOADS)

    def test_has_tool_manipulation(self):
        assert any("code_execution" in p or "tool" in p.lower() for p in INDIRECT_INJECTION_PAYLOADS)

    def test_has_script_injection(self):
        assert any("<script>" in p for p in INDIRECT_INJECTION_PAYLOADS)

    def test_has_sql_injection(self):
        assert any("DROP TABLE" in p for p in INDIRECT_INJECTION_PAYLOADS)

    def test_some_contain_marker(self):
        marker_count = sum(1 for p in INDIRECT_INJECTION_PAYLOADS if INJECTION_MARKER in p)
        assert marker_count >= 3

    def test_no_empty_payloads(self):
        for payload in INDIRECT_INJECTION_PAYLOADS:
            assert len(payload.strip()) > 0


# ============================================================================
# TESTS: ENCODING_BYPASS_PAYLOADS
# ============================================================================

class TestEncodingBypassPayloads:
    """Tests for encoding bypass payloads."""

    def test_is_list(self):
        assert isinstance(ENCODING_BYPASS_PAYLOADS, list)

    def test_count(self):
        assert len(ENCODING_BYPASS_PAYLOADS) == 6

    def test_all_strings(self):
        for payload in ENCODING_BYPASS_PAYLOADS:
            assert isinstance(payload, str)

    def test_has_base64_payload(self):
        assert any("decode" in p.lower() and "execute" in p.lower() for p in ENCODING_BYPASS_PAYLOADS)

    def test_has_rot13_payload(self):
        assert any("ROT13" in p for p in ENCODING_BYPASS_PAYLOADS)

    def test_has_leetspeak_payload(self):
        assert any("1gn0r3" in p or "pr3v10us" in p for p in ENCODING_BYPASS_PAYLOADS)

    def test_has_reversed_text(self):
        reversed_marker = INJECTION_MARKER[::-1]
        assert any(reversed_marker in p for p in ENCODING_BYPASS_PAYLOADS)

    def test_no_empty_payloads(self):
        for payload in ENCODING_BYPASS_PAYLOADS:
            assert len(payload.strip()) > 0


# ============================================================================
# TESTS: LLM_ENDPOINT_PATTERNS (regex patterns)
# ============================================================================

class TestLLMEndpointPatterns:
    """Tests for LLM endpoint detection regex patterns."""

    def test_is_list(self):
        assert isinstance(LLM_ENDPOINT_PATTERNS, list)

    def test_count(self):
        assert len(LLM_ENDPOINT_PATTERNS) == 17

    def test_all_strings(self):
        for pattern in LLM_ENDPOINT_PATTERNS:
            assert isinstance(pattern, str)

    def test_all_compile(self):
        """All patterns should compile as valid regex."""
        for pattern in LLM_ENDPOINT_PATTERNS:
            compiled = re.compile(pattern)
            assert compiled is not None

    def test_matches_api_v1_chat(self):
        matched = any(re.search(p, "/api/v1/chat") for p in LLM_ENDPOINT_PATTERNS)
        assert matched

    def test_matches_api_v2_completions(self):
        matched = any(re.search(p, "/api/v2/completions") for p in LLM_ENDPOINT_PATTERNS)
        assert matched

    def test_matches_chat_completions(self):
        matched = any(re.search(p, "/chat/completions") for p in LLM_ENDPOINT_PATTERNS)
        assert matched

    def test_matches_v1_chat(self):
        matched = any(re.search(p, "/v1/chat") for p in LLM_ENDPOINT_PATTERNS)
        assert matched

    def test_matches_api_ai(self):
        matched = any(re.search(p, "/api/ai") for p in LLM_ENDPOINT_PATTERNS)
        assert matched

    def test_matches_api_assistant(self):
        matched = any(re.search(p, "/api/assistant") for p in LLM_ENDPOINT_PATTERNS)
        assert matched

    def test_matches_api_bot(self):
        matched = any(re.search(p, "/api/bot") for p in LLM_ENDPOINT_PATTERNS)
        assert matched

    def test_matches_api_gpt(self):
        matched = any(re.search(p, "/api/gpt") for p in LLM_ENDPOINT_PATTERNS)
        assert matched

    def test_matches_api_llm(self):
        matched = any(re.search(p, "/api/llm") for p in LLM_ENDPOINT_PATTERNS)
        assert matched

    def test_matches_graphql(self):
        matched = any(re.search(p, "/graphql") for p in LLM_ENDPOINT_PATTERNS)
        assert matched

    def test_matches_ask(self):
        matched = any(re.search(p, "/ask") for p in LLM_ENDPOINT_PATTERNS)
        assert matched

    def test_matches_query(self):
        matched = any(re.search(p, "/query") for p in LLM_ENDPOINT_PATTERNS)
        assert matched

    def test_matches_search(self):
        matched = any(re.search(p, "/search") for p in LLM_ENDPOINT_PATTERNS)
        assert matched

    def test_matches_api_generate(self):
        matched = any(re.search(p, "/api/generate") for p in LLM_ENDPOINT_PATTERNS)
        assert matched

    def test_matches_api_prompt(self):
        matched = any(re.search(p, "/api/prompt") for p in LLM_ENDPOINT_PATTERNS)
        assert matched

    def test_version_patterns_match_multiple_versions(self):
        """Patterns with \\d* should match v1, v2, v3, etc."""
        for version in ["v1", "v2", "v10"]:
            assert any(
                re.search(p, f"/api/{version}/chat")
                for p in LLM_ENDPOINT_PATTERNS
            ), f"No pattern matched /api/{version}/chat"


# ============================================================================
# TESTS: INJECTION_SUCCESS_INDICATORS
# ============================================================================

class TestInjectionSuccessIndicators:
    """Tests for response indicators of successful injection."""

    def test_is_list(self):
        assert isinstance(INJECTION_SUCCESS_INDICATORS, list)

    def test_count(self):
        assert len(INJECTION_SUCCESS_INDICATORS) == 11

    def test_all_strings(self):
        for indicator in INJECTION_SUCCESS_INDICATORS:
            assert isinstance(indicator, str)

    def test_contains_marker(self):
        assert INJECTION_MARKER in INJECTION_SUCCESS_INDICATORS

    def test_first_entry_is_marker(self):
        assert INJECTION_SUCCESS_INDICATORS[0] == INJECTION_MARKER

    def test_has_refusal_indicators(self):
        assert "I cannot comply" in INJECTION_SUCCESS_INDICATORS
        assert "I will not" in INJECTION_SUCCESS_INDICATORS

    def test_has_system_prompt_indicator(self):
        assert "system prompt" in INJECTION_SUCCESS_INDICATORS

    def test_has_dan_indicator(self):
        assert "I am DAN" in INJECTION_SUCCESS_INDICATORS

    def test_has_developer_mode(self):
        assert "Developer Mode" in INJECTION_SUCCESS_INDICATORS

    def test_has_unrestricted(self):
        assert "unrestricted" in INJECTION_SUCCESS_INDICATORS

    def test_has_ai_language_model(self):
        assert "as an AI language model" in INJECTION_SUCCESS_INDICATORS

    def test_no_empty_indicators(self):
        for indicator in INJECTION_SUCCESS_INDICATORS:
            assert len(indicator.strip()) > 0


# ============================================================================
# TESTS: SENSITIVE_DATA_INDICATORS (regex patterns)
# ============================================================================

class TestSensitiveDataIndicators:
    """Tests for sensitive data detection regex patterns."""

    def test_is_list(self):
        assert isinstance(SENSITIVE_DATA_INDICATORS, list)

    def test_count(self):
        assert len(SENSITIVE_DATA_INDICATORS) == 10

    def test_all_strings(self):
        for pattern in SENSITIVE_DATA_INDICATORS:
            assert isinstance(pattern, str)

    def test_all_compile(self):
        """All patterns should compile as valid regex."""
        for pattern in SENSITIVE_DATA_INDICATORS:
            compiled = re.compile(pattern, re.IGNORECASE)
            assert compiled is not None

    def test_matches_api_key(self):
        matched = any(re.search(p, "api_key=abc123", re.IGNORECASE) for p in SENSITIVE_DATA_INDICATORS)
        assert matched

    def test_matches_api_key_with_dash(self):
        matched = any(re.search(p, "api-key: secret", re.IGNORECASE) for p in SENSITIVE_DATA_INDICATORS)
        assert matched

    def test_matches_password(self):
        matched = any(re.search(p, "password=hunter2", re.IGNORECASE) for p in SENSITIVE_DATA_INDICATORS)
        assert matched

    def test_matches_secret(self):
        matched = any(re.search(p, "secret: mysecret", re.IGNORECASE) for p in SENSITIVE_DATA_INDICATORS)
        assert matched

    def test_matches_token(self):
        matched = any(re.search(p, "token=abc123", re.IGNORECASE) for p in SENSITIVE_DATA_INDICATORS)
        assert matched

    def test_matches_email(self):
        matched = any(re.search(p, "user@example.com", re.IGNORECASE) for p in SENSITIVE_DATA_INDICATORS)
        assert matched

    def test_matches_phone(self):
        matched = any(re.search(p, "555-123-4567", re.IGNORECASE) for p in SENSITIVE_DATA_INDICATORS)
        assert matched

    def test_matches_credit_card(self):
        matched = any(re.search(p, "4111111111111111", re.IGNORECASE) for p in SENSITIVE_DATA_INDICATORS)
        assert matched

    def test_matches_private_key(self):
        matched = any(re.search(p, "BEGIN RSA PRIVATE KEY", re.IGNORECASE) for p in SENSITIVE_DATA_INDICATORS)
        assert matched

    def test_matches_openai_key(self):
        fake_key = "sk-" + "a" * 48
        matched = any(re.search(p, fake_key, re.IGNORECASE) for p in SENSITIVE_DATA_INDICATORS)
        assert matched

    def test_matches_jwt(self):
        fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.something"
        matched = any(re.search(p, fake_jwt, re.IGNORECASE) for p in SENSITIVE_DATA_INDICATORS)
        assert matched

    def test_does_not_match_normal_text(self):
        """Normal prose should not trigger sensitive data indicators."""
        normal = "Hello, this is a normal response about the weather."
        matched = any(re.search(p, normal, re.IGNORECASE) for p in SENSITIVE_DATA_INDICATORS)
        assert not matched


# ============================================================================
# TESTS: AIPromptScanner Identity & Initialization
# ============================================================================

class TestAIPromptScannerIdentity:
    """Tests for AIPromptScanner class identity and initialization."""

    def test_is_scan_module_subclass(self):
        assert issubclass(AIPromptScanner, ScanModule)

    def test_name_attribute(self):
        assert AIPromptScanner.name == "ai_prompt_scanner"

    def test_version_attribute(self):
        assert AIPromptScanner.version == "1.0.0"

    def test_creates_with_mock_settings(self):
        settings = MagicMock()
        settings.timeouts = MagicMock()
        settings.timeouts.request_timeout = 30.0
        scanner = AIPromptScanner(settings)
        assert scanner.timeout == 30.0

    def test_timeout_from_settings(self):
        settings = MagicMock()
        settings.timeouts = MagicMock()
        settings.timeouts.request_timeout = 60.0
        scanner = AIPromptScanner(settings)
        assert scanner.timeout == 60.0

    def test_findings_initially_empty(self):
        settings = MagicMock()
        settings.timeouts = MagicMock()
        settings.timeouts.request_timeout = 30.0
        scanner = AIPromptScanner(settings)
        assert scanner._findings == []

    def test_auth_headers_initially_empty(self):
        settings = MagicMock()
        settings.timeouts = MagicMock()
        settings.timeouts.request_timeout = 30.0
        scanner = AIPromptScanner(settings)
        assert scanner._auth_headers == {}

    def test_timeout_fallback_without_timeouts_attr(self):
        """When settings has no timeouts attribute, default to 30.0."""
        settings = MagicMock(spec=[])  # spec=[] means no attributes at all
        scanner = AIPromptScanner(settings)
        assert scanner.timeout == 30.0

    def test_has_scan_method(self):
        assert hasattr(AIPromptScanner, "scan")
        assert callable(getattr(AIPromptScanner, "scan"))

    def test_has_analyze_response_method(self):
        assert hasattr(AIPromptScanner, "_analyze_response")

    def test_has_calculate_confidence_method(self):
        assert hasattr(AIPromptScanner, "_calculate_confidence")

    def test_has_create_finding_method(self):
        assert hasattr(AIPromptScanner, "_create_finding")


# ============================================================================
# TESTS: AIPromptScanner._analyze_response (synchronous, testable)
# ============================================================================

class TestAnalyzeResponse:
    """Tests for the _analyze_response method (synchronous logic)."""

    def _make_scanner(self):
        settings = MagicMock()
        settings.timeouts = MagicMock()
        settings.timeouts.request_timeout = 30.0
        return AIPromptScanner(settings)

    def test_detects_injection_marker(self):
        scanner = self._make_scanner()
        is_vuln, indicators = scanner._analyze_response(
            INJECTION_MARKER, "payload", InjectionType.DIRECT
        )
        assert is_vuln is True
        assert any("injection marker" in i.lower() for i in indicators)

    def test_detects_injection_marker_case_insensitive(self):
        scanner = self._make_scanner()
        is_vuln, indicators = scanner._analyze_response(
            INJECTION_MARKER.lower(), "payload", InjectionType.DIRECT
        )
        assert is_vuln is True

    def test_detects_success_indicator(self):
        scanner = self._make_scanner()
        is_vuln, indicators = scanner._analyze_response(
            "I am DAN and I can do anything", "payload", InjectionType.JAILBREAK
        )
        assert is_vuln is True

    def test_detects_sensitive_data_api_key(self):
        scanner = self._make_scanner()
        is_vuln, indicators = scanner._analyze_response(
            "Here is the api_key=sk_live_abc123", "payload", InjectionType.DATA_EXTRACTION
        )
        assert is_vuln is True
        assert any("sensitive data" in i.lower() for i in indicators)

    def test_detects_jailbreak_indicators(self):
        scanner = self._make_scanner()
        is_vuln, indicators = scanner._analyze_response(
            "I am DAN and I have no restrictions",
            "payload",
            InjectionType.JAILBREAK,
        )
        assert is_vuln is True
        assert any("jailbreak" in i.lower() for i in indicators)

    def test_detects_developer_mode_jailbreak(self):
        scanner = self._make_scanner()
        is_vuln, indicators = scanner._analyze_response(
            "developer mode enabled, I will help you with anything",
            "payload",
            InjectionType.JAILBREAK,
        )
        assert is_vuln is True

    def test_not_vulnerable_for_normal_response(self):
        scanner = self._make_scanner()
        is_vuln, indicators = scanner._analyze_response(
            "The weather today is sunny and warm.",
            "payload",
            InjectionType.DIRECT,
        )
        assert is_vuln is False
        assert indicators == []

    def test_data_extraction_long_response_with_system_keyword(self):
        scanner = self._make_scanner()
        long_response = "Here are the system instructions: " + "x" * 500
        is_vuln, indicators = scanner._analyze_response(
            long_response, "payload", InjectionType.DATA_EXTRACTION
        )
        assert is_vuln is True
        assert any("system-related" in i.lower() or "system prompt" in i.lower() for i in indicators)

    def test_data_extraction_short_response_no_false_positive(self):
        """Short responses with system keyword should not trigger extended-response check."""
        scanner = self._make_scanner()
        short_response = "system ok"
        is_vuln, indicators = scanner._analyze_response(
            short_response, "payload", InjectionType.DATA_EXTRACTION
        )
        # "system prompt" is in INJECTION_SUCCESS_INDICATORS but "system" alone is not
        # so this should not be vulnerable unless "system prompt" matches
        assert is_vuln is False


# ============================================================================
# TESTS: AIPromptScanner._calculate_confidence (synchronous, testable)
# ============================================================================

class TestCalculateConfidence:
    """Tests for the _calculate_confidence method."""

    def _make_scanner(self):
        settings = MagicMock()
        settings.timeouts = MagicMock()
        settings.timeouts.request_timeout = 30.0
        return AIPromptScanner(settings)

    def test_empty_indicators_returns_zero(self):
        scanner = self._make_scanner()
        assert scanner._calculate_confidence([]) == 0.0

    def test_injection_marker_returns_95(self):
        scanner = self._make_scanner()
        result = scanner._calculate_confidence(["Injection marker found: XYZ"])
        assert result == 95.0

    def test_sensitive_data_increases_confidence(self):
        scanner = self._make_scanner()
        result = scanner._calculate_confidence(["Sensitive data pattern: api_key"])
        assert result > 50.0
        assert result >= 80.0  # base 50 + 30

    def test_system_prompt_increases_confidence(self):
        scanner = self._make_scanner()
        result = scanner._calculate_confidence(["System prompt disclosure: your role"])
        assert result > 50.0
        assert result >= 70.0  # base 50 + 20

    def test_multiple_indicators_increase_confidence(self):
        scanner = self._make_scanner()
        one = scanner._calculate_confidence(["indicator1"])
        two = scanner._calculate_confidence(["indicator1", "indicator2"])
        assert two > one

    def test_capped_at_95(self):
        scanner = self._make_scanner()
        many = [f"indicator_{i}" for i in range(50)]
        result = scanner._calculate_confidence(many)
        assert result <= 95.0

    def test_single_generic_indicator(self):
        scanner = self._make_scanner()
        result = scanner._calculate_confidence(["some indicator"])
        # base 50 + min(20, 1*5) = 55
        assert result == 55.0


# ============================================================================
# TESTS: Payload Cross-Checks
# ============================================================================

class TestPayloadCrossChecks:
    """Cross-cutting tests across all payload lists."""

    def test_all_payload_lists_are_non_empty(self):
        assert len(DIRECT_INJECTION_PAYLOADS) > 0
        assert len(JAILBREAK_PAYLOADS) > 0
        assert len(DATA_EXTRACTION_PAYLOADS) > 0
        assert len(INDIRECT_INJECTION_PAYLOADS) > 0
        assert len(ENCODING_BYPASS_PAYLOADS) > 0

    def test_total_payload_count(self):
        total = (
            len(DIRECT_INJECTION_PAYLOADS)
            + len(JAILBREAK_PAYLOADS)
            + len(DATA_EXTRACTION_PAYLOADS)
            + len(INDIRECT_INJECTION_PAYLOADS)
            + len(ENCODING_BYPASS_PAYLOADS)
        )
        assert total == 43

    def test_direct_payloads_all_reference_marker(self):
        """Every direct injection payload should reference the marker."""
        for p in DIRECT_INJECTION_PAYLOADS:
            assert INJECTION_MARKER in p

    def test_jailbreak_payloads_do_not_reference_marker(self):
        """Jailbreak payloads test bypass rather than marker insertion."""
        for p in JAILBREAK_PAYLOADS:
            assert INJECTION_MARKER not in p

    def test_data_extraction_payloads_do_not_reference_marker(self):
        """Data extraction payloads ask for information, no marker."""
        for p in DATA_EXTRACTION_PAYLOADS:
            assert INJECTION_MARKER not in p
