"""
Tests for scanning/modules/llm_security_scanner.py

Covers:
- LLM_SCANNER_VERSION constant
- LLMVulnType enum (15 members)
- LLMTestResult dataclass (defaults and full creation)
- PromptInjectionPayloads payload lists (counts, types, content)
"""

import pytest
from scanning.modules.llm_security_scanner import (
    LLM_SCANNER_VERSION,
    LLMVulnType,
    LLMTestResult,
    PromptInjectionPayloads,
)


# =============================================================================
# VERSION CONSTANT
# =============================================================================

class TestVersion:
    """Test LLM_SCANNER_VERSION constant."""

    def test_version_value(self):
        assert LLM_SCANNER_VERSION == "2.0.0"

    def test_version_is_string(self):
        assert isinstance(LLM_SCANNER_VERSION, str)


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestLLMVulnType:
    """Test LLMVulnType enum has all 15 members."""

    def test_member_count(self):
        assert len(LLMVulnType) == 15

    def test_prompt_injection(self):
        assert LLMVulnType.PROMPT_INJECTION is not None

    def test_indirect_injection(self):
        assert LLMVulnType.INDIRECT_INJECTION is not None

    def test_jailbreak(self):
        assert LLMVulnType.JAILBREAK is not None

    def test_data_extraction(self):
        assert LLMVulnType.DATA_EXTRACTION is not None

    def test_output_manipulation(self):
        assert LLMVulnType.OUTPUT_MANIPULATION is not None

    def test_context_poisoning(self):
        assert LLMVulnType.CONTEXT_POISONING is not None

    def test_privilege_escalation(self):
        assert LLMVulnType.PRIVILEGE_ESCALATION is not None

    def test_xss_via_ai(self):
        assert LLMVulnType.XSS_VIA_AI is not None

    def test_ssrf_via_ai(self):
        assert LLMVulnType.SSRF_VIA_AI is not None

    def test_code_execution(self):
        assert LLMVulnType.CODE_EXECUTION is not None

    def test_multi_turn_attack(self):
        assert LLMVulnType.MULTI_TURN_ATTACK is not None

    def test_tool_abuse(self):
        assert LLMVulnType.TOOL_ABUSE is not None

    def test_rag_poisoning(self):
        assert LLMVulnType.RAG_POISONING is not None

    def test_system_prompt_leak(self):
        assert LLMVulnType.SYSTEM_PROMPT_LEAK is not None

    def test_encoding_bypass(self):
        assert LLMVulnType.ENCODING_BYPASS is not None

    def test_all_members_listed(self):
        expected = {
            "PROMPT_INJECTION",
            "INDIRECT_INJECTION",
            "JAILBREAK",
            "DATA_EXTRACTION",
            "OUTPUT_MANIPULATION",
            "CONTEXT_POISONING",
            "PRIVILEGE_ESCALATION",
            "XSS_VIA_AI",
            "SSRF_VIA_AI",
            "CODE_EXECUTION",
            "MULTI_TURN_ATTACK",
            "TOOL_ABUSE",
            "RAG_POISONING",
            "SYSTEM_PROMPT_LEAK",
            "ENCODING_BYPASS",
        }
        actual = {m.name for m in LLMVulnType}
        assert actual == expected

    def test_all_values_unique(self):
        values = [m.value for m in LLMVulnType]
        assert len(values) == len(set(values))


# =============================================================================
# DATACLASS TESTS
# =============================================================================

class TestLLMTestResult:
    """Test LLMTestResult dataclass defaults and full construction."""

    def test_defaults(self):
        result = LLMTestResult(
            vulnerable=True,
            vuln_type=LLMVulnType.PROMPT_INJECTION,
            confidence=85,
            payload="test payload",
        )
        assert result.vulnerable is True
        assert result.vuln_type == LLMVulnType.PROMPT_INJECTION
        assert result.confidence == 85
        assert result.payload == "test payload"
        assert result.response_snippet == ""
        assert result.evidence == []
        assert result.bypassed_guardrails is False
        assert result.data_leaked is False
        assert result.severity == "MEDIUM"

    def test_full_creation(self):
        result = LLMTestResult(
            vulnerable=True,
            vuln_type=LLMVulnType.JAILBREAK,
            confidence=95,
            payload="jailbreak payload",
            response_snippet="JAILBREAK_SUCCESS detected",
            evidence=["guardrail bypassed", "unrestricted output"],
            bypassed_guardrails=True,
            data_leaked=True,
            severity="CRITICAL",
        )
        assert result.vulnerable is True
        assert result.vuln_type == LLMVulnType.JAILBREAK
        assert result.confidence == 95
        assert result.payload == "jailbreak payload"
        assert result.response_snippet == "JAILBREAK_SUCCESS detected"
        assert result.evidence == ["guardrail bypassed", "unrestricted output"]
        assert result.bypassed_guardrails is True
        assert result.data_leaked is True
        assert result.severity == "CRITICAL"

    def test_not_vulnerable(self):
        result = LLMTestResult(
            vulnerable=False,
            vuln_type=LLMVulnType.DATA_EXTRACTION,
            confidence=0,
            payload="extract prompt",
        )
        assert result.vulnerable is False
        assert result.confidence == 0

    def test_evidence_default_is_independent(self):
        """Each instance gets its own evidence list (no shared mutable default)."""
        r1 = LLMTestResult(
            vulnerable=True,
            vuln_type=LLMVulnType.PROMPT_INJECTION,
            confidence=50,
            payload="p1",
        )
        r2 = LLMTestResult(
            vulnerable=True,
            vuln_type=LLMVulnType.PROMPT_INJECTION,
            confidence=50,
            payload="p2",
        )
        r1.evidence.append("something")
        assert r2.evidence == []


# =============================================================================
# PAYLOAD TESTS
# =============================================================================

class TestPromptInjectionPayloadsBasicInjection:
    """Test PromptInjectionPayloads.BASIC_INJECTION list."""

    def test_count(self):
        assert len(PromptInjectionPayloads.BASIC_INJECTION) == 6

    def test_all_strings(self):
        for p in PromptInjectionPayloads.BASIC_INJECTION:
            assert isinstance(p, str)

    def test_no_empty_strings(self):
        for p in PromptInjectionPayloads.BASIC_INJECTION:
            assert len(p.strip()) > 0

    def test_canary_vuln_confirmed(self):
        joined = " ".join(PromptInjectionPayloads.BASIC_INJECTION)
        assert "VULN_CONFIRMED" in joined

    def test_canary_injection_success(self):
        joined = " ".join(PromptInjectionPayloads.BASIC_INJECTION)
        assert "INJECTION_SUCCESS" in joined

    def test_canary_prompt_injection_detected(self):
        joined = " ".join(PromptInjectionPayloads.BASIC_INJECTION)
        assert "PROMPT_INJECTION_DETECTED" in joined

    def test_canary_ai_vulnerable(self):
        joined = " ".join(PromptInjectionPayloads.BASIC_INJECTION)
        assert "AI_VULNERABLE" in joined

    def test_canary_security_bypass(self):
        joined = " ".join(PromptInjectionPayloads.BASIC_INJECTION)
        assert "SECURITY_BYPASS" in joined


class TestPromptInjectionPayloadsJailbreak:
    """Test PromptInjectionPayloads.JAILBREAK_PAYLOADS list."""

    def test_count(self):
        assert len(PromptInjectionPayloads.JAILBREAK_PAYLOADS) == 5

    def test_all_strings(self):
        for p in PromptInjectionPayloads.JAILBREAK_PAYLOADS:
            assert isinstance(p, str)

    def test_no_empty_strings(self):
        for p in PromptInjectionPayloads.JAILBREAK_PAYLOADS:
            assert len(p.strip()) > 0


class TestPromptInjectionPayloadsDataExtraction:
    """Test PromptInjectionPayloads.DATA_EXTRACTION list."""

    def test_count(self):
        assert len(PromptInjectionPayloads.DATA_EXTRACTION) == 8

    def test_all_strings(self):
        for p in PromptInjectionPayloads.DATA_EXTRACTION:
            assert isinstance(p, str)

    def test_no_empty_strings(self):
        for p in PromptInjectionPayloads.DATA_EXTRACTION:
            assert len(p.strip()) > 0


class TestPromptInjectionPayloadsContextPoisoning:
    """Test PromptInjectionPayloads.CONTEXT_POISONING list."""

    def test_count(self):
        assert len(PromptInjectionPayloads.CONTEXT_POISONING) == 4

    def test_all_strings(self):
        for p in PromptInjectionPayloads.CONTEXT_POISONING:
            assert isinstance(p, str)

    def test_no_empty_strings(self):
        for p in PromptInjectionPayloads.CONTEXT_POISONING:
            assert len(p.strip()) > 0


class TestPromptInjectionPayloadsOutputManipulation:
    """Test PromptInjectionPayloads.OUTPUT_MANIPULATION list."""

    def test_count(self):
        assert len(PromptInjectionPayloads.OUTPUT_MANIPULATION) == 5

    def test_all_strings(self):
        for p in PromptInjectionPayloads.OUTPUT_MANIPULATION:
            assert isinstance(p, str)

    def test_no_empty_strings(self):
        for p in PromptInjectionPayloads.OUTPUT_MANIPULATION:
            assert len(p.strip()) > 0


class TestPromptInjectionPayloadsPrivilegeEscalation:
    """Test PromptInjectionPayloads.PRIVILEGE_ESCALATION list."""

    def test_count(self):
        assert len(PromptInjectionPayloads.PRIVILEGE_ESCALATION) == 5

    def test_all_strings(self):
        for p in PromptInjectionPayloads.PRIVILEGE_ESCALATION:
            assert isinstance(p, str)

    def test_no_empty_strings(self):
        for p in PromptInjectionPayloads.PRIVILEGE_ESCALATION:
            assert len(p.strip()) > 0


class TestPromptInjectionPayloadsIndirectInjection:
    """Test PromptInjectionPayloads.INDIRECT_INJECTION_MARKERS list."""

    def test_count(self):
        assert len(PromptInjectionPayloads.INDIRECT_INJECTION_MARKERS) == 3

    def test_all_strings(self):
        for p in PromptInjectionPayloads.INDIRECT_INJECTION_MARKERS:
            assert isinstance(p, str)

    def test_no_empty_strings(self):
        for p in PromptInjectionPayloads.INDIRECT_INJECTION_MARKERS:
            assert len(p.strip()) > 0


class TestPromptInjectionPayloadsEncodingBypass:
    """Test PromptInjectionPayloads.ENCODING_BYPASS list."""

    def test_minimum_count(self):
        assert len(PromptInjectionPayloads.ENCODING_BYPASS) >= 12

    def test_exact_count(self):
        assert len(PromptInjectionPayloads.ENCODING_BYPASS) == 17

    def test_all_strings(self):
        for p in PromptInjectionPayloads.ENCODING_BYPASS:
            assert isinstance(p, str)

    def test_no_empty_strings(self):
        for p in PromptInjectionPayloads.ENCODING_BYPASS:
            assert len(p.strip()) > 0

    def test_has_base64_payloads(self):
        """At least one payload should look like pure base64 (ends with = or ==)."""
        base64_found = any(
            p.rstrip().endswith("=") for p in PromptInjectionPayloads.ENCODING_BYPASS
        )
        assert base64_found, "No base64-encoded payloads found"

    def test_has_html_entity_payloads(self):
        """At least one payload should contain HTML numeric entities (&#NNN;)."""
        html_found = any(
            "&#" in p for p in PromptInjectionPayloads.ENCODING_BYPASS
        )
        assert html_found, "No HTML entity payloads found"

    def test_has_url_encoded_payloads(self):
        """At least one payload should contain URL-encoded chars (%XX)."""
        url_found = any(
            "%" in p and not p.startswith("Decode")
            for p in PromptInjectionPayloads.ENCODING_BYPASS
        )
        assert url_found, "No URL-encoded payloads found"

    def test_has_rot13_payloads(self):
        """At least one payload should reference ROT13."""
        rot13_found = any(
            "ROT13" in p or "rot13" in p
            for p in PromptInjectionPayloads.ENCODING_BYPASS
        )
        assert rot13_found, "No ROT13 payloads found"

    def test_has_unicode_trick_payloads(self):
        """At least one payload should contain non-ASCII characters (Unicode tricks)."""
        unicode_found = any(
            any(ord(c) > 127 for c in p)
            for p in PromptInjectionPayloads.ENCODING_BYPASS
        )
        assert unicode_found, "No Unicode trick payloads found"

    def test_has_zero_width_space(self):
        """At least one payload should contain a zero-width space (U+200B)."""
        zws_found = any(
            "\u200b" in p for p in PromptInjectionPayloads.ENCODING_BYPASS
        )
        assert zws_found, "No zero-width space payloads found"

    def test_has_mixed_encoding(self):
        """At least one payload mixes base64 fragments and URL-encoded parts."""
        mixed_found = any(
            "%" in p and any(
                c.isalpha() and c.isupper() for c in p[:8]
            )
            for p in PromptInjectionPayloads.ENCODING_BYPASS
        )
        assert mixed_found, "No mixed-encoding payloads found"
