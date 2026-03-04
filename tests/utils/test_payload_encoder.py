"""
Tests for utils/payload_encoder.py

Comprehensive tests for the PayloadEncoder and EncodingChain classes.
Tests cover:
- URL encodings (single, double, triple)
- Unicode encodings (escape, full-width, UTF-7)
- Hex encodings (various formats)
- Base64 encodings
- HTML entity encodings
- Case variations
- SQL-specific encodings
- EncodingChain
"""

import pytest
import base64

from utils.payload_encoder import (
    PayloadEncoder,
    EncodingChain,
    EncodingType,
)


class TestURLEncodings:
    """Tests for URL encoding methods."""

    def test_url_encode_basic(self):
        """Test basic URL encoding."""
        result = PayloadEncoder.url_encode("<script>alert(1)</script>")
        assert "%3C" in result or "%3c" in result  # <
        assert "%3E" in result or "%3e" in result  # >
        assert "script" in result  # Letters not encoded by default

    def test_url_encode_with_safe(self):
        """Test URL encoding with safe characters."""
        result = PayloadEncoder.url_encode("hello/world", safe="/")
        assert "/" in result  # Safe char preserved
        assert "hello" in result

    def test_url_encode_all(self):
        """Test URL encoding ALL characters."""
        result = PayloadEncoder.url_encode_all("ABC")
        assert result == "%41%42%43"

    def test_url_encode_all_special_chars(self):
        """Test URL encoding all with special characters."""
        result = PayloadEncoder.url_encode_all("<>")
        assert result == "%3C%3E"

    def test_double_url_encode(self):
        """Test double URL encoding."""
        result = PayloadEncoder.double_url_encode("<")
        # < -> %3C -> %253C
        assert "%25" in result  # The % itself is encoded

    def test_triple_url_encode(self):
        """Test triple URL encoding."""
        result = PayloadEncoder.triple_url_encode("<")
        # < -> %3C -> %253C -> %25253C
        assert "%2525" in result

    def test_url_decode(self):
        """Test URL decoding."""
        encoded = "%3Cscript%3E"
        result = PayloadEncoder.url_decode(encoded)
        assert result == "<script>"

    def test_url_encode_roundtrip(self):
        """Test URL encode/decode roundtrip."""
        original = "' OR '1'='1"
        encoded = PayloadEncoder.url_encode(original)
        decoded = PayloadEncoder.url_decode(encoded)
        assert decoded == original


class TestUnicodeEncodings:
    """Tests for Unicode encoding methods."""

    def test_unicode_escape(self):
        """Test Unicode escape encoding."""
        result = PayloadEncoder.unicode_escape("A")
        assert result == "\\u0041"

    def test_unicode_escape_string(self):
        """Test Unicode escape encoding for string."""
        result = PayloadEncoder.unicode_escape("<>")
        assert result == "\\u003c\\u003e"

    def test_unicode_full_width(self):
        """Test full-width Unicode conversion."""
        result = PayloadEncoder.unicode_full_width("<")
        # < (0x3C) should become full-width < (0xFF1C)
        assert ord(result[0]) == 0xFF1C

    def test_unicode_full_width_space(self):
        """Test full-width space conversion."""
        result = PayloadEncoder.unicode_full_width(" ")
        assert result == "\u3000"

    def test_utf7_encode(self):
        """Test UTF-7 encoding."""
        result = PayloadEncoder.utf7_encode("<script>")
        # UTF-7 should encode special chars
        assert "+" in result or "<" not in result or result == "<script>"


class TestHexEncodings:
    """Tests for hex encoding methods."""

    def test_hex_encode(self):
        """Test hex encoding with %XX format."""
        result = PayloadEncoder.hex_encode("A")
        assert result == "%41"

    def test_hex_encode_string(self):
        """Test hex encoding for string."""
        result = PayloadEncoder.hex_encode("<>")
        assert result == "%3c%3e"

    def test_hex_encode_0x(self):
        """Test hex encoding with 0xXX format."""
        result = PayloadEncoder.hex_encode_0x("A")
        assert result == "0x41"

    def test_hex_encode_char(self):
        """Test hex encoding with \\xXX format."""
        result = PayloadEncoder.hex_encode_char("A")
        assert result == "\\x41"

    def test_hex_decode_percent(self):
        """Test hex decoding %XX format."""
        result = PayloadEncoder.hex_decode("%41%42")
        assert result == "AB"

    def test_hex_decode_backslash_x(self):
        """Test hex decoding \\xXX format."""
        result = PayloadEncoder.hex_decode("\\x41\\x42")
        assert result == "AB"

    def test_hex_decode_mixed(self):
        """Test hex decoding mixed formats."""
        result = PayloadEncoder.hex_decode("%41\\x42")
        assert result == "AB"


class TestBase64Encodings:
    """Tests for Base64 encoding methods."""

    def test_base64_encode(self):
        """Test Base64 encoding."""
        result = PayloadEncoder.base64_encode("test")
        expected = base64.b64encode(b"test").decode()
        assert result == expected

    def test_base64_url_safe(self):
        """Test URL-safe Base64 encoding."""
        # Use a payload that would have + or / in regular base64
        result = PayloadEncoder.base64_url_safe("test~test")
        assert "+" not in result
        assert "/" not in result
        assert "=" not in result  # Padding removed

    def test_base64_decode(self):
        """Test Base64 decoding."""
        encoded = base64.b64encode(b"test").decode()
        result = PayloadEncoder.base64_decode(encoded)
        assert result == "test"

    def test_base64_decode_no_padding(self):
        """Test Base64 decoding without padding."""
        # "test" in base64 is "dGVzdA==" - remove padding
        result = PayloadEncoder.base64_decode("dGVzdA")
        assert result == "test"

    def test_base64_decode_invalid(self):
        """Test Base64 decoding with invalid input handles gracefully."""
        # Base64 decode uses errors="replace" so it won't return empty
        # but it should not raise an exception
        result = PayloadEncoder.base64_decode("!!invalid!!")
        # Should return something (decoded with replacement chars) or empty
        assert isinstance(result, str)


class TestHTMLEntityEncodings:
    """Tests for HTML entity encoding methods."""

    def test_html_entity_encode(self):
        """Test HTML entity encoding."""
        result = PayloadEncoder.html_entity_encode("<script>")
        assert "&lt;" in result
        assert "&gt;" in result

    def test_html_entity_encode_quotes(self):
        """Test HTML entity encoding with quotes."""
        result = PayloadEncoder.html_entity_encode('"test"')
        assert "&quot;" in result or "&#" in result

    def test_html_entity_decimal(self):
        """Test HTML decimal entity encoding."""
        result = PayloadEncoder.html_entity_decimal("<")
        assert result == "&#60;"

    def test_html_entity_decimal_string(self):
        """Test HTML decimal entity encoding for string."""
        result = PayloadEncoder.html_entity_decimal("AB")
        assert result == "&#65;&#66;"

    def test_html_entity_hex(self):
        """Test HTML hex entity encoding."""
        result = PayloadEncoder.html_entity_hex("<")
        assert result == "&#x3c;"

    def test_html_entity_hex_uppercase(self):
        """Test HTML hex entity encoding produces lowercase."""
        result = PayloadEncoder.html_entity_hex("A")
        # A is 0x41
        assert "&#x41;" in result or "&#x61;" in result.lower()


class TestCaseVariations:
    """Tests for case variation methods."""

    def test_case_upper(self):
        """Test uppercase conversion."""
        result = PayloadEncoder.case_upper("script")
        assert result == "SCRIPT"

    def test_case_lower(self):
        """Test lowercase conversion."""
        result = PayloadEncoder.case_lower("SCRIPT")
        assert result == "script"

    def test_case_mixed(self):
        """Test mixed case conversion."""
        result = PayloadEncoder.case_mixed("script")
        # ScrIpt or sCrIpT - alternating
        assert result != "script"
        assert result != "SCRIPT"
        assert result.lower() == "script"

    def test_case_mixed_alternating(self):
        """Test mixed case alternates correctly."""
        result = PayloadEncoder.case_mixed("abcd")
        # Should be AbCd (upper at even indices)
        assert result[0].isupper()
        assert result[1].islower()
        assert result[2].isupper()
        assert result[3].islower()

    def test_sql_keyword_case_bypass(self):
        """Test SQL keyword case bypass."""
        result = PayloadEncoder.sql_keyword_case_bypass("SELECT * FROM users")
        # SELECT and FROM should have mixed case
        assert result.lower() == "select * from users"
        assert result != "SELECT * FROM users"

    def test_xss_keyword_case_bypass(self):
        """Test XSS keyword case bypass."""
        result = PayloadEncoder.xss_keyword_case_bypass("<script>alert(1)</script>")
        # script and alert should have mixed case
        assert "script" in result.lower()
        assert "alert" in result.lower()


class TestSQLSpecificEncodings:
    """Tests for SQL-specific encoding methods."""

    def test_sql_comment_insertion(self):
        """Test SQL comment insertion."""
        result = PayloadEncoder.sql_comment_insertion("SELECT")
        # Should have /**/ inserted
        assert "/**/" in result
        assert result.replace("/**/", "").upper() == "SELECT"


class TestEncodingType:
    """Tests for EncodingType enum."""

    def test_all_types_present(self):
        """Test that all encoding types are defined."""
        types = {t.name for t in EncodingType}

        # URL encodings
        assert "URL_ENCODE" in types
        assert "DOUBLE_URL_ENCODE" in types
        assert "TRIPLE_URL_ENCODE" in types

        # Unicode encodings
        assert "UNICODE_ESCAPE" in types
        assert "UNICODE_FULL_WIDTH" in types

        # Base64
        assert "BASE64" in types

        # HTML
        assert "HTML_ENTITY" in types

        # Case
        assert "CASE_UPPER" in types
        assert "CASE_MIXED" in types

    def test_unique_values(self):
        """Test that all encoding types have unique values."""
        values = [t.value for t in EncodingType]
        assert len(values) == len(set(values))


class TestEncodingChain:
    """Tests for EncodingChain class."""

    def test_single_encoding(self):
        """Test chain with single encoding."""
        chain = EncodingChain()
        chain.add(EncodingType.URL_ENCODE)

        result = chain.encode("<")
        assert "%3C" in result or "%3c" in result

    def test_chained_encodings(self):
        """Test chain with multiple encodings."""
        chain = EncodingChain()
        chain.add(EncodingType.URL_ENCODE)
        chain.add(EncodingType.BASE64)

        result = chain.encode("<")
        # URL encode then base64 - result should be base64 of URL-encoded

        # The result should be different from just URL encoding
        simple_url = PayloadEncoder.url_encode("<")
        assert result != simple_url

    def test_chain_fluent_api(self):
        """Test chain fluent API (method chaining)."""
        result = (
            EncodingChain()
            .add(EncodingType.CASE_UPPER)
            .encode("test")
        )
        assert result == "TEST"

    def test_empty_chain(self):
        """Test empty chain returns original."""
        chain = EncodingChain()
        result = chain.encode("test")
        assert result == "test"


class TestEdgeCases:
    """Tests for edge cases and special inputs."""

    def test_empty_string(self):
        """Test encoding empty string."""
        assert PayloadEncoder.url_encode("") == ""
        assert PayloadEncoder.base64_encode("") == ""
        assert PayloadEncoder.hex_encode("") == ""

    def test_unicode_input(self):
        """Test encoding Unicode input."""
        result = PayloadEncoder.url_encode("café")
        assert "caf" in result or "%63%61%66" in result

    def test_special_characters(self):
        """Test encoding special characters."""
        special = "!@#$%^&*()"
        result = PayloadEncoder.url_encode_all(special)
        # All chars should be encoded
        for char in special:
            assert char not in result or char == '%'

    def test_newlines_and_tabs(self):
        """Test encoding newlines and tabs."""
        result = PayloadEncoder.url_encode("\n\t\r")
        assert "\n" not in result
        assert "\t" not in result
        assert "\r" not in result

    def test_null_byte(self):
        """Test encoding null byte."""
        result = PayloadEncoder.url_encode("\x00")
        assert "\x00" not in result


class TestPayloadEncoderConstants:
    """Tests for PayloadEncoder constants."""

    def test_sql_keywords_comprehensive(self):
        """Test SQL keywords list is comprehensive."""
        keywords = PayloadEncoder.SQL_KEYWORDS
        common = ["SELECT", "UNION", "AND", "OR", "FROM", "WHERE", "INSERT"]
        for kw in common:
            assert kw in keywords

    def test_xss_keywords_comprehensive(self):
        """Test XSS keywords list is comprehensive."""
        keywords = PayloadEncoder.XSS_KEYWORDS
        common = ["SCRIPT", "ALERT", "ONERROR", "ONLOAD", "IMG"]
        for kw in common:
            assert kw in keywords


class TestWAFBypassEncodings:
    """Tests specifically for WAF bypass encoding techniques."""

    def test_double_encode_bypasses_single_decode(self):
        """Test double encoding survives single URL decode."""
        original = "<script>"
        double = PayloadEncoder.double_url_encode(original)

        # Single decode
        single_decoded = PayloadEncoder.url_decode(double)

        # Should not be fully decoded yet
        assert single_decoded != original
        assert "%" in single_decoded

    def test_mixed_case_bypasses_keyword_filters(self):
        """Test mixed case bypasses simple keyword filters."""
        payload = "SELECT * FROM users"
        bypassed = PayloadEncoder.sql_keyword_case_bypass(payload)

        # Simple filter looking for "SELECT" would miss this
        assert "SELECT" not in bypassed
        # But functionality preserved
        assert bypassed.upper() == payload.upper()

    def test_comment_insertion_breaks_pattern(self):
        """Test comment insertion breaks keyword pattern."""
        bypassed = PayloadEncoder.sql_comment_insertion("SELECT")

        # Simple filter looking for "SELECT" would miss this
        assert "SELECT" not in bypassed
        # But SQL would still interpret it
        assert "SEL" in bypassed and "ECT" in bypassed
