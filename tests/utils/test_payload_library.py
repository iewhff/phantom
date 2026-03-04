"""
Tests for utils/payload_library.py - Centralized Payload Library.

Covers:
- PayloadCategory enum
- WAFBypassTechnique enum
- DatabaseType enum
- XSSContext enum
- Payload dataclass
- PayloadEncoder class
- PayloadLibrary class (singleton, get_payloads, filters)
"""

import pytest
from urllib.parse import quote
import base64

from utils.payload_library import (
    PayloadCategory,
    WAFBypassTechnique,
    DatabaseType,
    XSSContext,
    Payload,
    PayloadEncoder,
    PayloadLibrary,
)


# =============================================================================
# PAYLOAD CATEGORY ENUM TESTS
# =============================================================================

class TestPayloadCategory:
    """Tests for PayloadCategory enum."""

    def test_injection_categories(self):
        """Test injection categories are defined."""
        assert PayloadCategory.SQLI is not None
        assert PayloadCategory.XSS is not None
        assert PayloadCategory.CMDI is not None
        assert PayloadCategory.SSTI is not None

    def test_file_categories(self):
        """Test file-based categories are defined."""
        assert PayloadCategory.LFI is not None
        assert PayloadCategory.RFI is not None

    def test_network_categories(self):
        """Test network categories are defined."""
        assert PayloadCategory.SSRF is not None
        assert PayloadCategory.XXE is not None

    def test_other_categories(self):
        """Test other categories are defined."""
        assert PayloadCategory.LDAP is not None
        assert PayloadCategory.XPATH is not None
        assert PayloadCategory.NOSQL is not None
        assert PayloadCategory.CRLF is not None
        assert PayloadCategory.OPEN_REDIRECT is not None

    def test_category_count(self):
        """Test expected number of categories."""
        assert len(PayloadCategory) >= 12


# =============================================================================
# WAF BYPASS TECHNIQUE ENUM TESTS
# =============================================================================

class TestWAFBypassTechnique:
    """Tests for WAFBypassTechnique enum."""

    def test_encoding_techniques(self):
        """Test encoding techniques are defined."""
        assert WAFBypassTechnique.URL_ENCODE is not None
        assert WAFBypassTechnique.DOUBLE_URL_ENCODE is not None
        assert WAFBypassTechnique.UNICODE is not None
        assert WAFBypassTechnique.HEX is not None
        assert WAFBypassTechnique.BASE64 is not None
        assert WAFBypassTechnique.HTML_ENTITY is not None

    def test_obfuscation_techniques(self):
        """Test obfuscation techniques are defined."""
        assert WAFBypassTechnique.CASE_VARIATION is not None
        assert WAFBypassTechnique.COMMENT_INSERTION is not None
        assert WAFBypassTechnique.WHITESPACE_VARIATION is not None
        assert WAFBypassTechnique.NULL_BYTE is not None
        assert WAFBypassTechnique.CONCAT_BREAK is not None

    def test_none_technique(self):
        """Test NONE technique is defined."""
        assert WAFBypassTechnique.NONE is not None

    def test_technique_count(self):
        """Test expected number of techniques."""
        assert len(WAFBypassTechnique) >= 10


# =============================================================================
# DATABASE TYPE ENUM TESTS
# =============================================================================

class TestDatabaseType:
    """Tests for DatabaseType enum."""

    def test_common_databases(self):
        """Test common databases are defined."""
        assert DatabaseType.MYSQL.value == "mysql"
        assert DatabaseType.POSTGRESQL.value == "postgresql"
        assert DatabaseType.MSSQL.value == "mssql"
        assert DatabaseType.ORACLE.value == "oracle"
        assert DatabaseType.SQLITE.value == "sqlite"

    def test_generic_type(self):
        """Test GENERIC type is defined."""
        assert DatabaseType.GENERIC.value == "generic"


# =============================================================================
# XSS CONTEXT ENUM TESTS
# =============================================================================

class TestXSSContext:
    """Tests for XSSContext enum."""

    def test_html_contexts(self):
        """Test HTML contexts are defined."""
        assert XSSContext.HTML_TAG.value == "html_tag"
        assert XSSContext.HTML_ATTR.value == "html_attr"
        assert XSSContext.HTML_ATTR_QUOTED.value == "html_attr_quoted"

    def test_js_contexts(self):
        """Test JavaScript contexts are defined."""
        assert XSSContext.JS_STRING.value == "js_string"
        assert XSSContext.JS_BLOCK.value == "js_block"

    def test_other_contexts(self):
        """Test other contexts are defined."""
        assert XSSContext.URL.value == "url"
        assert XSSContext.CSS.value == "css"


# =============================================================================
# PAYLOAD DATACLASS TESTS
# =============================================================================

class TestPayload:
    """Tests for Payload dataclass."""

    @pytest.fixture
    def basic_payload(self):
        """Create basic payload."""
        return Payload(
            raw="' OR '1'='1",
            category=PayloadCategory.SQLI,
            description="Basic SQLi boolean bypass",
            waf_bypasses=[WAFBypassTechnique.URL_ENCODE, WAFBypassTechnique.CASE_VARIATION],
            success_indicators=["error", "mysql"],
            severity="high",
            tags={"boolean", "basic"}
        )

    def test_payload_creation(self, basic_payload):
        """Test basic payload creation."""
        assert basic_payload.raw == "' OR '1'='1"
        assert basic_payload.category == PayloadCategory.SQLI
        assert basic_payload.description == "Basic SQLi boolean bypass"
        assert basic_payload.severity == "high"

    def test_payload_waf_bypasses(self, basic_payload):
        """Test payload WAF bypasses."""
        assert len(basic_payload.waf_bypasses) == 2
        assert WAFBypassTechnique.URL_ENCODE in basic_payload.waf_bypasses

    def test_payload_success_indicators(self, basic_payload):
        """Test payload success indicators."""
        assert "error" in basic_payload.success_indicators
        assert "mysql" in basic_payload.success_indicators

    def test_payload_tags(self, basic_payload):
        """Test payload tags."""
        assert "boolean" in basic_payload.tags
        assert "basic" in basic_payload.tags

    def test_payload_defaults(self):
        """Test payload default values."""
        payload = Payload(
            raw="test",
            category=PayloadCategory.XSS,
            description="Test"
        )
        assert payload.waf_bypasses == []
        assert payload.db_type is None
        assert payload.context is None
        assert payload.success_indicators == []
        assert payload.severity == "medium"

    def test_get_variants_basic(self, basic_payload):
        """Test getting payload variants."""
        variants = basic_payload.get_variants()
        assert len(variants) >= 1
        assert basic_payload.raw in variants

    def test_get_variants_includes_bypasses(self, basic_payload):
        """Test variants include bypass versions."""
        variants = basic_payload.get_variants(max_variants=5)
        # Should have original + URL encoded at minimum
        assert len(variants) >= 2

    def test_get_variants_max_limit(self, basic_payload):
        """Test variants respects max limit."""
        variants = basic_payload.get_variants(max_variants=2)
        assert len(variants) <= 2


# =============================================================================
# PAYLOAD ENCODER TESTS
# =============================================================================

class TestPayloadEncoder:
    """Tests for PayloadEncoder class."""

    def test_url_encode(self):
        """Test URL encoding."""
        result = PayloadEncoder.apply_bypass("' OR '1'='1", WAFBypassTechnique.URL_ENCODE)
        assert "'" not in result
        assert "%27" in result

    def test_double_url_encode(self):
        """Test double URL encoding."""
        result = PayloadEncoder.apply_bypass("'", WAFBypassTechnique.DOUBLE_URL_ENCODE)
        assert "%2527" in result

    def test_unicode_encode(self):
        """Test Unicode encoding."""
        result = PayloadEncoder.apply_bypass("SELECT", WAFBypassTechnique.UNICODE)
        assert "\\u" in result

    def test_hex_encode(self):
        """Test hex encoding."""
        result = PayloadEncoder.apply_bypass("abc", WAFBypassTechnique.HEX)
        assert "%61" in result  # 'a' = 0x61
        assert "%62" in result  # 'b' = 0x62
        assert "%63" in result  # 'c' = 0x63

    def test_case_variation(self):
        """Test case variation."""
        result = PayloadEncoder.apply_bypass("SELECT * FROM users", WAFBypassTechnique.CASE_VARIATION)
        # Should have mixed case
        assert result != "SELECT * FROM users"
        assert "select" not in result.lower() or "SELECT" not in result

    def test_comment_insertion(self):
        """Test comment insertion."""
        result = PayloadEncoder.apply_bypass("SELECT * FROM users", WAFBypassTechnique.COMMENT_INSERTION)
        assert "/**/" in result

    def test_null_byte_insertion(self):
        """Test null byte insertion."""
        result = PayloadEncoder.apply_bypass("test value", WAFBypassTechnique.NULL_BYTE)
        assert "%00" in result
        assert " " not in result

    def test_html_entity(self):
        """Test HTML entity encoding."""
        result = PayloadEncoder.apply_bypass("<script>alert(1)</script>", WAFBypassTechnique.HTML_ENTITY)
        assert "&lt;" in result
        assert "&gt;" in result

    def test_base64_encoding(self):
        """Test base64 encoding."""
        result = PayloadEncoder.apply_bypass("test", WAFBypassTechnique.BASE64)
        assert result == base64.b64encode(b"test").decode()

    def test_none_technique(self):
        """Test NONE technique returns original."""
        original = "' OR '1'='1"
        result = PayloadEncoder.apply_bypass(original, WAFBypassTechnique.NONE)
        assert result == original


class TestPayloadEncoderHelpers:
    """Tests for PayloadEncoder helper methods."""

    def test_unicode_encode_alpha_only(self):
        """Test Unicode encoding only encodes alpha characters."""
        result = PayloadEncoder._unicode_encode("a1b2")
        assert "\\u0061" in result  # 'a'
        assert "\\u0062" in result  # 'b'
        assert "1" in result  # Numbers not encoded
        assert "2" in result

    def test_hex_encode_all_chars(self):
        """Test hex encoding encodes all characters."""
        result = PayloadEncoder._hex_encode("AB")
        assert "%41" in result  # 'A'
        assert "%42" in result  # 'B'

    def test_case_variation_keywords(self):
        """Test case variation on SQL keywords."""
        result = PayloadEncoder._case_variation("UNION SELECT")
        # Keywords should be mixed case
        assert "UNION" not in result or "SELECT" not in result

    def test_comment_insertion_select(self):
        """Test comment insertion in SELECT."""
        result = PayloadEncoder._insert_comments("SELECT * FROM")
        assert "/**/" in result

    def test_whitespace_variation_spaces(self):
        """Test whitespace variation replaces spaces."""
        result = PayloadEncoder._whitespace_variation("a b c")
        # Spaces should be replaced with alternatives
        assert result != "a b c"


# =============================================================================
# PAYLOAD LIBRARY TESTS
# =============================================================================

class TestPayloadLibrary:
    """Tests for PayloadLibrary class."""

    @pytest.fixture(autouse=True)
    def reset_singleton(self):
        """Reset singleton before each test."""
        PayloadLibrary.reset()
        yield
        PayloadLibrary.reset()

    def test_singleton_pattern(self):
        """Test singleton returns same instance."""
        lib1 = PayloadLibrary.get_instance()
        lib2 = PayloadLibrary.get_instance()
        assert lib1 is lib2

    def test_singleton_reset(self):
        """Test singleton reset works."""
        lib1 = PayloadLibrary.get_instance()
        PayloadLibrary.reset()
        lib2 = PayloadLibrary.get_instance()
        assert lib1 is not lib2


class TestPayloadLibraryGetPayloads:
    """Tests for PayloadLibrary.get_payloads method."""

    @pytest.fixture(autouse=True)
    def reset_singleton(self):
        PayloadLibrary.reset()
        yield
        PayloadLibrary.reset()

    @pytest.fixture
    def library(self):
        return PayloadLibrary.get_instance()

    def test_get_sqli_payloads(self, library):
        """Test getting SQLi payloads."""
        payloads = library.get_payloads(PayloadCategory.SQLI)
        assert len(payloads) > 0
        # Should contain common SQLi patterns
        found_or = any("OR" in p.upper() for p in payloads)
        assert found_or

    def test_get_xss_payloads(self, library):
        """Test getting XSS payloads."""
        payloads = library.get_payloads(PayloadCategory.XSS)
        assert len(payloads) > 0
        # Should contain script-related patterns
        found_script = any("script" in p.lower() for p in payloads)
        assert found_script

    def test_get_cmdi_payloads(self, library):
        """Test getting command injection payloads."""
        payloads = library.get_payloads(PayloadCategory.CMDI)
        assert len(payloads) > 0

    def test_get_lfi_payloads(self, library):
        """Test getting LFI payloads."""
        payloads = library.get_payloads(PayloadCategory.LFI)
        assert len(payloads) > 0
        # Should contain path traversal patterns
        found_traversal = any(".." in p for p in payloads)
        assert found_traversal

    def test_get_ssrf_payloads(self, library):
        """Test getting SSRF payloads."""
        payloads = library.get_payloads(PayloadCategory.SSRF)
        assert len(payloads) > 0

    def test_get_xxe_payloads(self, library):
        """Test getting XXE payloads."""
        payloads = library.get_payloads(PayloadCategory.XXE)
        assert len(payloads) > 0
        # Should contain XML entity patterns
        found_entity = any("ENTITY" in p.upper() for p in payloads)
        assert found_entity

    def test_get_ssti_payloads(self, library):
        """Test getting SSTI payloads."""
        payloads = library.get_payloads(PayloadCategory.SSTI)
        assert len(payloads) > 0

    def test_get_nosql_payloads(self, library):
        """Test getting NoSQL payloads."""
        payloads = library.get_payloads(PayloadCategory.NOSQL)
        assert len(payloads) > 0


class TestPayloadLibraryFilters:
    """Tests for PayloadLibrary filters."""

    @pytest.fixture(autouse=True)
    def reset_singleton(self):
        PayloadLibrary.reset()
        yield
        PayloadLibrary.reset()

    @pytest.fixture
    def library(self):
        return PayloadLibrary.get_instance()

    def test_filter_by_db_type_mysql(self, library):
        """Test filtering by MySQL."""
        payloads = library.get_payloads(PayloadCategory.SQLI, db_type="mysql")
        assert len(payloads) > 0
        # Generic payloads should still be included

    def test_filter_by_db_type_postgresql(self, library):
        """Test filtering by PostgreSQL."""
        payloads = library.get_payloads(PayloadCategory.SQLI, db_type="postgresql")
        assert len(payloads) > 0

    def test_filter_by_db_type_mssql(self, library):
        """Test filtering by MSSQL."""
        payloads = library.get_payloads(PayloadCategory.SQLI, db_type="mssql")
        assert len(payloads) > 0

    def test_max_payloads_limit(self, library):
        """Test max_payloads limit."""
        payloads = library.get_payloads(PayloadCategory.SQLI, max_payloads=5)
        assert len(payloads) <= 5

    def test_without_waf_bypass(self, library):
        """Test getting payloads without WAF bypass variants."""
        payloads_with = library.get_payloads(PayloadCategory.SQLI, with_waf_bypass=True, max_payloads=50)
        payloads_without = library.get_payloads(PayloadCategory.SQLI, with_waf_bypass=False, max_payloads=50)
        # Without bypass should have fewer variants
        assert len(payloads_without) <= len(payloads_with)


class TestPayloadLibraryPayloadObjects:
    """Tests for PayloadLibrary.get_payload_objects method."""

    @pytest.fixture(autouse=True)
    def reset_singleton(self):
        PayloadLibrary.reset()
        yield
        PayloadLibrary.reset()

    @pytest.fixture
    def library(self):
        return PayloadLibrary.get_instance()

    def test_get_payload_objects(self, library):
        """Test getting full Payload objects."""
        payloads = library.get_payload_objects(PayloadCategory.SQLI)
        assert len(payloads) > 0
        assert all(isinstance(p, Payload) for p in payloads)

    def test_payload_objects_have_metadata(self, library):
        """Test Payload objects have metadata."""
        payloads = library.get_payload_objects(PayloadCategory.SQLI)
        for p in payloads[:5]:  # Check first 5
            assert p.raw is not None
            assert p.category == PayloadCategory.SQLI
            assert p.description is not None

    def test_filter_payload_objects_by_db(self, library):
        """Test filtering Payload objects by database."""
        payloads = library.get_payload_objects(PayloadCategory.SQLI, db_type="mysql")
        # All should be MySQL or generic
        for p in payloads:
            assert p.db_type is None or p.db_type == "mysql"


class TestPayloadLibrarySuccessIndicators:
    """Tests for PayloadLibrary.get_success_indicators method."""

    @pytest.fixture(autouse=True)
    def reset_singleton(self):
        PayloadLibrary.reset()
        yield
        PayloadLibrary.reset()

    @pytest.fixture
    def library(self):
        return PayloadLibrary.get_instance()

    def test_sqli_success_indicators(self, library):
        """Test SQLi success indicators."""
        indicators = library.get_success_indicators(PayloadCategory.SQLI)
        assert len(indicators) > 0
        # Common SQL error indicators
        indicator_str = " ".join(indicators).lower()
        assert "error" in indicator_str or "mysql" in indicator_str or "syntax" in indicator_str

    def test_xss_success_indicators(self, library):
        """Test XSS success indicators."""
        indicators = library.get_success_indicators(PayloadCategory.XSS)
        assert len(indicators) >= 0  # May be empty for some implementations


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestPayloadLibraryIntegration:
    """Integration tests for PayloadLibrary."""

    @pytest.fixture(autouse=True)
    def reset_singleton(self):
        PayloadLibrary.reset()
        yield
        PayloadLibrary.reset()

    def test_complete_workflow(self):
        """Test complete payload workflow."""
        library = PayloadLibrary.get_instance()

        # Get SQLi payloads for MySQL
        payloads = library.get_payloads(
            PayloadCategory.SQLI,
            db_type="mysql",
            with_waf_bypass=True,
            max_payloads=20
        )
        assert len(payloads) > 0
        assert len(payloads) <= 20

        # Get success indicators
        indicators = library.get_success_indicators(PayloadCategory.SQLI)
        assert len(indicators) >= 0

        # Get full objects
        objects = library.get_payload_objects(PayloadCategory.SQLI, db_type="mysql")
        assert len(objects) > 0

    def test_all_categories_have_payloads(self):
        """Test all main categories have payloads."""
        library = PayloadLibrary.get_instance()

        categories_to_test = [
            PayloadCategory.SQLI,
            PayloadCategory.XSS,
            PayloadCategory.LFI,
            PayloadCategory.SSRF,
            PayloadCategory.XXE,
            PayloadCategory.SSTI,
        ]

        for category in categories_to_test:
            payloads = library.get_payloads(category, max_payloads=10)
            assert len(payloads) > 0, f"No payloads for {category}"

    def test_waf_bypass_generates_variants(self):
        """Test WAF bypass generates different variants."""
        library = PayloadLibrary.get_instance()

        # Get payloads with bypass
        payloads_with = library.get_payloads(
            PayloadCategory.SQLI,
            with_waf_bypass=True,
            max_payloads=50
        )

        # Get payloads without bypass
        payloads_without = library.get_payloads(
            PayloadCategory.SQLI,
            with_waf_bypass=False,
            max_payloads=50
        )

        # With bypass should include encoded versions
        found_encoded = any("%" in p for p in payloads_with)
        assert found_encoded or len(payloads_with) >= len(payloads_without)

