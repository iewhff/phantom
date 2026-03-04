"""
Tests for scanning/modules/cache_deception_scanner.py

Covers:
- VERSION constant
- CacheDeceptionType enum (7 members)
- CacheIndicator enum (6 members with string values)
- STATIC_EXTENSIONS constant (18 items)
- PATH_DELIMITERS constant (11 items)
- CACHE_HEADERS constant (13 items)
- CacheStatus dataclass (defaults)
- DeceptionTestResult dataclass (all required fields)
- CacheDeceptionFinding dataclass
"""

import pytest
from dataclasses import fields as dataclass_fields
from scanning.modules.cache_deception_scanner import (
    VERSION,
    CacheDeceptionType,
    CacheIndicator,
    STATIC_EXTENSIONS,
    PATH_DELIMITERS,
    CACHE_HEADERS,
    CacheStatus,
    DeceptionTestResult,
    CacheDeceptionFinding,
)


# =============================================================================
# VERSION
# =============================================================================

class TestVersion:
    def test_version_value(self):
        assert VERSION == "3.0.0"

    def test_version_is_string(self):
        assert isinstance(VERSION, str)


# =============================================================================
# CacheDeceptionType ENUM
# =============================================================================

class TestCacheDeceptionType:
    def test_count(self):
        assert len(CacheDeceptionType) == 7

    def test_path_confusion(self):
        assert CacheDeceptionType.PATH_CONFUSION is not None

    def test_delimiter_injection(self):
        assert CacheDeceptionType.DELIMITER_INJECTION is not None

    def test_extension_append(self):
        assert CacheDeceptionType.EXTENSION_APPEND is not None

    def test_query_caching(self):
        assert CacheDeceptionType.QUERY_CACHING is not None

    def test_fragment_caching(self):
        assert CacheDeceptionType.FRAGMENT_CACHING is not None

    def test_normalization_diff(self):
        assert CacheDeceptionType.NORMALIZATION_DIFF is not None

    def test_cache_key_manipulation(self):
        assert CacheDeceptionType.CACHE_KEY_MANIPULATION is not None

    def test_all_members(self):
        expected = {
            "PATH_CONFUSION",
            "DELIMITER_INJECTION",
            "EXTENSION_APPEND",
            "QUERY_CACHING",
            "FRAGMENT_CACHING",
            "NORMALIZATION_DIFF",
            "CACHE_KEY_MANIPULATION",
        }
        assert {m.name for m in CacheDeceptionType} == expected


# =============================================================================
# CacheIndicator ENUM
# =============================================================================

class TestCacheIndicator:
    def test_count(self):
        assert len(CacheIndicator) == 6

    def test_hit(self):
        assert CacheIndicator.HIT is not None

    def test_miss(self):
        assert CacheIndicator.MISS is not None

    def test_expired(self):
        assert CacheIndicator.EXPIRED is not None

    def test_stale(self):
        assert CacheIndicator.STALE is not None

    def test_bypass(self):
        assert CacheIndicator.BYPASS is not None

    def test_unknown(self):
        assert CacheIndicator.UNKNOWN is not None

    def test_hit_value(self):
        assert CacheIndicator.HIT.value == "HIT"

    def test_miss_value(self):
        assert CacheIndicator.MISS.value == "MISS"

    def test_expired_value(self):
        assert CacheIndicator.EXPIRED.value == "EXPIRED"

    def test_stale_value(self):
        assert CacheIndicator.STALE.value == "STALE"

    def test_bypass_value(self):
        assert CacheIndicator.BYPASS.value == "BYPASS"

    def test_unknown_value(self):
        assert CacheIndicator.UNKNOWN.value == "UNKNOWN"

    def test_all_string_values(self):
        for member in CacheIndicator:
            assert isinstance(member.value, str)

    def test_all_members(self):
        expected = {"HIT", "MISS", "EXPIRED", "STALE", "BYPASS", "UNKNOWN"}
        assert {m.name for m in CacheIndicator} == expected


# =============================================================================
# STATIC_EXTENSIONS
# =============================================================================

class TestStaticExtensions:
    def test_count(self):
        assert len(STATIC_EXTENSIONS) == 18

    def test_is_list(self):
        assert isinstance(STATIC_EXTENSIONS, list)

    def test_css(self):
        assert ".css" in STATIC_EXTENSIONS

    def test_js(self):
        assert ".js" in STATIC_EXTENSIONS

    def test_png(self):
        assert ".png" in STATIC_EXTENSIONS

    def test_jpg(self):
        assert ".jpg" in STATIC_EXTENSIONS

    def test_jpeg(self):
        assert ".jpeg" in STATIC_EXTENSIONS

    def test_gif(self):
        assert ".gif" in STATIC_EXTENSIONS

    def test_ico(self):
        assert ".ico" in STATIC_EXTENSIONS

    def test_svg(self):
        assert ".svg" in STATIC_EXTENSIONS

    def test_woff(self):
        assert ".woff" in STATIC_EXTENSIONS

    def test_woff2(self):
        assert ".woff2" in STATIC_EXTENSIONS

    def test_ttf(self):
        assert ".ttf" in STATIC_EXTENSIONS

    def test_eot(self):
        assert ".eot" in STATIC_EXTENSIONS

    def test_webp(self):
        assert ".webp" in STATIC_EXTENSIONS

    def test_pdf(self):
        assert ".pdf" in STATIC_EXTENSIONS

    def test_txt(self):
        assert ".txt" in STATIC_EXTENSIONS

    def test_xml(self):
        assert ".xml" in STATIC_EXTENSIONS

    def test_json(self):
        assert ".json" in STATIC_EXTENSIONS

    def test_map(self):
        assert ".map" in STATIC_EXTENSIONS

    def test_all_start_with_dot(self):
        for ext in STATIC_EXTENSIONS:
            assert ext.startswith("."), f"Extension {ext} does not start with a dot"


# =============================================================================
# PATH_DELIMITERS
# =============================================================================

class TestPathDelimiters:
    def test_count(self):
        assert len(PATH_DELIMITERS) == 11

    def test_is_list(self):
        assert isinstance(PATH_DELIMITERS, list)

    def test_semicolon(self):
        assert ";" in PATH_DELIMITERS

    def test_encoded_semicolon_lower(self):
        assert "%3b" in PATH_DELIMITERS

    def test_encoded_semicolon_upper(self):
        assert "%3B" in PATH_DELIMITERS

    def test_question_mark(self):
        assert "?" in PATH_DELIMITERS

    def test_encoded_question_mark(self):
        assert "%3f" in PATH_DELIMITERS

    def test_hash(self):
        assert "#" in PATH_DELIMITERS

    def test_encoded_hash(self):
        assert "%23" in PATH_DELIMITERS

    def test_null_byte(self):
        assert "%00" in PATH_DELIMITERS

    def test_dot_segment(self):
        assert "/." in PATH_DELIMITERS

    def test_double_slash(self):
        assert "//" in PATH_DELIMITERS

    def test_parent_directory(self):
        assert "/.." in PATH_DELIMITERS

    def test_all_strings(self):
        for delim in PATH_DELIMITERS:
            assert isinstance(delim, str)


# =============================================================================
# CACHE_HEADERS
# =============================================================================

class TestCacheHeaders:
    def test_count(self):
        assert len(CACHE_HEADERS) == 13

    def test_is_list(self):
        assert isinstance(CACHE_HEADERS, list)

    def test_x_cache(self):
        assert "X-Cache" in CACHE_HEADERS

    def test_x_cache_hit(self):
        assert "X-Cache-Hit" in CACHE_HEADERS

    def test_x_cache_status(self):
        assert "X-Cache-Status" in CACHE_HEADERS

    def test_cf_cache_status(self):
        assert "CF-Cache-Status" in CACHE_HEADERS

    def test_x_varnish(self):
        assert "X-Varnish" in CACHE_HEADERS

    def test_age(self):
        assert "Age" in CACHE_HEADERS

    def test_x_served_by(self):
        assert "X-Served-By" in CACHE_HEADERS

    def test_x_cache_hits(self):
        assert "X-Cache-Hits" in CACHE_HEADERS

    def test_x_proxy_cache(self):
        assert "X-Proxy-Cache" in CACHE_HEADERS

    def test_x_drupal_cache(self):
        assert "X-Drupal-Cache" in CACHE_HEADERS

    def test_x_vc_cache(self):
        assert "X-VC-Cache" in CACHE_HEADERS

    def test_fastly_debug_digest(self):
        assert "Fastly-Debug-Digest" in CACHE_HEADERS

    def test_x_akamai_cache_status(self):
        assert "X-Akamai-Cache-Status" in CACHE_HEADERS

    def test_all_strings(self):
        for header in CACHE_HEADERS:
            assert isinstance(header, str)


# =============================================================================
# CacheStatus DATACLASS
# =============================================================================

class TestCacheStatus:
    def test_default_is_cached(self):
        status = CacheStatus()
        assert status.is_cached is False

    def test_default_indicator(self):
        status = CacheStatus()
        assert status.indicator == CacheIndicator.UNKNOWN

    def test_default_cache_header(self):
        status = CacheStatus()
        assert status.cache_header is None

    def test_default_cache_value(self):
        status = CacheStatus()
        assert status.cache_value is None

    def test_default_age(self):
        status = CacheStatus()
        assert status.age is None

    def test_default_max_age(self):
        status = CacheStatus()
        assert status.max_age is None

    def test_default_vary_headers(self):
        status = CacheStatus()
        assert status.vary_headers == []

    def test_default_cdn_detected(self):
        status = CacheStatus()
        assert status.cdn_detected is None

    def test_custom_values(self):
        status = CacheStatus(
            is_cached=True,
            indicator=CacheIndicator.HIT,
            cache_header="X-Cache",
            cache_value="HIT",
            age=120,
            max_age=3600,
            vary_headers=["Accept-Encoding", "Cookie"],
            cdn_detected="Cloudflare",
        )
        assert status.is_cached is True
        assert status.indicator == CacheIndicator.HIT
        assert status.cache_header == "X-Cache"
        assert status.cache_value == "HIT"
        assert status.age == 120
        assert status.max_age == 3600
        assert status.vary_headers == ["Accept-Encoding", "Cookie"]
        assert status.cdn_detected == "Cloudflare"

    def test_vary_headers_independent_instances(self):
        status1 = CacheStatus()
        status2 = CacheStatus()
        status1.vary_headers.append("Cookie")
        assert status2.vary_headers == []


# =============================================================================
# DeceptionTestResult DATACLASS
# =============================================================================

class TestDeceptionTestResult:
    def _make_result(self, **overrides):
        defaults = {
            "test_type": CacheDeceptionType.PATH_CONFUSION,
            "original_url": "https://target.com/account",
            "deception_url": "https://target.com/account/nonexistent.css",
            "original_response_hash": "abc123",
            "cached_response_hash": "abc123",
            "content_matches": True,
            "private_data_cached": True,
            "cache_status": CacheStatus(is_cached=True, indicator=CacheIndicator.HIT),
            "evidence": {"header": "X-Cache: HIT"},
        }
        defaults.update(overrides)
        return DeceptionTestResult(**defaults)

    def test_creation(self):
        result = self._make_result()
        assert result.test_type == CacheDeceptionType.PATH_CONFUSION

    def test_original_url(self):
        result = self._make_result()
        assert result.original_url == "https://target.com/account"

    def test_deception_url(self):
        result = self._make_result()
        assert result.deception_url == "https://target.com/account/nonexistent.css"

    def test_original_response_hash(self):
        result = self._make_result()
        assert result.original_response_hash == "abc123"

    def test_cached_response_hash(self):
        result = self._make_result()
        assert result.cached_response_hash == "abc123"

    def test_content_matches(self):
        result = self._make_result()
        assert result.content_matches is True

    def test_private_data_cached(self):
        result = self._make_result()
        assert result.private_data_cached is True

    def test_cache_status(self):
        result = self._make_result()
        assert result.cache_status.is_cached is True
        assert result.cache_status.indicator == CacheIndicator.HIT

    def test_evidence(self):
        result = self._make_result()
        assert result.evidence == {"header": "X-Cache: HIT"}

    def test_all_fields_required(self):
        """DeceptionTestResult has no defaults -- all fields must be supplied."""
        fields = dataclass_fields(DeceptionTestResult)
        field_names = {f.name for f in fields}
        expected = {
            "test_type",
            "original_url",
            "deception_url",
            "original_response_hash",
            "cached_response_hash",
            "content_matches",
            "private_data_cached",
            "cache_status",
            "evidence",
        }
        assert field_names == expected

    def test_missing_field_raises(self):
        with pytest.raises(TypeError):
            DeceptionTestResult(
                test_type=CacheDeceptionType.PATH_CONFUSION,
                original_url="https://target.com/account",
            )


# =============================================================================
# CacheDeceptionFinding DATACLASS
# =============================================================================

class TestCacheDeceptionFinding:
    def _make_finding(self, **overrides):
        defaults = {
            "id": "WCD-001",
            "vuln_type": CacheDeceptionType.DELIMITER_INJECTION,
            "severity": "HIGH",
            "confidence": 0.95,
            "original_url": "https://target.com/profile",
            "deception_url": "https://target.com/profile;.css",
            "description": "Cache deception via delimiter injection",
            "impact": "Attacker can access victim cached private data",
            "remediation": "Configure cache to ignore path parameters",
            "test_results": [],
            "cwe_id": 525,
            "cvss_score": 7.5,
            "poc_steps": [
                "Authenticate as victim",
                "Visit /profile;.css",
                "As attacker, request /profile;.css",
            ],
        }
        defaults.update(overrides)
        return CacheDeceptionFinding(**defaults)

    def test_creation(self):
        finding = self._make_finding()
        assert finding.id == "WCD-001"

    def test_vuln_type(self):
        finding = self._make_finding()
        assert finding.vuln_type == CacheDeceptionType.DELIMITER_INJECTION

    def test_severity(self):
        finding = self._make_finding()
        assert finding.severity == "HIGH"

    def test_confidence(self):
        finding = self._make_finding()
        assert finding.confidence == 0.95

    def test_original_url(self):
        finding = self._make_finding()
        assert finding.original_url == "https://target.com/profile"

    def test_deception_url(self):
        finding = self._make_finding()
        assert finding.deception_url == "https://target.com/profile;.css"

    def test_description(self):
        finding = self._make_finding()
        assert "delimiter injection" in finding.description

    def test_impact(self):
        finding = self._make_finding()
        assert "private data" in finding.impact

    def test_remediation(self):
        finding = self._make_finding()
        assert len(finding.remediation) > 0

    def test_test_results_list(self):
        finding = self._make_finding()
        assert isinstance(finding.test_results, list)

    def test_cwe_id(self):
        finding = self._make_finding()
        assert finding.cwe_id == 525

    def test_cvss_score(self):
        finding = self._make_finding()
        assert finding.cvss_score == 7.5

    def test_poc_steps(self):
        finding = self._make_finding()
        assert len(finding.poc_steps) == 3

    def test_all_fields(self):
        fields = dataclass_fields(CacheDeceptionFinding)
        field_names = {f.name for f in fields}
        expected = {
            "id",
            "vuln_type",
            "severity",
            "confidence",
            "original_url",
            "deception_url",
            "description",
            "impact",
            "remediation",
            "test_results",
            "cwe_id",
            "cvss_score",
            "poc_steps",
        }
        assert field_names == expected

    def test_missing_field_raises(self):
        with pytest.raises(TypeError):
            CacheDeceptionFinding(id="WCD-002", vuln_type=CacheDeceptionType.PATH_CONFUSION)
