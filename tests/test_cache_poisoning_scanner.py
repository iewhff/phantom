"""
Tests for scanning/modules/cache_poisoning_scanner.py

Covers:
- CachePoisonType enum (10 types)
- CDNType enum (8 types)
- CacheTestResult dataclass
- CDNInfo dataclass
- UNKEYED_HEADERS constant (30+ headers)
- HOST_HEADER_ATTACKS constant
- PARAMETER_CLOAKING_PAYLOADS constant
- CACHE_DECEPTION_PATHS constant
- ESI_PAYLOADS constant
- CDN_FINGERPRINTS constant
- CachePoisoningScanner class attributes
"""

import pytest
from scanning.modules.cache_poisoning_scanner import (
    CachePoisonType,
    CDNType,
    CacheTestResult,
    CDNInfo,
    UNKEYED_HEADERS,
    HOST_HEADER_ATTACKS,
    PARAMETER_CLOAKING_PAYLOADS,
    CACHE_DECEPTION_PATHS,
    ESI_PAYLOADS,
    CDN_FINGERPRINTS,
    CachePoisoningScanner,
)


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestCachePoisonType:
    def test_count(self):
        assert len(CachePoisonType) == 10

    def test_unkeyed_header(self):
        assert CachePoisonType.UNKEYED_HEADER is not None

    def test_host_header(self):
        assert CachePoisonType.HOST_HEADER is not None

    def test_fat_get(self):
        assert CachePoisonType.FAT_GET is not None

    def test_parameter_cloaking(self):
        assert CachePoisonType.PARAMETER_CLOAKING is not None

    def test_cache_deception(self):
        assert CachePoisonType.CACHE_DECEPTION is not None

    def test_path_normalization(self):
        assert CachePoisonType.PATH_NORMALIZATION is not None

    def test_response_splitting(self):
        assert CachePoisonType.RESPONSE_SPLITTING is not None

    def test_cookie_based(self):
        assert CachePoisonType.COOKIE_BASED is not None

    def test_esi_injection(self):
        assert CachePoisonType.ESI_INJECTION is not None

    def test_vary_manipulation(self):
        assert CachePoisonType.VARY_MANIPULATION is not None


class TestCDNType:
    def test_count(self):
        assert len(CDNType) == 8

    def test_cloudflare(self):
        assert CDNType.CLOUDFLARE is not None

    def test_fastly(self):
        assert CDNType.FASTLY is not None

    def test_akamai(self):
        assert CDNType.AKAMAI is not None

    def test_cloudfront(self):
        assert CDNType.CLOUDFRONT is not None

    def test_varnish(self):
        assert CDNType.VARNISH is not None

    def test_nginx(self):
        assert CDNType.NGINX is not None

    def test_squid(self):
        assert CDNType.SQUID is not None

    def test_unknown(self):
        assert CDNType.UNKNOWN is not None


# =============================================================================
# DATACLASS TESTS
# =============================================================================

class TestCacheTestResult:
    def test_defaults(self):
        result = CacheTestResult(vulnerable=False)
        assert result.vulnerable is False
        assert result.poison_type is None
        assert result.confidence == 0.0
        assert result.cached is False
        assert result.evidence == []
        assert result.canary == ""

    def test_full(self):
        result = CacheTestResult(
            vulnerable=True,
            poison_type=CachePoisonType.UNKEYED_HEADER,
            confidence=0.95,
            cached=True,
            evidence=["X-Forwarded-Host reflected in <base> tag"],
            canary="phantom123",
        )
        assert result.vulnerable is True
        assert result.poison_type == CachePoisonType.UNKEYED_HEADER


class TestCDNInfo:
    def test_defaults(self):
        info = CDNInfo(cdn_type=CDNType.UNKNOWN)
        assert info.cdn_type == CDNType.UNKNOWN
        assert info.version is None
        assert info.cache_headers == []
        assert info.has_cache is False

    def test_full(self):
        info = CDNInfo(
            cdn_type=CDNType.CLOUDFLARE,
            version="latest",
            cache_headers=["cf-cache-status: HIT"],
            has_cache=True,
        )
        assert info.has_cache is True
        assert info.cdn_type == CDNType.CLOUDFLARE


# =============================================================================
# UNKEYED HEADERS
# =============================================================================

class TestUnkeyedHeaders:
    def test_not_empty(self):
        assert len(UNKEYED_HEADERS) > 0

    def test_count(self):
        assert len(UNKEYED_HEADERS) >= 30

    def test_all_are_tuples(self):
        for item in UNKEYED_HEADERS:
            assert isinstance(item, tuple)
            assert len(item) == 2

    def test_has_x_forwarded_host(self):
        headers = [h for h, t in UNKEYED_HEADERS]
        assert "X-Forwarded-Host" in headers

    def test_has_x_forwarded_scheme(self):
        headers = [h for h, t in UNKEYED_HEADERS]
        assert "X-Forwarded-Scheme" in headers

    def test_has_x_forwarded_proto(self):
        headers = [h for h, t in UNKEYED_HEADERS]
        assert "X-Forwarded-Proto" in headers

    def test_has_x_original_url(self):
        headers = [h for h, t in UNKEYED_HEADERS]
        assert "X-Original-URL" in headers

    def test_has_x_rewrite_url(self):
        headers = [h for h, t in UNKEYED_HEADERS]
        assert "X-Rewrite-URL" in headers

    def test_has_cloudflare_header(self):
        headers = [h for h, t in UNKEYED_HEADERS]
        assert "CF-Connecting-IP" in headers

    def test_has_true_client_ip(self):
        headers = [h for h, t in UNKEYED_HEADERS]
        assert "True-Client-IP" in headers

    def test_has_x_cache_key(self):
        headers = [h for h, t in UNKEYED_HEADERS]
        assert "X-Cache-Key" in headers

    def test_all_have_type(self):
        for header, attack_type in UNKEYED_HEADERS:
            assert len(attack_type) > 0


# =============================================================================
# HOST HEADER ATTACKS
# =============================================================================

class TestHostHeaderAttacks:
    def test_not_empty(self):
        assert len(HOST_HEADER_ATTACKS) > 0

    def test_all_are_dicts(self):
        for attack in HOST_HEADER_ATTACKS:
            assert isinstance(attack, dict)


# =============================================================================
# PARAMETER CLOAKING
# =============================================================================

class TestParameterCloakingPayloads:
    def test_not_empty(self):
        assert len(PARAMETER_CLOAKING_PAYLOADS) > 0

    def test_has_utm_source(self):
        assert any("utm_source" in p for p in PARAMETER_CLOAKING_PAYLOADS)

    def test_has_fbclid(self):
        assert any("fbclid" in p for p in PARAMETER_CLOAKING_PAYLOADS)

    def test_has_gclid(self):
        assert any("gclid" in p for p in PARAMETER_CLOAKING_PAYLOADS)

    def test_has_null_byte(self):
        assert any("%00" in p for p in PARAMETER_CLOAKING_PAYLOADS)

    def test_has_semicolon(self):
        assert any(p.startswith(";") for p in PARAMETER_CLOAKING_PAYLOADS)

    def test_has_array_notation(self):
        assert any("[]" in p for p in PARAMETER_CLOAKING_PAYLOADS)


# =============================================================================
# CACHE DECEPTION PATHS
# =============================================================================

class TestCacheDeceptionPaths:
    def test_not_empty(self):
        assert len(CACHE_DECEPTION_PATHS) > 0

    def test_has_css_trick(self):
        assert any(".css" in p for p in CACHE_DECEPTION_PATHS)

    def test_has_js_trick(self):
        assert any(".js" in p for p in CACHE_DECEPTION_PATHS)

    def test_has_png_trick(self):
        assert any(".png" in p for p in CACHE_DECEPTION_PATHS)

    def test_has_path_confusion(self):
        assert any("%2e%2e" in p or "%2f" in p for p in CACHE_DECEPTION_PATHS)


# =============================================================================
# ESI PAYLOADS
# =============================================================================

class TestESIPayloads:
    def test_not_empty(self):
        assert len(ESI_PAYLOADS) > 0

    def test_has_include(self):
        assert any("esi:include" in p for p in ESI_PAYLOADS)

    def test_has_inline(self):
        assert any("esi:inline" in p for p in ESI_PAYLOADS)

    def test_has_comment_bypass(self):
        assert any("esi:comment" in p or "<!--esi" in p for p in ESI_PAYLOADS)


# =============================================================================
# CDN FINGERPRINTS
# =============================================================================

class TestCDNFingerprints:
    def test_has_cloudflare(self):
        assert CDNType.CLOUDFLARE in CDN_FINGERPRINTS
        cf = CDN_FINGERPRINTS[CDNType.CLOUDFLARE]
        assert "cf-ray" in cf["headers"]

    def test_has_fastly(self):
        assert CDNType.FASTLY in CDN_FINGERPRINTS
        fastly = CDN_FINGERPRINTS[CDNType.FASTLY]
        assert "x-served-by" in fastly["headers"]

    def test_has_akamai(self):
        assert CDNType.AKAMAI in CDN_FINGERPRINTS

    def test_has_cloudfront(self):
        assert CDNType.CLOUDFRONT in CDN_FINGERPRINTS
        cf = CDN_FINGERPRINTS[CDNType.CLOUDFRONT]
        assert "x-amz-cf-id" in cf["headers"]

    def test_has_varnish(self):
        assert CDNType.VARNISH in CDN_FINGERPRINTS

    def test_all_have_headers(self):
        for cdn, config in CDN_FINGERPRINTS.items():
            assert "headers" in config


# =============================================================================
# SCANNER CLASS
# =============================================================================

class TestCachePoisoningScannerClass:
    def test_name(self):
        assert CachePoisoningScanner.name == "cache_poisoning_scanner"

    def test_version(self):
        assert CachePoisoningScanner.version == "2.0-enterprise"

    def test_is_scan_module(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(CachePoisoningScanner, ScanModule)

    def test_has_unkeyed_headers(self):
        assert len(CachePoisoningScanner.UNKEYED_HEADERS) > 0

    def test_has_cache_busters(self):
        assert len(CachePoisoningScanner.CACHE_BUSTERS) > 0


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    def test_all_poison_types_unique(self):
        values = [t.value for t in CachePoisonType]
        assert len(values) == len(set(values))

    def test_all_cdn_types_unique(self):
        values = [t.value for t in CDNType]
        assert len(values) == len(set(values))
