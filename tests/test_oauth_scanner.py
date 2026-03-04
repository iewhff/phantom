"""
Unit tests for OAuth/OpenID Connect Security Scanner.

Tests cover:
1. OAuthScanner identity and inheritance
2. OAUTH_ENDPOINTS completeness and specific entries
3. REDIRECT_BYPASS_PAYLOADS categories (subdomain, path, protocol, encoding, localhost)
4. JWT_ALG_PAYLOADS count and specific algorithm entries
5. Uniqueness of all payload/endpoint lists
6. Edge cases and structural integrity

Run with: pytest tests/test_oauth_scanner.py -v
"""

import pytest
from unittest.mock import MagicMock


class TestOAuthScannerIdentity:
    """Test scanner name and class hierarchy."""

    def test_name_is_oauth_scanner(self):
        """OAuthScanner.name must be 'oauth_scanner'."""
        from scanning.modules.oauth_scanner import OAuthScanner

        assert OAuthScanner.name == "oauth_scanner"

    def test_is_scan_module_subclass(self):
        """OAuthScanner must inherit from ScanModule."""
        from scanning.modules.oauth_scanner import OAuthScanner
        from scanning.vuln_scanner import ScanModule

        assert issubclass(OAuthScanner, ScanModule)

    def test_instance_is_scan_module(self):
        """Instantiated OAuthScanner should be a ScanModule instance."""
        from scanning.modules.oauth_scanner import OAuthScanner
        from scanning.vuln_scanner import ScanModule

        scanner = OAuthScanner(MagicMock())
        assert isinstance(scanner, ScanModule)

    def test_has_scan_method(self):
        """OAuthScanner must have an async scan method."""
        from scanning.modules.oauth_scanner import OAuthScanner

        scanner = OAuthScanner(MagicMock())
        assert hasattr(scanner, "scan")
        assert callable(scanner.scan)


class TestOAuthEndpoints:
    """Test OAUTH_ENDPOINTS list completeness and specific entries."""

    def test_endpoints_not_empty(self):
        """OAUTH_ENDPOINTS must not be empty."""
        from scanning.modules.oauth_scanner import OAuthScanner

        assert len(OAuthScanner.OAUTH_ENDPOINTS) > 0

    def test_endpoints_minimum_count(self):
        """OAUTH_ENDPOINTS must have at least 15 entries."""
        from scanning.modules.oauth_scanner import OAuthScanner

        assert len(OAuthScanner.OAUTH_ENDPOINTS) >= 15

    def test_has_oauth_authorize(self):
        """Must include /oauth/authorize."""
        from scanning.modules.oauth_scanner import OAuthScanner

        assert "/oauth/authorize" in OAuthScanner.OAUTH_ENDPOINTS

    def test_has_oauth2_authorize(self):
        """Must include /oauth2/authorize."""
        from scanning.modules.oauth_scanner import OAuthScanner

        assert "/oauth2/authorize" in OAuthScanner.OAUTH_ENDPOINTS

    def test_has_oauth_token(self):
        """Must include /oauth/token."""
        from scanning.modules.oauth_scanner import OAuthScanner

        assert "/oauth/token" in OAuthScanner.OAUTH_ENDPOINTS

    def test_has_oauth2_token(self):
        """Must include /oauth2/token."""
        from scanning.modules.oauth_scanner import OAuthScanner

        assert "/oauth2/token" in OAuthScanner.OAUTH_ENDPOINTS

    def test_has_well_known_openid_configuration(self):
        """Must include /.well-known/openid-configuration."""
        from scanning.modules.oauth_scanner import OAuthScanner

        assert "/.well-known/openid-configuration" in OAuthScanner.OAUTH_ENDPOINTS

    def test_has_well_known_oauth_authorization_server(self):
        """Must include /.well-known/oauth-authorization-server."""
        from scanning.modules.oauth_scanner import OAuthScanner

        assert "/.well-known/oauth-authorization-server" in OAuthScanner.OAUTH_ENDPOINTS

    def test_has_jwks_endpoints(self):
        """Must include JWKS endpoints."""
        from scanning.modules.oauth_scanner import OAuthScanner

        endpoints = OAuthScanner.OAUTH_ENDPOINTS
        assert "/oauth/jwks" in endpoints
        assert "/jwks.json" in endpoints
        assert "/.well-known/jwks.json" in endpoints

    def test_has_userinfo_endpoint(self):
        """Must include userinfo endpoints."""
        from scanning.modules.oauth_scanner import OAuthScanner

        endpoints = OAuthScanner.OAUTH_ENDPOINTS
        assert "/oauth/userinfo" in endpoints or "/userinfo" in endpoints

    def test_has_connect_authorize(self):
        """Must include /connect/authorize for OIDC."""
        from scanning.modules.oauth_scanner import OAuthScanner

        assert "/connect/authorize" in OAuthScanner.OAUTH_ENDPOINTS

    def test_all_endpoints_are_strings(self):
        """Every endpoint must be a string."""
        from scanning.modules.oauth_scanner import OAuthScanner

        for endpoint in OAuthScanner.OAUTH_ENDPOINTS:
            assert isinstance(endpoint, str), f"Non-string endpoint: {endpoint!r}"

    def test_all_endpoints_start_with_slash(self):
        """Every endpoint path must start with /."""
        from scanning.modules.oauth_scanner import OAuthScanner

        for endpoint in OAuthScanner.OAUTH_ENDPOINTS:
            assert endpoint.startswith("/"), f"Endpoint missing leading slash: {endpoint!r}"

    def test_no_duplicate_endpoints(self):
        """No duplicate entries in OAUTH_ENDPOINTS."""
        from scanning.modules.oauth_scanner import OAuthScanner

        endpoints = OAuthScanner.OAUTH_ENDPOINTS
        assert len(endpoints) == len(set(endpoints)), (
            f"Duplicate endpoints found: "
            f"{[e for e in endpoints if endpoints.count(e) > 1]}"
        )


class TestRedirectBypassPayloads:
    """Test REDIRECT_BYPASS_PAYLOADS categories and entries."""

    def test_payloads_not_empty(self):
        """REDIRECT_BYPASS_PAYLOADS must not be empty."""
        from scanning.modules.oauth_scanner import OAuthScanner

        assert len(OAuthScanner.REDIRECT_BYPASS_PAYLOADS) > 0

    def test_payloads_minimum_count(self):
        """REDIRECT_BYPASS_PAYLOADS should have at least 15 entries."""
        from scanning.modules.oauth_scanner import OAuthScanner

        assert len(OAuthScanner.REDIRECT_BYPASS_PAYLOADS) >= 15

    def test_all_payloads_are_strings(self):
        """Every payload must be a string."""
        from scanning.modules.oauth_scanner import OAuthScanner

        for payload in OAuthScanner.REDIRECT_BYPASS_PAYLOADS:
            assert isinstance(payload, str), f"Non-string payload: {payload!r}"

    def test_no_duplicate_payloads(self):
        """No duplicate entries in REDIRECT_BYPASS_PAYLOADS."""
        from scanning.modules.oauth_scanner import OAuthScanner

        payloads = OAuthScanner.REDIRECT_BYPASS_PAYLOADS
        assert len(payloads) == len(set(payloads)), (
            f"Duplicate payloads found: "
            f"{[p for p in payloads if payloads.count(p) > 1]}"
        )

    # -- Subdomain tricks --

    def test_has_subdomain_fragment_trick(self):
        """Must include fragment-based subdomain bypass (evil.com#@legitimate)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        payloads = OAuthScanner.REDIRECT_BYPASS_PAYLOADS
        assert any(
            "#@" in p and "evil.com" in p for p in payloads
        ), "Missing fragment-based subdomain bypass payload"

    def test_has_subdomain_suffix_trick(self):
        """Must include subdomain suffix bypass (legitimate.com.evil.com)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        payloads = OAuthScanner.REDIRECT_BYPASS_PAYLOADS
        assert any(
            "legitimate.com.evil.com" in p for p in payloads
        ), "Missing subdomain suffix bypass payload"

    def test_has_at_sign_trick(self):
        """Must include @ sign bypass (legitimate.com@evil.com)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        payloads = OAuthScanner.REDIRECT_BYPASS_PAYLOADS
        assert any(
            "legitimate.com@evil.com" in p for p in payloads
        ), "Missing @ sign bypass payload"

    # -- Path manipulation --

    def test_has_path_traversal(self):
        """Must include path traversal bypass (../)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        payloads = OAuthScanner.REDIRECT_BYPASS_PAYLOADS
        assert any(
            "../" in p for p in payloads
        ), "Missing path traversal bypass payload"

    def test_has_semicolon_path_trick(self):
        """Must include semicolon path bypass (..;/)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        payloads = OAuthScanner.REDIRECT_BYPASS_PAYLOADS
        assert any(
            "..;" in p for p in payloads
        ), "Missing semicolon path bypass payload"

    def test_has_fragment_path_trick(self):
        """Must include fragment path bypass (callback#evil.com)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        payloads = OAuthScanner.REDIRECT_BYPASS_PAYLOADS
        assert any(
            "callback#" in p for p in payloads
        ), "Missing fragment path bypass payload"

    def test_has_query_parameter_trick(self):
        """Must include query parameter bypass (callback?next=evil.com)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        payloads = OAuthScanner.REDIRECT_BYPASS_PAYLOADS
        assert any(
            "?next=" in p for p in payloads
        ), "Missing query parameter bypass payload"

    # -- Protocol manipulation --

    def test_has_javascript_protocol(self):
        """Must include javascript: protocol bypass."""
        from scanning.modules.oauth_scanner import OAuthScanner

        payloads = OAuthScanner.REDIRECT_BYPASS_PAYLOADS
        assert any(
            p.startswith("javascript:") for p in payloads
        ), "Missing javascript: protocol payload"

    def test_has_data_protocol(self):
        """Must include data: protocol bypass."""
        from scanning.modules.oauth_scanner import OAuthScanner

        payloads = OAuthScanner.REDIRECT_BYPASS_PAYLOADS
        assert any(
            p.startswith("data:") for p in payloads
        ), "Missing data: protocol payload"

    def test_has_protocol_relative_bypass(self):
        """Must include protocol-relative URL bypass (//evil.com)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        payloads = OAuthScanner.REDIRECT_BYPASS_PAYLOADS
        assert any(
            p.startswith("//") for p in payloads
        ), "Missing protocol-relative URL payload"

    def test_has_backslash_bypass(self):
        """Must include backslash bypass (/\\evil.com)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        payloads = OAuthScanner.REDIRECT_BYPASS_PAYLOADS
        assert any(
            "/\\" in p for p in payloads
        ), "Missing backslash bypass payload"

    # -- Unicode/encoding tricks --

    def test_has_url_encoded_bypass(self):
        """Must include URL-encoded bypass (%2f%2f)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        payloads = OAuthScanner.REDIRECT_BYPASS_PAYLOADS
        assert any(
            "%2f" in p.lower() for p in payloads
        ), "Missing URL-encoded bypass payload"

    def test_has_unicode_dot_trick(self):
        """Must include Unicode full-width dot bypass."""
        from scanning.modules.oauth_scanner import OAuthScanner

        payloads = OAuthScanner.REDIRECT_BYPASS_PAYLOADS
        # Unicode full-width dot or CJK dot
        assert any(
            "\u3002" in p for p in payloads  # ideographic full stop
        ), "Missing Unicode dot bypass payload"

    def test_has_unicode_homoglyph_trick(self):
        """Must include Unicode homoglyph bypass (e.g., Turkish i)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        payloads = OAuthScanner.REDIRECT_BYPASS_PAYLOADS
        # Turkish dotless i (U+0131) used in 'legitımate'
        assert any(
            "\u0131" in p for p in payloads
        ), "Missing Unicode homoglyph bypass payload"

    def test_has_percent_encoded_at_sign(self):
        """Must include percent-encoded @ sign bypass (%40)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        payloads = OAuthScanner.REDIRECT_BYPASS_PAYLOADS
        assert any(
            "%40" in p for p in payloads
        ), "Missing percent-encoded @ sign payload"

    # -- Localhost/internal --

    def test_has_localhost_bypass(self):
        """Must include localhost redirect bypass."""
        from scanning.modules.oauth_scanner import OAuthScanner

        payloads = OAuthScanner.REDIRECT_BYPASS_PAYLOADS
        assert any(
            "localhost" in p for p in payloads
        ), "Missing localhost redirect payload"

    def test_has_127_0_0_1_bypass(self):
        """Must include 127.0.0.1 redirect bypass."""
        from scanning.modules.oauth_scanner import OAuthScanner

        payloads = OAuthScanner.REDIRECT_BYPASS_PAYLOADS
        assert any(
            "127.0.0.1" in p for p in payloads
        ), "Missing 127.0.0.1 redirect payload"

    def test_has_ipv6_localhost_bypass(self):
        """Must include IPv6 localhost redirect bypass ([::1])."""
        from scanning.modules.oauth_scanner import OAuthScanner

        payloads = OAuthScanner.REDIRECT_BYPASS_PAYLOADS
        assert any(
            "[::1]" in p for p in payloads
        ), "Missing IPv6 localhost redirect payload"


class TestJWTAlgPayloads:
    """Test JWT_ALG_PAYLOADS count and specific entries."""

    def test_payloads_not_empty(self):
        """JWT_ALG_PAYLOADS must not be empty."""
        from scanning.modules.oauth_scanner import OAuthScanner

        assert len(OAuthScanner.JWT_ALG_PAYLOADS) > 0

    def test_payloads_count(self):
        """JWT_ALG_PAYLOADS should have exactly 7 entries."""
        from scanning.modules.oauth_scanner import OAuthScanner

        assert len(OAuthScanner.JWT_ALG_PAYLOADS) == 7

    def test_all_payloads_are_dicts(self):
        """Every JWT payload must be a dict."""
        from scanning.modules.oauth_scanner import OAuthScanner

        for payload in OAuthScanner.JWT_ALG_PAYLOADS:
            assert isinstance(payload, dict), f"Non-dict JWT payload: {payload!r}"

    def test_all_payloads_have_alg_key(self):
        """Every JWT payload must have an 'alg' key."""
        from scanning.modules.oauth_scanner import OAuthScanner

        for payload in OAuthScanner.JWT_ALG_PAYLOADS:
            assert "alg" in payload, f"JWT payload missing 'alg' key: {payload!r}"

    def test_has_none_lowercase(self):
        """Must include alg='none' (lowercase)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        algs = [p["alg"] for p in OAuthScanner.JWT_ALG_PAYLOADS]
        assert "none" in algs, "Missing 'none' algorithm payload"

    def test_has_none_titlecase(self):
        """Must include alg='None' (titlecase)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        algs = [p["alg"] for p in OAuthScanner.JWT_ALG_PAYLOADS]
        assert "None" in algs, "Missing 'None' algorithm payload"

    def test_has_none_uppercase(self):
        """Must include alg='NONE' (uppercase)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        algs = [p["alg"] for p in OAuthScanner.JWT_ALG_PAYLOADS]
        assert "NONE" in algs, "Missing 'NONE' algorithm payload"

    def test_has_none_mixed_case(self):
        """Must include alg='nOnE' (mixed case)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        algs = [p["alg"] for p in OAuthScanner.JWT_ALG_PAYLOADS]
        assert "nOnE" in algs, "Missing 'nOnE' algorithm payload"

    def test_has_hs256(self):
        """Must include alg='HS256' for RS256->HS256 confusion."""
        from scanning.modules.oauth_scanner import OAuthScanner

        algs = [p["alg"] for p in OAuthScanner.JWT_ALG_PAYLOADS]
        assert "HS256" in algs, "Missing 'HS256' algorithm payload"

    def test_has_hs384(self):
        """Must include alg='HS384'."""
        from scanning.modules.oauth_scanner import OAuthScanner

        algs = [p["alg"] for p in OAuthScanner.JWT_ALG_PAYLOADS]
        assert "HS384" in algs, "Missing 'HS384' algorithm payload"

    def test_has_hs512(self):
        """Must include alg='HS512'."""
        from scanning.modules.oauth_scanner import OAuthScanner

        algs = [p["alg"] for p in OAuthScanner.JWT_ALG_PAYLOADS]
        assert "HS512" in algs, "Missing 'HS512' algorithm payload"

    def test_none_variants_count(self):
        """Should have exactly 4 'none' variants (none, None, NONE, nOnE)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        none_variants = [
            p for p in OAuthScanner.JWT_ALG_PAYLOADS
            if p["alg"].lower() == "none"
        ]
        assert len(none_variants) == 4

    def test_hmac_variants_count(self):
        """Should have exactly 3 HMAC variants (HS256, HS384, HS512)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        hmac_variants = [
            p for p in OAuthScanner.JWT_ALG_PAYLOADS
            if p["alg"].startswith("HS")
        ]
        assert len(hmac_variants) == 3

    def test_no_duplicate_algorithms(self):
        """No duplicate algorithm values in JWT_ALG_PAYLOADS."""
        from scanning.modules.oauth_scanner import OAuthScanner

        algs = [p["alg"] for p in OAuthScanner.JWT_ALG_PAYLOADS]
        assert len(algs) == len(set(algs)), (
            f"Duplicate algorithms found: "
            f"{[a for a in algs if algs.count(a) > 1]}"
        )


class TestPayloadCategoryCoverage:
    """Test that redirect bypass payloads cover all attack categories."""

    def _get_payloads(self):
        from scanning.modules.oauth_scanner import OAuthScanner
        return OAuthScanner.REDIRECT_BYPASS_PAYLOADS

    def test_subdomain_category_has_multiple_entries(self):
        """Subdomain tricks category should have multiple payloads."""
        payloads = self._get_payloads()
        subdomain_payloads = [
            p for p in payloads
            if any(trick in p for trick in [
                "#@", ".evil.com", "@evil.com", "\\@", "%40"
            ])
        ]
        assert len(subdomain_payloads) >= 3, (
            f"Only {len(subdomain_payloads)} subdomain trick payloads found"
        )

    def test_path_category_has_multiple_entries(self):
        """Path manipulation category should have multiple payloads."""
        payloads = self._get_payloads()
        path_payloads = [
            p for p in payloads
            if any(trick in p for trick in ["../", "..;", "callback#", "?next="])
        ]
        assert len(path_payloads) >= 3, (
            f"Only {len(path_payloads)} path manipulation payloads found"
        )

    def test_protocol_category_has_multiple_entries(self):
        """Protocol manipulation category should have multiple payloads."""
        payloads = self._get_payloads()
        protocol_payloads = [
            p for p in payloads
            if p.startswith(("javascript:", "data:", "//", "///", "/\\"))
        ]
        assert len(protocol_payloads) >= 3, (
            f"Only {len(protocol_payloads)} protocol manipulation payloads found"
        )

    def test_encoding_category_has_multiple_entries(self):
        """Unicode/encoding tricks category should have multiple payloads."""
        payloads = self._get_payloads()
        encoding_payloads = [
            p for p in payloads
            if any(trick in p for trick in ["%2f", "%2F", "\u3002", "\u0131", "%40"])
        ]
        assert len(encoding_payloads) >= 2, (
            f"Only {len(encoding_payloads)} encoding trick payloads found"
        )

    def test_localhost_category_has_multiple_entries(self):
        """Localhost/internal category should have multiple payloads."""
        payloads = self._get_payloads()
        localhost_payloads = [
            p for p in payloads
            if any(trick in p for trick in ["localhost", "127.0.0.1", "[::1]"])
        ]
        assert len(localhost_payloads) >= 3, (
            f"Only {len(localhost_payloads)} localhost/internal payloads found"
        )


class TestEdgeCases:
    """Test edge cases and structural integrity."""

    def test_no_empty_string_in_endpoints(self):
        """OAUTH_ENDPOINTS must not contain empty strings."""
        from scanning.modules.oauth_scanner import OAuthScanner

        for endpoint in OAuthScanner.OAUTH_ENDPOINTS:
            assert endpoint.strip() != "", "Empty endpoint found"

    def test_no_empty_string_in_redirect_payloads(self):
        """REDIRECT_BYPASS_PAYLOADS must not contain empty strings."""
        from scanning.modules.oauth_scanner import OAuthScanner

        for payload in OAuthScanner.REDIRECT_BYPASS_PAYLOADS:
            assert payload.strip() != "", "Empty redirect payload found"

    def test_no_empty_alg_in_jwt_payloads(self):
        """JWT_ALG_PAYLOADS must not contain empty alg values."""
        from scanning.modules.oauth_scanner import OAuthScanner

        for payload in OAuthScanner.JWT_ALG_PAYLOADS:
            assert payload["alg"].strip() != "", "Empty alg value found"

    def test_endpoints_list_is_class_attribute(self):
        """OAUTH_ENDPOINTS should be a class attribute (not instance)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        assert hasattr(OAuthScanner, "OAUTH_ENDPOINTS")
        assert isinstance(OAuthScanner.OAUTH_ENDPOINTS, list)

    def test_redirect_payloads_is_class_attribute(self):
        """REDIRECT_BYPASS_PAYLOADS should be a class attribute (not instance)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        assert hasattr(OAuthScanner, "REDIRECT_BYPASS_PAYLOADS")
        assert isinstance(OAuthScanner.REDIRECT_BYPASS_PAYLOADS, list)

    def test_jwt_payloads_is_class_attribute(self):
        """JWT_ALG_PAYLOADS should be a class attribute (not instance)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        assert hasattr(OAuthScanner, "JWT_ALG_PAYLOADS")
        assert isinstance(OAuthScanner.JWT_ALG_PAYLOADS, list)

    def test_jwt_payloads_are_json_serializable(self):
        """All JWT payloads must be JSON-serializable (used in JWT header encoding)."""
        import json
        from scanning.modules.oauth_scanner import OAuthScanner

        for payload in OAuthScanner.JWT_ALG_PAYLOADS:
            try:
                json.dumps(payload)
            except (TypeError, ValueError) as e:
                pytest.fail(f"JWT payload not JSON-serializable: {payload!r} -- {e}")

    def test_scanner_has_discovered_config_after_init(self):
        """Scanner should initialize discovered_config as empty dict."""
        from scanning.modules.oauth_scanner import OAuthScanner

        scanner = OAuthScanner(MagicMock())
        assert hasattr(scanner, "discovered_config")
        assert scanner.discovered_config == {}

    def test_scanner_has_timeout_after_init(self):
        """Scanner should initialize timeout from settings or default."""
        from scanning.modules.oauth_scanner import OAuthScanner

        settings = MagicMock()
        settings.timeouts.request_timeout = 30.0
        scanner = OAuthScanner(settings)
        assert hasattr(scanner, "timeout")
        assert isinstance(scanner.timeout, (int, float))
        assert scanner.timeout > 0

    def test_scanner_timeout_defaults_when_no_timeouts_attr(self):
        """Scanner should default to 30.0 when settings has no timeouts."""
        from scanning.modules.oauth_scanner import OAuthScanner

        settings = MagicMock(spec=[])  # no attributes
        scanner = OAuthScanner(settings)
        assert scanner.timeout == 30.0

    def test_endpoints_no_trailing_slash(self):
        """Endpoints should not have trailing slashes (consistency)."""
        from scanning.modules.oauth_scanner import OAuthScanner

        for endpoint in OAuthScanner.OAUTH_ENDPOINTS:
            if endpoint != "/":
                assert not endpoint.endswith("/"), (
                    f"Endpoint has trailing slash: {endpoint!r}"
                )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
