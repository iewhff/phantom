"""
Tests for scanning/modules/edge_function_scanner.py

Covers:
- EdgeVulnType enum (8 members)
- EdgePlatform enum (7 members)
- EdgeEndpoint dataclass (defaults, full creation, field types)
- EdgeTestResult dataclass (defaults, full creation, field types)
- EdgeFunctionScanner class attributes:
  - Scanner identity (name, version, ScanModule subclass)
  - PLATFORM_HEADERS dict (6 platforms, header tuples)
  - EDGE_ENDPOINTS list (10 entries)
  - ENV_PATTERNS list (12 regex patterns)
  - STORAGE_PATTERNS dict (6 storage types, regex lists)
- Module-level constant EDGE_SCANNER_VERSION
- Regex pattern compilation and matching
"""

import re
import pytest
from dataclasses import fields

from scanning.modules.edge_function_scanner import (
    EdgeVulnType,
    EdgePlatform,
    EdgeEndpoint,
    EdgeTestResult,
    EdgeFunctionScanner,
    EDGE_SCANNER_VERSION,
)


# =============================================================================
# EDGE_SCANNER_VERSION MODULE CONSTANT
# =============================================================================

class TestEdgeScannerVersion:
    def test_version_is_string(self):
        assert isinstance(EDGE_SCANNER_VERSION, str)

    def test_version_value(self):
        assert EDGE_SCANNER_VERSION == "1.0.0"

    def test_version_semver_format(self):
        parts = EDGE_SCANNER_VERSION.split(".")
        assert len(parts) == 3
        for part in parts:
            assert part.isdigit()


# =============================================================================
# EdgeVulnType ENUM
# =============================================================================

class TestEdgeVulnTypeEnum:
    def test_member_count(self):
        assert len(EdgeVulnType) == 8

    def test_env_exposure_exists(self):
        assert EdgeVulnType.ENV_EXPOSURE is not None

    def test_storage_exposure_exists(self):
        assert EdgeVulnType.STORAGE_EXPOSURE is not None

    def test_origin_bypass_exists(self):
        assert EdgeVulnType.ORIGIN_BYPASS is not None

    def test_timeout_exploit_exists(self):
        assert EdgeVulnType.TIMEOUT_EXPLOIT is not None

    def test_memory_exhaust_exists(self):
        assert EdgeVulnType.MEMORY_EXHAUST is not None

    def test_runtime_leak_exists(self):
        assert EdgeVulnType.RUNTIME_LEAK is not None

    def test_edge_ssrf_exists(self):
        assert EdgeVulnType.EDGE_SSRF is not None

    def test_cache_poison_exists(self):
        assert EdgeVulnType.CACHE_POISON is not None

    def test_all_values_unique(self):
        values = [m.value for m in EdgeVulnType]
        assert len(values) == len(set(values))

    def test_all_members_are_auto(self):
        """auto() produces int values."""
        for member in EdgeVulnType:
            assert isinstance(member.value, int)


# =============================================================================
# EdgePlatform ENUM
# =============================================================================

class TestEdgePlatformEnum:
    def test_member_count(self):
        assert len(EdgePlatform) == 7

    def test_vercel(self):
        assert EdgePlatform.VERCEL.value == "vercel"

    def test_cloudflare(self):
        assert EdgePlatform.CLOUDFLARE.value == "cloudflare"

    def test_netlify(self):
        assert EdgePlatform.NETLIFY.value == "netlify"

    def test_deno_deploy(self):
        assert EdgePlatform.DENO_DEPLOY.value == "deno_deploy"

    def test_lambda_edge(self):
        assert EdgePlatform.LAMBDA_EDGE.value == "lambda_edge"

    def test_fastly(self):
        assert EdgePlatform.FASTLY.value == "fastly"

    def test_unknown(self):
        assert EdgePlatform.UNKNOWN.value == "unknown"

    def test_all_values_unique(self):
        values = [m.value for m in EdgePlatform]
        assert len(values) == len(set(values))

    def test_all_values_are_strings(self):
        for member in EdgePlatform:
            assert isinstance(member.value, str)

    def test_all_values_lowercase(self):
        for member in EdgePlatform:
            assert member.value == member.value.lower()


# =============================================================================
# EdgeEndpoint DATACLASS
# =============================================================================

class TestEdgeEndpointDataclass:
    def test_required_fields(self):
        """url and platform are required."""
        ep = EdgeEndpoint(url="https://example.com/api/", platform=EdgePlatform.VERCEL)
        assert ep.url == "https://example.com/api/"
        assert ep.platform == EdgePlatform.VERCEL

    def test_default_response_time_ms(self):
        ep = EdgeEndpoint(url="https://x.com", platform=EdgePlatform.UNKNOWN)
        assert ep.response_time_ms == 0.0

    def test_default_is_edge(self):
        ep = EdgeEndpoint(url="https://x.com", platform=EdgePlatform.UNKNOWN)
        assert ep.is_edge is False

    def test_default_region(self):
        ep = EdgeEndpoint(url="https://x.com", platform=EdgePlatform.UNKNOWN)
        assert ep.region == ""

    def test_default_features(self):
        ep = EdgeEndpoint(url="https://x.com", platform=EdgePlatform.UNKNOWN)
        assert ep.features == []
        assert isinstance(ep.features, list)

    def test_full_creation(self):
        ep = EdgeEndpoint(
            url="https://example.com/edge/",
            platform=EdgePlatform.CLOUDFLARE,
            response_time_ms=42.5,
            is_edge=True,
            region="IAD",
            features=["kv", "r2"],
        )
        assert ep.url == "https://example.com/edge/"
        assert ep.platform == EdgePlatform.CLOUDFLARE
        assert ep.response_time_ms == 42.5
        assert ep.is_edge is True
        assert ep.region == "IAD"
        assert ep.features == ["kv", "r2"]

    def test_field_count(self):
        assert len(fields(EdgeEndpoint)) == 6

    def test_features_default_factory_independence(self):
        """Each instance gets its own list."""
        ep1 = EdgeEndpoint(url="a", platform=EdgePlatform.VERCEL)
        ep2 = EdgeEndpoint(url="b", platform=EdgePlatform.VERCEL)
        ep1.features.append("x")
        assert ep2.features == []


# =============================================================================
# EdgeTestResult DATACLASS
# =============================================================================

class TestEdgeTestResultDataclass:
    def test_required_fields(self):
        """vulnerable, vuln_type, confidence, payload are required."""
        r = EdgeTestResult(
            vulnerable=True,
            vuln_type=EdgeVulnType.ENV_EXPOSURE,
            confidence=85,
            payload="?debug=true",
        )
        assert r.vulnerable is True
        assert r.vuln_type == EdgeVulnType.ENV_EXPOSURE
        assert r.confidence == 85
        assert r.payload == "?debug=true"

    def test_default_response_data(self):
        r = EdgeTestResult(
            vulnerable=False,
            vuln_type=EdgeVulnType.CACHE_POISON,
            confidence=0,
            payload="",
        )
        assert r.response_data == ""

    def test_default_evidence(self):
        r = EdgeTestResult(
            vulnerable=False,
            vuln_type=EdgeVulnType.CACHE_POISON,
            confidence=0,
            payload="",
        )
        assert r.evidence == []
        assert isinstance(r.evidence, list)

    def test_default_severity(self):
        r = EdgeTestResult(
            vulnerable=False,
            vuln_type=EdgeVulnType.CACHE_POISON,
            confidence=0,
            payload="",
        )
        assert r.severity == "MEDIUM"

    def test_default_data_leaked(self):
        r = EdgeTestResult(
            vulnerable=False,
            vuln_type=EdgeVulnType.CACHE_POISON,
            confidence=0,
            payload="",
        )
        assert r.data_leaked is False

    def test_full_creation(self):
        r = EdgeTestResult(
            vulnerable=True,
            vuln_type=EdgeVulnType.EDGE_SSRF,
            confidence=90,
            payload="http://169.254.169.254/",
            response_data="ami-id: ami-12345",
            evidence=["SSRF success", "AWS metadata"],
            severity="HIGH",
            data_leaked=True,
        )
        assert r.vulnerable is True
        assert r.vuln_type == EdgeVulnType.EDGE_SSRF
        assert r.confidence == 90
        assert r.payload == "http://169.254.169.254/"
        assert r.response_data == "ami-id: ami-12345"
        assert r.evidence == ["SSRF success", "AWS metadata"]
        assert r.severity == "HIGH"
        assert r.data_leaked is True

    def test_field_count(self):
        assert len(fields(EdgeTestResult)) == 8

    def test_evidence_default_factory_independence(self):
        """Each instance gets its own list."""
        r1 = EdgeTestResult(vulnerable=False, vuln_type=EdgeVulnType.RUNTIME_LEAK, confidence=0, payload="")
        r2 = EdgeTestResult(vulnerable=False, vuln_type=EdgeVulnType.RUNTIME_LEAK, confidence=0, payload="")
        r1.evidence.append("leak")
        assert r2.evidence == []


# =============================================================================
# EdgeFunctionScanner CLASS IDENTITY
# =============================================================================

class TestEdgeFunctionScannerIdentity:
    def test_name(self):
        assert EdgeFunctionScanner.name == "edge_function_scanner"

    def test_version(self):
        assert EdgeFunctionScanner.version == "1.0.0"

    def test_version_matches_module_constant(self):
        assert EdgeFunctionScanner.version == EDGE_SCANNER_VERSION

    def test_is_scan_module(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(EdgeFunctionScanner, ScanModule)


# =============================================================================
# PLATFORM_HEADERS DICT
# =============================================================================

class TestPlatformHeaders:
    def test_platform_count(self):
        """6 platforms have header detection patterns (UNKNOWN excluded)."""
        assert len(EdgeFunctionScanner.PLATFORM_HEADERS) == 6

    def test_keys_are_edge_platform_enums(self):
        for key in EdgeFunctionScanner.PLATFORM_HEADERS:
            assert isinstance(key, EdgePlatform)

    def test_unknown_not_in_headers(self):
        assert EdgePlatform.UNKNOWN not in EdgeFunctionScanner.PLATFORM_HEADERS

    def test_vercel_present(self):
        assert EdgePlatform.VERCEL in EdgeFunctionScanner.PLATFORM_HEADERS

    def test_cloudflare_present(self):
        assert EdgePlatform.CLOUDFLARE in EdgeFunctionScanner.PLATFORM_HEADERS

    def test_netlify_present(self):
        assert EdgePlatform.NETLIFY in EdgeFunctionScanner.PLATFORM_HEADERS

    def test_deno_deploy_present(self):
        assert EdgePlatform.DENO_DEPLOY in EdgeFunctionScanner.PLATFORM_HEADERS

    def test_lambda_edge_present(self):
        assert EdgePlatform.LAMBDA_EDGE in EdgeFunctionScanner.PLATFORM_HEADERS

    def test_fastly_present(self):
        assert EdgePlatform.FASTLY in EdgeFunctionScanner.PLATFORM_HEADERS

    def test_vercel_header_count(self):
        assert len(EdgeFunctionScanner.PLATFORM_HEADERS[EdgePlatform.VERCEL]) == 5

    def test_cloudflare_header_count(self):
        assert len(EdgeFunctionScanner.PLATFORM_HEADERS[EdgePlatform.CLOUDFLARE]) == 5

    def test_netlify_header_count(self):
        assert len(EdgeFunctionScanner.PLATFORM_HEADERS[EdgePlatform.NETLIFY]) == 4

    def test_deno_deploy_header_count(self):
        assert len(EdgeFunctionScanner.PLATFORM_HEADERS[EdgePlatform.DENO_DEPLOY]) == 3

    def test_lambda_edge_header_count(self):
        assert len(EdgeFunctionScanner.PLATFORM_HEADERS[EdgePlatform.LAMBDA_EDGE]) == 3

    def test_fastly_header_count(self):
        assert len(EdgeFunctionScanner.PLATFORM_HEADERS[EdgePlatform.FASTLY]) == 3

    def test_each_entry_is_tuple_of_two_strings(self):
        for platform, entries in EdgeFunctionScanner.PLATFORM_HEADERS.items():
            for entry in entries:
                assert isinstance(entry, tuple), f"{platform}: entry is not tuple"
                assert len(entry) == 2, f"{platform}: entry has {len(entry)} elements"
                assert isinstance(entry[0], str), f"{platform}: header name not str"
                assert isinstance(entry[1], str), f"{platform}: pattern not str"

    def test_vercel_has_x_vercel_cache_header(self):
        names = [h[0] for h in EdgeFunctionScanner.PLATFORM_HEADERS[EdgePlatform.VERCEL]]
        assert "x-vercel-cache" in names

    def test_cloudflare_has_cf_ray_header(self):
        names = [h[0] for h in EdgeFunctionScanner.PLATFORM_HEADERS[EdgePlatform.CLOUDFLARE]]
        assert "cf-ray" in names

    def test_netlify_has_nf_request_id_header(self):
        names = [h[0] for h in EdgeFunctionScanner.PLATFORM_HEADERS[EdgePlatform.NETLIFY]]
        assert "x-nf-request-id" in names

    def test_deno_has_region_header(self):
        names = [h[0] for h in EdgeFunctionScanner.PLATFORM_HEADERS[EdgePlatform.DENO_DEPLOY]]
        assert "x-deno-region" in names

    def test_lambda_has_amz_cf_id_header(self):
        names = [h[0] for h in EdgeFunctionScanner.PLATFORM_HEADERS[EdgePlatform.LAMBDA_EDGE]]
        assert "x-amz-cf-id" in names

    def test_fastly_has_served_by_header(self):
        names = [h[0] for h in EdgeFunctionScanner.PLATFORM_HEADERS[EdgePlatform.FASTLY]]
        assert "x-served-by" in names

    def test_all_patterns_compile_as_regex(self):
        for platform, entries in EdgeFunctionScanner.PLATFORM_HEADERS.items():
            for header_name, pattern in entries:
                compiled = re.compile(pattern, re.IGNORECASE)
                assert compiled is not None, f"Failed to compile: {pattern}"


# =============================================================================
# PLATFORM_HEADERS REGEX MATCHING
# =============================================================================

class TestPlatformHeadersRegexMatching:
    def test_vercel_server_header_matches(self):
        pattern = dict(EdgeFunctionScanner.PLATFORM_HEADERS[EdgePlatform.VERCEL])["server"]
        assert re.search(pattern, "vercel", re.IGNORECASE)

    def test_cloudflare_server_header_matches(self):
        pattern = dict(EdgeFunctionScanner.PLATFORM_HEADERS[EdgePlatform.CLOUDFLARE])["server"]
        assert re.search(pattern, "cloudflare", re.IGNORECASE)

    def test_deno_server_header_matches(self):
        pattern = dict(EdgeFunctionScanner.PLATFORM_HEADERS[EdgePlatform.DENO_DEPLOY])["server"]
        assert re.search(pattern, "deno", re.IGNORECASE)

    def test_lambda_x_cache_matches_from_cloudfront(self):
        pattern = dict(EdgeFunctionScanner.PLATFORM_HEADERS[EdgePlatform.LAMBDA_EDGE])["x-cache"]
        assert re.search(pattern, "Hit from cloudfront", re.IGNORECASE)

    def test_fastly_x_served_by_matches_cache(self):
        pattern = dict(EdgeFunctionScanner.PLATFORM_HEADERS[EdgePlatform.FASTLY])["x-served-by"]
        assert re.search(pattern, "cache-iad2133", re.IGNORECASE)

    def test_cf_ray_wildcard_matches_any(self):
        pattern = dict(EdgeFunctionScanner.PLATFORM_HEADERS[EdgePlatform.CLOUDFLARE])["cf-ray"]
        assert re.search(pattern, "8abc1234defgh-IAD", re.IGNORECASE)

    def test_vercel_id_wildcard_matches_any(self):
        pattern = dict(EdgeFunctionScanner.PLATFORM_HEADERS[EdgePlatform.VERCEL])["x-vercel-id"]
        assert re.search(pattern, "iad1::xxxxx-1234567890123-abc", re.IGNORECASE)


# =============================================================================
# EDGE_ENDPOINTS LIST
# =============================================================================

class TestEdgeEndpointsList:
    def test_count(self):
        assert len(EdgeFunctionScanner.EDGE_ENDPOINTS) == 9

    def test_all_entries_are_strings(self):
        for ep in EdgeFunctionScanner.EDGE_ENDPOINTS:
            assert isinstance(ep, str)

    def test_all_entries_start_with_slash(self):
        for ep in EdgeFunctionScanner.EDGE_ENDPOINTS:
            assert ep.startswith("/"), f"{ep} does not start with /"

    def test_contains_api_root(self):
        assert "/api/" in EdgeFunctionScanner.EDGE_ENDPOINTS

    def test_contains_edge_path(self):
        assert "/edge/" in EdgeFunctionScanner.EDGE_ENDPOINTS

    def test_contains_underscore_edge(self):
        assert "/_edge/" in EdgeFunctionScanner.EDGE_ENDPOINTS

    def test_contains_netlify_functions(self):
        assert "/.netlify/functions/" in EdgeFunctionScanner.EDGE_ENDPOINTS

    def test_contains_vercel_functions(self):
        assert "/.vercel/functions/" in EdgeFunctionScanner.EDGE_ENDPOINTS

    def test_contains_functions(self):
        assert "/functions/" in EdgeFunctionScanner.EDGE_ENDPOINTS

    def test_contains_api_hello(self):
        assert "/api/hello" in EdgeFunctionScanner.EDGE_ENDPOINTS

    def test_contains_api_test(self):
        assert "/api/test" in EdgeFunctionScanner.EDGE_ENDPOINTS

    def test_contains_api_edge(self):
        assert "/api/edge/" in EdgeFunctionScanner.EDGE_ENDPOINTS


# =============================================================================
# ENV_PATTERNS LIST
# =============================================================================

class TestEnvPatterns:
    def test_count(self):
        assert len(EdgeFunctionScanner.ENV_PATTERNS) == 12

    def test_all_entries_are_strings(self):
        for p in EdgeFunctionScanner.ENV_PATTERNS:
            assert isinstance(p, str)

    def test_all_patterns_compile_as_regex(self):
        for p in EdgeFunctionScanner.ENV_PATTERNS:
            compiled = re.compile(p)
            assert compiled is not None, f"Failed to compile: {p}"

    def test_vercel_pattern_present(self):
        assert r"VERCEL_[A-Z_]+" in EdgeFunctionScanner.ENV_PATTERNS

    def test_cf_pattern_present(self):
        assert r"CF_[A-Z_]+" in EdgeFunctionScanner.ENV_PATTERNS

    def test_cloudflare_pattern_present(self):
        assert r"CLOUDFLARE_[A-Z_]+" in EdgeFunctionScanner.ENV_PATTERNS

    def test_netlify_pattern_present(self):
        assert r"NETLIFY_[A-Z_]+" in EdgeFunctionScanner.ENV_PATTERNS

    def test_deno_pattern_present(self):
        assert r"DENO_[A-Z_]+" in EdgeFunctionScanner.ENV_PATTERNS

    def test_aws_pattern_present(self):
        assert r"AWS_[A-Z_]+" in EdgeFunctionScanner.ENV_PATTERNS

    def test_database_url_present(self):
        assert r"DATABASE_URL" in EdgeFunctionScanner.ENV_PATTERNS

    def test_api_key_present(self):
        assert r"API_KEY" in EdgeFunctionScanner.ENV_PATTERNS

    def test_secret_key_present(self):
        assert r"SECRET_KEY" in EdgeFunctionScanner.ENV_PATTERNS

    def test_auth_secret_present(self):
        assert r"AUTH_SECRET" in EdgeFunctionScanner.ENV_PATTERNS

    def test_next_public_present(self):
        assert r"NEXT_PUBLIC_[A-Z_]+" in EdgeFunctionScanner.ENV_PATTERNS

    def test_private_present(self):
        assert r"PRIVATE_[A-Z_]+" in EdgeFunctionScanner.ENV_PATTERNS


# =============================================================================
# ENV_PATTERNS REGEX MATCHING
# =============================================================================

class TestEnvPatternsRegexMatching:
    def test_vercel_env_matches(self):
        pattern = r"VERCEL_[A-Z_]+"
        assert re.search(pattern, "VERCEL_URL")
        assert re.search(pattern, "VERCEL_ENV")
        assert re.search(pattern, "VERCEL_GIT_COMMIT_SHA")

    def test_cf_env_matches(self):
        pattern = r"CF_[A-Z_]+"
        assert re.search(pattern, "CF_PAGES_URL")
        assert re.search(pattern, "CF_WORKER_ID")

    def test_cloudflare_env_matches(self):
        pattern = r"CLOUDFLARE_[A-Z_]+"
        assert re.search(pattern, "CLOUDFLARE_API_TOKEN")

    def test_netlify_env_matches(self):
        pattern = r"NETLIFY_[A-Z_]+"
        assert re.search(pattern, "NETLIFY_SITE_ID")

    def test_deno_env_matches(self):
        pattern = r"DENO_[A-Z_]+"
        assert re.search(pattern, "DENO_DEPLOYMENT_ID")

    def test_aws_env_matches(self):
        pattern = r"AWS_[A-Z_]+"
        assert re.search(pattern, "AWS_ACCESS_KEY_ID")
        assert re.search(pattern, "AWS_SECRET_ACCESS_KEY")
        assert re.search(pattern, "AWS_REGION")

    def test_database_url_matches(self):
        pattern = r"DATABASE_URL"
        assert re.search(pattern, 'DATABASE_URL=postgres://...')

    def test_api_key_matches(self):
        pattern = r"API_KEY"
        assert re.search(pattern, 'API_KEY=sk_live_xxx')

    def test_next_public_matches(self):
        pattern = r"NEXT_PUBLIC_[A-Z_]+"
        assert re.search(pattern, "NEXT_PUBLIC_API_URL")

    def test_private_matches(self):
        pattern = r"PRIVATE_[A-Z_]+"
        assert re.search(pattern, "PRIVATE_API_KEY")

    def test_no_match_on_lowercase(self):
        """Patterns require uppercase letters."""
        pattern = r"VERCEL_[A-Z_]+"
        assert not re.search(pattern, "VERCEL_lowercase")


# =============================================================================
# STORAGE_PATTERNS DICT
# =============================================================================

class TestStoragePatterns:
    def test_storage_type_count(self):
        assert len(EdgeFunctionScanner.STORAGE_PATTERNS) == 6

    def test_keys_are_strings(self):
        for key in EdgeFunctionScanner.STORAGE_PATTERNS:
            assert isinstance(key, str)

    def test_values_are_lists(self):
        for key, val in EdgeFunctionScanner.STORAGE_PATTERNS.items():
            assert isinstance(val, list), f"{key} value is not a list"

    def test_cloudflare_kv_present(self):
        assert "cloudflare_kv" in EdgeFunctionScanner.STORAGE_PATTERNS

    def test_cloudflare_r2_present(self):
        assert "cloudflare_r2" in EdgeFunctionScanner.STORAGE_PATTERNS

    def test_cloudflare_d1_present(self):
        assert "cloudflare_d1" in EdgeFunctionScanner.STORAGE_PATTERNS

    def test_netlify_blob_present(self):
        assert "netlify_blob" in EdgeFunctionScanner.STORAGE_PATTERNS

    def test_vercel_kv_present(self):
        assert "vercel_kv" in EdgeFunctionScanner.STORAGE_PATTERNS

    def test_vercel_postgres_present(self):
        assert "vercel_postgres" in EdgeFunctionScanner.STORAGE_PATTERNS

    def test_cloudflare_kv_pattern_count(self):
        assert len(EdgeFunctionScanner.STORAGE_PATTERNS["cloudflare_kv"]) == 4

    def test_cloudflare_r2_pattern_count(self):
        assert len(EdgeFunctionScanner.STORAGE_PATTERNS["cloudflare_r2"]) == 4

    def test_cloudflare_d1_pattern_count(self):
        assert len(EdgeFunctionScanner.STORAGE_PATTERNS["cloudflare_d1"]) == 4

    def test_netlify_blob_pattern_count(self):
        assert len(EdgeFunctionScanner.STORAGE_PATTERNS["netlify_blob"]) == 3

    def test_vercel_kv_pattern_count(self):
        assert len(EdgeFunctionScanner.STORAGE_PATTERNS["vercel_kv"]) == 3

    def test_vercel_postgres_pattern_count(self):
        assert len(EdgeFunctionScanner.STORAGE_PATTERNS["vercel_postgres"]) == 3

    def test_all_patterns_compile_as_regex(self):
        for storage_type, patterns in EdgeFunctionScanner.STORAGE_PATTERNS.items():
            for p in patterns:
                compiled = re.compile(p, re.IGNORECASE)
                assert compiled is not None, f"Failed to compile {storage_type}: {p}"


# =============================================================================
# STORAGE_PATTERNS REGEX MATCHING
# =============================================================================

class TestStoragePatternsRegexMatching:
    def test_cloudflare_kv_dot_matches(self):
        patterns = EdgeFunctionScanner.STORAGE_PATTERNS["cloudflare_kv"]
        assert any(re.search(p, "KV.get('mykey')", re.IGNORECASE) for p in patterns)

    def test_cloudflare_kv_env_matches(self):
        patterns = EdgeFunctionScanner.STORAGE_PATTERNS["cloudflare_kv"]
        assert any(re.search(p, "env.KV", re.IGNORECASE) for p in patterns)

    def test_cloudflare_kv_namespace_get_matches(self):
        patterns = EdgeFunctionScanner.STORAGE_PATTERNS["cloudflare_kv"]
        assert any(re.search(p, "NAMESPACE.get('key')", re.IGNORECASE) for p in patterns)

    def test_cloudflare_kv_namespace_put_matches(self):
        patterns = EdgeFunctionScanner.STORAGE_PATTERNS["cloudflare_kv"]
        assert any(re.search(p, "NAMESPACE.put('key','val')", re.IGNORECASE) for p in patterns)

    def test_cloudflare_r2_dot_matches(self):
        patterns = EdgeFunctionScanner.STORAGE_PATTERNS["cloudflare_r2"]
        assert any(re.search(p, "R2.get('file')", re.IGNORECASE) for p in patterns)

    def test_cloudflare_r2_bucket_matches(self):
        patterns = EdgeFunctionScanner.STORAGE_PATTERNS["cloudflare_r2"]
        assert any(re.search(p, "BUCKET.put('key', data)", re.IGNORECASE) for p in patterns)

    def test_cloudflare_d1_prepare_matches(self):
        patterns = EdgeFunctionScanner.STORAGE_PATTERNS["cloudflare_d1"]
        assert any(re.search(p, "DB.prepare('SELECT * FROM x')", re.IGNORECASE) for p in patterns)

    def test_cloudflare_d1_exec_matches(self):
        patterns = EdgeFunctionScanner.STORAGE_PATTERNS["cloudflare_d1"]
        assert any(re.search(p, "DB.exec('INSERT INTO x')", re.IGNORECASE) for p in patterns)

    def test_netlify_blob_get_store_matches(self):
        patterns = EdgeFunctionScanner.STORAGE_PATTERNS["netlify_blob"]
        assert any(re.search(p, "getStore('mystore')", re.IGNORECASE) for p in patterns)

    def test_netlify_blob_set_matches(self):
        patterns = EdgeFunctionScanner.STORAGE_PATTERNS["netlify_blob"]
        assert any(re.search(p, "Blob.set('key','val')", re.IGNORECASE) for p in patterns)

    def test_vercel_kv_import_matches(self):
        patterns = EdgeFunctionScanner.STORAGE_PATTERNS["vercel_kv"]
        assert any(re.search(p, "import { kv } from '@vercel/kv'", re.IGNORECASE) for p in patterns)

    def test_vercel_kv_get_matches(self):
        patterns = EdgeFunctionScanner.STORAGE_PATTERNS["vercel_kv"]
        assert any(re.search(p, "kv.get('session')", re.IGNORECASE) for p in patterns)

    def test_vercel_postgres_import_matches(self):
        patterns = EdgeFunctionScanner.STORAGE_PATTERNS["vercel_postgres"]
        assert any(re.search(p, "from '@vercel/postgres'", re.IGNORECASE) for p in patterns)

    def test_vercel_postgres_sql_matches(self):
        patterns = EdgeFunctionScanner.STORAGE_PATTERNS["vercel_postgres"]
        assert any(re.search(p, "sql`SELECT * FROM users`", re.IGNORECASE) for p in patterns)

    def test_vercel_postgres_db_query_matches(self):
        patterns = EdgeFunctionScanner.STORAGE_PATTERNS["vercel_postgres"]
        assert any(re.search(p, "db.query('SELECT 1')", re.IGNORECASE) for p in patterns)
