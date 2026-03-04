"""Tests for scanning.modules.bun_deno_fingerprinter — static structure tests."""

import re

import pytest

from scanning.modules.bun_deno_fingerprinter import (
    BUN_DANGEROUS_APIS,
    BUN_DENO_FINGERPRINTER_VERSION,
    BunDenoFingerprinter,
    DENO_PERMISSION_INDICATORS,
    JSRuntime,
    RUNTIME_FINGERPRINTS,
    RuntimeInfo,
    RuntimeTestResult,
    RuntimeVulnType,
)
from scanning.vuln_scanner import ScanModule


# =============================================================================
# ENUM: JSRuntime
# =============================================================================

class TestJSRuntime:
    """Test JSRuntime enum."""

    def test_member_count(self):
        assert len(JSRuntime) == 8

    def test_bun(self):
        assert JSRuntime.BUN.value == "bun"

    def test_deno(self):
        assert JSRuntime.DENO.value == "deno"

    def test_node(self):
        assert JSRuntime.NODE.value == "node"

    def test_deno_deploy(self):
        assert JSRuntime.DENO_DEPLOY.value == "deno_deploy"

    def test_cloudflare_workers(self):
        assert JSRuntime.CLOUDFLARE_WORKERS.value == "cloudflare_workers"

    def test_vercel_edge(self):
        assert JSRuntime.VERCEL_EDGE.value == "vercel_edge"

    def test_netlify_edge(self):
        assert JSRuntime.NETLIFY_EDGE.value == "netlify_edge"

    def test_unknown(self):
        assert JSRuntime.UNKNOWN.value == "unknown"

    def test_unique_values(self):
        values = [m.value for m in JSRuntime]
        assert len(values) == len(set(values))


# =============================================================================
# ENUM: RuntimeVulnType
# =============================================================================

class TestRuntimeVulnType:
    """Test RuntimeVulnType enum."""

    def test_member_count(self):
        assert len(RuntimeVulnType) == 8

    def test_runtime_version_leak(self):
        assert RuntimeVulnType.RUNTIME_VERSION_LEAK is not None

    def test_permission_misconfiguration(self):
        assert RuntimeVulnType.PERMISSION_MISCONFIGURATION is not None

    def test_unsafe_api_exposed(self):
        assert RuntimeVulnType.UNSAFE_API_EXPOSED is not None

    def test_debug_mode_enabled(self):
        assert RuntimeVulnType.DEBUG_MODE_ENABLED is not None

    def test_outdated_runtime(self):
        assert RuntimeVulnType.OUTDATED_RUNTIME is not None

    def test_config_exposure(self):
        assert RuntimeVulnType.CONFIG_EXPOSURE is not None

    def test_import_map_exposure(self):
        assert RuntimeVulnType.IMPORT_MAP_EXPOSURE is not None

    def test_permission_bypass(self):
        assert RuntimeVulnType.PERMISSION_BYPASS is not None

    def test_unique_values(self):
        values = [m.value for m in RuntimeVulnType]
        assert len(values) == len(set(values))


# =============================================================================
# DATACLASS: RuntimeInfo
# =============================================================================

class TestRuntimeInfo:
    """Test RuntimeInfo dataclass."""

    def test_minimal_creation(self):
        ri = RuntimeInfo(runtime=JSRuntime.BUN)
        assert ri.runtime == JSRuntime.BUN

    def test_defaults(self):
        ri = RuntimeInfo(runtime=JSRuntime.DENO)
        assert ri.version == ""
        assert ri.detected_via == ""
        assert ri.permissions == []
        assert ri.features == []
        assert ri.confidence == 0

    def test_full_creation(self):
        ri = RuntimeInfo(
            runtime=JSRuntime.DENO,
            version="1.30.0",
            detected_via="header",
            permissions=["--allow-net"],
            features=["kv"],
            confidence=95,
        )
        assert ri.version == "1.30.0"
        assert ri.confidence == 95


# =============================================================================
# DATACLASS: RuntimeTestResult
# =============================================================================

class TestRuntimeTestResult:
    """Test RuntimeTestResult dataclass."""

    def test_minimal_creation(self):
        rtr = RuntimeTestResult(
            vulnerable=True,
            vuln_type=RuntimeVulnType.RUNTIME_VERSION_LEAK,
            confidence=80,
            runtime=JSRuntime.BUN,
        )
        assert rtr.vulnerable is True
        assert rtr.confidence == 80

    def test_defaults(self):
        rtr = RuntimeTestResult(
            vulnerable=False,
            vuln_type=RuntimeVulnType.CONFIG_EXPOSURE,
            confidence=50,
            runtime=JSRuntime.NODE,
        )
        assert rtr.evidence == []
        assert rtr.severity == "INFO"
        assert rtr.cwe == "CWE-200"


# =============================================================================
# CONSTANT: RUNTIME_FINGERPRINTS
# =============================================================================

class TestRuntimeFingerprints:
    """Test RUNTIME_FINGERPRINTS dict."""

    def test_is_dict(self):
        assert isinstance(RUNTIME_FINGERPRINTS, dict)

    def test_has_bun(self):
        assert JSRuntime.BUN in RUNTIME_FINGERPRINTS

    def test_has_deno(self):
        assert JSRuntime.DENO in RUNTIME_FINGERPRINTS

    def test_has_node(self):
        assert JSRuntime.NODE in RUNTIME_FINGERPRINTS

    def test_has_deno_deploy(self):
        assert JSRuntime.DENO_DEPLOY in RUNTIME_FINGERPRINTS

    def test_has_cloudflare_workers(self):
        assert JSRuntime.CLOUDFLARE_WORKERS in RUNTIME_FINGERPRINTS

    def test_bun_has_headers(self):
        assert "headers" in RUNTIME_FINGERPRINTS[JSRuntime.BUN]
        assert len(RUNTIME_FINGERPRINTS[JSRuntime.BUN]["headers"]) >= 3

    def test_bun_has_errors(self):
        assert "errors" in RUNTIME_FINGERPRINTS[JSRuntime.BUN]
        assert len(RUNTIME_FINGERPRINTS[JSRuntime.BUN]["errors"]) >= 5

    def test_deno_has_permissions(self):
        assert "permissions" in RUNTIME_FINGERPRINTS[JSRuntime.DENO]
        perms = RUNTIME_FINGERPRINTS[JSRuntime.DENO]["permissions"]
        assert "--allow-read" in perms
        assert "--allow-all" in perms

    def test_node_has_known_vulns(self):
        vulns = RUNTIME_FINGERPRINTS[JSRuntime.NODE]["known_vulns"]
        assert isinstance(vulns, dict)
        assert len(vulns) >= 2

    def test_header_patterns_compile(self):
        for runtime, data in RUNTIME_FINGERPRINTS.items():
            for header_name, pattern, confidence in data.get("headers", []):
                compiled = re.compile(pattern)
                assert compiled is not None, f"Header pattern '{pattern}' for {runtime} failed"


# =============================================================================
# CONSTANT: DENO_PERMISSION_INDICATORS
# =============================================================================

class TestDenoPermissionIndicators:
    """Test DENO_PERMISSION_INDICATORS dict."""

    def test_is_dict(self):
        assert isinstance(DENO_PERMISSION_INDICATORS, dict)

    def test_key_count(self):
        assert len(DENO_PERMISSION_INDICATORS) == 6

    def test_has_allow_read(self):
        assert "allow-read" in DENO_PERMISSION_INDICATORS

    def test_has_allow_write(self):
        assert "allow-write" in DENO_PERMISSION_INDICATORS

    def test_has_allow_net(self):
        assert "allow-net" in DENO_PERMISSION_INDICATORS

    def test_has_allow_env(self):
        assert "allow-env" in DENO_PERMISSION_INDICATORS

    def test_has_allow_run(self):
        assert "allow-run" in DENO_PERMISSION_INDICATORS

    def test_has_allow_ffi(self):
        assert "allow-ffi" in DENO_PERMISSION_INDICATORS

    def test_patterns_compile(self):
        for perm, patterns in DENO_PERMISSION_INDICATORS.items():
            for p in patterns:
                compiled = re.compile(p)
                assert compiled is not None, f"Pattern '{p}' for {perm} failed"


# =============================================================================
# CONSTANT: BUN_DANGEROUS_APIS
# =============================================================================

class TestBunDangerousApis:
    """Test BUN_DANGEROUS_APIS dict."""

    def test_is_dict(self):
        assert isinstance(BUN_DANGEROUS_APIS, dict)

    def test_count(self):
        assert len(BUN_DANGEROUS_APIS) == 6

    def test_has_bun_spawn(self):
        assert "Bun.spawn" in BUN_DANGEROUS_APIS

    def test_has_bun_ffi(self):
        assert "bun:ffi" in BUN_DANGEROUS_APIS

    def test_bun_ffi_is_critical(self):
        assert BUN_DANGEROUS_APIS["bun:ffi"]["severity"] == "CRITICAL"

    def test_all_have_description(self):
        for api, data in BUN_DANGEROUS_APIS.items():
            assert "description" in data, f"{api} missing description"

    def test_all_have_severity(self):
        for api, data in BUN_DANGEROUS_APIS.items():
            assert "severity" in data, f"{api} missing severity"


# =============================================================================
# SCANNER IDENTITY
# =============================================================================

class TestScannerIdentity:
    """Test BunDenoFingerprinter scanner identity."""

    def test_is_scan_module_subclass(self):
        assert issubclass(BunDenoFingerprinter, ScanModule)

    def test_name_attribute(self):
        assert BunDenoFingerprinter.name == "bun_deno_fingerprinter"

    def test_version(self):
        assert BunDenoFingerprinter.version == BUN_DENO_FINGERPRINTER_VERSION

    def test_category(self):
        assert BunDenoFingerprinter.category == "fingerprint"

    def test_instantiation(self):
        scanner = BunDenoFingerprinter(
            settings={"target_url": "http://test.local", "safety_level": "safe"}
        )
        assert scanner is not None
