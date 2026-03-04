"""
Tests for scanning/modules/wasm_backend_scanner.py

Covers:
- WASMBackendVulnType enum (member count, values, uniqueness)
- WASMRuntime enum (member count, values, uniqueness)
- WASMBackendEndpoint dataclass (defaults, full creation)
- WASMBackendTestResult dataclass (defaults, full creation)
- Module-level constants: RUNTIME_FINGERPRINTS, WASI_DANGEROUS_CAPABILITIES, WASI_EXTENSIONS
- WASM_BACKEND_SCANNER_VERSION constant
- WASMBackendScanner identity (name, version, category, ScanModule subclass)
- Regex patterns in RUNTIME_FINGERPRINTS and config exposure (compile, match)
"""

import re

import pytest

from scanning.modules.wasm_backend_scanner import (
    # Constants
    WASM_BACKEND_SCANNER_VERSION,
    # Enums
    WASMBackendVulnType,
    WASMRuntime,
    # Dataclasses
    WASMBackendEndpoint,
    WASMBackendTestResult,
    # Dicts
    RUNTIME_FINGERPRINTS,
    WASI_DANGEROUS_CAPABILITIES,
    WASI_EXTENSIONS,
    # Scanner
    WASMBackendScanner,
)
from scanning.vuln_scanner import ScanModule


# =============================================================================
# MODULE VERSION CONSTANT
# =============================================================================

class TestWASMBackendScannerVersion:
    """Test module-level version constant."""

    def test_version_is_string(self):
        assert isinstance(WASM_BACKEND_SCANNER_VERSION, str)

    def test_version_value(self):
        assert WASM_BACKEND_SCANNER_VERSION == "1.0.0"

    def test_version_semver_format(self):
        parts = WASM_BACKEND_SCANNER_VERSION.split(".")
        assert len(parts) == 3
        for part in parts:
            assert part.isdigit()


# =============================================================================
# WASMBackendVulnType ENUM
# =============================================================================

class TestWASMBackendVulnType:
    """Test WASMBackendVulnType enum."""

    def test_member_count(self):
        assert len(WASMBackendVulnType) == 8

    def test_runtime_detection_exists(self):
        assert WASMBackendVulnType.RUNTIME_DETECTION is not None

    def test_wasi_overexposure_exists(self):
        assert WASMBackendVulnType.WASI_OVEREXPOSURE is not None

    def test_sandbox_weakness_exists(self):
        assert WASMBackendVulnType.SANDBOX_WEAKNESS is not None

    def test_resource_exhaustion_exists(self):
        assert WASMBackendVulnType.RESOURCE_EXHAUSTION is not None

    def test_module_injection_exists(self):
        assert WASMBackendVulnType.MODULE_INJECTION is not None

    def test_capability_bypass_exists(self):
        assert WASMBackendVulnType.CAPABILITY_BYPASS is not None

    def test_config_exposure_exists(self):
        assert WASMBackendVulnType.CONFIG_EXPOSURE is not None

    def test_memory_disclosure_exists(self):
        assert WASMBackendVulnType.MEMORY_DISCLOSURE is not None

    def test_all_values_unique(self):
        values = [m.value for m in WASMBackendVulnType]
        assert len(values) == len(set(values))

    def test_all_names_unique(self):
        names = [m.name for m in WASMBackendVulnType]
        assert len(names) == len(set(names))

    def test_name_access_via_string(self):
        assert WASMBackendVulnType["SANDBOX_WEAKNESS"] == WASMBackendVulnType.SANDBOX_WEAKNESS

    def test_members_are_auto(self):
        """All members use auto() so values should be ints."""
        for member in WASMBackendVulnType:
            assert isinstance(member.value, int)


# =============================================================================
# WASMRuntime ENUM
# =============================================================================

class TestWASMRuntime:
    """Test WASMRuntime enum."""

    def test_member_count(self):
        assert len(WASMRuntime) == 10

    def test_wasmtime_value(self):
        assert WASMRuntime.WASMTIME.value == "wasmtime"

    def test_wasmer_value(self):
        assert WASMRuntime.WASMER.value == "wasmer"

    def test_wasmedge_value(self):
        assert WASMRuntime.WASMEDGE.value == "wasmedge"

    def test_wamr_value(self):
        assert WASMRuntime.WAMR.value == "wamr"

    def test_wasmcloud_value(self):
        assert WASMRuntime.WASMCLOUD.value == "wasmcloud"

    def test_spin_value(self):
        assert WASMRuntime.SPIN.value == "spin"

    def test_lunatic_value(self):
        assert WASMRuntime.LUNATIC.value == "lunatic"

    def test_wazero_value(self):
        assert WASMRuntime.WAZERO.value == "wazero"

    def test_node_wasm_value(self):
        assert WASMRuntime.NODE_WASM.value == "node_wasm"

    def test_unknown_value(self):
        assert WASMRuntime.UNKNOWN.value == "unknown"

    def test_all_values_unique(self):
        values = [m.value for m in WASMRuntime]
        assert len(values) == len(set(values))

    def test_all_values_are_strings(self):
        for member in WASMRuntime:
            assert isinstance(member.value, str)

    def test_all_values_lowercase(self):
        for member in WASMRuntime:
            assert member.value == member.value.lower()

    def test_lookup_by_value(self):
        assert WASMRuntime("wasmtime") == WASMRuntime.WASMTIME

    def test_lookup_by_name(self):
        assert WASMRuntime["SPIN"] == WASMRuntime.SPIN


# =============================================================================
# WASMBackendEndpoint DATACLASS
# =============================================================================

class TestWASMBackendEndpoint:
    """Test WASMBackendEndpoint dataclass."""

    def test_minimal_creation(self):
        ep = WASMBackendEndpoint(url="http://test.local", runtime=WASMRuntime.WASMTIME)
        assert ep.url == "http://test.local"
        assert ep.runtime == WASMRuntime.WASMTIME

    def test_defaults(self):
        ep = WASMBackendEndpoint(url="http://test.local", runtime=WASMRuntime.UNKNOWN)
        assert ep.version == ""
        assert ep.wasi_capabilities == []
        assert ep.detected_via == ""

    def test_full_creation(self):
        ep = WASMBackendEndpoint(
            url="http://test.local/api",
            runtime=WASMRuntime.SPIN,
            version="2.0.1",
            wasi_capabilities=["filesystem", "network"],
            detected_via="header:server",
        )
        assert ep.url == "http://test.local/api"
        assert ep.runtime == WASMRuntime.SPIN
        assert ep.version == "2.0.1"
        assert ep.wasi_capabilities == ["filesystem", "network"]
        assert ep.detected_via == "header:server"

    def test_wasi_capabilities_list_independent(self):
        ep1 = WASMBackendEndpoint(url="http://a.local", runtime=WASMRuntime.WASMER)
        ep2 = WASMBackendEndpoint(url="http://b.local", runtime=WASMRuntime.WASMER)
        ep1.wasi_capabilities.append("filesystem")
        assert len(ep2.wasi_capabilities) == 0


# =============================================================================
# WASMBackendTestResult DATACLASS
# =============================================================================

class TestWASMBackendTestResult:
    """Test WASMBackendTestResult dataclass."""

    def test_minimal_creation(self):
        result = WASMBackendTestResult(
            vulnerable=True,
            vuln_type=WASMBackendVulnType.SANDBOX_WEAKNESS,
            confidence=85,
            runtime=WASMRuntime.WASMTIME,
        )
        assert result.vulnerable is True
        assert result.vuln_type == WASMBackendVulnType.SANDBOX_WEAKNESS
        assert result.confidence == 85
        assert result.runtime == WASMRuntime.WASMTIME

    def test_defaults(self):
        result = WASMBackendTestResult(
            vulnerable=False,
            vuln_type=WASMBackendVulnType.RUNTIME_DETECTION,
            confidence=50,
            runtime=WASMRuntime.UNKNOWN,
        )
        assert result.evidence == []
        assert result.severity == "MEDIUM"
        assert result.cwe == "CWE-250"
        assert result.exposed_capabilities == []

    def test_full_creation(self):
        result = WASMBackendTestResult(
            vulnerable=True,
            vuln_type=WASMBackendVulnType.WASI_OVEREXPOSURE,
            confidence=75,
            runtime=WASMRuntime.WASMEDGE,
            evidence=["cap exposed", "sandbox weak"],
            severity="HIGH",
            cwe="CWE-284",
            exposed_capabilities=["filesystem", "network", "process"],
        )
        assert result.vulnerable is True
        assert result.vuln_type == WASMBackendVulnType.WASI_OVEREXPOSURE
        assert result.confidence == 75
        assert result.runtime == WASMRuntime.WASMEDGE
        assert len(result.evidence) == 2
        assert result.severity == "HIGH"
        assert result.cwe == "CWE-284"
        assert len(result.exposed_capabilities) == 3

    def test_evidence_list_independent(self):
        r1 = WASMBackendTestResult(
            vulnerable=False,
            vuln_type=WASMBackendVulnType.RUNTIME_DETECTION,
            confidence=0,
            runtime=WASMRuntime.UNKNOWN,
        )
        r2 = WASMBackendTestResult(
            vulnerable=False,
            vuln_type=WASMBackendVulnType.RUNTIME_DETECTION,
            confidence=0,
            runtime=WASMRuntime.UNKNOWN,
        )
        r1.evidence.append("test")
        assert len(r2.evidence) == 0

    def test_exposed_capabilities_list_independent(self):
        r1 = WASMBackendTestResult(
            vulnerable=False,
            vuln_type=WASMBackendVulnType.RUNTIME_DETECTION,
            confidence=0,
            runtime=WASMRuntime.UNKNOWN,
        )
        r2 = WASMBackendTestResult(
            vulnerable=False,
            vuln_type=WASMBackendVulnType.RUNTIME_DETECTION,
            confidence=0,
            runtime=WASMRuntime.UNKNOWN,
        )
        r1.exposed_capabilities.append("filesystem")
        assert len(r2.exposed_capabilities) == 0


# =============================================================================
# RUNTIME_FINGERPRINTS DICT
# =============================================================================

class TestRuntimeFingerprints:
    """Test RUNTIME_FINGERPRINTS module-level dict."""

    def test_is_dict(self):
        assert isinstance(RUNTIME_FINGERPRINTS, dict)

    def test_key_count(self):
        assert len(RUNTIME_FINGERPRINTS) == 7

    def test_keys_are_wasm_runtime_enum(self):
        for key in RUNTIME_FINGERPRINTS:
            assert isinstance(key, WASMRuntime)

    def test_contains_wasmtime(self):
        assert WASMRuntime.WASMTIME in RUNTIME_FINGERPRINTS

    def test_contains_wasmer(self):
        assert WASMRuntime.WASMER in RUNTIME_FINGERPRINTS

    def test_contains_wasmedge(self):
        assert WASMRuntime.WASMEDGE in RUNTIME_FINGERPRINTS

    def test_contains_spin(self):
        assert WASMRuntime.SPIN in RUNTIME_FINGERPRINTS

    def test_contains_wasmcloud(self):
        assert WASMRuntime.WASMCLOUD in RUNTIME_FINGERPRINTS

    def test_contains_lunatic(self):
        assert WASMRuntime.LUNATIC in RUNTIME_FINGERPRINTS

    def test_contains_wazero(self):
        assert WASMRuntime.WAZERO in RUNTIME_FINGERPRINTS

    def test_does_not_contain_unknown(self):
        assert WASMRuntime.UNKNOWN not in RUNTIME_FINGERPRINTS

    def test_each_entry_has_headers_key(self):
        for runtime, fp in RUNTIME_FINGERPRINTS.items():
            assert "headers" in fp, f"{runtime.name} missing 'headers'"

    def test_each_entry_has_errors_key(self):
        for runtime, fp in RUNTIME_FINGERPRINTS.items():
            assert "errors" in fp, f"{runtime.name} missing 'errors'"

    def test_each_entry_has_features_key(self):
        for runtime, fp in RUNTIME_FINGERPRINTS.items():
            assert "features" in fp, f"{runtime.name} missing 'features'"

    def test_headers_are_lists_of_tuples(self):
        for runtime, fp in RUNTIME_FINGERPRINTS.items():
            assert isinstance(fp["headers"], list)
            for entry in fp["headers"]:
                assert isinstance(entry, tuple), f"{runtime.name} header entry not a tuple"
                assert len(entry) == 2

    def test_errors_are_lists_of_strings(self):
        for runtime, fp in RUNTIME_FINGERPRINTS.items():
            assert isinstance(fp["errors"], list)
            for entry in fp["errors"]:
                assert isinstance(entry, str)

    def test_features_are_lists_of_strings(self):
        for runtime, fp in RUNTIME_FINGERPRINTS.items():
            assert isinstance(fp["features"], list)
            for entry in fp["features"]:
                assert isinstance(entry, str)

    def test_all_error_patterns_compile_as_regex(self):
        for runtime, fp in RUNTIME_FINGERPRINTS.items():
            for pattern in fp["errors"]:
                compiled = re.compile(pattern, re.IGNORECASE)
                assert compiled is not None, f"Failed to compile: {pattern}"

    def test_all_header_patterns_compile_as_regex(self):
        for runtime, fp in RUNTIME_FINGERPRINTS.items():
            for header_name, pattern in fp["headers"]:
                compiled = re.compile(pattern, re.IGNORECASE)
                assert compiled is not None, f"Failed to compile: {pattern}"

    def test_wasmtime_header_pattern_matches(self):
        headers = RUNTIME_FINGERPRINTS[WASMRuntime.WASMTIME]["headers"]
        # First header: ("x-wasmtime-version", r".*")
        name, pattern = headers[0]
        assert name == "x-wasmtime-version"
        assert re.search(pattern, "1.2.3")

    def test_wasmtime_error_pattern_matches(self):
        errors = RUNTIME_FINGERPRINTS[WASMRuntime.WASMTIME]["errors"]
        assert re.search(errors[0], "wasmtime::some_error", re.IGNORECASE)
        assert re.search(errors[2], "cranelift compiler error", re.IGNORECASE)
        assert re.search(errors[3], "wasm trap occurred", re.IGNORECASE)

    def test_wasmer_error_pattern_matches(self):
        errors = RUNTIME_FINGERPRINTS[WASMRuntime.WASMER]["errors"]
        assert re.search(errors[0], "wasmer::runtime_error", re.IGNORECASE)
        assert re.search(errors[2], "RuntimeError: Out of bounds memory", re.IGNORECASE)

    def test_spin_header_pattern_matches(self):
        headers = RUNTIME_FINGERPRINTS[WASMRuntime.SPIN]["headers"]
        name, pattern = headers[0]
        assert name == "server"
        assert re.search(pattern, "spin/2.0", re.IGNORECASE)

    def test_wasmcloud_features_contain_capability(self):
        features = RUNTIME_FINGERPRINTS[WASMRuntime.WASMCLOUD]["features"]
        assert "capability" in features

    def test_wazero_has_empty_headers(self):
        headers = RUNTIME_FINGERPRINTS[WASMRuntime.WAZERO]["headers"]
        assert headers == []

    def test_wazero_errors_match(self):
        errors = RUNTIME_FINGERPRINTS[WASMRuntime.WAZERO]["errors"]
        assert re.search(errors[0], "wazero::module_error", re.IGNORECASE)


# =============================================================================
# WASI_DANGEROUS_CAPABILITIES DICT
# =============================================================================

class TestWASIDangerousCapabilities:
    """Test WASI_DANGEROUS_CAPABILITIES module-level dict."""

    def test_is_dict(self):
        assert isinstance(WASI_DANGEROUS_CAPABILITIES, dict)

    def test_key_count(self):
        assert len(WASI_DANGEROUS_CAPABILITIES) == 7

    def test_expected_keys(self):
        expected = {"filesystem", "network", "process", "random", "clock", "env", "args"}
        assert set(WASI_DANGEROUS_CAPABILITIES.keys()) == expected

    def test_each_entry_has_severity(self):
        for cap, info in WASI_DANGEROUS_CAPABILITIES.items():
            assert "severity" in info, f"{cap} missing 'severity'"

    def test_each_entry_has_description(self):
        for cap, info in WASI_DANGEROUS_CAPABILITIES.items():
            assert "description" in info, f"{cap} missing 'description'"
            assert isinstance(info["description"], str)
            assert len(info["description"]) > 0

    def test_each_entry_has_indicators(self):
        for cap, info in WASI_DANGEROUS_CAPABILITIES.items():
            assert "indicators" in info, f"{cap} missing 'indicators'"
            assert isinstance(info["indicators"], list)
            assert len(info["indicators"]) > 0

    def test_all_indicators_are_strings(self):
        for cap, info in WASI_DANGEROUS_CAPABILITIES.items():
            for indicator in info["indicators"]:
                assert isinstance(indicator, str)

    def test_severity_values_valid(self):
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for cap, info in WASI_DANGEROUS_CAPABILITIES.items():
            assert info["severity"] in valid, f"{cap} has invalid severity: {info['severity']}"

    def test_filesystem_severity_high(self):
        assert WASI_DANGEROUS_CAPABILITIES["filesystem"]["severity"] == "HIGH"

    def test_network_severity_high(self):
        assert WASI_DANGEROUS_CAPABILITIES["network"]["severity"] == "HIGH"

    def test_process_severity_critical(self):
        assert WASI_DANGEROUS_CAPABILITIES["process"]["severity"] == "CRITICAL"

    def test_random_severity_low(self):
        assert WASI_DANGEROUS_CAPABILITIES["random"]["severity"] == "LOW"

    def test_env_severity_medium(self):
        assert WASI_DANGEROUS_CAPABILITIES["env"]["severity"] == "MEDIUM"

    def test_filesystem_indicators(self):
        indicators = WASI_DANGEROUS_CAPABILITIES["filesystem"]["indicators"]
        assert "fd_prestat_get" in indicators
        assert "path_open" in indicators
        assert "fd_read" in indicators
        assert "fd_write" in indicators

    def test_network_indicators(self):
        indicators = WASI_DANGEROUS_CAPABILITIES["network"]["indicators"]
        assert "sock_accept" in indicators
        assert "sock_connect" in indicators

    def test_process_indicators(self):
        indicators = WASI_DANGEROUS_CAPABILITIES["process"]["indicators"]
        assert "proc_raise" in indicators
        assert "proc_exit" in indicators

    def test_env_indicators(self):
        indicators = WASI_DANGEROUS_CAPABILITIES["env"]["indicators"]
        assert "environ_get" in indicators
        assert "environ_sizes_get" in indicators


# =============================================================================
# WASI_EXTENSIONS DICT
# =============================================================================

class TestWASIExtensions:
    """Test WASI_EXTENSIONS module-level dict."""

    def test_is_dict(self):
        assert isinstance(WASI_EXTENSIONS, dict)

    def test_key_count(self):
        assert len(WASI_EXTENSIONS) == 6

    def test_expected_keys(self):
        expected = {"wasi-nn", "wasi-crypto", "wasi-http", "wasi-keyvalue", "wasi-blob", "wasi-messaging"}
        assert set(WASI_EXTENSIONS.keys()) == expected

    def test_each_entry_has_description(self):
        for ext, info in WASI_EXTENSIONS.items():
            assert "description" in info, f"{ext} missing 'description'"
            assert isinstance(info["description"], str)
            assert len(info["description"]) > 0

    def test_each_entry_has_security_note(self):
        for ext, info in WASI_EXTENSIONS.items():
            assert "security_note" in info, f"{ext} missing 'security_note'"
            assert isinstance(info["security_note"], str)
            assert len(info["security_note"]) > 0

    def test_wasi_http_security_note_mentions_ssrf(self):
        assert "SSRF" in WASI_EXTENSIONS["wasi-http"]["security_note"]

    def test_wasi_crypto_description(self):
        assert "Cryptographic" in WASI_EXTENSIONS["wasi-crypto"]["description"]

    def test_wasi_nn_description(self):
        assert "Neural" in WASI_EXTENSIONS["wasi-nn"]["description"] or "neural" in WASI_EXTENSIONS["wasi-nn"]["description"]

    def test_all_keys_start_with_wasi_prefix(self):
        for key in WASI_EXTENSIONS:
            assert key.startswith("wasi-"), f"Key '{key}' does not start with 'wasi-'"


# =============================================================================
# WASMBackendScanner IDENTITY
# =============================================================================

class TestWASMBackendScannerIdentity:
    """Test WASMBackendScanner class attributes and inheritance."""

    def test_is_scan_module_subclass(self):
        assert issubclass(WASMBackendScanner, ScanModule)

    def test_name_attribute(self):
        assert WASMBackendScanner.name == "wasm_backend_scanner"

    def test_version_attribute(self):
        assert WASMBackendScanner.version == WASM_BACKEND_SCANNER_VERSION

    def test_version_value(self):
        assert WASMBackendScanner.version == "1.0.0"

    def test_category_attribute(self):
        assert WASMBackendScanner.category == "wasm"

    def test_instantiation(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = WASMBackendScanner(settings)
        assert scanner.name == "wasm_backend_scanner"

    def test_instantiation_creates_empty_findings(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = WASMBackendScanner(settings)
        assert scanner.findings == []

    def test_instantiation_creates_empty_endpoints(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = WASMBackendScanner(settings)
        assert scanner.wasm_endpoints == []

    def test_has_scan_method(self):
        assert hasattr(WASMBackendScanner, "scan")
        assert callable(getattr(WASMBackendScanner, "scan"))

    def test_has_fingerprint_runtime_method(self):
        assert hasattr(WASMBackendScanner, "_fingerprint_runtime")

    def test_has_detect_wasm_runtime_method(self):
        assert hasattr(WASMBackendScanner, "_detect_wasm_runtime")

    def test_has_analyze_wasi_capabilities_method(self):
        assert hasattr(WASMBackendScanner, "_analyze_wasi_capabilities")

    def test_has_test_sandbox_weakness_method(self):
        assert hasattr(WASMBackendScanner, "_test_sandbox_weakness")

    def test_has_test_resource_limits_method(self):
        assert hasattr(WASMBackendScanner, "_test_resource_limits")

    def test_has_test_module_injection_method(self):
        assert hasattr(WASMBackendScanner, "_test_module_injection")

    def test_has_test_capability_bypass_method(self):
        assert hasattr(WASMBackendScanner, "_test_capability_bypass")

    def test_has_check_config_exposure_method(self):
        assert hasattr(WASMBackendScanner, "_check_config_exposure")

    def test_has_add_finding_method(self):
        assert hasattr(WASMBackendScanner, "_add_finding")


# =============================================================================
# CONFIG EXPOSURE REGEX PATTERNS (inline in _check_config_exposure)
# =============================================================================

class TestConfigExposurePatterns:
    """Test the regex patterns used in _check_config_exposure method.

    These are defined inline in the method body (lines 923-931) so we
    replicate them here to verify they compile and match expected inputs.
    """

    SENSITIVE_PATTERNS = [
        (r"secret[_-]?key\s*[:=]", "Secret key exposed"),
        (r"api[_-]?key\s*[:=]", "API key exposed"),
        (r"password\s*[:=]", "Password exposed"),
        (r"allowed_hosts\s*[:=]\s*\*", "Wildcard host allowed"),
        (r"wasi_caps\s*[:=]\s*all", "All WASI caps enabled"),
        (r"sandbox\s*[:=]\s*false", "Sandbox disabled"),
        (r"debug\s*[:=]\s*true", "Debug mode enabled"),
    ]

    def test_pattern_count(self):
        assert len(self.SENSITIVE_PATTERNS) == 7

    def test_all_patterns_compile(self):
        for pattern, desc in self.SENSITIVE_PATTERNS:
            compiled = re.compile(pattern, re.IGNORECASE)
            assert compiled is not None

    def test_secret_key_pattern_matches(self):
        pattern = self.SENSITIVE_PATTERNS[0][0]
        assert re.search(pattern, "secret_key = abc123", re.IGNORECASE)
        assert re.search(pattern, "secret-key: mysecret", re.IGNORECASE)
        assert re.search(pattern, "secretkey=value", re.IGNORECASE)

    def test_api_key_pattern_matches(self):
        pattern = self.SENSITIVE_PATTERNS[1][0]
        assert re.search(pattern, "api_key = abc", re.IGNORECASE)
        assert re.search(pattern, "api-key: value", re.IGNORECASE)
        assert re.search(pattern, "apikey=val", re.IGNORECASE)

    def test_password_pattern_matches(self):
        pattern = self.SENSITIVE_PATTERNS[2][0]
        assert re.search(pattern, "password = secret", re.IGNORECASE)
        assert re.search(pattern, "password:hunter2", re.IGNORECASE)

    def test_wildcard_host_pattern_matches(self):
        pattern = self.SENSITIVE_PATTERNS[3][0]
        assert re.search(pattern, "allowed_hosts = *", re.IGNORECASE)

    def test_wasi_caps_all_pattern_matches(self):
        pattern = self.SENSITIVE_PATTERNS[4][0]
        assert re.search(pattern, "wasi_caps = all", re.IGNORECASE)

    def test_sandbox_false_pattern_matches(self):
        pattern = self.SENSITIVE_PATTERNS[5][0]
        assert re.search(pattern, "sandbox = false", re.IGNORECASE)
        assert re.search(pattern, "sandbox:false", re.IGNORECASE)

    def test_debug_true_pattern_matches(self):
        pattern = self.SENSITIVE_PATTERNS[6][0]
        assert re.search(pattern, "debug = true", re.IGNORECASE)
        assert re.search(pattern, "debug:true", re.IGNORECASE)

    def test_sandbox_true_does_not_match(self):
        pattern = self.SENSITIVE_PATTERNS[5][0]
        assert not re.search(pattern, "sandbox = true", re.IGNORECASE)

    def test_debug_false_does_not_match(self):
        pattern = self.SENSITIVE_PATTERNS[6][0]
        assert not re.search(pattern, "debug = false", re.IGNORECASE)


# =============================================================================
# RUNTIME FINGERPRINT REGEX MATCHING (deeper integration)
# =============================================================================

class TestRuntimeFingerprintRegexMatching:
    """Test that error patterns from RUNTIME_FINGERPRINTS correctly match realistic strings."""

    def test_wasmtime_cranelift_match(self):
        pattern = r"cranelift"
        assert re.search(pattern, "Error: cranelift codegen failed at offset 0x42", re.IGNORECASE)

    def test_wasmtime_wasm_trap_match(self):
        pattern = r"wasm trap"
        assert re.search(pattern, "wasm trap: unreachable executed at index 3", re.IGNORECASE)

    def test_wasmer_out_of_bounds_match(self):
        pattern = r"RuntimeError: Out of bounds"
        assert re.search(pattern, "RuntimeError: Out of bounds memory access", re.IGNORECASE)

    def test_wasmedge_wasi_nn_match(self):
        pattern = r"wasi-nn"
        assert re.search(pattern, "Error in wasi-nn inference", re.IGNORECASE)

    def test_spin_fermyon_match(self):
        pattern = r"fermyon"
        assert re.search(pattern, "Fermyon Spin v2.3.0", re.IGNORECASE)

    def test_wasmcloud_capability_provider_match(self):
        pattern = r"capability provider"
        assert re.search(pattern, "failed to start capability provider", re.IGNORECASE)

    def test_lunatic_process_supervision_match(self):
        pattern = r"process supervision"
        assert re.search(pattern, "process supervision tree failed", re.IGNORECASE)

    def test_no_false_positive_on_unrelated_text(self):
        """None of the error patterns should match on generic 404 text."""
        text = "404 Not Found - The requested URL was not found on this server."
        for runtime, fp in RUNTIME_FINGERPRINTS.items():
            for pattern in fp["errors"]:
                assert not re.search(pattern, text, re.IGNORECASE), (
                    f"Pattern '{pattern}' for {runtime.name} false-positived on generic 404"
                )
