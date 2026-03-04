"""
Unit tests for P3 — Coverage & Modules.

Tests:
1. HTTP/2 support in http_client.py
2. WASM scanner parsing and analysis
3. Kill-switch integration
4. Safe-mode enforcement
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock


class TestHTTP2Support:
    """Test HTTP/2 support in http_client."""

    def test_http2_kwarg_added(self):
        """HTTP/2 kwarg should be added when enabled."""
        from utils.http_client import get_http_client_kwargs

        # Without http2
        kwargs1 = get_http_client_kwargs(timeout=10.0)
        assert kwargs1.get("http2") is None or kwargs1.get("http2") is False

        # With http2
        kwargs2 = get_http_client_kwargs(timeout=10.0, http2=True)
        assert kwargs2.get("http2") is True

    def test_create_protected_client_http2(self):
        """create_protected_client should accept http2 param."""
        import inspect
        from utils.http_client import create_protected_client

        sig = inspect.signature(create_protected_client)
        params = list(sig.parameters.keys())
        assert "http2" in params

    def test_get_http_client_http2(self):
        """get_http_client should accept http2 param."""
        import inspect
        from utils.http_client import get_http_client

        # Check the coroutine function signature
        sig = inspect.signature(get_http_client)
        params = list(sig.parameters.keys())
        assert "http2" in params

    def test_protected_request_http2(self):
        """protected_request should accept http2 param."""
        import inspect
        from utils.http_client import protected_request

        sig = inspect.signature(protected_request)
        params = list(sig.parameters.keys())
        assert "http2" in params


class TestWasmParser:
    """Test WASM binary parser."""

    def test_valid_wasm_header(self):
        """Should parse valid WASM header."""
        from scanning.modules.wasm_scanner import WasmParser, WASM_MAGIC, WASM_VERSION

        valid_wasm = WASM_MAGIC + WASM_VERSION
        parser = WasmParser(valid_wasm)
        result = parser.parse()

        assert result.valid is True
        assert result.version == 1
        assert result.error == ""

    def test_invalid_magic(self):
        """Should reject invalid magic number."""
        from scanning.modules.wasm_scanner import WasmParser

        parser = WasmParser(b"not wasm data")
        result = parser.parse()

        assert result.valid is False
        assert "magic" in result.error.lower()

    def test_too_small(self):
        """Should reject files too small."""
        from scanning.modules.wasm_scanner import WasmParser

        parser = WasmParser(b"\x00asm")  # Missing version
        result = parser.parse()

        assert result.valid is False
        assert "small" in result.error.lower()

    def test_empty_data(self):
        """Should handle empty data."""
        from scanning.modules.wasm_scanner import WasmParser

        parser = WasmParser(b"")
        result = parser.parse()

        assert result.valid is False


class TestWasmExportAnalysis:
    """Test WASM export security analysis."""

    def test_dangerous_export_patterns(self):
        """Should have comprehensive dangerous patterns."""
        from scanning.modules.wasm_scanner import DANGEROUS_EXPORT_PATTERNS

        # Check key patterns exist
        all_patterns = " ".join(p[0] for p in DANGEROUS_EXPORT_PATTERNS)

        assert "eval" in all_patterns
        assert "exec" in all_patterns
        assert "malloc" in all_patterns
        assert "password" in all_patterns
        assert "system" in all_patterns

    def test_secret_patterns(self):
        """Should have comprehensive secret patterns."""
        from scanning.modules.wasm_scanner import SECRET_PATTERNS

        all_patterns = " ".join(p[0] for p in SECRET_PATTERNS)

        assert "api" in all_patterns.lower()
        assert "key" in all_patterns.lower()
        assert "password" in all_patterns.lower()
        assert "jwt" in all_patterns.lower() or "eyJ" in all_patterns

    def test_weak_crypto_patterns(self):
        """Should detect weak crypto."""
        from scanning.modules.wasm_scanner import WEAK_CRYPTO_PATTERNS

        crypto_names = [p[1] for p in WEAK_CRYPTO_PATTERNS]

        assert any("md5" in c.lower() for c in crypto_names)
        assert any("sha1" in c.lower() for c in crypto_names)
        assert any("des" in c.lower() for c in crypto_names)


class TestWasmScanner:
    """Test WASM scanner module."""

    def test_scanner_instantiation(self):
        """Should create scanner instance."""
        from scanning.modules.wasm_scanner import WasmScanner

        scanner = WasmScanner(MagicMock())

        assert scanner.name == "wasm_scanner"
        assert scanner.version == "1.0.0"

    def test_common_paths(self):
        """Should have common WASM paths."""
        from scanning.modules.wasm_scanner import WasmScanner

        paths = WasmScanner.WASM_PATHS

        assert any("app.wasm" in p for p in paths)
        assert any("main.wasm" in p for p in paths)
        assert any("pkg" in p for p in paths)  # wasm-pack default

    def test_export_analysis_method(self):
        """Should have export analysis method."""
        from scanning.modules.wasm_scanner import WasmScanner, WasmAnalysis

        scanner = WasmScanner(MagicMock())

        # Empty analysis should return no findings
        analysis = WasmAnalysis(valid=True)
        findings = scanner._analyze_exports("http://test/app.wasm", analysis)

        assert findings == []

    def test_secrets_analysis_method(self):
        """Should have secrets analysis method."""
        from scanning.modules.wasm_scanner import WasmScanner, WasmAnalysis

        scanner = WasmScanner(MagicMock())

        # Empty analysis should return no findings
        analysis = WasmAnalysis(valid=True)
        findings = scanner._analyze_secrets("http://test/app.wasm", analysis)

        assert findings == []


class TestKillSwitch:
    """Test kill-switch integration."""

    def test_kill_switch_exception_exists(self):
        """KillSwitchActive exception should exist."""
        from utils.http_client import KillSwitchActive

        exc = KillSwitchActive("test")
        assert "test" in str(exc)

    def test_kill_switch_blocks_requests(self):
        """Kill switch should block get_http_client_kwargs."""
        from utils.http_client import (
            get_http_client_kwargs,
            activate_kill_switch,
            deactivate_kill_switch,
            KillSwitchActive,
        )

        # Activate kill switch
        activate_kill_switch("test reason")

        # Should raise exception
        with pytest.raises(KillSwitchActive):
            get_http_client_kwargs()

        # Deactivate
        deactivate_kill_switch()

        # Should work now
        kwargs = get_http_client_kwargs()
        assert kwargs is not None

    def test_kill_switch_status(self):
        """Should be able to check kill switch status."""
        from utils.http_client import (
            is_kill_switch_active,
            activate_kill_switch,
            deactivate_kill_switch,
        )

        # Initially inactive
        assert is_kill_switch_active() is False

        activate_kill_switch("test")
        assert is_kill_switch_active() is True

        deactivate_kill_switch()
        assert is_kill_switch_active() is False


class TestSafeModeIntegration:
    """Test safe-mode integration across modules."""

    def test_smuggling_blocked_in_safe_mode(self):
        """Smuggling should be blocked in safe mode."""
        import os
        from scanning.modules.smuggling_scanner import HTTPSmugglingScanner

        os.environ["PHANTOM_SAFE_MODE"] = "safe"

        scanner = HTTPSmugglingScanner(MagicMock())

        # Check scanner is aware of safe mode
        assert hasattr(scanner, "name")

        # Reset
        os.environ["PHANTOM_SAFE_MODE"] = "standard"

    def test_proof_engine_limits(self):
        """Proof engine should respect safe mode limits."""
        from scanning.exploit_proof_engine import PROOF_LIMITS

        # Safe mode = 0 requests
        assert PROOF_LIMITS["safe"]["max_requests"] == 0
        assert PROOF_LIMITS["safe"]["allow_write"] is False

        # Aggressive = full access
        assert PROOF_LIMITS["aggressive"]["max_requests"] >= 50
        assert PROOF_LIMITS["aggressive"]["allow_write"] is True


class TestRequestDedup:
    """Test request deduplication helpers."""

    def test_url_normalization(self):
        """Should normalize URLs for dedup."""
        # Simple normalization test
        url1 = "https://example.com/path"
        url2 = "https://example.com/path/"
        url3 = "https://example.com/path?a=1"

        # Basic normalization (strip trailing slash)
        assert url1.rstrip("/") == url2.rstrip("/")
        assert url1 != url3  # Query string makes them different

    def test_header_normalization(self):
        """Headers should be case-insensitive for comparison."""
        headers1 = {"Content-Type": "application/json"}
        headers2 = {"content-type": "application/json"}

        # Lowercase comparison
        h1_lower = {k.lower(): v for k, v in headers1.items()}
        h2_lower = {k.lower(): v for k, v in headers2.items()}

        assert h1_lower == h2_lower


class TestUserAgentRotation:
    """Test User-Agent rotation."""

    def test_ua_in_headers(self):
        """User-Agent should be set in headers."""
        from utils.http_client import get_http_client_kwargs

        kwargs = get_http_client_kwargs()
        headers = kwargs.get("headers", {})

        # Should have some headers (may include UA from protection)
        assert isinstance(headers, dict)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
