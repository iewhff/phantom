"""
Tests for scanning/modules/sse_scanner.py

Covers:
- SSEScanner class attributes (name, class hierarchy)
- SSE_ENDPOINTS constant (21 entries, key paths, format validation)
- Core method existence (scan, _discover_sse, _test_sse_cors, _test_sse_auth, _test_sse_injection)
"""

import pytest

from scanning.modules.sse_scanner import SSEScanner
from scanning.vuln_scanner import ScanModule


# =============================================================================
# CLASS IDENTITY
# =============================================================================

class TestSSEScannerIdentity:
    """Test SSEScanner class name and hierarchy."""

    def test_name(self):
        assert SSEScanner.name == "sse_scanner"

    def test_is_scan_module_subclass(self):
        assert issubclass(SSEScanner, ScanModule)

    def test_name_is_string(self):
        assert isinstance(SSEScanner.name, str)


# =============================================================================
# SSE_ENDPOINTS CONSTANT
# =============================================================================

class TestSSEEndpoints:
    """Test SSE_ENDPOINTS class attribute."""

    def test_is_list(self):
        assert isinstance(SSEScanner.SSE_ENDPOINTS, list)

    def test_count(self):
        assert len(SSEScanner.SSE_ENDPOINTS) == 22

    def test_no_empty_strings(self):
        for ep in SSEScanner.SSE_ENDPOINTS:
            assert ep != "", f"SSE_ENDPOINTS contains an empty string"

    def test_all_start_with_slash(self):
        for ep in SSEScanner.SSE_ENDPOINTS:
            assert ep.startswith("/"), f"Endpoint does not start with '/': {ep!r}"

    def test_all_are_strings(self):
        for ep in SSEScanner.SSE_ENDPOINTS:
            assert isinstance(ep, str), f"Endpoint is not a string: {ep!r}"

    def test_no_duplicates(self):
        assert len(SSEScanner.SSE_ENDPOINTS) == len(set(SSEScanner.SSE_ENDPOINTS))

    # Key entries ----------------------------------------------------------

    def test_contains_events(self):
        assert "/events" in SSEScanner.SSE_ENDPOINTS

    def test_contains_sse(self):
        assert "/sse" in SSEScanner.SSE_ENDPOINTS

    def test_contains_stream(self):
        assert "/stream" in SSEScanner.SSE_ENDPOINTS

    def test_contains_realtime(self):
        assert "/realtime" in SSEScanner.SSE_ENDPOINTS

    def test_contains_notifications(self):
        assert "/notifications" in SSEScanner.SSE_ENDPOINTS

    def test_contains_updates(self):
        assert "/updates" in SSEScanner.SSE_ENDPOINTS

    def test_contains_api_events(self):
        assert "/api/events" in SSEScanner.SSE_ENDPOINTS

    def test_contains_api_sse(self):
        assert "/api/sse" in SSEScanner.SSE_ENDPOINTS

    def test_contains_api_stream(self):
        assert "/api/stream" in SSEScanner.SSE_ENDPOINTS

    def test_contains_subscribe(self):
        assert "/subscribe" in SSEScanner.SSE_ENDPOINTS

    def test_contains_api_v1_events(self):
        assert "/api/v1/events" in SSEScanner.SSE_ENDPOINTS

    def test_contains_api_v1_sse(self):
        assert "/api/v1/sse" in SSEScanner.SSE_ENDPOINTS

    def test_contains_api_v1_stream(self):
        assert "/api/v1/stream" in SSEScanner.SSE_ENDPOINTS

    def test_contains_api_v2_events(self):
        assert "/api/v2/events" in SSEScanner.SSE_ENDPOINTS

    def test_contains_ws_events(self):
        assert "/ws/events" in SSEScanner.SSE_ENDPOINTS

    def test_contains_push(self):
        assert "/push" in SSEScanner.SSE_ENDPOINTS

    def test_contains_feed(self):
        assert "/feed" in SSEScanner.SSE_ENDPOINTS

    def test_contains_live(self):
        assert "/live" in SSEScanner.SSE_ENDPOINTS

    def test_contains_changes(self):
        assert "/changes" in SSEScanner.SSE_ENDPOINTS

    def test_contains_webhook_stream(self):
        assert "/webhook/stream" in SSEScanner.SSE_ENDPOINTS

    def test_contains_graphql_subscriptions(self):
        assert "/graphql/subscriptions" in SSEScanner.SSE_ENDPOINTS

    def test_contains_well_known_mercure(self):
        assert "/.well-known/mercure" in SSEScanner.SSE_ENDPOINTS


# =============================================================================
# METHOD EXISTENCE
# =============================================================================

class TestSSEScannerMethods:
    """Test that SSEScanner has the expected methods."""

    def test_has_scan_method(self):
        assert hasattr(SSEScanner, "scan")
        assert callable(getattr(SSEScanner, "scan"))

    def test_has_discover_sse_method(self):
        assert hasattr(SSEScanner, "_discover_sse")
        assert callable(getattr(SSEScanner, "_discover_sse"))

    def test_has_test_sse_cors_method(self):
        assert hasattr(SSEScanner, "_test_sse_cors")
        assert callable(getattr(SSEScanner, "_test_sse_cors"))

    def test_has_test_sse_auth_method(self):
        assert hasattr(SSEScanner, "_test_sse_auth")
        assert callable(getattr(SSEScanner, "_test_sse_auth"))

    def test_has_test_sse_injection_method(self):
        assert hasattr(SSEScanner, "_test_sse_injection")
        assert callable(getattr(SSEScanner, "_test_sse_injection"))

    def test_scan_is_async(self):
        import asyncio
        assert asyncio.iscoroutinefunction(SSEScanner.scan)

    def test_discover_sse_is_async(self):
        import asyncio
        assert asyncio.iscoroutinefunction(SSEScanner._discover_sse)

    def test_test_sse_cors_is_async(self):
        import asyncio
        assert asyncio.iscoroutinefunction(SSEScanner._test_sse_cors)

    def test_test_sse_auth_is_async(self):
        import asyncio
        assert asyncio.iscoroutinefunction(SSEScanner._test_sse_auth)

    def test_test_sse_injection_is_async(self):
        import asyncio
        assert asyncio.iscoroutinefunction(SSEScanner._test_sse_injection)
