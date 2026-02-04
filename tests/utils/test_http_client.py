"""
Tests for utils/http_client.py

Tests kill switch functionality and SSL verification defaults.
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.http_client import (
    activate_kill_switch,
    deactivate_kill_switch,
    is_kill_switch_active,
    set_ssl_verify_default,
    get_ssl_verify_default,
    get_http_client_kwargs,
    KillSwitchActive,
)


class TestKillSwitch:
    """Tests for kill switch functionality."""

    def setup_method(self):
        """Reset kill switch before each test."""
        deactivate_kill_switch()

    def teardown_method(self):
        """Reset kill switch after each test."""
        deactivate_kill_switch()

    def test_kill_switch_initially_inactive(self):
        """Test that kill switch is inactive by default."""
        assert is_kill_switch_active() is False

    def test_activate_kill_switch(self):
        """Test activating the kill switch."""
        activate_kill_switch("Test activation")
        assert is_kill_switch_active() is True

    def test_deactivate_kill_switch(self):
        """Test deactivating the kill switch."""
        activate_kill_switch("Test")
        deactivate_kill_switch()
        assert is_kill_switch_active() is False

    def test_kill_switch_blocks_http_client(self):
        """Test that active kill switch blocks HTTP client creation."""
        activate_kill_switch("Test blocking")

        with pytest.raises(KillSwitchActive) as exc_info:
            get_http_client_kwargs()

        assert "kill switch is active" in str(exc_info.value).lower()

    def test_kill_switch_message_in_exception(self):
        """Test that kill switch exception includes helpful message."""
        activate_kill_switch("Security breach detected")

        with pytest.raises(KillSwitchActive) as exc_info:
            get_http_client_kwargs()

        assert "deactivate_kill_switch()" in str(exc_info.value)


class TestSSLVerification:
    """Tests for SSL verification defaults."""

    def setup_method(self):
        """Reset SSL default before each test."""
        set_ssl_verify_default(True)
        deactivate_kill_switch()

    def teardown_method(self):
        """Reset to secure default after each test."""
        set_ssl_verify_default(True)
        deactivate_kill_switch()

    def test_ssl_verify_default_is_true(self):
        """Test that SSL verification is enabled by default (secure default)."""
        # Reset to initial state
        set_ssl_verify_default(True)
        assert get_ssl_verify_default() is True

    def test_set_ssl_verify_default_false(self):
        """Test setting SSL verification to false."""
        set_ssl_verify_default(False)
        assert get_ssl_verify_default() is False

    def test_http_client_kwargs_uses_ssl_default(self):
        """Test that get_http_client_kwargs uses the SSL default."""
        set_ssl_verify_default(True)

        with patch("utils.http_client.get_network_protection") as mock_protection:
            mock_protection.return_value.proxy_config.enabled = False
            mock_protection.return_value.get_httpx_client_kwargs.return_value = {}

            kwargs = get_http_client_kwargs()
            assert kwargs["verify"] is True

    def test_http_client_kwargs_explicit_ssl_overrides_default(self):
        """Test that explicit SSL parameter overrides default."""
        set_ssl_verify_default(True)

        with patch("utils.http_client.get_network_protection") as mock_protection:
            mock_protection.return_value.proxy_config.enabled = False
            mock_protection.return_value.get_httpx_client_kwargs.return_value = {}

            kwargs = get_http_client_kwargs(verify_ssl=False)
            assert kwargs["verify"] is False

    def test_http_client_kwargs_none_ssl_uses_default(self):
        """Test that None SSL parameter uses the default."""
        set_ssl_verify_default(False)

        with patch("utils.http_client.get_network_protection") as mock_protection:
            mock_protection.return_value.proxy_config.enabled = False
            mock_protection.return_value.get_httpx_client_kwargs.return_value = {}

            kwargs = get_http_client_kwargs(verify_ssl=None)
            assert kwargs["verify"] is False


class TestHTTPClientKwargs:
    """Tests for get_http_client_kwargs function."""

    def setup_method(self):
        """Reset state before each test."""
        deactivate_kill_switch()
        set_ssl_verify_default(True)

    def teardown_method(self):
        """Reset state after each test."""
        deactivate_kill_switch()
        set_ssl_verify_default(True)

    def test_includes_timeout(self):
        """Test that timeout is included in kwargs."""
        with patch("utils.http_client.get_network_protection") as mock:
            mock.return_value.proxy_config.enabled = False
            mock.return_value.get_httpx_client_kwargs.return_value = {}

            kwargs = get_http_client_kwargs(timeout=60.0)
            assert kwargs["timeout"] == 60.0

    def test_includes_follow_redirects(self):
        """Test that follow_redirects is included in kwargs."""
        with patch("utils.http_client.get_network_protection") as mock:
            mock.return_value.proxy_config.enabled = False
            mock.return_value.get_httpx_client_kwargs.return_value = {}

            kwargs = get_http_client_kwargs(follow_redirects=False)
            assert kwargs["follow_redirects"] is False

    def test_merges_custom_headers(self):
        """Test that custom headers are merged."""
        with patch("utils.http_client.get_network_protection") as mock:
            mock.return_value.proxy_config.enabled = False
            mock.return_value.get_httpx_client_kwargs.return_value = {
                "headers": {"User-Agent": "Test"}
            }

            kwargs = get_http_client_kwargs(
                custom_headers={"X-Custom": "value"}
            )

            assert kwargs["headers"]["User-Agent"] == "Test"
            assert kwargs["headers"]["X-Custom"] == "value"


class TestKillSwitchIntegration:
    """Integration tests for kill switch with protection verification."""

    def setup_method(self):
        """Reset state before each test."""
        deactivate_kill_switch()

    def teardown_method(self):
        """Reset state after each test."""
        deactivate_kill_switch()

    @pytest.mark.asyncio
    async def test_verify_protection_activates_kill_switch_on_failure(self):
        """Test that failed protection verification activates kill switch."""
        from utils.http_client import verify_protection

        with patch("utils.http_client.get_network_protection") as mock:
            # Simulate proxy enabled but verification failure
            mock.return_value.proxy_config.enabled = True
            mock.return_value.verify_proxy_working = AsyncMock(return_value=False)

            result = await verify_protection(auto_kill_switch=True)

            assert result is False
            assert is_kill_switch_active() is True

    @pytest.mark.asyncio
    async def test_verify_protection_no_kill_switch_when_disabled(self):
        """Test that kill switch can be disabled during verification."""
        from utils.http_client import verify_protection

        with patch("utils.http_client.get_network_protection") as mock:
            mock.return_value.proxy_config.enabled = True
            mock.return_value.verify_proxy_working = AsyncMock(return_value=False)

            result = await verify_protection(auto_kill_switch=False)

            assert result is False
            assert is_kill_switch_active() is False

    @pytest.mark.asyncio
    async def test_verify_protection_success_no_kill_switch(self):
        """Test that successful verification doesn't activate kill switch."""
        from utils.http_client import verify_protection

        with patch("utils.http_client.get_network_protection") as mock:
            mock.return_value.proxy_config.enabled = True
            mock.return_value.verify_proxy_working = AsyncMock(return_value=True)

            result = await verify_protection(auto_kill_switch=True)

            assert result is True
            assert is_kill_switch_active() is False
