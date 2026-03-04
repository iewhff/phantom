"""
Tests for scanning/context_manager/ module.

Tests ContextCoordinator, ContextState, and related functionality.
"""

import pytest
import time
from unittest.mock import Mock, PropertyMock
from dataclasses import dataclass, field
from typing import Any, Optional

from scanning.context_manager import (
    ContextCoordinator,
    ContextState,
    create_coordinator,
    build_minimal_asset_data,
    AuthContextProtocol,
    IntelligentContextProtocol,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Mock Contexts
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class MockAuthContext:
    """Mock authentication context for testing."""

    _has_auth: bool = True
    _token: str = "mock-jwt-token"
    _cookies: dict = field(default_factory=dict)
    _method: str = "form_login"
    _auth_headers: dict = field(default_factory=dict)

    @property
    def has_auth(self) -> bool:
        return self._has_auth

    @property
    def token(self) -> str:
        return self._token

    @property
    def cookies(self) -> dict:
        return self._cookies or {}

    @property
    def method(self) -> str:
        return self._method

    @property
    def auth_headers(self) -> dict:
        if self._auth_headers:
            return self._auth_headers
        if self._token:
            return {"Authorization": f"Bearer {self._token}"}
        return {}


@dataclass
class MockParameter:
    """Mock parameter with name attribute."""
    name: str


@dataclass
class MockParameterAnalysis:
    """Mock parameter analysis."""
    parameters: list


@dataclass
class MockIntelligentContext:
    """Mock intelligent scanning context for testing."""

    _endpoints_discovered: list = field(default_factory=list)
    _parameter_analysis: dict = field(default_factory=dict)

    @property
    def endpoints_discovered(self) -> list:
        return self._endpoints_discovered

    @property
    def parameter_analysis(self) -> dict:
        return self._parameter_analysis


# ═══════════════════════════════════════════════════════════════════════════════
# ContextState Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestContextState:
    """Tests for ContextState dataclass."""

    def test_default_state(self):
        """Test default state values."""
        state = ContextState()
        assert state.scan_id == ""
        assert state.target == ""
        assert state.has_auth_context is False
        assert state.has_intelligent_context is False
        assert state.auth_method == ""
        assert state.auth_acquired_at is None
        assert state.endpoints_count == 0
        assert state.parameters_count == 0
        assert state.initialized_at is None
        assert state.finalized_at is None

    def test_state_with_values(self):
        """Test state with initial values."""
        state = ContextState(
            scan_id="scan-123",
            target="https://example.com",
            has_auth_context=True,
            auth_method="jwt",
        )
        assert state.scan_id == "scan-123"
        assert state.target == "https://example.com"
        assert state.has_auth_context is True
        assert state.auth_method == "jwt"

    def test_is_initialized_property(self):
        """Test is_initialized property."""
        state = ContextState()
        assert state.is_initialized is False

        state.initialized_at = time.time()
        assert state.is_initialized is True

    def test_is_finalized_property(self):
        """Test is_finalized property."""
        state = ContextState()
        assert state.is_finalized is False

        state.finalized_at = time.time()
        assert state.is_finalized is True

    def test_auth_age_seconds_no_auth(self):
        """Test auth_age_seconds when no auth acquired."""
        state = ContextState()
        assert state.auth_age_seconds == 0.0

    def test_auth_age_seconds_with_auth(self):
        """Test auth_age_seconds with auth acquired."""
        state = ContextState()
        state.auth_acquired_at = time.time() - 30  # 30 seconds ago
        assert 29 <= state.auth_age_seconds <= 31

    def test_to_dict(self):
        """Test to_dict conversion."""
        state = ContextState(
            scan_id="scan-123",
            target="https://example.com",
            has_auth_context=True,
            has_intelligent_context=True,
            auth_method="jwt",
            endpoints_count=10,
            parameters_count=25,
        )
        state.initialized_at = time.time()

        result = state.to_dict()

        assert result["scan_id"] == "scan-123"
        assert result["target"] == "https://example.com"
        assert result["has_auth_context"] is True
        assert result["has_intelligent_context"] is True
        assert result["auth_method"] == "jwt"
        assert result["endpoints_count"] == 10
        assert result["parameters_count"] == 25
        assert result["is_initialized"] is True
        assert result["is_finalized"] is False

    def test_metadata_field(self):
        """Test metadata field is mutable dict."""
        state = ContextState()
        state.metadata["key1"] = "value1"
        assert state.metadata["key1"] == "value1"


# ═══════════════════════════════════════════════════════════════════════════════
# ContextCoordinator Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestContextCoordinatorInit:
    """Tests for ContextCoordinator initialization."""

    def test_default_init(self):
        """Test default initialization."""
        coordinator = ContextCoordinator()
        assert coordinator.scan_id == ""
        assert coordinator.target == ""
        assert coordinator.has_auth is False
        assert coordinator.has_intelligent_context is False

    def test_init_with_params(self):
        """Test initialization with parameters."""
        coordinator = ContextCoordinator(
            scan_id="scan-abc",
            target="https://example.com",
        )
        assert coordinator.scan_id == "scan-abc"
        assert coordinator.target == "https://example.com"

    def test_state_property(self):
        """Test state property returns ContextState."""
        coordinator = ContextCoordinator(scan_id="test", target="http://x.com")
        state = coordinator.state

        assert isinstance(state, ContextState)
        assert state.scan_id == "test"
        assert state.target == "http://x.com"


class TestContextCoordinatorAuthContext:
    """Tests for auth context registration."""

    def test_register_auth_context_with_auth(self):
        """Test registering auth context with authentication."""
        coordinator = ContextCoordinator()
        auth = MockAuthContext(_has_auth=True, _method="jwt")

        coordinator.register_auth_context(auth)

        assert coordinator.has_auth is True
        assert coordinator.state.has_auth_context is True
        assert coordinator.state.auth_method == "jwt"
        assert coordinator.state.auth_acquired_at is not None

    def test_register_auth_context_without_auth(self):
        """Test registering auth context without authentication."""
        coordinator = ContextCoordinator()
        auth = MockAuthContext(_has_auth=False)

        coordinator.register_auth_context(auth)

        assert coordinator.has_auth is False
        assert coordinator.state.has_auth_context is False
        assert coordinator.state.auth_method == ""
        assert coordinator.state.auth_acquired_at is None

    def test_get_auth_context(self):
        """Test getting auth context."""
        coordinator = ContextCoordinator()
        assert coordinator.get_auth_context() is None

        auth = MockAuthContext()
        coordinator.register_auth_context(auth)
        assert coordinator.get_auth_context() is auth

    def test_get_auth_headers_no_auth(self):
        """Test get_auth_headers with no auth context."""
        coordinator = ContextCoordinator()
        assert coordinator.get_auth_headers() == {}

    def test_get_auth_headers_with_auth(self):
        """Test get_auth_headers with auth context."""
        coordinator = ContextCoordinator()
        auth = MockAuthContext(_token="test-token")
        coordinator.register_auth_context(auth)

        headers = coordinator.get_auth_headers()
        assert headers == {"Authorization": "Bearer test-token"}


class TestContextCoordinatorIntelligentContext:
    """Tests for intelligent context registration."""

    def test_register_intelligent_context(self):
        """Test registering intelligent context."""
        coordinator = ContextCoordinator()
        intel = MockIntelligentContext(
            _endpoints_discovered=["http://x.com/api", "http://x.com/users"],
            _parameter_analysis={"http://x.com/api": {"params": ["id", "name"]}},
        )

        coordinator.register_intelligent_context(intel)

        assert coordinator.has_intelligent_context is True
        assert coordinator.state.has_intelligent_context is True
        assert coordinator.state.endpoints_count == 2
        assert coordinator.state.parameters_count == 1

    def test_get_intelligent_context(self):
        """Test getting intelligent context."""
        coordinator = ContextCoordinator()
        assert coordinator.get_intelligent_context() is None

        intel = MockIntelligentContext()
        coordinator.register_intelligent_context(intel)
        assert coordinator.get_intelligent_context() is intel

    def test_get_discovered_endpoints_no_context(self):
        """Test get_discovered_endpoints with no intelligent context."""
        coordinator = ContextCoordinator(target="http://default.com")
        endpoints = coordinator.get_discovered_endpoints()
        assert endpoints == ["http://default.com"]

    def test_get_discovered_endpoints_with_context(self):
        """Test get_discovered_endpoints with intelligent context."""
        coordinator = ContextCoordinator()
        intel = MockIntelligentContext(
            _endpoints_discovered=["http://x.com/a", "http://x.com/b"]
        )
        coordinator.register_intelligent_context(intel)

        endpoints = coordinator.get_discovered_endpoints()
        assert endpoints == ["http://x.com/a", "http://x.com/b"]


class TestContextCoordinatorOtherRegistrations:
    """Tests for other registration methods."""

    def test_register_tech_stack(self):
        """Test registering technology stack."""
        coordinator = ContextCoordinator()
        tech = {"framework": "Django", "database": "PostgreSQL"}

        coordinator.register_tech_stack(tech)

        technologies = coordinator.get_technologies()
        assert "framework" in technologies
        assert "database" in technologies

    def test_register_waf_detection(self):
        """Test registering WAF detection."""
        coordinator = ContextCoordinator()
        waf = {"detected": True, "type": "Cloudflare"}

        coordinator.register_waf_detection(waf)

        # Verify through build_asset_data
        data = coordinator.build_asset_data()
        assert data["waf_detection"] == waf

    def test_register_fingerprint(self):
        """Test registering fingerprint."""
        coordinator = ContextCoordinator()
        fingerprint = {"server": "nginx", "version": "1.20"}

        coordinator.register_fingerprint(fingerprint)

        data = coordinator.build_asset_data()
        assert data["fingerprint_result"] == fingerprint

    def test_register_forms(self):
        """Test registering discovered forms."""
        coordinator = ContextCoordinator()
        forms = [
            {"action": "/login", "method": "POST"},
            {"action": "/search", "method": "GET"},
        ]

        coordinator.register_forms(forms)

        assert coordinator.state.forms_count == 2
        data = coordinator.build_asset_data()
        assert data["forms"] == forms

    def test_register_semantic_analyzer(self):
        """Test registering semantic analyzer."""
        coordinator = ContextCoordinator()
        analyzer = Mock()

        coordinator.register_semantic_analyzer(analyzer)

        data = coordinator.build_asset_data()
        assert data["semantic_analyzer"] is analyzer

    def test_set_training_app(self):
        """Test setting training app name."""
        coordinator = ContextCoordinator()

        coordinator.set_training_app("DVWA")

        data = coordinator.build_asset_data()
        assert data["training_app"] == "DVWA"


class TestContextCoordinatorBuildAssetData:
    """Tests for build_asset_data method."""

    def test_build_minimal_asset_data(self):
        """Test building asset data with minimal info."""
        coordinator = ContextCoordinator(
            scan_id="scan-1",
            target="http://example.com",
        )

        data = coordinator.build_asset_data()

        assert data["scan_id"] == "scan-1"
        assert data["target"] == "http://example.com"
        assert data["endpoints"] == ["http://example.com"]
        assert data["parameters"] == []
        assert data["forms"] == []
        assert data["technologies"] == []
        assert data["has_auth"] is False

    def test_build_full_asset_data(self):
        """Test building asset data with all contexts registered."""
        coordinator = ContextCoordinator(
            scan_id="scan-full",
            target="http://example.com",
        )

        # Register auth
        auth = MockAuthContext(_has_auth=True, _method="jwt")
        coordinator.register_auth_context(auth)

        # Register intelligent context with parameters
        intel = MockIntelligentContext(
            _endpoints_discovered=["http://example.com/api"],
            _parameter_analysis={
                "http://example.com/api": MockParameterAnalysis(
                    parameters=[
                        MockParameter(name="id"),
                        MockParameter(name="query"),
                    ]
                )
            },
        )
        coordinator.register_intelligent_context(intel)

        # Register tech stack
        coordinator.register_tech_stack({"framework": "Django"})

        # Register forms
        coordinator.register_forms([{"action": "/login"}])

        # Register training app
        coordinator.set_training_app("WebGoat")

        data = coordinator.build_asset_data()

        assert data["scan_id"] == "scan-full"
        assert data["target"] == "http://example.com"
        assert data["endpoints"] == ["http://example.com/api"]
        assert set(data["parameters"]) == {"id", "query"}
        assert len(data["forms"]) == 1
        assert data["technologies"] == ["framework"]
        assert data["has_auth"] is True
        assert data["auth_context"] is auth
        assert data["training_app"] == "WebGoat"

    def test_build_asset_data_with_dict_parameters(self):
        """Test parameter extraction from dict-style analysis."""
        coordinator = ContextCoordinator()

        intel = MockIntelligentContext(
            _endpoints_discovered=["http://x.com"],
            _parameter_analysis={
                "http://x.com": {
                    "parameters": [
                        {"name": "user_id"},
                        {"name": "action"},
                        "raw_param",  # String parameter
                    ]
                }
            },
        )
        coordinator.register_intelligent_context(intel)

        data = coordinator.build_asset_data()

        # Should extract all parameter names
        assert "user_id" in data["parameters"]
        assert "action" in data["parameters"]
        assert "raw_param" in data["parameters"]

    def test_build_asset_data_deduplicates_parameters(self):
        """Test that parameters are deduplicated."""
        coordinator = ContextCoordinator()

        intel = MockIntelligentContext(
            _endpoints_discovered=["http://x.com"],
            _parameter_analysis={
                "http://x.com/a": {"parameters": ["id", "name"]},
                "http://x.com/b": {"parameters": ["id", "other"]},  # "id" is duplicate
            },
        )
        coordinator.register_intelligent_context(intel)

        data = coordinator.build_asset_data()

        # Should have unique parameters only
        assert len(data["parameters"]) == 3
        assert set(data["parameters"]) == {"id", "name", "other"}


class TestContextCoordinatorLifecycle:
    """Tests for lifecycle methods."""

    def test_initialize(self):
        """Test initialize method."""
        coordinator = ContextCoordinator()
        assert coordinator.state.is_initialized is False

        coordinator.initialize()

        assert coordinator.state.is_initialized is True
        assert coordinator.state.initialized_at is not None

    def test_finalize(self):
        """Test finalize method."""
        coordinator = ContextCoordinator()
        coordinator.initialize()
        assert coordinator.state.is_finalized is False

        result = coordinator.finalize()

        assert coordinator.state.is_finalized is True
        assert coordinator.state.finalized_at is not None
        assert isinstance(result, ContextState)

    def test_record_auth_refresh(self):
        """Test recording auth refresh."""
        coordinator = ContextCoordinator()
        assert coordinator.state.auth_refresh_count == 0

        coordinator.record_auth_refresh()

        assert coordinator.state.auth_refresh_count == 1
        assert coordinator.state.auth_refreshed_at is not None

        # Record another refresh
        coordinator.record_auth_refresh()
        assert coordinator.state.auth_refresh_count == 2

    def test_get_summary(self):
        """Test get_summary method."""
        coordinator = ContextCoordinator(
            scan_id="sum-test",
            target="http://example.com",
        )
        coordinator.initialize()

        auth = MockAuthContext(_has_auth=True)
        coordinator.register_auth_context(auth)

        intel = MockIntelligentContext(
            _endpoints_discovered=["http://x.com/a", "http://x.com/b"]
        )
        coordinator.register_intelligent_context(intel)

        summary = coordinator.get_summary()

        assert summary["scan_id"] == "sum-test"
        assert summary["target"] == "http://example.com"
        assert summary["has_auth"] is True
        assert summary["has_intelligent_context"] is True
        assert summary["endpoints_count"] == 2
        assert "state" in summary


# ═══════════════════════════════════════════════════════════════════════════════
# Factory Function Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCreateCoordinator:
    """Tests for create_coordinator factory function."""

    def test_create_default(self):
        """Test creating coordinator with defaults."""
        coordinator = create_coordinator()

        assert isinstance(coordinator, ContextCoordinator)
        assert coordinator.state.is_initialized is True

    def test_create_with_params(self):
        """Test creating coordinator with parameters."""
        coordinator = create_coordinator(
            scan_id="factory-test",
            target="http://factory.com",
        )

        assert coordinator.scan_id == "factory-test"
        assert coordinator.target == "http://factory.com"
        assert coordinator.state.is_initialized is True


class TestBuildMinimalAssetData:
    """Tests for build_minimal_asset_data function."""

    def test_minimal_data_target_only(self):
        """Test building minimal data with target only."""
        data = build_minimal_asset_data(target="http://example.com")

        assert data["target"] == "http://example.com"
        assert data["endpoints"] == ["http://example.com"]
        assert data["parameters"] == []
        assert data["forms"] == []
        assert data["technologies"] == []
        assert data["has_auth"] is False
        assert data["auth_context"] is None
        assert data["scan_id"] == ""

    def test_minimal_data_with_endpoints(self):
        """Test building minimal data with custom endpoints."""
        endpoints = ["http://x.com/a", "http://x.com/b"]
        data = build_minimal_asset_data(
            target="http://x.com",
            endpoints=endpoints,
        )

        assert data["endpoints"] == endpoints

    def test_minimal_data_with_auth_headers(self):
        """Test building minimal data with auth headers."""
        data = build_minimal_asset_data(
            target="http://x.com",
            auth_headers={"Authorization": "Bearer xyz"},
        )

        assert data["has_auth"] is True

    def test_minimal_data_empty_auth_headers(self):
        """Test that empty auth headers means no auth."""
        data = build_minimal_asset_data(
            target="http://x.com",
            auth_headers={},
        )

        assert data["has_auth"] is False


# ═══════════════════════════════════════════════════════════════════════════════
# Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestContextCoordinatorIntegration:
    """Integration tests for ContextCoordinator."""

    def test_full_lifecycle(self):
        """Test complete coordinator lifecycle."""
        # Create and initialize
        coordinator = create_coordinator(
            scan_id="integration-test",
            target="http://test.com",
        )

        # Register contexts
        auth = MockAuthContext(_has_auth=True, _method="form_login")
        coordinator.register_auth_context(auth)

        intel = MockIntelligentContext(
            _endpoints_discovered=["http://test.com/login", "http://test.com/api"],
            _parameter_analysis={
                "http://test.com/api": MockParameterAnalysis(
                    parameters=[MockParameter(name="user"), MockParameter(name="pass")]
                )
            },
        )
        coordinator.register_intelligent_context(intel)

        coordinator.register_tech_stack({"server": "Apache", "framework": "PHP"})
        coordinator.register_forms([{"action": "/login", "method": "POST"}])
        coordinator.set_training_app("DVWA")

        # Simulate auth refresh during scan
        coordinator.record_auth_refresh()

        # Build asset data for modules
        asset_data = coordinator.build_asset_data()

        # Verify asset data
        assert asset_data["scan_id"] == "integration-test"
        assert asset_data["target"] == "http://test.com"
        assert len(asset_data["endpoints"]) == 2
        assert "user" in asset_data["parameters"] or "pass" in asset_data["parameters"]
        assert asset_data["has_auth"] is True
        assert asset_data["training_app"] == "DVWA"

        # Finalize
        final_state = coordinator.finalize()

        # Verify final state
        assert final_state.is_initialized is True
        assert final_state.is_finalized is True
        assert final_state.has_auth_context is True
        assert final_state.has_intelligent_context is True
        assert final_state.auth_method == "form_login"
        assert final_state.auth_refresh_count == 1
        assert final_state.endpoints_count == 2

    def test_coordinator_without_intelligent_context(self):
        """Test coordinator works without intelligent context."""
        coordinator = ContextCoordinator(target="http://simple.com")
        coordinator.initialize()

        # Only register auth
        auth = MockAuthContext(_has_auth=True)
        coordinator.register_auth_context(auth)

        # Build asset data
        asset_data = coordinator.build_asset_data()

        # Should use target as fallback endpoint
        assert asset_data["endpoints"] == ["http://simple.com"]
        assert asset_data["parameters"] == []
        assert asset_data["has_auth"] is True

    def test_coordinator_without_auth(self):
        """Test coordinator works without auth context."""
        coordinator = ContextCoordinator(target="http://noauth.com")
        coordinator.initialize()

        # Only register intelligent context
        intel = MockIntelligentContext(
            _endpoints_discovered=["http://noauth.com/public"]
        )
        coordinator.register_intelligent_context(intel)

        # Build asset data
        asset_data = coordinator.build_asset_data()

        assert asset_data["endpoints"] == ["http://noauth.com/public"]
        assert asset_data["has_auth"] is False
        assert asset_data["auth_context"] is None


# ═══════════════════════════════════════════════════════════════════════════════
# Edge Cases
# ═══════════════════════════════════════════════════════════════════════════════


class TestContextCoordinatorEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_target(self):
        """Test coordinator with empty target."""
        coordinator = ContextCoordinator()
        endpoints = coordinator.get_discovered_endpoints()
        assert endpoints == []

    def test_none_values_in_analysis(self):
        """Test handling None values in parameter analysis."""
        coordinator = ContextCoordinator()

        intel = MockIntelligentContext(
            _endpoints_discovered=["http://x.com"],
            _parameter_analysis={
                "http://x.com": None  # None instead of dict
            },
        )
        coordinator.register_intelligent_context(intel)

        # Should not crash
        data = coordinator.build_asset_data()
        assert data["parameters"] == []

    def test_get_technologies_empty(self):
        """Test get_technologies with no tech stack."""
        coordinator = ContextCoordinator()
        assert coordinator.get_technologies() == []

    def test_multiple_auth_registrations(self):
        """Test that re-registering auth updates state."""
        coordinator = ContextCoordinator()

        # First auth
        auth1 = MockAuthContext(_has_auth=True, _method="jwt")
        coordinator.register_auth_context(auth1)
        assert coordinator.state.auth_method == "jwt"

        # Re-register with different auth
        auth2 = MockAuthContext(_has_auth=True, _method="basic")
        coordinator.register_auth_context(auth2)
        assert coordinator.state.auth_method == "basic"

        # The current auth context should be the latest
        assert coordinator.get_auth_context() is auth2
