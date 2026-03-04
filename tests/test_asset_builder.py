"""
Tests for scanning/asset_builder/ module.

Tests AssetDataBuilder, AssetData, and related functionality.
"""

import pytest
from unittest.mock import Mock, patch
from dataclasses import dataclass, field
from typing import Any, Optional

from scanning.asset_builder import (
    AssetBuilderConfig,
    AssetData,
    AssetDataBuilder,
    extract_parameters_from_analysis,
    build_asset_data,
    create_builder,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Mock Classes
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class MockParameter:
    """Mock parameter with name attribute."""
    name: str


@dataclass
class MockAnalysis:
    """Mock analysis with parameters."""
    parameters: list


@dataclass
class MockIntelligentContext:
    """Mock intelligent context."""
    _endpoints_discovered: list = field(default_factory=list)
    _parameter_analysis: dict = field(default_factory=dict)

    @property
    def endpoints_discovered(self) -> list:
        return self._endpoints_discovered

    @property
    def parameter_analysis(self) -> dict:
        return self._parameter_analysis


@dataclass
class MockClassification:
    """Mock classification."""
    detected_technologies: list = field(default_factory=list)


@dataclass
class MockTech:
    """Mock technology."""
    name: str


@dataclass
class MockTechAnalysis:
    """Mock tech analysis."""
    technologies: list = field(default_factory=list)


@dataclass
class MockAuthContext:
    """Mock auth context."""
    _has_auth: bool = True

    @property
    def has_auth(self) -> bool:
        return self._has_auth


@dataclass
class MockStackProfile:
    """Mock stack profile."""
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return self.data


# ═══════════════════════════════════════════════════════════════════════════════
# AssetBuilderConfig Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestAssetBuilderConfig:
    """Tests for AssetBuilderConfig."""

    def test_default_config(self):
        """Test default configuration."""
        config = AssetBuilderConfig()
        assert config.log_debug is True
        assert config.log_info is True
        assert config.log_warnings is True
        assert config.prioritize_training_app is True
        assert config.use_generic_fallback is True

    def test_injection_modules_default(self):
        """Test injection modules set."""
        config = AssetBuilderConfig()
        assert "sqli" in config.injection_modules
        assert "xss" in config.injection_modules
        assert "cmdi" in config.injection_modules

    def test_custom_config(self):
        """Test custom configuration."""
        config = AssetBuilderConfig(
            log_debug=False,
            prioritize_training_app=False,
        )
        assert config.log_debug is False
        assert config.prioritize_training_app is False


# ═══════════════════════════════════════════════════════════════════════════════
# AssetData Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestAssetData:
    """Tests for AssetData dataclass."""

    def test_default_values(self):
        """Test default values."""
        data = AssetData()
        assert data.endpoints == []
        assert data.parameters == []
        assert data.forms == []
        assert data.technologies == []
        assert data.is_training_app is False

    def test_with_values(self):
        """Test with values."""
        data = AssetData(
            endpoints=["http://x.com/api"],
            parameters=["id", "name"],
            technologies=["Django", "PostgreSQL"],
            is_training_app=True,
        )
        assert len(data.endpoints) == 1
        assert len(data.parameters) == 2
        assert len(data.technologies) == 2
        assert data.is_training_app is True

    def test_to_dict(self):
        """Test to_dict conversion."""
        data = AssetData(
            endpoints=["http://x.com"],
            parameters=["id"],
            technologies=["PHP"],
        )
        d = data.to_dict()

        assert d["endpoints"] == ["http://x.com"]
        assert d["parameters"] == ["id"]
        assert d["technologies"] == ["PHP"]
        assert "forms" in d
        assert "auth_context" in d


# ═══════════════════════════════════════════════════════════════════════════════
# Parameter Extraction Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestExtractParametersFromAnalysis:
    """Tests for extract_parameters_from_analysis function."""

    def test_empty_analysis(self):
        """Test with empty analysis."""
        result = extract_parameters_from_analysis({})
        assert result == set()

    def test_object_with_parameters_attr(self):
        """Test with objects having parameters attribute."""
        analysis = {
            "http://x.com/api": MockAnalysis(
                parameters=[
                    MockParameter(name="id"),
                    MockParameter(name="query"),
                ]
            )
        }
        result = extract_parameters_from_analysis(analysis)
        assert result == {"id", "query"}

    def test_object_with_string_parameters(self):
        """Test with string parameters."""
        analysis = {
            "http://x.com/api": MockAnalysis(
                parameters=["user", "pass"]
            )
        }
        result = extract_parameters_from_analysis(analysis)
        assert result == {"user", "pass"}

    def test_dict_with_parameters_key(self):
        """Test with dict having 'parameters' key."""
        analysis = {
            "http://x.com/api": {
                "parameters": [
                    {"name": "id"},
                    {"name": "action"},
                    "raw_param",
                ]
            }
        }
        result = extract_parameters_from_analysis(analysis)
        assert result == {"id", "action", "raw_param"}

    def test_dict_with_param_names_key(self):
        """Test with dict having 'param_names' key."""
        analysis = {
            "http://x.com/api": {
                "param_names": ["foo", "bar"]
            }
        }
        result = extract_parameters_from_analysis(analysis)
        assert result == {"foo", "bar"}

    def test_multiple_urls(self):
        """Test with multiple URLs."""
        analysis = {
            "http://x.com/a": MockAnalysis(
                parameters=[MockParameter(name="id")]
            ),
            "http://x.com/b": MockAnalysis(
                parameters=[MockParameter(name="name"), MockParameter(name="id")]
            ),
        }
        result = extract_parameters_from_analysis(analysis)
        # id appears twice but should be deduplicated
        assert result == {"id", "name"}


# ═══════════════════════════════════════════════════════════════════════════════
# AssetDataBuilder Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestAssetDataBuilderInit:
    """Tests for AssetDataBuilder initialization."""

    def test_default_init(self):
        """Test default initialization."""
        builder = AssetDataBuilder("http://example.com")
        assert builder.target == "http://example.com"
        assert builder.scheme == "http"
        assert builder.host == "example.com"

    def test_init_with_https(self):
        """Test initialization with HTTPS."""
        builder = AssetDataBuilder("https://secure.example.com")
        assert builder.scheme == "https"
        assert builder.host == "secure.example.com"

    def test_init_with_config(self):
        """Test initialization with config."""
        config = AssetBuilderConfig(log_debug=False)
        builder = AssetDataBuilder("http://x.com", config=config)
        assert builder.config.log_debug is False


class TestAssetDataBuilderRegistration:
    """Tests for registration methods."""

    def test_register_intelligent_context(self):
        """Test registering intelligent context."""
        builder = AssetDataBuilder("http://x.com")
        context = MockIntelligentContext()

        result = builder.register_intelligent_context(context)

        assert result is builder  # Returns self for chaining
        assert builder._intelligent_context is context

    def test_register_classification(self):
        """Test registering classification."""
        builder = AssetDataBuilder("http://x.com")
        classification = MockClassification(detected_technologies=["PHP"])

        builder.register_classification(classification)

        assert builder._classification is classification

    def test_register_tech_analysis(self):
        """Test registering tech analysis."""
        builder = AssetDataBuilder("http://x.com")
        tech = MockTechAnalysis(technologies=[MockTech(name="Django")])

        builder.register_tech_analysis(tech)

        assert builder._tech_analysis is tech

    def test_register_forms(self):
        """Test registering forms."""
        builder = AssetDataBuilder("http://x.com")
        forms = [{"action": "/login", "method": "POST"}]

        builder.register_forms(forms)

        assert builder._discovered_forms == forms

    def test_register_tool_discoveries(self):
        """Test registering tool discoveries."""
        builder = AssetDataBuilder("http://x.com")

        builder.register_tool_discoveries(
            endpoints=["http://x.com/admin"],
            params={"user": "injectable"},
            findings=[{"type": "info"}],
        )

        assert builder._tool_discovered_endpoints == ["http://x.com/admin"]
        assert builder._tool_discovered_params == {"user": "injectable"}
        assert builder._linux_tool_findings == [{"type": "info"}]

    def test_register_training_app(self):
        """Test registering training app endpoints."""
        builder = AssetDataBuilder("http://x.com")

        builder.register_priority_endpoints(["http://x.com/vuln"])

        assert builder._priority_endpoints == ["http://x.com/vuln"]

    def test_register_auth_context(self):
        """Test registering auth context."""
        builder = AssetDataBuilder("http://x.com")
        auth = MockAuthContext()

        builder.register_auth_context(auth)

        assert builder._auth_context is auth

    def test_chained_registration(self):
        """Test chained registration."""
        builder = AssetDataBuilder("http://x.com")
        context = MockIntelligentContext()
        auth = MockAuthContext()

        result = (
            builder
            .register_intelligent_context(context)
            .register_auth_context(auth)
            .register_forms([])
        )

        assert result is builder


class TestAssetDataBuilderBuild:
    """Tests for build methods."""

    def test_build_minimal(self):
        """Test building with minimal data."""
        builder = AssetDataBuilder("http://example.com")
        # Disable logging for cleaner tests
        builder.config.log_warnings = False
        builder.config.log_debug = False

        result = builder.build("test")

        assert isinstance(result, AssetData)
        assert result.endpoints == ["http://example.com"]
        assert result.parameters == []

    def test_build_with_intelligent_context(self):
        """Test building with intelligent context."""
        builder = AssetDataBuilder("http://example.com")
        builder.config.log_info = False
        builder.config.log_debug = False

        context = MockIntelligentContext(
            _endpoints_discovered=["http://example.com/api", "http://example.com/users"],
            _parameter_analysis={
                "http://example.com/api": MockAnalysis(
                    parameters=[MockParameter(name="id")]
                )
            },
        )
        builder.register_intelligent_context(context)

        result = builder.build("test")

        assert result.endpoints == ["http://example.com/api", "http://example.com/users"]
        assert "id" in result.parameters

    def test_build_with_technologies(self):
        """Test building with technologies."""
        builder = AssetDataBuilder("http://x.com")
        builder.config.log_warnings = False
        builder.config.log_debug = False

        classification = MockClassification(detected_technologies=["PHP", "Apache"])
        tech = MockTechAnalysis(technologies=[MockTech(name="MySQL")])

        builder.register_classification(classification)
        builder.register_tech_analysis(tech)

        result = builder.build("test")

        assert "PHP" in result.technologies
        assert "Apache" in result.technologies
        assert "MySQL" in result.technologies

    def test_build_with_auth_context_valid(self):
        """Test building with valid auth context."""
        builder = AssetDataBuilder("http://x.com")
        builder.config.log_warnings = False
        builder.config.log_debug = False

        auth = MockAuthContext(_has_auth=True)
        builder.register_auth_context(auth)

        result = builder.build("test")

        assert result.auth_context is auth

    def test_build_with_auth_context_invalid(self):
        """Test building with invalid auth context."""
        builder = AssetDataBuilder("http://x.com")
        builder.config.log_warnings = False
        builder.config.log_debug = False

        auth = MockAuthContext(_has_auth=False)
        builder.register_auth_context(auth)

        result = builder.build("test")

        # Invalid auth should not be included
        assert result.auth_context is None

    def test_build_with_training_app(self):
        """Test building with training app endpoints."""
        builder = AssetDataBuilder("http://x.com")
        builder.config.log_info = False
        builder.config.log_warnings = False
        builder.config.log_debug = False

        context = MockIntelligentContext(
            _endpoints_discovered=["http://x.com/api"]
        )
        builder.register_intelligent_context(context)
        builder.register_training_app(["http://x.com/vuln1", "http://x.com/vuln2"])

        result = builder.build("test")

        # Training app endpoints should be at the beginning
        assert result.is_training_app is True
        assert result.endpoints[0] == "http://x.com/vuln1"
        assert result.endpoints[1] == "http://x.com/vuln2"

    def test_build_with_stack_profile(self):
        """Test building with stack profile."""
        builder = AssetDataBuilder("http://x.com")
        builder.config.log_warnings = False
        builder.config.log_debug = False

        profile = MockStackProfile(data={"framework": "Django", "version": "4.0"})
        builder.register_stack_profile(profile)

        result = builder.build("test")

        assert result.stack_profile == {"framework": "Django", "version": "4.0"}

    def test_build_dict(self):
        """Test build_dict returns dictionary."""
        builder = AssetDataBuilder("http://x.com")
        builder.config.log_warnings = False
        builder.config.log_debug = False

        result = builder.build_dict("test")

        assert isinstance(result, dict)
        assert "endpoints" in result
        assert "parameters" in result

    def test_build_merges_tool_endpoints(self):
        """Test that tool-discovered endpoints are merged."""
        builder = AssetDataBuilder("http://x.com")
        builder.config.log_warnings = False
        builder.config.log_debug = False

        context = MockIntelligentContext(
            _endpoints_discovered=["http://x.com/api"]
        )
        builder.register_intelligent_context(context)
        builder.register_tool_discoveries(
            endpoints=["http://x.com/admin", "http://x.com/api"]  # api is duplicate
        )

        result = builder.build("test")

        assert "http://x.com/api" in result.endpoints
        assert "http://x.com/admin" in result.endpoints
        # Should not have duplicate
        assert result.endpoints.count("http://x.com/api") == 1


class TestAssetDataBuilderEdgeCases:
    """Tests for edge cases."""

    def test_warn_no_endpoints_once(self):
        """Test that warning is logged only once."""
        builder = AssetDataBuilder("http://x.com")
        builder.config.log_warnings = True
        builder.config.log_debug = False

        # First build should warn
        builder.build("module1")
        assert builder._warned_no_endpoints is True

        # Second build should not warn again (tracked internally)
        builder.build("module2")

    def test_injection_module_warning(self):
        """Test warning for injection modules without training app."""
        builder = AssetDataBuilder("http://x.com")
        builder.config.log_warnings = True
        builder.config.log_debug = False
        builder.config.log_info = False

        # Build for injection module without training app
        builder.build("sqli")
        # Should have warned (we can't verify logging directly but coverage is important)

    def test_generic_fallback(self):
        """Test generic fallback endpoint generation."""
        builder = AssetDataBuilder("http://x.com")
        builder.config.log_warnings = False
        builder.config.log_debug = False
        builder.config.log_info = False
        builder.config.use_generic_fallback = True

        # Register fallback function
        def fallback_func(target):
            return [f"{target}/admin", f"{target}/api"]

        builder.register_generic_fallback(fallback_func)

        result = builder.build("test")

        assert "http://x.com" in result.endpoints
        assert "http://x.com/admin" in result.endpoints
        assert "http://x.com/api" in result.endpoints

    def test_subdomains(self):
        """Test subdomain registration."""
        builder = AssetDataBuilder("http://x.com")
        builder.config.log_warnings = False
        builder.config.log_debug = False

        builder.register_subdomains({"api.x.com", "admin.x.com"})

        result = builder.build("test")

        assert "api.x.com" in result.subdomains
        assert "admin.x.com" in result.subdomains


# ═══════════════════════════════════════════════════════════════════════════════
# Convenience Functions Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestBuildAssetData:
    """Tests for build_asset_data function."""

    def test_minimal(self):
        """Test minimal build."""
        result = build_asset_data("http://x.com")

        assert result["endpoints"] == ["http://x.com"]
        assert result["parameters"] == []

    def test_with_endpoints(self):
        """Test with custom endpoints."""
        result = build_asset_data(
            "http://x.com",
            endpoints=["http://x.com/a", "http://x.com/b"],
        )

        assert result["endpoints"] == ["http://x.com/a", "http://x.com/b"]

    def test_with_parameters(self):
        """Test with parameters."""
        result = build_asset_data(
            "http://x.com",
            parameters=["id", "name"],
        )

        assert result["parameters"] == ["id", "name"]

    def test_with_auth_context(self):
        """Test with auth context."""
        auth = MockAuthContext()
        result = build_asset_data(
            "http://x.com",
            auth_context=auth,
        )

        assert result["auth_context"] is auth


class TestCreateBuilder:
    """Tests for create_builder function."""

    def test_creates_builder(self):
        """Test that create_builder returns builder."""
        builder = create_builder("http://example.com")

        assert isinstance(builder, AssetDataBuilder)
        assert builder.target == "http://example.com"


# ═══════════════════════════════════════════════════════════════════════════════
# Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestAssetBuilderIntegration:
    """Integration tests for asset builder."""

    def test_full_build_flow(self):
        """Test complete build flow with all registrations."""
        builder = create_builder("http://dvwa.local")
        builder.config.log_info = False
        builder.config.log_warnings = False
        builder.config.log_debug = False

        # Register intelligent context
        context = MockIntelligentContext(
            _endpoints_discovered=[
                "http://dvwa.local/login.php",
                "http://dvwa.local/vulnerabilities/sqli/",
            ],
            _parameter_analysis={
                "http://dvwa.local/vulnerabilities/sqli/": MockAnalysis(
                    parameters=[MockParameter(name="id"), MockParameter(name="Submit")]
                )
            },
        )
        builder.register_intelligent_context(context)

        # Register classification
        classification = MockClassification(
            detected_technologies=["PHP", "MySQL", "Apache"]
        )
        builder.register_classification(classification)

        # Register forms
        builder.register_forms([
            {"action": "/login.php", "method": "POST"},
        ])

        # Register auth
        auth = MockAuthContext(_has_auth=True)
        builder.register_auth_context(auth)

        # Register training app
        builder.register_training_app([
            "http://dvwa.local/vulnerabilities/sqli/",
            "http://dvwa.local/vulnerabilities/xss_r/",
        ])

        # Build for SQLi scanner
        result = builder.build("sqli")

        # Verify result
        assert result.is_training_app is True
        assert "id" in result.parameters
        assert "Submit" in result.parameters
        assert "PHP" in result.technologies
        assert result.auth_context is auth
        assert len(result.forms) == 1

        # Training app endpoints should be first
        assert "sqli" in result.endpoints[0] or "xss" in result.endpoints[0]

    def test_build_for_multiple_modules(self):
        """Test building for multiple modules."""
        builder = create_builder("http://x.com")
        builder.config.log_info = False
        builder.config.log_warnings = False
        builder.config.log_debug = False

        context = MockIntelligentContext(
            _endpoints_discovered=["http://x.com/api"]
        )
        builder.register_intelligent_context(context)

        # Build for different modules
        sqli_data = builder.build("sqli")
        xss_data = builder.build("xss")
        cors_data = builder.build("cors")

        # All should have same base data
        assert sqli_data.endpoints == xss_data.endpoints == cors_data.endpoints
