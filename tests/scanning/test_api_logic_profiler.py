"""
Tests for API Logic Profiler module.

These tests verify the API Logic Profiler functionality including:
- Response analysis
- Role comparison
- Vulnerability detection
- IDOR testing
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import httpx
import time

from scanning.modules.api_logic_profiler import (
    APILogicProfiler,
    ResponseAnalyzer,
    ResponseDiffVisualizer,
    ResponseProfile,
    ResponseDiff,
    ResponseDiffType,
    RoleConfig,
    VulnerabilityType,
    AuthzFinding,
    API_LOGIC_PROFILER_VERSION,
    SENSITIVE_FIELD_PATTERNS,
    ID_PATTERNS,
)


class TestResponseAnalyzer:
    """Test response analysis functionality."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return ResponseAnalyzer()

    def test_extract_fields_simple_dict(self):
        """Test field extraction from simple dict."""
        obj = {"name": "test", "email": "test@example.com"}
        fields, sensitive = ResponseAnalyzer._extract_fields(obj)

        assert "name" in fields
        assert "email" in fields
        assert "email" in sensitive  # email is sensitive

    def test_extract_fields_nested_dict(self):
        """Test field extraction from nested dict."""
        obj = {
            "user": {
                "id": 1,
                "profile": {
                    "email": "test@example.com",
                    "phone": "123456"
                }
            }
        }
        fields, sensitive = ResponseAnalyzer._extract_fields(obj)

        assert "user" in fields
        assert "user.id" in fields
        assert "user.profile" in fields
        assert "user.profile.email" in fields
        assert "user.profile.phone" in fields

        # Both email and phone should be sensitive
        assert "user.profile.email" in sensitive
        assert "user.profile.phone" in sensitive

    def test_extract_fields_with_array(self):
        """Test field extraction from array."""
        obj = {
            "users": [
                {"id": 1, "name": "test"}
            ]
        }
        fields, _ = ResponseAnalyzer._extract_fields(obj)

        assert "users" in fields
        assert "users[].id" in fields
        assert "users[].name" in fields

    def test_sensitive_field_detection(self):
        """Test detection of sensitive fields."""
        test_cases = [
            ("password", True),
            ("user_password", True),
            ("email", True),
            ("phone_number", True),
            ("credit_card", True),
            ("ssn", True),
            ("api_key", True),
            ("token", True),
            ("is_admin", True),
            ("role", True),
            ("name", True),  # name is in patterns
            ("description", False),
            ("count", False),
            ("timestamp", False),
        ]

        for field, should_be_sensitive in test_cases:
            is_sensitive = any(
                __import__('re').search(p, field.lower())
                for p in SENSITIVE_FIELD_PATTERNS
            )
            assert is_sensitive == should_be_sensitive, f"Field '{field}' sensitivity mismatch"

    def test_compare_profiles_status_code_diff(self):
        """Test comparison detects status code differences."""
        profile_a = ResponseProfile(
            role="admin",
            status_code=200,
            headers={},
            body={},
            body_hash="abc",
            response_time_ms=100,
            fields=set(),
            sensitive_fields=[],
            timestamp=time.time(),
        )

        profile_b = ResponseProfile(
            role="user",
            status_code=403,
            headers={},
            body={},
            body_hash="def",
            response_time_ms=100,
            fields=set(),
            sensitive_fields=[],
            timestamp=time.time(),
        )

        diffs = ResponseAnalyzer.compare_profiles(profile_a, profile_b)

        status_diffs = [d for d in diffs if d.diff_type == ResponseDiffType.STATUS_CODE]
        assert len(status_diffs) == 1
        assert status_diffs[0].severity == "CRITICAL"  # 200 vs 403 is critical

    def test_compare_profiles_field_presence(self):
        """Test comparison detects field presence differences."""
        profile_a = ResponseProfile(
            role="admin",
            status_code=200,
            headers={},
            body={"id": 1, "email": "test@test.com", "password_hash": "xxx"},
            body_hash="abc",
            response_time_ms=100,
            fields={"id", "email", "password_hash"},
            sensitive_fields=["email", "password_hash"],
            timestamp=time.time(),
        )

        profile_b = ResponseProfile(
            role="user",
            status_code=200,
            headers={},
            body={"id": 1, "email": "test@test.com"},
            body_hash="def",
            response_time_ms=100,
            fields={"id", "email"},
            sensitive_fields=["email"],
            timestamp=time.time(),
        )

        diffs = ResponseAnalyzer.compare_profiles(profile_a, profile_b)

        field_diffs = [d for d in diffs if d.diff_type == ResponseDiffType.FIELD_PRESENCE]
        assert len(field_diffs) >= 1

        # password_hash should be flagged as only visible to admin
        password_diff = [d for d in field_diffs if "password" in d.field_path]
        assert len(password_diff) == 1
        assert password_diff[0].severity == "HIGH"  # Sensitive field


class TestRoleConfig:
    """Test role configuration."""

    def test_role_config_defaults(self):
        """Test RoleConfig has correct defaults."""
        role = RoleConfig(name="test")

        assert role.name == "test"
        assert role.headers == {}
        assert role.cookies == {}
        assert role.params == {}
        assert role.description == ""

    def test_role_config_with_auth(self):
        """Test RoleConfig with authentication."""
        role = RoleConfig(
            name="admin",
            headers={"Authorization": "Bearer token123"},
            cookies={"session": "abc"},
        )

        assert role.headers["Authorization"] == "Bearer token123"
        assert role.cookies["session"] == "abc"


class TestResponseDiffVisualizer:
    """Test response diff visualization."""

    @pytest.fixture
    def visualizer(self):
        """Create visualizer instance."""
        return ResponseDiffVisualizer()

    def test_generate_markdown_report(self, visualizer):
        """Test markdown report generation."""
        profiles = [
            ResponseProfile(
                role="admin",
                status_code=200,
                headers={},
                body={"test": "value"},
                body_hash="abc",
                response_time_ms=100,
                fields={"test"},
                sensitive_fields=[],
                timestamp=time.time(),
            ),
            ResponseProfile(
                role="user",
                status_code=200,
                headers={},
                body={"test": "value"},
                body_hash="abc",
                response_time_ms=100,
                fields={"test"},
                sensitive_fields=[],
                timestamp=time.time(),
            ),
        ]

        diffs = []

        report = visualizer.generate_markdown_report("/api/test", profiles, diffs)

        assert "# API Role Comparison Report" in report
        assert "/api/test" in report
        assert "admin" in report
        assert "user" in report

    def test_generate_markdown_report_with_diffs(self, visualizer):
        """Test markdown report with differences."""
        profiles = [
            ResponseProfile(
                role="admin",
                status_code=200,
                headers={},
                body={},
                body_hash="abc",
                response_time_ms=100,
                fields=set(),
                sensitive_fields=[],
                timestamp=time.time(),
            ),
        ]

        diffs = [
            ResponseDiff(
                diff_type=ResponseDiffType.FIELD_PRESENCE,
                field_path="secret_data",
                role_a="admin",
                role_b="user",
                value_a="present",
                value_b="absent",
                severity="HIGH",
                description="Field 'secret_data' only visible to admin",
            ),
        ]

        report = visualizer.generate_markdown_report("/api/test", profiles, diffs)

        assert "HIGH" in report
        assert "secret_data" in report


class TestAPILogicProfiler:
    """Test API Logic Profiler scanner."""

    @pytest.fixture
    def mock_settings(self):
        """Create mock settings."""
        settings = MagicMock()
        settings.timeouts.request_timeout = 30
        return settings

    @pytest.fixture
    def profiler(self, mock_settings):
        """Create profiler instance."""
        return APILogicProfiler(mock_settings)

    def test_profiler_initialization(self, profiler):
        """Test profiler initializes correctly."""
        assert profiler.name == "api_logic_profiler"
        assert profiler.version == API_LOGIC_PROFILER_VERSION
        assert profiler.roles == []

    def test_configure_roles(self, profiler):
        """Test role configuration."""
        roles = [
            RoleConfig(name="admin", headers={"X-Role": "admin"}),
            RoleConfig(name="user", headers={"X-Role": "user"}),
        ]

        profiler.configure_roles(roles)

        assert len(profiler.roles) == 2
        assert profiler.roles[0].name == "admin"
        assert profiler.roles[1].name == "user"

    def test_analyze_for_vulnerabilities_bola(self, profiler):
        """Test BOLA vulnerability detection."""
        profiles = []
        diffs = [
            ResponseDiff(
                diff_type=ResponseDiffType.FIELD_VALUE,
                field_path="user_id",
                role_a="user1",
                role_b="user2",
                value_a=1,
                value_b=2,
                severity="CRITICAL",
                description="ID difference detected",
            ),
        ]

        findings = profiler._analyze_for_vulnerabilities("/api/user/1", profiles, diffs)

        assert len(findings) >= 1
        bola_findings = [f for f in findings if f.vuln_type == VulnerabilityType.BOLA]
        assert len(bola_findings) == 1

    def test_analyze_for_vulnerabilities_data_leakage(self, profiler):
        """Test data leakage detection."""
        profiles = []
        diffs = [
            ResponseDiff(
                diff_type=ResponseDiffType.FIELD_PRESENCE,
                field_path="email",
                role_a="admin",
                role_b="user",
                value_a="present",
                value_b="absent",
                severity="HIGH",
                description="Sensitive field only visible to admin",
            ),
        ]

        findings = profiler._analyze_for_vulnerabilities("/api/users", profiles, diffs)

        assert len(findings) >= 1
        leakage_findings = [f for f in findings if f.vuln_type == VulnerabilityType.DATA_LEAKAGE]
        assert len(leakage_findings) == 1

    def test_create_finding_idor(self, profiler):
        """Test finding creation for IDOR."""
        authz_finding = AuthzFinding(
            vuln_type=VulnerabilityType.IDOR,
            endpoint="https://example.com/api/user/123",
            method="GET",
            roles_affected=["user"],
            diffs=[],
            confidence=85.0,
            impact="Can access other users' data",
            evidence=["Original ID: 123", "Modified ID: 124"],
            remediation="Implement authorization checks",
        )

        finding = profiler._create_finding(authz_finding)

        assert finding.type == "authorization"
        assert "IDOR" in finding.name
        assert finding.severity == "HIGH"
        assert finding.cwe == "CWE-639"
        assert finding.confidence == 85.0


class TestVulnerabilityTypes:
    """Test vulnerability type enumeration."""

    def test_all_vuln_types_defined(self):
        """Test all expected vulnerability types are defined."""
        expected_types = [
            "IDOR",
            "BOLA",
            "BFLA",
            "HORIZONTAL_PRIV_ESC",
            "VERTICAL_PRIV_ESC",
            "MASS_ASSIGNMENT",
            "DATA_LEAKAGE",
            "MULTI_TENANT_ISOLATION",
            "STATE_INCONSISTENCY",
        ]

        actual_types = [v.name for v in VulnerabilityType]

        for expected in expected_types:
            assert expected in actual_types


@pytest.mark.asyncio
class TestAPILogicProfilerAsync:
    """Async tests for API Logic Profiler."""

    @pytest.fixture
    def mock_settings(self):
        """Create mock settings."""
        settings = MagicMock()
        settings.timeouts.request_timeout = 30
        return settings

    @pytest.fixture
    def profiler(self, mock_settings):
        """Create profiler instance."""
        return APILogicProfiler(mock_settings)

    @pytest.fixture
    def mock_rate_limiter(self):
        """Create mock rate limiter."""
        limiter = MagicMock()
        limiter.acquire = AsyncMock()
        return limiter

    async def test_scan_with_no_roles_creates_defaults(self, profiler, mock_rate_limiter):
        """Test scan creates default roles when none configured."""
        asset_data = {
            "endpoints": [],
            "api_endpoints": [],
            "roles": [],
        }

        # Mock httpx to avoid actual requests
        with patch('scanning.modules.api_logic_profiler.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {}
            mock_response.content = b'{}'
            mock_response.headers = {}

            mock_client_instance = AsyncMock()
            mock_client_instance.get = AsyncMock(return_value=mock_response)
            mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
            mock_client_instance.__aexit__ = AsyncMock()
            mock_client.return_value = mock_client_instance

            result = await profiler.scan("example.com", asset_data, mock_rate_limiter)

        assert result["module"] == "api_logic_profiler"
        # Should have created at least 2 default roles
        assert result["stats"]["roles_tested"] >= 2
