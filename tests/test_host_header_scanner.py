"""
Tests for scanning/modules/host_header_scanner.py

Covers:
- HostVulnType enum (11 types)
- InjectionVector enum (12 vectors)
- HOST_OVERRIDE_HEADERS list
- INTERNAL_HOSTS list
- CANARY_HOSTS list
- Dataclasses (HostEndpoint, HostTestResult, HostFinding, ScanConfig)
- HostManipulator class
- PasswordResetPoisoner class
"""

import pytest
from scanning.modules.host_header_scanner import (
    VERSION,
    HostVulnType,
    InjectionVector,
    HOST_OVERRIDE_HEADERS,
    INTERNAL_HOSTS,
    CANARY_HOSTS,
    HostEndpoint,
    HostTestResult,
    HostFinding,
    ScanConfig,
    HostManipulator,
    PasswordResetPoisoner,
)


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestHostVulnType:
    def test_count(self):
        assert len(HostVulnType) == 11

    def test_password_reset_poisoning(self):
        assert HostVulnType.PASSWORD_RESET_POISONING is not None

    def test_web_cache_poisoning(self):
        assert HostVulnType.WEB_CACHE_POISONING is not None

    def test_ssrf_via_host(self):
        assert HostVulnType.SSRF_VIA_HOST is not None

    def test_routing_based_ssrf(self):
        assert HostVulnType.ROUTING_BASED_SSRF is not None

    def test_auth_bypass(self):
        assert HostVulnType.AUTH_BYPASS is not None

    def test_virtual_host_brute(self):
        assert HostVulnType.VIRTUAL_HOST_BRUTE is not None

    def test_host_validation_bypass(self):
        assert HostVulnType.HOST_VALIDATION_BYPASS is not None

    def test_connection_state(self):
        assert HostVulnType.CONNECTION_STATE is not None

    def test_internal_access(self):
        assert HostVulnType.INTERNAL_ACCESS is not None


class TestInjectionVector:
    def test_count(self):
        assert len(InjectionVector) == 12

    def test_host_header(self):
        assert InjectionVector.HOST_HEADER is not None

    def test_x_forwarded_host(self):
        assert InjectionVector.X_FORWARDED_HOST is not None

    def test_forwarded(self):
        assert InjectionVector.FORWARDED is not None

    def test_absolute_url(self):
        assert InjectionVector.ABSOLUTE_URL is not None

    def test_duplicate_host(self):
        assert InjectionVector.DUPLICATE_HOST is not None

    def test_x_original_url(self):
        assert InjectionVector.X_ORIGINAL_URL is not None


# =============================================================================
# CONSTANTS
# =============================================================================

class TestHostOverrideHeaders:
    def test_not_empty(self):
        assert len(HOST_OVERRIDE_HEADERS) > 0

    def test_has_x_forwarded_host(self):
        assert "X-Forwarded-Host" in HOST_OVERRIDE_HEADERS

    def test_has_x_host(self):
        assert "X-Host" in HOST_OVERRIDE_HEADERS

    def test_has_forwarded(self):
        assert "Forwarded" in HOST_OVERRIDE_HEADERS

    def test_has_x_original_url(self):
        assert "X-Original-URL" in HOST_OVERRIDE_HEADERS

    def test_has_x_rewrite_url(self):
        assert "X-Rewrite-URL" in HOST_OVERRIDE_HEADERS

    def test_has_x_real_ip(self):
        assert "X-Real-IP" in HOST_OVERRIDE_HEADERS

    def test_has_true_client_ip(self):
        assert "True-Client-IP" in HOST_OVERRIDE_HEADERS

    def test_has_client_ip(self):
        assert "Client-IP" in HOST_OVERRIDE_HEADERS


class TestInternalHosts:
    def test_not_empty(self):
        assert len(INTERNAL_HOSTS) > 0

    def test_has_localhost(self):
        assert "localhost" in INTERNAL_HOSTS

    def test_has_127(self):
        assert "127.0.0.1" in INTERNAL_HOSTS

    def test_has_ipv6_loopback(self):
        assert "[::1]" in INTERNAL_HOSTS

    def test_has_private_ranges(self):
        assert any("192.168" in h for h in INTERNAL_HOSTS)
        assert any("10." in h for h in INTERNAL_HOSTS)
        assert any("172." in h for h in INTERNAL_HOSTS)

    def test_has_zero_address(self):
        assert "0.0.0.0" in INTERNAL_HOSTS or "0" in INTERNAL_HOSTS


class TestCanaryHosts:
    def test_not_empty(self):
        assert len(CANARY_HOSTS) > 0

    def test_has_burp(self):
        assert any("burp" in h for h in CANARY_HOSTS)

    def test_has_interact(self):
        assert any("interact" in h for h in CANARY_HOSTS)


# =============================================================================
# DATACLASS TESTS
# =============================================================================

class TestHostEndpoint:
    def test_defaults(self):
        ep = HostEndpoint(url="https://target.com/forgot-password")
        assert ep.method == "GET"
        assert ep.headers == {}
        assert ep.body is None
        assert ep.is_password_reset is False
        assert ep.is_cacheable is False

    def test_auto_host_extraction(self):
        ep = HostEndpoint(url="https://example.com:8443/path")
        assert ep.original_host == "example.com:8443"

    def test_custom_host(self):
        ep = HostEndpoint(url="https://target.com", original_host="custom.com")
        assert ep.original_host == "custom.com"

    def test_password_reset_endpoint(self):
        ep = HostEndpoint(
            url="https://target.com/forgot-password",
            method="POST",
            is_password_reset=True,
        )
        assert ep.is_password_reset is True


class TestHostTestResult:
    def test_creation(self):
        ep = HostEndpoint(url="https://target.com")
        result = HostTestResult(
            endpoint=ep,
            injection_vector=InjectionVector.X_FORWARDED_HOST,
            injected_value="evil.com",
            response_code=200,
            response_body="Reset link: https://evil.com/reset?token=abc",
            response_headers={},
            reflected_in_body=True,
            reflected_in_headers=False,
            reflected_in_location=False,
            caused_error=False,
            cache_hit=False,
            evidence={"vector": "X_FORWARDED_HOST", "reflected": True},
        )
        assert result.reflected_in_body is True
        assert result.injection_vector == InjectionVector.X_FORWARDED_HOST


class TestHostFinding:
    def test_creation(self):
        ep = HostEndpoint(url="https://target.com/forgot-password")
        finding = HostFinding(
            id="HOST-0001",
            vuln_type=HostVulnType.PASSWORD_RESET_POISONING,
            severity="HIGH",
            confidence=0.95,
            endpoint=ep,
            injection_vector=InjectionVector.X_FORWARDED_HOST,
            injected_value="evil.com",
            description="Password reset poisoning via X-Forwarded-Host",
            impact="Attacker can hijack password reset tokens",
            remediation="Ignore X-Forwarded-Host for link generation",
            evidence={"reflected": True},
            cwe_id=20,
            cvss_score=8.1,
            request_example="X-Forwarded-Host: evil.com",
            response_evidence="Reset link points to evil.com",
        )
        assert finding.cwe_id == 20


class TestScanConfig:
    def test_defaults(self):
        config = ScanConfig(target_url="https://target.com")
        assert config.timeout == 30.0
        assert config.test_password_reset is True
        assert config.test_cache_poisoning is True
        assert config.test_ssrf is True
        assert config.test_auth_bypass is True
        assert config.test_vhost_enum is True
        assert config.collaborator_domain is None
        assert config.safe_mode is True
        assert config.max_vhosts_to_test == 100


# =============================================================================
# HOST MANIPULATOR
# =============================================================================

class TestHostManipulator:
    def test_version(self):
        assert HostManipulator.VERSION == "3.0.0"

    def test_inject_port(self):
        assert HostManipulator.inject_port("example.com", 8080) == "example.com:8080"

    def test_inject_port_replace(self):
        assert HostManipulator.inject_port("example.com:443", 8080) == "example.com:8080"

    def test_inject_subdomain(self):
        assert HostManipulator.inject_subdomain("example.com", "admin") == "admin.example.com"

    def test_wrap_brackets(self):
        assert HostManipulator.wrap_brackets("127.0.0.1") == "[127.0.0.1]"

    def test_add_whitespace(self):
        variations = HostManipulator.add_whitespace("evil.com")
        assert len(variations) > 0
        assert any(v.startswith(" ") for v in variations)
        assert any(v.endswith(" ") for v in variations)
        assert any("\t" in v for v in variations)

    def test_case_variations(self):
        variations = HostManipulator.case_variations("evil.com")
        assert "EVIL.COM" in variations
        assert "evil.com" in variations

    def test_generate_bypass_hosts(self):
        bypasses = HostManipulator.generate_bypass_hosts("legit.com", "evil.com")
        assert len(bypasses) > 5
        assert "evil.com" in bypasses
        # Should have various bypass techniques
        assert any("#" in b for b in bypasses)
        assert any("@" in b for b in bypasses)
        assert any("." in b and "evil" in b and "legit" in b for b in bypasses)

    def test_generate_bypass_has_fragment(self):
        bypasses = HostManipulator.generate_bypass_hosts("legit.com", "evil.com")
        assert "evil.com#legit.com" in bypasses

    def test_generate_bypass_has_at_sign(self):
        bypasses = HostManipulator.generate_bypass_hosts("legit.com", "evil.com")
        assert "evil.com@legit.com" in bypasses
        assert "legit.com@evil.com" in bypasses

    def test_generate_internal_bypass(self):
        bypasses = HostManipulator.generate_internal_bypass("target.com", "localhost")
        assert len(bypasses) > 0
        assert "localhost" in bypasses
        assert any("target.com" in b and "localhost" in b for b in bypasses)


# =============================================================================
# PASSWORD RESET POISONER
# =============================================================================

class TestPasswordResetPoisoner:
    def test_version(self):
        assert PasswordResetPoisoner.VERSION == "3.0.0"

    def test_reset_patterns_not_empty(self):
        assert len(PasswordResetPoisoner.RESET_PATTERNS) > 0

    def test_has_forgot_password(self):
        assert "/forgot-password" in PasswordResetPoisoner.RESET_PATTERNS

    def test_has_password_reset(self):
        assert "/password/reset" in PasswordResetPoisoner.RESET_PATTERNS

    def test_has_recover(self):
        assert "/recover" in PasswordResetPoisoner.RESET_PATTERNS

    def test_email_params_not_empty(self):
        assert len(PasswordResetPoisoner.EMAIL_PARAMS) > 0

    def test_has_email_param(self):
        assert "email" in PasswordResetPoisoner.EMAIL_PARAMS

    def test_has_username_param(self):
        assert "username" in PasswordResetPoisoner.EMAIL_PARAMS

    def test_init(self):
        poisoner = PasswordResetPoisoner()
        assert poisoner.http_client is None
        assert poisoner.manipulator is not None


# =============================================================================
# ATTACK SCENARIOS
# =============================================================================

class TestAttackScenarios:
    def test_password_reset_poisoning_scenario(self):
        ep = HostEndpoint(
            url="https://target.com/forgot-password",
            method="POST",
            is_password_reset=True,
        )
        result = HostTestResult(
            endpoint=ep,
            injection_vector=InjectionVector.X_FORWARDED_HOST,
            injected_value="evil.com",
            response_code=200,
            response_body="A password reset link has been sent. https://evil.com/reset?token=secret123",
            response_headers={},
            reflected_in_body=True,
            reflected_in_headers=False,
            reflected_in_location=False,
            caused_error=False,
            cache_hit=False,
            evidence={"reflected": True},
        )
        assert result.reflected_in_body is True
        assert "evil.com" in result.response_body

    def test_cache_poisoning_scenario(self):
        ep = HostEndpoint(
            url="https://target.com/",
            is_cacheable=True,
        )
        result = HostTestResult(
            endpoint=ep,
            injection_vector=InjectionVector.HOST_HEADER,
            injected_value="evil.com",
            response_code=200,
            response_body='<base href="https://evil.com/">',
            response_headers={"X-Cache": "HIT"},
            reflected_in_body=True,
            reflected_in_headers=False,
            reflected_in_location=False,
            caused_error=False,
            cache_hit=True,
            evidence={"reflected": True, "cached": True},
        )
        assert result.cache_hit is True

    def test_ssrf_via_host_scenario(self):
        bypasses = HostManipulator.generate_internal_bypass("target.com", "localhost")
        assert "localhost" in bypasses

    def test_auth_bypass_internal_header(self):
        """Internal host headers can bypass IP-based access controls."""
        assert "X-Real-IP" in HOST_OVERRIDE_HEADERS
        assert "X-Custom-IP-Authorization" in HOST_OVERRIDE_HEADERS


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    def test_version(self):
        assert VERSION == "3.0.0"

    def test_all_vuln_types_unique(self):
        values = [t.value for t in HostVulnType]
        assert len(values) == len(set(values))

    def test_all_vectors_unique(self):
        values = [v.value for v in InjectionVector]
        assert len(values) == len(set(values))

    def test_endpoint_empty_url(self):
        ep = HostEndpoint(url="")
        assert ep.original_host == ""

    def test_manipulator_empty_host(self):
        result = HostManipulator.inject_port("", 80)
        assert result == ":80"

    def test_bypass_hosts_count(self):
        bypasses = HostManipulator.generate_bypass_hosts("a.com", "b.com")
        assert len(bypasses) >= 10  # Should have many bypass techniques
