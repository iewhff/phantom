"""
Tests for utils/validators.py - Input Validation Utilities.

Covers:
- ValidationError exception
- _sanitize_input function
- validate_target function
- validate_url function
- validate_domain function
- validate_ip function
- validate_cidr function
- validate_port function
- validate_port_range function
- validate_email function
- is_private_ip function
- is_loopback function
- extract_domain_from_url function
- extract_base_domain function
"""

import pytest

from utils.validators import (
    ValidationError,
    validate_target,
    validate_url,
    validate_domain,
    validate_ip,
    validate_cidr,
    validate_port,
    validate_port_range,
    validate_email,
    is_private_ip,
    is_loopback,
    extract_domain_from_url,
    extract_base_domain,
    _sanitize_input,
    MAX_TARGET_LENGTH,
    MAX_DOMAIN_LENGTH,
)


# =============================================================================
# VALIDATION ERROR TESTS
# =============================================================================

class TestValidationError:
    """Tests for ValidationError exception."""

    def test_validation_error_message(self):
        """Test ValidationError stores message."""
        error = ValidationError("Invalid input")
        assert str(error) == "Invalid input"

    def test_validation_error_raises(self):
        """Test ValidationError can be raised."""
        with pytest.raises(ValidationError):
            raise ValidationError("Test error")


# =============================================================================
# SANITIZE INPUT TESTS
# =============================================================================

class TestSanitizeInput:
    """Tests for _sanitize_input function."""

    def test_sanitize_normal_input(self):
        """Test normal input passes through."""
        result = _sanitize_input("example.com")
        assert result == "example.com"

    def test_sanitize_strips_whitespace(self):
        """Test whitespace is stripped."""
        result = _sanitize_input("  example.com  ")
        assert result == "example.com"

    def test_sanitize_non_string_raises(self):
        """Test non-string input raises error."""
        with pytest.raises(ValidationError, match="must be a string"):
            _sanitize_input(123)

    def test_sanitize_too_long_raises(self):
        """Test too-long input raises error."""
        long_input = "a" * (MAX_TARGET_LENGTH + 1)
        with pytest.raises(ValidationError, match="too long"):
            _sanitize_input(long_input)

    def test_sanitize_control_chars_raises(self):
        """Test control characters raise error."""
        with pytest.raises(ValidationError, match="control characters"):
            _sanitize_input("example\x00.com")

    def test_sanitize_null_byte_raises(self):
        """Test null byte raises error."""
        with pytest.raises(ValidationError, match="control characters"):
            _sanitize_input("example\x00.com")

    def test_sanitize_unicode_normalization(self):
        """Test unicode is normalized."""
        # Full-width 'A' (U+FF21) should normalize to 'A'
        result = _sanitize_input("Ａ")
        assert result == "A"


# =============================================================================
# VALIDATE TARGET TESTS
# =============================================================================

class TestValidateTarget:
    """Tests for validate_target function."""

    def test_validate_domain_target(self):
        """Test domain target validation."""
        result = validate_target("example.com")
        assert result == "example.com"

    def test_validate_url_target(self):
        """Test URL target validation."""
        result = validate_target("https://example.com")
        assert result == "https://example.com"

    def test_validate_ip_target(self):
        """Test IP target validation."""
        result = validate_target("192.168.1.1")
        assert result == "192.168.1.1"

    def test_validate_cidr_target(self):
        """Test CIDR target validation."""
        result = validate_target("192.168.1.0/24")
        assert "192.168.1.0/24" in result

    def test_validate_empty_target_raises(self):
        """Test empty target raises error."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_target("")

    def test_validate_whitespace_target_raises(self):
        """Test whitespace-only target raises error."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_target("   ")


# =============================================================================
# VALIDATE URL TESTS
# =============================================================================

class TestValidateUrl:
    """Tests for validate_url function."""

    def test_valid_http_url(self):
        """Test valid HTTP URL."""
        result = validate_url("http://example.com")
        assert result == "http://example.com"

    def test_valid_https_url(self):
        """Test valid HTTPS URL."""
        result = validate_url("https://example.com")
        assert result == "https://example.com"

    def test_url_with_path(self):
        """Test URL with path."""
        result = validate_url("https://example.com/api/v1")
        assert result == "https://example.com/api/v1"

    def test_url_with_port(self):
        """Test URL with port."""
        result = validate_url("https://example.com:8443")
        assert result == "https://example.com:8443"

    def test_url_with_query(self):
        """Test URL with query string."""
        result = validate_url("https://example.com/api?key=value")
        assert result == "https://example.com/api?key=value"

    def test_url_trailing_slash_removed(self):
        """Test trailing slash is removed when no path."""
        result = validate_url("https://example.com/")
        assert result == "https://example.com"

    def test_url_trailing_slash_kept_with_path(self):
        """Test trailing slash kept when path exists."""
        result = validate_url("https://example.com/api/")
        assert result == "https://example.com/api/"

    def test_url_with_ip(self):
        """Test URL with IP address."""
        result = validate_url("http://192.168.1.1/api")
        assert result == "http://192.168.1.1/api"

    def test_invalid_scheme_raises(self):
        """Test invalid scheme raises error."""
        with pytest.raises(ValidationError, match="Invalid URL scheme"):
            validate_url("ftp://example.com")

    def test_missing_host_raises(self):
        """Test missing host raises error."""
        with pytest.raises(ValidationError, match="missing host"):
            validate_url("http://")


# =============================================================================
# VALIDATE DOMAIN TESTS
# =============================================================================

class TestValidateDomain:
    """Tests for validate_domain function."""

    def test_valid_domain(self):
        """Test valid domain."""
        result = validate_domain("example.com")
        assert result == "example.com"

    def test_subdomain(self):
        """Test subdomain validation."""
        result = validate_domain("api.example.com")
        assert result == "api.example.com"

    def test_multiple_subdomains(self):
        """Test multiple subdomains."""
        result = validate_domain("a.b.c.example.com")
        assert result == "a.b.c.example.com"

    def test_domain_normalized_lowercase(self):
        """Test domain is normalized to lowercase."""
        result = validate_domain("EXAMPLE.COM")
        assert result == "example.com"

    def test_domain_trailing_dot_removed(self):
        """Test trailing dot is removed."""
        result = validate_domain("example.com.")
        assert result == "example.com"

    def test_empty_domain_raises(self):
        """Test empty domain raises error."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_domain("")

    def test_domain_too_long_raises(self):
        """Test too-long domain raises error."""
        long_domain = "a" * 254 + ".com"
        with pytest.raises(ValidationError, match="too long"):
            validate_domain(long_domain)

    def test_single_label_raises(self):
        """Test single label raises error."""
        with pytest.raises(ValidationError, match="at least two labels"):
            validate_domain("localhost")

    def test_label_too_long_raises(self):
        """Test label too long raises error."""
        long_label = "a" * 64 + ".com"
        with pytest.raises(ValidationError, match="Label too long"):
            validate_domain(long_label)

    def test_label_starts_hyphen_raises(self):
        """Test label starting with hyphen raises error."""
        with pytest.raises(ValidationError, match="cannot start/end with hyphen"):
            validate_domain("-example.com")

    def test_label_ends_hyphen_raises(self):
        """Test label ending with hyphen raises error."""
        with pytest.raises(ValidationError, match="cannot start/end with hyphen"):
            validate_domain("example-.com")

    def test_invalid_characters_raises(self):
        """Test invalid characters raise error."""
        with pytest.raises(ValidationError, match="Invalid characters"):
            validate_domain("exam_ple.com")

    def test_empty_label_raises(self):
        """Test empty label raises error."""
        with pytest.raises(ValidationError, match="Empty label"):
            validate_domain("example..com")


# =============================================================================
# VALIDATE IP TESTS
# =============================================================================

class TestValidateIp:
    """Tests for validate_ip function."""

    def test_valid_ipv4(self):
        """Test valid IPv4 address."""
        result = validate_ip("192.168.1.1")
        assert result == "192.168.1.1"

    def test_valid_ipv4_localhost(self):
        """Test localhost IPv4."""
        result = validate_ip("127.0.0.1")
        assert result == "127.0.0.1"

    def test_valid_ipv6(self):
        """Test valid IPv6 address."""
        result = validate_ip("::1")
        assert result == "::1"

    def test_valid_ipv6_full(self):
        """Test full IPv6 address."""
        result = validate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        # Normalized form
        assert "2001:" in result

    def test_invalid_ip_raises(self):
        """Test invalid IP raises error."""
        with pytest.raises(ValidationError, match="Invalid IP"):
            validate_ip("256.1.1.1")

    def test_invalid_format_raises(self):
        """Test invalid format raises error."""
        with pytest.raises(ValidationError, match="Invalid IP"):
            validate_ip("not-an-ip")


# =============================================================================
# VALIDATE CIDR TESTS
# =============================================================================

class TestValidateCidr:
    """Tests for validate_cidr function."""

    def test_valid_cidr_24(self):
        """Test valid /24 CIDR."""
        result = validate_cidr("192.168.1.0/24")
        assert "192.168.1.0/24" in result

    def test_valid_cidr_16(self):
        """Test valid /16 CIDR."""
        result = validate_cidr("10.0.0.0/16")
        assert "10.0.0.0/16" in result

    def test_valid_cidr_single(self):
        """Test single host CIDR."""
        result = validate_cidr("192.168.1.1/32")
        assert "192.168.1.1/32" in result

    def test_cidr_normalized(self):
        """Test CIDR is normalized (strict=False)."""
        result = validate_cidr("192.168.1.100/24")
        assert "192.168.1.0/24" in result

    def test_invalid_cidr_raises(self):
        """Test invalid CIDR raises error."""
        with pytest.raises(ValidationError, match="Invalid CIDR"):
            validate_cidr("192.168.1.0/33")

    def test_invalid_format_raises(self):
        """Test invalid format raises error."""
        with pytest.raises(ValidationError, match="Invalid CIDR"):
            validate_cidr("not/a/cidr")


# =============================================================================
# VALIDATE PORT TESTS
# =============================================================================

class TestValidatePort:
    """Tests for validate_port function."""

    def test_valid_port_80(self):
        """Test valid port 80."""
        result = validate_port(80)
        assert result == 80

    def test_valid_port_443(self):
        """Test valid port 443."""
        result = validate_port(443)
        assert result == 443

    def test_valid_port_string(self):
        """Test port as string."""
        result = validate_port("8080")
        assert result == 8080

    def test_port_min(self):
        """Test minimum port."""
        result = validate_port(1)
        assert result == 1

    def test_port_max(self):
        """Test maximum port."""
        result = validate_port(65535)
        assert result == 65535

    def test_port_zero_raises(self):
        """Test port 0 raises error."""
        with pytest.raises(ValidationError, match="out of range"):
            validate_port(0)

    def test_port_negative_raises(self):
        """Test negative port raises error."""
        with pytest.raises(ValidationError, match="out of range"):
            validate_port(-1)

    def test_port_too_high_raises(self):
        """Test port > 65535 raises error."""
        with pytest.raises(ValidationError, match="out of range"):
            validate_port(65536)

    def test_invalid_port_raises(self):
        """Test invalid port raises error."""
        with pytest.raises(ValidationError, match="Invalid port"):
            validate_port("abc")


# =============================================================================
# VALIDATE PORT RANGE TESTS
# =============================================================================

class TestValidatePortRange:
    """Tests for validate_port_range function."""

    def test_single_port(self):
        """Test single port as range."""
        start, end = validate_port_range("80")
        assert start == 80
        assert end == 80

    def test_port_range(self):
        """Test port range."""
        start, end = validate_port_range("1-1000")
        assert start == 1
        assert end == 1000

    def test_port_range_whitespace(self):
        """Test port range with whitespace."""
        start, end = validate_port_range("  80-443  ")
        assert start == 80
        assert end == 443

    def test_invalid_range_format_raises(self):
        """Test invalid format raises error."""
        with pytest.raises(ValidationError, match="Invalid port range format"):
            validate_port_range("1-2-3")

    def test_reversed_range_raises(self):
        """Test reversed range raises error."""
        with pytest.raises(ValidationError, match="start > end"):
            validate_port_range("1000-80")


# =============================================================================
# VALIDATE EMAIL TESTS
# =============================================================================

class TestValidateEmail:
    """Tests for validate_email function."""

    def test_valid_email(self):
        """Test valid email."""
        result = validate_email("user@example.com")
        assert result == "user@example.com"

    def test_email_with_plus(self):
        """Test email with plus sign."""
        result = validate_email("user+tag@example.com")
        assert result == "user+tag@example.com"

    def test_email_subdomain(self):
        """Test email with subdomain."""
        result = validate_email("user@mail.example.com")
        assert result == "user@mail.example.com"

    def test_email_normalized_lowercase(self):
        """Test email is normalized to lowercase."""
        result = validate_email("USER@EXAMPLE.COM")
        assert result == "user@example.com"

    def test_invalid_email_no_at(self):
        """Test invalid email without @."""
        with pytest.raises(ValidationError, match="Invalid email"):
            validate_email("userexample.com")

    def test_invalid_email_no_domain(self):
        """Test invalid email without domain."""
        with pytest.raises(ValidationError, match="Invalid email"):
            validate_email("user@")

    def test_invalid_email_no_tld(self):
        """Test invalid email without TLD."""
        with pytest.raises(ValidationError, match="Invalid email"):
            validate_email("user@example")


# =============================================================================
# IS PRIVATE IP TESTS
# =============================================================================

class TestIsPrivateIp:
    """Tests for is_private_ip function."""

    def test_private_10_network(self):
        """Test 10.x.x.x is private."""
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("10.255.255.255") is True

    def test_private_172_network(self):
        """Test 172.16-31.x.x is private."""
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("172.31.255.255") is True

    def test_private_192_network(self):
        """Test 192.168.x.x is private."""
        assert is_private_ip("192.168.0.1") is True
        assert is_private_ip("192.168.255.255") is True

    def test_public_ip(self):
        """Test public IP is not private."""
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False

    def test_invalid_ip_returns_false(self):
        """Test invalid IP returns False."""
        assert is_private_ip("not-an-ip") is False


# =============================================================================
# IS LOOPBACK TESTS
# =============================================================================

class TestIsLoopback:
    """Tests for is_loopback function."""

    def test_loopback_127_0_0_1(self):
        """Test 127.0.0.1 is loopback."""
        assert is_loopback("127.0.0.1") is True

    def test_loopback_127_network(self):
        """Test 127.x.x.x is loopback."""
        assert is_loopback("127.0.0.2") is True
        assert is_loopback("127.255.255.255") is True

    def test_loopback_ipv6(self):
        """Test ::1 is loopback."""
        assert is_loopback("::1") is True

    def test_not_loopback(self):
        """Test non-loopback is not loopback."""
        assert is_loopback("192.168.1.1") is False
        assert is_loopback("8.8.8.8") is False

    def test_invalid_ip_returns_false(self):
        """Test invalid IP returns False."""
        assert is_loopback("not-an-ip") is False


# =============================================================================
# EXTRACT DOMAIN FROM URL TESTS
# =============================================================================

class TestExtractDomainFromUrl:
    """Tests for extract_domain_from_url function."""

    def test_simple_url(self):
        """Test simple URL."""
        result = extract_domain_from_url("https://example.com")
        assert result == "example.com"

    def test_url_with_path(self):
        """Test URL with path."""
        result = extract_domain_from_url("https://example.com/api/v1")
        assert result == "example.com"

    def test_url_with_port(self):
        """Test URL with port."""
        result = extract_domain_from_url("https://example.com:8443/api")
        assert result == "example.com"

    def test_subdomain(self):
        """Test subdomain extraction."""
        result = extract_domain_from_url("https://api.example.com/v1")
        assert result == "api.example.com"

    def test_normalized_lowercase(self):
        """Test result is lowercase."""
        result = extract_domain_from_url("https://EXAMPLE.COM")
        assert result == "example.com"


# =============================================================================
# EXTRACT BASE DOMAIN TESTS
# =============================================================================

class TestExtractBaseDomain:
    """Tests for extract_base_domain function."""

    def test_simple_domain(self):
        """Test simple domain."""
        result = extract_base_domain("example.com")
        assert result == "example.com"

    def test_subdomain_removed(self):
        """Test subdomain is removed."""
        result = extract_base_domain("api.example.com")
        assert result == "example.com"

    def test_multiple_subdomains_removed(self):
        """Test multiple subdomains removed."""
        result = extract_base_domain("a.b.c.example.com")
        assert result == "example.com"

    def test_co_uk_handled(self):
        """Test .co.uk is handled."""
        result = extract_base_domain("www.example.co.uk")
        assert result == "example.co.uk"

    def test_com_br_handled(self):
        """Test .com.br is handled."""
        result = extract_base_domain("www.example.com.br")
        assert result == "example.com.br"

    def test_normalized_lowercase(self):
        """Test result is lowercase."""
        result = extract_base_domain("WWW.EXAMPLE.COM")
        assert result == "example.com"


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestValidatorsIntegration:
    """Integration tests for validators."""

    def test_validate_various_targets(self):
        """Test validating various target types."""
        # Domain
        assert validate_target("example.com") == "example.com"

        # URL
        assert "https://example.com" in validate_target("https://example.com")

        # IP
        assert validate_target("192.168.1.1") == "192.168.1.1"

        # CIDR
        assert "/24" in validate_target("192.168.1.0/24")

    def test_validation_chain(self):
        """Test validation chain works correctly."""
        url = "https://api.example.com:8443/v1/users"

        # Validate URL
        validated = validate_url(url)
        assert "https://" in validated

        # Extract domain
        domain = extract_domain_from_url(validated)
        assert domain == "api.example.com"

        # Validate domain
        validated_domain = validate_domain(domain)
        assert validated_domain == "api.example.com"

        # Extract base domain
        base = extract_base_domain(validated_domain)
        assert base == "example.com"

    def test_security_validations(self):
        """Test security-related validations."""
        # Control characters blocked
        with pytest.raises(ValidationError):
            validate_target("example\x00.com")

        # Long inputs blocked
        with pytest.raises(ValidationError):
            validate_target("a" * 3000)

        # Invalid schemes blocked
        with pytest.raises(ValidationError):
            validate_url("javascript:alert(1)")

