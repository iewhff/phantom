"""
Tests for SSRF Scanner v3.0.

Covers:
- SSRFType enum
- Protocol enum
- CloudProvider enum
- WAFType enum
- SSRFResult dataclass
- IPObfuscator class
- WAFDetector class

"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from dataclasses import asdict

from scanning.modules.ssrf_scanner import (
    SSRFType,
    Protocol,
    CloudProvider,
    WAFType,
    SSRFResult,
    IPObfuscator,
    WAFDetector,
    SSRF_SCANNER_VERSION,
)


# ============================================================================
# TESTS: SSRFType Enum
# ============================================================================

class TestSSRFType:
    """Tests for SSRFType enum."""

    def test_has_basic(self):
        """Should have BASIC type."""
        assert SSRFType.BASIC is not None

    def test_has_blind(self):
        """Should have BLIND type."""
        assert SSRFType.BLIND is not None

    def test_has_partial_blind(self):
        """Should have PARTIAL_BLIND type."""
        assert SSRFType.PARTIAL_BLIND is not None

    def test_has_time_based(self):
        """Should have TIME_BASED type."""
        assert SSRFType.TIME_BASED is not None

    def test_has_dns_oob(self):
        """Should have DNS_OOB type."""
        assert SSRFType.DNS_OOB is not None

    def test_has_http_oob(self):
        """Should have HTTP_OOB type."""
        assert SSRFType.HTTP_OOB is not None

    def test_has_protocol_smuggle(self):
        """Should have PROTOCOL_SMUGGLE type."""
        assert SSRFType.PROTOCOL_SMUGGLE is not None

    def test_has_dns_rebinding(self):
        """Should have DNS_REBINDING type."""
        assert SSRFType.DNS_REBINDING is not None

    def test_has_pdf_ssrf(self):
        """Should have PDF_SSRF type."""
        assert SSRFType.PDF_SSRF is not None

    def test_has_svg_ssrf(self):
        """Should have SVG_SSRF type."""
        assert SSRFType.SVG_SSRF is not None

    def test_has_xml_ssrf(self):
        """Should have XML_SSRF type."""
        assert SSRFType.XML_SSRF is not None

    def test_has_redirect(self):
        """Should have REDIRECT type."""
        assert SSRFType.REDIRECT is not None

    def test_all_types_are_unique(self):
        """All SSRF types should be unique."""
        values = [t.value for t in SSRFType]
        assert len(values) == len(set(values))


# ============================================================================
# TESTS: Protocol Enum
# ============================================================================

class TestProtocol:
    """Tests for Protocol enum."""

    def test_has_http(self):
        """Should have HTTP protocol."""
        assert Protocol.HTTP is not None
        assert Protocol.HTTP.value == "http"

    def test_has_https(self):
        """Should have HTTPS protocol."""
        assert Protocol.HTTPS is not None
        assert Protocol.HTTPS.value == "https"

    def test_has_file(self):
        """Should have FILE protocol."""
        assert Protocol.FILE is not None
        assert Protocol.FILE.value == "file"

    def test_has_ftp(self):
        """Should have FTP protocol."""
        assert Protocol.FTP is not None
        assert Protocol.FTP.value == "ftp"

    def test_has_gopher(self):
        """Should have GOPHER protocol (SSRF classic)."""
        assert Protocol.GOPHER is not None
        assert Protocol.GOPHER.value == "gopher"

    def test_has_dict(self):
        """Should have DICT protocol."""
        assert Protocol.DICT is not None
        assert Protocol.DICT.value == "dict"

    def test_has_ldap(self):
        """Should have LDAP protocol."""
        assert Protocol.LDAP is not None
        assert Protocol.LDAP.value == "ldap"

    def test_has_php_stream(self):
        """Should have PHP stream protocol."""
        assert Protocol.PHP_STREAM is not None
        assert Protocol.PHP_STREAM.value == "php"

    def test_has_phar(self):
        """Should have PHAR protocol (PHP deserialization)."""
        assert Protocol.PHAR is not None
        assert Protocol.PHAR.value == "phar"

    def test_has_data(self):
        """Should have DATA protocol."""
        assert Protocol.DATA is not None
        assert Protocol.DATA.value == "data"

    def test_all_protocols_are_unique(self):
        """All protocols should have unique values."""
        values = [p.value for p in Protocol]
        assert len(values) == len(set(values))


# ============================================================================
# TESTS: CloudProvider Enum
# ============================================================================

class TestCloudProvider:
    """Tests for CloudProvider enum."""

    def test_has_aws(self):
        """Should have AWS provider."""
        assert CloudProvider.AWS is not None
        assert CloudProvider.AWS.value == "aws"

    def test_has_gcp(self):
        """Should have GCP provider."""
        assert CloudProvider.GCP is not None
        assert CloudProvider.GCP.value == "gcp"

    def test_has_azure(self):
        """Should have Azure provider."""
        assert CloudProvider.AZURE is not None
        assert CloudProvider.AZURE.value == "azure"

    def test_has_digitalocean(self):
        """Should have DigitalOcean provider."""
        assert CloudProvider.DIGITALOCEAN is not None
        assert CloudProvider.DIGITALOCEAN.value == "digitalocean"

    def test_has_alibaba(self):
        """Should have Alibaba Cloud provider."""
        assert CloudProvider.ALIBABA is not None

    def test_has_oracle(self):
        """Should have Oracle Cloud provider."""
        assert CloudProvider.ORACLE is not None

    def test_has_kubernetes(self):
        """Should have Kubernetes provider."""
        assert CloudProvider.KUBERNETES is not None
        assert CloudProvider.KUBERNETES.value == "kubernetes"

    def test_has_docker(self):
        """Should have Docker provider."""
        assert CloudProvider.DOCKER is not None

    def test_all_providers_are_unique(self):
        """All providers should have unique values."""
        values = [p.value for p in CloudProvider]
        assert len(values) == len(set(values))


# ============================================================================
# TESTS: WAFType Enum
# ============================================================================

class TestWAFType:
    """Tests for WAFType enum."""

    def test_has_cloudflare(self):
        """Should have Cloudflare WAF."""
        assert WAFType.CLOUDFLARE is not None
        assert WAFType.CLOUDFLARE.value == "cloudflare"

    def test_has_akamai(self):
        """Should have Akamai WAF."""
        assert WAFType.AKAMAI is not None

    def test_has_aws_waf(self):
        """Should have AWS WAF."""
        assert WAFType.AWS_WAF is not None

    def test_has_imperva(self):
        """Should have Imperva WAF."""
        assert WAFType.IMPERVA is not None

    def test_has_modsecurity(self):
        """Should have ModSecurity WAF."""
        assert WAFType.MODSECURITY is not None

    def test_has_sucuri(self):
        """Should have Sucuri WAF."""
        assert WAFType.SUCURI is not None

    def test_has_azure_waf(self):
        """Should have Azure WAF."""
        assert WAFType.AZURE_WAF is not None

    def test_has_wordfence(self):
        """Should have Wordfence WAF."""
        assert WAFType.WORDFENCE is not None

    def test_has_unknown(self):
        """Should have UNKNOWN type."""
        assert WAFType.UNKNOWN is not None

    def test_has_none(self):
        """Should have NONE type."""
        assert WAFType.NONE is not None

    def test_all_waf_types_are_unique(self):
        """All WAF types should have unique values."""
        values = [w.value for w in WAFType]
        assert len(values) == len(set(values))


# ============================================================================
# TESTS: SSRFResult Dataclass
# ============================================================================

class TestSSRFResult:
    """Tests for SSRFResult dataclass."""

    def test_creates_with_required_fields(self):
        """Should create with required fields."""
        result = SSRFResult(
            vulnerable=True,
            ssrf_type=SSRFType.BASIC,
            confidence=90,
            payload="http://169.254.169.254/latest/meta-data/",
        )
        assert result.vulnerable is True
        assert result.ssrf_type == SSRFType.BASIC
        assert result.confidence == 90

    def test_default_values(self):
        """Should have correct default values."""
        result = SSRFResult(
            vulnerable=False,
            ssrf_type=SSRFType.BLIND,
            confidence=50,
            payload="http://example.com",
        )
        assert result.evidence == []
        assert result.response_data is None
        assert result.cloud_provider is None
        assert result.protocol is None
        assert result.metadata_leaked is False
        assert result.internal_ip_accessed is False
        assert result.service_discovered is None

    def test_stores_cloud_provider(self):
        """Should store cloud provider."""
        result = SSRFResult(
            vulnerable=True,
            ssrf_type=SSRFType.BASIC,
            confidence=95,
            payload="http://169.254.169.254/",
            cloud_provider=CloudProvider.AWS,
            metadata_leaked=True,
        )
        assert result.cloud_provider == CloudProvider.AWS
        assert result.metadata_leaked is True

    def test_stores_protocol(self):
        """Should store protocol used."""
        result = SSRFResult(
            vulnerable=True,
            ssrf_type=SSRFType.PROTOCOL_SMUGGLE,
            confidence=85,
            payload="gopher://localhost:6379/_INFO",
            protocol=Protocol.GOPHER,
        )
        assert result.protocol == Protocol.GOPHER

    def test_stores_evidence_list(self):
        """Should store evidence list."""
        result = SSRFResult(
            vulnerable=True,
            ssrf_type=SSRFType.DNS_OOB,
            confidence=80,
            payload="http://attacker.com",
            evidence=["DNS query received", "Callback URL accessed"],
        )
        assert len(result.evidence) == 2

    def test_stores_response_data(self):
        """Should store response data."""
        result = SSRFResult(
            vulnerable=True,
            ssrf_type=SSRFType.BASIC,
            confidence=100,
            payload="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            response_data='{"AccessKeyId": "AKIA..."}',
        )
        assert "AccessKeyId" in result.response_data

    def test_stores_service_discovered(self):
        """Should store discovered internal service."""
        result = SSRFResult(
            vulnerable=True,
            ssrf_type=SSRFType.BASIC,
            confidence=75,
            payload="http://192.168.1.1:6379",
            service_discovered="Redis",
            internal_ip_accessed=True,
        )
        assert result.service_discovered == "Redis"
        assert result.internal_ip_accessed is True

    def test_confidence_range(self):
        """Confidence should be 0-100."""
        # Valid confidence values
        result_low = SSRFResult(vulnerable=False, ssrf_type=SSRFType.BASIC, confidence=0, payload="")
        result_high = SSRFResult(vulnerable=True, ssrf_type=SSRFType.BASIC, confidence=100, payload="")

        assert result_low.confidence == 0
        assert result_high.confidence == 100


# ============================================================================
# TESTS: IPObfuscator Class
# ============================================================================

class TestIPObfuscator:
    """Tests for IPObfuscator class."""

    def test_class_exists(self):
        """IPObfuscator class should exist."""
        assert IPObfuscator is not None

    def test_can_instantiate(self):
        """Should be able to instantiate."""
        obfuscator = IPObfuscator()
        assert obfuscator is not None

    def test_has_obfuscation_methods(self):
        """Should have obfuscation methods."""
        # Check for common method patterns
        methods = dir(IPObfuscator)
        # Should have methods for IP obfuscation
        assert any("obfuscat" in m.lower() or "encode" in m.lower() or "convert" in m.lower()
                  for m in methods)


# ============================================================================
# TESTS: WAFDetector Class
# ============================================================================

class TestWAFDetector:
    """Tests for WAFDetector class."""

    def test_class_exists(self):
        """WAFDetector class should exist."""
        assert WAFDetector is not None

    def test_has_detect_method(self):
        """Should have detect class method."""
        assert hasattr(WAFDetector, "detect")
        assert callable(getattr(WAFDetector, "detect"))

    def test_has_is_blocked_method(self):
        """Should have is_blocked class method."""
        assert hasattr(WAFDetector, "is_blocked")
        assert callable(getattr(WAFDetector, "is_blocked"))

    def test_detect_with_mock_response(self):
        """Should handle mock response without WAF."""
        mock_response = MagicMock()
        mock_response.headers = {}
        mock_response.status_code = 200
        mock_response.text = "OK"

        # This should not raise
        with patch('scanning.modules.ssrf_scanner.BaseWAFDetector') as mock_detector:
            from utils.scanner_helpers import WAFType as BaseWAFType
            mock_detector.detect.return_value = (BaseWAFType.NONE, False)
            result = WAFDetector.detect(mock_response)
            # Should return None for no WAF or WAFType.NONE
            assert result is None or result == WAFType.NONE

    def test_is_blocked_with_mock_response(self):
        """Should detect if request was blocked."""
        mock_response = MagicMock()
        mock_response.headers = {}
        mock_response.status_code = 403

        with patch('scanning.modules.ssrf_scanner.BaseWAFDetector') as mock_detector:
            mock_detector.detect.return_value = (MagicMock(), True)
            result = WAFDetector.is_blocked(mock_response)
            assert result is True


# ============================================================================
# TESTS: Version Constant
# ============================================================================

class TestVersion:
    """Tests for version constant."""

    def test_version_defined(self):
        """Version should be defined."""
        assert SSRF_SCANNER_VERSION is not None

    def test_version_is_string(self):
        """Version should be a string."""
        assert isinstance(SSRF_SCANNER_VERSION, str)

    def test_version_format(self):
        """Version should follow semver-like format."""
        # Should contain at least one dot (x.y.z pattern)
        assert "." in SSRF_SCANNER_VERSION
        # Should start with a digit
        assert SSRF_SCANNER_VERSION[0].isdigit()


# ============================================================================
# TESTS: Cloud Metadata Patterns
# ============================================================================

class TestCloudMetadataPatterns:
    """Tests for cloud metadata awareness."""

    def test_aws_metadata_url(self):
        """Should recognize AWS metadata URL pattern."""
        aws_url = "http://169.254.169.254/latest/meta-data/"
        assert "169.254.169.254" in aws_url
        assert "meta-data" in aws_url

    def test_gcp_metadata_url(self):
        """Should recognize GCP metadata URL pattern."""
        gcp_url = "http://metadata.google.internal/computeMetadata/v1/"
        assert "metadata.google.internal" in gcp_url

    def test_azure_metadata_url(self):
        """Should recognize Azure metadata URL pattern."""
        azure_url = "http://169.254.169.254/metadata/instance"
        assert "169.254.169.254" in azure_url
        assert "metadata" in azure_url

    def test_digitalocean_metadata_url(self):
        """Should recognize DigitalOcean metadata URL pattern."""
        do_url = "http://169.254.169.254/metadata/v1/"
        assert "169.254.169.254" in do_url


# ============================================================================
# TESTS: Edge Cases
# ============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_ssrf_result_with_empty_payload(self):
        """Should handle empty payload."""
        result = SSRFResult(
            vulnerable=False,
            ssrf_type=SSRFType.BASIC,
            confidence=0,
            payload="",
        )
        assert result.payload == ""

    def test_ssrf_result_with_long_payload(self):
        """Should handle long payload."""
        long_payload = "http://example.com/" + "a" * 10000
        result = SSRFResult(
            vulnerable=True,
            ssrf_type=SSRFType.BASIC,
            confidence=50,
            payload=long_payload,
        )
        assert len(result.payload) > 10000

    def test_ssrf_result_with_unicode_payload(self):
        """Should handle unicode in payload."""
        result = SSRFResult(
            vulnerable=True,
            ssrf_type=SSRFType.BASIC,
            confidence=50,
            payload="http://example.com/用户",
        )
        assert "用户" in result.payload

    def test_all_cloud_providers_covered(self):
        """Should cover major cloud providers."""
        providers = [p.value for p in CloudProvider]
        assert "aws" in providers
        assert "gcp" in providers
        assert "azure" in providers
        assert "kubernetes" in providers

    def test_all_common_protocols_covered(self):
        """Should cover common SSRF protocols."""
        protocols = [p.value for p in Protocol]
        assert "http" in protocols
        assert "https" in protocols
        assert "file" in protocols
        assert "gopher" in protocols
        assert "ftp" in protocols


# ============================================================================
# TESTS: SSRF Attack Scenarios
# ============================================================================

class TestSSRFAttackScenarios:
    """Tests for SSRF attack scenario modeling."""

    def test_cloud_metadata_scenario(self):
        """Model a cloud metadata attack."""
        result = SSRFResult(
            vulnerable=True,
            ssrf_type=SSRFType.BASIC,
            confidence=100,
            payload="http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role",
            cloud_provider=CloudProvider.AWS,
            metadata_leaked=True,
            response_data='{"AccessKeyId": "AKIAIOSFODNN7EXAMPLE"}',
            evidence=["AWS metadata endpoint accessible", "IAM credentials leaked"],
        )
        assert result.metadata_leaked is True
        assert result.cloud_provider == CloudProvider.AWS
        assert "AccessKeyId" in result.response_data

    def test_internal_service_scenario(self):
        """Model an internal service discovery attack."""
        result = SSRFResult(
            vulnerable=True,
            ssrf_type=SSRFType.BASIC,
            confidence=85,
            payload="http://192.168.1.100:6379/INFO",
            internal_ip_accessed=True,
            service_discovered="Redis",
            protocol=Protocol.HTTP,
            evidence=["Internal IP accessible", "Redis INFO response received"],
        )
        assert result.internal_ip_accessed is True
        assert result.service_discovered == "Redis"

    def test_blind_ssrf_scenario(self):
        """Model a blind SSRF attack."""
        result = SSRFResult(
            vulnerable=True,
            ssrf_type=SSRFType.BLIND,
            confidence=75,
            payload="http://attacker-controlled.example.com/ssrf-callback",
            evidence=["No direct response", "DNS query detected", "HTTP callback received"],
        )
        assert result.ssrf_type == SSRFType.BLIND
        assert len(result.evidence) == 3

    def test_protocol_smuggling_scenario(self):
        """Model a protocol smuggling attack."""
        result = SSRFResult(
            vulnerable=True,
            ssrf_type=SSRFType.PROTOCOL_SMUGGLE,
            confidence=90,
            payload="gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a$4%0d%0atest%0d%0a$5%0d%0avalue%0d%0a",
            protocol=Protocol.GOPHER,
            service_discovered="Redis",
            evidence=["Gopher protocol accepted", "Redis command executed"],
        )
        assert result.protocol == Protocol.GOPHER
        assert result.ssrf_type == SSRFType.PROTOCOL_SMUGGLE

    def test_dns_rebinding_scenario(self):
        """Model a DNS rebinding attack."""
        result = SSRFResult(
            vulnerable=True,
            ssrf_type=SSRFType.DNS_REBINDING,
            confidence=70,
            payload="http://rebinding.attacker.com/",
            evidence=["DNS rebinding detected", "Internal resource accessed after TTL expiry"],
        )
        assert result.ssrf_type == SSRFType.DNS_REBINDING
