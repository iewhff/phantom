"""
Tests for XXE (XML External Entity) Scanner Module.

Covers:
- XXEType enum (11 attack types)
- XMLParser enum (7 parser types)
- ContentFormat enum (10 format types)
- WAFType enum (12 WAF types)
- XXEFinding dataclass
- WAFDetector class
- PayloadEncoder class
- XXEScanner constants (endpoints, payloads, indicators)
"""

import pytest
from dataclasses import fields
from unittest.mock import MagicMock, patch

from scanning.modules.xxe_scanner import (
    XXEType,
    XMLParser,
    ContentFormat,
    WAFType,
    XXEFinding,
    WAFDetector,
    PayloadEncoder,
    XXEScanner,
)


# ============================================================================
# TESTS: XXEType Enum
# ============================================================================

class TestXXEType:
    """Tests for XXEType enum."""

    def test_has_classic(self):
        """Should have CLASSIC XXE type."""
        assert XXEType.CLASSIC is not None

    def test_has_blind(self):
        """Should have BLIND XXE type."""
        assert XXEType.BLIND is not None

    def test_has_error_based(self):
        """Should have ERROR_BASED XXE type."""
        assert XXEType.ERROR_BASED is not None

    def test_has_oob_http(self):
        """Should have OOB_HTTP type."""
        assert XXEType.OOB_HTTP is not None

    def test_has_oob_dns(self):
        """Should have OOB_DNS type."""
        assert XXEType.OOB_DNS is not None

    def test_has_oob_ftp(self):
        """Should have OOB_FTP type."""
        assert XXEType.OOB_FTP is not None

    def test_has_parameter_entity(self):
        """Should have PARAMETER_ENTITY type."""
        assert XXEType.PARAMETER_ENTITY is not None

    def test_has_ssrf(self):
        """Should have SSRF type."""
        assert XXEType.SSRF is not None

    def test_has_dos(self):
        """Should have DOS type."""
        assert XXEType.DOS is not None

    def test_has_rce(self):
        """Should have RCE type."""
        assert XXEType.RCE is not None

    def test_has_xinclude(self):
        """Should have XINCLUDE type (DTD bypass)."""
        assert XXEType.XINCLUDE is not None

    def test_all_types_unique(self):
        """All XXE types should be unique."""
        types = [t.value for t in XXEType]
        assert len(types) == len(set(types))

    def test_total_count(self):
        """Should have 11 XXE types."""
        assert len(XXEType) == 11


# ============================================================================
# TESTS: XMLParser Enum
# ============================================================================

class TestXMLParser:
    """Tests for XMLParser enum."""

    def test_has_unknown(self):
        """Should have UNKNOWN parser."""
        assert XMLParser.UNKNOWN is not None

    def test_has_libxml2(self):
        """Should have LIBXML2 (PHP/Python lxml)."""
        assert XMLParser.LIBXML2 is not None

    def test_has_expat(self):
        """Should have EXPAT (Python xml.etree)."""
        assert XMLParser.EXPAT is not None

    def test_has_xerces(self):
        """Should have XERCES (Java)."""
        assert XMLParser.XERCES is not None

    def test_has_msxml(self):
        """Should have MSXML (.NET)."""
        assert XMLParser.MSXML is not None

    def test_has_saxon(self):
        """Should have SAXON (XSLT processor)."""
        assert XMLParser.SAXON is not None

    def test_has_libxmljs(self):
        """Should have LIBXMLJS (Node.js)."""
        assert XMLParser.LIBXMLJS is not None

    def test_total_count(self):
        """Should have 7 parser types."""
        assert len(XMLParser) == 7


# ============================================================================
# TESTS: ContentFormat Enum
# ============================================================================

class TestContentFormat:
    """Tests for ContentFormat enum."""

    def test_has_xml(self):
        """Should have XML format."""
        assert ContentFormat.XML is not None

    def test_has_soap(self):
        """Should have SOAP format."""
        assert ContentFormat.SOAP is not None

    def test_has_svg(self):
        """Should have SVG format."""
        assert ContentFormat.SVG is not None

    def test_has_rss(self):
        """Should have RSS format."""
        assert ContentFormat.RSS is not None

    def test_has_atom(self):
        """Should have ATOM format."""
        assert ContentFormat.ATOM is not None

    def test_has_saml(self):
        """Should have SAML format."""
        assert ContentFormat.SAML is not None

    def test_has_xhtml(self):
        """Should have XHTML format."""
        assert ContentFormat.XHTML is not None

    def test_has_docx(self):
        """Should have DOCX format."""
        assert ContentFormat.DOCX is not None

    def test_has_xlsx(self):
        """Should have XLSX format."""
        assert ContentFormat.XLSX is not None

    def test_has_pptx(self):
        """Should have PPTX format."""
        assert ContentFormat.PPTX is not None

    def test_total_count(self):
        """Should have 10 content formats."""
        assert len(ContentFormat) == 10


# ============================================================================
# TESTS: WAFType Enum
# ============================================================================

class TestWAFType:
    """Tests for WAFType enum."""

    def test_has_none(self):
        """Should have NONE (no WAF)."""
        assert WAFType.NONE is not None

    def test_has_cloudflare(self):
        """Should have CLOUDFLARE."""
        assert WAFType.CLOUDFLARE is not None

    def test_has_akamai(self):
        """Should have AKAMAI."""
        assert WAFType.AKAMAI is not None

    def test_has_aws_waf(self):
        """Should have AWS_WAF."""
        assert WAFType.AWS_WAF is not None

    def test_has_imperva(self):
        """Should have IMPERVA."""
        assert WAFType.IMPERVA is not None

    def test_has_f5_bigip(self):
        """Should have F5_BIG_IP."""
        assert WAFType.F5_BIG_IP is not None

    def test_has_modsecurity(self):
        """Should have MODSECURITY."""
        assert WAFType.MODSECURITY is not None

    def test_has_sucuri(self):
        """Should have SUCURI."""
        assert WAFType.SUCURI is not None

    def test_has_fortinet(self):
        """Should have FORTINET."""
        assert WAFType.FORTINET is not None

    def test_has_barracuda(self):
        """Should have BARRACUDA."""
        assert WAFType.BARRACUDA is not None

    def test_has_azure_waf(self):
        """Should have AZURE_WAF."""
        assert WAFType.AZURE_WAF is not None

    def test_has_wordfence(self):
        """Should have WORDFENCE."""
        assert WAFType.WORDFENCE is not None

    def test_total_count(self):
        """Should have 13 WAF types."""
        assert len(WAFType) == 13


# ============================================================================
# TESTS: XXEFinding Dataclass
# ============================================================================

class TestXXEFinding:
    """Tests for XXEFinding dataclass."""

    def test_creates_finding(self):
        """Should create XXE finding."""
        finding = XXEFinding(
            url="https://example.com/api/xml",
            xxe_type=XXEType.CLASSIC,
            payload='<!ENTITY xxe SYSTEM "file:///etc/passwd">',
            protocol="file://",
            parser=XMLParser.LIBXML2,
            content_format=ContentFormat.XML,
            detection_method="direct_response",
            evidence=["root:x:0:0"],
            confidence=95,
        )
        assert finding.url == "https://example.com/api/xml"
        assert finding.xxe_type == XXEType.CLASSIC
        assert finding.confidence == 95

    def test_has_required_fields(self):
        """Should have required fields."""
        field_names = {f.name for f in fields(XXEFinding)}
        assert "url" in field_names
        assert "xxe_type" in field_names
        assert "payload" in field_names
        assert "protocol" in field_names
        assert "parser" in field_names
        assert "content_format" in field_names
        assert "detection_method" in field_names
        assert "evidence" in field_names
        assert "confidence" in field_names

    def test_has_optional_fields(self):
        """Should have optional fields."""
        field_names = {f.name for f in fields(XXEFinding)}
        assert "file_disclosed" in field_names
        assert "waf_detected" in field_names
        assert "waf_bypassed" in field_names
        assert "file_content" in field_names

    def test_stores_file_content(self):
        """Should store disclosed file content."""
        finding = XXEFinding(
            url="https://example.com/api",
            xxe_type=XXEType.CLASSIC,
            payload="test",
            protocol="file://",
            parser=XMLParser.UNKNOWN,
            content_format=ContentFormat.XML,
            detection_method="direct",
            evidence=["root:x:0:0"],
            confidence=95,
            file_disclosed="/etc/passwd",
            file_content="root:x:0:0:root:/root:/bin/bash\n",
        )
        assert "/etc/passwd" in finding.file_disclosed
        assert "root:x:0:0" in finding.file_content

    def test_stores_waf_info(self):
        """Should store WAF detection info."""
        finding = XXEFinding(
            url="https://example.com/api",
            xxe_type=XXEType.CLASSIC,
            payload="test",
            protocol="file://",
            parser=XMLParser.UNKNOWN,
            content_format=ContentFormat.XML,
            detection_method="direct",
            evidence=[],
            confidence=85,
            waf_detected=WAFType.CLOUDFLARE,
            waf_bypassed=True,
        )
        assert finding.waf_detected == WAFType.CLOUDFLARE
        assert finding.waf_bypassed is True

    def test_stores_parser_type(self):
        """Should store detected parser type."""
        finding = XXEFinding(
            url="https://example.com/api",
            xxe_type=XXEType.CLASSIC,
            payload="test",
            protocol="file://",
            parser=XMLParser.XERCES,
            content_format=ContentFormat.SOAP,
            detection_method="direct",
            evidence=[],
            confidence=90,
        )
        assert finding.parser == XMLParser.XERCES
        assert finding.content_format == ContentFormat.SOAP


# ============================================================================
# TESTS: PayloadEncoder
# ============================================================================

class TestPayloadEncoder:
    """Tests for PayloadEncoder class."""

    def test_utf7_encode(self):
        """Should add UTF-7 encoding declaration."""
        payload = '<?xml version="1.0"?><root>test</root>'
        encoded = PayloadEncoder.utf7_encode(payload)
        assert 'encoding="UTF-7"' in encoded

    def test_utf16_encode(self):
        """Should add UTF-16 encoding declaration."""
        payload = '<?xml version="1.0"?><root>test</root>'
        encoded = PayloadEncoder.utf16_encode(payload)
        assert 'encoding="UTF-16"' in encoded

    def test_entity_encode(self):
        """Should entity encode alphabetic characters."""
        text = "file"
        encoded = PayloadEncoder.entity_encode(text)
        assert "&#x" in encoded
        assert "f" not in encoded  # 'f' should be encoded

    def test_hex_encode_file(self):
        """Should hex encode file path."""
        filepath = "/etc/passwd"
        encoded = PayloadEncoder.hex_encode_file(filepath)
        assert "&#x" in encoded
        # Original characters should be encoded
        assert "/" not in encoded or "&#x2f;" in encoded

    def test_cdata_wrap(self):
        """Should wrap content in CDATA."""
        content = "<malicious/>"
        wrapped = PayloadEncoder.cdata_wrap(content)
        assert "<![CDATA[" in wrapped
        assert "]]>" in wrapped
        assert "<malicious/>" in wrapped

    def test_parameter_entity_split_short_name(self):
        """Should not split very short entity names."""
        name = "ab"
        result = PayloadEncoder.parameter_entity_split(name)
        assert result == "ab"

    def test_parameter_entity_split_long_name(self):
        """Should split longer entity names with CDATA."""
        name = "entityname"
        result = PayloadEncoder.parameter_entity_split(name)
        assert "]]><![CDATA[" in result


# ============================================================================
# TESTS: WAFDetector
# ============================================================================

class TestWAFDetector:
    """Tests for WAFDetector class."""

    def test_detect_returns_none_for_no_waf(self):
        """detect should return None when no WAF detected."""
        mock_response = MagicMock()
        mock_response.headers = {}
        mock_response.status_code = 200
        mock_response.text = "OK"

        with patch("scanning.modules.xxe_scanner.BaseWAFDetector.detect") as mock_detect:
            from utils.scanner_helpers import WAFType as BaseWAFType
            mock_detect.return_value = (BaseWAFType.NONE, False)
            result = WAFDetector.detect(mock_response)
            assert result is None

    def test_detect_cloudflare(self):
        """Should detect Cloudflare WAF."""
        mock_response = MagicMock()
        mock_response.headers = {"cf-ray": "abc123"}
        mock_response.status_code = 403

        with patch("scanning.modules.xxe_scanner.BaseWAFDetector.detect") as mock_detect:
            from utils.scanner_helpers import WAFType as BaseWAFType
            mock_detect.return_value = (BaseWAFType.CLOUDFLARE, True)
            result = WAFDetector.detect(mock_response)
            assert result == WAFType.CLOUDFLARE

    def test_is_blocked_returns_bool(self):
        """is_blocked should return boolean."""
        mock_response = MagicMock()
        mock_response.headers = {}
        mock_response.status_code = 200

        with patch("scanning.modules.xxe_scanner.BaseWAFDetector.detect") as mock_detect:
            from utils.scanner_helpers import WAFType as BaseWAFType
            mock_detect.return_value = (BaseWAFType.NONE, False)
            result = WAFDetector.is_blocked(mock_response)
            assert result is False

    def test_is_blocked_when_waf_blocks(self):
        """Should return True when WAF blocks."""
        mock_response = MagicMock()
        mock_response.status_code = 403

        with patch("scanning.modules.xxe_scanner.BaseWAFDetector.detect") as mock_detect:
            from utils.scanner_helpers import WAFType as BaseWAFType
            mock_detect.return_value = (BaseWAFType.MODSECURITY, True)
            result = WAFDetector.is_blocked(mock_response)
            assert result is True


# ============================================================================
# TESTS: XXEScanner Constants - XML Endpoints
# ============================================================================

class TestXXEScannerXMLEndpoints:
    """Tests for XML endpoint constants."""

    def test_has_api_endpoints(self):
        """Should have API XML endpoints."""
        assert "/api/xml" in XXEScanner.XML_ENDPOINTS
        assert any("/api/" in e for e in XXEScanner.XML_ENDPOINTS)

    def test_has_soap_endpoints(self):
        """Should have SOAP endpoints."""
        assert any("soap" in e.lower() for e in XXEScanner.XML_ENDPOINTS)

    def test_has_wsdl_endpoints(self):
        """Should have WSDL endpoints."""
        assert any("wsdl" in e.lower() for e in XXEScanner.XML_ENDPOINTS)

    def test_has_rss_endpoints(self):
        """Should have RSS/feed endpoints."""
        assert any("rss" in e.lower() or "feed" in e.lower() for e in XXEScanner.XML_ENDPOINTS)

    def test_has_saml_endpoints(self):
        """Should have SAML authentication endpoints."""
        assert any("saml" in e.lower() for e in XXEScanner.XML_ENDPOINTS)

    def test_has_import_endpoints(self):
        """Should have import/upload endpoints."""
        assert any("import" in e.lower() for e in XXEScanner.XML_ENDPOINTS)
        assert any("upload" in e.lower() for e in XXEScanner.XML_ENDPOINTS)

    def test_has_svg_endpoint(self):
        """Should have SVG endpoint."""
        assert any("svg" in e.lower() for e in XXEScanner.XML_ENDPOINTS)

    def test_no_empty_endpoints(self):
        """Should not have empty endpoints."""
        assert "" not in XXEScanner.XML_ENDPOINTS

    def test_all_start_with_slash(self):
        """All endpoints should start with /."""
        assert all(e.startswith("/") for e in XXEScanner.XML_ENDPOINTS)


# ============================================================================
# TESTS: XXEScanner Constants - Content Types
# ============================================================================

class TestXXEScannerContentTypes:
    """Tests for content type constants."""

    def test_has_xml_content_types(self):
        """Should have XML content types."""
        assert ContentFormat.XML in XXEScanner.CONTENT_TYPES
        xml_types = XXEScanner.CONTENT_TYPES[ContentFormat.XML]
        assert "application/xml" in xml_types

    def test_has_soap_content_types(self):
        """Should have SOAP content types."""
        assert ContentFormat.SOAP in XXEScanner.CONTENT_TYPES
        soap_types = XXEScanner.CONTENT_TYPES[ContentFormat.SOAP]
        assert any("xml" in t for t in soap_types)

    def test_has_svg_content_type(self):
        """Should have SVG content type."""
        assert ContentFormat.SVG in XXEScanner.CONTENT_TYPES
        svg_types = XXEScanner.CONTENT_TYPES[ContentFormat.SVG]
        assert "image/svg+xml" in svg_types

    def test_has_saml_content_types(self):
        """Should have SAML content types."""
        assert ContentFormat.SAML in XXEScanner.CONTENT_TYPES


# ============================================================================
# TESTS: XXEScanner Constants - Classic Payloads
# ============================================================================

class TestXXEScannerClassicPayloads:
    """Tests for classic XXE payloads."""

    def test_has_linux_passwd_payload(self):
        """Should have Linux /etc/passwd payload."""
        assert "linux_passwd" in XXEScanner.CLASSIC_PAYLOADS
        payload = XXEScanner.CLASSIC_PAYLOADS["linux_passwd"]
        assert "file:///etc/passwd" in payload
        assert "<!ENTITY" in payload

    def test_has_linux_shadow_payload(self):
        """Should have Linux /etc/shadow payload."""
        assert "linux_shadow" in XXEScanner.CLASSIC_PAYLOADS
        payload = XXEScanner.CLASSIC_PAYLOADS["linux_shadow"]
        assert "file:///etc/shadow" in payload

    def test_has_windows_hosts_payload(self):
        """Should have Windows hosts payload."""
        assert "windows_hosts" in XXEScanner.CLASSIC_PAYLOADS
        payload = XXEScanner.CLASSIC_PAYLOADS["windows_hosts"]
        assert "hosts" in payload.lower()

    def test_has_windows_ini_payload(self):
        """Should have Windows win.ini payload."""
        assert "windows_ini" in XXEScanner.CLASSIC_PAYLOADS
        payload = XXEScanner.CLASSIC_PAYLOADS["windows_ini"]
        assert "win.ini" in payload.lower()

    def test_has_web_config_payload(self):
        """Should have web config payload."""
        assert "web_config" in XXEScanner.CLASSIC_PAYLOADS

    def test_has_env_file_payload(self):
        """Should have .env file payload."""
        assert "env_file" in XXEScanner.CLASSIC_PAYLOADS
        payload = XXEScanner.CLASSIC_PAYLOADS["env_file"]
        assert ".env" in payload

    def test_all_payloads_valid_xml(self):
        """All payloads should contain XML declaration."""
        for name, payload in XXEScanner.CLASSIC_PAYLOADS.items():
            assert "<?xml" in payload, f"{name} missing XML declaration"

    def test_all_payloads_have_entity(self):
        """All classic payloads should define entities."""
        for name, payload in XXEScanner.CLASSIC_PAYLOADS.items():
            assert "<!ENTITY" in payload, f"{name} missing entity declaration"


# ============================================================================
# TESTS: XXEScanner Constants - PHP Payloads
# ============================================================================

class TestXXEScannerPHPPayloads:
    """Tests for PHP wrapper XXE payloads."""

    def test_has_php_filter_payloads(self):
        """Should have php://filter payloads."""
        assert "php_filter_base64" in XXEScanner.PHP_PAYLOADS
        payload = XXEScanner.PHP_PAYLOADS["php_filter_base64"]
        assert "php://filter" in payload
        assert "base64" in payload

    def test_has_php_expect_payloads(self):
        """Should have expect:// RCE payloads."""
        assert "php_expect_id" in XXEScanner.PHP_PAYLOADS
        payload = XXEScanner.PHP_PAYLOADS["php_expect_id"]
        assert "expect://" in payload

    def test_has_php_data_payloads(self):
        """Should have data:// payloads."""
        assert "php_data_base64" in XXEScanner.PHP_PAYLOADS
        payload = XXEScanner.PHP_PAYLOADS["php_data_base64"]
        assert "data://" in payload

    def test_php_filter_targets_config(self):
        """PHP filter should target config files."""
        assert "php_filter_config" in XXEScanner.PHP_PAYLOADS
        payload = XXEScanner.PHP_PAYLOADS["php_filter_config"]
        assert "config.php" in payload

    def test_php_filter_targets_wp_config(self):
        """PHP filter should target WordPress config."""
        assert "php_filter_wp_config" in XXEScanner.PHP_PAYLOADS
        payload = XXEScanner.PHP_PAYLOADS["php_filter_wp_config"]
        assert "wp-config.php" in payload


# ============================================================================
# TESTS: XXEScanner Constants - SSRF Payloads
# ============================================================================

class TestXXEScannerSSRFPayloads:
    """Tests for SSRF XXE payloads."""

    def test_has_aws_metadata_payload(self):
        """Should have AWS metadata payload."""
        assert "aws_metadata" in XXEScanner.SSRF_PAYLOADS
        payload = XXEScanner.SSRF_PAYLOADS["aws_metadata"]
        assert "169.254.169.254" in payload

    def test_has_aws_credentials_payload(self):
        """Should have AWS credentials payload."""
        assert "aws_credentials" in XXEScanner.SSRF_PAYLOADS
        payload = XXEScanner.SSRF_PAYLOADS["aws_credentials"]
        assert "security-credentials" in payload

    def test_has_gcp_metadata_payload(self):
        """Should have GCP metadata payload."""
        assert "gcp_metadata" in XXEScanner.SSRF_PAYLOADS
        payload = XXEScanner.SSRF_PAYLOADS["gcp_metadata"]
        assert "metadata.google.internal" in payload

    def test_has_azure_metadata_payload(self):
        """Should have Azure metadata payload."""
        assert "azure_metadata" in XXEScanner.SSRF_PAYLOADS
        payload = XXEScanner.SSRF_PAYLOADS["azure_metadata"]
        assert "169.254.169.254" in payload

    def test_has_localhost_probe(self):
        """Should have localhost probe payload."""
        assert "localhost_probe" in XXEScanner.SSRF_PAYLOADS
        payload = XXEScanner.SSRF_PAYLOADS["localhost_probe"]
        assert "127.0.0.1" in payload

    def test_has_internal_scan_payload(self):
        """Should have internal network scan payload."""
        assert "internal_scan" in XXEScanner.SSRF_PAYLOADS
        payload = XXEScanner.SSRF_PAYLOADS["internal_scan"]
        assert "192.168" in payload


# ============================================================================
# TESTS: XXEScanner Constants - Parameter Entity Payloads
# ============================================================================

class TestXXEScannerParameterEntityPayloads:
    """Tests for parameter entity XXE payloads."""

    def test_has_basic_param_entity(self):
        """Should have basic parameter entity payload."""
        assert "param_basic" in XXEScanner.PARAMETER_ENTITY_PAYLOADS
        payload = XXEScanner.PARAMETER_ENTITY_PAYLOADS["param_basic"]
        assert "<!ENTITY %" in payload

    def test_has_external_dtd_param(self):
        """Should have external DTD parameter entity."""
        assert "param_external_dtd" in XXEScanner.PARAMETER_ENTITY_PAYLOADS
        payload = XXEScanner.PARAMETER_ENTITY_PAYLOADS["param_external_dtd"]
        assert "CALLBACK_HOST" in payload

    def test_has_nested_param_entities(self):
        """Should have nested parameter entities."""
        assert "param_nested" in XXEScanner.PARAMETER_ENTITY_PAYLOADS


# ============================================================================
# TESTS: XXEScanner Constants - OOB Payloads
# ============================================================================

class TestXXEScannerOOBPayloads:
    """Tests for Out-of-Band XXE payloads."""

    def test_has_oob_http(self):
        """Should have HTTP OOB payload."""
        assert "oob_http" in XXEScanner.OOB_PAYLOADS
        payload = XXEScanner.OOB_PAYLOADS["oob_http"]
        assert "CALLBACK_HOST" in payload

    def test_has_oob_dns(self):
        """Should have DNS OOB payload."""
        assert "oob_dns" in XXEScanner.OOB_PAYLOADS
        payload = XXEScanner.OOB_PAYLOADS["oob_dns"]
        assert "TOKEN" in payload

    def test_has_oob_ftp(self):
        """Should have FTP OOB payload."""
        assert "oob_ftp" in XXEScanner.OOB_PAYLOADS
        payload = XXEScanner.OOB_PAYLOADS["oob_ftp"]
        assert "ftp://" in payload

    def test_has_oob_gopher(self):
        """Should have Gopher OOB payload."""
        assert "oob_gopher" in XXEScanner.OOB_PAYLOADS
        payload = XXEScanner.OOB_PAYLOADS["oob_gopher"]
        assert "gopher://" in payload


# ============================================================================
# TESTS: XXEScanner Constants - Error Payloads
# ============================================================================

class TestXXEScannerErrorPayloads:
    """Tests for error-based XXE payloads."""

    def test_has_file_not_found_error(self):
        """Should have file not found error payload."""
        assert "error_file_not_found" in XXEScanner.ERROR_PAYLOADS
        payload = XXEScanner.ERROR_PAYLOADS["error_file_not_found"]
        assert "nonexistent" in payload

    def test_has_invalid_uri_error(self):
        """Should have invalid URI error payload."""
        assert "error_invalid_uri" in XXEScanner.ERROR_PAYLOADS


# ============================================================================
# TESTS: XXEScanner Constants - DoS Payloads
# ============================================================================

class TestXXEScannerDoSPayloads:
    """Tests for DoS XXE payloads."""

    def test_has_billion_laughs(self):
        """Should have Billion Laughs payload."""
        assert "billion_laughs" in XXEScanner.DOS_PAYLOADS
        payload = XXEScanner.DOS_PAYLOADS["billion_laughs"]
        assert "lol" in payload
        # Should have nested entities
        assert "&lol2;" in payload or "lol2" in payload

    def test_has_quadratic_blowup(self):
        """Should have quadratic blowup payload."""
        assert "quadratic_blowup" in XXEScanner.DOS_PAYLOADS
        payload = XXEScanner.DOS_PAYLOADS["quadratic_blowup"]
        assert "&a;" in payload

    def test_has_external_dtd_dos(self):
        """Should have external DTD DoS payload."""
        assert "external_dtd_dos" in XXEScanner.DOS_PAYLOADS


# ============================================================================
# TESTS: XXEScanner Constants - SOAP Payloads
# ============================================================================

class TestXXEScannerSOAPPayloads:
    """Tests for SOAP XXE payloads."""

    def test_has_soap_xxe(self):
        """Should have SOAP 1.1 XXE payload."""
        assert "soap_xxe" in XXEScanner.SOAP_PAYLOADS
        payload = XXEScanner.SOAP_PAYLOADS["soap_xxe"]
        assert "soap:Envelope" in payload
        assert "xmlsoap.org" in payload

    def test_has_soap12_xxe(self):
        """Should have SOAP 1.2 XXE payload."""
        assert "soap12_xxe" in XXEScanner.SOAP_PAYLOADS
        payload = XXEScanner.SOAP_PAYLOADS["soap12_xxe"]
        assert "w3.org/2003/05/soap-envelope" in payload


# ============================================================================
# TESTS: XXEScanner Constants - SVG Payloads
# ============================================================================

class TestXXEScannerSVGPayloads:
    """Tests for SVG XXE payloads."""

    def test_has_svg_xxe(self):
        """Should have SVG XXE payload."""
        assert "svg_xxe" in XXEScanner.SVG_PAYLOADS
        payload = XXEScanner.SVG_PAYLOADS["svg_xxe"]
        assert "<svg" in payload
        assert "w3.org/2000/svg" in payload

    def test_has_svg_xlink(self):
        """Should have SVG XLink payload."""
        assert "svg_xlink" in XXEScanner.SVG_PAYLOADS
        payload = XXEScanner.SVG_PAYLOADS["svg_xlink"]
        assert "xlink" in payload


# ============================================================================
# TESTS: XXEScanner Constants - WAF Bypass Payloads
# ============================================================================

class TestXXEScannerWAFBypassPayloads:
    """Tests for WAF bypass XXE payloads."""

    def test_has_utf16_bypass(self):
        """Should have UTF-16 bypass payload."""
        assert "utf16_bypass" in XXEScanner.WAF_BYPASS_PAYLOADS
        payload = XXEScanner.WAF_BYPASS_PAYLOADS["utf16_bypass"]
        assert "UTF-16" in payload

    def test_has_encoding_bypass(self):
        """Should have entity encoding bypass."""
        assert "encoding_bypass" in XXEScanner.WAF_BYPASS_PAYLOADS
        payload = XXEScanner.WAF_BYPASS_PAYLOADS["encoding_bypass"]
        assert "&#x" in payload  # Hex entity encoding

    def test_has_cdata_bypass(self):
        """Should have CDATA bypass payload."""
        assert "cdata_bypass" in XXEScanner.WAF_BYPASS_PAYLOADS
        payload = XXEScanner.WAF_BYPASS_PAYLOADS["cdata_bypass"]
        assert "<![CDATA[" in payload

    def test_has_null_byte_bypass(self):
        """Should have null byte bypass payload."""
        assert "null_byte_bypass" in XXEScanner.WAF_BYPASS_PAYLOADS
        payload = XXEScanner.WAF_BYPASS_PAYLOADS["null_byte_bypass"]
        assert "%00" in payload

    def test_has_double_entity_bypass(self):
        """Should have double entity bypass."""
        assert "double_entity" in XXEScanner.WAF_BYPASS_PAYLOADS


# ============================================================================
# TESTS: XXEScanner Constants - XInclude Payloads
# ============================================================================

class TestXXEScannerXIncludePayloads:
    """Tests for XInclude payloads (DTD bypass)."""

    def test_has_basic_xinclude(self):
        """Should have basic XInclude payload."""
        assert "xinclude_basic" in XXEScanner.XINCLUDE_PAYLOADS
        payload = XXEScanner.XINCLUDE_PAYLOADS["xinclude_basic"]
        assert "xi:include" in payload
        assert "w3.org/2001/XInclude" in payload

    def test_has_xinclude_fallback(self):
        """Should have XInclude with fallback."""
        assert "xinclude_fallback" in XXEScanner.XINCLUDE_PAYLOADS
        payload = XXEScanner.XINCLUDE_PAYLOADS["xinclude_fallback"]
        assert "xi:fallback" in payload

    def test_has_xinclude_windows(self):
        """Should have Windows XInclude payload."""
        assert "xinclude_windows" in XXEScanner.XINCLUDE_PAYLOADS
        payload = XXEScanner.XINCLUDE_PAYLOADS["xinclude_windows"]
        assert "win.ini" in payload.lower()

    def test_has_xinclude_ssrf(self):
        """Should have SSRF XInclude payload."""
        assert "xinclude_ssrf" in XXEScanner.XINCLUDE_PAYLOADS
        payload = XXEScanner.XINCLUDE_PAYLOADS["xinclude_ssrf"]
        assert "169.254.169.254" in payload

    def test_has_xinclude_soap(self):
        """Should have SOAP XInclude payload."""
        assert "xinclude_soap" in XXEScanner.XINCLUDE_PAYLOADS
        payload = XXEScanner.XINCLUDE_PAYLOADS["xinclude_soap"]
        assert "soap:Envelope" in payload

    def test_has_xinclude_svg(self):
        """Should have SVG XInclude payload."""
        assert "xinclude_svg" in XXEScanner.XINCLUDE_PAYLOADS
        payload = XXEScanner.XINCLUDE_PAYLOADS["xinclude_svg"]
        assert "<svg" in payload

    def test_xinclude_no_doctype(self):
        """XInclude payloads should NOT have DOCTYPE (that's the bypass)."""
        for name, payload in XXEScanner.XINCLUDE_PAYLOADS.items():
            assert "<!DOCTYPE" not in payload, f"{name} should not have DOCTYPE"


# ============================================================================
# TESTS: XXEScanner Constants - File Indicators
# ============================================================================

class TestXXEScannerFileIndicators:
    """Tests for file content indicators."""

    def test_has_linux_passwd_indicators(self):
        """Should have /etc/passwd indicators."""
        assert "linux_passwd" in XXEScanner.FILE_INDICATORS
        indicators = XXEScanner.FILE_INDICATORS["linux_passwd"]
        assert "root:x:0:0" in indicators
        assert any("bin/bash" in i or "bin/sh" in i for i in indicators)

    def test_has_linux_shadow_indicators(self):
        """Should have /etc/shadow indicators."""
        assert "linux_shadow" in XXEScanner.FILE_INDICATORS
        indicators = XXEScanner.FILE_INDICATORS["linux_shadow"]
        # Shadow file has hash prefixes
        assert any("$" in i for i in indicators)

    def test_has_windows_ini_indicators(self):
        """Should have win.ini indicators."""
        assert "windows_ini" in XXEScanner.FILE_INDICATORS
        indicators = XXEScanner.FILE_INDICATORS["windows_ini"]
        assert "[fonts]" in indicators

    def test_has_aws_metadata_indicators(self):
        """Should have AWS metadata indicators."""
        assert "aws_metadata" in XXEScanner.FILE_INDICATORS
        indicators = XXEScanner.FILE_INDICATORS["aws_metadata"]
        assert "ami-id" in indicators or "instance-id" in indicators

    def test_has_gcp_metadata_indicators(self):
        """Should have GCP metadata indicators."""
        assert "gcp_metadata" in XXEScanner.FILE_INDICATORS

    def test_has_azure_metadata_indicators(self):
        """Should have Azure metadata indicators."""
        assert "azure_metadata" in XXEScanner.FILE_INDICATORS


# ============================================================================
# TESTS: XXEScanner Constants - Error Indicators
# ============================================================================

class TestXXEScannerErrorIndicators:
    """Tests for error message indicators."""

    def test_has_entity_errors(self):
        """Should have entity-related errors."""
        errors = XXEScanner.ERROR_INDICATORS
        assert any("entity" in e.lower() for e in errors)

    def test_has_doctype_error(self):
        """Should have DOCTYPE error."""
        assert "DOCTYPE" in XXEScanner.ERROR_INDICATORS

    def test_has_parser_errors(self):
        """Should have parser error indicators."""
        errors = XXEScanner.ERROR_INDICATORS
        assert any("parser" in e.lower() for e in errors)

    def test_has_php_parser_errors(self):
        """Should have PHP parser error indicators."""
        errors = XXEScanner.ERROR_INDICATORS
        assert any(p in errors for p in ["DOMDocument", "SimpleXML", "XMLReader"])

    def test_has_java_parser_errors(self):
        """Should have Java parser error indicators."""
        errors = XXEScanner.ERROR_INDICATORS
        assert "SAXException" in errors


# ============================================================================
# TESTS: Attack Scenarios
# ============================================================================

class TestXXEAttackScenarios:
    """Tests modeling real-world XXE attack scenarios."""

    def test_file_disclosure_scenario(self):
        """Test classic file disclosure scenario."""
        finding = XXEFinding(
            url="https://example.com/api/xml",
            xxe_type=XXEType.CLASSIC,
            payload=XXEScanner.CLASSIC_PAYLOADS["linux_passwd"],
            protocol="file://",
            parser=XMLParser.LIBXML2,
            content_format=ContentFormat.XML,
            detection_method="direct_response",
            evidence=["root:x:0:0:root:/root:/bin/bash"],
            confidence=95,
            file_disclosed="/etc/passwd",
            file_content="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1",
        )
        assert finding.xxe_type == XXEType.CLASSIC
        assert "root:x:0:0" in finding.file_content

    def test_blind_oob_scenario(self):
        """Test blind OOB XXE scenario."""
        finding = XXEFinding(
            url="https://example.com/soap/api",
            xxe_type=XXEType.OOB_HTTP,
            payload=XXEScanner.OOB_PAYLOADS["oob_http"],
            protocol="http://",
            parser=XMLParser.XERCES,
            content_format=ContentFormat.SOAP,
            detection_method="oob_callback",
            evidence=["HTTP callback received", "Data: hostname=webapp-1"],
            confidence=90,
        )
        assert finding.xxe_type == XXEType.OOB_HTTP
        assert "callback" in finding.detection_method

    def test_ssrf_via_xxe_scenario(self):
        """Test SSRF via XXE to cloud metadata."""
        finding = XXEFinding(
            url="https://example.com/import",
            xxe_type=XXEType.SSRF,
            payload=XXEScanner.SSRF_PAYLOADS["aws_metadata"],
            protocol="http://",
            parser=XMLParser.LIBXML2,
            content_format=ContentFormat.XML,
            detection_method="direct_response",
            evidence=["ami-id", "instance-type: t2.micro"],
            confidence=95,
        )
        assert finding.xxe_type == XXEType.SSRF
        assert "ami-id" in finding.evidence

    def test_rce_via_expect_scenario(self):
        """Test RCE via expect:// wrapper."""
        finding = XXEFinding(
            url="https://example.com/api/upload",
            xxe_type=XXEType.RCE,
            payload=XXEScanner.PHP_PAYLOADS["php_expect_id"],
            protocol="expect://",
            parser=XMLParser.LIBXML2,
            content_format=ContentFormat.XML,
            detection_method="command_output",
            evidence=["uid=33(www-data) gid=33(www-data)"],
            confidence=100,
        )
        assert finding.xxe_type == XXEType.RCE
        assert "uid=" in finding.evidence[0]

    def test_xinclude_bypass_scenario(self):
        """Test XInclude bypassing DTD protections."""
        finding = XXEFinding(
            url="https://example.com/api/process",
            xxe_type=XXEType.XINCLUDE,
            payload=XXEScanner.XINCLUDE_PAYLOADS["xinclude_basic"],
            protocol="file://",
            parser=XMLParser.LIBXML2,
            content_format=ContentFormat.XML,
            detection_method="xinclude_parse",
            evidence=["XInclude processed", "root:x:0:0"],
            confidence=90,
        )
        assert finding.xxe_type == XXEType.XINCLUDE
        # XInclude works even when DTD is disabled
        assert "<!DOCTYPE" not in finding.payload

    def test_dos_billion_laughs_scenario(self):
        """Test Billion Laughs DoS detection."""
        finding = XXEFinding(
            url="https://example.com/api/xml",
            xxe_type=XXEType.DOS,
            payload=XXEScanner.DOS_PAYLOADS["billion_laughs"],
            protocol="entity://",
            parser=XMLParser.UNKNOWN,
            content_format=ContentFormat.XML,
            detection_method="timeout_or_error",
            evidence=["Server timeout", "Memory exhaustion detected"],
            confidence=80,
        )
        assert finding.xxe_type == XXEType.DOS


# ============================================================================
# TESTS: Edge Cases
# ============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_xxe_finding_minimal(self):
        """Should create XXEFinding with minimum required fields."""
        finding = XXEFinding(
            url="https://example.com",
            xxe_type=XXEType.CLASSIC,
            payload="<test/>",
            protocol="file://",
            parser=XMLParser.UNKNOWN,
            content_format=ContentFormat.XML,
            detection_method="test",
            evidence=[],
            confidence=0,
        )
        assert finding.file_disclosed is None
        assert finding.waf_detected is None
        assert finding.file_content is None

    def test_payload_encoder_empty_input(self):
        """PayloadEncoder should handle empty input."""
        assert PayloadEncoder.entity_encode("") == ""
        assert PayloadEncoder.cdata_wrap("") == "<![CDATA[]]>"

    def test_payload_encoder_special_chars(self):
        """PayloadEncoder should handle special characters."""
        result = PayloadEncoder.entity_encode("file:///etc/passwd")
        # Only alphabetic chars should be encoded
        assert "&#x" in result

    def test_all_payload_dicts_not_empty(self):
        """All payload dictionaries should have content."""
        assert len(XXEScanner.CLASSIC_PAYLOADS) > 0
        assert len(XXEScanner.PHP_PAYLOADS) > 0
        assert len(XXEScanner.SSRF_PAYLOADS) > 0
        assert len(XXEScanner.PARAMETER_ENTITY_PAYLOADS) > 0
        assert len(XXEScanner.OOB_PAYLOADS) > 0
        assert len(XXEScanner.ERROR_PAYLOADS) > 0
        assert len(XXEScanner.DOS_PAYLOADS) > 0
        assert len(XXEScanner.SOAP_PAYLOADS) > 0
        assert len(XXEScanner.SVG_PAYLOADS) > 0
        assert len(XXEScanner.WAF_BYPASS_PAYLOADS) > 0
        assert len(XXEScanner.XINCLUDE_PAYLOADS) > 0

    def test_scanner_has_name(self):
        """Scanner should have a name."""
        assert XXEScanner.name == "xxe_scanner"

    def test_scanner_has_confidence_threshold(self):
        """Scanner should have confidence threshold."""
        assert XXEScanner.MIN_CONFIDENCE_THRESHOLD >= 0
        assert XXEScanner.MIN_CONFIDENCE_THRESHOLD <= 100
