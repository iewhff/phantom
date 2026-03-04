"""
Tests for scanning/modules/file_upload_scanner.py

Covers:
- UploadVulnType enum (19 types)
- FileType enum (22 types)
- ServerType enum (7 types)
- FILE_SIGNATURES constant (magic bytes)
- Extension lists (PHP, JSP, ASP)
- generate_case_variations()
- DOUBLE_EXTENSIONS, SPECIAL_CHAR_BYPASSES
- Payload templates (PHP, JSP, ASP, ASPX, SVG, htaccess, web.config, XXE)
- Dataclasses (UploadEndpoint, UploadAttempt, UploadFinding, ScanConfig)
- PolyglotGenerator
"""

import pytest
import time
from scanning.modules.file_upload_scanner import (
    VERSION,
    UploadVulnType,
    FileType,
    ServerType,
    FILE_SIGNATURES,
    PHP_EXTENSIONS,
    JSP_EXTENSIONS,
    ASP_EXTENSIONS,
    generate_case_variations,
    MAX_CASE_VARIATIONS,
    DOUBLE_EXTENSIONS,
    SPECIAL_CHAR_BYPASSES,
    PHP_PAYLOADS,
    JSP_PAYLOADS,
    ASP_PAYLOADS,
    ASPX_PAYLOADS,
    SVG_XSS_PAYLOADS,
    HTACCESS_PAYLOADS,
    WEB_CONFIG_PAYLOADS,
    XXE_PAYLOADS,
    UploadEndpoint,
    UploadAttempt,
    UploadFinding,
    ScanConfig,
    PolyglotGenerator,
)


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestUploadVulnType:
    def test_count(self):
        assert len(UploadVulnType) == 19

    def test_has_unrestricted(self):
        assert UploadVulnType.UNRESTRICTED_UPLOAD is not None

    def test_has_content_type_bypass(self):
        assert UploadVulnType.CONTENT_TYPE_BYPASS is not None

    def test_has_extension_bypass(self):
        assert UploadVulnType.EXTENSION_BYPASS is not None

    def test_has_path_traversal(self):
        assert UploadVulnType.PATH_TRAVERSAL is not None

    def test_has_polyglot_file(self):
        assert UploadVulnType.POLYGLOT_FILE is not None

    def test_has_svg_xss(self):
        assert UploadVulnType.SVG_XSS is not None

    def test_has_htaccess(self):
        assert UploadVulnType.HTACCESS_UPLOAD is not None

    def test_has_zip_slip(self):
        assert UploadVulnType.ZIP_SLIP is not None

    def test_has_xxe_via_upload(self):
        assert UploadVulnType.XXE_VIA_UPLOAD is not None

    def test_has_ssrf_via_upload(self):
        assert UploadVulnType.SSRF_VIA_UPLOAD is not None

    def test_has_image_tragick(self):
        assert UploadVulnType.IMAGE_TRAGICK is not None


class TestFileType:
    def test_count(self):
        assert len(FileType) == 22

    def test_has_php(self):
        assert FileType.PHP.value == "php"

    def test_has_jsp(self):
        assert FileType.JSP.value == "jsp"

    def test_has_asp(self):
        assert FileType.ASP.value == "asp"

    def test_has_image_types(self):
        assert FileType.IMAGE_GIF.value == "gif"
        assert FileType.IMAGE_PNG.value == "png"
        assert FileType.IMAGE_JPG.value == "jpg"
        assert FileType.IMAGE_SVG.value == "svg"

    def test_has_htaccess(self):
        assert FileType.HTACCESS.value == "htaccess"


class TestServerType:
    def test_count(self):
        assert len(ServerType) == 7

    def test_has_apache(self):
        assert ServerType.APACHE.value == "apache"

    def test_has_nginx(self):
        assert ServerType.NGINX.value == "nginx"

    def test_has_iis(self):
        assert ServerType.IIS.value == "iis"

    def test_has_unknown(self):
        assert ServerType.UNKNOWN.value == "unknown"


# =============================================================================
# FILE SIGNATURES
# =============================================================================

class TestFileSignatures:
    def test_not_empty(self):
        assert len(FILE_SIGNATURES) > 0

    def test_gif_magic(self):
        assert FILE_SIGNATURES["gif"] == b"GIF89a"

    def test_png_magic(self):
        assert FILE_SIGNATURES["png"] == b"\x89PNG\r\n\x1a\n"

    def test_jpg_magic(self):
        assert FILE_SIGNATURES["jpg"] == b"\xff\xd8\xff\xe0"

    def test_pdf_magic(self):
        assert FILE_SIGNATURES["pdf"] == b"%PDF-"

    def test_zip_magic(self):
        assert FILE_SIGNATURES["zip"] == b"PK\x03\x04"

    def test_exe_magic(self):
        assert FILE_SIGNATURES["exe"] == b"MZ"

    def test_elf_magic(self):
        assert FILE_SIGNATURES["elf"] == b"\x7fELF"

    def test_bmp_magic(self):
        assert FILE_SIGNATURES["bmp"] == b"BM"

    def test_all_are_bytes(self):
        for name, sig in FILE_SIGNATURES.items():
            assert isinstance(sig, bytes), f"Signature for {name} should be bytes"


# =============================================================================
# EXTENSION LISTS
# =============================================================================

class TestExtensionLists:
    def test_php_not_empty(self):
        assert len(PHP_EXTENSIONS) > 0

    def test_php_has_php(self):
        assert ".php" in PHP_EXTENSIONS

    def test_php_has_phtml(self):
        assert ".phtml" in PHP_EXTENSIONS

    def test_php_has_phar(self):
        assert ".phar" in PHP_EXTENSIONS

    def test_php_has_php5(self):
        assert ".php5" in PHP_EXTENSIONS

    def test_jsp_not_empty(self):
        assert len(JSP_EXTENSIONS) > 0

    def test_jsp_has_jsp(self):
        assert ".jsp" in JSP_EXTENSIONS

    def test_jsp_has_war(self):
        assert ".war" in JSP_EXTENSIONS

    def test_asp_not_empty(self):
        assert len(ASP_EXTENSIONS) > 0

    def test_asp_has_asp(self):
        assert ".asp" in ASP_EXTENSIONS

    def test_asp_has_aspx(self):
        assert ".aspx" in ASP_EXTENSIONS

    def test_asp_has_config(self):
        assert ".config" in ASP_EXTENSIONS

    def test_all_start_with_dot(self):
        for ext in PHP_EXTENSIONS + JSP_EXTENSIONS + ASP_EXTENSIONS:
            assert ext.startswith("."), f"Extension should start with dot: {ext}"


# =============================================================================
# CASE VARIATIONS
# =============================================================================

class TestGenerateCaseVariations:
    def test_basic(self):
        variations = generate_case_variations(".php")
        assert len(variations) > 0
        assert ".php" in variations
        assert ".PHP" in variations

    def test_mixed_case(self):
        variations = generate_case_variations(".php")
        # Should have mixed case like .Php, .pHp, etc.
        assert len(variations) > 2

    def test_single_char(self):
        result = generate_case_variations("x")
        assert len(result) >= 1

    def test_empty_string(self):
        result = generate_case_variations("")
        assert len(result) >= 1

    def test_max_variations_limit(self):
        variations = generate_case_variations(".phtml")
        assert len(variations) <= MAX_CASE_VARIATIONS

    def test_long_extension_capped(self):
        """Long extensions should not cause exponential explosion."""
        variations = generate_case_variations(".verylongextension")
        assert len(variations) <= MAX_CASE_VARIATIONS


# =============================================================================
# DOUBLE EXTENSIONS
# =============================================================================

class TestDoubleExtensions:
    def test_not_empty(self):
        assert len(DOUBLE_EXTENSIONS) > 0

    def test_all_are_tuples(self):
        for item in DOUBLE_EXTENSIONS:
            assert isinstance(item, tuple)
            assert len(item) == 2

    def test_has_jpg_php(self):
        exts = [e for e, ct in DOUBLE_EXTENSIONS]
        assert ".jpg.php" in exts

    def test_has_null_byte(self):
        exts = [e for e, ct in DOUBLE_EXTENSIONS]
        assert any("%00" in e or "\x00" in e for e in exts)

    def test_has_iis_semicolon(self):
        exts = [e for e, ct in DOUBLE_EXTENSIONS]
        assert any(";" in e for e in exts)

    def test_has_unicode_tricks(self):
        exts = [e for e, ct in DOUBLE_EXTENSIONS]
        assert any("\u200b" in e or "\u202e" in e for e in exts)


class TestSpecialCharBypasses:
    def test_not_empty(self):
        assert len(SPECIAL_CHAR_BYPASSES) > 0

    def test_has_null_byte(self):
        assert "%00" in SPECIAL_CHAR_BYPASSES or "\x00" in SPECIAL_CHAR_BYPASSES

    def test_has_dots(self):
        assert ".." in SPECIAL_CHAR_BYPASSES


# =============================================================================
# PAYLOAD TEMPLATES
# =============================================================================

class TestPHPPayloads:
    def test_not_empty(self):
        assert len(PHP_PAYLOADS) > 0

    def test_has_basic(self):
        assert "basic" in PHP_PAYLOADS
        assert "<?php" in PHP_PAYLOADS["basic"]

    def test_has_short_tag(self):
        assert "short_tag" in PHP_PAYLOADS
        assert "<?=" in PHP_PAYLOADS["short_tag"]

    def test_has_script_tag(self):
        assert "script_tag" in PHP_PAYLOADS

    def test_all_have_marker_or_phpinfo(self):
        for name, payload in PHP_PAYLOADS.items():
            assert "PHANTOM" in payload or "phpinfo" in payload, f"PHP payload {name} missing marker"


class TestJSPPayloads:
    def test_not_empty(self):
        assert len(JSP_PAYLOADS) > 0

    def test_has_basic(self):
        assert "basic" in JSP_PAYLOADS

    def test_has_expression(self):
        assert "expression" in JSP_PAYLOADS
        assert "${" in JSP_PAYLOADS["expression"]


class TestASPPayloads:
    def test_not_empty(self):
        assert len(ASP_PAYLOADS) > 0
        assert len(ASPX_PAYLOADS) > 0


class TestSVGXSSPayloads:
    def test_not_empty(self):
        assert len(SVG_XSS_PAYLOADS) > 0

    def test_has_onload(self):
        assert "onload" in SVG_XSS_PAYLOADS
        assert "onload" in SVG_XSS_PAYLOADS["onload"]

    def test_has_script(self):
        assert "script" in SVG_XSS_PAYLOADS
        assert "<script" in SVG_XSS_PAYLOADS["script"]

    def test_has_foreignobject(self):
        assert "foreignobject" in SVG_XSS_PAYLOADS

    def test_all_have_svg(self):
        for name, payload in SVG_XSS_PAYLOADS.items():
            assert "<svg" in payload.lower(), f"SVG payload {name} missing <svg>"


class TestHtaccessPayloads:
    def test_not_empty(self):
        assert len(HTACCESS_PAYLOADS) > 0

    def test_has_php_handler(self):
        assert "php_handler" in HTACCESS_PAYLOADS
        assert "AddHandler" in HTACCESS_PAYLOADS["php_handler"]

    def test_has_add_type(self):
        assert "add_type" in HTACCESS_PAYLOADS

    def test_has_set_handler(self):
        assert "set_handler" in HTACCESS_PAYLOADS


class TestWebConfigPayloads:
    def test_not_empty(self):
        assert len(WEB_CONFIG_PAYLOADS) > 0

    def test_has_xml(self):
        for name, payload in WEB_CONFIG_PAYLOADS.items():
            assert "<?xml" in payload, f"web.config payload {name} missing XML header"


class TestXXEPayloads:
    def test_not_empty(self):
        assert len(XXE_PAYLOADS) > 0

    def test_has_docx(self):
        assert "docx" in XXE_PAYLOADS

    def test_has_svg(self):
        assert "svg" in XXE_PAYLOADS

    def test_all_have_entity(self):
        for name, payload in XXE_PAYLOADS.items():
            assert "ENTITY" in payload, f"XXE payload {name} missing ENTITY"


# =============================================================================
# DATACLASS TESTS
# =============================================================================

class TestUploadEndpoint:
    def test_defaults(self):
        ep = UploadEndpoint(url="https://target.com/upload")
        assert ep.method == "POST"
        assert ep.file_param == "file"
        assert ep.enctype == "multipart/form-data"
        assert ep.max_size is None
        assert ep.allowed_types == []

    def test_custom(self):
        ep = UploadEndpoint(
            url="https://target.com/api/upload",
            file_param="document",
            max_size=5 * 1024 * 1024,
            allowed_types=["image/png", "image/jpeg"],
            requires_auth=True,
        )
        assert ep.file_param == "document"
        assert ep.requires_auth is True


class TestUploadFinding:
    def test_creation(self):
        ep = UploadEndpoint(url="https://target.com/upload")
        finding = UploadFinding(
            id="UPLOAD-0001",
            vuln_type=UploadVulnType.UNRESTRICTED_UPLOAD,
            severity="CRITICAL",
            confidence=0.95,
            endpoint=ep,
            technique="Direct PHP upload",
            payload_used="<?php phpinfo(); ?>",
            filename="shell.php",
            uploaded_url="https://target.com/uploads/shell.php",
            execution_evidence="phpinfo() output detected",
            description="Unrestricted file upload allows PHP execution",
            remediation="Validate file content, not just extension",
            cwe_id=434,
            cvss_score=9.8,
            request_details={"content_type": "application/x-php"},
            response_details={"status": 200},
        )
        assert finding.cwe_id == 434
        assert finding.cvss_score == 9.8


class TestScanConfig:
    def test_defaults(self):
        config = ScanConfig(target_url="https://target.com")
        assert config.max_file_size == 10 * 1024 * 1024
        assert config.timeout == 30.0
        assert config.verify_execution is True
        assert config.test_race_conditions is True
        assert config.safe_mode is True
        assert config.server_type == ServerType.UNKNOWN


# =============================================================================
# POLYGLOT GENERATOR
# =============================================================================

class TestPolyglotGenerator:
    def test_version(self):
        assert PolyglotGenerator.VERSION == "3.0.0"

    def test_gif_php(self):
        data = PolyglotGenerator.gif_php()
        assert data.startswith(b"GIF89a")
        assert b"PHANTOM" in data

    def test_gif_php_custom(self):
        data = PolyglotGenerator.gif_php("<?php echo 'test'; ?>")
        assert data.startswith(b"GIF89a")
        assert b"test" in data

    def test_png_php(self):
        data = PolyglotGenerator.png_php()
        assert data.startswith(b"\x89PNG")
        assert b"PHANTOM" in data


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    def test_version(self):
        assert VERSION == "3.0.0"

    def test_all_vuln_types_unique(self):
        values = [t.value for t in UploadVulnType]
        assert len(values) == len(set(values))

    def test_all_file_types_unique(self):
        values = [t.value for t in FileType]
        assert len(values) == len(set(values))
