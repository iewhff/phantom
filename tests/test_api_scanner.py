"""
Tests for scanning/modules/api_scanner.py

Covers:
- UploadVulnType enum (12 members, values, uniqueness)
- UploadTestResult dataclass (defaults, full creation)
- FileSignature dataclass (full creation, fields)
- FILE_SIGNATURES module-level dict (count, key entries, types)
- DANGEROUS_EXTENSIONS list (count, key entries)
- EXTENSION_BYPASS_PAYLOADS list (count, format strings)
- CONTENT_TYPE_BYPASS list (count, tuple structure)
- POLYGLOT_TEMPLATES dict (count, keys, bytes content)
- SVG_XSS_PAYLOADS list (count, XML content)
- XXE_PAYLOADS list (count, DOCTYPE content)
- SSRF_PAYLOADS list (count, key entries)
- OpenAPIEndpoint dataclass (defaults, full creation)
- OpenAPISpec dataclass (defaults, full creation)
- OpenAPIParser.parse static method (v2, v3 specs)
- OpenAPIParser.to_asset_data static method
- APIScanner identity (name, version, ScanModule subclass)
- APIScanner class-level constants (API_PATHS, UPLOAD_PATHS, IDOR_PATTERNS, BFLA_PATTERNS)
- APIScanner.PII_PATTERNS regex dict (count, compile, match known examples)
- APIScanner.SENSITIVE_FIELD_NAMES list (count, key entries)
- APIScanner.GRAPHQL_INTROSPECTION query string
"""

import re
import pytest
from unittest.mock import MagicMock
from dataclasses import fields as dc_fields

from scanning.modules.api_scanner import (
    UploadVulnType,
    UploadTestResult,
    FileSignature,
    FILE_SIGNATURES,
    DANGEROUS_EXTENSIONS,
    EXTENSION_BYPASS_PAYLOADS,
    CONTENT_TYPE_BYPASS,
    POLYGLOT_TEMPLATES,
    SVG_XSS_PAYLOADS,
    XXE_PAYLOADS,
    SSRF_PAYLOADS,
    OpenAPIEndpoint,
    OpenAPISpec,
    OpenAPIParser,
    APIScanner,
)
from scanning.vuln_scanner import ScanModule


# ============================================================================
# TESTS: UploadVulnType Enum
# ============================================================================

class TestUploadVulnType:
    """Tests for UploadVulnType enum."""

    def test_member_count(self):
        """Should have exactly 12 members."""
        assert len(UploadVulnType) == 12

    def test_has_extension_bypass(self):
        assert UploadVulnType.EXTENSION_BYPASS is not None

    def test_has_content_type_bypass(self):
        assert UploadVulnType.CONTENT_TYPE_BYPASS is not None

    def test_has_magic_bytes_bypass(self):
        assert UploadVulnType.MAGIC_BYTES_BYPASS is not None

    def test_has_polyglot_file(self):
        assert UploadVulnType.POLYGLOT_FILE is not None

    def test_has_null_byte_injection(self):
        assert UploadVulnType.NULL_BYTE_INJECTION is not None

    def test_has_double_extension(self):
        assert UploadVulnType.DOUBLE_EXTENSION is not None

    def test_has_case_manipulation(self):
        assert UploadVulnType.CASE_MANIPULATION is not None

    def test_has_unicode_bypass(self):
        assert UploadVulnType.UNICODE_BYPASS is not None

    def test_has_path_traversal(self):
        assert UploadVulnType.PATH_TRAVERSAL is not None

    def test_has_svg_xss(self):
        assert UploadVulnType.SVG_XSS is not None

    def test_has_xml_xxe(self):
        assert UploadVulnType.XML_XXE is not None

    def test_has_zip_slip(self):
        assert UploadVulnType.ZIP_SLIP is not None

    def test_all_values_unique(self):
        """All enum values should be unique."""
        values = [m.value for m in UploadVulnType]
        assert len(values) == len(set(values))


# ============================================================================
# TESTS: UploadTestResult Dataclass
# ============================================================================

class TestUploadTestResult:
    """Tests for UploadTestResult dataclass."""

    def test_create_with_required_fields(self):
        """Should create with just test_type and success."""
        result = UploadTestResult(
            test_type=UploadVulnType.EXTENSION_BYPASS,
            success=True,
        )
        assert result.test_type == UploadVulnType.EXTENSION_BYPASS
        assert result.success is True

    def test_defaults(self):
        """Default values should be empty/zero."""
        result = UploadTestResult(
            test_type=UploadVulnType.SVG_XSS,
            success=False,
        )
        assert result.filename == ""
        assert result.content_type == ""
        assert result.response_code == 0
        assert result.uploaded_url == ""
        assert result.evidence == []

    def test_full_creation(self):
        """Should accept all fields."""
        result = UploadTestResult(
            test_type=UploadVulnType.POLYGLOT_FILE,
            success=True,
            filename="shell.gif.php",
            content_type="image/gif",
            response_code=200,
            uploaded_url="http://test.local/uploads/shell.gif.php",
            evidence=["File accepted", "Accessible at URL"],
        )
        assert result.filename == "shell.gif.php"
        assert result.content_type == "image/gif"
        assert result.response_code == 200
        assert result.uploaded_url == "http://test.local/uploads/shell.gif.php"
        assert len(result.evidence) == 2

    def test_evidence_list_independence(self):
        """Each instance should have its own evidence list."""
        r1 = UploadTestResult(test_type=UploadVulnType.SVG_XSS, success=False)
        r2 = UploadTestResult(test_type=UploadVulnType.SVG_XSS, success=False)
        r1.evidence.append("test")
        assert r2.evidence == []


# ============================================================================
# TESTS: FileSignature Dataclass
# ============================================================================

class TestFileSignature:
    """Tests for FileSignature dataclass."""

    def test_create_full(self):
        sig = FileSignature(
            extension="gif",
            mime_type="image/gif",
            magic_bytes=b"GIF89a",
            description="GIF Image",
        )
        assert sig.extension == "gif"
        assert sig.mime_type == "image/gif"
        assert sig.magic_bytes == b"GIF89a"
        assert sig.description == "GIF Image"

    def test_has_four_fields(self):
        """Should have exactly 4 fields."""
        assert len(dc_fields(FileSignature)) == 4


# ============================================================================
# TESTS: FILE_SIGNATURES Module Dict
# ============================================================================

class TestFileSignatures:
    """Tests for the FILE_SIGNATURES module-level dict."""

    def test_count(self):
        """Should have exactly 10 entries."""
        assert len(FILE_SIGNATURES) == 10

    def test_has_gif(self):
        assert "gif" in FILE_SIGNATURES

    def test_has_png(self):
        assert "png" in FILE_SIGNATURES

    def test_has_jpg(self):
        assert "jpg" in FILE_SIGNATURES

    def test_has_pdf(self):
        assert "pdf" in FILE_SIGNATURES

    def test_has_zip(self):
        assert "zip" in FILE_SIGNATURES

    def test_has_rar(self):
        assert "rar" in FILE_SIGNATURES

    def test_has_exe(self):
        assert "exe" in FILE_SIGNATURES

    def test_has_elf(self):
        assert "elf" in FILE_SIGNATURES

    def test_has_mp3(self):
        assert "mp3" in FILE_SIGNATURES

    def test_has_mp4(self):
        assert "mp4" in FILE_SIGNATURES

    def test_all_values_are_file_signature(self):
        """All values should be FileSignature instances."""
        for key, val in FILE_SIGNATURES.items():
            assert isinstance(val, FileSignature), f"{key} is not FileSignature"

    def test_gif_magic_bytes(self):
        assert FILE_SIGNATURES["gif"].magic_bytes == b"GIF89a"

    def test_png_magic_bytes(self):
        assert FILE_SIGNATURES["png"].magic_bytes == b"\x89PNG\r\n\x1a\n"

    def test_pdf_magic_bytes_start(self):
        assert FILE_SIGNATURES["pdf"].magic_bytes.startswith(b"%PDF")

    def test_exe_magic_bytes(self):
        assert FILE_SIGNATURES["exe"].magic_bytes == b"MZ"


# ============================================================================
# TESTS: DANGEROUS_EXTENSIONS List
# ============================================================================

class TestDangerousExtensions:
    """Tests for the DANGEROUS_EXTENSIONS module-level list."""

    def test_count(self):
        assert len(DANGEROUS_EXTENSIONS) == 39

    def test_contains_php(self):
        assert ".php" in DANGEROUS_EXTENSIONS

    def test_contains_asp(self):
        assert ".asp" in DANGEROUS_EXTENSIONS

    def test_contains_aspx(self):
        assert ".aspx" in DANGEROUS_EXTENSIONS

    def test_contains_jsp(self):
        assert ".jsp" in DANGEROUS_EXTENSIONS

    def test_contains_svg(self):
        assert ".svg" in DANGEROUS_EXTENSIONS

    def test_contains_htaccess(self):
        assert ".htaccess" in DANGEROUS_EXTENSIONS

    def test_all_start_with_dot(self):
        """All extensions should start with a dot."""
        for ext in DANGEROUS_EXTENSIONS:
            assert ext.startswith("."), f"{ext} does not start with dot"

    def test_all_are_strings(self):
        for ext in DANGEROUS_EXTENSIONS:
            assert isinstance(ext, str)


# ============================================================================
# TESTS: EXTENSION_BYPASS_PAYLOADS List
# ============================================================================

class TestExtensionBypassPayloads:
    """Tests for the EXTENSION_BYPASS_PAYLOADS module-level list."""

    def test_count(self):
        assert len(EXTENSION_BYPASS_PAYLOADS) == 34

    def test_all_are_strings(self):
        for p in EXTENSION_BYPASS_PAYLOADS:
            assert isinstance(p, str)

    def test_contain_name_placeholder(self):
        """Most payloads should contain {name} format placeholder."""
        with_name = [p for p in EXTENSION_BYPASS_PAYLOADS if "{name}" in p]
        assert len(with_name) == len(EXTENSION_BYPASS_PAYLOADS)

    def test_double_extension_present(self):
        """Should have double extension payloads like {name}.jpg.php."""
        assert "{name}.jpg.php" in EXTENSION_BYPASS_PAYLOADS

    def test_null_byte_present(self):
        """Should have null byte injection payloads."""
        null_byte_payloads = [p for p in EXTENSION_BYPASS_PAYLOADS if "%00" in p or "\x00" in p]
        assert len(null_byte_payloads) >= 2

    def test_case_manipulation_present(self):
        """Should have case manipulation payloads."""
        assert "{name}.PhP" in EXTENSION_BYPASS_PAYLOADS

    def test_ntfs_stream_present(self):
        """Should have NTFS alternate data stream payloads."""
        ntfs = [p for p in EXTENSION_BYPASS_PAYLOADS if "::$DATA" in p or "::$data" in p]
        assert len(ntfs) >= 1


# ============================================================================
# TESTS: CONTENT_TYPE_BYPASS List
# ============================================================================

class TestContentTypeBypass:
    """Tests for the CONTENT_TYPE_BYPASS module-level list."""

    def test_count(self):
        assert len(CONTENT_TYPE_BYPASS) == 8

    def test_all_are_tuples(self):
        for item in CONTENT_TYPE_BYPASS:
            assert isinstance(item, tuple), f"{item} is not a tuple"

    def test_all_tuples_have_two_elements(self):
        for item in CONTENT_TYPE_BYPASS:
            assert len(item) == 2, f"Tuple {item} does not have 2 elements"

    def test_first_entry_is_image_gif(self):
        assert CONTENT_TYPE_BYPASS[0][0] == "image/gif"

    def test_all_filenames_contain_shell(self):
        """All filenames should contain 'shell'."""
        for ct, filename in CONTENT_TYPE_BYPASS:
            assert "shell" in filename, f"Filename {filename} doesn't contain 'shell'"

    def test_has_empty_content_type(self):
        """Should include an empty content-type for bypass testing."""
        content_types = [ct for ct, _ in CONTENT_TYPE_BYPASS]
        assert "" in content_types


# ============================================================================
# TESTS: POLYGLOT_TEMPLATES Dict
# ============================================================================

class TestPolyglotTemplates:
    """Tests for the POLYGLOT_TEMPLATES module-level dict."""

    def test_count(self):
        assert len(POLYGLOT_TEMPLATES) == 3

    def test_has_gif_php(self):
        assert "gif_php" in POLYGLOT_TEMPLATES

    def test_has_png_php(self):
        assert "png_php" in POLYGLOT_TEMPLATES

    def test_has_jpg_php(self):
        assert "jpg_php" in POLYGLOT_TEMPLATES

    def test_all_values_are_bytes(self):
        for key, val in POLYGLOT_TEMPLATES.items():
            assert isinstance(val, bytes), f"{key} value is not bytes"

    def test_gif_starts_with_magic(self):
        """GIF polyglot should start with GIF89a magic bytes."""
        assert POLYGLOT_TEMPLATES["gif_php"].startswith(b"GIF89a")

    def test_png_starts_with_magic(self):
        """PNG polyglot should start with PNG magic bytes."""
        assert POLYGLOT_TEMPLATES["png_php"].startswith(b"\x89PNG")

    def test_jpg_starts_with_magic(self):
        """JPG polyglot should start with JPEG magic bytes."""
        assert POLYGLOT_TEMPLATES["jpg_php"].startswith(b"\xff\xd8\xff")

    def test_all_contain_php_tag(self):
        """All polyglots should contain PHP code."""
        for key, val in POLYGLOT_TEMPLATES.items():
            assert b"<?php" in val, f"{key} does not contain <?php tag"


# ============================================================================
# TESTS: SVG_XSS_PAYLOADS List
# ============================================================================

class TestSVGXSSPayloads:
    """Tests for the SVG_XSS_PAYLOADS module-level list."""

    def test_count(self):
        assert len(SVG_XSS_PAYLOADS) == 3

    def test_all_are_strings(self):
        for p in SVG_XSS_PAYLOADS:
            assert isinstance(p, str)

    def test_all_contain_svg_tag(self):
        """All payloads should contain SVG elements."""
        for p in SVG_XSS_PAYLOADS:
            assert "<svg" in p.lower() or "svg" in p.lower()

    def test_all_contain_xss_trigger(self):
        """All payloads should contain some XSS trigger."""
        for p in SVG_XSS_PAYLOADS:
            has_script = "<script>" in p or "onload=" in p
            assert has_script, f"Payload does not contain XSS trigger"


# ============================================================================
# TESTS: XXE_PAYLOADS List
# ============================================================================

class TestXXEPayloads:
    """Tests for the XXE_PAYLOADS module-level list."""

    def test_count(self):
        assert len(XXE_PAYLOADS) == 3

    def test_all_are_strings(self):
        for p in XXE_PAYLOADS:
            assert isinstance(p, str)

    def test_all_contain_doctype(self):
        """All payloads should contain DOCTYPE declaration."""
        for p in XXE_PAYLOADS:
            assert "<!DOCTYPE" in p

    def test_all_contain_entity(self):
        """All payloads should contain ENTITY definition."""
        for p in XXE_PAYLOADS:
            assert "ENTITY" in p

    def test_first_targets_etc_passwd(self):
        """First payload should target /etc/passwd."""
        assert "/etc/passwd" in XXE_PAYLOADS[0]

    def test_all_start_with_xml_declaration(self):
        for p in XXE_PAYLOADS:
            assert p.strip().startswith("<?xml")


# ============================================================================
# TESTS: SSRF_PAYLOADS List
# ============================================================================

class TestSSRFPayloads:
    """Tests for the SSRF_PAYLOADS module-level list."""

    def test_count(self):
        assert len(SSRF_PAYLOADS) == 12

    def test_all_are_strings(self):
        for p in SSRF_PAYLOADS:
            assert isinstance(p, str)

    def test_has_localhost(self):
        assert "http://localhost/" in SSRF_PAYLOADS

    def test_has_loopback(self):
        assert "http://127.0.0.1/" in SSRF_PAYLOADS

    def test_has_aws_metadata(self):
        aws = [p for p in SSRF_PAYLOADS if "169.254.169.254" in p]
        assert len(aws) >= 1

    def test_has_file_protocol(self):
        assert "file:///etc/passwd" in SSRF_PAYLOADS

    def test_has_gopher_protocol(self):
        gopher = [p for p in SSRF_PAYLOADS if p.startswith("gopher://")]
        assert len(gopher) >= 1

    def test_has_dict_protocol(self):
        dict_payloads = [p for p in SSRF_PAYLOADS if p.startswith("dict://")]
        assert len(dict_payloads) >= 1

    def test_has_gcp_metadata(self):
        gcp = [p for p in SSRF_PAYLOADS if "metadata.google.internal" in p]
        assert len(gcp) >= 1


# ============================================================================
# TESTS: OpenAPIEndpoint Dataclass
# ============================================================================

class TestOpenAPIEndpoint:
    """Tests for OpenAPIEndpoint dataclass."""

    def test_create_with_required_fields(self):
        ep = OpenAPIEndpoint(path="/users", method="GET")
        assert ep.path == "/users"
        assert ep.method == "GET"

    def test_defaults(self):
        ep = OpenAPIEndpoint(path="/test", method="POST")
        assert ep.parameters == []
        assert ep.request_body is None
        assert ep.security == []
        assert ep.description == ""
        assert ep.operation_id == ""
        assert ep.tags == []

    def test_full_creation(self):
        ep = OpenAPIEndpoint(
            path="/users/{id}",
            method="PUT",
            parameters=[{"name": "id", "in": "path"}],
            request_body={"content": {"application/json": {}}},
            security=[{"bearerAuth": []}],
            description="Update user",
            operation_id="updateUser",
            tags=["users", "admin"],
        )
        assert ep.path == "/users/{id}"
        assert ep.method == "PUT"
        assert len(ep.parameters) == 1
        assert ep.request_body is not None
        assert len(ep.security) == 1
        assert ep.description == "Update user"
        assert ep.operation_id == "updateUser"
        assert len(ep.tags) == 2

    def test_list_field_independence(self):
        """Each instance should have independent list fields."""
        ep1 = OpenAPIEndpoint(path="/a", method="GET")
        ep2 = OpenAPIEndpoint(path="/b", method="GET")
        ep1.parameters.append({"name": "x"})
        assert ep2.parameters == []


# ============================================================================
# TESTS: OpenAPISpec Dataclass
# ============================================================================

class TestOpenAPISpec:
    """Tests for OpenAPISpec dataclass."""

    def test_defaults(self):
        spec = OpenAPISpec()
        assert spec.title == ""
        assert spec.version == ""
        assert spec.base_url == ""
        assert spec.endpoints == []
        assert spec.security_schemes == {}
        assert spec.servers == []

    def test_full_creation(self):
        ep = OpenAPIEndpoint(path="/test", method="GET")
        spec = OpenAPISpec(
            title="Test API",
            version="1.0",
            base_url="http://api.test.local",
            endpoints=[ep],
            security_schemes={"bearerAuth": {"type": "http", "scheme": "bearer"}},
            servers=["http://api.test.local"],
        )
        assert spec.title == "Test API"
        assert spec.version == "1.0"
        assert len(spec.endpoints) == 1
        assert "bearerAuth" in spec.security_schemes
        assert len(spec.servers) == 1

    def test_list_field_independence(self):
        s1 = OpenAPISpec()
        s2 = OpenAPISpec()
        s1.endpoints.append(OpenAPIEndpoint(path="/x", method="GET"))
        assert s2.endpoints == []


# ============================================================================
# TESTS: OpenAPIParser
# ============================================================================

class TestOpenAPIParser:
    """Tests for OpenAPIParser static methods."""

    def test_parse_openapi_v3_dict(self):
        """Should parse an OpenAPI 3.0 spec from a dict."""
        spec_dict = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "servers": [{"url": "http://api.test.local"}],
            "paths": {
                "/users": {
                    "get": {
                        "summary": "List users",
                        "operationId": "listUsers",
                        "parameters": [
                            {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                        ],
                    }
                }
            },
        }
        result = OpenAPIParser.parse(spec_dict)
        assert result is not None
        assert result.title == "Test API"
        assert result.version == "1.0.0"
        assert result.base_url == "http://api.test.local"
        assert len(result.endpoints) == 1
        assert result.endpoints[0].path == "/users"
        assert result.endpoints[0].method == "GET"

    def test_parse_openapi_v3_json_string(self):
        """Should parse an OpenAPI 3.0 spec from a JSON string."""
        import json
        spec_dict = {
            "openapi": "3.0.0",
            "info": {"title": "String API", "version": "2.0"},
            "paths": {
                "/items": {
                    "post": {
                        "summary": "Create item",
                    }
                }
            },
        }
        result = OpenAPIParser.parse(json.dumps(spec_dict))
        assert result is not None
        assert result.title == "String API"
        assert len(result.endpoints) == 1
        assert result.endpoints[0].method == "POST"

    def test_parse_swagger_v2(self):
        """Should parse a Swagger 2.0 spec."""
        spec_dict = {
            "swagger": "2.0",
            "info": {"title": "Legacy API", "version": "1.0"},
            "host": "api.legacy.local",
            "basePath": "/v1",
            "schemes": ["https"],
            "paths": {
                "/products": {
                    "get": {"summary": "List products"},
                    "post": {"summary": "Create product"},
                }
            },
        }
        result = OpenAPIParser.parse(spec_dict)
        assert result is not None
        assert result.title == "Legacy API"
        assert result.base_url == "https://api.legacy.local/v1"
        assert len(result.endpoints) == 2

    def test_parse_with_security_schemes_v3(self):
        """Should extract security schemes from OpenAPI 3.0."""
        spec_dict = {
            "openapi": "3.0.0",
            "info": {"title": "Secure API", "version": "1.0"},
            "components": {
                "securitySchemes": {
                    "bearerAuth": {"type": "http", "scheme": "bearer"},
                    "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
                }
            },
            "paths": {},
        }
        result = OpenAPIParser.parse(spec_dict)
        assert result is not None
        assert "bearerAuth" in result.security_schemes
        assert "apiKey" in result.security_schemes

    def test_parse_invalid_json_returns_none(self):
        """Should return None for invalid JSON."""
        result = OpenAPIParser.parse("not valid json {{{")
        assert result is None

    def test_parse_empty_paths(self):
        """Should handle spec with no paths."""
        spec_dict = {
            "openapi": "3.0.0",
            "info": {"title": "Empty", "version": "0.1"},
            "paths": {},
        }
        result = OpenAPIParser.parse(spec_dict)
        assert result is not None
        assert result.endpoints == []

    def test_to_asset_data_structure(self):
        """to_asset_data should return expected keys."""
        ep = OpenAPIEndpoint(
            path="/users",
            method="GET",
            parameters=[{"name": "page", "in": "query", "required": False, "type": "integer"}],
        )
        spec = OpenAPISpec(
            title="Test",
            version="1.0",
            endpoints=[ep],
            servers=["http://test.local"],
        )
        data = OpenAPIParser.to_asset_data(spec, "http://test.local")
        assert "endpoints" in data
        assert "urls" in data
        assert "forms" in data
        assert "tool_discovered_params" in data
        assert "openapi_spec" in data
        assert data["openapi_spec"]["title"] == "Test"
        assert data["openapi_spec"]["endpoint_count"] == 1

    def test_to_asset_data_params_extracted(self):
        """to_asset_data should extract query parameters."""
        ep = OpenAPIEndpoint(
            path="/search",
            method="GET",
            parameters=[
                {"name": "q", "in": "query", "required": True, "type": "string"},
                {"name": "page", "in": "query", "required": False, "type": "integer"},
            ],
        )
        spec = OpenAPISpec(title="Search", version="1.0", endpoints=[ep])
        data = OpenAPIParser.to_asset_data(spec, "http://test.local")
        assert len(data["tool_discovered_params"]) >= 1
        # Check that params are extracted for the endpoint URL
        found_params = False
        for url, params in data["tool_discovered_params"].items():
            if "q" in params and "page" in params:
                found_params = True
        assert found_params


# ============================================================================
# TESTS: APIScanner Identity & Constants
# ============================================================================

class TestAPIScannerIdentity:
    """Tests for APIScanner class identity."""

    def test_name(self):
        assert APIScanner.name == "api_scanner"

    def test_version(self):
        assert APIScanner.version == "2.0-enterprise"

    def test_is_scan_module_subclass(self):
        assert issubclass(APIScanner, ScanModule)

    def test_instantiation(self):
        """Should be instantiable with mock settings."""
        settings = MagicMock()
        settings.scope = None
        scanner = APIScanner(settings=settings)
        assert scanner.name == "api_scanner"
        assert scanner.version == "2.0-enterprise"

    def test_init_sets_empty_upload_results(self):
        settings = MagicMock()
        settings.scope = None
        scanner = APIScanner(settings=settings)
        assert scanner.upload_results == []

    def test_init_sets_empty_discovered_uploads(self):
        settings = MagicMock()
        settings.scope = None
        scanner = APIScanner(settings=settings)
        assert scanner.discovered_uploads == []

    def test_init_sets_empty_discovered_parameters(self):
        settings = MagicMock()
        settings.scope = None
        scanner = APIScanner(settings=settings)
        assert scanner.discovered_parameters == {}


# ============================================================================
# TESTS: APIScanner.API_PATHS
# ============================================================================

class TestAPIPaths:
    """Tests for APIScanner.API_PATHS class constant."""

    def test_count(self):
        assert len(APIScanner.API_PATHS) == 24

    def test_is_list(self):
        assert isinstance(APIScanner.API_PATHS, list)

    def test_all_strings(self):
        for path in APIScanner.API_PATHS:
            assert isinstance(path, str)

    def test_has_api(self):
        assert "/api" in APIScanner.API_PATHS

    def test_has_graphql(self):
        assert "/graphql" in APIScanner.API_PATHS

    def test_has_swagger_json(self):
        assert "/swagger.json" in APIScanner.API_PATHS

    def test_has_openapi_json(self):
        assert "/openapi.json" in APIScanner.API_PATHS

    def test_has_health(self):
        assert "/health" in APIScanner.API_PATHS or "/api/health" in APIScanner.API_PATHS

    def test_all_start_with_slash(self):
        for path in APIScanner.API_PATHS:
            assert path.startswith("/") or path.startswith("."), f"{path} does not start with /"


# ============================================================================
# TESTS: APIScanner.UPLOAD_PATHS
# ============================================================================

class TestUploadPaths:
    """Tests for APIScanner.UPLOAD_PATHS class constant."""

    def test_count(self):
        assert len(APIScanner.UPLOAD_PATHS) == 19

    def test_is_list(self):
        assert isinstance(APIScanner.UPLOAD_PATHS, list)

    def test_has_upload(self):
        assert "/upload" in APIScanner.UPLOAD_PATHS

    def test_has_api_upload(self):
        assert "/api/upload" in APIScanner.UPLOAD_PATHS

    def test_has_avatar_upload(self):
        assert "/avatar/upload" in APIScanner.UPLOAD_PATHS

    def test_has_import(self):
        assert "/import" in APIScanner.UPLOAD_PATHS

    def test_all_start_with_slash(self):
        for path in APIScanner.UPLOAD_PATHS:
            assert path.startswith("/"), f"{path} does not start with /"


# ============================================================================
# TESTS: APIScanner.IDOR_PATTERNS
# ============================================================================

class TestIDORPatterns:
    """Tests for APIScanner.IDOR_PATTERNS class constant."""

    def test_count(self):
        assert len(APIScanner.IDOR_PATTERNS) == 86

    def test_is_list(self):
        assert isinstance(APIScanner.IDOR_PATTERNS, list)

    def test_has_users_id(self):
        assert "/users/{id}" in APIScanner.IDOR_PATTERNS

    def test_has_orders_id(self):
        assert "/orders/{id}" in APIScanner.IDOR_PATTERNS

    def test_has_me_endpoint(self):
        assert "/me" in APIScanner.IDOR_PATTERNS

    def test_has_vehicles_id(self):
        """Should have crAPI-style vehicle patterns."""
        assert "/vehicles/{id}" in APIScanner.IDOR_PATTERNS

    def test_has_admin_patterns(self):
        """Should have admin endpoint patterns for BFLA testing."""
        admin = [p for p in APIScanner.IDOR_PATTERNS if "/admin/" in p]
        assert len(admin) >= 1

    def test_has_nested_resources(self):
        """Should have nested resource patterns."""
        nested = [p for p in APIScanner.IDOR_PATTERNS if p.count("/") >= 3 and "{id}" in p]
        assert len(nested) >= 1

    def test_all_start_with_slash(self):
        for path in APIScanner.IDOR_PATTERNS:
            assert path.startswith("/"), f"{path} does not start with /"


# ============================================================================
# TESTS: APIScanner.BFLA_PATTERNS
# ============================================================================

class TestBFLAPatterns:
    """Tests for APIScanner.BFLA_PATTERNS class constant."""

    def test_count(self):
        assert len(APIScanner.BFLA_PATTERNS) == 26

    def test_is_list(self):
        assert isinstance(APIScanner.BFLA_PATTERNS, list)

    def test_has_admin(self):
        assert "/admin" in APIScanner.BFLA_PATTERNS

    def test_has_management(self):
        assert "/management" in APIScanner.BFLA_PATTERNS

    def test_has_internal(self):
        assert "/internal" in APIScanner.BFLA_PATTERNS

    def test_has_backoffice(self):
        assert "/backoffice" in APIScanner.BFLA_PATTERNS

    def test_all_start_with_slash(self):
        for path in APIScanner.BFLA_PATTERNS:
            assert path.startswith("/"), f"{path} does not start with /"


# ============================================================================
# TESTS: APIScanner.GRAPHQL_INTROSPECTION
# ============================================================================

class TestGraphQLIntrospection:
    """Tests for APIScanner.GRAPHQL_INTROSPECTION class constant."""

    def test_is_string(self):
        assert isinstance(APIScanner.GRAPHQL_INTROSPECTION, str)

    def test_contains_introspection_query(self):
        assert "IntrospectionQuery" in APIScanner.GRAPHQL_INTROSPECTION

    def test_contains_schema(self):
        assert "__schema" in APIScanner.GRAPHQL_INTROSPECTION

    def test_contains_types(self):
        assert "types" in APIScanner.GRAPHQL_INTROSPECTION

    def test_contains_fields(self):
        assert "fields" in APIScanner.GRAPHQL_INTROSPECTION

    def test_is_valid_query_structure(self):
        """Should have query keyword and braces."""
        assert "query" in APIScanner.GRAPHQL_INTROSPECTION
        assert "{" in APIScanner.GRAPHQL_INTROSPECTION
        assert "}" in APIScanner.GRAPHQL_INTROSPECTION


# ============================================================================
# TESTS: APIScanner.PII_PATTERNS (Regex Patterns)
# ============================================================================

class TestPIIPatterns:
    """Tests for APIScanner.PII_PATTERNS regex dict."""

    def test_count(self):
        assert len(APIScanner.PII_PATTERNS) == 9

    def test_is_dict(self):
        assert isinstance(APIScanner.PII_PATTERNS, dict)

    def test_all_values_are_compiled_regex(self):
        for key, val in APIScanner.PII_PATTERNS.items():
            assert isinstance(val, re.Pattern), f"{key} is not a compiled regex"

    def test_has_email(self):
        assert "email" in APIScanner.PII_PATTERNS

    def test_has_phone(self):
        assert "phone" in APIScanner.PII_PATTERNS

    def test_has_ssn(self):
        assert "ssn" in APIScanner.PII_PATTERNS

    def test_has_credit_card(self):
        assert "credit_card" in APIScanner.PII_PATTERNS

    def test_has_ip_address(self):
        assert "ip_address" in APIScanner.PII_PATTERNS

    def test_has_jwt(self):
        assert "jwt" in APIScanner.PII_PATTERNS

    def test_has_api_key(self):
        assert "api_key" in APIScanner.PII_PATTERNS

    def test_has_aws_key(self):
        assert "aws_key" in APIScanner.PII_PATTERNS

    def test_has_private_key(self):
        assert "private_key" in APIScanner.PII_PATTERNS

    # --- Positive matches ---

    def test_email_matches_valid(self):
        assert APIScanner.PII_PATTERNS["email"].search("user@example.com")

    def test_email_no_match_plain_text(self):
        assert not APIScanner.PII_PATTERNS["email"].search("just plain text")

    def test_phone_matches_us_format(self):
        assert APIScanner.PII_PATTERNS["phone"].search("+1-555-123-4567")

    def test_phone_no_match_short_number(self):
        assert not APIScanner.PII_PATTERNS["phone"].search("123")

    def test_ssn_matches_dashed(self):
        assert APIScanner.PII_PATTERNS["ssn"].search("123-45-6789")

    def test_ssn_no_match_letters(self):
        assert not APIScanner.PII_PATTERNS["ssn"].search("abc-de-fghi")

    def test_credit_card_matches_spaced(self):
        assert APIScanner.PII_PATTERNS["credit_card"].search("4111 1111 1111 1111")

    def test_credit_card_matches_dashed(self):
        assert APIScanner.PII_PATTERNS["credit_card"].search("4111-1111-1111-1111")

    def test_ip_matches_valid(self):
        assert APIScanner.PII_PATTERNS["ip_address"].search("192.168.1.1")

    def test_ip_no_match_text(self):
        assert not APIScanner.PII_PATTERNS["ip_address"].search("not an ip address")

    def test_jwt_matches_valid(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        assert APIScanner.PII_PATTERNS["jwt"].search(jwt)

    def test_jwt_no_match_random_string(self):
        assert not APIScanner.PII_PATTERNS["jwt"].search("not-a-jwt-token")

    def test_aws_key_matches_valid(self):
        assert APIScanner.PII_PATTERNS["aws_key"].search("AKIAIOSFODNN7EXAMPLE")

    def test_aws_key_no_match_lowercase(self):
        assert not APIScanner.PII_PATTERNS["aws_key"].search("akiaiosfodnn7example")

    def test_private_key_matches_rsa(self):
        assert APIScanner.PII_PATTERNS["private_key"].search("-----BEGIN RSA PRIVATE KEY-----")

    def test_private_key_matches_ec(self):
        assert APIScanner.PII_PATTERNS["private_key"].search("-----BEGIN EC PRIVATE KEY-----")

    def test_private_key_matches_generic(self):
        assert APIScanner.PII_PATTERNS["private_key"].search("-----BEGIN PRIVATE KEY-----")

    def test_api_key_matches_assignment(self):
        assert APIScanner.PII_PATTERNS["api_key"].search("api_key: abcdefghijklmnopqrstuvwxyz")

    def test_api_key_matches_equals(self):
        assert APIScanner.PII_PATTERNS["api_key"].search("apikey=ABCDEFGHIJKLMNOPQRST1234")


# ============================================================================
# TESTS: APIScanner.SENSITIVE_FIELD_NAMES
# ============================================================================

class TestSensitiveFieldNames:
    """Tests for APIScanner.SENSITIVE_FIELD_NAMES class constant."""

    def test_count(self):
        assert len(APIScanner.SENSITIVE_FIELD_NAMES) == 63

    def test_is_list(self):
        assert isinstance(APIScanner.SENSITIVE_FIELD_NAMES, list)

    def test_all_strings(self):
        for name in APIScanner.SENSITIVE_FIELD_NAMES:
            assert isinstance(name, str)

    def test_has_password(self):
        assert "password" in APIScanner.SENSITIVE_FIELD_NAMES

    def test_has_secret(self):
        assert "secret" in APIScanner.SENSITIVE_FIELD_NAMES

    def test_has_api_key(self):
        assert "api_key" in APIScanner.SENSITIVE_FIELD_NAMES

    def test_has_ssn(self):
        assert "ssn" in APIScanner.SENSITIVE_FIELD_NAMES

    def test_has_credit_card(self):
        assert "credit_card" in APIScanner.SENSITIVE_FIELD_NAMES

    def test_has_session_id(self):
        assert "session_id" in APIScanner.SENSITIVE_FIELD_NAMES

    def test_has_is_admin(self):
        assert "is_admin" in APIScanner.SENSITIVE_FIELD_NAMES

    def test_has_aws_key(self):
        assert "aws_key" in APIScanner.SENSITIVE_FIELD_NAMES

    def test_has_database_url(self):
        assert "database_url" in APIScanner.SENSITIVE_FIELD_NAMES

    def test_all_lowercase(self):
        """All field names should be lowercase/snake_case."""
        for name in APIScanner.SENSITIVE_FIELD_NAMES:
            assert name == name.lower(), f"{name} is not lowercase"
