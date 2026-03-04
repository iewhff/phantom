"""
Tests for scanning/modules/wasm_scanner.py

Covers:
- Module-level binary constants (WASM_MAGIC, WASM_VERSION, section IDs, export kinds)
- DANGEROUS_EXPORT_PATTERNS list (count, entries, regex validity)
- SECRET_PATTERNS list (count, entries, regex validity)
- WEAK_CRYPTO_PATTERNS list (count, entries, regex validity)
- WasmExport dataclass (creation, kind_name property)
- WasmImport dataclass (creation)
- WasmAnalysis dataclass (defaults, full creation)
- WasmParser (magic check, version check, valid minimal binary)
- WasmScanner identity (name, version, ScanModule subclass, WASM_PATHS)
"""

import re

import pytest

from scanning.modules.wasm_scanner import (
    # Binary constants
    WASM_MAGIC,
    WASM_VERSION,
    SECTION_CUSTOM,
    SECTION_TYPE,
    SECTION_IMPORT,
    SECTION_FUNCTION,
    SECTION_TABLE,
    SECTION_MEMORY,
    SECTION_GLOBAL,
    SECTION_EXPORT,
    SECTION_START,
    SECTION_ELEMENT,
    SECTION_CODE,
    SECTION_DATA,
    EXPORT_FUNC,
    EXPORT_TABLE,
    EXPORT_MEMORY,
    EXPORT_GLOBAL,
    # Pattern lists
    DANGEROUS_EXPORT_PATTERNS,
    SECRET_PATTERNS,
    WEAK_CRYPTO_PATTERNS,
    # Dataclasses
    WasmExport,
    WasmImport,
    WasmAnalysis,
    # Parser
    WasmParser,
    # Scanner
    WasmScanner,
)
from scanning.vuln_scanner import ScanModule


# =============================================================================
# BINARY CONSTANTS
# =============================================================================

class TestWasmMagicAndVersion:
    """Test WASM binary constants."""

    def test_wasm_magic_value(self):
        assert WASM_MAGIC == b'\x00asm'

    def test_wasm_magic_length(self):
        assert len(WASM_MAGIC) == 4

    def test_wasm_version_value(self):
        assert WASM_VERSION == b'\x01\x00\x00\x00'

    def test_wasm_version_length(self):
        assert len(WASM_VERSION) == 4


class TestSectionIDs:
    """Test WASM section ID constants."""

    def test_section_custom(self):
        assert SECTION_CUSTOM == 0

    def test_section_type(self):
        assert SECTION_TYPE == 1

    def test_section_import(self):
        assert SECTION_IMPORT == 2

    def test_section_function(self):
        assert SECTION_FUNCTION == 3

    def test_section_table(self):
        assert SECTION_TABLE == 4

    def test_section_memory(self):
        assert SECTION_MEMORY == 5

    def test_section_global(self):
        assert SECTION_GLOBAL == 6

    def test_section_export(self):
        assert SECTION_EXPORT == 7

    def test_section_start(self):
        assert SECTION_START == 8

    def test_section_element(self):
        assert SECTION_ELEMENT == 9

    def test_section_code(self):
        assert SECTION_CODE == 10

    def test_section_data(self):
        assert SECTION_DATA == 11

    def test_section_ids_are_sequential(self):
        ids = [
            SECTION_CUSTOM, SECTION_TYPE, SECTION_IMPORT, SECTION_FUNCTION,
            SECTION_TABLE, SECTION_MEMORY, SECTION_GLOBAL, SECTION_EXPORT,
            SECTION_START, SECTION_ELEMENT, SECTION_CODE, SECTION_DATA,
        ]
        assert ids == list(range(12))

    def test_all_section_ids_unique(self):
        ids = [
            SECTION_CUSTOM, SECTION_TYPE, SECTION_IMPORT, SECTION_FUNCTION,
            SECTION_TABLE, SECTION_MEMORY, SECTION_GLOBAL, SECTION_EXPORT,
            SECTION_START, SECTION_ELEMENT, SECTION_CODE, SECTION_DATA,
        ]
        assert len(ids) == len(set(ids))


class TestExportKinds:
    """Test WASM export kind constants."""

    def test_export_func(self):
        assert EXPORT_FUNC == 0

    def test_export_table(self):
        assert EXPORT_TABLE == 1

    def test_export_memory(self):
        assert EXPORT_MEMORY == 2

    def test_export_global(self):
        assert EXPORT_GLOBAL == 3

    def test_export_kinds_unique(self):
        kinds = [EXPORT_FUNC, EXPORT_TABLE, EXPORT_MEMORY, EXPORT_GLOBAL]
        assert len(kinds) == len(set(kinds))

    def test_export_kinds_sequential(self):
        kinds = [EXPORT_FUNC, EXPORT_TABLE, EXPORT_MEMORY, EXPORT_GLOBAL]
        assert kinds == list(range(4))


# =============================================================================
# SECURITY PATTERN LISTS
# =============================================================================

class TestDangerousExportPatterns:
    """Test DANGEROUS_EXPORT_PATTERNS list."""

    def test_count(self):
        assert len(DANGEROUS_EXPORT_PATTERNS) == 17

    def test_all_tuples_of_three(self):
        for entry in DANGEROUS_EXPORT_PATTERNS:
            assert isinstance(entry, tuple)
            assert len(entry) == 3

    def test_all_severities_valid(self):
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for pattern, severity, desc in DANGEROUS_EXPORT_PATTERNS:
            assert severity in valid_severities, f"Invalid severity '{severity}' for pattern '{pattern}'"

    def test_all_regexes_compile(self):
        for pattern, severity, desc in DANGEROUS_EXPORT_PATTERNS:
            compiled = re.compile(pattern)
            assert compiled is not None

    def test_all_descriptions_non_empty(self):
        for pattern, severity, desc in DANGEROUS_EXPORT_PATTERNS:
            assert len(desc) > 0

    def test_eval_pattern_matches(self):
        pattern = DANGEROUS_EXPORT_PATTERNS[0][0]
        assert re.search(pattern, "eval")
        assert re.search(pattern, "execute")
        assert re.search(pattern, "run_code")

    def test_memory_pattern_matches(self):
        pattern = DANGEROUS_EXPORT_PATTERNS[2][0]
        assert re.search(pattern, "malloc")
        assert re.search(pattern, "free")
        assert re.search(pattern, "realloc")

    def test_system_command_pattern(self):
        pattern = DANGEROUS_EXPORT_PATTERNS[13][0]
        assert re.search(pattern, "system")
        assert re.search(pattern, "shell")
        assert re.search(pattern, "command")

    def test_critical_severity_entries_exist(self):
        critical = [e for e in DANGEROUS_EXPORT_PATTERNS if e[1] == "CRITICAL"]
        assert len(critical) >= 3

    def test_contains_crypto_patterns(self):
        crypto_descs = [d for _, _, d in DANGEROUS_EXPORT_PATTERNS if "Crypto" in d or "crypto" in d]
        assert len(crypto_descs) >= 1

    def test_contains_debug_patterns(self):
        debug_descs = [d for _, _, d in DANGEROUS_EXPORT_PATTERNS if "Debug" in d or "debug" in d or "Internal" in d]
        assert len(debug_descs) >= 1


class TestSecretPatterns:
    """Test SECRET_PATTERNS list."""

    def test_count(self):
        assert len(SECRET_PATTERNS) == 11

    def test_all_tuples_of_two(self):
        for entry in SECRET_PATTERNS:
            assert isinstance(entry, tuple)
            assert len(entry) == 2

    def test_all_regexes_compile(self):
        for pattern, desc in SECRET_PATTERNS:
            compiled = re.compile(pattern, re.IGNORECASE)
            assert compiled is not None

    def test_all_descriptions_non_empty(self):
        for pattern, desc in SECRET_PATTERNS:
            assert len(desc) > 0

    def test_aws_key_pattern_matches(self):
        pattern = SECRET_PATTERNS[3][0]
        assert re.search(pattern, "AKIAIOSFODNN7EXAMPLE")

    def test_private_key_pattern_matches(self):
        pattern = SECRET_PATTERNS[5][0]
        assert re.search(pattern, "-----BEGIN RSA PRIVATE KEY-----")
        assert re.search(pattern, "-----BEGIN PRIVATE KEY-----")
        assert re.search(pattern, "-----BEGIN EC PRIVATE KEY-----")

    def test_jwt_pattern_matches(self):
        pattern = SECRET_PATTERNS[7][0]
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"
        assert re.search(pattern, jwt)

    def test_password_pattern_matches(self):
        pattern = SECRET_PATTERNS[8][0]
        assert re.search(pattern, "password = 'mysecretpassword123'")

    def test_db_connection_pattern_matches(self):
        pattern = SECRET_PATTERNS[10][0]
        assert re.search(pattern, "postgres://user:pass@host:5432/db")
        assert re.search(pattern, "mysql://root:pass@localhost/mydb")
        assert re.search(pattern, "mongodb://admin:pass@mongo:27017/app")

    def test_contains_api_key_type(self):
        types = [desc for _, desc in SECRET_PATTERNS]
        assert "API key" in types

    def test_contains_certificate_type(self):
        types = [desc for _, desc in SECRET_PATTERNS]
        assert "Certificate" in types

    def test_contains_jwt_type(self):
        types = [desc for _, desc in SECRET_PATTERNS]
        assert "JWT token" in types


class TestWeakCryptoPatterns:
    """Test WEAK_CRYPTO_PATTERNS list."""

    def test_count(self):
        assert len(WEAK_CRYPTO_PATTERNS) == 5

    def test_all_tuples_of_two(self):
        for entry in WEAK_CRYPTO_PATTERNS:
            assert isinstance(entry, tuple)
            assert len(entry) == 2

    def test_all_regexes_compile(self):
        for pattern, desc in WEAK_CRYPTO_PATTERNS:
            compiled = re.compile(pattern)
            assert compiled is not None

    def test_md5_pattern(self):
        pattern, desc = WEAK_CRYPTO_PATTERNS[0]
        assert re.search(pattern, "md5")
        assert desc == "MD5 (weak hash)"

    def test_sha1_pattern(self):
        pattern, desc = WEAK_CRYPTO_PATTERNS[1]
        assert re.search(pattern, "sha1")
        assert desc == "SHA1 (weak hash)"

    def test_des_pattern(self):
        pattern, desc = WEAK_CRYPTO_PATTERNS[2]
        assert re.search(pattern, "des")
        assert desc == "DES (weak cipher)"

    def test_rc4_pattern(self):
        pattern, desc = WEAK_CRYPTO_PATTERNS[3]
        assert re.search(pattern, "rc4")
        assert desc == "RC4 (weak cipher)"

    def test_blowfish_pattern(self):
        pattern, desc = WEAK_CRYPTO_PATTERNS[4]
        assert re.search(pattern, "blowfish")
        assert desc == "Blowfish (deprecated)"

    def test_word_boundary_prevents_partial_match(self):
        """MD5 pattern should not match 'cmd5xxx' due to word boundary."""
        pattern = WEAK_CRYPTO_PATTERNS[0][0]
        assert not re.search(pattern, "cmd5xxx")

    def test_all_descriptions_non_empty(self):
        for pattern, desc in WEAK_CRYPTO_PATTERNS:
            assert len(desc) > 0


# =============================================================================
# DATACLASSES
# =============================================================================

class TestWasmExport:
    """Test WasmExport dataclass."""

    def test_creation(self):
        export = WasmExport(name="malloc", kind=0, index=5)
        assert export.name == "malloc"
        assert export.kind == 0
        assert export.index == 5

    def test_kind_name_function(self):
        export = WasmExport(name="test", kind=0, index=0)
        assert export.kind_name == "function"

    def test_kind_name_table(self):
        export = WasmExport(name="test", kind=1, index=0)
        assert export.kind_name == "table"

    def test_kind_name_memory(self):
        export = WasmExport(name="test", kind=2, index=0)
        assert export.kind_name == "memory"

    def test_kind_name_global(self):
        export = WasmExport(name="test", kind=3, index=0)
        assert export.kind_name == "global"

    def test_kind_name_unknown(self):
        export = WasmExport(name="test", kind=99, index=0)
        assert export.kind_name == "unknown"


class TestWasmImport:
    """Test WasmImport dataclass."""

    def test_creation(self):
        imp = WasmImport(module="env", name="memory", kind=2, index=0)
        assert imp.module == "env"
        assert imp.name == "memory"
        assert imp.kind == 2
        assert imp.index == 0

    def test_different_kinds(self):
        for kind in range(4):
            imp = WasmImport(module="env", name=f"import_{kind}", kind=kind, index=kind)
            assert imp.kind == kind


class TestWasmAnalysis:
    """Test WasmAnalysis dataclass."""

    def test_defaults(self):
        analysis = WasmAnalysis()
        assert analysis.valid is False
        assert analysis.version == 0
        assert analysis.exports == []
        assert analysis.imports == []
        assert analysis.functions_count == 0
        assert analysis.memory_pages == 0
        assert analysis.data_segments == []
        assert analysis.custom_sections == []
        assert analysis.error == ""

    def test_full_creation(self):
        exports = [WasmExport(name="main", kind=0, index=0)]
        imports = [WasmImport(module="env", name="abort", kind=0, index=0)]
        analysis = WasmAnalysis(
            valid=True,
            version=1,
            exports=exports,
            imports=imports,
            functions_count=42,
            memory_pages=256,
            data_segments=[b"hello"],
            custom_sections=["name", "producers"],
            error="",
        )
        assert analysis.valid is True
        assert analysis.version == 1
        assert len(analysis.exports) == 1
        assert analysis.exports[0].name == "main"
        assert len(analysis.imports) == 1
        assert analysis.imports[0].module == "env"
        assert analysis.functions_count == 42
        assert analysis.memory_pages == 256
        assert len(analysis.data_segments) == 1
        assert analysis.data_segments[0] == b"hello"
        assert analysis.custom_sections == ["name", "producers"]

    def test_lists_are_independent(self):
        """Each WasmAnalysis instance should have independent lists."""
        a1 = WasmAnalysis()
        a2 = WasmAnalysis()
        a1.exports.append(WasmExport(name="foo", kind=0, index=0))
        assert len(a2.exports) == 0


# =============================================================================
# WASM PARSER (static/synchronous only)
# =============================================================================

class TestWasmParser:
    """Test WasmParser with crafted binary data."""

    def test_too_small(self):
        parser = WasmParser(b"\x00as")
        result = parser.parse()
        assert result.valid is False
        assert "too small" in result.error.lower()

    def test_invalid_magic(self):
        parser = WasmParser(b"\x00BAD\x01\x00\x00\x00")
        result = parser.parse()
        assert result.valid is False
        assert "magic" in result.error.lower()

    def test_unsupported_version(self):
        parser = WasmParser(b"\x00asm\x02\x00\x00\x00")
        result = parser.parse()
        assert result.valid is False
        assert "version" in result.error.lower()

    def test_valid_minimal_wasm(self):
        """A valid WASM binary with just the header (no sections)."""
        data = b"\x00asm\x01\x00\x00\x00"
        parser = WasmParser(data)
        result = parser.parse()
        assert result.valid is True
        assert result.version == 1
        assert result.exports == []
        assert result.imports == []

    def test_empty_data(self):
        parser = WasmParser(b"")
        result = parser.parse()
        assert result.valid is False


# =============================================================================
# SCANNER IDENTITY
# =============================================================================

class TestWasmScannerIdentity:
    """Test WasmScanner class attributes and inheritance."""

    def test_is_scan_module_subclass(self):
        assert issubclass(WasmScanner, ScanModule)

    def test_name_attribute(self):
        assert WasmScanner.name == "wasm_scanner"

    def test_version_attribute(self):
        assert WasmScanner.version == "1.0.0"

    def test_instantiation(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = WasmScanner(settings)
        assert scanner.name == "wasm_scanner"

    def test_wasm_paths_count(self):
        assert len(WasmScanner.WASM_PATHS) == 9

    def test_wasm_paths_all_strings(self):
        for path in WasmScanner.WASM_PATHS:
            assert isinstance(path, str)

    def test_wasm_paths_all_start_with_slash(self):
        for path in WasmScanner.WASM_PATHS:
            assert path.startswith("/"), f"Path '{path}' does not start with '/'"

    def test_wasm_paths_all_end_with_wasm(self):
        for path in WasmScanner.WASM_PATHS:
            assert path.endswith(".wasm"), f"Path '{path}' does not end with '.wasm'"

    def test_wasm_paths_contains_pkg_app(self):
        assert "/pkg/app.wasm" in WasmScanner.WASM_PATHS

    def test_wasm_paths_contains_pkg_bg(self):
        assert "/pkg/app_bg.wasm" in WasmScanner.WASM_PATHS

    def test_wasm_paths_contains_static_app(self):
        assert "/static/app.wasm" in WasmScanner.WASM_PATHS

    def test_wasm_paths_unique(self):
        assert len(WasmScanner.WASM_PATHS) == len(set(WasmScanner.WASM_PATHS))

    def test_default_timeout(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = WasmScanner(settings)
        assert scanner.timeout == 30

    def test_has_scan_method(self):
        assert hasattr(WasmScanner, "scan")
        assert callable(getattr(WasmScanner, "scan"))

    def test_has_analyze_exports_method(self):
        assert hasattr(WasmScanner, "_analyze_exports")

    def test_has_analyze_secrets_method(self):
        assert hasattr(WasmScanner, "_analyze_secrets")

    def test_has_analyze_crypto_method(self):
        assert hasattr(WasmScanner, "_analyze_crypto")
