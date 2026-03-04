"""
Tests for Server-Side Template Injection (SSTI) Scanner Module.

Covers:
- TemplateEngine enum (16 engines)
- SSTIVulnType enum (7 vulnerability types)
- SSTITestResult dataclass
- EngineSignature dataclass
- is_static_asset_url helper
- STATIC_ASSET_EXTENSIONS constants
- STATIC_ASSET_PATTERNS constants
- POLYGLOT_DETECTION_PAYLOADS
- ENGINE_SPECIFIC_DETECTION
- RCE_PAYLOADS per engine
- WAF_BYPASS_PAYLOADS
- BLIND_SSTI_PAYLOADS
- INFO_DISCLOSURE_PAYLOADS
- SSTIScanner constants
"""

import pytest
from dataclasses import fields

from scanning.modules.ssti_scanner import (
    TemplateEngine,
    SSTIVulnType,
    SSTITestResult,
    EngineSignature,
    is_static_asset_url,
    STATIC_ASSET_EXTENSIONS,
    STATIC_ASSET_PATTERNS,
    POLYGLOT_DETECTION_PAYLOADS,
    ENGINE_SPECIFIC_DETECTION,
    RCE_PAYLOADS,
    WAF_BYPASS_PAYLOADS,
    BLIND_SSTI_PAYLOADS,
    INFO_DISCLOSURE_PAYLOADS,
    SSTIScanner,
)


# ============================================================================
# TESTS: TemplateEngine Enum
# ============================================================================

class TestTemplateEngine:
    """Tests for TemplateEngine enum."""

    def test_has_jinja2(self):
        assert TemplateEngine.JINJA2 is not None

    def test_has_twig(self):
        assert TemplateEngine.TWIG is not None

    def test_has_freemarker(self):
        assert TemplateEngine.FREEMARKER is not None

    def test_has_velocity(self):
        assert TemplateEngine.VELOCITY is not None

    def test_has_smarty(self):
        assert TemplateEngine.SMARTY is not None

    def test_has_thymeleaf(self):
        assert TemplateEngine.THYMELEAF is not None

    def test_has_erb(self):
        assert TemplateEngine.ERB is not None

    def test_has_mako(self):
        assert TemplateEngine.MAKO is not None

    def test_has_tornado(self):
        assert TemplateEngine.TORNADO is not None

    def test_has_ejs(self):
        assert TemplateEngine.EJS is not None

    def test_has_pebble(self):
        assert TemplateEngine.PEBBLE is not None

    def test_has_handlebars(self):
        assert TemplateEngine.HANDLEBARS is not None

    def test_has_nunjucks(self):
        assert TemplateEngine.NUNJUCKS is not None

    def test_has_dust(self):
        assert TemplateEngine.DUST is not None

    def test_has_pug(self):
        assert TemplateEngine.PUG is not None

    def test_has_unknown(self):
        assert TemplateEngine.UNKNOWN is not None

    def test_total_count(self):
        assert len(TemplateEngine) == 16

    def test_all_unique(self):
        values = [e.value for e in TemplateEngine]
        assert len(values) == len(set(values))


# ============================================================================
# TESTS: SSTIVulnType Enum
# ============================================================================

class TestSSTIVulnType:
    """Tests for SSTIVulnType enum."""

    def test_has_expression_evaluation(self):
        assert SSTIVulnType.EXPRESSION_EVALUATION is not None

    def test_has_object_access(self):
        assert SSTIVulnType.OBJECT_ACCESS is not None

    def test_has_file_read(self):
        assert SSTIVulnType.FILE_READ is not None

    def test_has_remote_code_exec(self):
        assert SSTIVulnType.REMOTE_CODE_EXEC is not None

    def test_has_information_disclosure(self):
        assert SSTIVulnType.INFORMATION_DISCLOSURE is not None

    def test_has_sandbox_escape(self):
        assert SSTIVulnType.SANDBOX_ESCAPE is not None

    def test_has_blind_ssti(self):
        assert SSTIVulnType.BLIND_SSTI is not None

    def test_total_count(self):
        assert len(SSTIVulnType) == 7


# ============================================================================
# TESTS: SSTITestResult Dataclass
# ============================================================================

class TestSSTITestResult:
    """Tests for SSTITestResult dataclass."""

    def test_creates_vulnerable_result(self):
        result = SSTITestResult(
            vulnerable=True,
            engine=TemplateEngine.JINJA2,
            vuln_type=SSTIVulnType.EXPRESSION_EVALUATION,
            confidence=0.95,
            payload="{{7*7}}",
            evidence=["49"],
            response_indicator="49",
        )
        assert result.vulnerable is True
        assert result.engine == TemplateEngine.JINJA2
        assert result.confidence == 0.95

    def test_creates_not_vulnerable_result(self):
        result = SSTITestResult(vulnerable=False)
        assert result.vulnerable is False
        assert result.engine is None
        assert result.confidence == 0.0

    def test_has_required_fields(self):
        field_names = {f.name for f in fields(SSTITestResult)}
        assert "vulnerable" in field_names

    def test_has_optional_fields(self):
        field_names = {f.name for f in fields(SSTITestResult)}
        for name in ["engine", "vuln_type", "confidence", "payload", "evidence", "response_indicator"]:
            assert name in field_names

    def test_evidence_defaults_to_empty(self):
        result = SSTITestResult(vulnerable=False)
        assert result.evidence == []

    def test_rce_result(self):
        result = SSTITestResult(
            vulnerable=True,
            engine=TemplateEngine.JINJA2,
            vuln_type=SSTIVulnType.REMOTE_CODE_EXEC,
            confidence=1.0,
            payload="{{cycler.__init__.__globals__.os.popen('id').read()}}",
            evidence=["uid=33(www-data)"],
        )
        assert result.vuln_type == SSTIVulnType.REMOTE_CODE_EXEC
        assert result.confidence == 1.0


# ============================================================================
# TESTS: EngineSignature Dataclass
# ============================================================================

class TestEngineSignature:
    """Tests for EngineSignature dataclass."""

    def test_creates_signature(self):
        sig = EngineSignature(
            engine=TemplateEngine.JINJA2,
            keywords=["jinja2", "flask"],
            error_patterns=["UndefinedError"],
            behavior_tests={"{{7*7}}": "49"},
        )
        assert sig.engine == TemplateEngine.JINJA2
        assert "jinja2" in sig.keywords


# ============================================================================
# TESTS: is_static_asset_url
# ============================================================================

class TestIsStaticAssetUrl:
    """Tests for is_static_asset_url helper."""

    def test_image_extensions(self):
        assert is_static_asset_url("https://example.com/logo.png") is True
        assert is_static_asset_url("https://example.com/photo.jpg") is True
        assert is_static_asset_url("https://example.com/icon.svg") is True
        assert is_static_asset_url("https://example.com/pic.webp") is True

    def test_css_extension(self):
        assert is_static_asset_url("https://example.com/style.css") is True
        assert is_static_asset_url("https://example.com/main.scss") is True

    def test_js_extension(self):
        assert is_static_asset_url("https://example.com/app.js") is True
        assert is_static_asset_url("https://example.com/bundle.mjs") is True

    def test_font_extensions(self):
        assert is_static_asset_url("https://example.com/font.woff2") is True
        assert is_static_asset_url("https://example.com/icon.ttf") is True

    def test_document_extensions(self):
        assert is_static_asset_url("https://example.com/report.pdf") is True
        assert is_static_asset_url("https://example.com/data.xlsx") is True

    def test_archive_extensions(self):
        assert is_static_asset_url("https://example.com/backup.zip") is True
        assert is_static_asset_url("https://example.com/files.tar.gz") is True

    def test_data_file_extensions(self):
        assert is_static_asset_url("https://example.com/config.json") is True
        assert is_static_asset_url("https://example.com/data.xml") is True
        assert is_static_asset_url("https://example.com/config.yaml") is True

    def test_static_path_patterns(self):
        assert is_static_asset_url("https://example.com/static/main.css") is True
        assert is_static_asset_url("https://example.com/assets/image.png") is True
        assert is_static_asset_url("https://example.com/dist/bundle.js") is True

    def test_nextjs_static(self):
        assert is_static_asset_url("https://example.com/_next/static/chunks/main.js") is True

    def test_dynamic_urls_not_static(self):
        assert is_static_asset_url("https://example.com/api/search") is False
        assert is_static_asset_url("https://example.com/login") is False
        assert is_static_asset_url("https://example.com/user/profile") is False
        assert is_static_asset_url("https://example.com/page?id=1") is False

    def test_php_not_static(self):
        assert is_static_asset_url("https://example.com/index.php") is False
        assert is_static_asset_url("https://example.com/search.php?q=test") is False

    def test_extension_with_query_string(self):
        assert is_static_asset_url("https://example.com/style.css?v=123") is True
        assert is_static_asset_url("https://example.com/app.js?cache=abc") is True

    def test_case_insensitive(self):
        assert is_static_asset_url("https://example.com/LOGO.PNG") is True
        assert is_static_asset_url("https://example.com/Style.CSS") is True


# ============================================================================
# TESTS: STATIC_ASSET_EXTENSIONS
# ============================================================================

class TestStaticAssetExtensions:
    """Tests for static asset extension set."""

    def test_has_image_extensions(self):
        for ext in ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp']:
            assert ext in STATIC_ASSET_EXTENSIONS

    def test_has_css_extensions(self):
        assert '.css' in STATIC_ASSET_EXTENSIONS
        assert '.scss' in STATIC_ASSET_EXTENSIONS

    def test_has_js_extensions(self):
        assert '.js' in STATIC_ASSET_EXTENSIONS
        assert '.ts' in STATIC_ASSET_EXTENSIONS

    def test_has_font_extensions(self):
        assert '.woff' in STATIC_ASSET_EXTENSIONS
        assert '.woff2' in STATIC_ASSET_EXTENSIONS

    def test_has_map_extension(self):
        assert '.map' in STATIC_ASSET_EXTENSIONS

    def test_is_set_type(self):
        assert isinstance(STATIC_ASSET_EXTENSIONS, set)

    def test_all_start_with_dot(self):
        for ext in STATIC_ASSET_EXTENSIONS:
            assert ext.startswith('.'), f"Extension '{ext}' should start with '.'"


# ============================================================================
# TESTS: POLYGLOT_DETECTION_PAYLOADS
# ============================================================================

class TestPolyglotDetectionPayloads:
    """Tests for polyglot detection payloads."""

    def test_has_payloads(self):
        assert len(POLYGLOT_DETECTION_PAYLOADS) > 5

    def test_payloads_have_required_fields(self):
        for p in POLYGLOT_DETECTION_PAYLOADS:
            assert "payload" in p
            assert "expected" in p
            assert "engines" in p

    def test_uses_unique_numbers(self):
        """Should use unique multiplication (1337*997=1333189)."""
        assert any(p["expected"] == "1333189" for p in POLYGLOT_DETECTION_PAYLOADS)

    def test_jinja2_string_multiplication(self):
        """Jinja2 string multiplication should be tested."""
        assert any(p["expected"] == "7777777" for p in POLYGLOT_DETECTION_PAYLOADS)

    def test_covers_multiple_engines(self):
        all_engines = set()
        for p in POLYGLOT_DETECTION_PAYLOADS:
            all_engines.update(p["engines"])
        assert "jinja2" in all_engines
        assert "twig" in all_engines
        assert "freemarker" in all_engines
        assert "erb" in all_engines or "ejs" in all_engines

    def test_has_different_delimiter_styles(self):
        payloads = [p["payload"] for p in POLYGLOT_DETECTION_PAYLOADS]
        assert any("{{" in p for p in payloads)  # Jinja2/Twig
        assert any("${" in p for p in payloads)   # Freemarker
        assert any("<%" in p for p in payloads)   # ERB/EJS


# ============================================================================
# TESTS: ENGINE_SPECIFIC_DETECTION
# ============================================================================

class TestEngineSpecificDetection:
    """Tests for engine-specific detection payloads."""

    def test_has_jinja2(self):
        assert TemplateEngine.JINJA2 in ENGINE_SPECIFIC_DETECTION
        jinja = ENGINE_SPECIFIC_DETECTION[TemplateEngine.JINJA2]
        assert "payloads" in jinja
        assert "error_signatures" in jinja

    def test_jinja2_has_config_payload(self):
        payloads = ENGINE_SPECIFIC_DETECTION[TemplateEngine.JINJA2]["payloads"]
        assert any(p["payload"] == "{{config}}" for p in payloads)

    def test_jinja2_has_error_signatures(self):
        sigs = ENGINE_SPECIFIC_DETECTION[TemplateEngine.JINJA2]["error_signatures"]
        assert any("jinja2" in s.lower() for s in sigs)

    def test_has_twig(self):
        assert TemplateEngine.TWIG in ENGINE_SPECIFIC_DETECTION
        twig = ENGINE_SPECIFIC_DETECTION[TemplateEngine.TWIG]
        assert len(twig["payloads"]) > 0

    def test_twig_has_self_payload(self):
        payloads = ENGINE_SPECIFIC_DETECTION[TemplateEngine.TWIG]["payloads"]
        assert any("_self" in p["payload"] for p in payloads)

    def test_has_freemarker(self):
        assert TemplateEngine.FREEMARKER in ENGINE_SPECIFIC_DETECTION

    def test_freemarker_has_version_payload(self):
        payloads = ENGINE_SPECIFIC_DETECTION[TemplateEngine.FREEMARKER]["payloads"]
        assert any(".version" in p["payload"] for p in payloads)

    def test_has_velocity(self):
        assert TemplateEngine.VELOCITY in ENGINE_SPECIFIC_DETECTION

    def test_has_smarty(self):
        assert TemplateEngine.SMARTY in ENGINE_SPECIFIC_DETECTION

    def test_has_thymeleaf(self):
        assert TemplateEngine.THYMELEAF in ENGINE_SPECIFIC_DETECTION

    def test_has_erb(self):
        assert TemplateEngine.ERB in ENGINE_SPECIFIC_DETECTION

    def test_has_mako(self):
        assert TemplateEngine.MAKO in ENGINE_SPECIFIC_DETECTION

    def test_has_ejs(self):
        assert TemplateEngine.EJS in ENGINE_SPECIFIC_DETECTION

    def test_has_pebble(self):
        assert TemplateEngine.PEBBLE in ENGINE_SPECIFIC_DETECTION

    def test_has_nunjucks(self):
        assert TemplateEngine.NUNJUCKS in ENGINE_SPECIFIC_DETECTION

    def test_has_handlebars(self):
        assert TemplateEngine.HANDLEBARS in ENGINE_SPECIFIC_DETECTION

    def test_all_have_error_signatures(self):
        for engine, data in ENGINE_SPECIFIC_DETECTION.items():
            assert "error_signatures" in data, f"{engine} missing error_signatures"
            assert len(data["error_signatures"]) > 0


# ============================================================================
# TESTS: RCE_PAYLOADS
# ============================================================================

class TestRCEPayloads:
    """Tests for RCE payloads per engine."""

    def test_has_jinja2_rce(self):
        assert TemplateEngine.JINJA2 in RCE_PAYLOADS
        assert len(RCE_PAYLOADS[TemplateEngine.JINJA2]) > 5

    def test_jinja2_has_mro_traversal(self):
        payloads = RCE_PAYLOADS[TemplateEngine.JINJA2]
        assert any("__mro__" in p or "__subclasses__" in p for p in payloads)

    def test_jinja2_has_os_popen(self):
        payloads = RCE_PAYLOADS[TemplateEngine.JINJA2]
        assert any("os.popen" in p for p in payloads)

    def test_has_twig_rce(self):
        assert TemplateEngine.TWIG in RCE_PAYLOADS
        payloads = RCE_PAYLOADS[TemplateEngine.TWIG]
        assert any("system" in p or "exec" in p for p in payloads)

    def test_twig_has_filter_exploitation(self):
        payloads = RCE_PAYLOADS[TemplateEngine.TWIG]
        assert any("filter" in p for p in payloads)

    def test_has_freemarker_rce(self):
        assert TemplateEngine.FREEMARKER in RCE_PAYLOADS
        payloads = RCE_PAYLOADS[TemplateEngine.FREEMARKER]
        assert any("Execute" in p for p in payloads)

    def test_has_velocity_rce(self):
        assert TemplateEngine.VELOCITY in RCE_PAYLOADS

    def test_has_smarty_rce(self):
        assert TemplateEngine.SMARTY in RCE_PAYLOADS
        payloads = RCE_PAYLOADS[TemplateEngine.SMARTY]
        assert any("{php}" in p for p in payloads)

    def test_has_thymeleaf_rce(self):
        assert TemplateEngine.THYMELEAF in RCE_PAYLOADS
        payloads = RCE_PAYLOADS[TemplateEngine.THYMELEAF]
        assert any("Runtime" in p for p in payloads)

    def test_has_erb_rce(self):
        assert TemplateEngine.ERB in RCE_PAYLOADS
        payloads = RCE_PAYLOADS[TemplateEngine.ERB]
        assert any("system" in p for p in payloads)

    def test_has_mako_rce(self):
        assert TemplateEngine.MAKO in RCE_PAYLOADS
        payloads = RCE_PAYLOADS[TemplateEngine.MAKO]
        assert any("os" in p for p in payloads)

    def test_has_tornado_rce(self):
        assert TemplateEngine.TORNADO in RCE_PAYLOADS

    def test_has_ejs_rce(self):
        assert TemplateEngine.EJS in RCE_PAYLOADS
        payloads = RCE_PAYLOADS[TemplateEngine.EJS]
        assert any("child_process" in p for p in payloads)

    def test_has_pebble_rce(self):
        assert TemplateEngine.PEBBLE in RCE_PAYLOADS

    def test_has_nunjucks_rce(self):
        assert TemplateEngine.NUNJUCKS in RCE_PAYLOADS

    def test_has_handlebars_rce(self):
        assert TemplateEngine.HANDLEBARS in RCE_PAYLOADS


# ============================================================================
# TESTS: WAF_BYPASS_PAYLOADS
# ============================================================================

class TestWAFBypassPayloads:
    """Tests for WAF bypass payloads."""

    def test_has_payloads(self):
        assert len(WAF_BYPASS_PAYLOADS) > 10

    def test_payloads_have_required_fields(self):
        for p in WAF_BYPASS_PAYLOADS:
            assert "original" in p
            assert "bypass" in p
            assert "type" in p

    def test_has_url_encoding_bypass(self):
        types = [p["type"] for p in WAF_BYPASS_PAYLOADS]
        assert "url_encode" in types

    def test_has_double_url_encoding(self):
        types = [p["type"] for p in WAF_BYPASS_PAYLOADS]
        assert "double_url" in types

    def test_has_unicode_bypass(self):
        types = [p["type"] for p in WAF_BYPASS_PAYLOADS]
        assert "unicode" in types

    def test_has_html_entity_bypass(self):
        types = [p["type"] for p in WAF_BYPASS_PAYLOADS]
        assert "html_entity" in types

    def test_has_whitespace_bypass(self):
        types = [p["type"] for p in WAF_BYPASS_PAYLOADS]
        assert "whitespace" in types

    def test_has_comment_injection(self):
        types = [p["type"] for p in WAF_BYPASS_PAYLOADS]
        assert "comment" in types

    def test_has_string_concat_bypass(self):
        types = [p["type"] for p in WAF_BYPASS_PAYLOADS]
        assert "concat" in types or "tilde_concat" in types

    def test_has_filter_bypass(self):
        types = [p["type"] for p in WAF_BYPASS_PAYLOADS]
        assert "filter" in types

    def test_has_print_tag_bypass(self):
        types = [p["type"] for p in WAF_BYPASS_PAYLOADS]
        assert "print_tag" in types


# ============================================================================
# TESTS: BLIND_SSTI_PAYLOADS
# ============================================================================

class TestBlindSSTIPayloads:
    """Tests for blind/time-based SSTI payloads."""

    def test_has_payloads(self):
        assert len(BLIND_SSTI_PAYLOADS) >= 4

    def test_payloads_have_required_fields(self):
        for p in BLIND_SSTI_PAYLOADS:
            assert "payload" in p
            assert "engine" in p
            assert "delay" in p

    def test_has_jinja2_blind(self):
        engines = [p["engine"] for p in BLIND_SSTI_PAYLOADS]
        assert "jinja2" in engines

    def test_has_erb_blind(self):
        engines = [p["engine"] for p in BLIND_SSTI_PAYLOADS]
        assert "erb" in engines

    def test_has_thymeleaf_blind(self):
        engines = [p["engine"] for p in BLIND_SSTI_PAYLOADS]
        assert "thymeleaf" in engines

    def test_has_mako_blind(self):
        engines = [p["engine"] for p in BLIND_SSTI_PAYLOADS]
        assert "mako" in engines

    def test_delays_are_positive(self):
        for p in BLIND_SSTI_PAYLOADS:
            assert p["delay"] > 0


# ============================================================================
# TESTS: INFO_DISCLOSURE_PAYLOADS
# ============================================================================

class TestInfoDisclosurePayloads:
    """Tests for information disclosure payloads."""

    def test_has_payloads(self):
        assert len(INFO_DISCLOSURE_PAYLOADS) > 5

    def test_payloads_have_required_fields(self):
        for p in INFO_DISCLOSURE_PAYLOADS:
            assert "payload" in p
            assert "type" in p
            assert "engine" in p

    def test_has_config_disclosure(self):
        types = [p["type"] for p in INFO_DISCLOSURE_PAYLOADS]
        assert "config" in types

    def test_has_db_creds_disclosure(self):
        types = [p["type"] for p in INFO_DISCLOSURE_PAYLOADS]
        assert "db_creds" in types

    def test_has_secret_key_disclosure(self):
        types = [p["type"] for p in INFO_DISCLOSURE_PAYLOADS]
        assert "secret" in types

    def test_has_file_read_disclosure(self):
        types = [p["type"] for p in INFO_DISCLOSURE_PAYLOADS]
        assert "file_read" in types

    def test_jinja2_config_payload(self):
        jinja_payloads = [p for p in INFO_DISCLOSURE_PAYLOADS if p["engine"] == "jinja2"]
        assert any("config" in p["payload"].lower() for p in jinja_payloads)


# ============================================================================
# TESTS: SSTIScanner Constants
# ============================================================================

class TestSSTIScannerConstants:
    """Tests for SSTIScanner class constants."""

    def test_scanner_name(self):
        assert SSTIScanner.name == "ssti_scanner"

    def test_scanner_version(self):
        assert SSTIScanner.version == "2.0-enterprise"

    def test_detection_payloads_not_empty(self):
        assert len(SSTIScanner.DETECTION_PAYLOADS) > 10

    def test_detection_payloads_use_unique_numbers(self):
        """Detection payloads should use 1333189 (1337*997)."""
        values = list(SSTIScanner.DETECTION_PAYLOADS.values())
        assert "1333189" in values

    def test_detection_payloads_have_jinja2_syntax(self):
        assert "{{1337*997}}" in SSTIScanner.DETECTION_PAYLOADS

    def test_detection_payloads_have_freemarker_syntax(self):
        assert "${1337*997}" in SSTIScanner.DETECTION_PAYLOADS

    def test_detection_payloads_have_erb_syntax(self):
        assert any("<%=" in k for k in SSTIScanner.DETECTION_PAYLOADS)

    def test_detection_payloads_have_smarty_syntax(self):
        assert any("{math" in k or "{php}" in k for k in SSTIScanner.DETECTION_PAYLOADS)

    def test_detection_payloads_have_thymeleaf_syntax(self):
        assert any("[[${" in k for k in SSTIScanner.DETECTION_PAYLOADS)

    def test_rce_payloads_backward_compat(self):
        """Scanner should have string-keyed RCE payloads for backward compat."""
        assert "jinja2" in SSTIScanner.RCE_PAYLOADS
        assert "twig" in SSTIScanner.RCE_PAYLOADS
        assert "erb" in SSTIScanner.RCE_PAYLOADS

    def test_engine_signatures_not_empty(self):
        assert len(SSTIScanner.ENGINE_SIGNATURES) > 5

    def test_engine_signatures_have_jinja2(self):
        assert "jinja2" in SSTIScanner.ENGINE_SIGNATURES
        sigs = SSTIScanner.ENGINE_SIGNATURES["jinja2"]
        assert "jinja2" in sigs

    def test_engine_signatures_have_twig(self):
        assert "twig" in SSTIScanner.ENGINE_SIGNATURES

    def test_engine_signatures_have_freemarker(self):
        assert "freemarker" in SSTIScanner.ENGINE_SIGNATURES


# ============================================================================
# TESTS: Attack Scenarios
# ============================================================================

class TestAttackScenarios:
    """Tests modeling real-world SSTI attack scenarios."""

    def test_jinja2_rce_scenario(self):
        result = SSTITestResult(
            vulnerable=True,
            engine=TemplateEngine.JINJA2,
            vuln_type=SSTIVulnType.REMOTE_CODE_EXEC,
            confidence=1.0,
            payload="{{lipsum.__globals__.os.popen('id').read()}}",
            evidence=["uid=33(www-data) gid=33(www-data)"],
            response_indicator="uid=",
        )
        assert result.engine == TemplateEngine.JINJA2
        assert result.vuln_type == SSTIVulnType.REMOTE_CODE_EXEC

    def test_twig_filter_exploitation(self):
        result = SSTITestResult(
            vulnerable=True,
            engine=TemplateEngine.TWIG,
            vuln_type=SSTIVulnType.REMOTE_CODE_EXEC,
            confidence=0.95,
            payload="{{['id']|filter('system')}}",
            evidence=["uid=33(www-data)"],
        )
        assert result.engine == TemplateEngine.TWIG

    def test_thymeleaf_spel_injection(self):
        result = SSTITestResult(
            vulnerable=True,
            engine=TemplateEngine.THYMELEAF,
            vuln_type=SSTIVulnType.REMOTE_CODE_EXEC,
            confidence=0.90,
            payload="__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
            evidence=["Process"],
        )
        assert result.engine == TemplateEngine.THYMELEAF

    def test_erb_system_call(self):
        result = SSTITestResult(
            vulnerable=True,
            engine=TemplateEngine.ERB,
            vuln_type=SSTIVulnType.REMOTE_CODE_EXEC,
            confidence=1.0,
            payload="<%= system('id') %>",
            evidence=["uid=1000"],
        )
        assert result.engine == TemplateEngine.ERB

    def test_expression_evaluation_only(self):
        result = SSTITestResult(
            vulnerable=True,
            engine=TemplateEngine.JINJA2,
            vuln_type=SSTIVulnType.EXPRESSION_EVALUATION,
            confidence=0.85,
            payload="{{1337*997}}",
            evidence=["1333189"],
            response_indicator="1333189",
        )
        assert result.vuln_type == SSTIVulnType.EXPRESSION_EVALUATION
        assert "1333189" in result.evidence

    def test_info_disclosure_scenario(self):
        result = SSTITestResult(
            vulnerable=True,
            engine=TemplateEngine.JINJA2,
            vuln_type=SSTIVulnType.INFORMATION_DISCLOSURE,
            confidence=0.90,
            payload="{{config.SECRET_KEY}}",
            evidence=["super-secret-key-12345"],
        )
        assert result.vuln_type == SSTIVulnType.INFORMATION_DISCLOSURE

    def test_blind_ssti_scenario(self):
        result = SSTITestResult(
            vulnerable=True,
            engine=TemplateEngine.MAKO,
            vuln_type=SSTIVulnType.BLIND_SSTI,
            confidence=0.80,
            payload="<%import time;time.sleep(5)%>",
            evidence=["Response delayed by 5.1s (baseline 0.2s)"],
        )
        assert result.vuln_type == SSTIVulnType.BLIND_SSTI


# ============================================================================
# TESTS: Edge Cases
# ============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_static_asset_empty_url(self):
        assert is_static_asset_url("") is False

    def test_static_asset_just_extension(self):
        assert is_static_asset_url(".css") is True

    def test_static_asset_no_extension(self):
        assert is_static_asset_url("https://example.com/api") is False

    def test_ssti_result_minimal(self):
        result = SSTITestResult(vulnerable=False)
        assert result.payload == ""
        assert result.evidence == []
        assert result.response_indicator == ""

    def test_engine_signature_empty_lists(self):
        sig = EngineSignature(
            engine=TemplateEngine.UNKNOWN,
            keywords=[],
            error_patterns=[],
            behavior_tests={},
        )
        assert sig.engine == TemplateEngine.UNKNOWN
        assert len(sig.keywords) == 0

    def test_all_rce_engines_covered(self):
        """RCE payloads should cover major engines."""
        covered_engines = set(RCE_PAYLOADS.keys())
        major_engines = {
            TemplateEngine.JINJA2, TemplateEngine.TWIG, TemplateEngine.FREEMARKER,
            TemplateEngine.ERB, TemplateEngine.MAKO, TemplateEngine.EJS,
        }
        assert major_engines.issubset(covered_engines)

    def test_waf_bypass_all_have_original(self):
        for p in WAF_BYPASS_PAYLOADS:
            assert len(p["original"]) > 0
            assert len(p["bypass"]) > 0
