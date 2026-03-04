"""
Tests for scanning/modules/prototype_pollution_scanner.py

Covers:
- PPVulnType enum (8 types)
- GadgetType enum (7 types)
- PPTestResult dataclass
- LibraryVuln dataclass
- PP_PAYLOADS_BASIC constant
- PP_RCE_GADGETS constant
- URL_PP_PAYLOADS constant
- PP_DOS_PAYLOADS constant
- VULNERABLE_LIBRARIES constant
- DOM_POLLUTION_SINKS constant
- POLLUTION_INDICATORS constant
- PrototypePollutionScanner class attributes
"""

import pytest
from scanning.modules.prototype_pollution_scanner import (
    PPVulnType,
    GadgetType,
    PPTestResult,
    LibraryVuln,
    PP_PAYLOADS_BASIC,
    PP_RCE_GADGETS,
    URL_PP_PAYLOADS,
    PP_DOS_PAYLOADS,
    VULNERABLE_LIBRARIES,
    DOM_POLLUTION_SINKS,
    POLLUTION_INDICATORS,
    PrototypePollutionScanner,
)


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestPPVulnType:
    def test_count(self):
        assert len(PPVulnType) == 8

    def test_server_side(self):
        assert PPVulnType.SERVER_SIDE is not None

    def test_client_side(self):
        assert PPVulnType.CLIENT_SIDE is not None

    def test_rce_gadget(self):
        assert PPVulnType.RCE_GADGET is not None

    def test_privilege_escalation(self):
        assert PPVulnType.PRIVILEGE_ESCALATION is not None

    def test_dos(self):
        assert PPVulnType.DOS is not None

    def test_library_vuln(self):
        assert PPVulnType.LIBRARY_VULN is not None

    def test_query_param(self):
        assert PPVulnType.QUERY_PARAM is not None

    def test_json_merge(self):
        assert PPVulnType.JSON_MERGE is not None


class TestGadgetType:
    def test_count(self):
        assert len(GadgetType) == 7

    def test_ejs(self):
        assert GadgetType.EJS_OUTPUT_FUNCTION is not None

    def test_pug(self):
        assert GadgetType.PUG_COMPILE_DEBUG is not None

    def test_handlebars(self):
        assert GadgetType.HANDLEBARS_HELPERS is not None

    def test_nunjucks(self):
        assert GadgetType.NUNJUCKS_ENV is not None

    def test_express(self):
        assert GadgetType.EXPRESS_VIEW_OPTIONS is not None

    def test_lodash(self):
        assert GadgetType.LODASH_TEMPLATE is not None

    def test_jquery(self):
        assert GadgetType.JQUERY_EXTEND is not None


# =============================================================================
# DATACLASS TESTS
# =============================================================================

class TestPPTestResult:
    def test_defaults(self):
        result = PPTestResult(vulnerable=False)
        assert result.vulnerable is False
        assert result.vuln_type is None
        assert result.gadget is None
        assert result.confidence == 0.0
        assert result.payload == ""
        assert result.evidence == []
        assert result.rce_possible is False

    def test_full(self):
        result = PPTestResult(
            vulnerable=True,
            vuln_type=PPVulnType.RCE_GADGET,
            gadget=GadgetType.EJS_OUTPUT_FUNCTION,
            confidence=0.95,
            payload='{"__proto__": {"outputFunctionName": "x;..."}}',
            evidence=["RCE confirmed via EJS"],
            rce_possible=True,
        )
        assert result.rce_possible is True
        assert result.gadget == GadgetType.EJS_OUTPUT_FUNCTION


class TestLibraryVuln:
    def test_creation(self):
        vuln = LibraryVuln(
            library="lodash",
            cve="CVE-2019-10744",
            min_version="0.0.0",
            max_version="4.17.11",
            description="defaultsDeep prototype pollution",
            payload={"__proto__": {"polluted": True}},
        )
        assert vuln.library == "lodash"
        assert vuln.cve == "CVE-2019-10744"


# =============================================================================
# PP_PAYLOADS_BASIC
# =============================================================================

class TestPPPayloadsBasic:
    def test_not_empty(self):
        assert len(PP_PAYLOADS_BASIC) > 0

    def test_count(self):
        assert len(PP_PAYLOADS_BASIC) >= 15

    def test_has_proto(self):
        assert any("__proto__" in p for p in PP_PAYLOADS_BASIC)

    def test_has_constructor(self):
        assert any("constructor" in p for p in PP_PAYLOADS_BASIC)

    def test_has_nested_proto(self):
        assert any(
            isinstance(p.get("a"), dict) and "__proto__" in p["a"]
            for p in PP_PAYLOADS_BASIC
        )

    def test_has_admin_pollution(self):
        assert any(
            p.get("__proto__", {}).get("isAdmin") is True
            for p in PP_PAYLOADS_BASIC
        )

    def test_has_polluted_marker(self):
        assert any(
            p.get("__proto__", {}).get("polluted") == "true"
            for p in PP_PAYLOADS_BASIC
        )

    def test_all_are_dicts(self):
        for p in PP_PAYLOADS_BASIC:
            assert isinstance(p, dict)


# =============================================================================
# PP_RCE_GADGETS
# =============================================================================

class TestPPRCEGadgets:
    def test_not_empty(self):
        assert len(PP_RCE_GADGETS) > 0

    def test_has_ejs(self):
        assert GadgetType.EJS_OUTPUT_FUNCTION in PP_RCE_GADGETS
        payloads = PP_RCE_GADGETS[GadgetType.EJS_OUTPUT_FUNCTION]
        assert len(payloads) > 0
        assert any("outputFunctionName" in str(p) for p in payloads)

    def test_has_pug(self):
        assert GadgetType.PUG_COMPILE_DEBUG in PP_RCE_GADGETS
        payloads = PP_RCE_GADGETS[GadgetType.PUG_COMPILE_DEBUG]
        assert len(payloads) > 0

    def test_has_handlebars(self):
        assert GadgetType.HANDLEBARS_HELPERS in PP_RCE_GADGETS
        payloads = PP_RCE_GADGETS[GadgetType.HANDLEBARS_HELPERS]
        assert len(payloads) > 0

    def test_has_nunjucks(self):
        assert GadgetType.NUNJUCKS_ENV in PP_RCE_GADGETS

    def test_has_express(self):
        assert GadgetType.EXPRESS_VIEW_OPTIONS in PP_RCE_GADGETS

    def test_has_lodash(self):
        assert GadgetType.LODASH_TEMPLATE in PP_RCE_GADGETS


# =============================================================================
# URL_PP_PAYLOADS
# =============================================================================

class TestURLPPPayloads:
    def test_not_empty(self):
        assert len(URL_PP_PAYLOADS) > 0

    def test_count(self):
        assert len(URL_PP_PAYLOADS) >= 15

    def test_has_proto_bracket(self):
        assert any("__proto__[" in p for p in URL_PP_PAYLOADS)

    def test_has_proto_dot(self):
        assert any("__proto__." in p for p in URL_PP_PAYLOADS)

    def test_has_constructor(self):
        assert any("constructor" in p for p in URL_PP_PAYLOADS)

    def test_has_double_encoding(self):
        assert any("%5B" in p or "%5F" in p for p in URL_PP_PAYLOADS)

    def test_has_json_in_url(self):
        assert any("__proto__" in p and "{" in p for p in URL_PP_PAYLOADS)

    def test_all_are_strings(self):
        for p in URL_PP_PAYLOADS:
            assert isinstance(p, str)


# =============================================================================
# PP_DOS_PAYLOADS
# =============================================================================

class TestPPDOSPayloads:
    def test_not_empty(self):
        assert len(PP_DOS_PAYLOADS) > 0

    def test_has_length_overflow(self):
        assert any(
            p.get("__proto__", {}).get("length") == 999999999
            for p in PP_DOS_PAYLOADS
        )

    def test_all_are_dicts(self):
        for p in PP_DOS_PAYLOADS:
            assert isinstance(p, dict)


# =============================================================================
# VULNERABLE LIBRARIES
# =============================================================================

class TestVulnerableLibraries:
    def test_not_empty(self):
        assert len(VULNERABLE_LIBRARIES) > 0

    def test_has_lodash(self):
        lodash = [v for v in VULNERABLE_LIBRARIES if v.library == "lodash"]
        assert len(lodash) >= 2

    def test_has_jquery(self):
        jquery = [v for v in VULNERABLE_LIBRARIES if v.library == "jquery"]
        assert len(jquery) >= 1
        assert jquery[0].cve == "CVE-2019-11358"

    def test_has_minimist(self):
        minimist = [v for v in VULNERABLE_LIBRARIES if v.library == "minimist"]
        assert len(minimist) >= 1

    def test_all_have_cve(self):
        for v in VULNERABLE_LIBRARIES:
            assert v.cve.startswith("CVE-")

    def test_all_have_payload(self):
        for v in VULNERABLE_LIBRARIES:
            assert isinstance(v.payload, dict)
            assert len(v.payload) > 0

    def test_all_have_version_range(self):
        for v in VULNERABLE_LIBRARIES:
            assert v.min_version is not None
            assert v.max_version is not None


# =============================================================================
# DOM POLLUTION SINKS
# =============================================================================

class TestDOMPollutionSinks:
    def test_not_empty(self):
        assert len(DOM_POLLUTION_SINKS) > 0

    def test_count(self):
        assert len(DOM_POLLUTION_SINKS) >= 20

    def test_has_object_assign(self):
        assert "Object.assign" in DOM_POLLUTION_SINKS

    def test_has_jquery_extend(self):
        assert "$.extend" in DOM_POLLUTION_SINKS or "jQuery.extend" in DOM_POLLUTION_SINKS

    def test_has_lodash_merge(self):
        assert any("_.merge" in s for s in DOM_POLLUTION_SINKS)

    def test_has_lodash_defaults_deep(self):
        assert any("defaultsDeep" in s for s in DOM_POLLUTION_SINKS)

    def test_has_angular(self):
        assert any("angular" in s for s in DOM_POLLUTION_SINKS)

    def test_has_handlebars(self):
        assert any("Handlebars" in s for s in DOM_POLLUTION_SINKS)

    def test_all_are_strings(self):
        for s in DOM_POLLUTION_SINKS:
            assert isinstance(s, str)


# =============================================================================
# POLLUTION INDICATORS
# =============================================================================

class TestPollutionIndicators:
    def test_not_empty(self):
        assert len(POLLUTION_INDICATORS) > 0

    def test_has_polluted(self):
        assert "polluted" in POLLUTION_INDICATORS

    def test_has_isadmin(self):
        assert "isAdmin" in POLLUTION_INDICATORS

    def test_has_proto(self):
        assert "__proto__" in POLLUTION_INDICATORS


# =============================================================================
# SCANNER CLASS
# =============================================================================

class TestPrototypePollutionScannerClass:
    def test_name(self):
        assert PrototypePollutionScanner.name == "prototype_pollution_scanner"

    def test_version(self):
        assert PrototypePollutionScanner.version == "2.0-enterprise"

    def test_is_scan_module(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(PrototypePollutionScanner, ScanModule)

    def test_has_pp_payloads(self):
        assert len(PrototypePollutionScanner.PP_PAYLOADS) > 0

    def test_has_url_payloads(self):
        assert len(PrototypePollutionScanner.URL_PP_PAYLOADS) > 0

    def test_has_dom_sinks(self):
        assert len(PrototypePollutionScanner.DOM_SINKS) > 0

    def test_js_backend_indicators(self):
        assert "node.js" in PrototypePollutionScanner._JS_BACKEND_INDICATORS
        assert "express" in PrototypePollutionScanner._JS_BACKEND_INDICATORS
        assert "next.js" in PrototypePollutionScanner._JS_BACKEND_INDICATORS


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    def test_all_vuln_types_unique(self):
        values = [t.value for t in PPVulnType]
        assert len(values) == len(set(values))

    def test_all_gadget_types_unique(self):
        values = [t.value for t in GadgetType]
        assert len(values) == len(set(values))

    def test_all_rce_gadgets_covered(self):
        """All GadgetTypes except JQUERY_EXTEND should have RCE payloads."""
        for gadget in GadgetType:
            if gadget != GadgetType.JQUERY_EXTEND:
                assert gadget in PP_RCE_GADGETS, f"Missing RCE payloads for {gadget}"
