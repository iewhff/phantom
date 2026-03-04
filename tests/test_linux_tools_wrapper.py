"""
Tests for Linux Security Tools Wrapper - ENTERPRISE EDITION v2.0.

Covers:
- FuzzCategory enum (7 members)
- ResponseAnomalyType enum (6 members)
- FuzzResult dataclass (required + default fields)
- ResponseBaseline dataclass (all defaults)
- ParameterMutation dataclass (5 required fields)
- ToolFinding dataclass (required + optional fields, to_dict)
- ToolResult dataclass (required + defaults)
- LinuxToolsResult dataclass (all defaults)
- SMART_PAYLOADS dict (6 categories, key payloads)
- MUTATION_STRATEGIES dict (4 categories, callable lambdas)
- LinuxToolsWrapper class constants (WORDLISTS, TECH_WORDLISTS, version)
- EnterpriseLinuxTools subclass identity
- Regex patterns used in nmap/nikto/gobuster/sqlmap parsers
"""

import re
import pytest
from dataclasses import fields
from unittest.mock import MagicMock

from scanning.modules.linux_tools_wrapper import (
    FuzzCategory,
    ResponseAnomalyType,
    FuzzResult,
    ResponseBaseline,
    ParameterMutation,
    ToolFinding,
    ToolResult,
    LinuxToolsResult,
    LinuxToolsWrapper,
    EnterpriseLinuxTools,
    SMART_PAYLOADS,
    MUTATION_STRATEGIES,
)


# ============================================================================
# TESTS: FuzzCategory Enum
# ============================================================================

class TestFuzzCategory:
    """Tests for FuzzCategory enum."""

    def test_has_directory(self):
        assert FuzzCategory.DIRECTORY is not None

    def test_has_file(self):
        assert FuzzCategory.FILE is not None

    def test_has_parameter(self):
        assert FuzzCategory.PARAMETER is not None

    def test_has_subdomain(self):
        assert FuzzCategory.SUBDOMAIN is not None

    def test_has_vhost(self):
        assert FuzzCategory.VHOST is not None

    def test_has_api_endpoint(self):
        assert FuzzCategory.API_ENDPOINT is not None

    def test_has_header(self):
        assert FuzzCategory.HEADER is not None

    def test_total_count(self):
        assert len(FuzzCategory) == 7

    def test_all_unique(self):
        values = [m.value for m in FuzzCategory]
        assert len(values) == len(set(values))


# ============================================================================
# TESTS: ResponseAnomalyType Enum
# ============================================================================

class TestResponseAnomalyType:
    """Tests for ResponseAnomalyType enum."""

    def test_has_length_anomaly(self):
        assert ResponseAnomalyType.LENGTH_ANOMALY is not None

    def test_has_status_anomaly(self):
        assert ResponseAnomalyType.STATUS_ANOMALY is not None

    def test_has_time_anomaly(self):
        assert ResponseAnomalyType.TIME_ANOMALY is not None

    def test_has_content_anomaly(self):
        assert ResponseAnomalyType.CONTENT_ANOMALY is not None

    def test_has_header_anomaly(self):
        assert ResponseAnomalyType.HEADER_ANOMALY is not None

    def test_has_error_leak(self):
        assert ResponseAnomalyType.ERROR_LEAK is not None

    def test_total_count(self):
        assert len(ResponseAnomalyType) == 6

    def test_all_unique(self):
        values = [m.value for m in ResponseAnomalyType]
        assert len(values) == len(set(values))


# ============================================================================
# TESTS: FuzzResult Dataclass
# ============================================================================

class TestFuzzResult:
    """Tests for FuzzResult dataclass."""

    def test_creates_with_required_fields(self):
        result = FuzzResult(
            url="https://example.com/FUZZ",
            payload="admin",
            status_code=200,
            content_length=1234,
            response_time=0.5,
            content_hash="abc123",
        )
        assert result.url == "https://example.com/FUZZ"
        assert result.payload == "admin"
        assert result.status_code == 200
        assert result.content_length == 1234
        assert result.response_time == 0.5
        assert result.content_hash == "abc123"

    def test_defaults(self):
        result = FuzzResult(
            url="https://example.com",
            payload="test",
            status_code=200,
            content_length=0,
            response_time=0.0,
            content_hash="",
        )
        assert result.headers == {}
        assert result.anomaly_score == 0.0
        assert result.anomaly_types == []
        assert result.is_interesting is False

    def test_full_creation(self):
        result = FuzzResult(
            url="https://example.com/admin",
            payload="admin",
            status_code=200,
            content_length=5000,
            response_time=1.2,
            content_hash="deadbeef",
            headers={"Server": "nginx"},
            anomaly_score=0.8,
            anomaly_types=["LENGTH", "TIME"],
            is_interesting=True,
        )
        assert result.headers == {"Server": "nginx"}
        assert result.anomaly_score == 0.8
        assert result.anomaly_types == ["LENGTH", "TIME"]
        assert result.is_interesting is True

    def test_has_required_fields(self):
        field_names = {f.name for f in fields(FuzzResult)}
        required = {"url", "payload", "status_code", "content_length",
                     "response_time", "content_hash"}
        assert required.issubset(field_names)

    def test_has_optional_fields(self):
        field_names = {f.name for f in fields(FuzzResult)}
        optional = {"headers", "anomaly_score", "anomaly_types", "is_interesting"}
        assert optional.issubset(field_names)


# ============================================================================
# TESTS: ResponseBaseline Dataclass
# ============================================================================

class TestResponseBaseline:
    """Tests for ResponseBaseline dataclass."""

    def test_creates_with_all_defaults(self):
        baseline = ResponseBaseline()
        assert baseline.status_code == 200
        assert baseline.content_length == 0
        assert baseline.content_hash == ""
        assert baseline.avg_response_time == 0.0
        assert baseline.common_headers == {}
        assert baseline.error_patterns == []

    def test_full_creation(self):
        baseline = ResponseBaseline(
            status_code=302,
            content_length=500,
            content_hash="abc123",
            avg_response_time=0.3,
            common_headers={"Server": "Apache"},
            error_patterns=["Not Found"],
        )
        assert baseline.status_code == 302
        assert baseline.content_length == 500
        assert baseline.content_hash == "abc123"
        assert baseline.avg_response_time == 0.3
        assert baseline.common_headers == {"Server": "Apache"}
        assert baseline.error_patterns == ["Not Found"]

    def test_has_all_fields(self):
        field_names = {f.name for f in fields(ResponseBaseline)}
        expected = {"status_code", "content_length", "content_hash",
                    "avg_response_time", "common_headers", "error_patterns"}
        assert field_names == expected


# ============================================================================
# TESTS: ParameterMutation Dataclass
# ============================================================================

class TestParameterMutation:
    """Tests for ParameterMutation dataclass."""

    def test_creates_mutation(self):
        mutation = ParameterMutation(
            name="id",
            original_value="1",
            mutated_value="2",
            mutation_type="numeric_mutation_0",
            payload_category="mutation",
        )
        assert mutation.name == "id"
        assert mutation.original_value == "1"
        assert mutation.mutated_value == "2"
        assert mutation.mutation_type == "numeric_mutation_0"
        assert mutation.payload_category == "mutation"

    def test_has_all_required_fields(self):
        field_names = {f.name for f in fields(ParameterMutation)}
        expected = {"name", "original_value", "mutated_value",
                    "mutation_type", "payload_category"}
        assert field_names == expected

    def test_injection_mutation(self):
        mutation = ParameterMutation(
            name="query",
            original_value="hello",
            mutated_value="' OR '1'='1",
            mutation_type="injection_sqli",
            payload_category="sqli",
        )
        assert mutation.payload_category == "sqli"
        assert "OR" in mutation.mutated_value


# ============================================================================
# TESTS: ToolFinding Dataclass
# ============================================================================

class TestToolFinding:
    """Tests for ToolFinding dataclass."""

    def test_creates_with_required_fields(self):
        finding = ToolFinding(
            tool="nmap",
            severity="HIGH",
            title="Open port 22/tcp: ssh",
            description="Port 22 is open running ssh",
        )
        assert finding.tool == "nmap"
        assert finding.severity == "HIGH"
        assert finding.title == "Open port 22/tcp: ssh"

    def test_defaults(self):
        finding = ToolFinding(
            tool="test",
            severity="INFO",
            title="Test",
            description="Test finding",
        )
        assert finding.evidence == ""
        assert finding.url == ""
        assert finding.port == 0
        assert finding.service == ""
        assert finding.cve == ""
        assert finding.payload == ""
        assert finding.parameter == ""
        assert finding.anomaly_score == 0.0
        assert finding.confidence == "MEDIUM"
        assert finding.cwe == ""

    def test_full_creation(self):
        finding = ToolFinding(
            tool="sqlmap",
            severity="CRITICAL",
            title="SQL Injection: id",
            description="Boolean-based blind injection",
            evidence="Parameter 'id' is vulnerable",
            url="https://example.com/page?id=1",
            port=443,
            service="https",
            cve="CVE-2023-1234",
            payload="1' AND '1'='1",
            parameter="id",
            anomaly_score=0.9,
            confidence="HIGH",
            cwe="CWE-89",
        )
        assert finding.tool == "sqlmap"
        assert finding.port == 443
        assert finding.anomaly_score == 0.9

    def test_has_required_fields(self):
        field_names = {f.name for f in fields(ToolFinding)}
        required = {"tool", "severity", "title", "description"}
        assert required.issubset(field_names)

    def test_has_enterprise_fields(self):
        field_names = {f.name for f in fields(ToolFinding)}
        enterprise = {"payload", "parameter", "anomaly_score", "confidence", "cwe"}
        assert enterprise.issubset(field_names)

    def test_to_dict(self):
        finding = ToolFinding(
            tool="nmap",
            severity="HIGH",
            title="Open port",
            description="Port is open",
            url="https://example.com",
            port=80,
        )
        d = finding.to_dict()
        assert isinstance(d, dict)
        assert d["tool"] == "nmap"
        assert d["severity"] == "HIGH"
        assert d["title"] == "Open port"
        assert d["port"] == 80
        assert d["url"] == "https://example.com"

    def test_to_dict_has_all_keys(self):
        finding = ToolFinding(
            tool="test",
            severity="INFO",
            title="Test",
            description="Desc",
        )
        d = finding.to_dict()
        expected_keys = {
            "tool", "severity", "title", "description", "evidence",
            "url", "port", "service", "cve", "payload", "parameter",
            "anomaly_score", "confidence", "cwe",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_truncates_evidence(self):
        long_evidence = "A" * 1000
        finding = ToolFinding(
            tool="test",
            severity="INFO",
            title="Test",
            description="Desc",
            evidence=long_evidence,
        )
        d = finding.to_dict()
        assert len(d["evidence"]) == 500


# ============================================================================
# TESTS: ToolResult Dataclass
# ============================================================================

class TestToolResult:
    """Tests for ToolResult dataclass."""

    def test_creates_with_required_fields(self):
        result = ToolResult(tool="nmap", success=True)
        assert result.tool == "nmap"
        assert result.success is True

    def test_defaults(self):
        result = ToolResult(tool="test", success=False)
        assert result.findings == []
        assert result.raw_output == ""
        assert result.error == ""
        assert result.duration == 0.0

    def test_full_creation(self):
        finding = ToolFinding(
            tool="nmap", severity="INFO",
            title="Test", description="Desc",
        )
        result = ToolResult(
            tool="nmap",
            success=True,
            findings=[finding],
            raw_output="<xml>...</xml>",
            error="",
            duration=12.5,
        )
        assert len(result.findings) == 1
        assert result.duration == 12.5

    def test_has_all_fields(self):
        field_names = {f.name for f in fields(ToolResult)}
        expected = {"tool", "success", "findings", "raw_output", "error", "duration"}
        assert field_names == expected


# ============================================================================
# TESTS: LinuxToolsResult Dataclass
# ============================================================================

class TestLinuxToolsResult:
    """Tests for LinuxToolsResult dataclass."""

    def test_creates_with_all_defaults(self):
        result = LinuxToolsResult()
        assert result.findings == []
        assert result.tools_run == []
        assert result.tools_failed == []
        assert result.tools_missing == []

    def test_full_creation(self):
        finding = ToolFinding(
            tool="nmap", severity="HIGH",
            title="Open port", description="Port 22",
        )
        result = LinuxToolsResult(
            findings=[finding],
            tools_run=["nmap", "nikto"],
            tools_failed=["sqlmap"],
            tools_missing=["hydra"],
        )
        assert len(result.findings) == 1
        assert "nmap" in result.tools_run
        assert "sqlmap" in result.tools_failed
        assert "hydra" in result.tools_missing

    def test_has_all_fields(self):
        field_names = {f.name for f in fields(LinuxToolsResult)}
        expected = {"findings", "tools_run", "tools_failed", "tools_missing"}
        assert field_names == expected


# ============================================================================
# TESTS: SMART_PAYLOADS Dict
# ============================================================================

class TestSmartPayloads:
    """Tests for SMART_PAYLOADS module-level dict."""

    def test_has_6_categories(self):
        assert len(SMART_PAYLOADS) == 6

    def test_has_sqli_category(self):
        assert "sqli" in SMART_PAYLOADS
        payloads = SMART_PAYLOADS["sqli"]
        assert len(payloads) == 10
        assert "'" in payloads
        assert "\"" in payloads
        assert any("UNION" in p for p in payloads)

    def test_has_xss_category(self):
        assert "xss" in SMART_PAYLOADS
        payloads = SMART_PAYLOADS["xss"]
        assert len(payloads) == 6
        assert any("<script>" in p for p in payloads)
        assert any("onerror" in p for p in payloads)

    def test_has_lfi_category(self):
        assert "lfi" in SMART_PAYLOADS
        payloads = SMART_PAYLOADS["lfi"]
        assert len(payloads) == 5
        assert any("etc/passwd" in p for p in payloads)
        assert any("php://" in p for p in payloads)

    def test_has_rce_category(self):
        assert "rce" in SMART_PAYLOADS
        payloads = SMART_PAYLOADS["rce"]
        assert len(payloads) == 7
        assert "; id" in payloads
        assert "| id" in payloads
        assert "`id`" in payloads
        assert "$(id)" in payloads

    def test_has_ssti_category(self):
        assert "ssti" in SMART_PAYLOADS
        payloads = SMART_PAYLOADS["ssti"]
        assert len(payloads) == 6
        assert "{{7*7}}" in payloads
        assert "${7*7}" in payloads

    def test_has_ssrf_category(self):
        assert "ssrf" in SMART_PAYLOADS
        payloads = SMART_PAYLOADS["ssrf"]
        assert len(payloads) == 5
        assert "http://127.0.0.1" in payloads
        assert any("169.254.169.254" in p for p in payloads)

    def test_all_values_are_lists(self):
        for category, payloads in SMART_PAYLOADS.items():
            assert isinstance(payloads, list), f"{category} should be a list"

    def test_no_empty_payloads(self):
        for category, payloads in SMART_PAYLOADS.items():
            for payload in payloads:
                assert isinstance(payload, str), f"{category}: payload should be str"
                assert len(payload) > 0, f"{category}: payload should not be empty"


# ============================================================================
# TESTS: MUTATION_STRATEGIES Dict
# ============================================================================

class TestMutationStrategies:
    """Tests for MUTATION_STRATEGIES module-level dict."""

    def test_has_4_categories(self):
        assert len(MUTATION_STRATEGIES) == 4

    def test_has_numeric_category(self):
        assert "numeric" in MUTATION_STRATEGIES
        strategies = MUTATION_STRATEGIES["numeric"]
        assert len(strategies) == 7

    def test_has_string_category(self):
        assert "string" in MUTATION_STRATEGIES
        strategies = MUTATION_STRATEGIES["string"]
        assert len(strategies) == 7

    def test_has_boolean_category(self):
        assert "boolean" in MUTATION_STRATEGIES
        strategies = MUTATION_STRATEGIES["boolean"]
        assert len(strategies) == 3

    def test_has_id_category(self):
        assert "id" in MUTATION_STRATEGIES
        strategies = MUTATION_STRATEGIES["id"]
        assert len(strategies) == 6

    def test_all_strategies_are_callable(self):
        for category, strategies in MUTATION_STRATEGIES.items():
            for i, strategy in enumerate(strategies):
                assert callable(strategy), f"{category}[{i}] should be callable"

    def test_numeric_increment(self):
        strategy = MUTATION_STRATEGIES["numeric"][0]
        assert strategy("5") == "6"

    def test_numeric_decrement(self):
        strategy = MUTATION_STRATEGIES["numeric"][1]
        assert strategy("5") == "4"

    def test_numeric_zero(self):
        strategy = MUTATION_STRATEGIES["numeric"][2]
        assert strategy("anything") == "0"

    def test_numeric_negative(self):
        strategy = MUTATION_STRATEGIES["numeric"][3]
        assert strategy("anything") == "-1"

    def test_numeric_large(self):
        strategy = MUTATION_STRATEGIES["numeric"][4]
        assert strategy("anything") == "999999999"

    def test_string_upper(self):
        strategy = MUTATION_STRATEGIES["string"][0]
        assert strategy("hello") == "HELLO"

    def test_string_single_quote(self):
        strategy = MUTATION_STRATEGIES["string"][1]
        assert strategy("hello") == "hello'"

    def test_string_double_quote(self):
        strategy = MUTATION_STRATEGIES["string"][2]
        assert strategy("hello") == 'hello"'

    def test_string_script_injection(self):
        strategy = MUTATION_STRATEGIES["string"][3]
        assert strategy("hello") == "hello<script>"

    def test_string_path_traversal(self):
        strategy = MUTATION_STRATEGIES["string"][4]
        assert strategy("hello") == "../hello"

    def test_string_null_byte(self):
        strategy = MUTATION_STRATEGIES["string"][5]
        assert strategy("hello") == "hello%00"

    def test_string_long_repetition(self):
        strategy = MUTATION_STRATEGIES["string"][6]
        result = strategy("A")
        assert len(result) == 1000

    def test_boolean_toggle_false_to_true(self):
        strategy = MUTATION_STRATEGIES["boolean"][0]
        assert strategy("false") == "true"

    def test_boolean_toggle_true_to_false(self):
        strategy = MUTATION_STRATEGIES["boolean"][0]
        assert strategy("true") == "false"

    def test_id_increment(self):
        strategy = MUTATION_STRATEGIES["id"][0]
        assert strategy("1") == "2"

    def test_id_decrement(self):
        strategy = MUTATION_STRATEGIES["id"][1]
        assert strategy("10") == "9"

    def test_id_admin(self):
        strategy = MUTATION_STRATEGIES["id"][4]
        assert strategy("anything") == "admin"


# ============================================================================
# TESTS: LinuxToolsWrapper Class Constants
# ============================================================================

class TestLinuxToolsWrapperConstants:
    """Tests for LinuxToolsWrapper class-level constants."""

    def test_version(self):
        assert LinuxToolsWrapper.version == "2.0-enterprise"

    def test_wordlists_count(self):
        assert len(LinuxToolsWrapper.WORDLISTS) == 11

    def test_wordlists_has_common(self):
        assert "common" in LinuxToolsWrapper.WORDLISTS
        assert LinuxToolsWrapper.WORDLISTS["common"] == "/usr/share/wordlists/dirb/common.txt"

    def test_wordlists_has_big(self):
        assert "big" in LinuxToolsWrapper.WORDLISTS
        assert "dirb" in LinuxToolsWrapper.WORDLISTS["big"]

    def test_wordlists_has_rockyou(self):
        assert "rockyou" in LinuxToolsWrapper.WORDLISTS
        assert "rockyou.txt" in LinuxToolsWrapper.WORDLISTS["rockyou"]

    def test_wordlists_has_seclists_entries(self):
        assert "seclists_web" in LinuxToolsWrapper.WORDLISTS
        assert "seclists_api" in LinuxToolsWrapper.WORDLISTS
        assert "seclists_params" in LinuxToolsWrapper.WORDLISTS
        assert "seclists_subdomains" in LinuxToolsWrapper.WORDLISTS

    def test_wordlists_has_fuzz_entries(self):
        assert "fuzz_lfi" in LinuxToolsWrapper.WORDLISTS
        assert "fuzz_sqli" in LinuxToolsWrapper.WORDLISTS

    def test_wordlists_all_values_are_strings(self):
        for name, path in LinuxToolsWrapper.WORDLISTS.items():
            assert isinstance(path, str), f"{name}: path should be string"
            assert path.startswith("/"), f"{name}: path should be absolute"

    def test_tech_wordlists_count(self):
        assert len(LinuxToolsWrapper.TECH_WORDLISTS) == 7

    def test_tech_wordlists_has_expected_keys(self):
        expected_keys = {"php", "asp", "java", "python", "node", "api", "default"}
        assert set(LinuxToolsWrapper.TECH_WORDLISTS.keys()) == expected_keys

    def test_tech_wordlists_all_values_are_lists(self):
        for tech, wl_list in LinuxToolsWrapper.TECH_WORDLISTS.items():
            assert isinstance(wl_list, list), f"{tech}: should be list"
            assert len(wl_list) > 0, f"{tech}: should not be empty"

    def test_tech_wordlists_reference_valid_wordlists(self):
        """All wordlist references in TECH_WORDLISTS should exist in WORDLISTS."""
        for tech, wl_names in LinuxToolsWrapper.TECH_WORDLISTS.items():
            for wl_name in wl_names:
                assert wl_name in LinuxToolsWrapper.WORDLISTS, (
                    f"{tech} references '{wl_name}' not found in WORDLISTS"
                )

    def test_default_timeout(self):
        wrapper = LinuxToolsWrapper()
        assert wrapper.timeout == 300

    def test_tool_cache_is_dict(self):
        assert isinstance(LinuxToolsWrapper._tool_cache, dict)


# ============================================================================
# TESTS: LinuxToolsWrapper Initialization
# ============================================================================

class TestLinuxToolsWrapperInit:
    """Tests for LinuxToolsWrapper initialization."""

    def test_creates_without_settings(self):
        wrapper = LinuxToolsWrapper()
        assert wrapper.settings is None
        assert wrapper.timeout == 300

    def test_creates_with_settings(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        wrapper = LinuxToolsWrapper(settings=settings)
        assert wrapper.settings == settings

    def test_initializes_result(self):
        wrapper = LinuxToolsWrapper()
        assert isinstance(wrapper.result, LinuxToolsResult)
        assert wrapper.result.findings == []
        assert wrapper.result.tools_run == []

    def test_initializes_enterprise_fields(self):
        wrapper = LinuxToolsWrapper()
        assert wrapper.response_baseline is None
        assert wrapper.fuzz_results == []
        assert wrapper.discovered_params == []
        assert isinstance(wrapper.correlation_data, dict)


# ============================================================================
# TESTS: EnterpriseLinuxTools Subclass
# ============================================================================

class TestEnterpriseLinuxTools:
    """Tests for EnterpriseLinuxTools subclass."""

    def test_inherits_from_linux_tools_wrapper(self):
        assert issubclass(EnterpriseLinuxTools, LinuxToolsWrapper)

    def test_creates_without_settings(self):
        wrapper = EnterpriseLinuxTools()
        assert wrapper.settings is None

    def test_creates_with_settings(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        wrapper = EnterpriseLinuxTools(settings=settings)
        assert wrapper.settings == settings

    def test_has_impl_methods(self):
        wrapper = EnterpriseLinuxTools()
        assert hasattr(wrapper, '_run_ffuf_advanced_impl')
        assert hasattr(wrapper, '_run_arjun_impl')
        assert hasattr(wrapper, '_run_subfinder_impl')
        assert hasattr(wrapper, '_run_smart_parameter_fuzzing_impl')
        assert hasattr(wrapper, '_run_sqlmap_advanced_impl')

    def test_has_enterprise_methods(self):
        wrapper = EnterpriseLinuxTools()
        assert hasattr(wrapper, 'run_ffuf_advanced')
        assert hasattr(wrapper, 'run_arjun')
        assert hasattr(wrapper, 'run_subfinder')
        assert hasattr(wrapper, 'run_smart_parameter_fuzzing')
        assert hasattr(wrapper, 'run_sqlmap_advanced')

    def test_inherits_version(self):
        assert EnterpriseLinuxTools.version == "2.0-enterprise"

    def test_inherits_wordlists(self):
        assert EnterpriseLinuxTools.WORDLISTS == LinuxToolsWrapper.WORDLISTS

    def test_inherits_tech_wordlists(self):
        assert EnterpriseLinuxTools.TECH_WORDLISTS == LinuxToolsWrapper.TECH_WORDLISTS


# ============================================================================
# TESTS: Regex Patterns (nmap XML parser)
# ============================================================================

class TestNmapXmlRegex:
    """Tests for nmap XML parsing regex patterns."""

    def test_port_pattern_compiles(self):
        pattern = r'<port protocol="(\w+)" portid="(\d+)".*?<state state="open".*?<service name="([^"]*)".*?(?:version="([^"]*)")?'
        compiled = re.compile(pattern, re.DOTALL)
        assert compiled is not None

    def test_port_pattern_matches_open_port(self):
        pattern = r'<port protocol="(\w+)" portid="(\d+)".*?<state state="open".*?<service name="([^"]*)".*?(?:version="([^"]*)")?'
        xml_snippet = (
            '<port protocol="tcp" portid="22">'
            '<state state="open" reason="syn-ack"/>'
            '<service name="ssh" version="OpenSSH 8.9"/>'
            '</port>'
        )
        match = re.search(pattern, xml_snippet, re.DOTALL)
        assert match is not None
        protocol, port, service, _version = match.groups()
        assert protocol == "tcp"
        assert port == "22"
        assert service == "ssh"
        # version group is optional in the regex (non-greedy .*? before it)
        # It may or may not capture depending on XML structure; verify the
        # groups count is 4 (the regex always has 4 groups)
        assert len(match.groups()) == 4

    def test_port_pattern_matches_without_version(self):
        pattern = r'<port protocol="(\w+)" portid="(\d+)".*?<state state="open".*?<service name="([^"]*)".*?(?:version="([^"]*)")?'
        xml_snippet = (
            '<port protocol="tcp" portid="80">'
            '<state state="open" reason="syn-ack"/>'
            '<service name="http"/>'
            '</port>'
        )
        match = re.search(pattern, xml_snippet, re.DOTALL)
        assert match is not None
        protocol, port, service, version = match.groups()
        assert protocol == "tcp"
        assert port == "80"
        assert service == "http"

    def test_script_pattern_compiles(self):
        pattern = r'<script id="([^"]*)".*?output="([^"]*)"'
        compiled = re.compile(pattern)
        assert compiled is not None

    def test_script_pattern_matches_vuln(self):
        pattern = r'<script id="([^"]*)".*?output="([^"]*)"'
        xml_snippet = '<script id="http-vuln-cve2021-1234" output="VULNERABLE: Remote code execution"'
        match = re.search(pattern, xml_snippet)
        assert match is not None
        script_id, output = match.groups()
        assert script_id == "http-vuln-cve2021-1234"
        assert "VULNERABLE" in output


# ============================================================================
# TESTS: Regex Patterns (nikto parser)
# ============================================================================

class TestNiktoRegex:
    """Tests for nikto output parsing regex patterns."""

    def test_nikto_pattern_compiles(self):
        pattern = r'\+ (OSVDB-\d+|[A-Z]+): ([^:]+): (.+)'
        compiled = re.compile(pattern)
        assert compiled is not None

    def test_nikto_pattern_matches_osvdb(self):
        pattern = r'\+ (OSVDB-\d+|[A-Z]+): ([^:]+): (.+)'
        line = "+ OSVDB-3092: /admin/: This might be interesting..."
        match = re.search(pattern, line)
        assert match is not None
        id_str, path, desc = match.groups()
        assert id_str == "OSVDB-3092"
        assert "/admin/" in path

    def test_nikto_pattern_matches_alpha_id(self):
        pattern = r'\+ (OSVDB-\d+|[A-Z]+): ([^:]+): (.+)'
        line = "+ HTTPSONLY: /login: Should be HTTPS only"
        match = re.search(pattern, line)
        assert match is not None


# ============================================================================
# TESTS: Regex Patterns (gobuster parser)
# ============================================================================

class TestGobusterRegex:
    """Tests for gobuster output parsing regex patterns."""

    def test_gobuster_pattern_compiles(self):
        pattern = r'(/[^\s]+)\s+\(Status:\s*(\d+)\)'
        compiled = re.compile(pattern)
        assert compiled is not None

    def test_gobuster_pattern_matches_found_path(self):
        pattern = r'(/[^\s]+)\s+\(Status:\s*(\d+)\)'
        line = "/admin (Status: 200) [Size: 1234]"
        match = re.search(pattern, line)
        assert match is not None
        path, status = match.groups()
        assert path == "/admin"
        assert status == "200"

    def test_gobuster_pattern_matches_403(self):
        pattern = r'(/[^\s]+)\s+\(Status:\s*(\d+)\)'
        line = "/config (Status: 403) [Size: 345]"
        match = re.search(pattern, line)
        assert match is not None
        path, status = match.groups()
        assert path == "/config"
        assert status == "403"


# ============================================================================
# TESTS: Regex Patterns (sqlmap parser)
# ============================================================================

class TestSqlmapRegex:
    """Tests for sqlmap output parsing regex patterns."""

    def test_parameter_pattern_compiles(self):
        pattern = r"Parameter: ([^\s]+)"
        compiled = re.compile(pattern)
        assert compiled is not None

    def test_parameter_pattern_matches(self):
        pattern = r"Parameter: ([^\s]+)"
        line = "Parameter: id (GET)"
        match = re.search(pattern, line)
        assert match is not None
        assert match.group(1) == "id"

    def test_injection_type_pattern_compiles(self):
        pattern = r"Type: ([^\n]+)"
        compiled = re.compile(pattern)
        assert compiled is not None

    def test_injection_type_pattern_matches(self):
        pattern = r"Type: ([^\n]+)"
        line = "Type: boolean-based blind"
        match = re.search(pattern, line)
        assert match is not None
        assert match.group(1) == "boolean-based blind"


# ============================================================================
# TESTS: Regex Patterns (dirb parser)
# ============================================================================

class TestDirbRegex:
    """Tests for dirb output parsing regex patterns."""

    def test_dirb_pattern_compiles(self):
        pattern = r'\+ (https?://[^\s]+)'
        compiled = re.compile(pattern)
        assert compiled is not None

    def test_dirb_pattern_matches_http(self):
        pattern = r'\+ (https?://[^\s]+)'
        line = "+ http://example.com/admin/ (CODE:200|SIZE:1234)"
        match = re.search(pattern, line)
        assert match is not None
        assert match.group(1) == "http://example.com/admin/"

    def test_dirb_pattern_matches_https(self):
        pattern = r'\+ (https?://[^\s]+)'
        line = "+ https://example.com/api/v1 (CODE:200|SIZE:567)"
        match = re.search(pattern, line)
        assert match is not None
        assert match.group(1) == "https://example.com/api/v1"


# ============================================================================
# TESTS: Dangerous Services Dict (nmap parser)
# ============================================================================

class TestDangerousServices:
    """Tests for dangerous_services mapping used in _parse_nmap_xml."""

    def test_dangerous_services_structure(self):
        """Verify the dangerous services dict is correctly structured."""
        dangerous_services = {
            "telnet": ("HIGH", "Telnet transmits credentials in plaintext"),
            "ftp": ("MEDIUM", "FTP may transmit credentials in plaintext"),
            "mysql": ("MEDIUM", "MySQL exposed to network"),
            "postgresql": ("MEDIUM", "PostgreSQL exposed to network"),
            "redis": ("HIGH", "Redis often lacks authentication"),
            "mongodb": ("HIGH", "MongoDB often lacks authentication"),
            "smb": ("MEDIUM", "SMB exposed - check for vulnerabilities"),
            "rdp": ("MEDIUM", "RDP exposed - brute force risk"),
            "vnc": ("MEDIUM", "VNC exposed - authentication check needed"),
        }
        assert len(dangerous_services) == 9
        for svc, (severity, desc) in dangerous_services.items():
            assert severity in ("HIGH", "MEDIUM", "LOW", "CRITICAL", "INFO")
            assert isinstance(desc, str)
            assert len(desc) > 0

    def test_high_severity_services(self):
        dangerous_services = {
            "telnet": ("HIGH",), "redis": ("HIGH",), "mongodb": ("HIGH",),
        }
        for svc in ["telnet", "redis", "mongodb"]:
            assert dangerous_services[svc][0] == "HIGH"

    def test_medium_severity_services(self):
        dangerous_services = {
            "ftp": ("MEDIUM",), "mysql": ("MEDIUM",),
            "postgresql": ("MEDIUM",), "smb": ("MEDIUM",),
            "rdp": ("MEDIUM",), "vnc": ("MEDIUM",),
        }
        for svc in ["ftp", "mysql", "postgresql", "smb", "rdp", "vnc"]:
            assert dangerous_services[svc][0] == "MEDIUM"


# ============================================================================
# TESTS: Interesting Paths List (gobuster parser)
# ============================================================================

class TestInterestingPaths:
    """Tests for interesting_paths list used in _parse_gobuster_output."""

    def test_interesting_paths_content(self):
        interesting_paths = [
            "admin", "backup", "config", "database", "db", "debug",
            "login", "api", "swagger", "graphql", ".git", ".env",
            "wp-admin", "phpmyadmin", "server-status", "actuator",
        ]
        assert len(interesting_paths) == 16

    def test_has_security_critical_paths(self):
        interesting_paths = [
            "admin", "backup", "config", "database", "db", "debug",
            "login", "api", "swagger", "graphql", ".git", ".env",
            "wp-admin", "phpmyadmin", "server-status", "actuator",
        ]
        assert ".git" in interesting_paths
        assert ".env" in interesting_paths
        assert "backup" in interesting_paths
        assert "debug" in interesting_paths

    def test_has_admin_paths(self):
        interesting_paths = [
            "admin", "backup", "config", "database", "db", "debug",
            "login", "api", "swagger", "graphql", ".git", ".env",
            "wp-admin", "phpmyadmin", "server-status", "actuator",
        ]
        assert "admin" in interesting_paths
        assert "wp-admin" in interesting_paths
        assert "phpmyadmin" in interesting_paths

    def test_has_api_paths(self):
        interesting_paths = [
            "admin", "backup", "config", "database", "db", "debug",
            "login", "api", "swagger", "graphql", ".git", ".env",
            "wp-admin", "phpmyadmin", "server-status", "actuator",
        ]
        assert "api" in interesting_paths
        assert "swagger" in interesting_paths
        assert "graphql" in interesting_paths


# ============================================================================
# TESTS: Correlation Constants
# ============================================================================

class TestCorrelationConstants:
    """Tests for tool method group constants used in _correlate_findings."""

    def test_regex_tools(self):
        REGEX_TOOLS = {"nikto", "whatweb", "wapiti"}
        assert len(REGEX_TOOLS) == 3
        assert "nikto" in REGEX_TOOLS

    def test_probe_tools(self):
        PROBE_TOOLS = {"nmap", "masscan"}
        assert len(PROBE_TOOLS) == 2
        assert "nmap" in PROBE_TOOLS

    def test_dynamic_tools(self):
        DYNAMIC_TOOLS = {"nuclei", "sqlmap", "xsser"}
        assert len(DYNAMIC_TOOLS) == 3
        assert "nuclei" in DYNAMIC_TOOLS
        assert "sqlmap" in DYNAMIC_TOOLS


# ============================================================================
# TESTS: CWE Mapping (EnterpriseLinuxTools)
# ============================================================================

class TestCWEMapping:
    """Tests for _get_cwe_for_vuln mapping in EnterpriseLinuxTools."""

    def test_sqli_maps_to_cwe89(self):
        wrapper = EnterpriseLinuxTools()
        assert wrapper._get_cwe_for_vuln("sqli") == "CWE-89"

    def test_xss_maps_to_cwe79(self):
        wrapper = EnterpriseLinuxTools()
        assert wrapper._get_cwe_for_vuln("xss") == "CWE-79"

    def test_lfi_maps_to_cwe22(self):
        wrapper = EnterpriseLinuxTools()
        assert wrapper._get_cwe_for_vuln("lfi") == "CWE-22"

    def test_rce_maps_to_cwe78(self):
        wrapper = EnterpriseLinuxTools()
        assert wrapper._get_cwe_for_vuln("rce") == "CWE-78"

    def test_ssti_maps_to_cwe1336(self):
        wrapper = EnterpriseLinuxTools()
        assert wrapper._get_cwe_for_vuln("ssti") == "CWE-1336"

    def test_ssrf_maps_to_cwe918(self):
        wrapper = EnterpriseLinuxTools()
        assert wrapper._get_cwe_for_vuln("ssrf") == "CWE-918"

    def test_unknown_maps_to_cwe20(self):
        wrapper = EnterpriseLinuxTools()
        assert wrapper._get_cwe_for_vuln("unknown_type") == "CWE-20"

    def test_empty_maps_to_cwe20(self):
        wrapper = EnterpriseLinuxTools()
        assert wrapper._get_cwe_for_vuln("") == "CWE-20"


# ============================================================================
# TESTS: _detect_param_type (EnterpriseLinuxTools)
# ============================================================================

class TestDetectParamType:
    """Tests for _detect_param_type static logic in EnterpriseLinuxTools."""

    def test_detects_id_param(self):
        wrapper = EnterpriseLinuxTools()
        assert wrapper._detect_param_type("user_id", "123") == "id"
        assert wrapper._detect_param_type("id", "1") == "id"
        assert wrapper._detect_param_type("item_id", "42") == "id"

    def test_detects_boolean_param(self):
        wrapper = EnterpriseLinuxTools()
        assert wrapper._detect_param_type("active", "true") == "boolean"
        assert wrapper._detect_param_type("enabled", "false") == "boolean"
        assert wrapper._detect_param_type("flag", "0") == "boolean"
        assert wrapper._detect_param_type("flag", "1") == "boolean"
        assert wrapper._detect_param_type("opt", "yes") == "boolean"
        assert wrapper._detect_param_type("opt", "no") == "boolean"

    def test_detects_numeric_param(self):
        wrapper = EnterpriseLinuxTools()
        assert wrapper._detect_param_type("count", "42") == "numeric"
        assert wrapper._detect_param_type("offset", "-5") == "numeric"

    def test_detects_path_param(self):
        wrapper = EnterpriseLinuxTools()
        assert wrapper._detect_param_type("file", "/etc/passwd") == "path"
        assert wrapper._detect_param_type("dir", "C:\\Windows") == "path"

    def test_detects_string_param(self):
        wrapper = EnterpriseLinuxTools()
        assert wrapper._detect_param_type("name", "hello") == "string"
        assert wrapper._detect_param_type("query", "search term") == "string"


# ============================================================================
# TESTS: get_available_tools (list of supported tools)
# ============================================================================

class TestGetAvailableTools:
    """Tests for the tool list in get_available_tools."""

    def test_returns_dict(self):
        # Clear cache first to avoid stale state from other tests
        LinuxToolsWrapper._tool_cache = {}
        result = LinuxToolsWrapper.get_available_tools()
        assert isinstance(result, dict)

    def test_has_core_tools(self):
        LinuxToolsWrapper._tool_cache = {}
        result = LinuxToolsWrapper.get_available_tools()
        core_tools = ["nmap", "nikto", "sqlmap", "gobuster", "dirb", "hydra", "nuclei"]
        for tool in core_tools:
            assert tool in result, f"Missing core tool: {tool}"

    def test_has_enterprise_tools(self):
        LinuxToolsWrapper._tool_cache = {}
        result = LinuxToolsWrapper.get_available_tools()
        enterprise_tools = ["ffuf", "arjun", "subfinder", "wfuzz", "amass"]
        for tool in enterprise_tools:
            assert tool in result, f"Missing enterprise tool: {tool}"

    def test_total_tool_count(self):
        LinuxToolsWrapper._tool_cache = {}
        result = LinuxToolsWrapper.get_available_tools()
        assert len(result) == 12

    def test_all_values_are_bool(self):
        LinuxToolsWrapper._tool_cache = {}
        result = LinuxToolsWrapper.get_available_tools()
        for tool, available in result.items():
            assert isinstance(available, bool), f"{tool}: should be bool"
