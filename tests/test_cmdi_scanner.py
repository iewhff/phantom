"""
Tests for Command Injection (CMDi) Scanner Module.

Covers:
- OSType enum (6 OS types)
- ShellType enum (7 shell types)
- InjectionContext enum (16 contexts)
- WAFType enum (14 types)
- CMDiFinding dataclass
- WAFDetector class
- PayloadMutator class (12 mutation methods)
- CommandInjectionScanner constants (params, payloads, patterns)
"""

import base64
import pytest
from dataclasses import fields
from unittest.mock import MagicMock, patch

from scanning.modules.cmdi_scanner import (
    OSType,
    ShellType,
    InjectionContext,
    WAFType,
    CMDiFinding,
    WAFDetector,
    PayloadMutator,
    CommandInjectionScanner,
)


# ============================================================================
# TESTS: OSType Enum
# ============================================================================

class TestOSType:
    """Tests for OSType enum."""

    def test_has_unknown(self):
        assert OSType.UNKNOWN is not None

    def test_has_linux(self):
        assert OSType.LINUX is not None

    def test_has_windows(self):
        assert OSType.WINDOWS is not None

    def test_has_macos(self):
        assert OSType.MACOS is not None

    def test_has_freebsd(self):
        assert OSType.FREEBSD is not None

    def test_has_solaris(self):
        assert OSType.SOLARIS is not None

    def test_total_count(self):
        assert len(OSType) == 6

    def test_all_unique(self):
        values = [o.value for o in OSType]
        assert len(values) == len(set(values))


# ============================================================================
# TESTS: ShellType Enum
# ============================================================================

class TestShellType:
    """Tests for ShellType enum."""

    def test_has_unknown(self):
        assert ShellType.UNKNOWN is not None

    def test_has_bash(self):
        assert ShellType.BASH is not None

    def test_has_sh(self):
        assert ShellType.SH is not None

    def test_has_zsh(self):
        assert ShellType.ZSH is not None

    def test_has_cmd(self):
        assert ShellType.CMD is not None

    def test_has_powershell(self):
        assert ShellType.POWERSHELL is not None

    def test_has_fish(self):
        assert ShellType.FISH is not None

    def test_total_count(self):
        assert len(ShellType) == 7


# ============================================================================
# TESTS: InjectionContext Enum
# ============================================================================

class TestInjectionContext:
    """Tests for InjectionContext enum."""

    def test_has_direct(self):
        assert InjectionContext.DIRECT is not None

    def test_has_shell_command(self):
        assert InjectionContext.SHELL_COMMAND is not None

    def test_has_subprocess(self):
        assert InjectionContext.SUBPROCESS is not None

    def test_has_backtick(self):
        assert InjectionContext.BACKTICK is not None

    def test_has_dollar_paren(self):
        assert InjectionContext.DOLLAR_PAREN is not None

    def test_has_pipe(self):
        assert InjectionContext.PIPE is not None

    def test_has_semicolon(self):
        assert InjectionContext.SEMICOLON is not None

    def test_has_and(self):
        assert InjectionContext.AND is not None

    def test_has_or(self):
        assert InjectionContext.OR is not None

    def test_has_newline(self):
        assert InjectionContext.NEWLINE is not None

    def test_has_argument(self):
        assert InjectionContext.ARGUMENT is not None

    def test_has_environment(self):
        assert InjectionContext.ENVIRONMENT is not None

    def test_has_heredoc(self):
        assert InjectionContext.HEREDOC is not None

    def test_has_eval(self):
        assert InjectionContext.EVAL is not None

    def test_has_template(self):
        assert InjectionContext.TEMPLATE is not None

    def test_has_php_function(self):
        assert InjectionContext.PHP_FUNCTION is not None

    def test_total_count(self):
        assert len(InjectionContext) == 16


# ============================================================================
# TESTS: WAFType Enum
# ============================================================================

class TestWAFType:
    """Tests for WAFType enum."""

    def test_has_none(self):
        assert WAFType.NONE is not None

    def test_has_cloudflare(self):
        assert WAFType.CLOUDFLARE is not None

    def test_has_modsecurity(self):
        assert WAFType.MODSECURITY is not None

    def test_has_comodo(self):
        assert WAFType.COMODO is not None

    def test_total_count(self):
        assert len(WAFType) == 14

    def test_from_base_converts(self):
        """from_base should convert centralized WAF types."""
        from utils.scanner_helpers import WAFType as BaseWAFType
        result = WAFType.from_base(BaseWAFType.CLOUDFLARE)
        assert result == WAFType.CLOUDFLARE

    def test_from_base_unknown_fallback(self):
        """from_base should fallback to UNKNOWN for unmapped types."""
        result = WAFType.from_base(MagicMock())
        assert result == WAFType.UNKNOWN


# ============================================================================
# TESTS: CMDiFinding Dataclass
# ============================================================================

class TestCMDiFinding:
    """Tests for CMDiFinding dataclass."""

    def test_creates_finding(self):
        finding = CMDiFinding(
            url="https://example.com/ping",
            parameter="ip",
            payload="; id",
            os_type=OSType.LINUX,
            shell_type=ShellType.BASH,
            context=InjectionContext.SEMICOLON,
            detection_method="result_based",
            evidence=["uid=33(www-data)"],
            confidence=95,
        )
        assert finding.url == "https://example.com/ping"
        assert finding.parameter == "ip"
        assert finding.confidence == 95

    def test_has_required_fields(self):
        field_names = {f.name for f in fields(CMDiFinding)}
        required = {"url", "parameter", "payload", "os_type", "shell_type",
                     "context", "detection_method", "evidence", "confidence"}
        assert required.issubset(field_names)

    def test_has_optional_fields(self):
        field_names = {f.name for f in fields(CMDiFinding)}
        assert "waf_detected" in field_names
        assert "waf_bypassed" in field_names
        assert "response_time" in field_names
        assert "baseline_time" in field_names

    def test_defaults(self):
        finding = CMDiFinding(
            url="https://example.com",
            parameter="cmd",
            payload="; id",
            os_type=OSType.UNKNOWN,
            shell_type=ShellType.UNKNOWN,
            context=InjectionContext.DIRECT,
            detection_method="test",
            evidence=[],
            confidence=0,
        )
        assert finding.waf_detected is None
        assert finding.waf_bypassed is False
        assert finding.response_time == 0.0
        assert finding.baseline_time == 0.0

    def test_stores_timing_info(self):
        finding = CMDiFinding(
            url="https://example.com",
            parameter="ip",
            payload="; sleep 5",
            os_type=OSType.LINUX,
            shell_type=ShellType.BASH,
            context=InjectionContext.SEMICOLON,
            detection_method="time_based",
            evidence=["Delay: 5.1s vs baseline 0.3s"],
            confidence=85,
            response_time=5.1,
            baseline_time=0.3,
        )
        assert finding.response_time == 5.1
        assert finding.baseline_time == 0.3
        assert finding.response_time > finding.baseline_time


# ============================================================================
# TESTS: WAFDetector
# ============================================================================

class TestWAFDetector:
    """Tests for WAFDetector class."""

    def test_returns_none_for_no_waf(self):
        mock_response = MagicMock()
        with patch("scanning.modules.cmdi_scanner.BaseWAFDetector.detect") as mock_detect:
            from utils.scanner_helpers import WAFType as BaseWAFType
            mock_detect.return_value = (BaseWAFType.NONE, False)
            assert WAFDetector.detect(mock_response) is None

    def test_detects_cloudflare(self):
        mock_response = MagicMock()
        with patch("scanning.modules.cmdi_scanner.BaseWAFDetector.detect") as mock_detect:
            from utils.scanner_helpers import WAFType as BaseWAFType
            mock_detect.return_value = (BaseWAFType.CLOUDFLARE, True)
            assert WAFDetector.detect(mock_response) == WAFType.CLOUDFLARE

    def test_is_blocked_false(self):
        mock_response = MagicMock()
        with patch("scanning.modules.cmdi_scanner.BaseWAFDetector.detect") as mock_detect:
            from utils.scanner_helpers import WAFType as BaseWAFType
            mock_detect.return_value = (BaseWAFType.NONE, False)
            assert WAFDetector.is_blocked(mock_response) is False

    def test_is_blocked_true(self):
        mock_response = MagicMock()
        with patch("scanning.modules.cmdi_scanner.BaseWAFDetector.detect") as mock_detect:
            from utils.scanner_helpers import WAFType as BaseWAFType
            mock_detect.return_value = (BaseWAFType.MODSECURITY, True)
            assert WAFDetector.is_blocked(mock_response) is True


# ============================================================================
# TESTS: PayloadMutator
# ============================================================================

class TestPayloadMutator:
    """Tests for PayloadMutator class."""

    def test_url_encode(self):
        encoded = PayloadMutator.url_encode("; id")
        assert encoded != "; id"

    def test_double_url_encode(self):
        encoded = PayloadMutator.double_url_encode("; id")
        assert "%25" in encoded

    def test_unicode_encode_special_chars(self):
        encoded = PayloadMutator.unicode_encode("; id")
        assert "\\u003b" in encoded  # semicolon

    def test_unicode_encode_preserves_alphanumeric(self):
        encoded = PayloadMutator.unicode_encode("abc123")
        assert encoded == "abc123"

    def test_hex_encode_bash(self):
        encoded = PayloadMutator.hex_encode_bash("id")
        assert encoded.startswith("$'")
        assert "\\x69" in encoded  # 'i'
        assert "\\x64" in encoded  # 'd'

    def test_octal_encode(self):
        encoded = PayloadMutator.octal_encode("id")
        assert encoded.startswith("$'")
        assert "\\105" in encoded or "\\151" in encoded or "\\" in encoded

    def test_base64_bash(self):
        encoded = PayloadMutator.base64_bash("id")
        assert "base64" in encoded
        assert "|bash" in encoded
        # Verify the base64 part
        b64_part = encoded.split("echo ")[1].split("|")[0]
        decoded = base64.b64decode(b64_part).decode()
        assert decoded == "id"

    def test_base64_powershell(self):
        encoded = PayloadMutator.base64_powershell("whoami")
        assert "powershell" in encoded
        assert "-enc" in encoded

    def test_char_by_char(self):
        result = PayloadMutator.char_by_char("id")
        assert "printf" in result
        assert "\\x69" in result  # 'i'

    def test_wildcard_bypass_cat(self):
        result = PayloadMutator.wildcard_bypass("cat /etc/passwd")
        assert "/???/c?t" in result  # cat → wildcard

    def test_wildcard_bypass_ls(self):
        result = PayloadMutator.wildcard_bypass("ls")
        assert "?" in result

    def test_environment_bypass(self):
        result = PayloadMutator.environment_bypass("/etc/passwd")
        assert "${PATH:0:1}" in result
        assert "/" not in result  # slashes replaced

    def test_insert_junk(self):
        result = PayloadMutator.insert_junk("id")
        assert "${z}" in result

    def test_newline_separator(self):
        result = PayloadMutator.newline_separator("id")
        assert result.startswith("\n")
        assert result.endswith("\n")
        assert "id" in result

    def test_tab_separator(self):
        result = PayloadMutator.tab_separator("cat /etc/passwd")
        assert "\t" in result
        assert " " not in result

    def test_get_all_mutations(self):
        mutations = PayloadMutator.get_all_mutations("; id")
        assert len(mutations) >= 5
        assert "; id" in mutations  # Original preserved

    def test_get_all_mutations_deduplicates(self):
        mutations = PayloadMutator.get_all_mutations("test")
        assert len(mutations) == len(set(mutations))


# ============================================================================
# TESTS: CommandInjectionScanner Constants - CMDI_PARAMS
# ============================================================================

class TestCMDIParams:
    """Tests for vulnerable parameter names."""

    def test_has_command_params(self):
        assert "cmd" in CommandInjectionScanner.CMDI_PARAMS
        assert "exec" in CommandInjectionScanner.CMDI_PARAMS
        assert "command" in CommandInjectionScanner.CMDI_PARAMS

    def test_has_php_function_params(self):
        assert "shell_exec" in CommandInjectionScanner.CMDI_PARAMS
        assert "passthru" in CommandInjectionScanner.CMDI_PARAMS
        assert "eval" in CommandInjectionScanner.CMDI_PARAMS

    def test_has_network_params(self):
        assert "ping" in CommandInjectionScanner.CMDI_PARAMS
        assert "host" in CommandInjectionScanner.CMDI_PARAMS
        assert "ip" in CommandInjectionScanner.CMDI_PARAMS
        assert "nslookup" in CommandInjectionScanner.CMDI_PARAMS

    def test_has_file_params(self):
        assert "file" in CommandInjectionScanner.CMDI_PARAMS
        assert "filename" in CommandInjectionScanner.CMDI_PARAMS
        assert "path" in CommandInjectionScanner.CMDI_PARAMS

    def test_has_process_params(self):
        assert "process" in CommandInjectionScanner.CMDI_PARAMS
        assert "service" in CommandInjectionScanner.CMDI_PARAMS

    def test_has_git_params(self):
        assert "clone" in CommandInjectionScanner.CMDI_PARAMS
        assert "repo" in CommandInjectionScanner.CMDI_PARAMS

    def test_has_archive_params(self):
        assert "zip" in CommandInjectionScanner.CMDI_PARAMS
        assert "tar" in CommandInjectionScanner.CMDI_PARAMS

    def test_no_empty_params(self):
        assert "" not in CommandInjectionScanner.CMDI_PARAMS


# ============================================================================
# TESTS: CommandInjectionScanner Constants - KNOWN_CMDI_PATHS
# ============================================================================

class TestKnownCMDIPaths:
    """Tests for known vulnerable endpoint paths."""

    def test_has_dvwa_paths(self):
        paths = CommandInjectionScanner.KNOWN_CMDI_PATHS
        assert any("dvwa" in p.lower() or "exec" in p.lower() for p in paths)

    def test_has_bwapp_paths(self):
        paths = CommandInjectionScanner.KNOWN_CMDI_PATHS
        assert any("bwapp" in p.lower() or "commandi" in p.lower() for p in paths)

    def test_has_mutillidae_paths(self):
        paths = CommandInjectionScanner.KNOWN_CMDI_PATHS
        assert any("mutillidae" in p.lower() for p in paths)

    def test_has_webgoat_paths(self):
        paths = CommandInjectionScanner.KNOWN_CMDI_PATHS
        assert any("webgoat" in p.lower() for p in paths)

    def test_has_generic_paths(self):
        paths = CommandInjectionScanner.KNOWN_CMDI_PATHS
        assert "/ping.php" in paths
        assert "/cmd.php" in paths or "/exec.php" in paths

    def test_has_api_paths(self):
        paths = CommandInjectionScanner.KNOWN_CMDI_PATHS
        assert any("/api/" in p for p in paths)

    def test_has_cgi_paths(self):
        paths = CommandInjectionScanner.KNOWN_CMDI_PATHS
        assert any("cgi-bin" in p for p in paths)

    def test_all_start_with_slash(self):
        for path in CommandInjectionScanner.KNOWN_CMDI_PATHS:
            assert path.startswith("/"), f"{path} doesn't start with /"


# ============================================================================
# TESTS: CommandInjectionScanner Constants - OS_DETECTION_PAYLOADS
# ============================================================================

class TestOSDetectionPayloads:
    """Tests for OS detection payloads."""

    def test_has_linux_detection(self):
        assert OSType.LINUX in CommandInjectionScanner.OS_DETECTION_PAYLOADS
        payloads = CommandInjectionScanner.OS_DETECTION_PAYLOADS[OSType.LINUX]
        assert len(payloads) > 0
        # Check for uname
        assert any("uname" in p[0] for p in payloads)

    def test_has_windows_detection(self):
        assert OSType.WINDOWS in CommandInjectionScanner.OS_DETECTION_PAYLOADS
        payloads = CommandInjectionScanner.OS_DETECTION_PAYLOADS[OSType.WINDOWS]
        assert len(payloads) > 0
        # Check for ver or systeminfo
        assert any("ver" in p[0].lower() or "systeminfo" in p[0].lower() for p in payloads)

    def test_has_macos_detection(self):
        assert OSType.MACOS in CommandInjectionScanner.OS_DETECTION_PAYLOADS
        payloads = CommandInjectionScanner.OS_DETECTION_PAYLOADS[OSType.MACOS]
        assert any("sw_vers" in p[0] or "Darwin" in str(p[1]) for p in payloads)

    def test_has_freebsd_detection(self):
        assert OSType.FREEBSD in CommandInjectionScanner.OS_DETECTION_PAYLOADS

    def test_payloads_have_indicators(self):
        """All detection payloads should have success indicators."""
        for os_type, payloads in CommandInjectionScanner.OS_DETECTION_PAYLOADS.items():
            for payload, indicators in payloads:
                assert isinstance(indicators, list), f"{os_type}: indicators should be list"


# ============================================================================
# TESTS: CommandInjectionScanner Constants - RESULT_PAYLOADS
# ============================================================================

class TestResultPayloads:
    """Tests for result-based OS-specific payloads."""

    def test_has_linux_payloads(self):
        assert OSType.LINUX in CommandInjectionScanner.RESULT_PAYLOADS
        payloads = CommandInjectionScanner.RESULT_PAYLOADS[OSType.LINUX]
        assert len(payloads) > 10

    def test_linux_has_id_command(self):
        payloads = CommandInjectionScanner.RESULT_PAYLOADS[OSType.LINUX]
        payload_strs = [p[0] for p in payloads]
        assert any("id" in p for p in payload_strs)

    def test_linux_has_multiple_separators(self):
        """Linux payloads should use multiple separator types."""
        payloads = CommandInjectionScanner.RESULT_PAYLOADS[OSType.LINUX]
        payload_strs = [p[0] for p in payloads]
        separators = set()
        for p in payload_strs:
            if p.startswith(";"):
                separators.add(";")
            elif p.startswith("|"):
                separators.add("|")
            elif p.startswith("||"):
                separators.add("||")
            elif p.startswith("&&"):
                separators.add("&&")
            elif p.startswith("`"):
                separators.add("`")
            elif p.startswith("$("):
                separators.add("$()")
        assert len(separators) >= 3

    def test_has_windows_payloads(self):
        assert OSType.WINDOWS in CommandInjectionScanner.RESULT_PAYLOADS
        payloads = CommandInjectionScanner.RESULT_PAYLOADS[OSType.WINDOWS]
        assert len(payloads) > 5

    def test_windows_has_dir_command(self):
        payloads = CommandInjectionScanner.RESULT_PAYLOADS[OSType.WINDOWS]
        payload_strs = [p[0] for p in payloads]
        assert any("dir" in p for p in payload_strs)

    def test_windows_has_powershell(self):
        payloads = CommandInjectionScanner.RESULT_PAYLOADS[OSType.WINDOWS]
        payload_strs = [p[0] for p in payloads]
        assert any("powershell" in p.lower() for p in payload_strs)

    def test_has_macos_payloads(self):
        assert OSType.MACOS in CommandInjectionScanner.RESULT_PAYLOADS


# ============================================================================
# TESTS: CommandInjectionScanner Constants - TIME_PAYLOADS
# ============================================================================

class TestTimePayloads:
    """Tests for time-based blind payloads."""

    def test_has_linux_time_payloads(self):
        assert OSType.LINUX in CommandInjectionScanner.TIME_PAYLOADS
        payloads = CommandInjectionScanner.TIME_PAYLOADS[OSType.LINUX]
        assert len(payloads) > 5

    def test_linux_has_sleep(self):
        payloads = CommandInjectionScanner.TIME_PAYLOADS[OSType.LINUX]
        assert any("sleep" in p[0] for p in payloads)

    def test_payloads_have_delay_placeholder(self):
        """All time payloads should have {delay} placeholder."""
        for os_type, payloads in CommandInjectionScanner.TIME_PAYLOADS.items():
            for payload, method in payloads:
                assert "{delay}" in payload, f"{os_type}/{method}: missing {{delay}}"

    def test_has_windows_time_payloads(self):
        assert OSType.WINDOWS in CommandInjectionScanner.TIME_PAYLOADS
        payloads = CommandInjectionScanner.TIME_PAYLOADS[OSType.WINDOWS]
        assert any("ping" in p[0] for p in payloads)

    def test_windows_has_powershell_sleep(self):
        payloads = CommandInjectionScanner.TIME_PAYLOADS[OSType.WINDOWS]
        assert any("powershell" in p[0].lower() and "sleep" in p[0].lower() for p in payloads)

    def test_has_macos_time_payloads(self):
        assert OSType.MACOS in CommandInjectionScanner.TIME_PAYLOADS


# ============================================================================
# TESTS: CommandInjectionScanner Constants - POLYGLOT_PAYLOADS
# ============================================================================

class TestPolyglotPayloads:
    """Tests for cross-platform polyglot payloads."""

    def test_has_payloads(self):
        assert len(CommandInjectionScanner.POLYGLOT_PAYLOADS) > 5

    def test_payloads_have_marker(self):
        """All polyglot payloads should contain CMDI_MARKER."""
        for payload, indicators in CommandInjectionScanner.POLYGLOT_PAYLOADS:
            assert "CMDI_MARKER" in payload

    def test_indicators_reference_marker(self):
        """Indicators should reference the marker."""
        for payload, indicators in CommandInjectionScanner.POLYGLOT_PAYLOADS:
            assert any("CMDI_MARKER" in i for i in indicators)

    def test_has_pipe_separator(self):
        payloads = [p[0] for p in CommandInjectionScanner.POLYGLOT_PAYLOADS]
        assert any(p.startswith("|") for p in payloads)

    def test_has_ampersand_separator(self):
        payloads = [p[0] for p in CommandInjectionScanner.POLYGLOT_PAYLOADS]
        assert any(p.startswith("&") for p in payloads)

    def test_has_semicolon_separator(self):
        payloads = [p[0] for p in CommandInjectionScanner.POLYGLOT_PAYLOADS]
        assert any(p.startswith(";") for p in payloads)

    def test_has_subshell(self):
        payloads = [p[0] for p in CommandInjectionScanner.POLYGLOT_PAYLOADS]
        assert any("$(" in p for p in payloads)

    def test_has_backtick(self):
        payloads = [p[0] for p in CommandInjectionScanner.POLYGLOT_PAYLOADS]
        assert any("`" in p for p in payloads)


# ============================================================================
# TESTS: CommandInjectionScanner Constants - PHP_CMDI_PAYLOADS
# ============================================================================

class TestPHPCMDIPayloads:
    """Tests for PHP-specific command injection payloads."""

    def test_has_payloads(self):
        assert len(CommandInjectionScanner.PHP_CMDI_PAYLOADS) > 20

    def test_has_system_function(self):
        payloads = [p[0] for p in CommandInjectionScanner.PHP_CMDI_PAYLOADS]
        assert any("system(" in p for p in payloads)

    def test_has_exec_function(self):
        payloads = [p[0] for p in CommandInjectionScanner.PHP_CMDI_PAYLOADS]
        assert any("exec(" in p for p in payloads)

    def test_has_shell_exec_function(self):
        payloads = [p[0] for p in CommandInjectionScanner.PHP_CMDI_PAYLOADS]
        assert any("shell_exec(" in p for p in payloads)

    def test_has_passthru_function(self):
        payloads = [p[0] for p in CommandInjectionScanner.PHP_CMDI_PAYLOADS]
        assert any("passthru(" in p for p in payloads)

    def test_has_backtick_execution(self):
        payloads = [p[0] for p in CommandInjectionScanner.PHP_CMDI_PAYLOADS]
        assert any("`id`" in p or "`whoami`" in p for p in payloads)

    def test_has_pipe_injection(self):
        payloads = [p[0] for p in CommandInjectionScanner.PHP_CMDI_PAYLOADS]
        assert any(p.startswith("| ") for p in payloads)

    def test_has_semicolon_injection(self):
        payloads = [p[0] for p in CommandInjectionScanner.PHP_CMDI_PAYLOADS]
        assert any(p.startswith("; ") for p in payloads)

    def test_has_quote_breakout(self):
        payloads = [p[0] for p in CommandInjectionScanner.PHP_CMDI_PAYLOADS]
        assert any(p.startswith('"') or p.startswith("'") for p in payloads)


# ============================================================================
# TESTS: CommandInjectionScanner Constants - PHP_DETECTION_PATTERNS
# ============================================================================

class TestPHPDetectionPatterns:
    """Tests for PHP detection patterns."""

    def test_has_php_errors(self):
        assert "php_errors" in CommandInjectionScanner.PHP_DETECTION_PATTERNS
        patterns = CommandInjectionScanner.PHP_DETECTION_PATTERNS["php_errors"]
        assert "PHP Warning:" in patterns
        assert "command not found" in patterns

    def test_has_php_function_output(self):
        assert "php_function_output" in CommandInjectionScanner.PHP_DETECTION_PATTERNS
        patterns = CommandInjectionScanner.PHP_DETECTION_PATTERNS["php_function_output"]
        assert "uid=" in patterns
        assert "root:" in patterns

    def test_has_php_version(self):
        assert "php_version" in CommandInjectionScanner.PHP_DETECTION_PATTERNS
        patterns = CommandInjectionScanner.PHP_DETECTION_PATTERNS["php_version"]
        assert any("PHP" in p for p in patterns)


# ============================================================================
# TESTS: CommandInjectionScanner Constants - WAF_BYPASS_PAYLOADS
# ============================================================================

class TestWAFBypassPayloads:
    """Tests for WAF-specific bypass payloads."""

    def test_has_cloudflare_bypasses(self):
        assert WAFType.CLOUDFLARE in CommandInjectionScanner.WAF_BYPASS_PAYLOADS
        payloads = CommandInjectionScanner.WAF_BYPASS_PAYLOADS[WAFType.CLOUDFLARE]
        assert len(payloads) >= 5

    def test_cloudflare_has_ifs_bypass(self):
        """Cloudflare bypasses should include $IFS technique."""
        payloads = CommandInjectionScanner.WAF_BYPASS_PAYLOADS[WAFType.CLOUDFLARE]
        payload_strs = [p[0] for p in payloads]
        assert any("IFS" in p for p in payload_strs)

    def test_has_akamai_bypasses(self):
        assert WAFType.AKAMAI in CommandInjectionScanner.WAF_BYPASS_PAYLOADS

    def test_has_aws_waf_bypasses(self):
        assert WAFType.AWS_WAF in CommandInjectionScanner.WAF_BYPASS_PAYLOADS

    def test_has_modsecurity_bypasses(self):
        assert WAFType.MODSECURITY in CommandInjectionScanner.WAF_BYPASS_PAYLOADS

    def test_has_imperva_bypasses(self):
        assert WAFType.IMPERVA in CommandInjectionScanner.WAF_BYPASS_PAYLOADS

    def test_has_unknown_waf_bypasses(self):
        """Should have generic bypasses for unknown WAFs."""
        assert WAFType.UNKNOWN in CommandInjectionScanner.WAF_BYPASS_PAYLOADS


# ============================================================================
# TESTS: CommandInjectionScanner Constants - ARGUMENT_PAYLOADS
# ============================================================================

class TestArgumentPayloads:
    """Tests for argument injection payloads."""

    def test_has_payloads(self):
        assert len(CommandInjectionScanner.ARGUMENT_PAYLOADS) > 5

    def test_has_help_flag(self):
        payloads = [p[0] for p in CommandInjectionScanner.ARGUMENT_PAYLOADS]
        assert "--help" in payloads

    def test_has_version_flag(self):
        payloads = [p[0] for p in CommandInjectionScanner.ARGUMENT_PAYLOADS]
        assert "--version" in payloads

    def test_has_git_injection(self):
        payloads = [p[0] for p in CommandInjectionScanner.ARGUMENT_PAYLOADS]
        assert any("upload-pack" in p or "--exec" in p for p in payloads)

    def test_has_tar_checkpoint(self):
        payloads = [p[0] for p in CommandInjectionScanner.ARGUMENT_PAYLOADS]
        assert any("checkpoint" in p for p in payloads)


# ============================================================================
# TESTS: CommandInjectionScanner Constants - OOB_PAYLOADS
# ============================================================================

class TestOOBPayloads:
    """Tests for Out-of-Band exfiltration payloads."""

    def test_has_dns_payloads(self):
        assert "dns" in CommandInjectionScanner.OOB_PAYLOADS
        dns = CommandInjectionScanner.OOB_PAYLOADS["dns"]
        assert any("nslookup" in p or "dig" in p or "host" in p for p in dns)

    def test_has_http_payloads(self):
        assert "http" in CommandInjectionScanner.OOB_PAYLOADS
        http = CommandInjectionScanner.OOB_PAYLOADS["http"]
        assert any("curl" in p or "wget" in p for p in http)

    def test_dns_payloads_have_placeholders(self):
        for payload in CommandInjectionScanner.OOB_PAYLOADS["dns"]:
            assert "{marker}" in payload
            assert "{oob_domain}" in payload

    def test_http_payloads_have_placeholders(self):
        for payload in CommandInjectionScanner.OOB_PAYLOADS["http"]:
            assert "{oob_domain}" in payload
            assert "{marker}" in payload

    def test_http_has_windows_payload(self):
        http = CommandInjectionScanner.OOB_PAYLOADS["http"]
        assert any("powershell" in p.lower() for p in http)


# ============================================================================
# TESTS: CommandInjectionScanner Constants - WINDOWS_BYPASS_PAYLOADS
# ============================================================================

class TestWindowsBypassPayloads:
    """Tests for Windows-specific bypass payloads."""

    def test_has_payloads(self):
        assert len(CommandInjectionScanner.WINDOWS_BYPASS_PAYLOADS) > 5

    def test_has_caret_escape(self):
        payloads = [p[0] for p in CommandInjectionScanner.WINDOWS_BYPASS_PAYLOADS]
        assert any("^" in p for p in payloads)

    def test_has_comspec(self):
        payloads = [p[0] for p in CommandInjectionScanner.WINDOWS_BYPASS_PAYLOADS]
        assert any("COMSPEC" in p for p in payloads)

    def test_has_powershell_encoded(self):
        payloads = [p[0] for p in CommandInjectionScanner.WINDOWS_BYPASS_PAYLOADS]
        assert any("powershell -enc" in p or "powershell -e" in p for p in payloads)


# ============================================================================
# TESTS: Scanner Initialization
# ============================================================================

class TestScannerInit:
    """Tests for CommandInjectionScanner initialization."""

    def test_scanner_has_name(self):
        assert CommandInjectionScanner.name == "cmdi_scanner"

    def test_scanner_has_confidence_threshold(self):
        assert CommandInjectionScanner.MIN_CONFIDENCE_THRESHOLD == 0.70

    def test_scanner_creates_with_settings(self):
        settings = MagicMock()
        settings.timeouts = MagicMock()
        settings.timeouts.request_timeout = 30.0
        scanner = CommandInjectionScanner(settings)
        assert scanner.timeout == 30.0
        assert scanner.detected_os == OSType.UNKNOWN
        assert scanner.detected_shell == ShellType.UNKNOWN
        assert scanner.detected_waf is None

    def test_scanner_blind_detection_defaults(self):
        settings = MagicMock()
        settings.timeouts = MagicMock()
        settings.timeouts.request_timeout = 30.0
        scanner = CommandInjectionScanner(settings)
        assert scanner.blind_delays == [5, 3, 2]
        assert scanner.delay_tolerance == 0.7

    def test_scanner_timeout_limit(self):
        settings = MagicMock()
        settings.timeouts = MagicMock()
        settings.timeouts.request_timeout = 30.0
        scanner = CommandInjectionScanner(settings)
        assert scanner._max_total_time == 300.0


# ============================================================================
# TESTS: Attack Scenarios
# ============================================================================

class TestAttackScenarios:
    """Tests modeling real-world CMDi attack scenarios."""

    def test_linux_ping_injection(self):
        """Classic ping -c command injection on Linux."""
        finding = CMDiFinding(
            url="https://example.com/ping",
            parameter="ip",
            payload="; id",
            os_type=OSType.LINUX,
            shell_type=ShellType.BASH,
            context=InjectionContext.SEMICOLON,
            detection_method="result_based",
            evidence=["uid=33(www-data) gid=33(www-data)"],
            confidence=95,
        )
        assert finding.os_type == OSType.LINUX
        assert finding.context == InjectionContext.SEMICOLON
        assert "uid=" in finding.evidence[0]

    def test_windows_ping_injection(self):
        """Windows ping command injection."""
        finding = CMDiFinding(
            url="https://example.com/tools/ping",
            parameter="target",
            payload="& whoami",
            os_type=OSType.WINDOWS,
            shell_type=ShellType.CMD,
            context=InjectionContext.AND,
            detection_method="result_based",
            evidence=["NT AUTHORITY\\NETWORK SERVICE"],
            confidence=90,
        )
        assert finding.os_type == OSType.WINDOWS
        assert "AUTHORITY" in finding.evidence[0]

    def test_blind_time_based(self):
        """Blind time-based command injection."""
        finding = CMDiFinding(
            url="https://example.com/api/ping",
            parameter="host",
            payload="; sleep 5",
            os_type=OSType.LINUX,
            shell_type=ShellType.BASH,
            context=InjectionContext.SEMICOLON,
            detection_method="time_based",
            evidence=["Response time: 5.2s (baseline: 0.3s)"],
            confidence=85,
            response_time=5.2,
            baseline_time=0.3,
        )
        assert finding.detection_method == "time_based"
        assert finding.response_time > finding.baseline_time * 5

    def test_php_dvwa_injection(self):
        """DVWA-style PHP command injection."""
        finding = CMDiFinding(
            url="https://dvwa.local/vulnerabilities/exec/",
            parameter="ip",
            payload="; cat /etc/passwd",
            os_type=OSType.LINUX,
            shell_type=ShellType.SH,
            context=InjectionContext.SEMICOLON,
            detection_method="result_based",
            evidence=["root:x:0:0:root:/root:/bin/bash"],
            confidence=98,
        )
        assert "root:x:0:0" in finding.evidence[0]

    def test_waf_bypass_injection(self):
        """Command injection with WAF bypass."""
        finding = CMDiFinding(
            url="https://example.com/api/ping",
            parameter="host",
            payload=";${IFS}id",
            os_type=OSType.LINUX,
            shell_type=ShellType.BASH,
            context=InjectionContext.SEMICOLON,
            detection_method="result_based",
            evidence=["uid=33(www-data)"],
            confidence=90,
            waf_detected=WAFType.CLOUDFLARE,
            waf_bypassed=True,
        )
        assert finding.waf_detected == WAFType.CLOUDFLARE
        assert finding.waf_bypassed is True

    def test_argument_injection(self):
        """Argument injection scenario."""
        finding = CMDiFinding(
            url="https://example.com/git/clone",
            parameter="repo",
            payload="--upload-pack=id",
            os_type=OSType.LINUX,
            shell_type=ShellType.BASH,
            context=InjectionContext.ARGUMENT,
            detection_method="result_based",
            evidence=["uid=1000(git)"],
            confidence=85,
        )
        assert finding.context == InjectionContext.ARGUMENT


# ============================================================================
# TESTS: Edge Cases
# ============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_finding_minimal(self):
        finding = CMDiFinding(
            url="https://example.com",
            parameter="cmd",
            payload="test",
            os_type=OSType.UNKNOWN,
            shell_type=ShellType.UNKNOWN,
            context=InjectionContext.DIRECT,
            detection_method="test",
            evidence=[],
            confidence=0,
        )
        assert finding.waf_detected is None
        assert finding.response_time == 0.0

    def test_payload_mutator_empty_input(self):
        assert PayloadMutator.hex_encode_bash("") == "$''"
        assert PayloadMutator.octal_encode("") == "$''"
        assert PayloadMutator.unicode_encode("") == ""

    def test_payload_mutator_special_chars(self):
        result = PayloadMutator.unicode_encode("| ; & ` $")
        assert "\\u" in result

    def test_base64_bash_roundtrip(self):
        """Verify base64 bash encoding is decodable."""
        cmd = "cat /etc/passwd"
        encoded = PayloadMutator.base64_bash(cmd)
        b64_part = encoded.split("echo ")[1].split("|")[0]
        decoded = base64.b64decode(b64_part).decode()
        assert decoded == cmd

    def test_all_os_types_have_result_payloads(self):
        """Major OS types should have result payloads."""
        assert OSType.LINUX in CommandInjectionScanner.RESULT_PAYLOADS
        assert OSType.WINDOWS in CommandInjectionScanner.RESULT_PAYLOADS
        assert OSType.MACOS in CommandInjectionScanner.RESULT_PAYLOADS

    def test_all_os_types_have_time_payloads(self):
        """Major OS types should have time-based payloads."""
        assert OSType.LINUX in CommandInjectionScanner.TIME_PAYLOADS
        assert OSType.WINDOWS in CommandInjectionScanner.TIME_PAYLOADS
        assert OSType.MACOS in CommandInjectionScanner.TIME_PAYLOADS
