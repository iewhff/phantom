"""
PHANTOM AI - Information Disclosure Vulnerability Scanner

Enterprise-grade information disclosure detection covering:
- Error message analysis (stack traces, debug info)
- Debug endpoint discovery
- Source code disclosure
- Backup file detection (.bak, .old, ~)
- Version information leakage
- Database error extraction
- Path disclosure (server paths, internal structure)
- Internal IP/hostname disclosure
- Technology fingerprinting
- Git/SVN/Mercurial repository exposure
- Configuration file exposure
- phpinfo(), server-status endpoints
- Sensitive data in comments
- API documentation exposure

Based on PortSwigger Web Security Academy - Information Disclosure (5 labs)

Version: 3.0.0
Author: PHANTOM AI Team
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, quote

logger = logging.getLogger(__name__)


# =============================================================================
# CONSTANTS & CONFIGURATIONS
# =============================================================================

VERSION = "3.0.0"


class DisclosureType(Enum):
    """Types of information disclosure."""

    ERROR_MESSAGE = auto()              # Verbose error messages
    STACK_TRACE = auto()                # Full stack traces
    DEBUG_ENDPOINT = auto()             # Debug/diagnostic endpoints
    SOURCE_CODE = auto()                # Source code exposure
    BACKUP_FILE = auto()                # Backup files
    VERSION_INFO = auto()               # Software version disclosure
    DATABASE_ERROR = auto()             # Database error messages
    PATH_DISCLOSURE = auto()            # Server path disclosure
    INTERNAL_IP = auto()                # Internal IP addresses
    GIT_EXPOSURE = auto()               # Git repository exposure
    SVN_EXPOSURE = auto()               # SVN repository exposure
    CONFIG_FILE = auto()                # Configuration file exposure
    PHPINFO = auto()                    # phpinfo() page
    SERVER_STATUS = auto()              # Server status pages
    COMMENT_LEAK = auto()               # Sensitive data in comments
    API_DOCS = auto()                   # Unprotected API documentation
    ENVIRONMENT_VAR = auto()            # Environment variables
    CREDENTIAL_LEAK = auto()            # Hardcoded credentials
    SESSION_INFO = auto()               # Session/token information
    USER_ENUMERATION = auto()           # User enumeration


class SeverityLevel(Enum):
    """Severity levels for disclosures."""

    CRITICAL = "CRITICAL"   # Credentials, API keys
    HIGH = "HIGH"           # Source code, database errors
    MEDIUM = "MEDIUM"       # Stack traces, paths
    LOW = "LOW"             # Version info, minor leaks
    INFO = "INFO"           # Technology fingerprinting


# =============================================================================
# PATTERNS FOR DETECTION
# =============================================================================

# Error message patterns
ERROR_PATTERNS = {
    "php": [
        r"Parse error:.*in\s+([^\s]+)\s+on line\s+(\d+)",
        r"Fatal error:.*in\s+([^\s]+)\s+on line\s+(\d+)",
        r"Warning:.*in\s+([^\s]+)\s+on line\s+(\d+)",
        r"Notice:.*in\s+([^\s]+)\s+on line\s+(\d+)",
        r"<b>Fatal error</b>:",
        r"Uncaught exception",
    ],
    "python": [
        r"Traceback \(most recent call last\):",
        r"File \"([^\"]+)\", line (\d+)",
        r"^\s+raise\s+\w+",
        r"django\.core\.exceptions",
        r"flask\.debughelpers",
    ],
    "java": [
        r"java\.\w+\.\w+Exception:",
        r"at\s+[\w\.$]+\([\w]+\.java:\d+\)",
        r"Caused by:",
        r"org\.springframework\.",
        r"javax\.servlet\.ServletException",
    ],
    "dotnet": [
        r"System\.\w+Exception:",
        r"at\s+[\w\.]+\s+in\s+([^:]+):line\s+(\d+)",
        r"Stack Trace:",
        r"Server Error in '/' Application",
        r"ASP\.NET",
    ],
    "ruby": [
        r"ActionController::RoutingError",
        r"NoMethodError:",
        r"SyntaxError:",
        r"\.rb:\d+:in\s+`",
    ],
    "nodejs": [
        r"ReferenceError:",
        r"TypeError:",
        r"at\s+[\w\.]+\s+\(([^)]+):(\d+):\d+\)",
        r"node_modules",
        r"Error: Cannot find module",
    ],
}

# Database error patterns
DATABASE_ERRORS = {
    "mysql": [
        r"You have an error in your SQL syntax",
        r"mysql_fetch",
        r"mysqli_",
        r"Warning.*mysql",
        r"SQLSTATE\[HY000\]",
        r"MySQL server version",
    ],
    "postgresql": [
        r"ERROR:\s+syntax error at or near",
        r"pg_query\(\)",
        r"pg_",
        r"PostgreSQL",
        r"SQLSTATE\[42P01\]",
    ],
    "mssql": [
        r"Unclosed quotation mark",
        r"Microsoft OLE DB Provider",
        r"ODBC SQL Server Driver",
        r"SqlException",
        r"mssql_query\(\)",
    ],
    "oracle": [
        r"ORA-\d{5}",
        r"Oracle error",
        r"PLS-\d{5}",
        r"oci_",
    ],
    "sqlite": [
        r"SQLite error",
        r"sqlite3\.OperationalError",
        r"SQLITE_ERROR",
    ],
    "mongodb": [
        r"MongoError:",
        r"MongoDB",
        r"mongoose",
    ],
}

# Path disclosure patterns
PATH_PATTERNS = [
    # Unix paths
    r"/var/www/[\w/\.-]+",
    r"/home/[\w]+/[\w/\.-]+",
    r"/usr/[\w/\.-]+",
    r"/opt/[\w/\.-]+",
    r"/etc/[\w/\.-]+",
    r"/tmp/[\w/\.-]+",

    # Windows paths
    r"C:\\[\w\\\.]+",
    r"D:\\[\w\\\.]+",
    r"\\\\[\w\.]+\\[\w\\]+",
    r"C:/[\w/\.]+",
]

# Internal IP patterns
INTERNAL_IP_PATTERNS = [
    r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    r"\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b",
    r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
    r"\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    r"\blocalhost\b",
    r"::1",
    r"fe80::",
]

# Sensitive comment patterns
COMMENT_PATTERNS = [
    r"<!--.*?(password|passwd|pwd|secret|api[_-]?key|token|credential).*?-->",
    r"//.*?(password|passwd|pwd|secret|api[_-]?key|token)",
    r"/\*.*?(password|passwd|pwd|secret|api[_-]?key|token).*?\*/",
    r"#.*?(password|passwd|pwd|secret|api[_-]?key|token)",
    r"<!--.*?TODO.*?-->",
    r"<!--.*?FIXME.*?-->",
    r"<!--.*?DEBUG.*?-->",
    r"<!--.*?HACK.*?-->",
]

# Version disclosure patterns
VERSION_PATTERNS = {
    "apache": r"Apache/(\d+\.\d+(?:\.\d+)?)",
    "nginx": r"nginx/(\d+\.\d+(?:\.\d+)?)",
    "iis": r"Microsoft-IIS/(\d+\.\d+)",
    "php": r"PHP/(\d+\.\d+(?:\.\d+)?)",
    "python": r"Python/(\d+\.\d+(?:\.\d+)?)",
    "ruby": r"Ruby/(\d+\.\d+(?:\.\d+)?)",
    "nodejs": r"Node\.js/v?(\d+\.\d+(?:\.\d+)?)",
    "django": r"Django/(\d+\.\d+(?:\.\d+)?)",
    "rails": r"Rails/(\d+\.\d+(?:\.\d+)?)",
    "express": r"Express/(\d+\.\d+(?:\.\d+)?)",
    "wordpress": r"WordPress/(\d+\.\d+(?:\.\d+)?)",
    "drupal": r"Drupal (\d+(?:\.\d+)?)",
    "joomla": r"Joomla!?\s*(\d+\.\d+(?:\.\d+)?)",
    "tomcat": r"Apache Tomcat/(\d+\.\d+(?:\.\d+)?)",
    "jetty": r"Jetty\((\d+\.\d+(?:\.\d+)?)",
    "aspnet": r"X-AspNet-Version:\s*(\d+\.\d+(?:\.\d+)?)",
    "openssl": r"OpenSSL/(\d+\.\d+\.\d+\w?)",
}


# =============================================================================
# ENDPOINT LISTS
# =============================================================================

# Debug/diagnostic endpoints
DEBUG_ENDPOINTS = [
    # PHP
    "/phpinfo.php",
    "/info.php",
    "/php_info.php",
    "/test.php",
    "/debug.php",
    "/php-info.php",
    "/i.php",
    "/pi.php",

    # Python/Django
    "/__debug__/",
    "/debug/",
    "/django-debug-toolbar/",
    "/_debug_toolbar/",

    # Java
    "/actuator",
    "/actuator/health",
    "/actuator/info",
    "/actuator/env",
    "/actuator/configprops",
    "/actuator/beans",
    "/actuator/mappings",
    "/actuator/heapdump",
    "/actuator/threaddump",
    "/jolokia/",
    "/jmx-console/",

    # .NET
    "/elmah.axd",
    "/trace.axd",

    # General
    "/server-status",
    "/server-info",
    "/status",
    "/health",
    "/healthcheck",
    "/metrics",
    "/stats",
    "/diagnostics",
    "/debug/vars",
    "/debug/pprof/",

    # API Debug Endpoints (GENERALIST — works for REST APIs)
    # Pattern: /_debug at various path levels
    "/_debug",
    "/api/_debug",
    "/v1/_debug",
    "/v2/_debug",
    "/api/v1/_debug",
    "/api/v2/_debug",
    # Common resource debug endpoints
    "/users/_debug",
    "/accounts/_debug",
    "/admin/_debug",
    "/system/_debug",
    "/internal/_debug",
    # Versioned resource debug (VAmPI pattern: /users/v1/_debug)
    "/users/v1/_debug",
    "/users/v2/_debug",
    "/accounts/v1/_debug",
    "/admin/v1/_debug",
    # Alternative naming patterns
    "/_internal",
    "/api/_internal",
    "/_admin",
    "/api/_admin",
    "/_system",
    "/api/_system",
    "/_dump",
    "/api/_dump",
    "/_export",
    "/api/_export",
    # Debug query patterns (will be probed with ?debug=1 etc.)
    "/_test",
    "/api/_test",
]

# Backup file patterns
BACKUP_PATTERNS = [
    "{path}.bak",
    "{path}.backup",
    "{path}.old",
    "{path}.orig",
    "{path}.save",
    "{path}~",
    "{path}.swp",
    "{path}.swo",
    "#{path}#",
    "{path}.copy",
    "{path}.tmp",
    "{path}.temp",
    "{path}_backup",
    "{path}_old",
    "{path}_bak",
    "{path}.1",
    "{path}.2",
    "{base}.{ext}.bak",
    "{base}_backup.{ext}",
]

# Source code extensions
SOURCE_EXTENSIONS = [
    ".php", ".php3", ".php4", ".php5",
    ".py", ".pyc", ".pyo",
    ".rb", ".erb",
    ".java", ".class", ".jar",
    ".cs", ".aspx", ".asp",
    ".js", ".jsx", ".ts", ".tsx",
    ".vue", ".svelte",
    ".go",
    ".pl", ".pm",
    ".sh", ".bash",
    ".c", ".cpp", ".h",
]

# Configuration files
CONFIG_FILES = [
    # Web config
    "web.config",
    ".htaccess",
    ".htpasswd",
    "nginx.conf",
    "httpd.conf",

    # Application config
    "config.php",
    "config.inc.php",
    "config.py",
    "settings.py",
    "local_settings.py",
    "config.yml",
    "config.yaml",
    "config.json",
    "config.xml",
    "application.yml",
    "application.properties",
    "appsettings.json",

    # Environment
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.example",
    "env.php",

    # Database
    "database.yml",
    "database.php",
    "db.php",
    "db_config.php",

    # Secrets
    "secrets.yml",
    "credentials.json",
    "auth.json",
]

# VCS directories
VCS_PATHS = [
    ".git/",
    ".git/HEAD",
    ".git/config",
    ".git/index",
    ".gitignore",
    ".svn/",
    ".svn/entries",
    ".svn/wc.db",
    ".hg/",
    ".hg/hgrc",
    ".bzr/",
    "CVS/",
    "CVS/Root",
]

# =============================================================================
# ERROR PAGE DETECTION (FP Reduction)
# =============================================================================

# Generic error page indicators - disclosures in these are usually FP
GENERIC_ERROR_PAGE_PATTERNS = [
    # HTTP status in title/body
    r"<title>\s*404\s*(Not Found|Page Not Found|Error)?\s*</title>",
    r"<title>\s*500\s*(Internal Server Error|Server Error)?\s*</title>",
    r"<title>\s*403\s*(Forbidden|Access Denied)?\s*</title>",
    r"<title>\s*(Error|Oops|Something went wrong)</title>",
    r"<h1>\s*404\s*(Not Found)?\s*</h1>",
    r"<h1>\s*500\s*(Internal Server Error)?\s*</h1>",
    r"<h1>\s*(Error|Oops|Page Not Found)\s*</h1>",

    # Framework default error pages
    r"The page you are looking for could not be found",
    r"The requested URL was not found on this server",
    r"The server encountered an internal error",
    r"We're sorry, but something went wrong",
    r"This page doesn't exist",
    r"Page you requested was not found",
    r"Resource not found",

    # Framework-specific generic error templates
    r"<div class=\"error-page\">",
    r"<div id=\"error-page\">",
    r"class=\"error-template\"",
    r"class=\"http-error\"",
    r"<div class=\"exception\">",  # Generic exception div

    # Django/Rails/Laravel default error pages
    r"Django Debug Toolbar",  # Debug mode (different from production error)
    r"You're seeing this error because you have <code>DEBUG = True</code>",
    r"PrettyPrinted by BetterErrors",
    r"Whoops! There was an error",  # Laravel Whoops
    r"Laravel",  # Laravel error page
]

# Patterns that indicate legitimate disclosure (not just generic error page)
# FIX 2026-02-19: Added Node.js, Ruby, Go patterns and unquoted credentials
# Audit found: Node.js stack traces and unquoted credentials were being filtered
LEGITIMATE_DISCLOSURE_PATTERNS = [
    # Specific file paths in errors (not just generic message)
    r"in\s+(/[^\s]+\.php)\s+on line\s+\d+",  # PHP with specific file
    r"File\s+\"(/[^\"]+\.py)\",\s+line\s+\d+",  # Python with specific file (quotes)
    r"File\s+(/[^\s]+\.py),\s+line\s+\d+",      # Python without quotes
    r"at\s+[\w\.]+\((/[^\)]+\.java):\d+\)",     # Java with file path

    # FIX: Node.js / JavaScript patterns (Audit: these were missing)
    r"at\s+[\w\.]+\s+\(/[^\)]+\.js:\d+:\d+\)",  # Node.js: at function (/path/file.js:12:5)
    r"at\s+/[^\s]+\.js:\d+:\d+",                # Node.js: at /path/file.js:12:5
    r"(/[^\s]+\.ts):\d+:\d+",                   # TypeScript file path
    r"node_modules/[^\s]+",                      # Node modules path
    r"Error:\s+Cannot find module",              # Module error

    # FIX: Ruby patterns
    r"\.rb:\d+:in\s+`",                         # Ruby: file.rb:12:in `method'

    # FIX: Go patterns
    r"\.go:\d+",                                 # Go: file.go:123
    r"goroutine\s+\d+\s+\[",                    # Go stack trace

    # Actual database queries leaked
    r"SELECT\s+.*\s+FROM\s+",
    r"INSERT\s+INTO\s+",
    r"UPDATE\s+.*\s+SET\s+",
    r"DELETE\s+FROM\s+",
    r"DROP\s+TABLE",

    # Configuration values exposed (with quotes)
    r"password\s*[=:]\s*['\"][^'\"]+['\"]",
    r"api[_-]?key\s*[=:]\s*['\"][^'\"]+['\"]",
    r"secret\s*[=:]\s*['\"][^'\"]+['\"]",

    # FIX: Unquoted credentials (Audit: these were missing)
    r"password\s*[=:]\s*\S+",                   # password=value (no quotes)
    r"api[_-]?key\s*[=:]\s*\S+",                # api_key=value
    r"secret\s*[=:]\s*\S+",                     # secret=value
    r"token\s*[=:]\s*\S+",                      # token=value
    r"auth\s*[=:]\s*\S+",                       # auth=value
    r"(DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD)\s*[=:]\s*\S+",

    # Actual internal IPs (not just localhost reference in error)
    r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
    r"\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b",  # 172.16-31.x.x

    # FIX: Connection strings (often exposed in debug pages)
    r"(mongodb|mysql|postgresql|redis)://[^\s]+",
    r"Data Source=[^\s;]+",                     # .NET connection string
    r"Server=[^\s;]+;\s*Database=",             # SQL Server connection string
]


def is_generic_error_page(response_body: str, status_code: int = 0) -> bool:
    """
    Detect if response is a generic error page.

    Generic error pages (404, 500 templates) often contain stack traces
    or path info as part of their default template, not as actual leaks.

    Returns True if this looks like a generic error page.
    """
    if not response_body:
        return False

    # Check status code first (if provided)
    if status_code in (404, 403, 500, 502, 503):
        # Higher likelihood of being generic error page
        pass

    # Check for generic error page patterns
    for pattern in GENERIC_ERROR_PAGE_PATTERNS:
        if re.search(pattern, response_body, re.I | re.S):
            return True

    # Check for very short error responses (likely generic)
    body_text = re.sub(r'<[^>]+>', '', response_body).strip()
    if len(body_text) < 200 and status_code in (404, 403, 500):
        # Short response with error status = likely generic
        return True

    return False


def has_legitimate_disclosure(response_body: str) -> bool:
    """
    Check if response contains legitimate disclosure beyond generic error page.

    Even if a page is an error page, it might still have legitimate disclosures
    like actual database queries or credentials.
    """
    for pattern in LEGITIMATE_DISCLOSURE_PATTERNS:
        if re.search(pattern, response_body, re.I | re.S):
            return True
    return False


def filter_error_page_disclosures(
    items: list,
    response_body: str,
    status_code: int = 0,
) -> list:
    """
    Filter out disclosures that are part of generic error pages.

    Args:
        items: List of DisclosureItem objects
        response_body: HTTP response body
        status_code: HTTP status code

    Returns:
        Filtered list with error page FPs removed
    """
    if not items:
        return items

    # Check if this is a generic error page
    if not is_generic_error_page(response_body, status_code):
        return items  # Not an error page, keep all findings

    # It's an error page - check if there's legitimate disclosure
    if has_legitimate_disclosure(response_body):
        return items  # Has real leak, keep all findings

    # Filter out low-value disclosures from error pages
    filtered = []
    for item in items:
        # Keep CRITICAL items even from error pages
        if hasattr(item, 'severity') and item.severity == SeverityLevel.CRITICAL:
            filtered.append(item)
            continue

        # Keep credential/sensitive data leaks
        if item.disclosure_type in (
            DisclosureType.CREDENTIAL_LEAK,
            DisclosureType.CONFIG_FILE,
            DisclosureType.GIT_EXPOSURE,
            DisclosureType.SVN_EXPOSURE,
        ):
            filtered.append(item)
            continue

        # Skip version info, path disclosure, error messages from generic pages
        if item.disclosure_type in (
            DisclosureType.VERSION_INFO,
            DisclosureType.PATH_DISCLOSURE,
            DisclosureType.ERROR_MESSAGE,
            DisclosureType.STACK_TRACE,
            DisclosureType.INTERNAL_IP,
        ):
            # These are usually part of the error page template
            logger.debug(f"[InfoDisclosure] Filtered FP from error page: {item.disclosure_type.name}")
            continue

        # Keep everything else
        filtered.append(item)

    return filtered


# API documentation paths
API_DOC_PATHS = [
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/swagger/ui",
    "/swagger/index.html",
    "/api-docs",
    "/api/docs",
    "/docs/api",
    "/documentation",
    "/redoc",
    "/graphql",
    "/graphiql",
    "/playground",
    "/explorer",
    "/.well-known/openapi",
    "/openapi.json",
    "/openapi.yaml",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
]


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class DisclosureItem:
    """Individual disclosure item found."""

    disclosure_type: DisclosureType
    content: str
    location: str
    context: str
    severity: SeverityLevel
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DisclosureEndpoint:
    """Endpoint information for disclosure testing."""

    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    test_errors: bool = True
    test_backup: bool = True
    test_vcs: bool = True


@dataclass
class DisclosureFinding:
    """Information disclosure vulnerability finding."""

    id: str
    disclosure_type: DisclosureType
    severity: str
    confidence: float
    endpoint: str
    description: str
    impact: str
    remediation: str
    items: List[DisclosureItem]
    cwe_id: int
    cvss_score: float
    evidence: Dict[str, Any]


@dataclass
class ScanConfig:
    """Information disclosure scanner configuration."""

    target_url: str
    timeout: float = 30.0
    test_debug_endpoints: bool = True
    test_backup_files: bool = True
    test_vcs_exposure: bool = True
    test_config_files: bool = True
    test_api_docs: bool = True
    test_error_messages: bool = True
    test_comments: bool = True
    follow_redirects: bool = True
    max_paths_to_test: int = 200
    custom_paths: List[str] = field(default_factory=list)


# =============================================================================
# DETECTION ENGINES
# =============================================================================

class ErrorMessageDetector:
    """Detect sensitive information in error messages."""

    VERSION = "3.0.0"

    def detect(self, content: str) -> List[DisclosureItem]:
        """Detect error message disclosures."""
        items = []

        # Check for each error type
        for tech, patterns in ERROR_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.I | re.M)
                for match in matches:
                    items.append(DisclosureItem(
                        disclosure_type=DisclosureType.ERROR_MESSAGE,
                        content=match.group(0)[:200],
                        location="response_body",
                        context=f"{tech} error message",
                        severity=SeverityLevel.MEDIUM,
                        evidence={"technology": tech, "pattern": pattern},
                    ))

        # Check for stack traces
        if "Traceback" in content or "Stack Trace" in content or "at " in content:
            stack_match = re.search(
                r"(Traceback.*?(?=\n\n|\Z))|(Stack Trace:.*?(?=\n\n|\Z))",
                content, re.S | re.I
            )
            if stack_match:
                items.append(DisclosureItem(
                    disclosure_type=DisclosureType.STACK_TRACE,
                    content=stack_match.group(0)[:500],
                    location="response_body",
                    context="Full stack trace exposed",
                    severity=SeverityLevel.HIGH,
                ))

        return items


class DatabaseErrorDetector:
    """Detect database error messages."""

    VERSION = "3.0.0"

    def detect(self, content: str) -> List[DisclosureItem]:
        """Detect database error disclosures."""
        items = []

        for db_type, patterns in DATABASE_ERRORS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.I):
                    items.append(DisclosureItem(
                        disclosure_type=DisclosureType.DATABASE_ERROR,
                        content=re.search(pattern, content, re.I).group(0)[:200],
                        location="response_body",
                        context=f"{db_type} database error",
                        severity=SeverityLevel.HIGH,
                        evidence={"database_type": db_type},
                    ))
                    break  # One match per DB type is enough

        return items


class PathDisclosureDetector:
    """Detect server path disclosures."""

    VERSION = "3.0.0"

    def detect(self, content: str) -> List[DisclosureItem]:
        """Detect path disclosures."""
        items = []

        for pattern in PATH_PATTERNS:
            matches = re.finditer(pattern, content)
            for match in matches:
                path = match.group(0)
                # Filter out false positives (URLs, etc.)
                if not path.startswith("http") and not ".com" in path:
                    items.append(DisclosureItem(
                        disclosure_type=DisclosureType.PATH_DISCLOSURE,
                        content=path,
                        location="response_body",
                        context="Server path exposed",
                        severity=SeverityLevel.MEDIUM,
                    ))

        return items


class InternalIPDetector:
    """Detect internal IP address disclosures."""

    VERSION = "3.0.0"

    def detect(self, content: str, headers: Dict[str, str]) -> List[DisclosureItem]:
        """Detect internal IP disclosures."""
        items = []

        # Check response body
        for pattern in INTERNAL_IP_PATTERNS:
            matches = re.finditer(pattern, content, re.I)
            for match in matches:
                items.append(DisclosureItem(
                    disclosure_type=DisclosureType.INTERNAL_IP,
                    content=match.group(0),
                    location="response_body",
                    context="Internal IP address exposed",
                    severity=SeverityLevel.MEDIUM,
                ))

        # Check headers
        for header, value in headers.items():
            for pattern in INTERNAL_IP_PATTERNS:
                if re.search(pattern, value, re.I):
                    items.append(DisclosureItem(
                        disclosure_type=DisclosureType.INTERNAL_IP,
                        content=f"{header}: {value}",
                        location="response_header",
                        context=f"Internal IP in {header} header",
                        severity=SeverityLevel.MEDIUM,
                    ))

        return items


class VersionDisclosureDetector:
    """Detect software version disclosures."""

    VERSION = "3.0.0"

    def detect(self, content: str, headers: Dict[str, str]) -> List[DisclosureItem]:
        """Detect version information disclosures."""
        items = []

        # Check headers (Server, X-Powered-By, etc.)
        header_checks = {
            "Server": headers.get("Server", ""),
            "X-Powered-By": headers.get("X-Powered-By", ""),
            "X-AspNet-Version": headers.get("X-AspNet-Version", ""),
            "X-AspNetMvc-Version": headers.get("X-AspNetMvc-Version", ""),
        }

        for header, value in header_checks.items():
            if value:
                for tech, pattern in VERSION_PATTERNS.items():
                    match = re.search(pattern, value, re.I)
                    if match:
                        items.append(DisclosureItem(
                            disclosure_type=DisclosureType.VERSION_INFO,
                            content=f"{header}: {value}",
                            location="response_header",
                            context=f"{tech} version disclosed",
                            severity=SeverityLevel.LOW,
                            evidence={"technology": tech, "version": match.group(1)},
                        ))

        # Check response body for version info
        for tech, pattern in VERSION_PATTERNS.items():
            match = re.search(pattern, content, re.I)
            if match:
                items.append(DisclosureItem(
                    disclosure_type=DisclosureType.VERSION_INFO,
                    content=match.group(0),
                    location="response_body",
                    context=f"{tech} version in response",
                    severity=SeverityLevel.LOW,
                    evidence={"technology": tech, "version": match.group(1)},
                ))

        return items


class CommentLeakDetector:
    """Detect sensitive information in HTML/JS comments."""

    VERSION = "3.0.0"

    def detect(self, content: str) -> List[DisclosureItem]:
        """Detect sensitive comment disclosures."""
        items = []

        for pattern in COMMENT_PATTERNS:
            matches = re.finditer(pattern, content, re.I | re.S)
            for match in matches:
                comment = match.group(0)
                # Determine severity based on content
                severity = SeverityLevel.LOW
                if any(s in comment.lower() for s in ["password", "secret", "api_key", "token"]):
                    severity = SeverityLevel.HIGH
                elif any(s in comment.lower() for s in ["todo", "fixme", "debug"]):
                    severity = SeverityLevel.INFO

                items.append(DisclosureItem(
                    disclosure_type=DisclosureType.COMMENT_LEAK,
                    content=comment[:200],
                    location="response_body",
                    context="Sensitive comment found",
                    severity=severity,
                ))

        return items


# =============================================================================
# MAIN SCANNER CLASS
# =============================================================================

class InfoDisclosureScanner:
    """
    Enterprise-grade information disclosure vulnerability scanner.

    Detects:
    - Verbose error messages and stack traces
    - Debug endpoints (phpinfo, actuator, etc.)
    - Source code and backup file exposure
    - Version information leakage
    - Database error messages
    - Server path disclosure
    - Internal IP address exposure
    - Git/SVN repository exposure
    - Configuration file exposure
    - Sensitive data in comments
    - API documentation exposure

    Usage:
        scanner = InfoDisclosureScanner()
        findings = await scanner.scan("https://target.com")
    """

    VERSION = "3.0.0"
    CWE_ID = 200  # CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

    def __init__(
        self,
        http_client: Any = None,
        config: Optional[ScanConfig] = None,
    ):
        """Initialize the scanner."""
        self.http_client = http_client
        self.config = config
        self.error_detector = ErrorMessageDetector()
        self.db_error_detector = DatabaseErrorDetector()
        self.path_detector = PathDisclosureDetector()
        self.ip_detector = InternalIPDetector()
        self.version_detector = VersionDisclosureDetector()
        self.comment_detector = CommentLeakDetector()
        self.findings: List[DisclosureFinding] = []
        self._session_id = str(uuid.uuid4())[:8]
        self._tested_urls: Set[str] = set()

    async def scan(
        self,
        target_url: str,
        asset_data: Optional[Dict[str, Any]] = None,
        rate_limiter: Any = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Scan for information disclosure vulnerabilities.

        Args:
            target_url: Target URL to scan
            asset_data: Asset data with endpoints, forms (optional)
            rate_limiter: Rate limiter (optional)
            **kwargs: Additional configuration

        Returns:
            List of discovered vulnerabilities
        """
        logger.info(f"[InfoDisclosure] Starting scan: {target_url}")

        # FIX: Store rate limiter for use in HTTP requests
        self._rate_limiter = rate_limiter

        # Create config if not provided
        if not self.config:
            self.config = ScanConfig(target_url=target_url)

        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Test main page first
        await self._test_page(target_url)

        # Test debug endpoints
        if self.config.test_debug_endpoints:
            await self._test_debug_endpoints(base_url)

        # Test backup files
        if self.config.test_backup_files:
            await self._test_backup_files(target_url)

        # Test VCS exposure
        if self.config.test_vcs_exposure:
            await self._test_vcs_exposure(base_url)

        # Test config files
        if self.config.test_config_files:
            await self._test_config_files(base_url)

        # Test API documentation
        if self.config.test_api_docs:
            await self._test_api_docs(base_url)

        # Test error messages
        if self.config.test_error_messages:
            await self._test_error_triggers(target_url)

        logger.info(f"[InfoDisclosure] Scan complete. Found {len(self.findings)} vulnerabilities")
        return {"findings": self.findings, "info": []}

    async def _acquire_rate_limit(self) -> None:
        """Acquire rate limit before making HTTP request."""
        if hasattr(self, '_rate_limiter') and self._rate_limiter:
            try:
                await self._rate_limiter.acquire()
            except Exception:
                pass  # Proceed if rate limiter fails

    async def _test_page(self, url: str) -> None:
        """Test a page for information disclosure."""
        if url in self._tested_urls:
            return
        self._tested_urls.add(url)

        logger.debug(f"[InfoDisclosure] Testing: {url}")

        response_headers = {}
        response_body = ""
        response_code = 0

        try:
            if self.http_client:
                await self._acquire_rate_limit()  # FIX: Rate limit before request
                response = await self.http_client.get(
                    url,
                    follow_redirects=self.config.follow_redirects if self.config else True,
                    timeout=self.config.timeout if self.config else 30.0,
                )
                response_code = response.status_code
                response_body = response.text if hasattr(response, 'text') else str(response.content)
                response_headers = dict(response.headers) if hasattr(response, 'headers') else {}
            else:
                # Simulation
                response_code = 200
                response_body = "<html><body>Test content</body></html>"

        except Exception as e:
            logger.debug(f"[InfoDisclosure] Request failed: {e}")
            return

        # Run all detectors
        all_items: List[DisclosureItem] = []

        # Error messages
        all_items.extend(self.error_detector.detect(response_body))

        # Database errors
        all_items.extend(self.db_error_detector.detect(response_body))

        # Path disclosure
        all_items.extend(self.path_detector.detect(response_body))

        # Internal IPs
        all_items.extend(self.ip_detector.detect(response_body, response_headers))

        # Version info
        all_items.extend(self.version_detector.detect(response_body, response_headers))

        # Comments (if enabled)
        if self.config and self.config.test_comments:
            all_items.extend(self.comment_detector.detect(response_body))

        # FP REDUCTION: Filter out disclosures from generic error pages
        original_count = len(all_items)
        all_items = filter_error_page_disclosures(all_items, response_body, response_code)
        if len(all_items) < original_count:
            logger.debug(f"[InfoDisclosure] Filtered {original_count - len(all_items)} FPs from error page at {url}")

        # Create findings from items
        self._create_findings_from_items(url, all_items)

    async def _test_debug_endpoints(self, base_url: str) -> None:
        """Test for debug endpoint exposure."""
        logger.debug("[InfoDisclosure] Testing debug endpoints")

        # FIX 2026-02-20: GENERALIST — Detect context path for apps like /WebGoat/
        # Many Java apps run at a context path, not the root
        context_paths = [""]  # Start with root
        if hasattr(self, 'config') and self.config and self.config.target_url:
            parsed_target = urlparse(self.config.target_url)
            path_parts = parsed_target.path.strip("/").split("/")
            if path_parts and path_parts[0]:
                context_paths.append(f"/{path_parts[0]}")
                logger.debug(f"[InfoDisclosure] Using context path: /{path_parts[0]}")

        # Build paths to test: standard + context-prefixed
        paths_to_test = set()
        for path in DEBUG_ENDPOINTS:
            paths_to_test.add(path)
            # Add context-prefixed versions for actuator endpoints
            if "/actuator" in path:
                for ctx in context_paths:
                    if ctx:
                        prefixed = f"{ctx}{path}"
                        paths_to_test.add(prefixed)

        for path in paths_to_test:
            url = urljoin(base_url, path)
            if url in self._tested_urls:
                continue
            self._tested_urls.add(url)

            try:
                if self.http_client:
                    await self._acquire_rate_limit()  # FIX: Rate limit before request
                    response = await self.http_client.get(url, timeout=10.0)

                    if response.status_code == 200:
                        response_body = response.text if hasattr(response, 'text') else ""

                        # Check for specific debug indicators
                        is_debug = False
                        debug_type = None
                        severity = "HIGH"

                        if "phpinfo()" in response_body or "PHP Version" in response_body:
                            is_debug = True
                            debug_type = "phpinfo"
                        elif "_links" in response_body and "/actuator" in response_body:
                            # Spring Boot actuator root endpoint (HAL+JSON format)
                            is_debug = True
                            debug_type = "actuator"
                            # Check for sensitive sub-endpoints
                            await self._check_actuator_sensitive_endpoints(url, response_body)
                        elif "/actuator" in path:
                            is_debug = True
                            debug_type = "actuator"
                            # Sensitive actuator endpoints get CRITICAL severity
                            if any(s in path for s in ["/env", "/configprops", "/heapdump", "/jolokia"]):
                                severity = "CRITICAL"
                        elif "server-status" in response_body or "Apache Status" in response_body:
                            is_debug = True
                            debug_type = "server-status"
                        elif "Django Debug" in response_body:
                            is_debug = True
                            debug_type = "django-debug"

                        # FIX 2026-02-20: GENERALIST — Detect JSON credential exposure
                        # API debug endpoints like VAmPI's /_debug often return passwords in JSON
                        # This works for any API, not just specific debug types
                        if not is_debug and "_debug" in path.lower() or "_internal" in path.lower() or "_dump" in path.lower():
                            # Check if response looks like JSON with credentials
                            credentials_found = await self._check_json_credential_exposure(url, response_body, path)
                            if credentials_found:
                                is_debug = True
                                debug_type = "api-debug-credentials"
                                severity = "CRITICAL"  # Always CRITICAL when passwords exposed

                        if is_debug:
                            self._create_finding(
                                disclosure_type=DisclosureType.DEBUG_ENDPOINT,
                                severity=severity,
                                confidence=0.95,
                                endpoint=url,
                                description=f"Debug endpoint exposed: {path}",
                                impact="Attackers can gather sensitive system information, credentials, and environment variables.",
                                items=[DisclosureItem(
                                    disclosure_type=DisclosureType.DEBUG_ENDPOINT,
                                    content=f"Debug endpoint: {path}",
                                    location=url,
                                    context=f"{debug_type} endpoint",
                                    severity=SeverityLevel.CRITICAL if severity == "CRITICAL" else SeverityLevel.HIGH,
                                )],
                            )

            except Exception as e:
                logger.debug(f"[InfoDisclosure] Request error: {e}")

    async def _check_actuator_sensitive_endpoints(self, actuator_url: str, response_body: str) -> None:
        """
        Check for sensitive actuator sub-endpoints when actuator root is found.

        GENERALIST: Works on any Spring Boot app with exposed actuator.
        """
        import json
        try:
            data = json.loads(response_body)
            links = data.get("_links", {})

            # Sensitive endpoints that expose credentials/secrets
            sensitive_endpoints = {
                "env": ("CRITICAL", "Environment variables may contain credentials, API keys, database passwords"),
                "configprops": ("CRITICAL", "Configuration properties may expose secrets and internal settings"),
                "heapdump": ("CRITICAL", "Memory dump may contain credentials, session tokens, and sensitive data"),
                "jolokia": ("CRITICAL", "JMX endpoint may allow remote code execution"),
                "httptrace": ("HIGH", "HTTP traces may expose session tokens and request data"),
                "trace": ("HIGH", "Traces may expose session tokens and request data"),
                "mappings": ("MEDIUM", "Endpoint mappings reveal application structure"),
                "beans": ("LOW", "Bean information reveals application components"),
            }

            for endpoint_name, (severity, impact) in sensitive_endpoints.items():
                if endpoint_name in links:
                    endpoint_data = links[endpoint_name]
                    href = endpoint_data.get("href", "") if isinstance(endpoint_data, dict) else ""

                    if href:
                        # Test if endpoint is accessible
                        try:
                            await self._acquire_rate_limit()
                            test_response = await self.http_client.get(href, timeout=10.0)

                            if test_response.status_code == 200:
                                self._create_finding(
                                    disclosure_type=DisclosureType.DEBUG_ENDPOINT,
                                    severity=severity,
                                    confidence=0.98,
                                    endpoint=href,
                                    description=f"Spring Boot Actuator '{endpoint_name}' endpoint exposed",
                                    impact=impact,
                                    items=[DisclosureItem(
                                        disclosure_type=DisclosureType.DEBUG_ENDPOINT,
                                        content=f"Actuator {endpoint_name}: {href}",
                                        location=href,
                                        context=f"Spring Boot Actuator sensitive endpoint",
                                        severity=SeverityLevel.CRITICAL if severity == "CRITICAL" else SeverityLevel.HIGH,
                                    )],
                                )
                        except Exception:
                            pass

        except json.JSONDecodeError:
            pass

    async def _check_json_credential_exposure(self, url: str, response_body: str, path: str) -> bool:
        """
        Check if JSON response contains credential exposure (passwords, tokens, secrets).

        GENERALIST: Works for any REST API debug endpoint, not just specific frameworks.
        Pattern: VAmPI's /users/v1/_debug returns {"users": [{"username": "admin", "password": "..."}]}

        Returns True if credentials found and a finding was created.
        """
        import json

        # Only check JSON responses
        if not response_body.strip().startswith(("{", "[")):
            return False

        try:
            data = json.loads(response_body)
        except json.JSONDecodeError:
            return False

        # Sensitive field patterns (lowercase for matching)
        sensitive_fields = {
            "password": "Password exposed in JSON response",
            "passwd": "Password exposed in JSON response",
            "pwd": "Password exposed in JSON response",
            "secret": "Secret value exposed in JSON response",
            "api_key": "API key exposed in JSON response",
            "apikey": "API key exposed in JSON response",
            "api-key": "API key exposed in JSON response",
            "private_key": "Private key exposed in JSON response",
            "privatekey": "Private key exposed in JSON response",
            "access_token": "Access token exposed in JSON response",
            "accesstoken": "Access token exposed in JSON response",
            "refresh_token": "Refresh token exposed in JSON response",
            "auth_token": "Auth token exposed in JSON response",
            "bearer_token": "Bearer token exposed in JSON response",
            "credentials": "Credentials exposed in JSON response",
            "credit_card": "Credit card data exposed in JSON response",
            "ssn": "Social Security Number exposed in JSON response",
            "bank_account": "Bank account exposed in JSON response",
        }

        # Recursively search for sensitive fields with non-empty values
        exposed_fields = []

        def search_object(obj, parent_key=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    full_key = f"{parent_key}.{key}" if parent_key else key
                    key_lower = key.lower()

                    # Check if key matches sensitive pattern
                    for sensitive_key, description in sensitive_fields.items():
                        if sensitive_key in key_lower:
                            # Only flag if value is non-empty and not a placeholder
                            if value and isinstance(value, str) and len(value) > 0:
                                # Skip obvious placeholders
                                if value.lower() not in {"null", "none", "", "*****", "***", "redacted", "[redacted]"}:
                                    exposed_fields.append((full_key, sensitive_key, description))
                            break

                    # Recurse into nested objects
                    search_object(value, full_key)

            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    search_object(item, f"{parent_key}[{i}]")

        search_object(data)

        if exposed_fields:
            # Create a finding for credential exposure
            field_list = ", ".join([f[0] for f in exposed_fields[:5]])  # Limit to 5 examples
            unique_types = set(f[1] for f in exposed_fields)

            logger.info(f"[InfoDisclosure] CRITICAL: Credential exposure at {url} — fields: {field_list}")

            self._create_finding(
                disclosure_type=DisclosureType.DEBUG_ENDPOINT,
                severity="CRITICAL",
                confidence=0.98,
                endpoint=url,
                description=f"API debug endpoint exposes credentials: {', '.join(unique_types)}",
                impact=f"Attackers can extract sensitive data including {', '.join(unique_types)}. Found in fields: {field_list}",
                items=[DisclosureItem(
                    disclosure_type=DisclosureType.DEBUG_ENDPOINT,
                    content=f"Credential exposure: {field_list}",
                    location=url,
                    context=f"API debug endpoint with {len(exposed_fields)} exposed credential field(s)",
                    severity=SeverityLevel.CRITICAL,
                )],
            )
            return True

        return False

    async def _test_backup_files(self, original_url: str) -> None:
        """Test for backup file exposure."""
        logger.debug("[InfoDisclosure] Testing backup files")

        parsed = urlparse(original_url)
        path = parsed.path or "/"

        # Get base and extension
        if "." in path:
            base = path.rsplit(".", 1)[0]
            ext = path.rsplit(".", 1)[1]
        else:
            base = path
            ext = ""

        # Generate backup file URLs
        backup_urls = []
        for pattern in BACKUP_PATTERNS[:10]:  # Limit patterns
            backup_path = pattern.format(path=path, base=base, ext=ext)
            backup_url = f"{parsed.scheme}://{parsed.netloc}{backup_path}"
            if backup_url not in self._tested_urls:
                backup_urls.append(backup_url)
                self._tested_urls.add(backup_url)

        # Test backup URLs
        for url in backup_urls:
            try:
                if self.http_client:
                    await self._acquire_rate_limit()  # FIX: Rate limit before request
                    response = await self.http_client.get(url, timeout=10.0)

                    if response.status_code == 200:
                        content_type = response.headers.get("Content-Type", "")

                        # Check if it looks like source code
                        if "text/html" not in content_type.lower():
                            response_body = response.text if hasattr(response, 'text') else ""

                            if len(response_body) > 100:
                                self._create_finding(
                                    disclosure_type=DisclosureType.BACKUP_FILE,
                                    severity="HIGH",
                                    confidence=0.85,
                                    endpoint=url,
                                    description=f"Backup file accessible: {url}",
                                    impact="Backup files may contain source code or sensitive data.",
                                    items=[DisclosureItem(
                                        disclosure_type=DisclosureType.BACKUP_FILE,
                                        content=f"Backup file: {url}",
                                        location=url,
                                        context="Backup file exposed",
                                        severity=SeverityLevel.HIGH,
                                    )],
                                )

            except Exception as e:
                logger.debug(f"[InfoDisclosure] Request error: {e}")

    async def _test_vcs_exposure(self, base_url: str) -> None:
        """Test for version control system exposure."""
        logger.debug("[InfoDisclosure] Testing VCS exposure")

        for path in VCS_PATHS:
            url = urljoin(base_url, path)
            if url in self._tested_urls:
                continue
            self._tested_urls.add(url)

            try:
                if self.http_client:
                    await self._acquire_rate_limit()  # FIX: Rate limit before request
                    response = await self.http_client.get(url, timeout=10.0)

                    if response.status_code == 200:
                        response_body = response.text if hasattr(response, 'text') else ""

                        # Determine VCS type
                        vcs_type = None
                        if ".git" in path:
                            vcs_type = "git"
                            # Check for git-specific content
                            if "ref:" in response_body or "gitdir:" in response_body:
                                pass  # Valid git exposure
                            else:
                                continue
                        elif ".svn" in path:
                            vcs_type = "svn"
                        elif ".hg" in path:
                            vcs_type = "mercurial"

                        if vcs_type:
                            disclosure_type = DisclosureType.GIT_EXPOSURE if vcs_type == "git" else DisclosureType.SVN_EXPOSURE

                            self._create_finding(
                                disclosure_type=disclosure_type,
                                severity="CRITICAL",
                                confidence=0.95,
                                endpoint=url,
                                description=f"{vcs_type.upper()} repository exposed: {path}",
                                impact=f"Attackers can download entire source code repository "
                                       f"and commit history using tools like git-dumper.",
                                items=[DisclosureItem(
                                    disclosure_type=disclosure_type,
                                    content=f"VCS exposure: {path}",
                                    location=url,
                                    context=f"{vcs_type} repository",
                                    severity=SeverityLevel.CRITICAL,
                                )],
                            )

            except Exception as e:
                logger.debug(f"[InfoDisclosure] Request error: {e}")

    async def _test_config_files(self, base_url: str) -> None:
        """Test for configuration file exposure."""
        logger.debug("[InfoDisclosure] Testing config files")

        for filename in CONFIG_FILES[:20]:  # Limit files
            url = urljoin(base_url, filename)
            if url in self._tested_urls:
                continue
            self._tested_urls.add(url)

            try:
                if self.http_client:
                    await self._acquire_rate_limit()  # FIX: Rate limit before request
                    response = await self.http_client.get(url, timeout=10.0)

                    if response.status_code == 200:
                        response_body = response.text if hasattr(response, 'text') else ""

                        # Check if it looks like a config file (not HTML)
                        if not response_body.strip().startswith("<!DOCTYPE") and \
                           not response_body.strip().startswith("<html"):

                            # Check for sensitive patterns
                            severity = "HIGH"
                            if any(s in response_body.lower() for s in ["password", "secret", "api_key", "token"]):
                                severity = "CRITICAL"

                            self._create_finding(
                                disclosure_type=DisclosureType.CONFIG_FILE,
                                severity=severity,
                                confidence=0.90,
                                endpoint=url,
                                description=f"Configuration file exposed: {filename}",
                                impact="Configuration files may contain credentials and sensitive settings.",
                                items=[DisclosureItem(
                                    disclosure_type=DisclosureType.CONFIG_FILE,
                                    content=f"Config file: {filename}",
                                    location=url,
                                    context="Configuration file",
                                    severity=SeverityLevel.CRITICAL if severity == "CRITICAL" else SeverityLevel.HIGH,
                                )],
                            )

            except Exception as e:
                logger.debug(f"[InfoDisclosure] Request error: {e}")

    async def _test_api_docs(self, base_url: str) -> None:
        """Test for unprotected API documentation."""
        logger.debug("[InfoDisclosure] Testing API documentation")

        for path in API_DOC_PATHS:
            url = urljoin(base_url, path)
            if url in self._tested_urls:
                continue
            self._tested_urls.add(url)

            try:
                if self.http_client:
                    await self._acquire_rate_limit()  # FIX: Rate limit before request
                    response = await self.http_client.get(url, timeout=10.0)

                    if response.status_code == 200:
                        response_body = response.text if hasattr(response, 'text') else ""

                        # Check for API doc indicators
                        is_api_doc = any(ind in response_body.lower() for ind in [
                            "swagger", "openapi", "graphql", "api documentation",
                            "endpoints", "routes", "operations"
                        ])

                        if is_api_doc:
                            self._create_finding(
                                disclosure_type=DisclosureType.API_DOCS,
                                severity="MEDIUM",
                                confidence=0.85,
                                endpoint=url,
                                description=f"API documentation exposed: {path}",
                                impact="Attackers can learn about all API endpoints and their parameters.",
                                items=[DisclosureItem(
                                    disclosure_type=DisclosureType.API_DOCS,
                                    content=f"API docs: {path}",
                                    location=url,
                                    context="API documentation",
                                    severity=SeverityLevel.MEDIUM,
                                )],
                            )

            except Exception as e:
                logger.debug(f"[InfoDisclosure] Request error: {e}")

    async def _test_error_triggers(self, target_url: str) -> None:
        """Test for error message disclosure by triggering errors."""
        logger.debug("[InfoDisclosure] Testing error triggers")

        # Error-triggering payloads
        error_payloads = [
            ("id", "1'"),                    # SQL error
            ("id", "<script>"),              # Potential error
            ("id", "{{7*7}}"),               # SSTI error
            ("file", "../../../etc/passwd"), # Path error
            ("callback", "alert(1)"),        # JSONP error
            ("format", "xxx"),               # Format error
        ]

        parsed = urlparse(target_url)

        for param, value in error_payloads:
            test_url = f"{target_url}?{param}={quote(value)}"

            try:
                if self.http_client:
                    await self._acquire_rate_limit()  # FIX: Rate limit before request
                    response = await self.http_client.get(test_url, timeout=10.0)
                    response_body = response.text if hasattr(response, 'text') else ""
                    response_code = response.status_code if hasattr(response, 'status_code') else 0

                    # Check for error disclosures
                    items = self.error_detector.detect(response_body)
                    items.extend(self.db_error_detector.detect(response_body))
                    items.extend(self.path_detector.detect(response_body))

                    # FP REDUCTION: Filter out generic error page disclosures
                    # Error trigger tests are especially prone to FPs
                    items = filter_error_page_disclosures(items, response_body, response_code)

                    if items:
                        self._create_findings_from_items(test_url, items)
                        break  # One error is enough to confirm

            except Exception as e:
                logger.debug(f"[InfoDisclosure] Request error: {e}")

    def _create_findings_from_items(self, url: str, items: List[DisclosureItem]) -> None:
        """Create findings from disclosure items."""
        # Group items by type
        grouped: Dict[DisclosureType, List[DisclosureItem]] = {}
        for item in items:
            if item.disclosure_type not in grouped:
                grouped[item.disclosure_type] = []
            grouped[item.disclosure_type].append(item)

        # Create finding for each group
        for dtype, type_items in grouped.items():
            # Get highest severity
            severity = max(type_items, key=lambda x: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(x.severity.value)).severity

            self._create_finding(
                disclosure_type=dtype,
                severity=severity.value,
                confidence=0.80,
                endpoint=url,
                description=self._get_description(dtype),
                impact=self._get_impact(dtype),
                items=type_items,
            )

    def _get_description(self, dtype: DisclosureType) -> str:
        """Get description for disclosure type."""
        descriptions = {
            DisclosureType.ERROR_MESSAGE: "Verbose error messages expose internal details",
            DisclosureType.STACK_TRACE: "Full stack trace exposes code structure and paths",
            DisclosureType.DEBUG_ENDPOINT: "Debug endpoint exposes sensitive system information",
            DisclosureType.SOURCE_CODE: "Source code is directly accessible",
            DisclosureType.BACKUP_FILE: "Backup file exposes source code or data",
            DisclosureType.VERSION_INFO: "Software version information is disclosed",
            DisclosureType.DATABASE_ERROR: "Database error messages reveal schema details",
            DisclosureType.PATH_DISCLOSURE: "Server file paths are exposed",
            DisclosureType.INTERNAL_IP: "Internal IP addresses are disclosed",
            DisclosureType.GIT_EXPOSURE: "Git repository is publicly accessible",
            DisclosureType.SVN_EXPOSURE: "SVN repository is publicly accessible",
            DisclosureType.CONFIG_FILE: "Configuration file is accessible",
            DisclosureType.PHPINFO: "phpinfo() page exposes server configuration",
            DisclosureType.SERVER_STATUS: "Server status page is publicly accessible",
            DisclosureType.COMMENT_LEAK: "Sensitive information found in comments",
            DisclosureType.API_DOCS: "API documentation is publicly accessible",
        }
        return descriptions.get(dtype, "Information disclosure detected")

    def _get_impact(self, dtype: DisclosureType) -> str:
        """Get impact description for disclosure type."""
        impacts = {
            DisclosureType.ERROR_MESSAGE: "Attackers can understand application internals and find vulnerabilities",
            DisclosureType.STACK_TRACE: "Reveals code paths, file locations, and potential vulnerabilities",
            DisclosureType.DEBUG_ENDPOINT: "Exposes configuration, environment variables, and sensitive data",
            DisclosureType.SOURCE_CODE: "Complete source code exposure enables finding all vulnerabilities",
            DisclosureType.BACKUP_FILE: "May contain credentials, API keys, or business logic",
            DisclosureType.VERSION_INFO: "Enables targeted attacks against known vulnerabilities",
            DisclosureType.DATABASE_ERROR: "Reveals database structure for SQL injection attacks",
            DisclosureType.PATH_DISCLOSURE: "Helps attackers map the server file system",
            DisclosureType.INTERNAL_IP: "Reveals internal network structure for pivoting",
            DisclosureType.GIT_EXPOSURE: "Attackers can download entire codebase and history",
            DisclosureType.SVN_EXPOSURE: "Attackers can download entire codebase and history",
            DisclosureType.CONFIG_FILE: "May contain credentials, API keys, database connections",
            DisclosureType.PHPINFO: "Reveals PHP configuration, paths, and loaded modules",
            DisclosureType.SERVER_STATUS: "Reveals server load, connections, and requests",
            DisclosureType.COMMENT_LEAK: "May reveal credentials, TODOs, or security notes",
            DisclosureType.API_DOCS: "Reveals all API endpoints and their parameters",
        }
        return impacts.get(dtype, "Information can be used to plan further attacks")

    def _create_finding(
        self,
        disclosure_type: DisclosureType,
        severity: str,
        confidence: float,
        endpoint: str,
        description: str,
        impact: str,
        items: List[DisclosureItem],
    ) -> None:
        """Create and store a finding."""
        # Avoid duplicates
        for existing in self.findings:
            if existing.endpoint == endpoint and existing.disclosure_type == disclosure_type:
                return

        finding = DisclosureFinding(
            id=f"INFO-{len(self.findings)+1:04d}",
            disclosure_type=disclosure_type,
            severity=severity,
            confidence=confidence,
            endpoint=endpoint,
            description=description,
            impact=impact,
            remediation=self._generate_remediation(disclosure_type),
            items=items,
            cwe_id=self.CWE_ID,
            cvss_score=self._calculate_cvss(severity),
            evidence={
                "items_found": len(items),
                "disclosure_contents": [item.content[:100] for item in items[:5]],
            },
        )

        self.findings.append(finding)
        logger.info(f"[InfoDisclosure] Found: {disclosure_type.name} ({severity})")

    def _generate_remediation(self, dtype: DisclosureType) -> str:
        """Generate remediation advice."""
        remediations = {
            DisclosureType.ERROR_MESSAGE: """
1. Configure custom error pages for production
2. Disable display_errors in PHP
3. Set DEBUG=False in Django/Flask
4. Use generic error messages for users
5. Log detailed errors server-side only
""",
            DisclosureType.DEBUG_ENDPOINT: """
1. Disable debug endpoints in production
2. Protect actuator endpoints with authentication
3. Remove phpinfo() files from production
4. Restrict access by IP if endpoints are needed
""",
            DisclosureType.GIT_EXPOSURE: """
1. Block access to .git directory in web server config
2. Remove .git from production deployments
3. Use .htaccess: RedirectMatch 404 /\\.git
4. Or nginx: location ~ /\\.git { deny all; }
""",
            DisclosureType.CONFIG_FILE: """
1. Store config files outside web root
2. Block access to sensitive extensions
3. Use environment variables for secrets
4. Encrypt sensitive configuration values
""",
            DisclosureType.VERSION_INFO: """
1. Remove version from Server header (ServerTokens Prod)
2. Remove X-Powered-By header
3. Configure expose_php = Off in PHP
4. Don't include version in error pages
""",
        }
        return remediations.get(dtype, """
1. Review and remove unnecessary information exposure
2. Implement proper access controls
3. Use least privilege principle
4. Regular security audits
""")

    def _calculate_cvss(self, severity: str) -> float:
        """Calculate CVSS score based on severity."""
        cvss_map = {
            "CRITICAL": 7.5,
            "HIGH": 5.3,
            "MEDIUM": 4.0,
            "LOW": 2.0,
            "INFO": 0.0,
        }
        return cvss_map.get(severity, 3.0)

    def get_findings(self) -> List[DisclosureFinding]:
        """Get all findings."""
        return self.findings

    def get_statistics(self) -> Dict[str, Any]:
        """Get scan statistics."""
        return {
            "total_findings": len(self.findings),
            "critical_findings": len([f for f in self.findings if f.severity == "CRITICAL"]),
            "high_findings": len([f for f in self.findings if f.severity == "HIGH"]),
            "medium_findings": len([f for f in self.findings if f.severity == "MEDIUM"]),
            "low_findings": len([f for f in self.findings if f.severity == "LOW"]),
            "disclosure_types": list(set(f.disclosure_type.name for f in self.findings)),
            "urls_tested": len(self._tested_urls),
        }


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================

def create_info_disclosure_scanner(
    http_client: Any = None,
    config: Optional[ScanConfig] = None,
) -> InfoDisclosureScanner:
    """Create a configured information disclosure scanner instance."""
    return InfoDisclosureScanner(http_client=http_client, config=config)


async def scan_info_disclosure(
    target_url: str,
    http_client: Any = None,
    **kwargs,
) -> List[DisclosureFinding]:
    """Convenience function to scan for information disclosure."""
    scanner = create_info_disclosure_scanner(http_client=http_client)
    return await scanner.scan(target_url, **kwargs)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Version
    "VERSION",

    # Enums
    "DisclosureType",
    "SeverityLevel",

    # Data classes
    "DisclosureItem",
    "DisclosureEndpoint",
    "DisclosureFinding",
    "ScanConfig",

    # Classes
    "InfoDisclosureScanner",
    "ErrorMessageDetector",
    "DatabaseErrorDetector",
    "PathDisclosureDetector",
    "InternalIPDetector",
    "VersionDisclosureDetector",
    "CommentLeakDetector",

    # Constants
    "ERROR_PATTERNS",
    "DATABASE_ERRORS",
    "PATH_PATTERNS",
    "INTERNAL_IP_PATTERNS",
    "VERSION_PATTERNS",
    "DEBUG_ENDPOINTS",
    "CONFIG_FILES",
    "VCS_PATHS",
    "API_DOC_PATHS",

    # Factory functions
    "create_info_disclosure_scanner",
    "scan_info_disclosure",
]
