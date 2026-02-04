"""
Enterprise Technology Intelligence System v2.0
==============================================

Professional-grade technology fingerprinting, version detection,
and intelligent module selection for penetration testing.

Features:
- 100+ technology fingerprints with multiple detection vectors
- Version detection with regex patterns from multiple sources
- CVE/vulnerability correlation database
- EOL (End-of-Life) tracking
- Intelligent module recommendations per technology
- Technology stack analysis for combo vulnerabilities
- Confidence scoring with evidence tracking

Usage:
    intel = TechIntelligence()
    result = await intel.analyze(target_url)

    # Get detected technologies with versions
    for tech in result.technologies:
        print(f"{tech.name} {tech.version} (confidence: {tech.confidence})")

    # Get recommended modules
    modules = result.recommended_modules
    skip = result.skip_modules
"""

from __future__ import annotations

import asyncio
import re
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
from datetime import datetime

import httpx

logger = logging.getLogger(__name__)

# Flag to track if orchestrator is available for whatweb/httpx integration
_ORCHESTRATOR_AVAILABLE = True
try:
    from scanning.linux_tools_orchestrator import LinuxToolsOrchestrator, ToolStatus
except ImportError:
    _ORCHESTRATOR_AVAILABLE = False
    logger.debug("LinuxToolsOrchestrator not available - whatweb/httpx integration disabled")


class TechCategory(Enum):
    """Technology categories for classification."""
    WEB_SERVER = "web_server"
    LANGUAGE = "language"
    FRAMEWORK = "framework"
    CMS = "cms"
    DATABASE = "database"
    CACHE = "cache"
    CDN = "cdn"
    BAAS = "baas"
    FRONTEND = "frontend"
    JS_LIBRARY = "js_library"
    HOSTING = "hosting"
    CONTAINER = "container"
    API_GATEWAY = "api_gateway"
    AUTH_PROVIDER = "auth_provider"
    ANALYTICS = "analytics"
    PAYMENT = "payment"
    MONITORING = "monitoring"
    BUILD_TOOL = "build_tool"
    SECURITY = "security"


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class KnownVulnerability:
    """Known vulnerability for a technology version."""
    cve_id: str
    severity: Severity
    affected_versions: list[str]  # Version patterns like "<5.9.0", ">=4.0,<4.5"
    description: str
    cvss_score: float = 0.0
    exploit_available: bool = False
    patch_version: str = ""


@dataclass
class DetectionPattern:
    """Pattern for detecting a technology."""
    source: str  # "header", "html", "cookie", "url", "js", "meta", "response"
    pattern: str  # Regex pattern
    confidence: float = 0.8  # Base confidence for this pattern
    version_group: int = 0  # Capture group for version (0 = no version)
    requires: list[str] = field(default_factory=list)  # Required patterns to also match


@dataclass
class TechnologyFingerprint:
    """Complete fingerprint for a technology."""
    name: str
    category: TechCategory
    aliases: list[str] = field(default_factory=list)

    # Detection patterns (multiple vectors)
    patterns: list[DetectionPattern] = field(default_factory=list)

    # Version detection
    version_patterns: list[DetectionPattern] = field(default_factory=list)
    latest_version: str = ""
    eol_date: Optional[str] = None  # ISO date or None if current

    # Security implications
    known_vulns: list[KnownVulnerability] = field(default_factory=list)
    common_misconfigs: list[str] = field(default_factory=list)

    # Module recommendations
    recommended_modules: list[str] = field(default_factory=list)
    skip_modules: list[str] = field(default_factory=list)
    skip_reasons: dict[str, str] = field(default_factory=dict)

    # Priority for module selection (higher = more important)
    priority: int = 50


@dataclass
class DetectedTechnology:
    """A technology detected on a target."""
    name: str
    category: TechCategory
    version: str = ""
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    is_eol: bool = False
    known_vulns: list[KnownVulnerability] = field(default_factory=list)
    fingerprint: Optional[TechnologyFingerprint] = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category.value,
            "version": self.version,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "is_eol": self.is_eol,
            "known_vulns_count": len(self.known_vulns),
        }


@dataclass
class TechAnalysisResult:
    """Complete technology analysis result."""
    target: str
    technologies: list[DetectedTechnology] = field(default_factory=list)
    tech_stack: dict[str, list[str]] = field(default_factory=dict)  # category -> [techs]

    # Module recommendations (aggregated from all technologies)
    recommended_modules: list[str] = field(default_factory=list)
    skip_modules: list[str] = field(default_factory=list)
    skip_reasons: dict[str, str] = field(default_factory=dict)

    # Risk assessment
    eol_technologies: list[str] = field(default_factory=list)
    vulnerable_technologies: list[tuple[str, str, list[str]]] = field(default_factory=list)  # (name, version, [CVEs])

    # Analysis metadata
    analysis_time: float = 0.0
    confidence_overall: float = 0.0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "technologies": [t.to_dict() for t in self.technologies],
            "tech_stack": self.tech_stack,
            "recommended_modules": self.recommended_modules,
            "skip_modules": self.skip_modules,
            "skip_reasons": self.skip_reasons,
            "eol_technologies": self.eol_technologies,
            "vulnerable_technologies": [
                {"name": n, "version": v, "cves": c}
                for n, v, c in self.vulnerable_technologies
            ],
            "analysis_time": self.analysis_time,
            "confidence_overall": self.confidence_overall,
        }


# =============================================================================
# ENTERPRISE TECHNOLOGY FINGERPRINT DATABASE
# =============================================================================

TECH_FINGERPRINTS: dict[str, TechnologyFingerprint] = {}


def _register_fingerprint(fp: TechnologyFingerprint) -> None:
    """Register a technology fingerprint."""
    TECH_FINGERPRINTS[fp.name.lower()] = fp
    for alias in fp.aliases:
        TECH_FINGERPRINTS[alias.lower()] = fp


# -----------------------------------------------------------------------------
# WEB SERVERS
# -----------------------------------------------------------------------------

_register_fingerprint(TechnologyFingerprint(
    name="nginx",
    category=TechCategory.WEB_SERVER,
    aliases=["nginx/", "openresty"],
    patterns=[
        DetectionPattern("header", r"server:\s*nginx", 0.95),
        DetectionPattern("header", r"server:\s*openresty", 0.9),
        DetectionPattern("html", r"nginx/\d+\.\d+", 0.7),
    ],
    version_patterns=[
        DetectionPattern("header", r"nginx/(\d+\.\d+(?:\.\d+)?)", 0.95, version_group=1),
        DetectionPattern("html", r"nginx/(\d+\.\d+(?:\.\d+)?)", 0.7, version_group=1),
    ],
    latest_version="1.25.4",
    common_misconfigs=[
        "Directory listing enabled",
        "Server version disclosure",
        "Missing security headers",
        "Proxy buffer overflow",
    ],
    recommended_modules=["headers", "ssl", "cors", "dir"],
    skip_modules=[],
))

_register_fingerprint(TechnologyFingerprint(
    name="Apache",
    category=TechCategory.WEB_SERVER,
    aliases=["apache2", "httpd", "apache-coyote"],
    patterns=[
        DetectionPattern("header", r"server:\s*apache", 0.95),
        DetectionPattern("header", r"server:\s*apache-coyote", 0.9),
        DetectionPattern("html", r"apache/\d+\.\d+", 0.7),
        DetectionPattern("html", r"mod_ssl", 0.6),
    ],
    version_patterns=[
        DetectionPattern("header", r"apache/(\d+\.\d+(?:\.\d+)?)", 0.95, version_group=1),
        DetectionPattern("header", r"apache-coyote/(\d+\.\d+)", 0.9, version_group=1),
    ],
    latest_version="2.4.58",
    common_misconfigs=[
        "Directory listing enabled",
        "Server-status exposed",
        "mod_info exposed",
        "Outdated modules",
    ],
    recommended_modules=["headers", "ssl", "cors", "dir", "lfi"],
    skip_modules=[],
))

_register_fingerprint(TechnologyFingerprint(
    name="IIS",
    category=TechCategory.WEB_SERVER,
    aliases=["microsoft-iis", "iis/"],
    patterns=[
        DetectionPattern("header", r"server:\s*microsoft-iis", 0.95),
        DetectionPattern("header", r"x-powered-by:\s*asp\.net", 0.8),
        DetectionPattern("header", r"x-aspnet-version", 0.85),
    ],
    version_patterns=[
        DetectionPattern("header", r"microsoft-iis/(\d+\.\d+)", 0.95, version_group=1),
    ],
    latest_version="10.0",
    common_misconfigs=[
        "Short filename disclosure",
        "Trace.axd exposed",
        "Verbose error messages",
        "IIS Manager exposed",
    ],
    recommended_modules=["headers", "ssl", "cors", "dir", "iis_shortname"],
    skip_modules=[],
    known_vulns=[
        KnownVulnerability(
            cve_id="CVE-2017-7269",
            severity=Severity.CRITICAL,
            affected_versions=["6.0"],
            description="Buffer overflow in WebDAV",
            cvss_score=9.8,
            exploit_available=True,
        ),
    ],
))

# -----------------------------------------------------------------------------
# LANGUAGES
# -----------------------------------------------------------------------------

_register_fingerprint(TechnologyFingerprint(
    name="PHP",
    category=TechCategory.LANGUAGE,
    aliases=["php/"],
    patterns=[
        DetectionPattern("header", r"x-powered-by:\s*php", 0.95),
        DetectionPattern("cookie", r"phpsessid", 0.9),
        DetectionPattern("url", r"\.php(?:\?|$)", 0.7),
        DetectionPattern("html", r"<\?php", 0.6),
    ],
    version_patterns=[
        DetectionPattern("header", r"x-powered-by:\s*php/(\d+\.\d+(?:\.\d+)?)", 0.95, version_group=1),
    ],
    latest_version="8.3.2",
    eol_date=None,
    common_misconfigs=[
        "Display errors enabled",
        "phpinfo() exposed",
        "allow_url_include enabled",
        "Outdated version",
    ],
    recommended_modules=["sqli", "xss", "lfi", "rce", "cmdi", "upload", "deserialization", "ssti"],
    skip_modules=["graphql"],
    skip_reasons={"graphql": "GraphQL typically not used with PHP"},
    known_vulns=[
        KnownVulnerability(
            cve_id="CVE-2024-4577",
            severity=Severity.CRITICAL,
            affected_versions=["<8.1.29", "<8.2.20", "<8.3.8"],
            description="CGI argument injection",
            cvss_score=9.8,
            exploit_available=True,
            patch_version="8.3.8",
        ),
    ],
))

_register_fingerprint(TechnologyFingerprint(
    name="Python",
    category=TechCategory.LANGUAGE,
    aliases=["python/", "cpython"],
    patterns=[
        DetectionPattern("header", r"server:\s*python", 0.8),
        DetectionPattern("header", r"server:\s*gunicorn", 0.85),
        DetectionPattern("header", r"server:\s*uvicorn", 0.85),
        DetectionPattern("header", r"server:\s*werkzeug", 0.9),
        DetectionPattern("cookie", r"session", 0.3),  # Generic, low confidence
    ],
    version_patterns=[
        DetectionPattern("header", r"python/(\d+\.\d+(?:\.\d+)?)", 0.9, version_group=1),
    ],
    latest_version="3.12.1",
    recommended_modules=["sqli", "xss", "ssti", "ssrf", "cmdi", "deserialization", "nosql"],
    skip_modules=[],
))

_register_fingerprint(TechnologyFingerprint(
    name="Node.js",
    category=TechCategory.LANGUAGE,
    aliases=["node", "nodejs"],
    patterns=[
        DetectionPattern("header", r"x-powered-by:\s*express", 0.9),
        DetectionPattern("header", r"server:\s*node", 0.85),
        DetectionPattern("js", r"__dirname|__filename|require\s*\(", 0.6),
    ],
    version_patterns=[
        DetectionPattern("header", r"x-powered-by:\s*express\s*/\s*(\d+\.\d+)", 0.8, version_group=1),
    ],
    latest_version="21.6.1",
    recommended_modules=["xss", "ssrf", "prototype", "nosql", "deserialization", "ssti"],
    skip_modules=["sqli"],
    skip_reasons={"sqli": "Node.js typically uses NoSQL or ORMs"},
))

_register_fingerprint(TechnologyFingerprint(
    name="Java",
    category=TechCategory.LANGUAGE,
    aliases=["java/", "openjdk"],
    patterns=[
        DetectionPattern("cookie", r"jsessionid", 0.95),
        DetectionPattern("header", r"x-powered-by:\s*servlet", 0.9),
        DetectionPattern("url", r"\.jsp(?:\?|$)", 0.85),
        DetectionPattern("url", r"\.do(?:\?|$)", 0.7),
        DetectionPattern("header", r"server:\s*apache-coyote", 0.85),
    ],
    version_patterns=[
        DetectionPattern("header", r"servlet/(\d+\.\d+)", 0.8, version_group=1),
    ],
    latest_version="21",
    common_misconfigs=[
        "Deserialization vulnerabilities",
        "JNDI injection points",
        "Expression Language injection",
        "Struts/Spring misconfigs",
    ],
    recommended_modules=["sqli", "xss", "xxe", "deserialization", "ssti", "cmdi", "log4j"],
    skip_modules=["nosql"],
    skip_reasons={"nosql": "Java typically uses SQL databases"},
    known_vulns=[
        KnownVulnerability(
            cve_id="CVE-2021-44228",
            severity=Severity.CRITICAL,
            affected_versions=["log4j<2.17.0"],
            description="Log4Shell - Remote code execution via JNDI",
            cvss_score=10.0,
            exploit_available=True,
            patch_version="2.17.1",
        ),
    ],
))

_register_fingerprint(TechnologyFingerprint(
    name="ASP.NET",
    category=TechCategory.LANGUAGE,
    aliases=["aspnet", "asp.net core", "dotnet"],
    patterns=[
        DetectionPattern("header", r"x-powered-by:\s*asp\.net", 0.95),
        DetectionPattern("header", r"x-aspnet-version", 0.95),
        DetectionPattern("cookie", r"asp\.net_sessionid", 0.95),
        DetectionPattern("cookie", r"\.aspxauth", 0.9),
        DetectionPattern("url", r"\.aspx(?:\?|$)", 0.9),
        DetectionPattern("url", r"\.ashx(?:\?|$)", 0.85),
        DetectionPattern("html", r"__viewstate", 0.9),
    ],
    version_patterns=[
        DetectionPattern("header", r"x-aspnet-version:\s*(\d+\.\d+(?:\.\d+)?)", 0.95, version_group=1),
        DetectionPattern("header", r"x-aspnetmvc-version:\s*(\d+\.\d+)", 0.9, version_group=1),
    ],
    latest_version="8.0",
    common_misconfigs=[
        "ViewState not encrypted",
        "Debug mode enabled",
        "Trace.axd exposed",
        "Machine key disclosure",
    ],
    recommended_modules=["sqli", "xss", "xxe", "deserialization", "viewstate", "csrf"],
    skip_modules=["nosql", "ssti"],
    skip_reasons={
        "nosql": "ASP.NET typically uses SQL Server",
        "ssti": "ASP.NET uses Razor which is generally safe",
    },
))

# -----------------------------------------------------------------------------
# FRAMEWORKS
# -----------------------------------------------------------------------------

_register_fingerprint(TechnologyFingerprint(
    name="Django",
    category=TechCategory.FRAMEWORK,
    aliases=["django/"],
    patterns=[
        DetectionPattern("cookie", r"csrftoken", 0.85),
        DetectionPattern("cookie", r"sessionid", 0.6),
        DetectionPattern("header", r"x-frame-options:\s*(?:deny|sameorigin)", 0.3),
        DetectionPattern("html", r"csrfmiddlewaretoken", 0.9),
        DetectionPattern("html", r"django\.contrib", 0.95),
        DetectionPattern("html", r"/admin/login/", 0.7),
    ],
    version_patterns=[
        DetectionPattern("html", r"django[^\d]*(\d+\.\d+(?:\.\d+)?)", 0.7, version_group=1),
    ],
    latest_version="5.0.1",
    common_misconfigs=[
        "DEBUG = True in production",
        "Secret key exposed",
        "Admin interface exposed",
        "ALLOWED_HOSTS misconfigured",
    ],
    recommended_modules=["sqli", "xss", "csrf", "ssti", "idor", "auth", "ssrf"],
    skip_modules=["nosql", "xxe"],
    skip_reasons={
        "nosql": "Django ORM uses SQL databases by default",
        "xxe": "Django doesn't parse XML by default",
    },
    priority=70,
))

_register_fingerprint(TechnologyFingerprint(
    name="Laravel",
    category=TechCategory.FRAMEWORK,
    aliases=["laravel/"],
    patterns=[
        DetectionPattern("cookie", r"laravel_session", 0.95),
        DetectionPattern("cookie", r"xsrf-token", 0.7),
        DetectionPattern("html", r"laravel", 0.6),
        DetectionPattern("header", r"set-cookie:.*laravel", 0.9),
    ],
    version_patterns=[
        DetectionPattern("html", r"laravel[^\d]*(\d+\.\d+(?:\.\d+)?)", 0.6, version_group=1),
    ],
    latest_version="10.40.0",
    common_misconfigs=[
        "APP_DEBUG = true",
        "Exposed .env file",
        "Mass assignment vulnerabilities",
        "Insecure deserialization",
    ],
    recommended_modules=["sqli", "xss", "csrf", "lfi", "deserialization", "auth", "idor", "mass_assign"],
    skip_modules=["nosql", "xxe"],
    skip_reasons={
        "nosql": "Laravel Eloquent uses SQL databases",
        "xxe": "Laravel doesn't parse XML by default",
    },
    priority=70,
))

_register_fingerprint(TechnologyFingerprint(
    name="Rails",
    category=TechCategory.FRAMEWORK,
    aliases=["ruby on rails", "rubyonrails", "ror"],
    patterns=[
        DetectionPattern("cookie", r"_session_id", 0.7),
        DetectionPattern("header", r"x-powered-by:\s*phusion passenger", 0.9),
        DetectionPattern("header", r"x-runtime", 0.7),
        DetectionPattern("header", r"x-request-id", 0.5),
        DetectionPattern("html", r"rails", 0.5),
        DetectionPattern("html", r"authenticity_token", 0.85),
    ],
    version_patterns=[
        DetectionPattern("header", r"x-rails-version:\s*(\d+\.\d+(?:\.\d+)?)", 0.95, version_group=1),
    ],
    latest_version="7.1.2",
    common_misconfigs=[
        "Mass assignment vulnerabilities",
        "SQL injection via params",
        "Insecure direct object references",
        "Secret key exposure",
    ],
    recommended_modules=["sqli", "xss", "csrf", "deserialization", "mass_assign", "idor", "auth"],
    skip_modules=["xxe"],
    skip_reasons={"xxe": "Rails doesn't parse XML by default"},
    priority=70,
))

_register_fingerprint(TechnologyFingerprint(
    name="Spring",
    category=TechCategory.FRAMEWORK,
    aliases=["spring boot", "spring framework", "springboot"],
    patterns=[
        DetectionPattern("cookie", r"jsessionid", 0.6),
        DetectionPattern("header", r"x-application-context", 0.9),
        DetectionPattern("url", r"/actuator", 0.85),
        DetectionPattern("url", r"/swagger-ui", 0.7),
        DetectionPattern("html", r"spring", 0.4),
        DetectionPattern("html", r"_csrf", 0.6),
    ],
    version_patterns=[
        DetectionPattern("html", r"spring[^\d]*(\d+\.\d+(?:\.\d+)?)", 0.6, version_group=1),
    ],
    latest_version="3.2.1",
    common_misconfigs=[
        "Actuator endpoints exposed",
        "SpEL injection",
        "Mass assignment via binding",
        "Insecure deserialization",
    ],
    recommended_modules=["sqli", "xss", "xxe", "deserialization", "ssti", "actuator", "auth"],
    skip_modules=["nosql"],
    skip_reasons={"nosql": "Spring typically uses JPA/Hibernate with SQL"},
    priority=75,
    known_vulns=[
        KnownVulnerability(
            cve_id="CVE-2022-22965",
            severity=Severity.CRITICAL,
            affected_versions=["<5.3.18", "<5.2.20"],
            description="Spring4Shell - RCE via data binding",
            cvss_score=9.8,
            exploit_available=True,
            patch_version="5.3.18",
        ),
    ],
))

_register_fingerprint(TechnologyFingerprint(
    name="Express.js",
    category=TechCategory.FRAMEWORK,
    aliases=["express", "expressjs"],
    patterns=[
        DetectionPattern("header", r"x-powered-by:\s*express", 0.95),
        DetectionPattern("header", r"etag:\s*w/", 0.5),
    ],
    version_patterns=[
        DetectionPattern("header", r"x-powered-by:\s*express", 0.5),  # No version usually
    ],
    latest_version="4.18.2",
    common_misconfigs=[
        "Debug mode exposed",
        "Verbose error messages",
        "Missing rate limiting",
        "CORS misconfiguration",
    ],
    recommended_modules=["xss", "ssrf", "nosql", "prototype", "auth", "ratelimit"],
    skip_modules=["sqli", "xxe"],
    skip_reasons={
        "sqli": "Express typically uses MongoDB/NoSQL",
        "xxe": "Express doesn't parse XML by default",
    },
    priority=65,
))

_register_fingerprint(TechnologyFingerprint(
    name="FastAPI",
    category=TechCategory.FRAMEWORK,
    aliases=["fast api", "fastapi/"],
    patterns=[
        DetectionPattern("header", r"server:\s*uvicorn", 0.8),
        DetectionPattern("url", r"/docs(?:\?|$|/)", 0.85),
        DetectionPattern("url", r"/redoc(?:\?|$)", 0.85),
        DetectionPattern("url", r"/openapi\.json", 0.9),
        DetectionPattern("html", r"swagger-ui", 0.7),
    ],
    version_patterns=[
        DetectionPattern("html", r"fastapi[^\d]*(\d+\.\d+(?:\.\d+)?)", 0.7, version_group=1),
    ],
    latest_version="0.109.0",
    common_misconfigs=[
        "Debug mode in production",
        "OpenAPI docs exposed",
        "Missing authentication on endpoints",
        "Dependency injection vulnerabilities",
    ],
    recommended_modules=["sqli", "xss", "ssrf", "auth", "idor", "api", "nosql"],
    skip_modules=["xxe", "csrf"],
    skip_reasons={
        "xxe": "FastAPI uses JSON by default",
        "csrf": "FastAPI is stateless API framework",
    },
    priority=70,
))

_register_fingerprint(TechnologyFingerprint(
    name="Flask",
    category=TechCategory.FRAMEWORK,
    aliases=["flask/"],
    patterns=[
        DetectionPattern("header", r"server:\s*werkzeug", 0.9),
        DetectionPattern("cookie", r"session=\.ey", 0.85),  # Flask signed cookie
        DetectionPattern("html", r"jinja2", 0.7),
    ],
    version_patterns=[
        DetectionPattern("header", r"werkzeug/(\d+\.\d+(?:\.\d+)?)", 0.8, version_group=1),
    ],
    latest_version="3.0.0",
    common_misconfigs=[
        "Debug mode enabled",
        "Secret key weak/exposed",
        "SSTI via Jinja2",
        "Session cookie not secure",
    ],
    recommended_modules=["sqli", "xss", "ssti", "ssrf", "auth", "nosql", "deserialization"],
    skip_modules=["xxe"],
    skip_reasons={"xxe": "Flask doesn't parse XML by default"},
    priority=65,
))

# -----------------------------------------------------------------------------
# FRONTEND FRAMEWORKS
# -----------------------------------------------------------------------------

_register_fingerprint(TechnologyFingerprint(
    name="React",
    category=TechCategory.FRONTEND,
    aliases=["reactjs", "react.js"],
    patterns=[
        DetectionPattern("html", r"data-reactroot", 0.95),
        DetectionPattern("html", r"_reactRootContainer", 0.95),
        DetectionPattern("html", r"__REACT_DEVTOOLS", 0.9),
        DetectionPattern("js", r"react\.production\.min\.js", 0.95),
        DetectionPattern("js", r"react-dom", 0.9),
        DetectionPattern("html", r'react["\s]', 0.6),
    ],
    version_patterns=[
        DetectionPattern("js", r"react[^\d]*(\d+\.\d+(?:\.\d+)?)", 0.7, version_group=1),
        DetectionPattern("html", r'react@(\d+\.\d+(?:\.\d+)?)', 0.8, version_group=1),
    ],
    latest_version="18.2.0",
    common_misconfigs=[
        "dangerouslySetInnerHTML misuse (XSS)",
        "Exposed API keys in bundle",
        "Source maps in production",
        "Unprotected routes",
    ],
    recommended_modules=["dom_xss", "xss", "prototype", "secrets", "cors"],
    skip_modules=["sqli", "lfi", "cmdi", "xxe", "ssti"],
    skip_reasons={
        "sqli": "React is frontend-only, no direct DB access",
        "lfi": "React is frontend-only, no file system access",
        "cmdi": "React is frontend-only, no command execution",
        "xxe": "React doesn't parse XML",
        "ssti": "React doesn't use server-side templates",
    },
    priority=60,
))

_register_fingerprint(TechnologyFingerprint(
    name="Vue.js",
    category=TechCategory.FRONTEND,
    aliases=["vue", "vuejs"],
    patterns=[
        DetectionPattern("html", r"__VUE__", 0.95),
        DetectionPattern("html", r"v-cloak", 0.9),
        DetectionPattern("html", r"data-v-[a-f0-9]+", 0.9),
        DetectionPattern("js", r"vue\.(?:runtime\.)?(?:esm\.)?(?:min\.)?js", 0.9),
        DetectionPattern("html", r'vue["\s]', 0.5),
    ],
    version_patterns=[
        DetectionPattern("js", r"vue[^\d]*(\d+\.\d+(?:\.\d+)?)", 0.7, version_group=1),
        DetectionPattern("html", r'vue@(\d+\.\d+(?:\.\d+)?)', 0.8, version_group=1),
    ],
    latest_version="3.4.15",
    common_misconfigs=[
        "v-html directive misuse (XSS)",
        "Exposed API keys in bundle",
        "Source maps in production",
        "Unprotected routes",
    ],
    recommended_modules=["dom_xss", "xss", "prototype", "secrets", "cors"],
    skip_modules=["sqli", "lfi", "cmdi", "xxe", "ssti"],
    skip_reasons={
        "sqli": "Vue is frontend-only, no direct DB access",
        "lfi": "Vue is frontend-only, no file system access",
        "cmdi": "Vue is frontend-only, no command execution",
        "xxe": "Vue doesn't parse XML",
        "ssti": "Vue doesn't use server-side templates",
    },
    priority=60,
))

_register_fingerprint(TechnologyFingerprint(
    name="Angular",
    category=TechCategory.FRONTEND,
    aliases=["angularjs", "angular.js"],
    patterns=[
        DetectionPattern("html", r"ng-version", 0.95),
        DetectionPattern("html", r"ng-app", 0.9),
        DetectionPattern("html", r"ng-controller", 0.9),
        DetectionPattern("html", r"\[\(ngModel\)\]", 0.85),
        DetectionPattern("js", r"angular(?:\.min)?\.js", 0.9),
        DetectionPattern("html", r"@angular/core", 0.95),
    ],
    version_patterns=[
        DetectionPattern("html", r'ng-version="(\d+\.\d+(?:\.\d+)?)"', 0.95, version_group=1),
        DetectionPattern("js", r"angular[^\d]*(\d+\.\d+(?:\.\d+)?)", 0.7, version_group=1),
    ],
    latest_version="17.1.0",
    common_misconfigs=[
        "Angular expression sandbox bypass (AngularJS <1.6)",
        "Exposed API keys in environment.ts",
        "Source maps in production",
        "bypassSecurityTrust misuse",
    ],
    recommended_modules=["dom_xss", "xss", "prototype", "secrets", "cors"],
    skip_modules=["sqli", "lfi", "cmdi", "xxe", "ssti"],
    skip_reasons={
        "sqli": "Angular is frontend-only",
        "lfi": "Angular is frontend-only",
        "cmdi": "Angular is frontend-only",
        "xxe": "Angular doesn't parse XML by default",
        "ssti": "Angular doesn't use server-side templates",
    },
    priority=60,
    known_vulns=[
        KnownVulnerability(
            cve_id="CVE-2020-7676",
            severity=Severity.MEDIUM,
            affected_versions=["<1.8.0"],
            description="Prototype pollution via jQuery",
            cvss_score=6.5,
            exploit_available=True,
        ),
    ],
))

_register_fingerprint(TechnologyFingerprint(
    name="Next.js",
    category=TechCategory.FRONTEND,
    aliases=["nextjs", "next"],
    patterns=[
        DetectionPattern("html", r"__NEXT_DATA__", 0.95),
        DetectionPattern("html", r"/_next/static", 0.9),
        DetectionPattern("header", r"x-powered-by:\s*next\.js", 0.95),
        DetectionPattern("html", r"next/head", 0.8),
    ],
    version_patterns=[
        DetectionPattern("header", r"x-powered-by:\s*next\.js\s*(\d+\.\d+(?:\.\d+)?)", 0.95, version_group=1),
        DetectionPattern("html", r'"next":\s*"(\d+\.\d+(?:\.\d+)?)"', 0.8, version_group=1),
    ],
    latest_version="14.1.0",
    common_misconfigs=[
        "API routes exposed without auth",
        "SSRF via image optimization",
        "getServerSideProps data exposure",
        "Environment variables leaked",
    ],
    recommended_modules=["xss", "ssrf", "auth", "idor", "secrets", "api", "cors"],
    skip_modules=["sqli", "lfi", "cmdi"],
    skip_reasons={
        "sqli": "Next.js typically uses Prisma/ORM",
        "lfi": "Next.js has sandboxed file system",
        "cmdi": "Next.js doesn't execute commands",
    },
    priority=70,
))

_register_fingerprint(TechnologyFingerprint(
    name="Nuxt.js",
    category=TechCategory.FRONTEND,
    aliases=["nuxtjs", "nuxt"],
    patterns=[
        DetectionPattern("html", r"__NUXT__", 0.95),
        DetectionPattern("html", r"/_nuxt/", 0.9),
        DetectionPattern("html", r"nuxt", 0.5),
    ],
    version_patterns=[
        DetectionPattern("html", r'"nuxt":\s*"(\d+\.\d+(?:\.\d+)?)"', 0.8, version_group=1),
    ],
    latest_version="3.9.3",
    common_misconfigs=[
        "Server routes exposed",
        "asyncData/fetch data exposure",
        "Environment variables leaked",
    ],
    recommended_modules=["xss", "ssrf", "auth", "idor", "secrets", "api", "cors"],
    skip_modules=["sqli", "lfi", "cmdi"],
    skip_reasons={
        "sqli": "Nuxt typically uses Prisma/ORM",
        "lfi": "Nuxt has sandboxed file system",
        "cmdi": "Nuxt doesn't execute commands",
    },
    priority=70,
))

# -----------------------------------------------------------------------------
# MODERN FRONTEND FRAMEWORKS (2024+)
# -----------------------------------------------------------------------------

_register_fingerprint(TechnologyFingerprint(
    name="Svelte",
    category=TechCategory.FRONTEND,
    aliases=["svelte.js", "sveltejs"],
    patterns=[
        DetectionPattern("html", r"__svelte", 0.95),
        DetectionPattern("html", r'class="svelte-[a-z0-9]+"', 0.9),
        DetectionPattern("js", r"svelte", 0.7),
        DetectionPattern("html", r"\.svelte", 0.6),
    ],
    version_patterns=[
        DetectionPattern("js", r"svelte[^\d]*(\d+\.\d+(?:\.\d+)?)", 0.7, version_group=1),
        DetectionPattern("html", r'svelte@(\d+\.\d+(?:\.\d+)?)', 0.8, version_group=1),
    ],
    latest_version="4.2.9",
    common_misconfigs=[
        "{@html} directive misuse (XSS)",
        "Exposed API keys in bundle",
        "Source maps in production",
        "Unprotected routes",
    ],
    recommended_modules=["dom_xss", "xss", "prototype", "secrets", "cors"],
    skip_modules=["sqli", "lfi", "cmdi", "xxe", "ssti"],
    skip_reasons={
        "sqli": "Svelte is frontend-only, no direct DB access",
        "lfi": "Svelte is frontend-only, no file system access",
        "cmdi": "Svelte is frontend-only, no command execution",
        "xxe": "Svelte doesn't parse XML",
        "ssti": "Svelte doesn't use server-side templates",
    },
    priority=60,
))

_register_fingerprint(TechnologyFingerprint(
    name="SvelteKit",
    category=TechCategory.FRONTEND,
    aliases=["svelte-kit", "sveltekit"],
    patterns=[
        DetectionPattern("html", r"__sveltekit", 0.95),
        DetectionPattern("html", r"_app/immutable", 0.9),
        DetectionPattern("html", r"/_app/", 0.85),
        DetectionPattern("html", r"data-sveltekit", 0.9),
    ],
    version_patterns=[
        DetectionPattern("html", r'"@sveltejs/kit":\s*"(\d+\.\d+(?:\.\d+)?)"', 0.8, version_group=1),
    ],
    latest_version="2.0.6",
    common_misconfigs=[
        "Server endpoints exposed without auth",
        "Form actions vulnerable to CSRF",
        "Load functions leak data",
        "Environment variables exposed",
    ],
    recommended_modules=["xss", "dom_xss", "ssrf", "auth", "idor", "secrets", "api", "cors", "csrf"],
    skip_modules=["sqli", "lfi", "cmdi"],
    skip_reasons={
        "sqli": "SvelteKit typically uses Prisma/ORM",
        "lfi": "SvelteKit has sandboxed file system",
        "cmdi": "SvelteKit doesn't execute commands",
    },
    priority=70,
))

_register_fingerprint(TechnologyFingerprint(
    name="htmx",
    category=TechCategory.JS_LIBRARY,
    aliases=["htmx.org"],
    patterns=[
        DetectionPattern("html", r"hx-get|hx-post|hx-put|hx-delete|hx-patch", 0.95),
        DetectionPattern("html", r"hx-target|hx-swap|hx-trigger", 0.9),
        DetectionPattern("js", r"htmx\.org", 0.95),
        DetectionPattern("html", r"htmx\.js", 0.9),
        DetectionPattern("html", r"htmx\.min\.js", 0.9),
    ],
    version_patterns=[
        DetectionPattern("js", r"htmx[^\d]*(\d+\.\d+(?:\.\d+)?)", 0.7, version_group=1),
        DetectionPattern("html", r'htmx@(\d+\.\d+(?:\.\d+)?)', 0.8, version_group=1),
    ],
    latest_version="1.9.10",
    common_misconfigs=[
        "XSS via hx-swap innerHTML",
        "CSRF on state-changing hx-post",
        "Unvalidated hx-target",
        "Server-side template injection via partials",
    ],
    recommended_modules=["xss", "csrf", "ssti", "auth", "idor", "headers", "cors"],
    skip_modules=["nosql", "graphql"],
    skip_reasons={
        "nosql": "htmx is backend-agnostic, depends on server",
        "graphql": "htmx typically uses REST/hypermedia",
    },
    priority=55,
))

_register_fingerprint(TechnologyFingerprint(
    name="Alpine.js",
    category=TechCategory.JS_LIBRARY,
    aliases=["alpinejs", "alpine"],
    patterns=[
        DetectionPattern("html", r"x-data|x-bind|x-on|x-show|x-if", 0.9),
        DetectionPattern("html", r"@click|@submit|@change", 0.7),
        DetectionPattern("js", r"alpinejs|alpine\.js", 0.9),
        DetectionPattern("html", r'x-text|x-html|x-model', 0.85),
    ],
    version_patterns=[
        DetectionPattern("js", r"alpine[^\d]*(\d+\.\d+(?:\.\d+)?)", 0.7, version_group=1),
        DetectionPattern("html", r'alpinejs@(\d+\.\d+(?:\.\d+)?)', 0.8, version_group=1),
    ],
    latest_version="3.13.3",
    common_misconfigs=[
        "x-html directive misuse (XSS)",
        "Exposed secrets in x-data",
        "Client-side auth bypass",
    ],
    recommended_modules=["dom_xss", "xss", "secrets", "cors"],
    skip_modules=["sqli", "lfi", "cmdi", "xxe", "ssti"],
    skip_reasons={
        "sqli": "Alpine.js is frontend-only",
        "lfi": "Alpine.js is frontend-only",
        "cmdi": "Alpine.js is frontend-only",
        "xxe": "Alpine.js doesn't parse XML",
        "ssti": "Alpine.js doesn't use server-side templates",
    },
    priority=50,
))

_register_fingerprint(TechnologyFingerprint(
    name="Remix",
    category=TechCategory.FRONTEND,
    aliases=["remix.run", "remixjs"],
    patterns=[
        DetectionPattern("html", r"__remix", 0.95),
        DetectionPattern("html", r"__remixContext", 0.95),
        DetectionPattern("html", r"remix-run", 0.85),
        DetectionPattern("js", r"@remix-run", 0.9),
    ],
    version_patterns=[
        DetectionPattern("html", r'"@remix-run/react":\s*"(\d+\.\d+(?:\.\d+)?)"', 0.8, version_group=1),
    ],
    latest_version="2.5.1",
    common_misconfigs=[
        "Loader data exposure",
        "Action CSRF vulnerabilities",
        "Session cookie misconfiguration",
        "Environment variables leaked",
    ],
    recommended_modules=["xss", "csrf", "ssrf", "auth", "idor", "secrets", "api", "cors"],
    skip_modules=["sqli", "lfi", "cmdi"],
    skip_reasons={
        "sqli": "Remix typically uses Prisma/ORM",
        "lfi": "Remix has sandboxed file system",
        "cmdi": "Remix doesn't execute commands",
    },
    priority=70,
))

_register_fingerprint(TechnologyFingerprint(
    name="Astro",
    category=TechCategory.FRONTEND,
    aliases=["astro.build", "astrojs"],
    patterns=[
        DetectionPattern("html", r"data-astro-", 0.95),
        DetectionPattern("html", r"astro-island", 0.95),
        DetectionPattern("html", r"astro-slot", 0.9),
        DetectionPattern("html", r"_astro/", 0.85),
    ],
    version_patterns=[
        DetectionPattern("html", r'"astro":\s*"(\d+\.\d+(?:\.\d+)?)"', 0.8, version_group=1),
    ],
    latest_version="4.2.6",
    common_misconfigs=[
        "Island hydration XSS",
        "API endpoint auth bypass",
        "Static file exposure",
        "Environment variables leaked",
    ],
    recommended_modules=["xss", "dom_xss", "ssrf", "auth", "idor", "secrets", "api", "cors"],
    skip_modules=["sqli", "lfi", "cmdi", "ssti"],
    skip_reasons={
        "sqli": "Astro generates static content by default",
        "lfi": "Astro has sandboxed build process",
        "cmdi": "Astro doesn't execute commands",
        "ssti": "Astro uses compile-time templating",
    },
    priority=65,
))

_register_fingerprint(TechnologyFingerprint(
    name="SolidJS",
    category=TechCategory.FRONTEND,
    aliases=["solid-js", "solid.js", "solidstart"],
    patterns=[
        DetectionPattern("html", r"solid-js", 0.95),
        DetectionPattern("js", r"createSignal|createEffect|createMemo", 0.85),
        DetectionPattern("js", r"solid-start", 0.9),
        DetectionPattern("html", r"_\$", 0.5),  # Solid's compiled markers
    ],
    version_patterns=[
        DetectionPattern("js", r"solid-js[^\d]*(\d+\.\d+(?:\.\d+)?)", 0.7, version_group=1),
        DetectionPattern("html", r'"solid-js":\s*"(\d+\.\d+(?:\.\d+)?)"', 0.8, version_group=1),
    ],
    latest_version="1.8.11",
    common_misconfigs=[
        "innerHTML prop misuse (XSS)",
        "Exposed API keys in bundle",
        "Source maps in production",
    ],
    recommended_modules=["dom_xss", "xss", "prototype", "secrets", "cors"],
    skip_modules=["sqli", "lfi", "cmdi", "xxe", "ssti"],
    skip_reasons={
        "sqli": "SolidJS is frontend-only",
        "lfi": "SolidJS is frontend-only",
        "cmdi": "SolidJS is frontend-only",
        "xxe": "SolidJS doesn't parse XML",
        "ssti": "SolidJS doesn't use server-side templates",
    },
    priority=60,
))

_register_fingerprint(TechnologyFingerprint(
    name="Qwik",
    category=TechCategory.FRONTEND,
    aliases=["qwik.builder.io", "qwikjs"],
    patterns=[
        DetectionPattern("html", r"q:container", 0.95),
        DetectionPattern("html", r"q:id|q:base|q:chunk", 0.9),
        DetectionPattern("js", r"@builder\.io/qwik", 0.95),
        DetectionPattern("html", r"qwik", 0.5),
    ],
    version_patterns=[
        DetectionPattern("html", r'"@builder\.io/qwik":\s*"(\d+\.\d+(?:\.\d+)?)"', 0.8, version_group=1),
    ],
    latest_version="1.4.5",
    common_misconfigs=[
        "useVisibleTask$ XSS",
        "Resumability data exposure",
        "Server$ function auth bypass",
        "Environment variables leaked",
    ],
    recommended_modules=["xss", "dom_xss", "ssrf", "auth", "idor", "secrets", "api", "cors"],
    skip_modules=["sqli", "lfi", "cmdi"],
    skip_reasons={
        "sqli": "Qwik typically uses ORM/Prisma",
        "lfi": "Qwik has sandboxed runtime",
        "cmdi": "Qwik doesn't execute commands",
    },
    priority=65,
))

_register_fingerprint(TechnologyFingerprint(
    name="Ember.js",
    category=TechCategory.FRONTEND,
    aliases=["ember", "emberjs"],
    patterns=[
        DetectionPattern("html", r"ember", 0.6),
        DetectionPattern("html", r"data-ember-", 0.95),
        DetectionPattern("js", r"Ember\.Application", 0.95),
        DetectionPattern("html", r"/assets/vendor", 0.5),  # Common Ember CLI pattern
    ],
    version_patterns=[
        DetectionPattern("js", r"ember[^\d]*(\d+\.\d+(?:\.\d+)?)", 0.7, version_group=1),
    ],
    latest_version="5.6.0",
    common_misconfigs=[
        "Handlebars template injection",
        "Exposed API keys",
        "Source maps in production",
    ],
    recommended_modules=["dom_xss", "xss", "ssti", "prototype", "secrets", "cors"],
    skip_modules=["sqli", "lfi", "cmdi", "xxe"],
    skip_reasons={
        "sqli": "Ember is frontend-only",
        "lfi": "Ember is frontend-only",
        "cmdi": "Ember is frontend-only",
        "xxe": "Ember doesn't parse XML",
    },
    priority=60,
))

_register_fingerprint(TechnologyFingerprint(
    name="Backbone.js",
    category=TechCategory.FRONTEND,
    aliases=["backbone", "backbonejs"],
    patterns=[
        DetectionPattern("js", r"Backbone\.", 0.9),
        DetectionPattern("js", r"backbone\.js|backbone\.min\.js", 0.95),
        DetectionPattern("js", r"Backbone\.Model|Backbone\.View", 0.95),
    ],
    version_patterns=[
        DetectionPattern("js", r"backbone[^\d]*(\d+\.\d+(?:\.\d+)?)", 0.7, version_group=1),
    ],
    latest_version="1.5.0",
    common_misconfigs=[
        "innerHTML injection in views",
        "XSS via template interpolation",
        "Exposed API endpoints",
    ],
    recommended_modules=["dom_xss", "xss", "prototype", "secrets", "cors"],
    skip_modules=["sqli", "lfi", "cmdi", "xxe", "ssti"],
    skip_reasons={
        "sqli": "Backbone is frontend-only",
        "lfi": "Backbone is frontend-only",
        "cmdi": "Backbone is frontend-only",
        "xxe": "Backbone doesn't parse XML",
        "ssti": "Backbone doesn't use server-side templates",
    },
    priority=55,
))

# -----------------------------------------------------------------------------
# CMS
# -----------------------------------------------------------------------------

_register_fingerprint(TechnologyFingerprint(
    name="WordPress",
    category=TechCategory.CMS,
    aliases=["wp", "wordpress.org"],
    patterns=[
        DetectionPattern("html", r"wp-content/", 0.95),
        DetectionPattern("html", r"wp-includes/", 0.95),
        DetectionPattern("html", r'/wp-json/', 0.9),
        DetectionPattern("meta", r'<meta name="generator" content="WordPress', 0.95),
        DetectionPattern("url", r"/wp-admin", 0.9),
        DetectionPattern("url", r"/wp-login\.php", 0.95),
        DetectionPattern("cookie", r"wordpress_", 0.9),
    ],
    version_patterns=[
        DetectionPattern("meta", r'content="WordPress\s+(\d+\.\d+(?:\.\d+)?)"', 0.95, version_group=1),
        DetectionPattern("html", r"ver=(\d+\.\d+(?:\.\d+)?)", 0.6, version_group=1),
        DetectionPattern("url", r"\?ver=(\d+\.\d+(?:\.\d+)?)", 0.7, version_group=1),
    ],
    latest_version="6.4.2",
    common_misconfigs=[
        "XML-RPC enabled (brute force)",
        "User enumeration via REST API",
        "Debug log exposed",
        "Vulnerable plugins",
        "wp-config.php backup exposed",
    ],
    recommended_modules=[
        "sqli", "xss", "lfi", "auth", "upload", "wordpress", "xmlrpc",
        "user_enum", "plugin_vulns", "csrf"
    ],
    skip_modules=["graphql", "nosql"],
    skip_reasons={
        "graphql": "WordPress uses REST API by default",
        "nosql": "WordPress uses MySQL",
    },
    priority=80,
))

_register_fingerprint(TechnologyFingerprint(
    name="Drupal",
    category=TechCategory.CMS,
    aliases=["drupal.org"],
    patterns=[
        DetectionPattern("html", r"/sites/default/files", 0.9),
        DetectionPattern("html", r"/sites/all/", 0.85),
        DetectionPattern("meta", r'<meta name="generator" content="Drupal', 0.95),
        DetectionPattern("header", r"x-drupal-cache", 0.95),
        DetectionPattern("header", r"x-generator:\s*drupal", 0.95),
        DetectionPattern("html", r"drupal\.js", 0.85),
    ],
    version_patterns=[
        DetectionPattern("meta", r'content="Drupal\s+(\d+)', 0.9, version_group=1),
        DetectionPattern("header", r"x-generator:\s*drupal\s+(\d+)", 0.95, version_group=1),
    ],
    latest_version="10.2.2",
    common_misconfigs=[
        "Drupalgeddon vulnerabilities",
        "User enumeration",
        "Admin path exposed",
        "Outdated modules",
    ],
    recommended_modules=["sqli", "xss", "lfi", "auth", "drupal", "user_enum", "csrf"],
    skip_modules=["graphql", "nosql"],
    skip_reasons={
        "graphql": "Drupal uses REST by default",
        "nosql": "Drupal uses MySQL/PostgreSQL",
    },
    priority=80,
    known_vulns=[
        KnownVulnerability(
            cve_id="CVE-2018-7600",
            severity=Severity.CRITICAL,
            affected_versions=["<7.58", "8.x<8.3.9", "8.4.x<8.4.6", "8.5.x<8.5.1"],
            description="Drupalgeddon 2 - Remote code execution",
            cvss_score=9.8,
            exploit_available=True,
        ),
    ],
))

_register_fingerprint(TechnologyFingerprint(
    name="Joomla",
    category=TechCategory.CMS,
    aliases=["joomla.org"],
    patterns=[
        DetectionPattern("html", r"/media/jui/", 0.9),
        DetectionPattern("html", r"/components/com_", 0.85),
        DetectionPattern("meta", r'<meta name="generator" content="Joomla', 0.95),
        DetectionPattern("url", r"/administrator", 0.7),
        DetectionPattern("html", r"joomla", 0.4),
    ],
    version_patterns=[
        DetectionPattern("meta", r'content="Joomla!\s*-?\s*.*?(\d+\.\d+(?:\.\d+)?)"', 0.9, version_group=1),
    ],
    latest_version="5.0.2",
    common_misconfigs=[
        "Administrator path exposed",
        "User enumeration",
        "Vulnerable extensions",
        "Debug mode enabled",
    ],
    recommended_modules=["sqli", "xss", "lfi", "auth", "joomla", "user_enum", "csrf"],
    skip_modules=["graphql", "nosql"],
    skip_reasons={
        "graphql": "Joomla uses REST by default",
        "nosql": "Joomla uses MySQL",
    },
    priority=80,
))

# -----------------------------------------------------------------------------
# BAAS (Backend as a Service)
# -----------------------------------------------------------------------------

_register_fingerprint(TechnologyFingerprint(
    name="Supabase",
    category=TechCategory.BAAS,
    aliases=["supabase.co", "supabase.io"],
    patterns=[
        DetectionPattern("js", r"https://[a-z0-9]+\.supabase\.co", 0.95),
        DetectionPattern("js", r"supabase-js", 0.9),
        DetectionPattern("js", r"createClient.*supabase", 0.85),
        DetectionPattern("html", r"supabase", 0.5),
        DetectionPattern("js", r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", 0.6),  # JWT anon key
    ],
    version_patterns=[
        DetectionPattern("js", r"@supabase/supabase-js@(\d+\.\d+(?:\.\d+)?)", 0.9, version_group=1),
    ],
    latest_version="2.39.3",
    common_misconfigs=[
        "RLS (Row Level Security) disabled",
        "Service role key exposed",
        "Permissive RLS policies",
        "Storage bucket public access",
        "Auth settings misconfigured",
    ],
    recommended_modules=[
        "rls_bypass", "supabase", "auth", "idor", "storage_access",
        "jwt", "api", "cors", "secrets"
    ],
    skip_modules=["sqli", "lfi", "cmdi", "xxe", "ssti"],
    skip_reasons={
        "sqli": "Supabase uses PostgREST with parameterized queries",
        "lfi": "No file system access in Supabase",
        "cmdi": "No command execution in Supabase",
        "xxe": "Supabase uses JSON only",
        "ssti": "No server-side templates in Supabase",
    },
    priority=90,
))

_register_fingerprint(TechnologyFingerprint(
    name="Firebase",
    category=TechCategory.BAAS,
    aliases=["firebase.google.com", "firebaseio.com", "firebaseapp.com"],
    patterns=[
        DetectionPattern("js", r"firebase(?:Config|App|Database)", 0.95),
        DetectionPattern("js", r"\.firebaseio\.com", 0.95),
        DetectionPattern("js", r"\.firebaseapp\.com", 0.9),
        DetectionPattern("js", r"firebase\.initializeApp", 0.9),
        DetectionPattern("html", r"firebase", 0.4),
    ],
    version_patterns=[
        DetectionPattern("js", r"firebase@(\d+\.\d+(?:\.\d+)?)", 0.9, version_group=1),
    ],
    latest_version="10.7.2",
    common_misconfigs=[
        "Firestore rules too permissive",
        "Realtime Database rules misconfigured",
        "Storage rules allow public access",
        "Auth domain hijacking",
        "API key exposed without restrictions",
    ],
    recommended_modules=[
        "firebase", "firebase_rules", "auth", "idor", "storage_access",
        "api", "cors", "secrets"
    ],
    skip_modules=["sqli", "lfi", "cmdi", "xxe", "ssti"],
    skip_reasons={
        "sqli": "Firebase uses NoSQL (Firestore/RTDB)",
        "lfi": "No file system access in Firebase",
        "cmdi": "No command execution in Firebase",
        "xxe": "Firebase uses JSON only",
        "ssti": "No server-side templates in Firebase",
    },
    priority=90,
))

# -----------------------------------------------------------------------------
# CDN/HOSTING
# -----------------------------------------------------------------------------

_register_fingerprint(TechnologyFingerprint(
    name="Cloudflare",
    category=TechCategory.CDN,
    aliases=["cf", "cloudflare.com"],
    patterns=[
        DetectionPattern("header", r"server:\s*cloudflare", 0.95),
        DetectionPattern("header", r"cf-ray:", 0.95),
        DetectionPattern("header", r"cf-cache-status:", 0.9),
        DetectionPattern("cookie", r"__cf", 0.85),
    ],
    version_patterns=[],
    latest_version="",
    common_misconfigs=[
        "Origin IP exposed",
        "Cache poisoning",
        "Bypass via direct IP",
        "WAF bypass techniques",
    ],
    recommended_modules=["headers", "ssl", "cors", "waf_bypass", "origin_discovery"],
    skip_modules=["sqli", "xss", "cmdi"],  # Behind WAF
    skip_reasons={
        "sqli": "Cloudflare WAF typically blocks SQLi",
        "xss": "Cloudflare WAF typically blocks XSS",
        "cmdi": "Cloudflare WAF typically blocks command injection",
    },
    priority=40,
))

_register_fingerprint(TechnologyFingerprint(
    name="Vercel",
    category=TechCategory.HOSTING,
    aliases=["vercel.app", "vercel.com", "now.sh"],
    patterns=[
        DetectionPattern("header", r"server:\s*vercel", 0.95),
        DetectionPattern("header", r"x-vercel-", 0.95),
        DetectionPattern("url", r"\.vercel\.app", 0.9),
        DetectionPattern("header", r"x-powered-by:\s*next\.js", 0.7),
    ],
    version_patterns=[],
    latest_version="",
    common_misconfigs=[
        "Serverless function secrets exposed",
        "Environment variables leaked",
        "Preview deployments accessible",
        "vercel.json misconfigured",
    ],
    recommended_modules=["headers", "ssl", "cors", "secrets", "api", "auth"],
    skip_modules=["lfi", "cmdi"],
    skip_reasons={
        "lfi": "Vercel has sandboxed serverless",
        "cmdi": "Vercel doesn't allow command execution",
    },
    priority=50,
))

_register_fingerprint(TechnologyFingerprint(
    name="Netlify",
    category=TechCategory.HOSTING,
    aliases=["netlify.app", "netlify.com"],
    patterns=[
        DetectionPattern("header", r"server:\s*netlify", 0.95),
        DetectionPattern("header", r"x-nf-", 0.9),
        DetectionPattern("url", r"\.netlify\.app", 0.9),
    ],
    version_patterns=[],
    latest_version="",
    common_misconfigs=[
        "Function secrets exposed",
        "Redirect rules misconfigured",
        "Form handling vulnerabilities",
    ],
    recommended_modules=["headers", "ssl", "cors", "secrets", "api"],
    skip_modules=["lfi", "cmdi", "sqli"],
    skip_reasons={
        "lfi": "Netlify has sandboxed functions",
        "cmdi": "Netlify doesn't allow command execution",
        "sqli": "Netlify functions are typically stateless",
    },
    priority=50,
))

# -----------------------------------------------------------------------------
# DATABASES (Detected via errors/leaks)
# -----------------------------------------------------------------------------

_register_fingerprint(TechnologyFingerprint(
    name="MySQL",
    category=TechCategory.DATABASE,
    aliases=["mysql", "mariadb"],
    patterns=[
        DetectionPattern("response", r"mysql_fetch|mysql_query|mysqli_", 0.9),
        DetectionPattern("response", r"you have an error in your sql syntax", 0.95),
        DetectionPattern("response", r"warning:.*mysql", 0.9),
        DetectionPattern("response", r"supplied argument is not a valid mysql", 0.95),
    ],
    version_patterns=[
        DetectionPattern("response", r"mysql[^\d]*(\d+\.\d+(?:\.\d+)?)", 0.7, version_group=1),
    ],
    latest_version="8.2.0",
    common_misconfigs=[
        "Remote root access enabled",
        "Weak passwords",
        "Verbose error messages",
        "Outdated version",
    ],
    recommended_modules=["sqli"],
    skip_modules=[],
    priority=30,
))

_register_fingerprint(TechnologyFingerprint(
    name="PostgreSQL",
    category=TechCategory.DATABASE,
    aliases=["postgres", "psql"],
    patterns=[
        DetectionPattern("response", r"pg_query|pg_connect|psql", 0.9),
        DetectionPattern("response", r"postgresql.*error", 0.95),
        DetectionPattern("response", r"syntax error at or near", 0.9),
    ],
    version_patterns=[
        DetectionPattern("response", r"postgresql[^\d]*(\d+\.\d+(?:\.\d+)?)", 0.7, version_group=1),
    ],
    latest_version="16.1",
    recommended_modules=["sqli"],
    skip_modules=[],
    priority=30,
))

_register_fingerprint(TechnologyFingerprint(
    name="MongoDB",
    category=TechCategory.DATABASE,
    aliases=["mongo", "mongodb.com"],
    patterns=[
        DetectionPattern("response", r"mongodb://", 0.95),
        DetectionPattern("response", r"mongoose", 0.7),
        DetectionPattern("response", r"MongoError", 0.95),
        DetectionPattern("js", r"mongodb\+srv://", 0.9),
    ],
    version_patterns=[
        DetectionPattern("response", r"mongodb[^\d]*(\d+\.\d+(?:\.\d+)?)", 0.7, version_group=1),
    ],
    latest_version="7.0.4",
    common_misconfigs=[
        "No authentication required",
        "Exposed to internet",
        "Connection string in code",
    ],
    recommended_modules=["nosql", "ssrf"],
    skip_modules=["sqli"],
    skip_reasons={"sqli": "MongoDB is NoSQL, use nosql module instead"},
    priority=30,
))

# -----------------------------------------------------------------------------
# ANALYTICS & THIRD-PARTY
# -----------------------------------------------------------------------------

_register_fingerprint(TechnologyFingerprint(
    name="Google Analytics",
    category=TechCategory.ANALYTICS,
    aliases=["ga", "gtag"],
    patterns=[
        DetectionPattern("html", r"(?:UA-\d+-\d+|G-[A-Z0-9]+)", 0.95),
        DetectionPattern("js", r"google-analytics\.com/analytics", 0.95),
        DetectionPattern("js", r"googletagmanager\.com", 0.9),
        DetectionPattern("html", r"gtag\(", 0.85),
    ],
    version_patterns=[],
    latest_version="",
    recommended_modules=["secrets"],  # Check for exposed tracking IDs
    skip_modules=[],
    priority=10,
))

_register_fingerprint(TechnologyFingerprint(
    name="Stripe",
    category=TechCategory.PAYMENT,
    aliases=["stripe.com"],
    patterns=[
        DetectionPattern("js", r"pk_(?:live|test)_[A-Za-z0-9]{24,}", 0.95),
        DetectionPattern("js", r"stripe\.com/v3", 0.9),
        DetectionPattern("html", r"stripe", 0.4),
    ],
    version_patterns=[],
    latest_version="",
    common_misconfigs=[
        "Secret key exposed (sk_*)",
        "Webhook signature not verified",
        "Test mode in production",
    ],
    recommended_modules=["secrets", "api"],
    skip_modules=[],
    priority=20,
))

# =============================================================================
# TECH STACK COMBINATIONS & VULNERABILITY PROFILES
# =============================================================================

TECH_STACK_PROFILES: dict[frozenset[str], dict[str, Any]] = {
    frozenset(["React", "Node.js", "MongoDB"]): {
        "name": "MERN Stack",
        "expected_vulns": ["nosql_injection", "prototype_pollution", "xss", "ssrf"],
        "priority_modules": ["nosql", "prototype", "xss", "ssrf", "auth"],
        "common_issues": [
            "NoSQL injection in query builders",
            "Prototype pollution via lodash/other libs",
            "XSS via dangerouslySetInnerHTML",
            "SSRF in image proxies",
        ],
    },
    frozenset(["React", "Django", "PostgreSQL"]): {
        "name": "React + Django",
        "expected_vulns": ["sqli", "ssti", "csrf", "idor"],
        "priority_modules": ["sqli", "ssti", "csrf", "idor", "auth"],
        "common_issues": [
            "SQL injection via raw queries",
            "SSTI in email templates",
            "CSRF on state-changing endpoints",
            "IDOR in REST API",
        ],
    },
    frozenset(["Vue.js", "Laravel", "MySQL"]): {
        "name": "Vue + Laravel",
        "expected_vulns": ["sqli", "mass_assignment", "xss", "csrf"],
        "priority_modules": ["sqli", "mass_assign", "xss", "csrf", "deserialization"],
        "common_issues": [
            "SQL injection in raw queries",
            "Mass assignment in Eloquent models",
            "XSS via v-html",
            "Insecure deserialization in Laravel",
        ],
    },
    frozenset(["Next.js", "Supabase"]): {
        "name": "Next.js + Supabase",
        "expected_vulns": ["rls_bypass", "idor", "auth_bypass", "ssrf"],
        "priority_modules": ["rls_bypass", "supabase", "idor", "auth", "ssrf"],
        "common_issues": [
            "RLS policies too permissive",
            "IDOR via predictable IDs",
            "Auth bypass in middleware",
            "SSRF via image optimization",
        ],
    },
    frozenset(["React", "Firebase"]): {
        "name": "React + Firebase",
        "expected_vulns": ["firebase_rules", "idor", "auth_bypass"],
        "priority_modules": ["firebase", "firebase_rules", "idor", "auth"],
        "common_issues": [
            "Firestore rules allow read/write all",
            "IDOR in document IDs",
            "Auth domain spoofing",
        ],
    },
    frozenset(["WordPress", "PHP", "MySQL"]): {
        "name": "WordPress Stack",
        "expected_vulns": ["sqli", "xss", "lfi", "upload", "plugin_vulns"],
        "priority_modules": ["wordpress", "sqli", "xss", "lfi", "upload", "xmlrpc"],
        "common_issues": [
            "Plugin vulnerabilities",
            "SQLi in custom queries",
            "XSS in comments/forms",
            "LFI via theme editors",
            "XML-RPC brute force",
        ],
    },
    frozenset(["Java", "Spring"]): {
        "name": "Spring Framework",
        "expected_vulns": ["sqli", "deserialization", "xxe", "actuator_exposure"],
        "priority_modules": ["sqli", "deserialization", "xxe", "actuator", "ssti"],
        "common_issues": [
            "SQL injection in JPQL",
            "Insecure deserialization",
            "XXE in XML endpoints",
            "Actuator endpoints exposed",
            "SpEL injection",
        ],
    },
    # Modern frontend stack profiles
    frozenset(["SvelteKit", "Supabase"]): {
        "name": "SvelteKit + Supabase",
        "expected_vulns": ["rls_bypass", "idor", "csrf", "xss"],
        "priority_modules": ["rls_bypass", "supabase", "idor", "auth", "csrf", "xss"],
        "common_issues": [
            "RLS policies too permissive",
            "Form actions vulnerable to CSRF",
            "IDOR via predictable IDs",
            "XSS in server-rendered content",
        ],
    },
    frozenset(["Astro", "Supabase"]): {
        "name": "Astro + Supabase",
        "expected_vulns": ["rls_bypass", "idor", "ssrf"],
        "priority_modules": ["rls_bypass", "supabase", "idor", "ssrf", "secrets"],
        "common_issues": [
            "RLS bypass via server endpoints",
            "SSRF in API routes",
            "Static site data leakage",
        ],
    },
    frozenset(["Remix", "PostgreSQL"]): {
        "name": "Remix + PostgreSQL",
        "expected_vulns": ["sqli", "csrf", "idor"],
        "priority_modules": ["sqli", "csrf", "idor", "auth", "xss"],
        "common_issues": [
            "SQL injection in raw queries",
            "CSRF in form actions",
            "IDOR in loaders",
        ],
    },
    frozenset(["Qwik", "Firebase"]): {
        "name": "Qwik + Firebase",
        "expected_vulns": ["firebase_rules", "idor", "xss"],
        "priority_modules": ["firebase", "firebase_rules", "idor", "xss", "secrets"],
        "common_issues": [
            "Firebase rules too permissive",
            "XSS via resumability",
            "Server$ function auth bypass",
        ],
    },
    frozenset(["htmx", "Django"]): {
        "name": "htmx + Django",
        "expected_vulns": ["csrf", "ssti", "xss", "idor"],
        "priority_modules": ["csrf", "ssti", "xss", "idor", "sqli", "auth"],
        "common_issues": [
            "CSRF on hx-post without tokens",
            "SSTI in partial templates",
            "XSS via hx-swap innerHTML",
            "IDOR in htmx endpoints",
        ],
    },
    frozenset(["htmx", "Flask"]): {
        "name": "htmx + Flask",
        "expected_vulns": ["ssti", "csrf", "xss"],
        "priority_modules": ["ssti", "csrf", "xss", "ssrf", "auth"],
        "common_issues": [
            "Jinja2 SSTI in partials",
            "CSRF without proper tokens",
            "XSS via innerHTML swap",
        ],
    },
    frozenset(["Alpine.js", "Laravel"]): {
        "name": "Alpine.js + Laravel",
        "expected_vulns": ["sqli", "mass_assignment", "csrf", "xss"],
        "priority_modules": ["sqli", "mass_assign", "csrf", "xss", "deserialization"],
        "common_issues": [
            "SQL injection in raw queries",
            "Mass assignment in Eloquent",
            "x-html XSS",
            "CSRF on AJAX requests",
        ],
    },
}


# =============================================================================
# INTELLIGENT MODULE SELECTION ENGINE
# =============================================================================

class ModuleRecommendationEngine:
    """
    Intelligently recommends which scanner modules to run based on
    detected technologies and their combinations.
    """

    # All available scanner modules
    ALL_MODULES = {
        # Injection modules
        "sqli", "xss", "dom_xss", "nosql", "cmdi", "xxe", "ssti", "crlf",
        "ldap", "deserialization", "prototype",
        # Auth/Access modules
        "auth", "oauth", "jwt", "csrf", "idor", "mass_assign", "authz",
        "mfa", "saml", "ratelimit",
        # Infrastructure modules
        "headers", "ssl", "cors", "cloud", "s3", "secrets",
        "subdomain_takeover", "dns_rebind", "k8s",
        # CMS/Framework specific
        "wordpress", "drupal", "joomla", "xmlrpc",
        # BaaS specific
        "supabase", "firebase", "rls_bypass", "firebase_rules",
        # API modules
        "api", "graphql", "websocket", "sse", "grpc",
        # Advanced
        "smuggling", "cache", "upload", "lfi", "ssrf",
        # Discovery
        "dir", "nuclei", "cms", "email", "mobile", "backend", "third_party",
        # Business logic
        "business", "postexploit",
    }

    # Modules that are always safe to run (infrastructure checks)
    ALWAYS_RUN = {"headers", "ssl", "cors", "secrets"}

    # Modules that require specific conditions
    CONDITIONAL_MODULES = {
        "sqli": {"requires_db": True, "requires_params": True},
        "nosql": {"requires_nosql": True, "requires_params": True},
        "xss": {"requires_params": True, "requires_html": True},
        "dom_xss": {"requires_frontend": True},
        "csrf": {"requires_forms": True, "requires_session": True},
        "ssti": {"requires_templates": True},
        "lfi": {"requires_params": True},
        "ssrf": {"requires_params": True},
        "cmdi": {"requires_params": True},
        "xxe": {"requires_xml": True},
        "graphql": {"requires_graphql": True},
        "websocket": {"requires_websocket": True},
        "rls_bypass": {"requires_baas": True},
        "firebase_rules": {"requires_firebase": True},
        "supabase": {"requires_supabase": True},
        "wordpress": {"requires_wordpress": True},
        "drupal": {"requires_drupal": True},
        "joomla": {"requires_joomla": True},
    }

    def __init__(self):
        self.tech_fingerprints = TECH_FINGERPRINTS
        self.stack_profiles = TECH_STACK_PROFILES

    def recommend(
        self,
        detected_techs: list[DetectedTechnology],
        has_params: bool = False,
        has_forms: bool = False,
        has_session: bool = False,
        has_api: bool = False,
        endpoints_discovered: int = 0,
    ) -> tuple[list[str], list[str], dict[str, str]]:
        """
        Generate module recommendations based on detected technologies.

        Returns:
            (recommended_modules, skip_modules, skip_reasons)
        """
        recommended = set(self.ALWAYS_RUN)
        skip = set()
        skip_reasons = {}

        # Get technology names for stack matching
        tech_names = {t.name for t in detected_techs}
        tech_categories = {t.category for t in detected_techs}

        # Check for known tech stack combinations
        for stack_techs, profile in self.stack_profiles.items():
            if stack_techs.issubset(tech_names):
                logger.info(f"Detected tech stack: {profile['name']}")
                recommended.update(profile.get("priority_modules", []))

        # Process each detected technology
        for tech in detected_techs:
            if tech.fingerprint:
                fp = tech.fingerprint
                recommended.update(fp.recommended_modules)
                for mod in fp.skip_modules:
                    if mod not in recommended:  # Don't skip if explicitly recommended
                        skip.add(mod)
                        if mod in fp.skip_reasons:
                            skip_reasons[mod] = fp.skip_reasons[mod]

        # Apply conditional logic
        context = {
            "requires_params": has_params or endpoints_discovered > 0,
            "requires_forms": has_forms,
            "requires_session": has_session,
            "requires_html": TechCategory.FRONTEND in tech_categories or TechCategory.CMS in tech_categories,
            "requires_frontend": TechCategory.FRONTEND in tech_categories,
            "requires_db": any(t.category == TechCategory.DATABASE for t in detected_techs) or \
                          any(t.name.lower() in ["php", "python", "java", "asp.net"] for t in detected_techs),
            "requires_nosql": any(t.name.lower() in ["mongodb", "node.js", "express.js"] for t in detected_techs),
            "requires_templates": any(t.name.lower() in ["django", "flask", "jinja2", "twig", "blade"] for t in detected_techs),
            "requires_xml": any(t.name.lower() in ["java", "asp.net", "spring"] for t in detected_techs),
            "requires_graphql": has_api,  # Check via API discovery
            "requires_websocket": False,  # Need to detect
            "requires_baas": TechCategory.BAAS in tech_categories,
            "requires_firebase": any(t.name.lower() == "firebase" for t in detected_techs),
            "requires_supabase": any(t.name.lower() == "supabase" for t in detected_techs),
            "requires_wordpress": any(t.name.lower() == "wordpress" for t in detected_techs),
            "requires_drupal": any(t.name.lower() == "drupal" for t in detected_techs),
            "requires_joomla": any(t.name.lower() == "joomla" for t in detected_techs),
        }

        # Skip modules that don't meet conditions
        for module, conditions in self.CONDITIONAL_MODULES.items():
            should_skip = False
            skip_reason = None

            for condition, required in conditions.items():
                if required and not context.get(condition, False):
                    should_skip = True
                    skip_reason = f"Condition not met: {condition}"
                    break

            if should_skip and module not in recommended:
                skip.add(module)
                if skip_reason and module not in skip_reasons:
                    skip_reasons[module] = skip_reason

        # Remove skipped modules from recommended
        recommended = recommended - skip

        # Sort by priority
        def get_priority(mod: str) -> int:
            for tech in detected_techs:
                if tech.fingerprint and mod in tech.fingerprint.recommended_modules:
                    return tech.fingerprint.priority
            return 50

        recommended_list = sorted(recommended, key=get_priority, reverse=True)
        skip_list = sorted(skip)

        return recommended_list, skip_list, skip_reasons


# =============================================================================
# MAIN TECH INTELLIGENCE CLASS
# =============================================================================

class TechIntelligence:
    """
    Enterprise-grade technology intelligence system.

    Performs comprehensive technology fingerprinting, version detection,
    and intelligent module selection for penetration testing.
    """

    VERSION = "2.0.0-ENTERPRISE"

    def __init__(self, settings: Any = None):
        self.settings = settings
        self.fingerprints = TECH_FINGERPRINTS
        self.recommendation_engine = ModuleRecommendationEngine()
        self._orchestrator: Any = None
        self._use_external_tools = getattr(settings, 'use_linux_tools', True) if settings else True
        logger.info(f"TechIntelligence v{self.VERSION} initialized with {len(self.fingerprints)} fingerprints")

    def _get_orchestrator(self) -> Any:
        """Get or create the Linux tools orchestrator."""
        if not _ORCHESTRATOR_AVAILABLE or not self._use_external_tools:
            return None

        if self._orchestrator is None:
            try:
                self._orchestrator = LinuxToolsOrchestrator(self.settings)
            except Exception as e:
                logger.debug(f"Failed to initialize orchestrator: {e}")
                return None

        return self._orchestrator

    async def _run_external_tech_detection(
        self,
        target: str,
    ) -> list[DetectedTechnology]:
        """
        Run external tools (whatweb, httpx) for technology detection.

        These tools provide additional detection capabilities:
        - whatweb: Comprehensive web fingerprinting
        - httpx: Fast HTTP probing with tech detection

        Returns list of DetectedTechnology from external tools.
        """
        detected = []
        orchestrator = self._get_orchestrator()

        if not orchestrator:
            logger.debug("[TechIntel] External tools not available")
            return detected

        # Run whatweb (comprehensive fingerprinting)
        if orchestrator.is_tool_available("whatweb"):
            logger.info(f"[TechIntel] Running whatweb on {target}")
            try:
                result = await orchestrator.run_single_tool("whatweb", target)
                if result.status == ToolStatus.SUCCESS:
                    for finding in result.findings:
                        if finding.get("type") == "technology_detected":
                            tech_name = finding.get("metadata", {}).get("technology", "")
                            version = finding.get("metadata", {}).get("version", "")
                            if tech_name:
                                tech = self._convert_external_tech(tech_name, version, "whatweb")
                                if tech:
                                    detected.append(tech)
                    logger.info(f"[TechIntel] whatweb found {len(detected)} technologies")
            except Exception as e:
                logger.debug(f"[TechIntel] whatweb error: {e}")

        # Run httpx (fast probing with tech detect)
        if orchestrator.is_tool_available("httpx"):
            logger.info(f"[TechIntel] Running httpx on {target}")
            try:
                result = await orchestrator.run_single_tool("httpx", target)
                if result.status == ToolStatus.SUCCESS:
                    httpx_count = 0
                    for finding in result.findings:
                        metadata = finding.get("metadata", {})
                        technologies = metadata.get("technologies", [])
                        for tech_name in technologies:
                            tech = self._convert_external_tech(tech_name, "", "httpx")
                            if tech and not self._is_duplicate_tech(tech, detected):
                                detected.append(tech)
                                httpx_count += 1
                    logger.info(f"[TechIntel] httpx found {httpx_count} additional technologies")
            except Exception as e:
                logger.debug(f"[TechIntel] httpx error: {e}")

        return detected

    def _convert_external_tech(
        self,
        tech_name: str,
        version: str,
        source: str,
    ) -> Optional[DetectedTechnology]:
        """Convert external tool technology to DetectedTechnology."""
        # Normalize tech name
        tech_name_lower = tech_name.lower()

        # Map to category
        category_map = {
            "php": TechCategory.LANGUAGE,
            "python": TechCategory.LANGUAGE,
            "ruby": TechCategory.LANGUAGE,
            "java": TechCategory.LANGUAGE,
            "node": TechCategory.LANGUAGE,
            "asp": TechCategory.LANGUAGE,
            "nginx": TechCategory.WEB_SERVER,
            "apache": TechCategory.WEB_SERVER,
            "iis": TechCategory.WEB_SERVER,
            "lighttpd": TechCategory.WEB_SERVER,
            "wordpress": TechCategory.CMS,
            "drupal": TechCategory.CMS,
            "joomla": TechCategory.CMS,
            "magento": TechCategory.CMS,
            "laravel": TechCategory.FRAMEWORK,
            "django": TechCategory.FRAMEWORK,
            "rails": TechCategory.FRAMEWORK,
            "express": TechCategory.FRAMEWORK,
            "spring": TechCategory.FRAMEWORK,
            "react": TechCategory.FRONTEND,
            "angular": TechCategory.FRONTEND,
            "vue": TechCategory.FRONTEND,
            "jquery": TechCategory.JS_LIBRARY,
            "bootstrap": TechCategory.JS_LIBRARY,
            "mysql": TechCategory.DATABASE,
            "postgresql": TechCategory.DATABASE,
            "mongodb": TechCategory.DATABASE,
            "redis": TechCategory.CACHE,
            "cloudflare": TechCategory.CDN,
            "akamai": TechCategory.CDN,
            "aws": TechCategory.HOSTING,
            "azure": TechCategory.HOSTING,
            "google cloud": TechCategory.HOSTING,
        }

        category = TechCategory.FRONTEND  # Default
        for key, cat in category_map.items():
            if key in tech_name_lower:
                category = cat
                break

        return DetectedTechnology(
            name=tech_name,
            category=category,
            version=version,
            confidence=0.85,  # External tool confidence
            evidence=[f"Detected by {source}"],
            is_eol=False,
            known_vulns=[],
        )

    def _is_duplicate_tech(
        self,
        new_tech: DetectedTechnology,
        existing: list[DetectedTechnology],
    ) -> bool:
        """Check if technology is already detected."""
        new_name = new_tech.name.lower()
        for tech in existing:
            if tech.name.lower() == new_name:
                return True
        return False

    async def analyze(
        self,
        target: str,
        html_content: str = "",
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        js_content: str = "",
        deep_scan: bool = True,
    ) -> TechAnalysisResult:
        """
        Perform comprehensive technology analysis on a target.

        Args:
            target: Target URL
            html_content: Pre-fetched HTML (optional)
            headers: Pre-fetched headers (optional)
            cookies: Pre-fetched cookies (optional)
            js_content: Pre-fetched JS content (optional)
            deep_scan: Whether to fetch additional resources

        Returns:
            TechAnalysisResult with detected technologies and recommendations
        """
        start_time = asyncio.get_event_loop().time()
        result = TechAnalysisResult(target=target)

        # Fetch content if not provided
        if not html_content or headers is None:
            html_content, headers, cookies = await self._fetch_target(target)

        if not html_content:
            logger.warning(f"Could not fetch content from {target}")
            result.analysis_time = asyncio.get_event_loop().time() - start_time
            return result

        # Fetch JS files if deep scan enabled
        if deep_scan and not js_content:
            js_content = await self._fetch_js_files(target, html_content)

        # Combine all content for analysis
        all_content = {
            "html": html_content,
            "headers": headers or {},
            "cookies": cookies or {},
            "js": js_content,
            "url": target,
        }

        # Run external tools for enhanced detection (whatweb, httpx)
        external_techs = await self._run_external_tech_detection(target)

        # Detect technologies (internal fingerprinting)
        detected = await self._detect_technologies(all_content)

        # Merge external detections (avoiding duplicates)
        for ext_tech in external_techs:
            if not self._is_duplicate_tech(ext_tech, detected):
                detected.append(ext_tech)
        result.technologies = detected

        # Build tech stack summary
        for tech in detected:
            category = tech.category.value
            if category not in result.tech_stack:
                result.tech_stack[category] = []
            result.tech_stack[category].append(tech.name)

        # Check for EOL and vulnerable technologies
        for tech in detected:
            if tech.is_eol:
                result.eol_technologies.append(f"{tech.name} {tech.version}")
            if tech.known_vulns:
                cves = [v.cve_id for v in tech.known_vulns]
                result.vulnerable_technologies.append((tech.name, tech.version, cves))

        # Get module recommendations
        has_params = "?" in html_content or "=" in html_content
        has_forms = "<form" in html_content.lower()
        has_session = bool(cookies)
        has_api = "/api" in html_content or "/graphql" in html_content

        recommended, skip, skip_reasons = self.recommendation_engine.recommend(
            detected_techs=detected,
            has_params=has_params,
            has_forms=has_forms,
            has_session=has_session,
            has_api=has_api,
        )

        result.recommended_modules = recommended
        result.skip_modules = skip
        result.skip_reasons = skip_reasons

        # Calculate overall confidence
        if detected:
            result.confidence_overall = sum(t.confidence for t in detected) / len(detected)

        result.analysis_time = asyncio.get_event_loop().time() - start_time

        logger.info(
            f"Tech analysis complete: {len(detected)} technologies, "
            f"{len(recommended)} recommended modules, "
            f"{len(skip)} skipped modules"
        )

        return result

    async def _fetch_target(
        self, target: str
    ) -> tuple[str, dict[str, str], dict[str, str]]:
        """Fetch HTML, headers, and cookies from target."""
        try:
            async with httpx.AsyncClient(
                timeout=15.0,
                follow_redirects=True,
                verify=False,
            ) as client:
                response = await client.get(target)

                html = response.text
                headers = {k.lower(): v for k, v in response.headers.items()}
                cookies = {k: v for k, v in response.cookies.items()}

                return html, headers, cookies

        except Exception as e:
            logger.error(f"Failed to fetch {target}: {e}")
            return "", {}, {}

    async def _fetch_js_files(self, target: str, html: str) -> str:
        """Fetch JavaScript files referenced in HTML."""
        js_content = []

        # Find JS file references
        js_patterns = [
            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
            r'src=["\']([^"\']+\.js)["\']',
        ]

        js_urls = set()
        for pattern in js_patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                url = match.group(1)
                if not url.startswith(("http://", "https://")):
                    # Make absolute URL
                    from urllib.parse import urljoin
                    url = urljoin(target, url)
                js_urls.add(url)

        # Fetch JS files (limit to first 10)
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for url in list(js_urls)[:10]:
                try:
                    response = await client.get(url)
                    if response.status_code == 200:
                        js_content.append(response.text)
                except Exception:
                    pass

        return "\n".join(js_content)

    async def _detect_technologies(
        self, content: dict[str, Any]
    ) -> list[DetectedTechnology]:
        """Detect technologies from all content sources."""
        detected: dict[str, DetectedTechnology] = {}

        for name, fingerprint in self.fingerprints.items():
            if name in detected:
                continue

            tech = await self._check_fingerprint(fingerprint, content)
            if tech:
                # Use canonical name
                detected[fingerprint.name] = tech

        return list(detected.values())

    async def _check_fingerprint(
        self,
        fingerprint: TechnologyFingerprint,
        content: dict[str, Any],
    ) -> DetectedTechnology | None:
        """Check if a fingerprint matches the content."""
        evidence = []
        max_confidence = 0.0
        version = ""

        for pattern in fingerprint.patterns:
            source_content = self._get_source_content(pattern.source, content)
            if not source_content:
                continue

            if re.search(pattern.pattern, source_content, re.IGNORECASE):
                evidence.append(f"{pattern.source}: {pattern.pattern[:50]}")
                max_confidence = max(max_confidence, pattern.confidence)

        if not evidence:
            return None

        # Try to detect version
        for v_pattern in fingerprint.version_patterns:
            source_content = self._get_source_content(v_pattern.source, content)
            if not source_content:
                continue

            match = re.search(v_pattern.pattern, source_content, re.IGNORECASE)
            if match and v_pattern.version_group > 0:
                try:
                    version = match.group(v_pattern.version_group)
                    break
                except IndexError:
                    pass

        # Check EOL status
        is_eol = False
        if fingerprint.eol_date:
            try:
                eol = datetime.fromisoformat(fingerprint.eol_date)
                is_eol = datetime.now() > eol
            except ValueError:
                pass

        # Check for known vulnerabilities
        known_vulns = []
        if version:
            for vuln in fingerprint.known_vulns:
                if self._version_affected(version, vuln.affected_versions):
                    known_vulns.append(vuln)

        return DetectedTechnology(
            name=fingerprint.name,
            category=fingerprint.category,
            version=version,
            confidence=max_confidence,
            evidence=evidence,
            is_eol=is_eol,
            known_vulns=known_vulns,
            fingerprint=fingerprint,
        )

    def _get_source_content(self, source: str, content: dict[str, Any]) -> str:
        """Get content for a specific source type."""
        if source == "header":
            return " ".join(f"{k}: {v}" for k, v in content.get("headers", {}).items())
        elif source == "html":
            return content.get("html", "")
        elif source == "cookie":
            return " ".join(content.get("cookies", {}).keys())
        elif source == "url":
            return content.get("url", "")
        elif source == "js":
            return content.get("js", "")
        elif source == "meta":
            return content.get("html", "")  # Meta tags are in HTML
        elif source == "response":
            return content.get("html", "")
        return ""

    def _version_affected(self, version: str, affected: list[str]) -> bool:
        """Check if a version is affected by vulnerability patterns."""
        from packaging import version as pkg_version

        try:
            v = pkg_version.parse(version)

            for pattern in affected:
                # Handle patterns like "<5.9.0", ">=4.0,<4.5"
                if pattern.startswith("<"):
                    compare_v = pkg_version.parse(pattern[1:])
                    if v < compare_v:
                        return True
                elif pattern.startswith(">="):
                    parts = pattern.split(",")
                    min_v = pkg_version.parse(parts[0][2:])
                    if len(parts) > 1 and parts[1].startswith("<"):
                        max_v = pkg_version.parse(parts[1][1:])
                        if min_v <= v < max_v:
                            return True
                elif v == pkg_version.parse(pattern):
                    return True

        except Exception:
            # Fallback to string comparison
            return version in affected

        return False


# =============================================================================
# INTEGRATION HELPER
# =============================================================================

async def analyze_target_intelligence(
    target: str,
    settings: Any = None,
) -> TechAnalysisResult:
    """
    Convenience function for quick technology analysis.

    Usage:
        result = await analyze_target_intelligence("https://example.com")
        print(f"Detected: {[t.name for t in result.technologies]}")
        print(f"Recommended: {result.recommended_modules}")
    """
    intel = TechIntelligence(settings)
    return await intel.analyze(target)


__all__ = [
    "TechIntelligence",
    "TechAnalysisResult",
    "DetectedTechnology",
    "TechnologyFingerprint",
    "TechCategory",
    "ModuleRecommendationEngine",
    "analyze_target_intelligence",
    "TECH_FINGERPRINTS",
    "TECH_STACK_PROFILES",
]
