"""
Insecure Deserialization Scanner - Enterprise Edition v2.0.

Comprehensive insecure deserialization vulnerability detection across multiple
languages, frameworks, and serialization formats. Includes coverage for:
- Java (ysoserial gadget chains, JMX, T3, IIOP, RMI)
- PHP (Magento, Laravel, WordPress, Symfony, Doctrine, PHPGGC)
- Python (pickle, PyYAML, shelve, marshal, jsonpickle)
- .NET (ViewState, BinaryFormatter, ObjectStateFormatter, Json.NET)
- Ruby (Marshal, YAML, ERB)
- Node.js (node-serialize, cryo, funcster)

Implements detection for OWASP Top 10 A8:2017 and CWE-502.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urljoin

import httpx

from scanning.findings import Finding, Severity
from scanning.vuln_scanner import ScanModule
from scanning.scan_context import ScanContext
from utils.scan_client import get_scan_client
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from utils.shared_findings_store import SharedFindingsStore

# =============================================================================
# FP MITIGATION v3.0: Enhanced false positive prevention
# =============================================================================

STATIC_EXTENSIONS = frozenset({
    '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.eot', '.ttf', '.json', '.txt', '.xml', '.map',
    '.mp3', '.mp4', '.webm', '.pdf', '.zip', '.tar', '.gz',
})

# SPA routes and trivial endpoints to SKIP (never contain deserialization)
SPA_TRIVIAL_ENDPOINTS = frozenset({
    '/', '/index.html', '/app', '/home', '/about', '/login', '/register',
    '/logout', '/help', '/faq', '/terms', '/privacy', '/contact',
    '/assets/', '/static/', '/public/', '/dist/', '/build/',
    '/node_modules/', '/vendor/', '/.well-known/',
    # API documentation (never deserialize)
    '/swagger', '/api-docs', '/openapi', '/graphql', '/graphiql',
})

# Generic error patterns that appear on ANY error page (not deserialization-specific)
GENERIC_ERROR_PATTERNS = frozenset({
    'fatal error', 'allowed memory size', 'call to undefined method',
    'call to a member function', 'page not found', '404', 'not found',
    'access denied', 'forbidden', 'internal server error', '500 error',
    'bad request', 'method not allowed', 'unauthorized', 'service unavailable',
    'gateway timeout', 'connection refused', 'connection timed out',
})

# Error patterns that SPECIFICALLY indicate deserialization attempts
DESER_SPECIFIC_PATTERNS = {
    'java': [
        r'java\.io\.(StreamCorruptedException|InvalidClassException)',
        r'ClassNotFoundException.*during deserialization',
        r'ObjectInputStream.*readObject',
        r'ysoserial|CommonsCollections|BeanShell',
        r'java\.lang\.ClassCastException.*during.*serial',
        r'ObjectStreamClass.*mismatch',
        r'InvalidObjectException',
        r'NotSerializableException',
    ],
    'php': [
        r'unserialize\(\).*expects parameter',
        r'__wakeup.*on a non-object',
        r'O:\d+:"[^"]*":\d+:\{',  # PHP serialized object pattern
        r'Classes.*could not be loaded',
        r'__destruct.*fatal',
        r'unserialize.*failed',
        r'unserialize.*incomplete object',
    ],
    'python': [
        r'pickle\.UnpicklingError',
        r'cPickle\.error',
        r'yaml\.scanner\.ScannerError.*unsafe',
        r'__reduce__.*called',
        r'pickle.*untrusted',
        r'unpickling.*error',
        r'yaml\.load.*Loader',
    ],
    'dotnet': [
        r'BinaryFormatter.*deserialize',
        r'ObjectStateFormatter.*invalid',
        r'ViewState.*invalid',
        r'System\.Runtime\.Serialization',
        r'SerializationException',
        r'LosFormatter.*invalid',
        r'TypeConfuseDelegate',
    ],
    'ruby': [
        r'Marshal\.load.*invalid',
        r'psych.*error',
        r'YAML\.load.*unsafe',
        r'Gem::.*RCE',
    ],
    'node': [
        r'node-serialize.*error',
        r'_\$\$ND_FUNC\$\$_',
        r'cryo.*deserialize',
        r'funcster.*error',
    ],
}

# Content-types that NEVER contain deserialized objects
SAFE_CONTENT_TYPES = frozenset({
    'text/html', 'text/css', 'text/javascript', 'application/javascript',
    'image/', 'font/', 'audio/', 'video/',
    'text/plain', 'text/csv', 'application/pdf',
})

# Minimum signals required for different severity levels (FP reduction)
SEVERITY_SIGNAL_REQUIREMENTS = {
    'CRITICAL': 3,  # Need 3+ signals for CRITICAL
    'HIGH': 2,      # Need 2+ signals for HIGH
    'MEDIUM': 1,    # 1 signal for MEDIUM
}

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class DeserVulnType(Enum):
    """Types of deserialization vulnerabilities."""
    JAVA_OBJECT = "java_object_deserialization"
    JAVA_RMI = "java_rmi_deserialization"
    JAVA_JMX = "java_jmx_deserialization"
    JAVA_T3 = "weblogic_t3_deserialization"
    JAVA_IIOP = "java_iiop_deserialization"
    JAVA_SPRING = "spring_framework_deserialization"
    PHP_OBJECT = "php_object_injection"
    PHP_PHAR = "php_phar_deserialization"
    PYTHON_PICKLE = "python_pickle_deserialization"
    PYTHON_YAML = "python_yaml_deserialization"
    PYTHON_SHELVE = "python_shelve_deserialization"
    PYTHON_JSONPICKLE = "python_jsonpickle_deserialization"
    DOTNET_VIEWSTATE = "dotnet_viewstate_deserialization"
    DOTNET_BINARY = "dotnet_binaryformatter_deserialization"
    DOTNET_SOAP = "dotnet_soapformatter_deserialization"
    DOTNET_JSON = "dotnet_jsonnet_deserialization"
    DOTNET_FASTJSON = "dotnet_fastjson_deserialization"
    RUBY_MARSHAL = "ruby_marshal_deserialization"
    RUBY_YAML = "ruby_yaml_deserialization"
    RUBY_ERB = "ruby_erb_deserialization"
    NODE_SERIALIZE = "node_serialize_deserialization"
    NODE_CRYO = "node_cryo_deserialization"
    NODE_FUNCSTER = "node_funcster_deserialization"


class GadgetChainType(Enum):
    """Known gadget chain types for various languages."""
    # Java ysoserial gadgets
    COMMONS_COLLECTIONS = "CommonsCollections"
    COMMONS_COLLECTIONS_K1 = "CommonsCollectionsK1"
    COMMONS_COLLECTIONS_K2 = "CommonsCollectionsK2"
    COMMONS_BEANUTILS = "CommonsBeanutils"
    COMMONS_BEANUTILS_183 = "CommonsBeanutils183NOCC"
    SPRING_CORE = "Spring"
    SPRING_CORE_2 = "Spring2"
    HIBERNATE_1 = "Hibernate1"
    HIBERNATE_2 = "Hibernate2"
    JBOSS = "JBossInterceptors"
    JBOSS_1 = "JBossInterceptors1"
    GROOVY_1 = "Groovy1"
    VAADIN_1 = "Vaadin1"
    CLICK_1 = "Click1"
    MYFACES_1 = "Myfaces1"
    MYFACES_2 = "Myfaces2"
    C3P0 = "C3P0"
    C3P0_WRAP = "C3P0WrapperConnPool"
    JRMPCLIENT = "JRMPClient"
    JRMPLISTENER = "JRMPListener"
    URLDNS = "URLDNS"
    FILEUPLOAD_1 = "FileUpload1"
    ASPECTJWEAVER = "AspectJWeaver"
    BeanShell_1 = "BeanShell1"
    Clojure = "Clojure"
    ROME = "ROME"
    JSON_IO = "JSON1"
    JAVASSIST_WELD = "JavassistWeld1"
    JYTHON_1 = "Jython1"
    MOZILLA_RHINO = "MozillaRhino1"
    # PHP PHPGGC gadgets
    GUZZLE_FW1 = "Guzzle/FW1"
    GUZZLE_INFO1 = "Guzzle/INFO1"
    GUZZLE_RCE1 = "Guzzle/RCE1"
    MONOLOG_RCE1 = "Monolog/RCE1"
    MONOLOG_RCE2 = "Monolog/RCE2"
    MONOLOG_RCE3 = "Monolog/RCE3"
    MONOLOG_RCE4 = "Monolog/RCE4"
    MONOLOG_RCE5 = "Monolog/RCE5"
    MONOLOG_RCE6 = "Monolog/RCE6"
    SYMFONY_RCE1 = "Symfony/RCE1"
    SYMFONY_RCE2 = "Symfony/RCE2"
    SYMFONY_RCE3 = "Symfony/RCE3"
    SYMFONY_RCE4 = "Symfony/RCE4"
    SYMFONY_FW1 = "Symfony/FW1"
    SYMFONY_FW2 = "Symfony/FW2"
    LARAVEL_RCE1 = "Laravel/RCE1"
    LARAVEL_RCE2 = "Laravel/RCE2"
    LARAVEL_RCE3 = "Laravel/RCE3"
    LARAVEL_RCE4 = "Laravel/RCE4"
    LARAVEL_RCE5 = "Laravel/RCE5"
    LARAVEL_RCE6 = "Laravel/RCE6"
    LARAVEL_RCE7 = "Laravel/RCE7"
    LARAVEL_RCE8 = "Laravel/RCE8"
    DOCTRINE_FW1 = "Doctrine/FW1"
    DOCTRINE_FW2 = "Doctrine/FW2"
    DOCTRINE_RCE1 = "Doctrine/RCE1"
    DOCTRINE_RCE2 = "Doctrine/RCE2"
    WORDPRESS_RCE1 = "WordPress/RCE1"
    WORDPRESS_P1 = "WordPress/P/PropertyOrientedProgramming1"
    MAGENTO_FW1 = "Magento/FW1"
    MAGENTO_SQLI = "Magento/SQLI1"
    SLIM_RCE1 = "Slim/RCE1"
    YIIFRAMEWORK_RCE1 = "Yii/RCE1"
    YIIFRAMEWORK_RCE2 = "Yii/RCE2"
    CAKEPHP_RCE1 = "CakePHP/RCE1"
    SWIFTMAILER_FW1 = "SwiftMailer/FW1"
    SWIFTMAILER_FW2 = "SwiftMailer/FW2"
    SWIFTMAILER_FW3 = "SwiftMailer/FW3"
    PHPUNIT_RCE1 = "PHPUnit/RCE1"
    # .NET gadgets (ysoserial.net)
    TYPECONFUSE = "TypeConfuseDelegate"
    TYPECONFUSE_FUNC = "TypeConfuseDelegateMono"
    ACTIVITYSURROGATE = "ActivitySurrogateSelector"
    ACTIVITYSURROGATE_DIS = "ActivitySurrogateSelectorFromFile"
    TEXTFORMATTINGRUNPROPERTIES = "TextFormattingRunProperties"
    WINDOWSIDENTITY = "WindowsIdentity"
    WINDOWSPRINCIPAL = "WindowsPrincipal"
    OBJECTDATAPROVIDER = "ObjectDataProvider"
    PAGECONTENT_RCE = "PSObject"
    SESSIONVIEWSTATEWRAPPER = "SessionViewStateWrapper"
    VIEWSTATE_RCE = "ViewState"
    CLAIMSPRINCIPAL = "ClaimsPrincipal"
    # Ruby gadgets
    GEM_INSTALLER = "Gem::Installer"
    GEM_SPECFETCHER = "Gem::SpecFetcher"
    GEM_REQUIREMENT = "Gem::Requirement"
    ERB_TEMPLATE = "ERB"
    NET_BUFFERED = "Net::BufferedIO"


class SerializationFormat(Enum):
    """Serialization format identifiers."""
    JAVA_NATIVE = "java_native_serialization"
    JAVA_XML = "java_xml_serialization"
    JAVA_XSTREAM = "java_xstream"
    PHP_SERIALIZE = "php_native_serialize"
    PHP_PHAR = "php_phar_archive"
    PYTHON_PICKLE = "python_pickle"
    PYTHON_YAML = "python_yaml"
    PYTHON_JSON_PICKLE = "python_jsonpickle"
    PYTHON_MARSHAL = "python_marshal"
    DOTNET_BINARY = "dotnet_binaryformatter"
    DOTNET_SOAP = "dotnet_soapformatter"
    DOTNET_JSON = "dotnet_jsonnet"
    DOTNET_LOS = "dotnet_losformatter"
    DOTNET_OBJECTSTATE = "dotnet_objectstateformatter"
    RUBY_MARSHAL = "ruby_marshal"
    RUBY_YAML = "ruby_yaml"
    NODE_JSON_FUNC = "node_json_function"
    MSGPACK = "msgpack"
    PROTOBUF = "protobuf"
    AMF = "amf_flash"


@dataclass
class DeserTestResult:
    """Result from a deserialization test."""
    vuln_type: DeserVulnType
    gadget_chain: GadgetChainType | None = None
    serialization_format: SerializationFormat | None = None
    parameter: str = ""
    endpoint: str = ""
    evidence: list[str] = field(default_factory=list)
    rce_confirmed: bool = False
    dns_callback: bool = False
    time_based: bool = False
    error_based: bool = False
    response_diff: bool = False
    cve_ids: list[str] = field(default_factory=list)


@dataclass
class FrameworkSignature:
    """Framework identification signature."""
    name: str
    version_pattern: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)
    body_patterns: list[str] = field(default_factory=list)
    gadget_chains: list[GadgetChainType] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
