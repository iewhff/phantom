"""
Tests for scanning/modules/info_disclosure_scanner.py

Covers:
- DisclosureType enum (20 types)
- SeverityLevel enum (5 levels)
- ERROR_PATTERNS constant (6 languages)
- DATABASE_ERRORS constant (6 databases)
- PATH_PATTERNS constant
- INTERNAL_IP_PATTERNS constant
- COMMENT_PATTERNS constant
- VERSION_PATTERNS constant (17 tech)
- DEBUG_ENDPOINTS list
- BACKUP_PATTERNS list
- SOURCE_EXTENSIONS list
- CONFIG_FILES list
"""

import pytest
import re
from scanning.modules.info_disclosure_scanner import (
    VERSION,
    DisclosureType,
    SeverityLevel,
    ERROR_PATTERNS,
    DATABASE_ERRORS,
    PATH_PATTERNS,
    INTERNAL_IP_PATTERNS,
    COMMENT_PATTERNS,
    VERSION_PATTERNS,
    DEBUG_ENDPOINTS,
    BACKUP_PATTERNS,
    SOURCE_EXTENSIONS,
    CONFIG_FILES,
)


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestDisclosureType:
    def test_count(self):
        assert len(DisclosureType) == 20

    def test_error_message(self):
        assert DisclosureType.ERROR_MESSAGE is not None

    def test_stack_trace(self):
        assert DisclosureType.STACK_TRACE is not None

    def test_debug_endpoint(self):
        assert DisclosureType.DEBUG_ENDPOINT is not None

    def test_source_code(self):
        assert DisclosureType.SOURCE_CODE is not None

    def test_backup_file(self):
        assert DisclosureType.BACKUP_FILE is not None

    def test_version_info(self):
        assert DisclosureType.VERSION_INFO is not None

    def test_database_error(self):
        assert DisclosureType.DATABASE_ERROR is not None

    def test_path_disclosure(self):
        assert DisclosureType.PATH_DISCLOSURE is not None

    def test_internal_ip(self):
        assert DisclosureType.INTERNAL_IP is not None

    def test_git_exposure(self):
        assert DisclosureType.GIT_EXPOSURE is not None

    def test_credential_leak(self):
        assert DisclosureType.CREDENTIAL_LEAK is not None

    def test_user_enumeration(self):
        assert DisclosureType.USER_ENUMERATION is not None


class TestSeverityLevel:
    def test_count(self):
        assert len(SeverityLevel) == 5

    def test_critical(self):
        assert SeverityLevel.CRITICAL.value == "CRITICAL"

    def test_high(self):
        assert SeverityLevel.HIGH.value == "HIGH"

    def test_medium(self):
        assert SeverityLevel.MEDIUM.value == "MEDIUM"

    def test_low(self):
        assert SeverityLevel.LOW.value == "LOW"

    def test_info(self):
        assert SeverityLevel.INFO.value == "INFO"


# =============================================================================
# ERROR PATTERNS
# =============================================================================

class TestErrorPatterns:
    def test_has_php(self):
        assert "php" in ERROR_PATTERNS
        assert len(ERROR_PATTERNS["php"]) > 0

    def test_has_python(self):
        assert "python" in ERROR_PATTERNS
        assert len(ERROR_PATTERNS["python"]) > 0

    def test_has_java(self):
        assert "java" in ERROR_PATTERNS
        assert len(ERROR_PATTERNS["java"]) > 0

    def test_has_dotnet(self):
        assert "dotnet" in ERROR_PATTERNS
        assert len(ERROR_PATTERNS["dotnet"]) > 0

    def test_has_ruby(self):
        assert "ruby" in ERROR_PATTERNS
        assert len(ERROR_PATTERNS["ruby"]) > 0

    def test_has_nodejs(self):
        assert "nodejs" in ERROR_PATTERNS
        assert len(ERROR_PATTERNS["nodejs"]) > 0

    def test_php_patterns_compile(self):
        for p in ERROR_PATTERNS["php"]:
            re.compile(p)

    def test_python_patterns_compile(self):
        for p in ERROR_PATTERNS["python"]:
            re.compile(p)

    def test_java_patterns_compile(self):
        for p in ERROR_PATTERNS["java"]:
            re.compile(p)

    def test_dotnet_patterns_compile(self):
        for p in ERROR_PATTERNS["dotnet"]:
            re.compile(p)

    def test_php_detects_fatal_error(self):
        body = "Fatal error: Uncaught Exception in /var/www/app.php on line 42"
        assert any(re.search(p, body) for p in ERROR_PATTERNS["php"])

    def test_python_detects_traceback(self):
        body = "Traceback (most recent call last):"
        assert any(re.search(p, body) for p in ERROR_PATTERNS["python"])

    def test_java_detects_exception(self):
        body = "java.lang.NullPointerException:"
        assert any(re.search(p, body) for p in ERROR_PATTERNS["java"])

    def test_dotnet_detects_exception(self):
        body = "System.NullReferenceException:"
        assert any(re.search(p, body) for p in ERROR_PATTERNS["dotnet"])

    def test_nodejs_detects_reference_error(self):
        body = "ReferenceError: undefined variable"
        assert any(re.search(p, body) for p in ERROR_PATTERNS["nodejs"])


# =============================================================================
# DATABASE ERRORS
# =============================================================================

class TestDatabaseErrors:
    def test_has_mysql(self):
        assert "mysql" in DATABASE_ERRORS
        assert len(DATABASE_ERRORS["mysql"]) > 0

    def test_has_postgresql(self):
        assert "postgresql" in DATABASE_ERRORS
        assert len(DATABASE_ERRORS["postgresql"]) > 0

    def test_has_mssql(self):
        assert "mssql" in DATABASE_ERRORS
        assert len(DATABASE_ERRORS["mssql"]) > 0

    def test_has_oracle(self):
        assert "oracle" in DATABASE_ERRORS
        assert len(DATABASE_ERRORS["oracle"]) > 0

    def test_has_sqlite(self):
        assert "sqlite" in DATABASE_ERRORS
        assert len(DATABASE_ERRORS["sqlite"]) > 0

    def test_has_mongodb(self):
        assert "mongodb" in DATABASE_ERRORS
        assert len(DATABASE_ERRORS["mongodb"]) > 0

    def test_mysql_detects_syntax(self):
        body = "You have an error in your SQL syntax"
        assert any(re.search(p, body) for p in DATABASE_ERRORS["mysql"])

    def test_postgresql_detects_syntax(self):
        body = "ERROR:  syntax error at or near \"foo\""
        assert any(re.search(p, body) for p in DATABASE_ERRORS["postgresql"])

    def test_oracle_detects_ora(self):
        body = "ORA-01756: quoted string not properly terminated"
        assert any(re.search(p, body) for p in DATABASE_ERRORS["oracle"])

    def test_all_patterns_compile(self):
        for db, patterns in DATABASE_ERRORS.items():
            for p in patterns:
                re.compile(p)


# =============================================================================
# PATH PATTERNS
# =============================================================================

class TestPathPatterns:
    def test_not_empty(self):
        assert len(PATH_PATTERNS) > 0

    def test_all_compile(self):
        for p in PATH_PATTERNS:
            re.compile(p)

    def test_detects_var_www(self):
        body = "/var/www/html/app.php"
        assert any(re.search(p, body) for p in PATH_PATTERNS)

    def test_detects_home(self):
        body = "/home/user/project/app.py"
        assert any(re.search(p, body) for p in PATH_PATTERNS)

    def test_detects_windows_c(self):
        body = "C:\\inetpub\\wwwroot\\web.config"
        assert any(re.search(p, body) for p in PATH_PATTERNS)

    def test_detects_etc(self):
        body = "/etc/passwd"
        assert any(re.search(p, body) for p in PATH_PATTERNS)


# =============================================================================
# INTERNAL IP PATTERNS
# =============================================================================

class TestInternalIPPatterns:
    def test_not_empty(self):
        assert len(INTERNAL_IP_PATTERNS) > 0

    def test_all_compile(self):
        for p in INTERNAL_IP_PATTERNS:
            re.compile(p)

    def test_detects_10_range(self):
        body = "Server: 10.0.1.50"
        assert any(re.search(p, body) for p in INTERNAL_IP_PATTERNS)

    def test_detects_172_range(self):
        body = "Backend: 172.16.0.1"
        assert any(re.search(p, body) for p in INTERNAL_IP_PATTERNS)

    def test_detects_192_range(self):
        body = "192.168.1.100"
        assert any(re.search(p, body) for p in INTERNAL_IP_PATTERNS)

    def test_detects_localhost(self):
        body = "connected to localhost"
        assert any(re.search(p, body) for p in INTERNAL_IP_PATTERNS)

    def test_detects_127(self):
        body = "127.0.0.1"
        assert any(re.search(p, body) for p in INTERNAL_IP_PATTERNS)


# =============================================================================
# COMMENT PATTERNS
# =============================================================================

class TestCommentPatterns:
    def test_not_empty(self):
        assert len(COMMENT_PATTERNS) > 0

    def test_all_compile(self):
        for p in COMMENT_PATTERNS:
            re.compile(p, re.I | re.S)

    def test_detects_html_password(self):
        body = "<!-- password: admin123 -->"
        assert any(re.search(p, body, re.I | re.S) for p in COMMENT_PATTERNS)

    def test_detects_html_api_key(self):
        body = "<!-- api_key: sk-12345 -->"
        assert any(re.search(p, body, re.I | re.S) for p in COMMENT_PATTERNS)

    def test_detects_todo(self):
        body = "<!-- TODO: fix authentication -->"
        assert any(re.search(p, body, re.I | re.S) for p in COMMENT_PATTERNS)

    def test_detects_debug(self):
        body = "<!-- DEBUG: session data here -->"
        assert any(re.search(p, body, re.I | re.S) for p in COMMENT_PATTERNS)


# =============================================================================
# VERSION PATTERNS
# =============================================================================

class TestVersionPatterns:
    def test_has_apache(self):
        assert "apache" in VERSION_PATTERNS

    def test_has_nginx(self):
        assert "nginx" in VERSION_PATTERNS

    def test_has_iis(self):
        assert "iis" in VERSION_PATTERNS

    def test_has_php(self):
        assert "php" in VERSION_PATTERNS

    def test_has_python(self):
        assert "python" in VERSION_PATTERNS

    def test_has_nodejs(self):
        assert "nodejs" in VERSION_PATTERNS

    def test_has_wordpress(self):
        assert "wordpress" in VERSION_PATTERNS

    def test_has_django(self):
        assert "django" in VERSION_PATTERNS

    def test_has_openssl(self):
        assert "openssl" in VERSION_PATTERNS

    def test_all_compile(self):
        for name, p in VERSION_PATTERNS.items():
            re.compile(p)

    def test_apache_extracts_version(self):
        header = "Apache/2.4.51"
        m = re.search(VERSION_PATTERNS["apache"], header)
        assert m is not None
        assert m.group(1) == "2.4.51"

    def test_nginx_extracts_version(self):
        header = "nginx/1.21.6"
        m = re.search(VERSION_PATTERNS["nginx"], header)
        assert m is not None
        assert m.group(1) == "1.21.6"

    def test_php_extracts_version(self):
        header = "PHP/8.1.12"
        m = re.search(VERSION_PATTERNS["php"], header)
        assert m is not None
        assert m.group(1) == "8.1.12"


# =============================================================================
# DEBUG ENDPOINTS
# =============================================================================

class TestDebugEndpoints:
    def test_not_empty(self):
        assert len(DEBUG_ENDPOINTS) > 0

    def test_has_phpinfo(self):
        assert "/phpinfo.php" in DEBUG_ENDPOINTS

    def test_has_actuator(self):
        assert "/actuator" in DEBUG_ENDPOINTS

    def test_has_actuator_env(self):
        assert "/actuator/env" in DEBUG_ENDPOINTS

    def test_has_actuator_heapdump(self):
        assert "/actuator/heapdump" in DEBUG_ENDPOINTS

    def test_has_server_status(self):
        assert "/server-status" in DEBUG_ENDPOINTS

    def test_has_debug(self):
        assert "/debug/" in DEBUG_ENDPOINTS or "/__debug__/" in DEBUG_ENDPOINTS

    def test_has_elmah(self):
        assert "/elmah.axd" in DEBUG_ENDPOINTS

    def test_has_health(self):
        assert "/health" in DEBUG_ENDPOINTS

    def test_has_metrics(self):
        assert "/metrics" in DEBUG_ENDPOINTS

    def test_all_are_strings(self):
        for ep in DEBUG_ENDPOINTS:
            assert isinstance(ep, str)


# =============================================================================
# BACKUP PATTERNS
# =============================================================================

class TestBackupPatterns:
    def test_not_empty(self):
        assert len(BACKUP_PATTERNS) > 0

    def test_has_bak(self):
        assert "{path}.bak" in BACKUP_PATTERNS

    def test_has_backup(self):
        assert "{path}.backup" in BACKUP_PATTERNS

    def test_has_old(self):
        assert "{path}.old" in BACKUP_PATTERNS

    def test_has_swp(self):
        assert "{path}.swp" in BACKUP_PATTERNS

    def test_has_tilde(self):
        assert "{path}~" in BACKUP_PATTERNS

    def test_has_tmp(self):
        assert "{path}.tmp" in BACKUP_PATTERNS


# =============================================================================
# SOURCE EXTENSIONS
# =============================================================================

class TestSourceExtensions:
    def test_not_empty(self):
        assert len(SOURCE_EXTENSIONS) > 0

    def test_has_php(self):
        assert ".php" in SOURCE_EXTENSIONS

    def test_has_py(self):
        assert ".py" in SOURCE_EXTENSIONS

    def test_has_java(self):
        assert ".java" in SOURCE_EXTENSIONS

    def test_has_js(self):
        assert ".js" in SOURCE_EXTENSIONS

    def test_has_go(self):
        assert ".go" in SOURCE_EXTENSIONS

    def test_has_rb(self):
        assert ".rb" in SOURCE_EXTENSIONS

    def test_all_start_with_dot(self):
        for ext in SOURCE_EXTENSIONS:
            assert ext.startswith(".")


# =============================================================================
# CONFIG FILES
# =============================================================================

class TestConfigFiles:
    def test_not_empty(self):
        assert len(CONFIG_FILES) > 0

    def test_has_env(self):
        assert ".env" in CONFIG_FILES

    def test_has_env_production(self):
        assert ".env.production" in CONFIG_FILES

    def test_has_web_config(self):
        assert "web.config" in CONFIG_FILES

    def test_has_htaccess(self):
        assert ".htaccess" in CONFIG_FILES

    def test_has_application_yml(self):
        assert "application.yml" in CONFIG_FILES

    def test_has_appsettings_json(self):
        assert "appsettings.json" in CONFIG_FILES

    def test_has_secrets_yml(self):
        assert "secrets.yml" in CONFIG_FILES

    def test_has_database_yml(self):
        assert "database.yml" in CONFIG_FILES


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    def test_version(self):
        assert VERSION == "3.0.0"

    def test_all_disclosure_types_unique(self):
        values = [t.value for t in DisclosureType]
        assert len(values) == len(set(values))

    def test_all_severity_levels_unique(self):
        values = [s.value for s in SeverityLevel]
        assert len(values) == len(set(values))

    def test_version_patterns_count(self):
        assert len(VERSION_PATTERNS) >= 15

    def test_debug_endpoints_count(self):
        assert len(DEBUG_ENDPOINTS) >= 30
