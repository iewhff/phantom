"""
Tests for scanning/modules/config_exposure_scanner.py

Covers:
- SensitiveFile dataclass (defaults, full creation, properties)
- VCS_FILES list (count, key entries, types)
- ENV_FILES list (count, key entries, types)
- CONFIG_FILES list (count, key entries)
- BACKUP_FILES list (count, key entries)
- BUILD_FILES list (count, key entries)
- IDE_FILES list (count, key entries)
- DEBUG_ENDPOINTS list (count, key entries)
- API_DOCS list (count, key entries)
- SECURITY_FILES list (count, key entries)
- ALL_SENSITIVE_FILES combined list (count, composition)
- ConfigExposureScanner identity (name, ScanModule subclass)
- ConfigExposureScanner instance attributes (timeout, max_concurrent)
- Redaction regex patterns (_extract_preview)
- _categorize_file method
"""

import re

import pytest

from scanning.modules.config_exposure_scanner import (
    SensitiveFile,
    VCS_FILES,
    ENV_FILES,
    CONFIG_FILES,
    BACKUP_FILES,
    BUILD_FILES,
    IDE_FILES,
    DEBUG_ENDPOINTS,
    API_DOCS,
    SECURITY_FILES,
    ALL_SENSITIVE_FILES,
    ConfigExposureScanner,
)
from scanning.vuln_scanner import ScanModule


MOCK_SETTINGS = {"target_url": "http://test.local", "safety_level": "safe"}


# =============================================================================
# DATACLASS TESTS
# =============================================================================

class TestSensitiveFile:
    """Test SensitiveFile dataclass."""

    def test_defaults(self):
        sf = SensitiveFile(path="/test", description="Test file", severity="LOW")
        assert sf.path == "/test"
        assert sf.description == "Test file"
        assert sf.severity == "LOW"
        assert sf.indicators == []
        assert sf.anti_indicators == []
        assert sf.min_size == 0
        assert sf.max_size == 10_000_000

    def test_full_creation(self):
        sf = SensitiveFile(
            path="/.git/config",
            description="Git config exposed",
            severity="CRITICAL",
            indicators=["[core]", "[remote"],
            anti_indicators=["<!DOCTYPE", "<html"],
            min_size=10,
            max_size=5000,
        )
        assert sf.path == "/.git/config"
        assert sf.description == "Git config exposed"
        assert sf.severity == "CRITICAL"
        assert sf.indicators == ["[core]", "[remote"]
        assert sf.anti_indicators == ["<!DOCTYPE", "<html"]
        assert sf.min_size == 10
        assert sf.max_size == 5000

    def test_indicators_are_independent(self):
        sf1 = SensitiveFile(path="/a", description="a", severity="LOW")
        sf2 = SensitiveFile(path="/b", description="b", severity="LOW")
        sf1.indicators.append("test")
        assert sf2.indicators == []

    def test_anti_indicators_are_independent(self):
        sf1 = SensitiveFile(path="/a", description="a", severity="LOW")
        sf2 = SensitiveFile(path="/b", description="b", severity="LOW")
        sf1.anti_indicators.append("test")
        assert sf2.anti_indicators == []


# =============================================================================
# VCS FILES
# =============================================================================

class TestVCSFiles:
    """Test VCS_FILES list."""

    def test_count(self):
        assert len(VCS_FILES) == 11

    def test_all_are_sensitive_file(self):
        for sf in VCS_FILES:
            assert isinstance(sf, SensitiveFile)

    def test_has_git_config(self):
        paths = [sf.path for sf in VCS_FILES]
        assert "/.git/config" in paths

    def test_has_git_head(self):
        paths = [sf.path for sf in VCS_FILES]
        assert "/.git/HEAD" in paths

    def test_has_git_index(self):
        paths = [sf.path for sf in VCS_FILES]
        assert "/.git/index" in paths

    def test_has_git_logs_head(self):
        paths = [sf.path for sf in VCS_FILES]
        assert "/.git/logs/HEAD" in paths

    def test_has_svn_entries(self):
        paths = [sf.path for sf in VCS_FILES]
        assert "/.svn/entries" in paths

    def test_has_svn_wc_db(self):
        paths = [sf.path for sf in VCS_FILES]
        assert "/.svn/wc.db" in paths

    def test_has_hg_hgrc(self):
        paths = [sf.path for sf in VCS_FILES]
        assert "/.hg/hgrc" in paths

    def test_has_bzr_config(self):
        paths = [sf.path for sf in VCS_FILES]
        assert "/.bzr/branch/branch.conf" in paths

    def test_has_cvs_root(self):
        paths = [sf.path for sf in VCS_FILES]
        assert "/CVS/Root" in paths

    def test_has_cvs_entries(self):
        paths = [sf.path for sf in VCS_FILES]
        assert "/CVS/Entries" in paths

    def test_git_config_severity_critical(self):
        sf = next(s for s in VCS_FILES if s.path == "/.git/config")
        assert sf.severity == "CRITICAL"

    def test_git_config_indicators(self):
        sf = next(s for s in VCS_FILES if s.path == "/.git/config")
        assert "[core]" in sf.indicators
        assert "[remote" in sf.indicators

    def test_all_have_anti_indicators(self):
        for sf in VCS_FILES:
            assert isinstance(sf.anti_indicators, list)


# =============================================================================
# ENV FILES
# =============================================================================

class TestEnvFiles:
    """Test ENV_FILES list."""

    def test_count(self):
        assert len(ENV_FILES) == 9

    def test_all_are_sensitive_file(self):
        for sf in ENV_FILES:
            assert isinstance(sf, SensitiveFile)

    def test_has_env(self):
        paths = [sf.path for sf in ENV_FILES]
        assert "/.env" in paths

    def test_has_env_local(self):
        paths = [sf.path for sf in ENV_FILES]
        assert "/.env.local" in paths

    def test_has_env_development(self):
        paths = [sf.path for sf in ENV_FILES]
        assert "/.env.development" in paths

    def test_has_env_production(self):
        paths = [sf.path for sf in ENV_FILES]
        assert "/.env.production" in paths

    def test_has_env_staging(self):
        paths = [sf.path for sf in ENV_FILES]
        assert "/.env.staging" in paths

    def test_has_env_backup(self):
        paths = [sf.path for sf in ENV_FILES]
        assert "/.env.backup" in paths

    def test_has_env_example(self):
        paths = [sf.path for sf in ENV_FILES]
        assert "/.env.example" in paths

    def test_has_env_sample(self):
        paths = [sf.path for sf in ENV_FILES]
        assert "/.env.sample" in paths

    def test_has_env_js(self):
        paths = [sf.path for sf in ENV_FILES]
        assert "/env.js" in paths

    def test_env_is_critical(self):
        sf = next(s for s in ENV_FILES if s.path == "/.env")
        assert sf.severity == "CRITICAL"

    def test_env_production_is_critical(self):
        sf = next(s for s in ENV_FILES if s.path == "/.env.production")
        assert sf.severity == "CRITICAL"

    def test_env_example_is_low(self):
        sf = next(s for s in ENV_FILES if s.path == "/.env.example")
        assert sf.severity == "LOW"

    def test_env_indicators_include_common_patterns(self):
        sf = next(s for s in ENV_FILES if s.path == "/.env")
        assert "DB_" in sf.indicators
        assert "API_" in sf.indicators
        assert "SECRET" in sf.indicators


# =============================================================================
# CONFIG FILES
# =============================================================================

class TestConfigFiles:
    """Test CONFIG_FILES list."""

    def test_count(self):
        assert len(CONFIG_FILES) == 45

    def test_all_are_sensitive_file(self):
        for sf in CONFIG_FILES:
            assert isinstance(sf, SensitiveFile)

    def test_has_config_json(self):
        paths = [sf.path for sf in CONFIG_FILES]
        assert "/config.json" in paths

    def test_has_config_yml(self):
        paths = [sf.path for sf in CONFIG_FILES]
        assert "/config.yml" in paths

    def test_has_config_yaml(self):
        paths = [sf.path for sf in CONFIG_FILES]
        assert "/config.yaml" in paths

    def test_has_wp_config(self):
        paths = [sf.path for sf in CONFIG_FILES]
        assert "/wp-config.php" in paths

    def test_has_wp_config_bak(self):
        paths = [sf.path for sf in CONFIG_FILES]
        assert "/wp-config.php.bak" in paths

    def test_has_rails_database_yml(self):
        paths = [sf.path for sf in CONFIG_FILES]
        assert "/config/database.yml" in paths

    def test_has_rails_secrets_yml(self):
        paths = [sf.path for sf in CONFIG_FILES]
        assert "/config/secrets.yml" in paths

    def test_has_rails_master_key(self):
        paths = [sf.path for sf in CONFIG_FILES]
        assert "/config/master.key" in paths

    def test_has_package_json(self):
        paths = [sf.path for sf in CONFIG_FILES]
        assert "/package.json" in paths

    def test_has_requirements_txt(self):
        paths = [sf.path for sf in CONFIG_FILES]
        assert "/requirements.txt" in paths

    def test_has_composer_json(self):
        paths = [sf.path for sf in CONFIG_FILES]
        assert "/composer.json" in paths

    def test_has_pom_xml(self):
        paths = [sf.path for sf in CONFIG_FILES]
        assert "/pom.xml" in paths

    def test_has_application_properties(self):
        paths = [sf.path for sf in CONFIG_FILES]
        assert "/application.properties" in paths

    def test_has_application_yml(self):
        paths = [sf.path for sf in CONFIG_FILES]
        assert "/application.yml" in paths

    def test_has_web_config(self):
        paths = [sf.path for sf in CONFIG_FILES]
        assert "/web.config" in paths

    def test_has_appsettings_json(self):
        paths = [sf.path for sf in CONFIG_FILES]
        assert "/appsettings.json" in paths

    def test_has_go_mod(self):
        paths = [sf.path for sf in CONFIG_FILES]
        assert "/go.mod" in paths

    def test_has_gemfile(self):
        paths = [sf.path for sf in CONFIG_FILES]
        assert "/Gemfile" in paths

    def test_wp_config_is_critical(self):
        sf = next(s for s in CONFIG_FILES if s.path == "/wp-config.php")
        assert sf.severity == "CRITICAL"

    def test_package_json_is_low(self):
        sf = next(s for s in CONFIG_FILES if s.path == "/package.json")
        assert sf.severity == "LOW"

    def test_spring_prod_is_critical(self):
        sf = next(s for s in CONFIG_FILES if s.path == "/application-prod.properties")
        assert sf.severity == "CRITICAL"

    def test_rails_master_key_max_size(self):
        sf = next(s for s in CONFIG_FILES if s.path == "/config/master.key")
        assert sf.max_size == 64
        assert sf.min_size == 32


# =============================================================================
# BACKUP FILES
# =============================================================================

class TestBackupFiles:
    """Test BACKUP_FILES list."""

    def test_count(self):
        assert len(BACKUP_FILES) == 9

    def test_all_are_sensitive_file(self):
        for sf in BACKUP_FILES:
            assert isinstance(sf, SensitiveFile)

    def test_has_backup_sql(self):
        paths = [sf.path for sf in BACKUP_FILES]
        assert "/backup.sql" in paths

    def test_has_backup_zip(self):
        paths = [sf.path for sf in BACKUP_FILES]
        assert "/backup.zip" in paths

    def test_has_db_sql(self):
        paths = [sf.path for sf in BACKUP_FILES]
        assert "/db.sql" in paths

    def test_has_database_sql(self):
        paths = [sf.path for sf in BACKUP_FILES]
        assert "/database.sql" in paths

    def test_has_dump_sql(self):
        paths = [sf.path for sf in BACKUP_FILES]
        assert "/dump.sql" in paths

    def test_has_mysql_sql(self):
        paths = [sf.path for sf in BACKUP_FILES]
        assert "/mysql.sql" in paths

    def test_has_localhost_sql(self):
        paths = [sf.path for sf in BACKUP_FILES]
        assert "/localhost.sql" in paths

    def test_all_are_critical_or_high(self):
        for sf in BACKUP_FILES:
            assert sf.severity in ("CRITICAL", "HIGH"), f"{sf.path} severity is {sf.severity}"

    def test_backup_sql_indicators(self):
        sf = next(s for s in BACKUP_FILES if s.path == "/backup.sql")
        assert "CREATE TABLE" in sf.indicators
        assert "INSERT INTO" in sf.indicators

    def test_backup_zip_indicator(self):
        sf = next(s for s in BACKUP_FILES if s.path == "/backup.zip")
        assert "PK" in sf.indicators


# =============================================================================
# BUILD FILES
# =============================================================================

class TestBuildFiles:
    """Test BUILD_FILES list."""

    def test_count(self):
        assert len(BUILD_FILES) == 14

    def test_all_are_sensitive_file(self):
        for sf in BUILD_FILES:
            assert isinstance(sf, SensitiveFile)

    def test_has_main_js_map(self):
        paths = [sf.path for sf in BUILD_FILES]
        assert "/main.js.map" in paths

    def test_has_app_js_map(self):
        paths = [sf.path for sf in BUILD_FILES]
        assert "/app.js.map" in paths

    def test_has_bundle_js_map(self):
        paths = [sf.path for sf in BUILD_FILES]
        assert "/bundle.js.map" in paths

    def test_has_webpack_config(self):
        paths = [sf.path for sf in BUILD_FILES]
        assert "/webpack.config.js" in paths

    def test_has_vite_config(self):
        paths = [sf.path for sf in BUILD_FILES]
        assert "/vite.config.js" in paths

    def test_has_tsconfig(self):
        paths = [sf.path for sf in BUILD_FILES]
        assert "/tsconfig.json" in paths

    def test_has_dockerfile(self):
        paths = [sf.path for sf in BUILD_FILES]
        assert "/Dockerfile" in paths

    def test_has_docker_compose_yml(self):
        paths = [sf.path for sf in BUILD_FILES]
        assert "/docker-compose.yml" in paths

    def test_has_docker_compose_yaml(self):
        paths = [sf.path for sf in BUILD_FILES]
        assert "/docker-compose.yaml" in paths

    def test_has_makefile(self):
        paths = [sf.path for sf in BUILD_FILES]
        assert "/Makefile" in paths

    def test_has_babelrc(self):
        paths = [sf.path for sf in BUILD_FILES]
        assert "/.babelrc" in paths

    def test_docker_compose_is_high(self):
        sf = next(s for s in BUILD_FILES if s.path == "/docker-compose.yml")
        assert sf.severity == "HIGH"

    def test_source_maps_are_medium(self):
        source_maps = [sf for sf in BUILD_FILES if sf.path.endswith(".js.map")]
        for sf in source_maps:
            assert sf.severity == "MEDIUM"


# =============================================================================
# IDE FILES
# =============================================================================

class TestIDEFiles:
    """Test IDE_FILES list."""

    def test_count(self):
        assert len(IDE_FILES) == 8

    def test_all_are_sensitive_file(self):
        for sf in IDE_FILES:
            assert isinstance(sf, SensitiveFile)

    def test_has_idea_workspace(self):
        paths = [sf.path for sf in IDE_FILES]
        assert "/.idea/workspace.xml" in paths

    def test_has_idea_modules(self):
        paths = [sf.path for sf in IDE_FILES]
        assert "/.idea/modules.xml" in paths

    def test_has_vscode_settings(self):
        paths = [sf.path for sf in IDE_FILES]
        assert "/.vscode/settings.json" in paths

    def test_has_vscode_launch(self):
        paths = [sf.path for sf in IDE_FILES]
        assert "/.vscode/launch.json" in paths

    def test_has_sublime_project(self):
        paths = [sf.path for sf in IDE_FILES]
        assert "/.sublime-project" in paths

    def test_has_editorconfig(self):
        paths = [sf.path for sf in IDE_FILES]
        assert "/.editorconfig" in paths

    def test_has_ds_store(self):
        paths = [sf.path for sf in IDE_FILES]
        assert "/.DS_Store" in paths

    def test_has_thumbs_db(self):
        paths = [sf.path for sf in IDE_FILES]
        assert "/Thumbs.db" in paths

    def test_ds_store_indicator(self):
        sf = next(s for s in IDE_FILES if s.path == "/.DS_Store")
        assert "Bud1" in sf.indicators


# =============================================================================
# DEBUG ENDPOINTS
# =============================================================================

class TestDebugEndpoints:
    """Test DEBUG_ENDPOINTS list."""

    def test_count(self):
        assert len(DEBUG_ENDPOINTS) == 25

    def test_all_are_sensitive_file(self):
        for sf in DEBUG_ENDPOINTS:
            assert isinstance(sf, SensitiveFile)

    def test_has_debug(self):
        paths = [sf.path for sf in DEBUG_ENDPOINTS]
        assert "/debug" in paths

    def test_has_phpinfo(self):
        paths = [sf.path for sf in DEBUG_ENDPOINTS]
        assert "/phpinfo.php" in paths

    def test_has_info_php(self):
        paths = [sf.path for sf in DEBUG_ENDPOINTS]
        assert "/info.php" in paths

    def test_has_elmah_axd(self):
        paths = [sf.path for sf in DEBUG_ENDPOINTS]
        assert "/elmah.axd" in paths

    def test_has_trace_axd(self):
        paths = [sf.path for sf in DEBUG_ENDPOINTS]
        assert "/trace.axd" in paths

    def test_has_actuator(self):
        paths = [sf.path for sf in DEBUG_ENDPOINTS]
        assert "/actuator" in paths

    def test_has_actuator_env(self):
        paths = [sf.path for sf in DEBUG_ENDPOINTS]
        assert "/actuator/env" in paths

    def test_has_actuator_heapdump(self):
        paths = [sf.path for sf in DEBUG_ENDPOINTS]
        assert "/actuator/heapdump" in paths

    def test_has_actuator_health(self):
        paths = [sf.path for sf in DEBUG_ENDPOINTS]
        assert "/actuator/health" in paths

    def test_has_actuator_configprops(self):
        paths = [sf.path for sf in DEBUG_ENDPOINTS]
        assert "/actuator/configprops" in paths

    def test_has_server_status(self):
        paths = [sf.path for sf in DEBUG_ENDPOINTS]
        assert "/server-status" in paths

    def test_has_server_info(self):
        paths = [sf.path for sf in DEBUG_ENDPOINTS]
        assert "/server-info" in paths

    def test_has_nginx_status(self):
        paths = [sf.path for sf in DEBUG_ENDPOINTS]
        assert "/nginx_status" in paths

    def test_has_profiler(self):
        paths = [sf.path for sf in DEBUG_ENDPOINTS]
        assert "/_profiler" in paths

    def test_has_rails_info(self):
        paths = [sf.path for sf in DEBUG_ENDPOINTS]
        assert "/rails/info" in paths

    def test_has_health(self):
        paths = [sf.path for sf in DEBUG_ENDPOINTS]
        assert "/health" in paths

    def test_has_metrics(self):
        paths = [sf.path for sf in DEBUG_ENDPOINTS]
        assert "/metrics" in paths

    def test_actuator_env_is_critical(self):
        sf = next(s for s in DEBUG_ENDPOINTS if s.path == "/actuator/env")
        assert sf.severity == "CRITICAL"

    def test_actuator_heapdump_is_critical(self):
        sf = next(s for s in DEBUG_ENDPOINTS if s.path == "/actuator/heapdump")
        assert sf.severity == "CRITICAL"

    def test_health_is_low(self):
        sf = next(s for s in DEBUG_ENDPOINTS if s.path == "/health")
        assert sf.severity == "LOW"


# =============================================================================
# API DOCS
# =============================================================================

class TestAPIDocs:
    """Test API_DOCS list."""

    def test_count(self):
        assert len(API_DOCS) == 11

    def test_all_are_sensitive_file(self):
        for sf in API_DOCS:
            assert isinstance(sf, SensitiveFile)

    def test_has_swagger_json(self):
        paths = [sf.path for sf in API_DOCS]
        assert "/swagger.json" in paths

    def test_has_swagger_yaml(self):
        paths = [sf.path for sf in API_DOCS]
        assert "/swagger.yaml" in paths

    def test_has_openapi_json(self):
        paths = [sf.path for sf in API_DOCS]
        assert "/openapi.json" in paths

    def test_has_openapi_yaml(self):
        paths = [sf.path for sf in API_DOCS]
        assert "/openapi.yaml" in paths

    def test_has_api_docs(self):
        paths = [sf.path for sf in API_DOCS]
        assert "/api-docs" in paths

    def test_has_api_slash_docs(self):
        paths = [sf.path for sf in API_DOCS]
        assert "/api/docs" in paths

    def test_has_graphql_schema(self):
        paths = [sf.path for sf in API_DOCS]
        assert "/graphql/schema" in paths

    def test_has_graphiql(self):
        paths = [sf.path for sf in API_DOCS]
        assert "/graphiql" in paths

    def test_has_well_known_openapi(self):
        paths = [sf.path for sf in API_DOCS]
        assert "/.well-known/openapi.json" in paths

    def test_all_are_medium(self):
        for sf in API_DOCS:
            assert sf.severity == "MEDIUM", f"{sf.path} is {sf.severity}, expected MEDIUM"


# =============================================================================
# SECURITY FILES
# =============================================================================

class TestSecurityFiles:
    """Test SECURITY_FILES list."""

    def test_count(self):
        assert len(SECURITY_FILES) == 13

    def test_all_are_sensitive_file(self):
        for sf in SECURITY_FILES:
            assert isinstance(sf, SensitiveFile)

    def test_has_htpasswd(self):
        paths = [sf.path for sf in SECURITY_FILES]
        assert "/.htpasswd" in paths

    def test_has_htaccess(self):
        paths = [sf.path for sf in SECURITY_FILES]
        assert "/.htaccess" in paths

    def test_has_id_rsa(self):
        paths = [sf.path for sf in SECURITY_FILES]
        assert "/id_rsa" in paths

    def test_has_id_rsa_pub(self):
        paths = [sf.path for sf in SECURITY_FILES]
        assert "/id_rsa.pub" in paths

    def test_has_ssh_id_rsa(self):
        paths = [sf.path for sf in SECURITY_FILES]
        assert "/.ssh/id_rsa" in paths

    def test_has_private_key(self):
        paths = [sf.path for sf in SECURITY_FILES]
        assert "/private.key" in paths

    def test_has_server_key(self):
        paths = [sf.path for sf in SECURITY_FILES]
        assert "/server.key" in paths

    def test_has_ssl_key(self):
        paths = [sf.path for sf in SECURITY_FILES]
        assert "/ssl.key" in paths

    def test_has_pgpass(self):
        paths = [sf.path for sf in SECURITY_FILES]
        assert "/.pgpass" in paths

    def test_has_my_cnf(self):
        paths = [sf.path for sf in SECURITY_FILES]
        assert "/.my.cnf" in paths

    def test_has_netrc(self):
        paths = [sf.path for sf in SECURITY_FILES]
        assert "/.netrc" in paths

    def test_has_crossdomain_xml(self):
        paths = [sf.path for sf in SECURITY_FILES]
        assert "/crossdomain.xml" in paths

    def test_has_clientaccesspolicy_xml(self):
        paths = [sf.path for sf in SECURITY_FILES]
        assert "/clientaccesspolicy.xml" in paths

    def test_htpasswd_is_critical(self):
        sf = next(s for s in SECURITY_FILES if s.path == "/.htpasswd")
        assert sf.severity == "CRITICAL"

    def test_private_key_indicators(self):
        sf = next(s for s in SECURITY_FILES if s.path == "/id_rsa")
        assert "-----BEGIN" in sf.indicators
        assert "PRIVATE KEY" in sf.indicators

    def test_id_rsa_pub_is_low(self):
        sf = next(s for s in SECURITY_FILES if s.path == "/id_rsa.pub")
        assert sf.severity == "LOW"


# =============================================================================
# ALL SENSITIVE FILES (COMBINED)
# =============================================================================

class TestAllSensitiveFiles:
    """Test ALL_SENSITIVE_FILES combined list."""

    def test_total_count(self):
        expected = (
            len(VCS_FILES)
            + len(ENV_FILES)
            + len(CONFIG_FILES)
            + len(BACKUP_FILES)
            + len(BUILD_FILES)
            + len(IDE_FILES)
            + len(DEBUG_ENDPOINTS)
            + len(API_DOCS)
            + len(SECURITY_FILES)
        )
        assert len(ALL_SENSITIVE_FILES) == expected

    def test_exact_total(self):
        assert len(ALL_SENSITIVE_FILES) == 145

    def test_all_are_sensitive_file(self):
        for sf in ALL_SENSITIVE_FILES:
            assert isinstance(sf, SensitiveFile)

    def test_all_have_path(self):
        for sf in ALL_SENSITIVE_FILES:
            assert isinstance(sf.path, str)
            assert len(sf.path) > 0

    def test_all_have_description(self):
        for sf in ALL_SENSITIVE_FILES:
            assert isinstance(sf.description, str)
            assert len(sf.description) > 0

    def test_all_have_valid_severity(self):
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for sf in ALL_SENSITIVE_FILES:
            assert sf.severity in valid_severities, f"{sf.path} has invalid severity: {sf.severity}"

    def test_all_indicators_are_lists(self):
        for sf in ALL_SENSITIVE_FILES:
            assert isinstance(sf.indicators, list)
            assert isinstance(sf.anti_indicators, list)

    def test_all_paths_start_with_slash(self):
        for sf in ALL_SENSITIVE_FILES:
            assert sf.path.startswith("/"), f"Path should start with /: {sf.path}"

    def test_no_duplicate_paths(self):
        paths = [sf.path for sf in ALL_SENSITIVE_FILES]
        assert len(paths) == len(set(paths)), "Duplicate paths found"

    def test_severity_distribution(self):
        severities = [sf.severity for sf in ALL_SENSITIVE_FILES]
        assert severities.count("CRITICAL") > 0
        assert severities.count("HIGH") > 0
        assert severities.count("MEDIUM") > 0
        assert severities.count("LOW") > 0

    def test_vcs_files_at_start(self):
        """VCS files should be the first entries."""
        for i, sf in enumerate(VCS_FILES):
            assert ALL_SENSITIVE_FILES[i] is sf

    def test_security_files_at_end(self):
        """Security files should be the last entries."""
        offset = len(ALL_SENSITIVE_FILES) - len(SECURITY_FILES)
        for i, sf in enumerate(SECURITY_FILES):
            assert ALL_SENSITIVE_FILES[offset + i] is sf


# =============================================================================
# SCANNER IDENTITY
# =============================================================================

class TestConfigExposureScannerIdentity:
    """Test ConfigExposureScanner class identity and structure."""

    def test_is_scan_module_subclass(self):
        assert issubclass(ConfigExposureScanner, ScanModule)

    def test_name_attribute(self):
        assert ConfigExposureScanner.name == "config_exposure"

    def test_description_attribute(self):
        assert ConfigExposureScanner.description == "Detects exposed configuration files, .env, .git, backups"

    def test_version_attribute(self):
        assert ConfigExposureScanner.version == "1.0.0"

    def test_author_attribute(self):
        assert ConfigExposureScanner.author == "PHANTOM AI"

    def test_tags_attribute(self):
        assert isinstance(ConfigExposureScanner.tags, list)
        assert "config" in ConfigExposureScanner.tags
        assert "exposure" in ConfigExposureScanner.tags
        assert "secrets" in ConfigExposureScanner.tags
        assert "discovery" in ConfigExposureScanner.tags
        assert len(ConfigExposureScanner.tags) == 4


# =============================================================================
# SCANNER INSTANCE ATTRIBUTES
# =============================================================================

class TestConfigExposureScannerInstance:
    """Test ConfigExposureScanner instance creation and defaults."""

    def test_instance_creation(self):
        scanner = ConfigExposureScanner(MOCK_SETTINGS)
        assert scanner is not None

    def test_timeout_default(self):
        scanner = ConfigExposureScanner(MOCK_SETTINGS)
        assert scanner.timeout == 10.0

    def test_max_concurrent_default(self):
        scanner = ConfigExposureScanner(MOCK_SETTINGS)
        assert scanner.max_concurrent == 20

    def test_homepage_hash_default(self):
        scanner = ConfigExposureScanner(MOCK_SETTINGS)
        assert scanner._homepage_hash == ""

    def test_homepage_size_default(self):
        scanner = ConfigExposureScanner(MOCK_SETTINGS)
        assert scanner._homepage_size == 0

    def test_instance_with_none_settings(self):
        scanner = ConfigExposureScanner(None)
        assert scanner.timeout == 10.0


# =============================================================================
# REDACTION REGEX PATTERNS
# =============================================================================

class TestRedactionPatterns:
    """Test the regex patterns used in _extract_preview for redacting sensitive values."""

    REDACTION_PATTERNS = [
        (r'(password\s*[=:]\s*)[^\s\n"\']+', r'\1[REDACTED]'),
        (r'(secret\s*[=:]\s*)[^\s\n"\']+', r'\1[REDACTED]'),
        (r'(api_key\s*[=:]\s*)[^\s\n"\']+', r'\1[REDACTED]'),
        (r'(token\s*[=:]\s*)[^\s\n"\']+', r'\1[REDACTED]'),
        (r'(DB_PASSWORD\s*=\s*)[^\s\n]+', r'\1[REDACTED]'),
        (r'(AWS_SECRET[^\s]*\s*=\s*)[^\s\n]+', r'\1[REDACTED]'),
        (r'-----BEGIN[^-]*PRIVATE KEY-----[\s\S]*?-----END[^-]*PRIVATE KEY-----', '[PRIVATE KEY REDACTED]'),
    ]

    def test_pattern_count(self):
        assert len(self.REDACTION_PATTERNS) == 7

    def test_all_patterns_compile(self):
        for pattern, _ in self.REDACTION_PATTERNS:
            re.compile(pattern, re.IGNORECASE)

    def test_password_redaction(self):
        pattern, replacement = self.REDACTION_PATTERNS[0]
        text = "password = mysecretpass123"
        result = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        assert "[REDACTED]" in result
        assert "mysecretpass123" not in result

    def test_password_colon_redaction(self):
        pattern, replacement = self.REDACTION_PATTERNS[0]
        text = "password: hunter2"
        result = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        assert "[REDACTED]" in result
        assert "hunter2" not in result

    def test_secret_redaction(self):
        pattern, replacement = self.REDACTION_PATTERNS[1]
        text = "secret = abc123xyz"
        result = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        assert "[REDACTED]" in result
        assert "abc123xyz" not in result

    def test_api_key_redaction(self):
        pattern, replacement = self.REDACTION_PATTERNS[2]
        text = "api_key = sk-1234567890abcdef"
        result = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        assert "[REDACTED]" in result
        assert "sk-1234567890abcdef" not in result

    def test_token_redaction(self):
        pattern, replacement = self.REDACTION_PATTERNS[3]
        text = "token = eyJhbGciOiJIUzI1NiJ9"
        result = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        assert "[REDACTED]" in result
        assert "eyJhbGciOiJIUzI1NiJ9" not in result

    def test_db_password_redaction(self):
        pattern, replacement = self.REDACTION_PATTERNS[4]
        text = "DB_PASSWORD=supersecret123"
        result = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        assert "[REDACTED]" in result
        assert "supersecret123" not in result

    def test_aws_secret_redaction(self):
        pattern, replacement = self.REDACTION_PATTERNS[5]
        text = "AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        result = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        assert "[REDACTED]" in result
        assert "wJalrXUtnFEMI" not in result

    def test_private_key_redaction(self):
        pattern, replacement = self.REDACTION_PATTERNS[6]
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        result = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        assert result == "[PRIVATE KEY REDACTED]"
        assert "MIIEowIBAAKCAQEA" not in result

    def test_password_case_insensitive(self):
        pattern, replacement = self.REDACTION_PATTERNS[0]
        text = "PASSWORD = MySecret"
        result = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        assert "[REDACTED]" in result
        assert "MySecret" not in result


# =============================================================================
# CATEGORIZE FILE METHOD
# =============================================================================

class TestCategorizeFile:
    """Test _categorize_file method."""

    def test_vcs_category(self):
        scanner = ConfigExposureScanner(MOCK_SETTINGS)
        sf = VCS_FILES[0]
        assert scanner._categorize_file(sf) == "Version Control"

    def test_env_category(self):
        scanner = ConfigExposureScanner(MOCK_SETTINGS)
        sf = ENV_FILES[0]
        assert scanner._categorize_file(sf) == "Environment Configuration"

    def test_config_category(self):
        scanner = ConfigExposureScanner(MOCK_SETTINGS)
        sf = CONFIG_FILES[0]
        assert scanner._categorize_file(sf) == "Application Configuration"

    def test_backup_category(self):
        scanner = ConfigExposureScanner(MOCK_SETTINGS)
        sf = BACKUP_FILES[0]
        assert scanner._categorize_file(sf) == "Backup / Database Dump"

    def test_build_category(self):
        scanner = ConfigExposureScanner(MOCK_SETTINGS)
        sf = BUILD_FILES[0]
        assert scanner._categorize_file(sf) == "Build Artifacts"

    def test_ide_category(self):
        scanner = ConfigExposureScanner(MOCK_SETTINGS)
        sf = IDE_FILES[0]
        assert scanner._categorize_file(sf) == "IDE / Editor Files"

    def test_debug_category(self):
        scanner = ConfigExposureScanner(MOCK_SETTINGS)
        sf = DEBUG_ENDPOINTS[0]
        assert scanner._categorize_file(sf) == "Debug / Development Endpoint"

    def test_api_docs_category(self):
        scanner = ConfigExposureScanner(MOCK_SETTINGS)
        sf = API_DOCS[0]
        assert scanner._categorize_file(sf) == "API Documentation"

    def test_security_category(self):
        scanner = ConfigExposureScanner(MOCK_SETTINGS)
        sf = SECURITY_FILES[0]
        assert scanner._categorize_file(sf) == "Security / Credentials"

    def test_unknown_category(self):
        scanner = ConfigExposureScanner(MOCK_SETTINGS)
        sf = SensitiveFile(path="/unknown", description="Unknown", severity="LOW")
        assert scanner._categorize_file(sf) == "Other"


# =============================================================================
# EXTRACT PREVIEW METHOD
# =============================================================================

class TestExtractPreview:
    """Test _extract_preview method."""

    def test_truncation_at_500_chars(self):
        scanner = ConfigExposureScanner(MOCK_SETTINGS)
        sf = SensitiveFile(path="/test", description="test", severity="LOW")
        long_content = "A" * 1000
        preview = scanner._extract_preview(long_content, sf)
        assert "... [truncated]" in preview

    def test_no_truncation_short_content(self):
        scanner = ConfigExposureScanner(MOCK_SETTINGS)
        sf = SensitiveFile(path="/test", description="test", severity="LOW")
        short_content = "Hello"
        preview = scanner._extract_preview(short_content, sf)
        assert "... [truncated]" not in preview

    def test_password_is_redacted(self):
        scanner = ConfigExposureScanner(MOCK_SETTINGS)
        sf = SensitiveFile(path="/.env", description="env", severity="CRITICAL")
        content = "password = hunter2\nDB_HOST=localhost"
        preview = scanner._extract_preview(content, sf)
        assert "hunter2" not in preview
        assert "[REDACTED]" in preview

    def test_db_password_is_redacted(self):
        scanner = ConfigExposureScanner(MOCK_SETTINGS)
        sf = SensitiveFile(path="/.env", description="env", severity="CRITICAL")
        content = "DB_PASSWORD=supersecret\nDB_HOST=localhost"
        preview = scanner._extract_preview(content, sf)
        assert "supersecret" not in preview
        assert "[REDACTED]" in preview

    def test_private_key_is_redacted(self):
        scanner = ConfigExposureScanner(MOCK_SETTINGS)
        sf = SensitiveFile(path="/id_rsa", description="key", severity="CRITICAL")
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
        preview = scanner._extract_preview(content, sf)
        assert "MIIE" not in preview
        assert "[PRIVATE KEY REDACTED]" in preview


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_sensitive_file_min_size_zero_default(self):
        sf = SensitiveFile(path="/a", description="a", severity="LOW")
        assert sf.min_size == 0

    def test_sensitive_file_max_size_10mb_default(self):
        sf = SensitiveFile(path="/a", description="a", severity="LOW")
        assert sf.max_size == 10_000_000

    def test_all_categories_represented_in_combined(self):
        """Each category list contributes at least one entry to ALL_SENSITIVE_FILES."""
        categories = [
            VCS_FILES, ENV_FILES, CONFIG_FILES, BACKUP_FILES,
            BUILD_FILES, IDE_FILES, DEBUG_ENDPOINTS, API_DOCS, SECURITY_FILES,
        ]
        for cat in categories:
            assert len(cat) > 0
            assert cat[0] in ALL_SENSITIVE_FILES

    def test_scanner_has_scan_method(self):
        assert hasattr(ConfigExposureScanner, "scan")
        assert callable(getattr(ConfigExposureScanner, "scan"))

    def test_scanner_has_categorize_file_method(self):
        assert hasattr(ConfigExposureScanner, "_categorize_file")

    def test_scanner_has_extract_preview_method(self):
        assert hasattr(ConfigExposureScanner, "_extract_preview")

    def test_scanner_has_check_sensitive_file_method(self):
        assert hasattr(ConfigExposureScanner, "_check_sensitive_file")

    def test_scanner_has_capture_homepage_baseline_method(self):
        assert hasattr(ConfigExposureScanner, "_capture_homepage_baseline")
