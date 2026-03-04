"""
Tests for scanning/modules/dir_scanner.py

Covers:
- DirectoryScanner class attributes
- DIRECTORIES constant
- SENSITIVE_FILES constant
- BACKUP_EXTENSIONS constant
"""

import pytest
from scanning.modules.dir_scanner import DirectoryScanner


# =============================================================================
# CLASS ATTRIBUTES
# =============================================================================

class TestDirectoryScannerClass:
    def test_name(self):
        assert DirectoryScanner.name == "directory_scanner"

    def test_is_scan_module(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(DirectoryScanner, ScanModule)


# =============================================================================
# DIRECTORIES CONSTANT
# =============================================================================

class TestDirectories:
    def test_not_empty(self):
        assert len(DirectoryScanner.DIRECTORIES) > 0

    # Admin panels
    def test_has_admin(self):
        assert "admin/" in DirectoryScanner.DIRECTORIES

    def test_has_administrator(self):
        assert "administrator/" in DirectoryScanner.DIRECTORIES

    def test_has_wp_admin(self):
        assert "wp-admin/" in DirectoryScanner.DIRECTORIES

    def test_has_phpmyadmin(self):
        assert "phpmyadmin/" in DirectoryScanner.DIRECTORIES

    def test_has_cpanel(self):
        assert "cpanel/" in DirectoryScanner.DIRECTORIES

    # API endpoints
    def test_has_api(self):
        assert "api/" in DirectoryScanner.DIRECTORIES

    def test_has_api_v1(self):
        assert "api/v1/" in DirectoryScanner.DIRECTORIES

    def test_has_graphql(self):
        assert "graphql/" in DirectoryScanner.DIRECTORIES

    def test_has_swagger(self):
        assert "swagger/" in DirectoryScanner.DIRECTORIES

    # Config and backup
    def test_has_config(self):
        assert "config/" in DirectoryScanner.DIRECTORIES

    def test_has_backup(self):
        assert "backup/" in DirectoryScanner.DIRECTORIES

    def test_has_temp(self):
        assert "temp/" in DirectoryScanner.DIRECTORIES

    # Version control
    def test_has_git(self):
        assert ".git/" in DirectoryScanner.DIRECTORIES

    def test_has_svn(self):
        assert ".svn/" in DirectoryScanner.DIRECTORIES

    def test_has_hg(self):
        assert ".hg/" in DirectoryScanner.DIRECTORIES

    # Server
    def test_has_cgi_bin(self):
        assert "cgi-bin/" in DirectoryScanner.DIRECTORIES

    def test_has_logs(self):
        assert "logs/" in DirectoryScanner.DIRECTORIES

    # CMS specific
    def test_has_wp_content(self):
        assert "wp-content/" in DirectoryScanner.DIRECTORIES

    def test_has_plugins(self):
        assert "plugins/" in DirectoryScanner.DIRECTORIES

    # Common
    def test_has_uploads(self):
        assert "uploads/" in DirectoryScanner.DIRECTORIES

    def test_has_static(self):
        assert "static/" in DirectoryScanner.DIRECTORIES

    def test_has_vendor(self):
        assert "vendor/" in DirectoryScanner.DIRECTORIES

    def test_has_node_modules(self):
        assert "node_modules/" in DirectoryScanner.DIRECTORIES

    def test_all_are_strings(self):
        for d in DirectoryScanner.DIRECTORIES:
            assert isinstance(d, str)


# =============================================================================
# SENSITIVE FILES CONSTANT
# =============================================================================

class TestSensitiveFiles:
    def test_not_empty(self):
        assert len(DirectoryScanner.SENSITIVE_FILES) > 0

    # Config files
    def test_has_env(self):
        assert ".env" in DirectoryScanner.SENSITIVE_FILES

    def test_has_env_local(self):
        assert ".env.local" in DirectoryScanner.SENSITIVE_FILES

    def test_has_env_production(self):
        assert ".env.production" in DirectoryScanner.SENSITIVE_FILES

    def test_has_wp_config(self):
        assert "wp-config.php" in DirectoryScanner.SENSITIVE_FILES

    def test_has_web_config(self):
        assert "web.config" in DirectoryScanner.SENSITIVE_FILES

    def test_has_config_php(self):
        assert "config.php" in DirectoryScanner.SENSITIVE_FILES

    def test_has_settings_py(self):
        assert "settings.py" in DirectoryScanner.SENSITIVE_FILES

    def test_has_database_yml(self):
        assert "database.yml" in DirectoryScanner.SENSITIVE_FILES

    # Backup files
    def test_has_backup_sql(self):
        assert "backup.sql" in DirectoryScanner.SENSITIVE_FILES

    def test_has_dump_sql(self):
        assert "dump.sql" in DirectoryScanner.SENSITIVE_FILES

    def test_has_backup_zip(self):
        assert "backup.zip" in DirectoryScanner.SENSITIVE_FILES

    # Log files
    def test_has_error_log(self):
        assert "error.log" in DirectoryScanner.SENSITIVE_FILES

    def test_has_access_log(self):
        assert "access.log" in DirectoryScanner.SENSITIVE_FILES

    # Version control
    def test_has_git_config(self):
        assert ".git/config" in DirectoryScanner.SENSITIVE_FILES

    def test_has_git_head(self):
        assert ".git/HEAD" in DirectoryScanner.SENSITIVE_FILES

    # Server files
    def test_has_phpinfo(self):
        assert "phpinfo.php" in DirectoryScanner.SENSITIVE_FILES

    def test_has_htaccess(self):
        assert ".htaccess" in DirectoryScanner.SENSITIVE_FILES

    def test_has_htpasswd(self):
        assert ".htpasswd" in DirectoryScanner.SENSITIVE_FILES

    def test_has_robots(self):
        assert "robots.txt" in DirectoryScanner.SENSITIVE_FILES

    def test_has_sitemap(self):
        assert "sitemap.xml" in DirectoryScanner.SENSITIVE_FILES

    # Credentials
    def test_has_id_rsa(self):
        assert "id_rsa" in DirectoryScanner.SENSITIVE_FILES

    def test_has_credentials_xml(self):
        assert "credentials.xml" in DirectoryScanner.SENSITIVE_FILES

    def test_has_secrets_yml(self):
        assert "secrets.yml" in DirectoryScanner.SENSITIVE_FILES

    def test_all_are_strings(self):
        for f in DirectoryScanner.SENSITIVE_FILES:
            assert isinstance(f, str)


# =============================================================================
# BACKUP EXTENSIONS
# =============================================================================

class TestBackupExtensions:
    def test_not_empty(self):
        assert len(DirectoryScanner.BACKUP_EXTENSIONS) > 0

    def test_has_bak(self):
        assert ".bak" in DirectoryScanner.BACKUP_EXTENSIONS

    def test_has_backup(self):
        assert ".backup" in DirectoryScanner.BACKUP_EXTENSIONS

    def test_has_old(self):
        assert ".old" in DirectoryScanner.BACKUP_EXTENSIONS

    def test_has_orig(self):
        assert ".orig" in DirectoryScanner.BACKUP_EXTENSIONS

    def test_has_swp(self):
        assert ".swp" in DirectoryScanner.BACKUP_EXTENSIONS

    def test_has_tilde(self):
        assert "~" in DirectoryScanner.BACKUP_EXTENSIONS

    def test_has_tmp(self):
        assert ".tmp" in DirectoryScanner.BACKUP_EXTENSIONS

    def test_all_are_strings(self):
        for ext in DirectoryScanner.BACKUP_EXTENSIONS:
            assert isinstance(ext, str)


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    def test_no_duplicate_directories(self):
        assert len(DirectoryScanner.DIRECTORIES) == len(set(DirectoryScanner.DIRECTORIES))

    def test_no_duplicate_sensitive_files(self):
        assert len(DirectoryScanner.SENSITIVE_FILES) == len(set(DirectoryScanner.SENSITIVE_FILES))

    def test_no_duplicate_backup_extensions(self):
        assert len(DirectoryScanner.BACKUP_EXTENSIONS) == len(set(DirectoryScanner.BACKUP_EXTENSIONS))

    def test_directory_count(self):
        assert len(DirectoryScanner.DIRECTORIES) >= 40

    def test_sensitive_files_count(self):
        assert len(DirectoryScanner.SENSITIVE_FILES) >= 30

    def test_backup_extensions_count(self):
        assert len(DirectoryScanner.BACKUP_EXTENSIONS) >= 8
