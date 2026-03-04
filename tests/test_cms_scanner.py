"""
Tests for scanning/modules/cms_scanner.py

Covers:
- CMSScanner class identity (name, subclass)
- CMS_SIGNATURES dict structure and content (5 CMS keys)
- WP_VULNS dict structure and content (6 keys)
- WordPress-specific paths and vulnerability entries
"""

import pytest
from scanning.modules.cms_scanner import CMSScanner
from scanning.vuln_scanner import ScanModule


# =============================================================================
# CLASS IDENTITY
# =============================================================================

class TestCMSScannerIdentity:
    """Test CMSScanner class basics."""

    def test_name(self):
        assert CMSScanner.name == "cms_scanner"

    def test_is_scan_module_subclass(self):
        assert issubclass(CMSScanner, ScanModule)


# =============================================================================
# CMS_SIGNATURES STRUCTURE
# =============================================================================

class TestCMSSignaturesStructure:
    """Test CMS_SIGNATURES dict has correct CMS keys and inner structure."""

    def test_has_five_cms_keys(self):
        assert len(CMSScanner.CMS_SIGNATURES) == 5

    def test_has_wordpress(self):
        assert "wordpress" in CMSScanner.CMS_SIGNATURES

    def test_has_joomla(self):
        assert "joomla" in CMSScanner.CMS_SIGNATURES

    def test_has_drupal(self):
        assert "drupal" in CMSScanner.CMS_SIGNATURES

    def test_has_magento(self):
        assert "magento" in CMSScanner.CMS_SIGNATURES

    def test_has_shopify(self):
        assert "shopify" in CMSScanner.CMS_SIGNATURES

    @pytest.mark.parametrize("cms_key", ["wordpress", "joomla", "drupal", "magento", "shopify"])
    def test_signature_has_paths_key(self, cms_key):
        assert "paths" in CMSScanner.CMS_SIGNATURES[cms_key]

    @pytest.mark.parametrize("cms_key", ["wordpress", "joomla", "drupal", "magento", "shopify"])
    def test_signature_has_meta_key(self, cms_key):
        assert "meta" in CMSScanner.CMS_SIGNATURES[cms_key]

    @pytest.mark.parametrize("cms_key", ["wordpress", "joomla", "drupal", "magento", "shopify"])
    def test_signature_has_headers_key(self, cms_key):
        assert "headers" in CMSScanner.CMS_SIGNATURES[cms_key]

    @pytest.mark.parametrize("cms_key", ["wordpress", "joomla", "drupal", "magento", "shopify"])
    def test_paths_is_list(self, cms_key):
        assert isinstance(CMSScanner.CMS_SIGNATURES[cms_key]["paths"], list)

    @pytest.mark.parametrize("cms_key", ["wordpress", "joomla", "drupal", "magento", "shopify"])
    def test_meta_is_list(self, cms_key):
        assert isinstance(CMSScanner.CMS_SIGNATURES[cms_key]["meta"], list)

    @pytest.mark.parametrize("cms_key", ["wordpress", "joomla", "drupal", "magento", "shopify"])
    def test_headers_is_list(self, cms_key):
        assert isinstance(CMSScanner.CMS_SIGNATURES[cms_key]["headers"], list)


# =============================================================================
# WORDPRESS SIGNATURES
# =============================================================================

class TestWordPressSignatures:
    """Test WordPress-specific entries in CMS_SIGNATURES."""

    @pytest.fixture
    def wp_paths(self):
        return CMSScanner.CMS_SIGNATURES["wordpress"]["paths"]

    def test_wp_paths_count(self, wp_paths):
        assert len(wp_paths) == 5

    def test_wp_login_path(self, wp_paths):
        assert "/wp-login.php" in wp_paths

    def test_wp_admin_path(self, wp_paths):
        assert "/wp-admin/" in wp_paths

    def test_wp_content_path(self, wp_paths):
        assert "/wp-content/" in wp_paths

    def test_xmlrpc_path(self, wp_paths):
        assert "/xmlrpc.php" in wp_paths

    def test_wp_includes_path(self, wp_paths):
        assert "/wp-includes/" in wp_paths

    def test_wp_meta_not_empty(self):
        assert len(CMSScanner.CMS_SIGNATURES["wordpress"]["meta"]) > 0

    def test_wp_headers_not_empty(self):
        assert len(CMSScanner.CMS_SIGNATURES["wordpress"]["headers"]) > 0


# =============================================================================
# WP_VULNS STRUCTURE
# =============================================================================

class TestWPVulnsStructure:
    """Test WP_VULNS dict has correct keys and counts."""

    def test_has_six_keys(self):
        assert len(CMSScanner.WP_VULNS) == 6

    def test_has_user_enumeration(self):
        assert "user_enumeration" in CMSScanner.WP_VULNS

    def test_has_xmlrpc(self):
        assert "xmlrpc" in CMSScanner.WP_VULNS

    def test_has_readme(self):
        assert "readme" in CMSScanner.WP_VULNS

    def test_has_debug_log(self):
        assert "debug_log" in CMSScanner.WP_VULNS

    def test_has_uploads_listing(self):
        assert "uploads_listing" in CMSScanner.WP_VULNS

    def test_has_config_backup(self):
        assert "config_backup" in CMSScanner.WP_VULNS


# =============================================================================
# WP_VULNS — user_enumeration
# =============================================================================

class TestWPVulnsUserEnumeration:
    """Test WP_VULNS user_enumeration entry."""

    @pytest.fixture
    def user_enum(self):
        return CMSScanner.WP_VULNS["user_enumeration"]

    def test_is_list(self, user_enum):
        assert isinstance(user_enum, list)

    def test_has_three_paths(self, user_enum):
        assert len(user_enum) == 3

    def test_has_author_param(self, user_enum):
        assert "/?author=1" in user_enum

    def test_has_wp_json_users(self, user_enum):
        assert "/wp-json/wp/v2/users" in user_enum

    def test_has_wp_json_users_paged(self, user_enum):
        assert "/wp-json/wp/v2/users/?per_page=100" in user_enum


# =============================================================================
# WP_VULNS — scalar entries
# =============================================================================

class TestWPVulnsScalarEntries:
    """Test WP_VULNS scalar (string) entries."""

    def test_xmlrpc_value(self):
        assert CMSScanner.WP_VULNS["xmlrpc"] == "/xmlrpc.php"

    def test_readme_value(self):
        assert CMSScanner.WP_VULNS["readme"] == "/readme.html"

    def test_debug_log_value(self):
        assert CMSScanner.WP_VULNS["debug_log"] == "/wp-content/debug.log"

    def test_uploads_listing_value(self):
        assert CMSScanner.WP_VULNS["uploads_listing"] == "/wp-content/uploads/"


# =============================================================================
# WP_VULNS — config_backup
# =============================================================================

class TestWPVulnsConfigBackup:
    """Test WP_VULNS config_backup entry."""

    @pytest.fixture
    def config_backup(self):
        return CMSScanner.WP_VULNS["config_backup"]

    def test_is_list(self, config_backup):
        assert isinstance(config_backup, list)

    def test_has_five_items(self, config_backup):
        assert len(config_backup) == 5

    def test_has_bak(self, config_backup):
        assert "/wp-config.php.bak" in config_backup

    def test_has_old(self, config_backup):
        assert "/wp-config.php.old" in config_backup

    def test_has_tilde(self, config_backup):
        assert "/wp-config.php~" in config_backup

    def test_has_config_bak(self, config_backup):
        assert "/wp-config.bak" in config_backup

    def test_has_config_old(self, config_backup):
        assert "/wp-config.old" in config_backup
