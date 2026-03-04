"""
Tests for the scanning configuration module.

Tests the extracted configuration from scanning/config/.
"""

import pytest

from scanning.config import (
    ALL_MODULES,
    SHORT_TO_REGISTRY_NAME,
    SAFETY_HIERARCHY,
    MODULE_SAFETY_LEVELS,
    CATEGORIES,
    get_module_path,
    get_registry_name,
    get_module_safety_level,
    is_safe_for_mode,
    get_category_modules,
    get_all_category_names,
)
from scanning.config.modules import get_all_module_names
from scanning.config.safety import get_modules_for_mode, get_safety_index
from scanning.config.categories import is_valid_category, expand_modules


class TestAllModules:
    """Test ALL_MODULES configuration."""

    def test_all_modules_not_empty(self):
        """ALL_MODULES should contain modules."""
        assert len(ALL_MODULES) > 0
        assert len(ALL_MODULES) >= 70  # We have ~78 modules

    def test_all_modules_have_valid_paths(self):
        """Each module should have a valid class path."""
        for name, path in ALL_MODULES.items():
            assert "." in path, f"Module {name} has invalid path: {path}"
            assert path.startswith("scanning."), f"Module {name} path should start with scanning."

    def test_core_modules_present(self):
        """Core security modules should be present."""
        core_modules = ["sqli", "xss", "cmdi", "ssrf", "lfi", "auth", "api"]
        for module in core_modules:
            assert module in ALL_MODULES, f"Core module {module} missing"

    def test_get_module_path(self):
        """get_module_path should return correct path."""
        assert get_module_path("sqli") == "scanning.modules.sqli_scanner.SQLiScanner"
        assert get_module_path("nonexistent") is None

    def test_get_all_module_names(self):
        """get_all_module_names should return all short names."""
        names = get_all_module_names()
        assert "sqli" in names
        assert "xss" in names
        assert len(names) == len(ALL_MODULES)


class TestShortToRegistryName:
    """Test SHORT_TO_REGISTRY_NAME mapping."""

    def test_mapping_not_empty(self):
        """Mapping should contain entries."""
        assert len(SHORT_TO_REGISTRY_NAME) > 0

    def test_sqli_mapping(self):
        """SQLi should map to sqli_scanner."""
        assert SHORT_TO_REGISTRY_NAME["sqli"] == "sqli_scanner"

    def test_xss_mapping(self):
        """XSS should map to xss_scanner."""
        assert SHORT_TO_REGISTRY_NAME["xss"] == "xss_scanner"

    def test_get_registry_name(self):
        """get_registry_name should return correct mapping."""
        assert get_registry_name("sqli") == "sqli_scanner"
        assert get_registry_name("nonexistent") is None

    def test_cross_surface_is_none(self):
        """cross_surface should map to None (handled separately)."""
        assert SHORT_TO_REGISTRY_NAME.get("cross_surface") is None


class TestSafetyHierarchy:
    """Test SAFETY_HIERARCHY configuration."""

    def test_hierarchy_order(self):
        """Safety hierarchy should be in correct order."""
        expected = ["passive", "safe", "cautious", "standard", "aggressive", "unrestricted"]
        assert SAFETY_HIERARCHY == expected

    def test_hierarchy_length(self):
        """Safety hierarchy should have 6 levels."""
        assert len(SAFETY_HIERARCHY) == 6

    def test_get_safety_index(self):
        """get_safety_index should return correct indices."""
        assert get_safety_index("passive") == 0
        assert get_safety_index("aggressive") == 4
        assert get_safety_index("unknown") == 0  # Default


class TestModuleSafetyLevels:
    """Test MODULE_SAFETY_LEVELS configuration."""

    def test_safety_levels_not_empty(self):
        """Safety levels should contain entries."""
        assert len(MODULE_SAFETY_LEVELS) > 0
        assert len(MODULE_SAFETY_LEVELS) >= 80  # We have ~82 entries

    def test_passive_modules(self):
        """Certain modules should be passive."""
        passive_modules = ["headers", "ssl", "cors", "backend", "cms"]
        for module in passive_modules:
            assert MODULE_SAFETY_LEVELS.get(module) == "passive", f"{module} should be passive"

    def test_cautious_modules(self):
        """Injection modules should be cautious."""
        cautious_modules = ["sqli", "xss", "cmdi", "lfi", "nosql"]
        for module in cautious_modules:
            assert MODULE_SAFETY_LEVELS.get(module) == "cautious", f"{module} should be cautious"

    def test_aggressive_modules(self):
        """Dangerous modules should be aggressive."""
        aggressive_modules = ["smuggling", "cache", "creative_exploiter"]
        for module in aggressive_modules:
            assert MODULE_SAFETY_LEVELS.get(module) == "aggressive", f"{module} should be aggressive"

    def test_get_module_safety_level(self):
        """get_module_safety_level should return correct level."""
        assert get_module_safety_level("sqli") == "cautious"
        assert get_module_safety_level("smuggling") == "aggressive"
        assert get_module_safety_level("unknown") == "passive"  # Default


class TestIsSafeForMode:
    """Test is_safe_for_mode function."""

    def test_passive_always_safe(self):
        """Passive modules should run in any mode."""
        assert is_safe_for_mode("headers", "passive") is True
        assert is_safe_for_mode("headers", "cautious") is True
        assert is_safe_for_mode("headers", "aggressive") is True

    def test_cautious_needs_cautious_or_higher(self):
        """Cautious modules need cautious mode or higher."""
        assert is_safe_for_mode("sqli", "passive") is False
        assert is_safe_for_mode("sqli", "safe") is False
        assert is_safe_for_mode("sqli", "cautious") is True
        assert is_safe_for_mode("sqli", "standard") is True
        assert is_safe_for_mode("sqli", "aggressive") is True

    def test_aggressive_needs_aggressive(self):
        """Aggressive modules need aggressive mode."""
        assert is_safe_for_mode("smuggling", "passive") is False
        assert is_safe_for_mode("smuggling", "cautious") is False
        assert is_safe_for_mode("smuggling", "standard") is False
        assert is_safe_for_mode("smuggling", "aggressive") is True

    def test_get_modules_for_mode(self):
        """get_modules_for_mode should filter correctly."""
        passive_mods = get_modules_for_mode("passive")
        cautious_mods = get_modules_for_mode("cautious")
        aggressive_mods = get_modules_for_mode("aggressive")

        assert len(passive_mods) < len(cautious_mods)
        assert len(cautious_mods) < len(aggressive_mods)
        assert "headers" in passive_mods
        assert "sqli" not in passive_mods
        assert "sqli" in cautious_mods


class TestCategories:
    """Test CATEGORIES configuration."""

    def test_categories_not_empty(self):
        """Categories should contain presets."""
        assert len(CATEGORIES) > 0
        assert len(CATEGORIES) >= 10

    def test_required_categories(self):
        """Required categories should exist."""
        required = ["quick", "web", "api", "injection", "auth", "bounty", "full"]
        for cat in required:
            assert cat in CATEGORIES, f"Category {cat} missing"

    def test_quick_category(self):
        """Quick category should have fast modules."""
        quick = CATEGORIES["quick"]
        assert "headers" in quick
        assert "ssl" in quick
        assert "sqli" not in quick  # Too slow for quick

    def test_bounty_category(self):
        """Bounty category should have high-value modules."""
        bounty = CATEGORIES["bounty"]
        assert "idor" in bounty
        assert "sqli" in bounty
        assert "xss" in bounty
        assert "business" in bounty

    def test_full_category(self):
        """Full category should have all modules."""
        full = CATEGORIES["full"]
        assert len(full) == len(ALL_MODULES)

    def test_get_category_modules(self):
        """get_category_modules should return correct modules."""
        quick = get_category_modules("quick")
        assert "headers" in quick
        assert get_category_modules("nonexistent") == []

    def test_get_all_category_names(self):
        """get_all_category_names should return all names."""
        names = get_all_category_names()
        assert "quick" in names
        assert "bounty" in names
        assert len(names) == len(CATEGORIES)

    def test_is_valid_category(self):
        """is_valid_category should validate correctly."""
        assert is_valid_category("quick") is True
        assert is_valid_category("bounty") is True
        assert is_valid_category("nonexistent") is False

    def test_expand_modules(self):
        """expand_modules should expand category names."""
        expanded = expand_modules(["quick", "sqli"])
        assert "headers" in expanded  # From quick
        assert "ssl" in expanded      # From quick
        assert "sqli" in expanded     # Direct


class TestFullScannerIntegration:
    """Test that FullScanner uses the config correctly."""

    def test_fullscanner_uses_config(self):
        """FullScanner should reference config module."""
        from scanning.full_scanner import FullScanner

        # Class attributes should reference config
        assert FullScanner.ALL_MODULES is ALL_MODULES
        assert FullScanner.SHORT_TO_REGISTRY_NAME is SHORT_TO_REGISTRY_NAME
        assert FullScanner.SAFETY_HIERARCHY is SAFETY_HIERARCHY
        assert FullScanner.MODULE_SAFETY_LEVELS is MODULE_SAFETY_LEVELS
        assert FullScanner.CATEGORIES is CATEGORIES

    def test_fullscanner_module_count(self):
        """FullScanner should have same module count as config."""
        from scanning.full_scanner import FullScanner

        assert len(FullScanner.ALL_MODULES) == len(ALL_MODULES)
        assert len(FullScanner.CATEGORIES) == len(CATEGORIES)
