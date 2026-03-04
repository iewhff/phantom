"""
Tests for Scanner Groups and Module Registry Integration.

Tests the scanner consolidation architecture:
- ModuleRegistry functionality
- ScannerGroup abstraction
- FullScanner registry integration

Author: PHANTOM AI
Version: 2.0.0
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from scanning.module_registry import (
    ModuleRegistry,
    ModuleCategory,
    ModulePriority,
    ModuleInfo,
    get_module_registry,
)
from scanning.scanner_group import (
    ScannerGroup,
    GroupExecutionMode,
    GroupResult,
    ScannerResult,
    InjectionScannerGroup,
    AuthScannerGroup,
    APIScannerGroup,
    AccessControlScannerGroup,
    InfrastructureScannerGroup,
    BusinessLogicScannerGroup,
    AdvancedScannerGroup,
    get_scanner_group,
)


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE REGISTRY TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestModuleRegistry:
    """Tests for ModuleRegistry."""

    def test_singleton_pattern(self):
        """Test registry is a singleton."""
        registry1 = get_module_registry()
        registry2 = get_module_registry()
        assert registry1 is registry2

    def test_get_all_modules(self):
        """Test getting all registered modules."""
        registry = get_module_registry()
        modules = registry.get_all()

        assert len(modules) > 0
        assert all(isinstance(m, ModuleInfo) for m in modules)

    def test_get_module_by_name(self):
        """Test getting specific module by name."""
        registry = get_module_registry()

        # Get sqli_scanner
        sqli = registry.get("sqli_scanner")
        assert sqli is not None
        assert sqli.name == "sqli_scanner"
        assert sqli.category == ModuleCategory.INJECTION
        assert sqli.priority == ModulePriority.CRITICAL

    def test_get_nonexistent_module(self):
        """Test getting module that doesn't exist."""
        registry = get_module_registry()
        result = registry.get("nonexistent_scanner")
        assert result is None

    def test_get_by_category(self):
        """Test getting modules by category."""
        registry = get_module_registry()

        injection_modules = registry.get_by_category(ModuleCategory.INJECTION)
        assert len(injection_modules) > 0
        assert all(m.category == ModuleCategory.INJECTION for m in injection_modules)

        # Check expected modules are present
        names = [m.name for m in injection_modules]
        assert "sqli_scanner" in names
        assert "xss_scanner" in names

    def test_get_by_priority(self):
        """Test getting modules by priority."""
        registry = get_module_registry()

        critical_modules = registry.get_by_priority(ModulePriority.CRITICAL)
        assert len(critical_modules) > 0
        assert all(m.priority == ModulePriority.CRITICAL for m in critical_modules)

    def test_get_by_tag(self):
        """Test getting modules by tag."""
        registry = get_module_registry()

        owasp_modules = registry.get_by_tag("owasp-top10")
        assert len(owasp_modules) > 0
        assert all("owasp-top10" in m.tags for m in owasp_modules)

    def test_get_ordered(self):
        """Test getting modules ordered by priority."""
        registry = get_module_registry()

        ordered = registry.get_ordered()
        assert len(ordered) > 0

        # Verify ordering (lower priority value = higher priority)
        for i in range(len(ordered) - 1):
            assert ordered[i].priority.value <= ordered[i + 1].priority.value

    def test_get_ordered_exclude_destructive(self):
        """Test excluding destructive modules."""
        registry = get_module_registry()

        safe_modules = registry.get_ordered(exclude_destructive=True)
        all_modules = registry.get_ordered(exclude_destructive=False)

        assert len(safe_modules) <= len(all_modules)
        assert all(not m.is_destructive for m in safe_modules)

    def test_get_requiring_auth(self):
        """Test getting modules that require authentication."""
        registry = get_module_registry()

        auth_required = registry.get_requiring_auth()
        assert len(auth_required) > 0
        assert all(m.requires_auth for m in auth_required)

    def test_module_info_fields(self):
        """Test ModuleInfo has all expected fields."""
        registry = get_module_registry()
        module = registry.get("sqli_scanner")

        assert module is not None
        assert hasattr(module, "name")
        assert hasattr(module, "category")
        assert hasattr(module, "priority")
        assert hasattr(module, "description")
        assert hasattr(module, "module_path")
        assert hasattr(module, "class_name")
        assert hasattr(module, "tags")
        assert hasattr(module, "timeout_multiplier")
        assert hasattr(module, "is_destructive")
        assert hasattr(module, "requires_auth")


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER GROUP TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestScannerGroupAbstraction:
    """Tests for ScannerGroup base functionality."""

    def test_injection_group_creation(self):
        """Test creating InjectionScannerGroup."""
        group = InjectionScannerGroup()

        assert group.name == "InjectionScanners"
        # ScannerGroup doesn't store category as attribute - it's implicit
        assert len(group.get_scanner_names()) > 0

    def test_injection_group_scanners(self):
        """Test InjectionScannerGroup has expected scanners."""
        group = InjectionScannerGroup()
        names = group.get_scanner_names()

        assert "sqli_scanner" in names
        assert "xss_scanner" in names
        assert "cmdi_scanner" in names

    def test_auth_group_scanners(self):
        """Test AuthScannerGroup has expected scanners."""
        group = AuthScannerGroup()
        names = group.get_scanner_names()

        assert "auth_scanner" in names
        assert "jwt_scanner" in names
        assert "oauth_scanner" in names

    def test_api_group_scanners(self):
        """Test APIScannerGroup has expected scanners."""
        group = APIScannerGroup()
        names = group.get_scanner_names()

        assert "api_scanner" in names
        assert "graphql_advanced_scanner" in names

    def test_access_control_group_scanners(self):
        """Test AccessControlScannerGroup has expected scanners."""
        group = AccessControlScannerGroup()
        names = group.get_scanner_names()

        assert "authorization_engine" in names

    def test_infrastructure_group_scanners(self):
        """Test InfrastructureScannerGroup has expected scanners."""
        group = InfrastructureScannerGroup()
        names = group.get_scanner_names()

        assert "ssl_checker" in names

    def test_business_logic_group_scanners(self):
        """Test BusinessLogicScannerGroup has expected scanners."""
        group = BusinessLogicScannerGroup()
        names = group.get_scanner_names()

        assert "business_logic_scanner" in names
        assert "race_condition_scanner" in names

    def test_advanced_group_scanners(self):
        """Test AdvancedScannerGroup has expected scanners."""
        group = AdvancedScannerGroup()
        names = group.get_scanner_names()

        assert "deserialization_scanner" in names
        assert "smuggling_scanner" in names
        assert "cache_poisoning_scanner" in names


class TestScannerGroupFactory:
    """Tests for get_scanner_group factory function."""

    def test_factory_injection(self):
        """Test factory returns InjectionScannerGroup."""
        group = get_scanner_group(ModuleCategory.INJECTION)
        assert isinstance(group, InjectionScannerGroup)

    def test_factory_auth(self):
        """Test factory returns AuthScannerGroup."""
        group = get_scanner_group(ModuleCategory.AUTH)
        assert isinstance(group, AuthScannerGroup)

    def test_factory_api(self):
        """Test factory returns APIScannerGroup."""
        group = get_scanner_group(ModuleCategory.API)
        assert isinstance(group, APIScannerGroup)

    def test_factory_access_control(self):
        """Test factory returns AccessControlScannerGroup."""
        group = get_scanner_group(ModuleCategory.ACCESS_CONTROL)
        assert isinstance(group, AccessControlScannerGroup)

    def test_factory_infrastructure(self):
        """Test factory returns InfrastructureScannerGroup."""
        group = get_scanner_group(ModuleCategory.INFRASTRUCTURE)
        assert isinstance(group, InfrastructureScannerGroup)

    def test_factory_business_logic(self):
        """Test factory returns BusinessLogicScannerGroup."""
        group = get_scanner_group(ModuleCategory.BUSINESS_LOGIC)
        assert isinstance(group, BusinessLogicScannerGroup)

    def test_factory_advanced(self):
        """Test factory returns AdvancedScannerGroup."""
        group = get_scanner_group(ModuleCategory.ADVANCED)
        assert isinstance(group, AdvancedScannerGroup)

    def test_factory_fallback_category(self):
        """Test factory returns CategoryBasedGroup for unmapped categories."""
        from scanning.scanner_group import CategoryBasedGroup

        group = get_scanner_group(ModuleCategory.EXTERNAL)
        # Factory returns a CategoryBasedGroup for unmapped categories
        assert isinstance(group, CategoryBasedGroup)
        assert isinstance(group, ScannerGroup)


class TestGroupExecutionMode:
    """Tests for GroupExecutionMode."""

    def test_default_mode_is_parallel(self):
        """Test default execution mode is PARALLEL."""
        group = InjectionScannerGroup()
        assert group.execution_mode == GroupExecutionMode.PARALLEL

    def test_sequential_mode(self):
        """Test creating group with SEQUENTIAL mode."""
        group = InjectionScannerGroup(execution_mode=GroupExecutionMode.SEQUENTIAL)
        assert group.execution_mode == GroupExecutionMode.SEQUENTIAL

    def test_priority_mode(self):
        """Test creating group with PRIORITY mode."""
        group = InjectionScannerGroup(execution_mode=GroupExecutionMode.PRIORITY)
        assert group.execution_mode == GroupExecutionMode.PRIORITY


class TestGroupResult:
    """Tests for GroupResult dataclass."""

    def test_group_result_creation(self):
        """Test creating GroupResult."""
        from scanning.scanner_group import GroupStatus

        result = GroupResult(
            group_name="TestGroup",
            status=GroupStatus.COMPLETED,
            duration_seconds=10.5,
            scanners_completed=4,
            scanners_failed=1,
            scanners_skipped=0,
            total_findings=5,
        )

        assert result.group_name == "TestGroup"
        assert result.status == GroupStatus.COMPLETED
        assert result.scanners_completed == 4
        assert result.scanners_failed == 1
        assert result.duration_seconds == 10.5

    def test_group_result_success_property(self):
        """Test GroupResult success property."""
        from scanning.scanner_group import GroupStatus

        # Success case
        success_result = GroupResult(
            group_name="TestGroup",
            status=GroupStatus.COMPLETED,
            scanners_completed=5,
            scanners_failed=0,
        )
        assert success_result.success is True

        # Failure case
        failure_result = GroupResult(
            group_name="TestGroup",
            status=GroupStatus.COMPLETED,
            scanners_completed=4,
            scanners_failed=1,
        )
        assert failure_result.success is False


# ═══════════════════════════════════════════════════════════════════════════════
# FULLSCANNER REGISTRY INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestFullScannerRegistryIntegration:
    """Tests for FullScanner's integration with ModuleRegistry."""

    def test_short_to_registry_name_mapping(self):
        """Test SHORT_TO_REGISTRY_NAME mapping exists and is valid."""
        from scanning.full_scanner import FullScanner

        mapping = FullScanner.SHORT_TO_REGISTRY_NAME

        # Check mapping exists and has entries
        assert len(mapping) > 0

        # Check some key mappings
        assert mapping.get("sqli") == "sqli_scanner"
        assert mapping.get("xss") == "xss_scanner"
        assert mapping.get("auth") == "auth_scanner"
        assert mapping.get("api") == "api_scanner"

    def test_short_names_map_to_valid_registry_entries(self):
        """Test most short names map to valid registry entries."""
        from scanning.full_scanner import FullScanner

        registry = get_module_registry()
        mapping = FullScanner.SHORT_TO_REGISTRY_NAME

        valid_count = 0
        invalid_names = []

        for short_name, registry_name in mapping.items():
            if registry_name is None:
                continue  # Some are explicitly None (e.g., cross_surface)

            module_info = registry.get(registry_name)
            if module_info is not None:
                valid_count += 1
            else:
                invalid_names.append((short_name, registry_name))

        # At least 90% should be valid
        total = sum(1 for v in mapping.values() if v is not None)
        valid_ratio = valid_count / total if total > 0 else 0

        assert valid_ratio >= 0.9, f"Only {valid_ratio:.1%} of mappings are valid. Invalid: {invalid_names[:5]}"

    def test_all_modules_covered_by_mapping(self):
        """Test ALL_MODULES keys have corresponding registry mappings."""
        from scanning.full_scanner import FullScanner

        all_modules = FullScanner.ALL_MODULES
        mapping = FullScanner.SHORT_TO_REGISTRY_NAME

        # Most ALL_MODULES keys should have a mapping
        covered = 0
        for short_name in all_modules.keys():
            if short_name in mapping:
                covered += 1

        # At least 80% should be covered
        coverage = covered / len(all_modules)
        assert coverage >= 0.8, f"Only {coverage:.1%} of ALL_MODULES have registry mappings"


class TestFullScannerModuleLoading:
    """Tests for FullScanner._load_module with registry integration."""

    @pytest.fixture
    def mock_settings(self):
        """Create mock settings."""
        settings = MagicMock()
        settings.scanning.modules = {}
        settings.scanning.rate_limit = 100
        settings.scanning.timeout = 30
        settings.timeouts.vuln_scan = 300
        return settings

    def test_get_module_info_with_short_name(self, mock_settings):
        """Test get_module_info resolves short names."""
        from scanning.full_scanner import FullScanner

        scanner = FullScanner(mock_settings, safe_mode="standard")
        info = scanner.get_module_info("sqli")

        assert info is not None
        assert info.name == "sqli_scanner"

    def test_get_module_info_with_registry_name(self, mock_settings):
        """Test get_module_info works with full registry names."""
        from scanning.full_scanner import FullScanner

        scanner = FullScanner(mock_settings, safe_mode="standard")
        info = scanner.get_module_info("sqli_scanner")

        assert info is not None
        assert info.name == "sqli_scanner"

    def test_get_module_info_nonexistent(self, mock_settings):
        """Test get_module_info returns None for unknown modules."""
        from scanning.full_scanner import FullScanner

        scanner = FullScanner(mock_settings, safe_mode="standard")
        info = scanner.get_module_info("nonexistent_module")

        assert info is None

    def test_get_registry_modules(self, mock_settings):
        """Test get_registry_modules returns all modules."""
        from scanning.full_scanner import FullScanner

        scanner = FullScanner(mock_settings, safe_mode="standard")
        modules = scanner.get_registry_modules()

        assert len(modules) > 0
        assert all(isinstance(m, ModuleInfo) for m in modules)

    def test_get_modules_by_category(self, mock_settings):
        """Test get_modules_by_category filters correctly."""
        from scanning.full_scanner import FullScanner

        scanner = FullScanner(mock_settings, safe_mode="standard")
        injection_modules = scanner.get_modules_by_category(ModuleCategory.INJECTION)

        assert len(injection_modules) > 0
        assert all(m.category == ModuleCategory.INJECTION for m in injection_modules)


# ═══════════════════════════════════════════════════════════════════════════════
# ASYNC EXECUTION TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestScannerGroupExecution:
    """Tests for ScannerGroup async execution."""

    @pytest.fixture
    def mock_settings(self):
        """Create mock settings."""
        settings = MagicMock()
        settings.scanning.modules = {}
        settings.scanning.rate_limit = 100
        settings.scanning.timeout = 30
        settings.timeouts.vuln_scan = 300
        return settings

    def test_group_scanner_list(self):
        """Test that scanner groups return valid scanner lists."""
        group = InjectionScannerGroup()
        names = group.get_scanner_names()

        # Should have multiple scanners
        assert len(names) >= 5

        # All should be strings
        assert all(isinstance(n, str) for n in names)

        # Should contain key injection scanners
        assert "sqli_scanner" in names
        assert "xss_scanner" in names

    def test_group_configuration(self):
        """Test group can be configured with different modes."""
        # Test parallel mode
        parallel_group = InjectionScannerGroup(
            execution_mode=GroupExecutionMode.PARALLEL,
            max_concurrent=10,
            timeout_seconds=300.0,
        )
        assert parallel_group.max_concurrent == 10
        assert parallel_group.timeout_seconds == 300.0

        # Test sequential mode
        sequential_group = InjectionScannerGroup(
            execution_mode=GroupExecutionMode.SEQUENTIAL,
        )
        assert sequential_group.execution_mode == GroupExecutionMode.SEQUENTIAL


# ═══════════════════════════════════════════════════════════════════════════════
# IMPORTS AND EXPORTS TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestScanningModuleExports:
    """Tests for scanning module exports."""

    def test_scanning_init_exports_scanner_groups(self):
        """Test scanning/__init__.py exports ScannerGroup classes."""
        from scanning import (
            ScannerGroup,
            GroupExecutionMode,
            GroupResult,
            InjectionScannerGroup,
            AuthScannerGroup,
            APIScannerGroup,
            get_scanner_group,
        )

        # Just verify imports work
        assert ScannerGroup is not None
        assert GroupExecutionMode is not None
        assert GroupResult is not None
        assert InjectionScannerGroup is not None
        assert AuthScannerGroup is not None
        assert APIScannerGroup is not None
        assert get_scanner_group is not None

    def test_scanning_init_exports_module_registry(self):
        """Test scanning/__init__.py exports ModuleRegistry classes."""
        from scanning import (
            ModuleRegistry,
            ModuleCategory,
            ModulePriority,
            ModuleInfo,
            get_module_registry,
        )

        # Just verify imports work
        assert ModuleRegistry is not None
        assert ModuleCategory is not None
        assert ModulePriority is not None
        assert ModuleInfo is not None
        assert get_module_registry is not None
