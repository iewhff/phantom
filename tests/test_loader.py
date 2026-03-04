"""
Tests for the scanning/loader/ module.

Tests ModuleLoader, LoadStatus, and ModuleLoadResult.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

from scanning.loader import ModuleLoader, ModuleLoadResult, LoadStatus


class TestLoadStatus:
    """Tests for LoadStatus enum."""

    def test_load_status_values(self):
        """Test LoadStatus has expected values."""
        assert LoadStatus.SUCCESS.value == "success"
        assert LoadStatus.CACHED.value == "cached"
        assert LoadStatus.SAFETY_BLOCKED.value == "safety_blocked"
        assert LoadStatus.NOT_FOUND.value == "not_found"
        assert LoadStatus.IMPORT_ERROR.value == "import_error"
        assert LoadStatus.INSTANTIATION_ERROR.value == "instantiation_error"

    def test_load_status_enum_count(self):
        """Test LoadStatus has expected number of values."""
        assert len(LoadStatus) == 6


class TestModuleLoadResult:
    """Tests for ModuleLoadResult dataclass."""

    def test_success_result(self):
        """Test successful load result."""
        result = ModuleLoadResult(
            status=LoadStatus.SUCCESS,
            module=Mock(),
            name="sqli",
            source="registry",
        )
        assert result.success
        assert result.module is not None
        assert result.name == "sqli"
        assert result.source == "registry"
        assert result.error is None

    def test_cached_result(self):
        """Test cached load result."""
        result = ModuleLoadResult(
            status=LoadStatus.CACHED,
            module=Mock(),
            name="xss",
            source="cache",
        )
        assert result.success
        assert result.source == "cache"

    def test_failure_result(self):
        """Test failed load result."""
        result = ModuleLoadResult(
            status=LoadStatus.NOT_FOUND,
            name="unknown_module",
            error="Unknown module: unknown_module",
        )
        assert not result.success
        assert result.module is None
        assert result.error is not None

    def test_safety_blocked_result(self):
        """Test safety blocked result."""
        result = ModuleLoadResult(
            status=LoadStatus.SAFETY_BLOCKED,
            name="smuggling",
            error="Module 'smuggling' requires 'aggressive' mode",
        )
        assert not result.success
        assert "aggressive" in result.error


class TestModuleLoader:
    """Tests for ModuleLoader class."""

    def test_loader_initialization(self):
        """Test ModuleLoader initialization."""
        settings = Mock()
        loader = ModuleLoader(settings, safe_mode="safe")

        assert loader.settings is settings
        assert loader.safe_mode == "safe"
        assert loader.load_count == 0
        assert len(loader.loaded_modules) == 0

    def test_is_loaded_false(self):
        """Test is_loaded returns False for unloaded module."""
        settings = Mock()
        loader = ModuleLoader(settings)
        assert not loader.is_loaded("sqli")

    def test_get_cached_returns_none(self):
        """Test get_cached returns None for uncached module."""
        settings = Mock()
        loader = ModuleLoader(settings)
        assert loader.get_cached("sqli") is None

    def test_load_cached_module(self):
        """Test loading a cached module returns cached result."""
        settings = Mock()
        loader = ModuleLoader(settings)

        # Manually add a module to cache
        mock_module = Mock()
        loader._loaded_modules["test"] = mock_module

        result = loader.load("test")
        assert result.status == LoadStatus.CACHED
        assert result.module is mock_module
        assert result.source == "cache"

    def test_load_unknown_module(self):
        """Test loading unknown module returns NOT_FOUND."""
        settings = Mock()
        loader = ModuleLoader(settings)

        result = loader.load("completely_unknown_module_xyz")
        assert result.status == LoadStatus.NOT_FOUND
        assert not result.success
        assert "Unknown module" in result.error

    def test_safety_check_blocks_aggressive_in_safe_mode(self):
        """Test that aggressive modules are blocked in safe mode."""
        settings = Mock()
        loader = ModuleLoader(settings, safe_mode="safe")

        # Test that smuggling (aggressive) is blocked
        allowed, reason = loader._check_safety("smuggling")
        assert not allowed
        assert "aggressive" in reason

    def test_safety_check_allows_passive_in_safe_mode(self):
        """Test that passive modules are allowed in safe mode."""
        settings = Mock()
        loader = ModuleLoader(settings, safe_mode="safe")

        # Test that headers (passive) is allowed
        allowed, reason = loader._check_safety("headers")
        assert allowed
        assert reason == "OK"

    def test_safety_check_allows_cautious_in_standard_mode(self):
        """Test that cautious modules are allowed in standard mode."""
        settings = Mock()
        loader = ModuleLoader(settings, safe_mode="standard")

        # Test that sqli (cautious) is allowed
        allowed, reason = loader._check_safety("sqli")
        assert allowed
        assert reason == "OK"

    def test_safety_check_allows_aggressive_in_aggressive_mode(self):
        """Test that aggressive modules are allowed in aggressive mode."""
        settings = Mock()
        loader = ModuleLoader(settings, safe_mode="aggressive")

        # Test that smuggling (aggressive) is allowed
        allowed, reason = loader._check_safety("smuggling")
        assert allowed
        assert reason == "OK"

    def test_load_multiple(self):
        """Test loading multiple modules."""
        settings = Mock()
        loader = ModuleLoader(settings, safe_mode="safe")

        # Add some modules to cache for testing
        loader._loaded_modules["headers"] = Mock()
        loader._loaded_modules["ssl"] = Mock()

        results = loader.load_multiple(["headers", "ssl", "unknown_xyz"])

        assert "headers" in results
        assert "ssl" in results
        assert "unknown_xyz" in results
        assert results["headers"].success
        assert results["ssl"].success
        assert not results["unknown_xyz"].success

    def test_get_load_stats(self):
        """Test get_load_stats returns correct counts."""
        settings = Mock()
        loader = ModuleLoader(settings, safe_mode="safe")

        # Simulate some loads
        loader._load_history = [
            ModuleLoadResult(status=LoadStatus.SUCCESS, name="a"),
            ModuleLoadResult(status=LoadStatus.SUCCESS, name="b"),
            ModuleLoadResult(status=LoadStatus.CACHED, name="c"),
            ModuleLoadResult(status=LoadStatus.NOT_FOUND, name="d"),
        ]

        stats = loader.get_load_stats()

        assert stats["success"] == 2
        assert stats["cached"] == 1
        assert stats["not_found"] == 1

    def test_clear_cache(self):
        """Test clear_cache empties loaded modules."""
        settings = Mock()
        loader = ModuleLoader(settings)

        loader._loaded_modules["a"] = Mock()
        loader._loaded_modules["b"] = Mock()

        count = loader.clear_cache()

        assert count == 2
        assert len(loader.loaded_modules) == 0

    def test_update_safe_mode(self):
        """Test update_safe_mode changes the mode."""
        settings = Mock()
        loader = ModuleLoader(settings, safe_mode="safe")

        assert loader.safe_mode == "safe"
        loader.update_safe_mode("aggressive")
        assert loader.safe_mode == "aggressive"


class TestModuleLoaderIntegration:
    """Integration tests for ModuleLoader with FullScanner."""

    def test_fullscanner_uses_module_loader(self):
        """Test that FullScanner correctly uses ModuleLoader."""
        from scanning.full_scanner import FullScanner
        from core.config_manager import Settings

        settings = Settings()
        scanner = FullScanner(settings, safe_mode="safe")

        # Verify ModuleLoader is initialized
        assert hasattr(scanner, '_module_loader')
        assert isinstance(scanner._module_loader, ModuleLoader)
        assert scanner._module_loader.safe_mode == "safe"

    def test_fullscanner_loaded_modules_property(self):
        """Test that loaded_modules property delegates to ModuleLoader."""
        from scanning.full_scanner import FullScanner
        from core.config_manager import Settings

        settings = Settings()
        scanner = FullScanner(settings, safe_mode="safe")

        # Property should return ModuleLoader's dict
        assert scanner.loaded_modules is scanner._module_loader.loaded_modules

    def test_fullscanner_load_module_delegates(self):
        """Test that _load_module delegates to ModuleLoader."""
        from scanning.full_scanner import FullScanner
        from core.config_manager import Settings

        settings = Settings()
        scanner = FullScanner(settings, safe_mode="standard")

        # Load a module
        module = scanner._load_module("headers")

        assert module is not None
        assert "headers" in scanner.loaded_modules
        assert scanner._module_loader.load_count == 1

    def test_fullscanner_safety_blocking(self):
        """Test that safety blocking works through FullScanner."""
        from scanning.full_scanner import FullScanner
        from core.config_manager import Settings

        settings = Settings()
        scanner = FullScanner(settings, safe_mode="safe")

        # Try to load an aggressive module in safe mode
        module = scanner._load_module("smuggling")

        assert module is None  # Should be blocked

    @pytest.mark.asyncio
    async def test_fullscanner_cleanup_delegates(self):
        """Test that _cleanup_modules delegates to ModuleLoader."""
        from scanning.full_scanner import FullScanner
        from core.config_manager import Settings

        settings = Settings()
        scanner = FullScanner(settings, safe_mode="standard")

        # Load a module
        scanner._load_module("headers")
        assert scanner._module_loader.load_count == 1

        # Cleanup
        await scanner._cleanup_modules()

        # Modules should be cleared
        assert len(scanner.loaded_modules) == 0
