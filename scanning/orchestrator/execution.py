"""
Execution Configuration - Module Execution Settings.

Handles configuration for module execution:
- Timeout settings (heavy vs normal modules)
- Concurrency configuration
- Jitter/delay settings for OPSEC
- Module categorization by complexity

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

import random
import logging
from dataclasses import dataclass, field
from typing import Optional, Set

logger = logging.getLogger("phantom")


# Module categories by execution characteristics
HEAVY_MODULES: Set[str] = {
    'sqli', 'xss', 'dom_xss', 'nosql', 'cmdi', 'lfi', 'ssrf',
    'auth', 'ssti', 'graphql', 'api', 'smuggling', 'business'
}

BROWSER_MODULES: Set[str] = {'dom_xss', 'spa_crawler'}

STATEFUL_MODULES: Set[str] = {
    'business_logic', 'auth', 'session_abuse', 'race_condition'
}

EXTERNAL_MODULES: Set[str] = {'nuclei', 'linux_tools', 'cms'}


@dataclass
class TimeoutConfig:
    """Configuration for module timeouts."""
    heavy_timeout: float = 900.0
    normal_timeout: float = 600.0
    browser_timeout: float = 600.0
    stateful_timeout: float = 600.0
    external_timeout: float = 900.0

    @classmethod
    def from_settings(cls, settings) -> "TimeoutConfig":
        """Create config from application settings.

        Args:
            settings: Application settings object

        Returns:
            TimeoutConfig with values from settings or defaults
        """
        try:
            return cls(
                heavy_timeout=getattr(settings.timeouts, 'module_heavy', 900),
                normal_timeout=getattr(settings.timeouts, 'module_normal', 600),
            )
        except AttributeError:
            return cls()

    def get_timeout_for_module(self, module_name: str) -> float:
        """Get appropriate timeout for a module.

        Args:
            module_name: Name of the module

        Returns:
            Timeout in seconds
        """
        if module_name in HEAVY_MODULES:
            return self.heavy_timeout
        if module_name in BROWSER_MODULES:
            return self.browser_timeout
        if module_name in STATEFUL_MODULES:
            return self.stateful_timeout
        if module_name in EXTERNAL_MODULES:
            return self.external_timeout
        return self.normal_timeout


@dataclass
class JitterConfig:
    """Configuration for request jitter (OPSEC)."""
    min_delay: float = 0.1
    max_delay: float = 0.5
    gaussian_sigma: float = 0.2

    @classmethod
    def from_settings(cls, settings) -> "JitterConfig":
        """Create config from application settings.

        Args:
            settings: Application settings object

        Returns:
            JitterConfig with values from settings or defaults
        """
        try:
            exec_config = getattr(settings, 'scan_execution', {})
            if hasattr(exec_config, 'jitter'):
                jitter_config = exec_config.jitter
            elif isinstance(exec_config, dict):
                jitter_config = exec_config.get('jitter', {})
            else:
                jitter_config = {}

            min_delay = (
                getattr(jitter_config, 'min', None)
                or jitter_config.get('min', 0.1)
            )
            max_delay = (
                getattr(jitter_config, 'max', None)
                or jitter_config.get('max', 0.5)
            )
            sigma = (
                getattr(jitter_config, 'gaussian_sigma', None)
                or jitter_config.get('gaussian_sigma', 0.2)
            )

            return cls(
                min_delay=min_delay,
                max_delay=max_delay,
                gaussian_sigma=sigma,
            )
        except Exception:
            return cls()

    def get_delay(self) -> float:
        """Get a random delay with jitter.

        Returns:
            Delay in seconds with gaussian jitter applied
        """
        base_delay = random.uniform(self.min_delay, self.max_delay)
        jitter = random.gauss(0, base_delay * self.gaussian_sigma)
        return max(0.05, base_delay + jitter)


@dataclass
class ConcurrencyConfig:
    """Configuration for concurrency control."""
    default_concurrency: int = 10
    waf_reduced_concurrency: int = 2
    rate_limited_concurrency: int = 3

    @classmethod
    def from_settings(cls, settings) -> "ConcurrencyConfig":
        """Create config from application settings.

        Args:
            settings: Application settings object

        Returns:
            ConcurrencyConfig with values from settings or defaults
        """
        try:
            exec_config = getattr(settings, 'scan_execution', {})
            if hasattr(exec_config, 'concurrency'):
                conc_config = exec_config.concurrency
            elif isinstance(exec_config, dict):
                conc_config = exec_config.get('concurrency', {})
            else:
                conc_config = {}

            default_conc = (
                getattr(conc_config, 'default', None)
                or conc_config.get('default', 10)
            )
            waf_conc = (
                getattr(conc_config, 'waf_reduced', None)
                or conc_config.get('waf_reduced', 2)
            )
            rate_limited_conc = (
                getattr(conc_config, 'rate_limited', None)
                or conc_config.get('rate_limited', 3)
            )

            return cls(
                default_concurrency=default_conc,
                waf_reduced_concurrency=waf_conc,
                rate_limited_concurrency=rate_limited_conc,
            )
        except Exception:
            return cls()

    def get_effective_concurrency(
        self,
        base_concurrency: int,
        waf_detected: bool = False,
        rate_limited: bool = False,
    ) -> int:
        """Get effective concurrency based on conditions.

        Args:
            base_concurrency: Requested concurrency
            waf_detected: Whether WAF was detected
            rate_limited: Whether rate limiting was detected

        Returns:
            Adjusted concurrency value
        """
        if waf_detected:
            return max(self.waf_reduced_concurrency, base_concurrency // 2)
        if rate_limited:
            return max(self.rate_limited_concurrency, base_concurrency // 3)
        return base_concurrency


@dataclass
class ExecutionConfig:
    """Combined execution configuration."""
    timeout: TimeoutConfig = field(default_factory=TimeoutConfig)
    jitter: JitterConfig = field(default_factory=JitterConfig)
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)

    @classmethod
    def from_settings(cls, settings) -> "ExecutionConfig":
        """Create combined config from application settings.

        Args:
            settings: Application settings object

        Returns:
            ExecutionConfig with all sub-configs populated
        """
        return cls(
            timeout=TimeoutConfig.from_settings(settings),
            jitter=JitterConfig.from_settings(settings),
            concurrency=ConcurrencyConfig.from_settings(settings),
        )


def is_heavy_module(name: str) -> bool:
    """Check if a module is categorized as heavy.

    Args:
        name: Module name

    Returns:
        True if module requires longer timeouts
    """
    return name in HEAVY_MODULES


def is_browser_module(name: str) -> bool:
    """Check if a module requires browser execution.

    Args:
        name: Module name

    Returns:
        True if module requires browser
    """
    return name in BROWSER_MODULES


def is_stateful_module(name: str) -> bool:
    """Check if a module is stateful.

    Args:
        name: Module name

    Returns:
        True if module maintains state across requests
    """
    return name in STATEFUL_MODULES


def is_external_module(name: str) -> bool:
    """Check if a module calls external tools.

    Args:
        name: Module name

    Returns:
        True if module uses external CLI tools
    """
    return name in EXTERNAL_MODULES
