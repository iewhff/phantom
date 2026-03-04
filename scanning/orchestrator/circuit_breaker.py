"""
Circuit Breaker - Rate Limiting and Block Protection.

Manages circuit breaker state for concurrent scan coordination:
- Tracks consecutive blocks per target
- Implements exponential backoff on rate limiting
- Provides global coordination between scanner instances

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("phantom")


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior."""
    max_consecutive_blocks: int = 3
    pause_duration: float = 30.0
    max_backoff_multiplier: int = 8

    @classmethod
    def from_settings(cls, settings) -> "CircuitBreakerConfig":
        """Create config from application settings.

        Args:
            settings: Application settings object

        Returns:
            CircuitBreakerConfig with values from settings or defaults
        """
        try:
            cb_config = getattr(settings, 'scan_execution', {})
            if hasattr(cb_config, 'circuit_breaker'):
                cb_config = cb_config.circuit_breaker
            elif isinstance(cb_config, dict):
                cb_config = cb_config.get('circuit_breaker', {})
            else:
                cb_config = {}

            max_consecutive = (
                getattr(cb_config, 'max_consecutive_blocks', None)
                or cb_config.get('max_consecutive_blocks', 3)
            )
            pause_duration = (
                getattr(cb_config, 'pause_duration', None)
                or cb_config.get('pause_duration', 30)
            )
            max_backoff = (
                getattr(cb_config, 'max_backoff_multiplier', None)
                or cb_config.get('max_backoff_multiplier', 8)
            )

            return cls(
                max_consecutive_blocks=max_consecutive,
                pause_duration=pause_duration,
                max_backoff_multiplier=max_backoff,
            )
        except Exception:
            return cls()


@dataclass
class CircuitBreakerState:
    """State for a single circuit breaker instance."""
    consecutive_blocks: int = 0
    is_paused: bool = False
    total_pauses: int = 0
    max_consecutive: int = 3
    pause_duration: float = 30.0


class CircuitBreakerManager:
    """Manages circuit breaker state for multiple targets.

    Provides global coordination between concurrent FullScanner instances
    to prevent overwhelming targets with requests after rate limiting.
    """

    # Class-level state for global coordination
    _global_states: dict[str, CircuitBreakerState] = {}
    _global_lock: Optional[asyncio.Lock] = None

    def __init__(self, config: Optional[CircuitBreakerConfig] = None):
        """Initialize the circuit breaker manager.

        Args:
            config: Optional configuration. Uses defaults if not provided.
        """
        self.config = config or CircuitBreakerConfig()

    @classmethod
    def _get_lock(cls) -> asyncio.Lock:
        """Get or create the global lock."""
        if cls._global_lock is None:
            cls._global_lock = asyncio.Lock()
        return cls._global_lock

    async def get_state(self, target: str) -> CircuitBreakerState:
        """Get or create circuit breaker state for a target.

        Args:
            target: Target URL/host

        Returns:
            CircuitBreakerState for the target
        """
        async with self._get_lock():
            if target not in self._global_states:
                self._global_states[target] = CircuitBreakerState(
                    max_consecutive=self.config.max_consecutive_blocks,
                    pause_duration=self.config.pause_duration,
                )
            return self._global_states[target]

    async def cleanup(self, target: str) -> None:
        """Clean up circuit breaker state for a target.

        Args:
            target: Target URL/host
        """
        async with self._get_lock():
            self._global_states.pop(target, None)

    async def check_and_wait(self, target: str) -> bool:
        """Check circuit breaker and wait if necessary.

        If the circuit breaker is triggered (too many consecutive blocks),
        this method will pause for an exponentially increasing duration.

        Args:
            target: Target URL/host

        Returns:
            True if we had to wait, False otherwise
        """
        state = await self.get_state(target)
        lock = self._get_lock()

        # Calculate max backoff exponent
        max_backoff_exp = (
            int(self.config.max_backoff_multiplier).bit_length() - 1
            if self.config.max_backoff_multiplier > 0
            else 3
        )

        async with lock:
            if state.consecutive_blocks >= state.max_consecutive:
                if not state.is_paused:
                    state.is_paused = True
                    state.total_pauses += 1
                    pause_time = state.pause_duration * (
                        2 ** min(state.total_pauses - 1, max_backoff_exp)
                    )
                    logger.warning(
                        f"Circuit breaker triggered - pausing for {pause_time:.0f}s "
                        f"(attempt {state.total_pauses})"
                    )

        if state.is_paused:
            pause_time = state.pause_duration * (
                2 ** min(state.total_pauses - 1, max_backoff_exp)
            )
            await asyncio.sleep(pause_time)
            async with lock:
                state.consecutive_blocks = 0
                state.is_paused = False
            return True

        return False

    async def record_block(self, target: str) -> None:
        """Record a blocked request.

        Args:
            target: Target URL/host
        """
        state = await self.get_state(target)
        async with self._get_lock():
            state.consecutive_blocks += 1

    async def record_success(self, target: str) -> None:
        """Record a successful request - resets consecutive counter.

        Args:
            target: Target URL/host
        """
        state = await self.get_state(target)
        async with self._get_lock():
            state.consecutive_blocks = 0

    def get_stats(self, target: str) -> dict:
        """Get circuit breaker statistics for a target.

        Args:
            target: Target URL/host

        Returns:
            Dictionary with circuit breaker stats
        """
        state = self._global_states.get(target)
        if state is None:
            return {
                "consecutive_blocks": 0,
                "is_paused": False,
                "total_pauses": 0,
            }
        return {
            "consecutive_blocks": state.consecutive_blocks,
            "is_paused": state.is_paused,
            "total_pauses": state.total_pauses,
        }


# Global instance for singleton access
_circuit_breaker_manager: Optional[CircuitBreakerManager] = None


def get_circuit_breaker_manager(
    config: Optional[CircuitBreakerConfig] = None,
) -> CircuitBreakerManager:
    """Get the global circuit breaker manager.

    Args:
        config: Optional configuration for initialization

    Returns:
        CircuitBreakerManager instance
    """
    global _circuit_breaker_manager
    if _circuit_breaker_manager is None:
        _circuit_breaker_manager = CircuitBreakerManager(config)
    return _circuit_breaker_manager


def reset_circuit_breaker_manager() -> None:
    """Reset the global circuit breaker manager (for testing)."""
    global _circuit_breaker_manager
    _circuit_breaker_manager = None
    CircuitBreakerManager._global_states.clear()
    CircuitBreakerManager._global_lock = None
