"""
PHANTOM AI - Smart Retry System (Theme 7)

Implements intelligent retry logic for rate-limited and slow targets:
- Exponential backoff for 429 responses
- Module state preservation for resumption
- Error-rate based retry decisions
- Extended timeout for slow targets

Philosophy: "Primeiro falhanço NÃO significa abandonar. Significa adaptar."

Version: 1.0.0
Date: 2026-02-08
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable, List, Optional, Dict, Set

from utils.logger import get_logger

logger = get_logger(__name__)


class RetryReason(Enum):
    """Reason for retry attempt."""
    RATE_LIMITED = auto()       # 429 response
    TIMEOUT = auto()            # Request timeout
    CONNECTION_ERROR = auto()   # Network error
    WAF_BLOCKED = auto()        # WAF blocked (may need evasion)
    SERVER_ERROR = auto()       # 5xx responses
    HIGH_ERROR_RATE = auto()    # Module had >30% error rate


@dataclass
class RetryableEndpoint:
    """
    Tracks an endpoint that failed with a recoverable error.

    THEME-7: Instead of abandoning after first failure, we queue
    endpoints for smart retry with adjusted parameters.
    """
    endpoint: str
    param: str = ""
    reason: RetryReason = RetryReason.RATE_LIMITED
    attempts: int = 0
    last_attempt: float = 0.0
    next_retry_after: float = 0.0
    original_timeout: float = 10.0
    current_timeout: float = 10.0
    vuln_type: str = ""
    context: Dict[str, Any] = field(default_factory=dict)

    # Backoff parameters
    MAX_ATTEMPTS: int = 5
    BACKOFF_BASE: float = 5.0  # Start with 5s wait
    BACKOFF_MAX: float = 120.0  # Max 2 minutes wait
    TIMEOUT_MULTIPLIER: float = 1.5  # Increase timeout by 50% each retry

    def should_retry(self) -> bool:
        """Check if this endpoint should be retried."""
        if self.attempts >= self.MAX_ATTEMPTS:
            return False

        # Check if enough time has passed
        now = time.time()
        if now < self.next_retry_after:
            return False

        return True

    def calculate_backoff(self) -> float:
        """Calculate exponential backoff time."""
        # Exponential backoff: 5s, 15s, 45s, 90s, 120s (capped)
        backoff = self.BACKOFF_BASE * (3 ** self.attempts)
        return min(backoff, self.BACKOFF_MAX)

    def prepare_retry(self) -> None:
        """Prepare for next retry attempt."""
        self.attempts += 1
        self.last_attempt = time.time()

        # Calculate next retry time
        backoff = self.calculate_backoff()
        self.next_retry_after = self.last_attempt + backoff

        # Increase timeout for slow targets
        self.current_timeout = min(
            self.current_timeout * self.TIMEOUT_MULTIPLIER,
            60.0  # Max 60s timeout
        )

        logger.info(
            f"[THEME-7] Retry #{self.attempts} for {self.endpoint[:50]}... "
            f"Backoff: {backoff:.0f}s, Timeout: {self.current_timeout:.0f}s"
        )

    def get_retry_params(self) -> Dict[str, Any]:
        """Get adjusted parameters for retry."""
        return {
            "timeout": self.current_timeout,
            "attempt": self.attempts,
            "reason": self.reason.name,
        }


@dataclass
class ModuleState:
    """
    Preserves module scan state for resumption.

    THEME-7: When a module is interrupted (rate limited, timeout flood),
    save state so it can resume from where it left off.
    """
    module_name: str
    host: str
    started_at: datetime = field(default_factory=datetime.now)

    # Progress tracking
    endpoints_completed: Set[str] = field(default_factory=set)
    endpoints_pending: List[str] = field(default_factory=list)
    params_completed: Dict[str, Set[str]] = field(default_factory=dict)  # endpoint -> tested params

    # Error tracking
    retryable_endpoints: List[RetryableEndpoint] = field(default_factory=list)
    error_rate: float = 0.0
    consecutive_failures: int = 0

    # Scan configuration at pause time
    current_timeout: float = 10.0
    rate_limit_delay: float = 0.0

    # Findings already collected
    findings_so_far: List[Dict] = field(default_factory=list)

    # Pause reason
    pause_reason: str = ""
    paused_at: Optional[datetime] = None

    def mark_completed(self, endpoint: str, param: str = "") -> None:
        """Mark an endpoint/param as completed."""
        self.endpoints_completed.add(endpoint)
        if param:
            if endpoint not in self.params_completed:
                self.params_completed[endpoint] = set()
            self.params_completed[endpoint].add(param)
        self.consecutive_failures = 0  # Reset on success

    def mark_failed(
        self,
        endpoint: str,
        reason: RetryReason,
        param: str = "",
        vuln_type: str = "",
    ) -> None:
        """Mark an endpoint as failed (for retry)."""
        self.consecutive_failures += 1

        # Check if already queued for retry
        existing = next(
            (r for r in self.retryable_endpoints
             if r.endpoint == endpoint and r.param == param),
            None
        )

        if existing:
            existing.prepare_retry()
        else:
            retryable = RetryableEndpoint(
                endpoint=endpoint,
                param=param,
                reason=reason,
                vuln_type=vuln_type,
                original_timeout=self.current_timeout,
                current_timeout=self.current_timeout,
            )
            self.retryable_endpoints.append(retryable)

    def is_endpoint_done(self, endpoint: str, param: str = "") -> bool:
        """Check if endpoint/param was already tested."""
        if endpoint in self.endpoints_completed:
            if not param:
                return True
            params_done = self.params_completed.get(endpoint, set())
            return param in params_done
        return False

    def should_pause(self) -> tuple[bool, str]:
        """
        Determine if module should pause based on error rate.

        Returns:
            Tuple of (should_pause, reason)
        """
        # Too many consecutive failures
        if self.consecutive_failures >= 10:
            return True, f"10 consecutive failures"

        # High error rate
        if self.error_rate > 0.5:  # >50% failures
            return True, f"High error rate: {self.error_rate*100:.0f}%"

        return False, ""

    def pause(self, reason: str) -> None:
        """Pause module execution."""
        self.pause_reason = reason
        self.paused_at = datetime.now()
        logger.warning(
            f"[THEME-7] Module {self.module_name} PAUSED: {reason}. "
            f"Progress: {len(self.endpoints_completed)} completed, "
            f"{len(self.endpoints_pending)} pending, "
            f"{len(self.retryable_endpoints)} queued for retry."
        )

    def get_pending_retries(self) -> List[RetryableEndpoint]:
        """Get endpoints ready for retry."""
        return [r for r in self.retryable_endpoints if r.should_retry()]

    def get_resumption_summary(self) -> Dict[str, Any]:
        """Get summary for resumption."""
        return {
            "module": self.module_name,
            "host": self.host,
            "completed": len(self.endpoints_completed),
            "pending": len(self.endpoints_pending),
            "retryable": len(self.retryable_endpoints),
            "findings": len(self.findings_so_far),
            "pause_reason": self.pause_reason,
            "paused_at": self.paused_at.isoformat() if self.paused_at else None,
        }


class SmartRetryManager:
    """
    Manages smart retry logic across the scan.

    THEME-7 FIX: Instead of abandoning on first failure:
    1. Queue failed endpoints for retry with backoff
    2. Adjust timeouts for slow targets
    3. Pause modules with high error rates
    4. Resume modules after backoff period
    """

    def __init__(self):
        self._module_states: Dict[str, ModuleState] = {}
        self._global_rate_limit_until: float = 0.0
        self._lock = asyncio.Lock()

        # Statistics
        self.total_retries: int = 0
        self.successful_retries: int = 0
        self.failed_after_retry: int = 0

    def get_or_create_state(self, module_name: str, host: str) -> ModuleState:
        """Get or create module state."""
        key = f"{module_name}:{host}"
        if key not in self._module_states:
            self._module_states[key] = ModuleState(
                module_name=module_name,
                host=host,
            )
        return self._module_states[key]

    def get_state(self, module_name: str, host: str) -> Optional[ModuleState]:
        """Get existing module state if any."""
        key = f"{module_name}:{host}"
        return self._module_states.get(key)

    async def wait_for_rate_limit(self) -> None:
        """Wait if global rate limit is active."""
        now = time.time()
        if now < self._global_rate_limit_until:
            wait_time = self._global_rate_limit_until - now
            logger.info(f"[THEME-7] Waiting {wait_time:.0f}s for rate limit cooldown...")
            await asyncio.sleep(wait_time)

    async def signal_rate_limited(self, domain: str = "default") -> None:
        """Signal that a 429 was received globally."""
        async with self._lock:
            # Global backoff for 30 seconds
            self._global_rate_limit_until = time.time() + 30.0
            logger.warning(f"[THEME-7] Global rate limit triggered for {domain}")

    def should_retry_module(self, module_name: str, host: str) -> tuple[bool, str]:
        """
        Check if a module should be retried.

        Returns:
            Tuple of (should_retry, reason)
        """
        state = self.get_state(module_name, host)
        if not state:
            return False, "No state found"

        # Check if there are pending retries
        pending = state.get_pending_retries()
        if pending:
            return True, f"{len(pending)} endpoints ready for retry"

        # Check if module was paused and backoff period passed
        if state.paused_at:
            pause_duration = (datetime.now() - state.paused_at).total_seconds()
            if pause_duration > 60:  # 1 minute minimum pause
                return True, f"Paused {pause_duration:.0f}s ago, ready to resume"

        return False, "No retries needed"

    def get_modules_for_retry(self) -> List[tuple[str, str, str]]:
        """
        Get all modules that should be retried.

        Returns:
            List of (module_name, host, reason) tuples
        """
        to_retry = []
        for key, state in self._module_states.items():
            should, reason = self.should_retry_module(
                state.module_name, state.host
            )
            if should:
                to_retry.append((state.module_name, state.host, reason))
        return to_retry

    def get_retry_summary(self) -> Dict[str, Any]:
        """Get summary of retry operations."""
        return {
            "total_retries": self.total_retries,
            "successful_retries": self.successful_retries,
            "failed_after_retry": self.failed_after_retry,
            "modules_with_state": len(self._module_states),
            "modules_paused": sum(
                1 for s in self._module_states.values() if s.paused_at
            ),
            "pending_retries": sum(
                len(s.get_pending_retries())
                for s in self._module_states.values()
            ),
        }


# Singleton instance
_retry_manager: Optional[SmartRetryManager] = None


def get_retry_manager() -> SmartRetryManager:
    """Get the singleton retry manager."""
    global _retry_manager
    if _retry_manager is None:
        _retry_manager = SmartRetryManager()
    return _retry_manager


def reset_retry_manager() -> None:
    """Reset the retry manager for new scan."""
    global _retry_manager
    _retry_manager = SmartRetryManager()


# =============================================================================
# HELPER DECORATORS FOR MODULES
# =============================================================================

def with_smart_retry(
    max_attempts: int = 3,
    backoff_base: float = 5.0,
    timeout_multiplier: float = 1.5,
):
    """
    Decorator that adds smart retry to an async function.

    THEME-7: Use this on test methods that might fail due to rate limiting.

    Example:
        @with_smart_retry(max_attempts=3, backoff_base=5.0)
        async def test_endpoint(self, endpoint: str, payload: str) -> Optional[Finding]:
            response = await self.client.get(endpoint, params={"q": payload})
            # ... validation logic ...
    """
    def decorator(func: Callable):
        async def wrapper(*args, **kwargs):
            attempt = 0
            current_timeout = kwargs.get("timeout", 10.0)
            last_error = None

            while attempt < max_attempts:
                try:
                    # Update timeout for retry attempts
                    if attempt > 0:
                        current_timeout = min(
                            current_timeout * timeout_multiplier,
                            60.0
                        )
                        kwargs["timeout"] = current_timeout

                        # Wait with backoff
                        wait_time = backoff_base * (2 ** (attempt - 1))
                        logger.debug(
                            f"[THEME-7] Retry #{attempt}, waiting {wait_time:.0f}s..."
                        )
                        await asyncio.sleep(wait_time)

                    return await func(*args, **kwargs)

                except asyncio.TimeoutError as e:
                    last_error = e
                    attempt += 1
                    logger.debug(
                        f"[THEME-7] Timeout on attempt {attempt}/{max_attempts}"
                    )

                except Exception as e:
                    # Check if it's a 429 or rate limit error
                    status_code = getattr(getattr(e, 'response', None), 'status_code', 0)

                    if status_code == 429:
                        last_error = e
                        attempt += 1
                        # Longer backoff for rate limits
                        wait_time = backoff_base * (3 ** attempt)
                        logger.debug(
                            f"[THEME-7] Rate limited, waiting {wait_time:.0f}s..."
                        )
                        await asyncio.sleep(wait_time)
                    else:
                        # Non-retryable error, re-raise
                        raise

            # All attempts exhausted
            if last_error:
                logger.warning(
                    f"[THEME-7] All {max_attempts} retry attempts exhausted"
                )
            return None

        return wrapper
    return decorator


async def retry_with_backoff(
    coro_func: Callable,
    *args,
    max_attempts: int = 3,
    backoff_base: float = 5.0,
    on_retry: Optional[Callable[[int, Exception], None]] = None,
    **kwargs,
) -> Any:
    """
    Execute a coroutine with smart retry logic.

    THEME-7: Helper function for one-off retries.

    Args:
        coro_func: Async function to call
        *args: Arguments for the function
        max_attempts: Maximum retry attempts
        backoff_base: Base backoff time in seconds
        on_retry: Optional callback when retry occurs
        **kwargs: Keyword arguments for the function

    Returns:
        Result of the coroutine, or None if all attempts fail

    Example:
        result = await retry_with_backoff(
            client.get,
            url,
            timeout=10,
            max_attempts=3,
            backoff_base=5.0,
        )
    """
    attempt = 0
    last_error = None

    while attempt < max_attempts:
        try:
            return await coro_func(*args, **kwargs)

        except (asyncio.TimeoutError, Exception) as e:
            last_error = e
            attempt += 1

            # Check if retryable
            status_code = getattr(getattr(e, 'response', None), 'status_code', 0)
            is_retryable = (
                isinstance(e, asyncio.TimeoutError) or
                status_code in (429, 502, 503, 504)
            )

            if not is_retryable:
                raise

            if attempt < max_attempts:
                # Calculate backoff
                wait_time = backoff_base * (2 ** (attempt - 1))
                if status_code == 429:
                    wait_time *= 2  # Double for rate limits

                if on_retry:
                    on_retry(attempt, e)

                logger.debug(
                    f"[THEME-7] Attempt {attempt}/{max_attempts} failed, "
                    f"waiting {wait_time:.0f}s..."
                )
                await asyncio.sleep(wait_time)

    # All attempts failed
    logger.warning(
        f"[THEME-7] All {max_attempts} attempts failed: {last_error}"
    )
    return None
