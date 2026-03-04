"""
PHANTOM AI - Deterministic Scan Mode (Theme 8 Fix)

Provides controllable randomness for reproducible scans.

Philosophy: "Non-determinism is NOT a coding error. It is an emergent property
of concurrent, adaptive offensive systems. The issue is not that randomness
exists — it's that it is not **controllable** when reproducibility matters."

When DETERMINISTIC_MODE is enabled:
- All random operations use a target-based seed
- Module execution order is predictable
- Payload selections are reproducible
- Same scan on same target = same results

Usage:
    from scanning.determinism import (
        is_deterministic_mode,
        get_deterministic_random,
        set_scan_target,
        get_seeded_shuffle,
    )

    # Check mode
    if is_deterministic_mode():
        rng = get_deterministic_random("payload_encoder")
        choice = rng.choice([True, False])
    else:
        import random
        choice = random.choice([True, False])

Version: 1.0.0
Date: 2026-02-08
"""

from __future__ import annotations

import hashlib
import os
import random
import threading
from dataclasses import dataclass, field
from typing import Any, List, Optional, TypeVar

from utils.logger import get_logger

logger = get_logger(__name__)

T = TypeVar("T")


# =============================================================================
# CONFIGURATION
# =============================================================================

def is_deterministic_mode() -> bool:
    """
    Check if deterministic mode is enabled.

    Controlled by:
    - Environment variable PHANTOM_DETERMINISTIC=1
    - CLI flag --deterministic (sets the env var)
    """
    return os.environ.get("PHANTOM_DETERMINISTIC", "").lower() in ("1", "true", "yes")


def enable_deterministic_mode() -> None:
    """Enable deterministic mode for this process."""
    os.environ["PHANTOM_DETERMINISTIC"] = "1"
    logger.info("[THEME-8] Deterministic mode ENABLED — scans will be reproducible")


def disable_deterministic_mode() -> None:
    """Disable deterministic mode for this process."""
    os.environ.pop("PHANTOM_DETERMINISTIC", None)
    logger.info("[THEME-8] Deterministic mode DISABLED — scans will use true randomness")


# =============================================================================
# SEED GENERATION
# =============================================================================

def get_target_seed(target: str) -> int:
    """
    Generate a deterministic seed from the target URL.

    The seed is derived from a SHA-256 hash of the target, ensuring:
    - Same target always produces same seed
    - Different targets produce different seeds
    - Seed is uniformly distributed in 32-bit range

    Args:
        target: The scan target URL (e.g., "https://example.com")

    Returns:
        Integer seed for random.seed()
    """
    # Use first 8 hex chars (32 bits) of SHA-256 hash
    hash_hex = hashlib.sha256(target.encode()).hexdigest()[:8]
    return int(hash_hex, 16)


def get_component_seed(target: str, component: str, index: int = 0) -> int:
    """
    Generate a seed for a specific component of the scan.

    Each component (module, encoder, etc.) gets a unique but deterministic seed
    derived from the target + component name + optional index.

    Args:
        target: The scan target URL
        component: Component name (e.g., "payload_encoder", "race_scanner")
        index: Optional index for array operations

    Returns:
        Integer seed for this specific component
    """
    combined = f"{target}:{component}:{index}"
    hash_hex = hashlib.sha256(combined.encode()).hexdigest()[:8]
    return int(hash_hex, 16)


# =============================================================================
# DETERMINISTIC CONTEXT
# =============================================================================

@dataclass
class DeterministicContext:
    """
    Thread-safe context for deterministic operations.

    Stores the current target and provides seeded random instances
    for each component.

    Usage:
        ctx = DeterministicContext()
        ctx.set_target("https://example.com")

        rng = ctx.get_random("payload_encoder")
        choice = rng.choice([True, False])  # Deterministic!
    """
    target: str = ""
    base_seed: int = 0
    _random_instances: dict = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def set_target(self, target: str) -> None:
        """Set the target and compute base seed."""
        with self._lock:
            self.target = target
            self.base_seed = get_target_seed(target)
            self._random_instances.clear()  # Reset all instances

            if is_deterministic_mode():
                logger.info(
                    f"[THEME-8] Deterministic context set for {target[:50]}... "
                    f"(seed={self.base_seed})"
                )

    def get_random(self, component: str, index: int = 0) -> random.Random:
        """
        Get a seeded Random instance for a component.

        Each component gets its own Random instance with a unique seed,
        ensuring operations within one component don't affect others.

        Args:
            component: Component name (e.g., "xss_scanner", "payload_encoder")
            index: Optional index for multiple instances

        Returns:
            random.Random instance seeded for this component
        """
        key = f"{component}:{index}"

        with self._lock:
            if key not in self._random_instances:
                seed = get_component_seed(self.target, component, index)
                rng = random.Random(seed)
                self._random_instances[key] = rng

            return self._random_instances[key]

    def reset(self) -> None:
        """Reset context for a new scan."""
        with self._lock:
            self.target = ""
            self.base_seed = 0
            self._random_instances.clear()


# Global context instance
_context: Optional[DeterministicContext] = None
_context_lock = threading.Lock()


def get_deterministic_context() -> DeterministicContext:
    """Get the global deterministic context."""
    global _context
    with _context_lock:
        if _context is None:
            _context = DeterministicContext()
        return _context


def set_scan_target(target: str) -> None:
    """
    Set the current scan target for deterministic operations.

    Call this at the start of each scan to initialize seeds.

    Args:
        target: The scan target URL
    """
    get_deterministic_context().set_target(target)


def reset_deterministic_context() -> None:
    """Reset the deterministic context for a new scan."""
    get_deterministic_context().reset()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def get_deterministic_random(component: str, index: int = 0) -> random.Random:
    """
    Get a deterministic random instance for a component.

    If deterministic mode is disabled, returns the global random module
    (which maintains non-deterministic behavior).

    Args:
        component: Component name
        index: Optional index

    Returns:
        random.Random instance (seeded if deterministic mode enabled)

    Example:
        rng = get_deterministic_random("payload_encoder")
        if rng.choice([True, False]):
            # This choice is deterministic when mode is enabled
            pass
    """
    if is_deterministic_mode():
        return get_deterministic_context().get_random(component, index)
    else:
        # Return a wrapper that uses global random
        # This maintains the same interface but uses true randomness
        return random  # type: ignore


def deterministic_shuffle(items: List[T], component: str, index: int = 0) -> List[T]:
    """
    Shuffle a list deterministically.

    Args:
        items: List to shuffle (modified in place AND returned)
        component: Component name for seeding
        index: Optional index

    Returns:
        The shuffled list (same object as input)

    Example:
        payloads = ["a", "b", "c"]
        deterministic_shuffle(payloads, "xss_scanner")
        # payloads is now shuffled deterministically
    """
    if is_deterministic_mode():
        rng = get_deterministic_context().get_random(component, index)
        rng.shuffle(items)
    else:
        random.shuffle(items)
    return items


def deterministic_choice(options: List[T], component: str, index: int = 0) -> T:
    """
    Make a deterministic choice from a list.

    Args:
        options: List to choose from
        component: Component name for seeding
        index: Optional index

    Returns:
        Chosen element

    Example:
        encoding = deterministic_choice(["url", "hex", "base64"], "encoder")
    """
    if is_deterministic_mode():
        rng = get_deterministic_context().get_random(component, index)
        return rng.choice(options)
    else:
        return random.choice(options)


def deterministic_sample(population: List[T], k: int, component: str, index: int = 0) -> List[T]:
    """
    Take a deterministic sample from a list.

    Args:
        population: List to sample from
        k: Number of elements to sample
        component: Component name for seeding
        index: Optional index

    Returns:
        List of k sampled elements
    """
    if is_deterministic_mode():
        rng = get_deterministic_context().get_random(component, index)
        return rng.sample(population, min(k, len(population)))
    else:
        return random.sample(population, min(k, len(population)))


def deterministic_choices(
    population: List[T],
    k: int,
    component: str,
    index: int = 0,
    weights: Optional[List[float]] = None,
) -> List[T]:
    """
    Make k deterministic choices with replacement.

    Args:
        population: List to choose from
        k: Number of choices
        component: Component name for seeding
        index: Optional index
        weights: Optional weights for each element

    Returns:
        List of k chosen elements (may have duplicates)
    """
    if is_deterministic_mode():
        rng = get_deterministic_context().get_random(component, index)
        if weights:
            return rng.choices(population, weights=weights, k=k)
        return rng.choices(population, k=k)
    else:
        if weights:
            return random.choices(population, weights=weights, k=k)
        return random.choices(population, k=k)


def deterministic_string(
    length: int,
    component: str,
    index: int = 0,
    alphabet: str = "abcdefghijklmnopqrstuvwxyz0123456789",
) -> str:
    """
    Generate a deterministic random string.

    Args:
        length: Length of string
        component: Component name for seeding
        index: Optional index
        alphabet: Characters to use

    Returns:
        Random string of specified length

    Example:
        suffix = deterministic_string(6, "auth_context")
        # suffix is always the same for the same target
    """
    if is_deterministic_mode():
        rng = get_deterministic_context().get_random(component, index)
        return "".join(rng.choices(alphabet, k=length))
    else:
        return "".join(random.choices(alphabet, k=length))


def deterministic_int(
    low: int,
    high: int,
    component: str,
    index: int = 0,
) -> int:
    """
    Generate a deterministic random integer.

    Args:
        low: Lower bound (inclusive)
        high: Upper bound (inclusive)
        component: Component name for seeding
        index: Optional index

    Returns:
        Random integer in [low, high]
    """
    if is_deterministic_mode():
        rng = get_deterministic_context().get_random(component, index)
        return rng.randint(low, high)
    else:
        return random.randint(low, high)


# =============================================================================
# MODULE ORDERING
# =============================================================================

def get_deterministic_module_order(modules: List[str], target: str) -> List[str]:
    """
    Get a deterministic but varied module execution order.

    In deterministic mode, modules are ordered by a hash of (target + module_name).
    This ensures:
    - Same order for same target
    - Different order for different targets (helps find timing-dependent bugs)
    - Order is not alphabetical (avoids systematic biases)

    In non-deterministic mode, returns modules in original order.

    Args:
        modules: List of module names
        target: Scan target URL

    Returns:
        Ordered list of module names
    """
    if not is_deterministic_mode():
        return modules

    def module_sort_key(module: str) -> int:
        combined = f"{target}:{module}"
        return int(hashlib.sha256(combined.encode()).hexdigest()[:8], 16)

    ordered = sorted(modules, key=module_sort_key)

    logger.debug(
        f"[THEME-8] Deterministic module order: {ordered[:5]}... "
        f"(total: {len(ordered)})"
    )

    return ordered


# =============================================================================
# SCAN SESSION MANAGEMENT
# =============================================================================

def init_deterministic_scan(target: str) -> dict:
    """
    Initialize deterministic context for a new scan.

    Call this at the start of FullScanner.run_scan().

    Args:
        target: The scan target URL

    Returns:
        Dict with scan determinism info for logging
    """
    reset_deterministic_context()
    set_scan_target(target)

    info = {
        "deterministic_mode": is_deterministic_mode(),
        "target": target,
        "base_seed": get_deterministic_context().base_seed if is_deterministic_mode() else None,
    }

    if is_deterministic_mode():
        logger.info(
            f"[THEME-8] Initialized deterministic scan: "
            f"target={target[:50]}..., seed={info['base_seed']}"
        )

    return info


def finalize_deterministic_scan() -> dict:
    """
    Finalize deterministic context after scan.

    Returns:
        Dict with determinism stats for reporting
    """
    ctx = get_deterministic_context()

    stats = {
        "deterministic_mode": is_deterministic_mode(),
        "target": ctx.target,
        "base_seed": ctx.base_seed,
        "components_seeded": len(ctx._random_instances),
    }

    if is_deterministic_mode():
        logger.info(
            f"[THEME-8] Finalized deterministic scan: "
            f"{stats['components_seeded']} components used seeded randomness"
        )

    reset_deterministic_context()

    return stats
