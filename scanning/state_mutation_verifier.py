"""
PHANTOM AI - State Mutation Verifier

Philosophy: "O PHANTOM detecta estados inválidos, mas raramente prova consequências
            persistentes. Falta: state mutation + re-check automático"

This module provides a consistent 3-step pattern for proving persistent state changes:
1. Capture baseline (GET before mutation)
2. Execute mutation (POST/PUT/DELETE)
3. Verify persistence (GET after mutation, compare to baseline)

A finding is only marked as "state_persisted=True" when step 3 confirms the change stuck.

IMPORTANT: This is about PROVING impact, not just detecting acceptance.
- 200 OK on mutation request = "Accepted" (not proof)
- Different response on re-check = "Persisted" (proof)
"""

from __future__ import annotations

import hashlib
import json
import re
import ssl
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

import aiohttp

from utils.logger import get_logger

logger = get_logger(__name__)

# Permissive SSL for local/self-signed targets
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


class PersistenceResult(Enum):
    """Result of state persistence verification."""
    NOT_CHECKED = auto()      # Re-check not performed
    NOT_PERSISTED = auto()    # Re-check shows original state (FP likely)
    PARTIAL = auto()          # Re-check shows some change
    PERSISTED = auto()        # Re-check confirms full state change
    RESOURCE_DELETED = auto() # Resource no longer exists (DELETE verified)
    RESOURCE_CREATED = auto() # New resource exists (POST verified)


@dataclass
class StateSnapshot:
    """Snapshot of a resource's state at a point in time."""
    url: str
    status_code: int
    body: str
    body_hash: str
    content_length: int
    # Extracted state indicators
    numeric_values: dict[str, float] = field(default_factory=dict)  # field: value
    string_values: dict[str, str] = field(default_factory=dict)     # field: value
    resource_exists: bool = True

    @classmethod
    def from_response(cls, url: str, status: int, body: str) -> "StateSnapshot":
        """Create snapshot from HTTP response."""
        body_hash = hashlib.md5(body.encode() if isinstance(body, str) else body).hexdigest()

        # Try to extract JSON values for comparison
        numeric_values = {}
        string_values = {}
        try:
            data = json.loads(body) if body.strip().startswith("{") else {}
            cls._extract_values(data, "", numeric_values, string_values)
        except (json.JSONDecodeError, ValueError):
            pass

        return cls(
            url=url,
            status_code=status,
            body=body,
            body_hash=body_hash,
            content_length=len(body),
            numeric_values=numeric_values,
            string_values=string_values,
            resource_exists=status not in (404, 410, 204),
        )

    @staticmethod
    def _extract_values(
        data: Any,
        prefix: str,
        numeric: dict,
        string: dict,
        max_depth: int = 3,
    ) -> None:
        """Recursively extract field values from JSON."""
        if max_depth <= 0:
            return
        if isinstance(data, dict):
            for k, v in data.items():
                key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (int, float)):
                    numeric[key] = v
                elif isinstance(v, str) and len(v) < 200:
                    string[key] = v
                elif isinstance(v, dict):
                    StateSnapshot._extract_values(v, key, numeric, string, max_depth - 1)
                elif isinstance(v, list) and v and isinstance(v[0], dict):
                    StateSnapshot._extract_values(v[0], f"{key}[0]", numeric, string, max_depth - 1)


@dataclass
class MutationVerification:
    """Complete record of a state mutation verification."""
    # Input
    target_url: str
    mutation_method: str  # POST, PUT, DELETE, PATCH
    mutation_payload: Any

    # Snapshots
    baseline: StateSnapshot | None = None
    post_mutation: StateSnapshot | None = None

    # Verification result
    persistence: PersistenceResult = PersistenceResult.NOT_CHECKED
    changes_detected: list[str] = field(default_factory=list)

    # Evidence for reports
    evidence_summary: str = ""
    confidence_boost: float = 0.0  # Extra confidence if persisted

    @property
    def is_proven(self) -> bool:
        """Return True if state change was proven persistent."""
        return self.persistence in (
            PersistenceResult.PERSISTED,
            PersistenceResult.RESOURCE_DELETED,
            PersistenceResult.RESOURCE_CREATED,
        )


class StateMutationVerifier:
    """
    Stateful verification engine that proves persistent consequences.

    Usage:
        verifier = StateMutationVerifier(rate_limiter, auth_headers)

        # 3-step verification
        result = await verifier.verify_mutation(
            url="/api/cart/1",
            method="PUT",
            payload={"quantity": -1},
            baseline_url="/api/cart/1",  # GET this before and after
        )

        if result.is_proven:
            # State change CONFIRMED persistent
            if isinstance(data, dict):
                finding.metadata["state_persisted"] = True
            finding.confidence += result.confidence_boost
    """

    # Fields that indicate meaningful state changes when modified
    STATE_SENSITIVE_FIELDS = [
        # Financial
        "quantity", "qty", "amount", "price", "total", "balance", "credits",
        # User state
        "role", "admin", "is_admin", "permissions", "access_level", "status",
        # Resource state
        "id", "user_id", "owner", "created_at", "updated_at", "deleted",
    ]

    def __init__(
        self,
        rate_limiter: Any | None = None,
        auth_headers: dict[str, str] | None = None,
        timeout: float = 10.0,
        max_requests: int = 5,  # Budget for verification
    ) -> None:
        self._rate_limiter = rate_limiter
        self._auth_headers = auth_headers or {}
        self._timeout = timeout
        self._max_requests = max_requests
        self._requests_used = 0

    @property
    def budget_remaining(self) -> int:
        return max(0, self._max_requests - self._requests_used)

    async def _request(
        self,
        method: str,
        url: str,
        json_data: Any = None,
        data: Any = None,
    ) -> tuple[int, str]:
        """Make HTTP request with rate limiting."""
        if self.budget_remaining <= 0:
            return (0, "")

        if self._rate_limiter:
            try:
                await self._rate_limiter.acquire()
            except Exception as e:
                logger.debug(f"[StateMutationVerifier] Rate limit error: {e}")

        self._requests_used += 1

        headers = dict(self._auth_headers)
        if json_data is not None:
            headers["Content-Type"] = "application/json"

        timeout = aiohttp.ClientTimeout(total=self._timeout)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                kwargs: dict[str, Any] = {"headers": headers, "ssl": _SSL_CTX}
                if json_data is not None:
                    kwargs["json"] = json_data
                if data is not None:
                    kwargs["data"] = data

                async with session.request(method, url, **kwargs) as resp:
                    body = await resp.text()
                    return (resp.status, body)
        except Exception as e:
            logger.debug(f"[StateMutationVerifier] Request failed: {method} {url} — {e}")
            return (0, "")

    async def capture_baseline(self, url: str) -> StateSnapshot | None:
        """Step 1: Capture baseline state before mutation."""
        status, body = await self._request("GET", url)
        if status > 0:
            return StateSnapshot.from_response(url, status, body)
        return None

    async def execute_mutation(
        self,
        url: str,
        method: str,
        payload: Any = None,
    ) -> tuple[int, str]:
        """Step 2: Execute the mutation."""
        if method.upper() in ("POST", "PUT", "PATCH"):
            return await self._request(method.upper(), url, json_data=payload)
        elif method.upper() == "DELETE":
            return await self._request("DELETE", url)
        else:
            return await self._request(method.upper(), url)

    async def verify_persistence(
        self,
        url: str,
        baseline: StateSnapshot,
    ) -> tuple[StateSnapshot | None, PersistenceResult, list[str]]:
        """Step 3: Re-check and compare to baseline."""
        status, body = await self._request("GET", url)
        if status == 0:
            return (None, PersistenceResult.NOT_CHECKED, [])

        post = StateSnapshot.from_response(url, status, body)
        changes: list[str] = []

        # Case 1: Resource deleted
        if not post.resource_exists and baseline.resource_exists:
            return (post, PersistenceResult.RESOURCE_DELETED, ["Resource deleted (404/410)"])

        # Case 2: Resource created (for POST)
        if post.resource_exists and not baseline.resource_exists:
            return (post, PersistenceResult.RESOURCE_CREATED, ["Resource created"])

        # Case 3: Same response = NOT persisted (likely caught by server validation)
        if post.body_hash == baseline.body_hash:
            return (post, PersistenceResult.NOT_PERSISTED, ["Response identical to baseline"])

        # Case 4: Check specific field changes
        for field_name in self.STATE_SENSITIVE_FIELDS:
            # Check numeric fields
            if field_name in baseline.numeric_values and field_name in post.numeric_values:
                old_val = baseline.numeric_values[field_name]
                new_val = post.numeric_values[field_name]
                if old_val != new_val:
                    changes.append(f"{field_name}: {old_val} → {new_val}")

            # Check in nested keys (e.g., "cart.quantity")
            for key in baseline.numeric_values:
                if field_name in key.lower():
                    if key in post.numeric_values:
                        old_val = baseline.numeric_values[key]
                        new_val = post.numeric_values[key]
                        if old_val != new_val:
                            changes.append(f"{key}: {old_val} → {new_val}")

        # If specific field changes detected, it's verified
        if changes:
            return (post, PersistenceResult.PERSISTED, changes)

        # Case 5: Different response but no specific field changes detected
        # Could be timestamps, etc. — mark as partial
        if post.content_length != baseline.content_length:
            changes.append(f"Content length: {baseline.content_length} → {post.content_length}")
            return (post, PersistenceResult.PARTIAL, changes)

        return (post, PersistenceResult.NOT_PERSISTED, ["No meaningful changes detected"])

    async def verify_mutation(
        self,
        url: str,
        method: str,
        payload: Any = None,
        baseline_url: str | None = None,
    ) -> MutationVerification:
        """
        Complete 3-step verification: baseline → mutate → verify.

        Args:
            url: URL to mutate
            method: HTTP method (POST, PUT, DELETE, PATCH)
            payload: Mutation payload (for POST/PUT/PATCH)
            baseline_url: URL to check for state changes (defaults to url)

        Returns:
            MutationVerification with persistence result and evidence
        """
        result = MutationVerification(
            target_url=url,
            mutation_method=method,
            mutation_payload=payload,
        )

        check_url = baseline_url or url

        # Step 1: Capture baseline
        result.baseline = await self.capture_baseline(check_url)
        if not result.baseline:
            result.evidence_summary = "Could not capture baseline state"
            return result

        # Step 2: Execute mutation
        mut_status, mut_body = await self.execute_mutation(url, method, payload)
        if mut_status == 0:
            result.evidence_summary = "Mutation request failed"
            return result

        # If mutation returned error, state likely not changed
        if mut_status >= 400:
            result.persistence = PersistenceResult.NOT_PERSISTED
            result.evidence_summary = f"Mutation rejected (status {mut_status})"
            return result

        # Step 3: Verify persistence
        result.post_mutation, result.persistence, result.changes_detected = (
            await self.verify_persistence(check_url, result.baseline)
        )

        # Generate evidence summary
        if result.is_proven:
            if result.changes_detected:
                result.evidence_summary = f"STATE PERSISTED: {', '.join(result.changes_detected[:3])}"
            else:
                result.evidence_summary = f"STATE PERSISTED ({result.persistence.name})"
            result.confidence_boost = 15.0  # +15% confidence for proven persistence
        elif result.persistence == PersistenceResult.PARTIAL:
            result.evidence_summary = "Partial state change detected"
            result.confidence_boost = 5.0
        else:
            result.evidence_summary = "State change NOT persisted (server rejected)"
            result.confidence_boost = -10.0  # Reduce confidence for unverified

        logger.debug(
            f"[StateMutationVerifier] {method} {url}: "
            f"{result.persistence.name} — {result.evidence_summary}"
        )

        return result


# =============================================================================
# Convenience functions for common verification patterns
# =============================================================================

async def verify_cart_mutation(
    verifier: StateMutationVerifier,
    cart_url: str,
    item_id: str,
    new_quantity: int,
) -> MutationVerification:
    """Verify cart quantity mutation persists."""
    return await verifier.verify_mutation(
        url=f"{cart_url}/{item_id}",
        method="PUT",
        payload={"quantity": new_quantity},
        baseline_url=cart_url,
    )


async def verify_delete_persists(
    verifier: StateMutationVerifier,
    resource_url: str,
) -> MutationVerification:
    """Verify DELETE actually removes the resource."""
    return await verifier.verify_mutation(
        url=resource_url,
        method="DELETE",
    )


async def verify_role_escalation(
    verifier: StateMutationVerifier,
    profile_url: str,
    new_role: str,
) -> MutationVerification:
    """Verify role escalation persists."""
    return await verifier.verify_mutation(
        url=profile_url,
        method="PUT",
        payload={"role": new_role},
    )


# =============================================================================
# Integration helper for existing scanners
# =============================================================================

def create_verifier_for_scanner(
    rate_limiter: Any = None,
    auth_headers: dict[str, str] | None = None,
    max_requests: int = 3,
) -> StateMutationVerifier:
    """Create a verifier instance for use in scanner modules."""
    return StateMutationVerifier(
        rate_limiter=rate_limiter,
        auth_headers=auth_headers,
        max_requests=max_requests,
    )
