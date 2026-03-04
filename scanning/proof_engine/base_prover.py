"""
PHANTOM AI - Base Prover

Abstract base class for all vulnerability provers.
Provides rate-limited HTTP requests, budget management, and utility methods.
Extracted from scanning/exploit_proof_engine.py.
"""

from __future__ import annotations

import asyncio
import re
import ssl
from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import urlparse

import aiohttp

from scanning.proof_engine.models import DEFAULT_REQUEST_TIMEOUT, ProofResult
from utils.logger import get_logger

logger = get_logger(__name__)

# Permissive SSL for local/self-signed targets
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


class BaseProver(ABC):
    """Base class for all vulnerability provers."""

    def __init__(
        self,
        auth_context: Any,
        rate_limiter: Any,
        endpoint_map: Any,
        limits: dict,
        all_findings: list[dict],
        exhaustion_tracker: Any = None,
        focus_lock: Any = None,
        current_finding_id: str = "",
        type_cache: dict[str, Any] | None = None,
    ) -> None:
        self._auth_context = auth_context
        self._rate_limiter = rate_limiter
        self._endpoint_map = endpoint_map
        self._limits = limits
        self._all_findings = all_findings
        self._requests_used = 0
        self._exhaustion_tracker = exhaustion_tracker
        self._focus_lock = focus_lock
        self._current_finding_id = current_finding_id
        self._type_cache = type_cache or {}
        self._working_technique: str = ""

    def _record_vector_attempt(
        self,
        vector: str,
        succeeded: bool,
        payload: str = "",
        endpoint: str = "",
    ) -> None:
        """Report a vector attempt to exhaustion tracker and focus lock."""
        if self._exhaustion_tracker and self._current_finding_id:
            try:
                self._exhaustion_tracker.record_attempt(
                    finding_id=self._current_finding_id,
                    vector=vector,
                    succeeded=succeeded,
                    payload=payload[:200] if payload else "",
                )
            except Exception as e:
                logger.debug(f"[ProofEngine] Exhaustion tracking error: {e}")

        if self._focus_lock and hasattr(self._focus_lock, 'record_vector_attempt'):
            try:
                self._focus_lock.record_vector_attempt(
                    vector=vector,
                    succeeded=succeeded,
                    module=self.__class__.__name__,
                    endpoint=endpoint,
                )
            except Exception as e:
                logger.debug(f"[ProofEngine] Focus lock tracking error: {e}")

    @property
    def budget_remaining(self) -> int:
        return max(0, self._limits["max_requests"] - self._requests_used)

    def can_spend_budget(self, requests_needed: int = 1) -> bool:
        """Explicit budget check helper."""
        return self.budget_remaining >= requests_needed

    @property
    def _auth_headers(self) -> dict[str, str]:
        if self._auth_context and hasattr(self._auth_context, 'auth_headers'):
            return self._auth_context.auth_headers
        return {}

    async def _safe_request(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        json_data: Any = None,
        data: Any = None,
        params: dict | None = None,
        timeout: float = DEFAULT_REQUEST_TIMEOUT,
    ) -> tuple[int, str, dict[str, str]]:
        """Make a rate-limited HTTP request via aiohttp.

        Returns: (status_code, body_text, response_headers)
        """
        if self.budget_remaining <= 0:
            return (0, "", {})

        # Block write operations if not allowed
        if method.upper() in ("POST", "PUT", "DELETE", "PATCH"):
            if not self._limits.get("allow_write", False):
                return (0, "", {})

        # Rate limit
        if self._rate_limiter:
            try:
                await self._rate_limiter.acquire()
            except Exception as e:
                logger.debug(f"[ProofEngine] Rate limiter error (continuing): {e}")

        self._requests_used += 1

        req_headers = dict(self._auth_headers)
        if headers:
            req_headers.update(headers)

        req_timeout = aiohttp.ClientTimeout(total=timeout)

        try:
            async with aiohttp.ClientSession(timeout=req_timeout) as session:
                kwargs: dict[str, Any] = {"headers": req_headers, "ssl": _SSL_CTX}
                if json_data is not None:
                    kwargs["json"] = json_data
                if data is not None:
                    kwargs["data"] = data
                if params is not None:
                    kwargs["params"] = params

                async with session.request(method, url, **kwargs) as resp:
                    body = await resp.text()
                    resp_headers = {k: v for k, v in resp.headers.items()}
                    return (resp.status, body, resp_headers)
        except asyncio.TimeoutError:
            logger.debug(f"[ProofEngine] Request timeout: {method} {url}")
            return (0, "", {})
        except aiohttp.ClientError as e:
            logger.debug(f"[ProofEngine] Client error: {method} {url} — {type(e).__name__}: {e}")
            return (0, "", {})
        except OSError as e:
            logger.debug(f"[ProofEngine] Network error: {method} {url} — {type(e).__name__}: {e}")
            return (0, "", {})

    @abstractmethod
    async def prove(self, finding: dict) -> ProofResult:
        """Prove the 4 questions for a finding."""
        ...

    def _parse_matched_at(self, finding: dict) -> tuple[str, str, str]:
        """Parse matched_at into (url, param_type, param_name)."""
        matched = finding.get("matched_at") or ""
        metadata = finding.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        param_type = metadata.get("param_type", "")
        param_name = metadata.get("parameter", "")

        if matched:
            m = re.match(r'^(.*?)\s*\((\w+):\s*(\w+)\)\s*$', matched)
            if m:
                url = m.group(1).strip()
                param_type = m.group(2)
                param_name = m.group(3)
            else:
                url = matched
        else:
            url = metadata.get("url", "")

        if url and not url.startswith("http"):
            host = finding.get("host", "")
            if host:
                url = f"{host.rstrip('/')}/{url.lstrip('/')}"

        return url, param_type, param_name

    def _find_related_findings(self, types: list[str]) -> list[dict]:
        """Find other findings of given types from the scan results."""
        return [f for f in self._all_findings if f.get("type") in types]

    def _resolve_host(self) -> str:
        """Resolve the target host from findings or metadata."""
        for f in self._all_findings:
            host = f.get("host")
            if host:
                return host
            url = (f.get("metadata") or {}).get("url", "")
            if url and url.startswith("http"):
                parsed = urlparse(url)
                return f"{parsed.scheme}://{parsed.netloc}"
        return ""
