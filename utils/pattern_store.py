"""
PHANTOM AI - Pattern Store

Persists successful attack patterns across scans for learning.
Each confirmed business logic finding is generalized and stored,
so future scans against similar domains prioritize known-working patterns.

Storage: ~/.phantom/learned_patterns.json
Privacy: Target URLs are SHA256-hashed, only pattern structure is stored.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)

STORE_PATH = Path.home() / ".phantom" / "learned_patterns.json"


@dataclass
class LearnedPattern:
    """A generalized attack pattern learned from a confirmed finding."""
    domain: str                    # "ecommerce"
    pattern_type: str              # "negative_quantity", "price_tampering"
    endpoint_pattern: str          # "/api/*/items" (generalized)
    method: str                    # "PUT"
    field: str                     # "quantity"
    payload: Any                   # -1
    severity: str                  # "CRITICAL"
    first_seen: str = ""           # ISO date
    times_confirmed: int = 1       # How many targets confirmed this
    targets: list[str] = field(default_factory=list)  # SHA256 hashed URLs


class PatternStore:
    """Persist and retrieve successful attack patterns across scans."""

    def __init__(self, store_path: Path | None = None) -> None:
        self._path = store_path or STORE_PATH
        self._patterns: list[dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        """Load patterns from disk."""
        try:
            if self._path.exists():
                data = json.loads(self._path.read_text())
                self._patterns = data.get("patterns", [])
                logger.debug(f"[PatternStore] Loaded {len(self._patterns)} patterns")
        except Exception as e:
            logger.debug(f"[PatternStore] Load failed: {e}")
            self._patterns = []

    def _save(self) -> None:
        """Save patterns to disk."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "version": 1,
                "updated": datetime.now(timezone.utc).isoformat(),
                "patterns": self._patterns,
            }
            self._path.write_text(json.dumps(data, indent=2, default=str))
        except Exception as e:
            logger.debug(f"[PatternStore] Save failed: {e}")

    def record(self, finding: dict[str, Any], domain: str, target_url: str) -> None:
        """Record a successful business logic finding as a learned pattern.

        Args:
            finding: The finding dict from the scanner
            domain: Business domain (e.g., "ecommerce")
            target_url: The target URL (will be hashed for privacy)
        """
        pattern_type = finding.get("name", finding.get("vulnerability_type", "unknown"))
        endpoint = finding.get("matched_at", finding.get("endpoint", ""))
        method = finding.get("method", "POST")
        field_name = finding.get("field", "")
        payload = finding.get("payload", "")
        severity = finding.get("severity", "MEDIUM")

        # Generalize the endpoint pattern (replace IDs with wildcards)
        generalized = self._generalize_endpoint(endpoint)
        target_hash = hashlib.sha256(target_url.encode()).hexdigest()[:16]

        # Check if we already have this pattern
        for existing in self._patterns:
            if (
                existing.get("domain") == domain
                and existing.get("pattern_type") == pattern_type
                and existing.get("endpoint_pattern") == generalized
                and existing.get("field") == field_name
            ):
                # Update existing pattern
                existing["times_confirmed"] = existing.get("times_confirmed", 1) + 1
                targets = existing.get("targets", [])
                if target_hash not in targets:
                    targets.append(target_hash)
                    existing["targets"] = targets
                self._save()
                logger.debug(f"[PatternStore] Updated pattern: {pattern_type} "
                             f"(confirmed {existing['times_confirmed']}x)")
                return

        # New pattern
        pattern = LearnedPattern(
            domain=domain,
            pattern_type=pattern_type,
            endpoint_pattern=generalized,
            method=method,
            field=field_name,
            payload=payload,
            severity=severity,
            first_seen=datetime.now(timezone.utc).isoformat(),
            times_confirmed=1,
            targets=[target_hash],
        )
        self._patterns.append(asdict(pattern))
        self._save()
        logger.debug(f"[PatternStore] Recorded new pattern: {pattern_type} on {generalized}")

    def suggest(self, domain: str) -> list[LearnedPattern]:
        """Get patterns previously successful for this domain type.

        Returns patterns sorted by confirmation count (most confirmed first).
        """
        matches = []
        for p in self._patterns:
            if p.get("domain") == domain:
                matches.append(LearnedPattern(
                    domain=p["domain"],
                    pattern_type=p["pattern_type"],
                    endpoint_pattern=p["endpoint_pattern"],
                    method=p.get("method", "POST"),
                    field=p.get("field", ""),
                    payload=p.get("payload", ""),
                    severity=p.get("severity", "MEDIUM"),
                    first_seen=p.get("first_seen", ""),
                    times_confirmed=p.get("times_confirmed", 1),
                    targets=p.get("targets", []),
                ))

        # Sort by most confirmed
        matches.sort(key=lambda x: x.times_confirmed, reverse=True)
        return matches

    def get_stats(self) -> dict[str, Any]:
        """Return pattern learning statistics."""
        by_domain: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        total_confirmations = 0

        for p in self._patterns:
            domain = p.get("domain", "unknown")
            severity = p.get("severity", "unknown")
            by_domain[domain] = by_domain.get(domain, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1
            total_confirmations += p.get("times_confirmed", 1)

        return {
            "total_patterns": len(self._patterns),
            "total_confirmations": total_confirmations,
            "by_domain": by_domain,
            "by_severity": by_severity,
        }

    @staticmethod
    def _generalize_endpoint(endpoint: str) -> str:
        """Generalize an endpoint by replacing IDs with wildcards.

        /api/users/123/orders → /api/users/*/orders
        /rest/basket/5/coupon → /rest/basket/*/coupon
        """
        from urllib.parse import urlparse
        if endpoint.startswith("http"):
            parsed = urlparse(endpoint)
            path = parsed.path
        else:
            path = endpoint

        # Replace numeric path segments with *
        parts = path.split("/")
        generalized = []
        for part in parts:
            if part and part.isdigit():
                generalized.append("*")
            elif part and re.match(r'^[0-9a-f]{8,}$', part, re.IGNORECASE):
                # UUID-like or hash-like segments
                generalized.append("*")
            else:
                generalized.append(part)

        return "/".join(generalized)
