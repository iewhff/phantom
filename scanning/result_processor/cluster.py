"""
Root-Cause Clustering Engine — Groups findings sharing the same root cause.

Runs as Phase 4.54 in the postprocessing pipeline, AFTER post-amplification
dedup (4.53).  Annotates each finding with ``metadata["cluster"]`` containing
cluster_id, root_cause description, representative flag, and cluster-level
severity / confidence.

This is **additive**: no findings are removed or modified (except metadata
enrichment).  Dedup removes exact duplicates; clustering groups conceptually
related findings that survived dedup.

Time-window note: clustering runs within a single scan session, so all
findings are temporally correlated by definition.
"""

from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

from .deduplicate import (
    HOST_ONLY_DEDUP_TYPES,
    HTTP_METHOD_AGNOSTIC_TYPES,
    PARAM_BASED_TYPES,
    TYPE_NORMALIZATION,
)

logger = logging.getLogger("phantom")

# ═══════════════════════════════════════════════════════════════════════════════
# Severity helpers
# ═══════════════════════════════════════════════════════════════════════════════

_SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}
_RANK_TO_SEVERITY: dict[int, str] = {v: k for k, v in _SEVERITY_RANK.items()}

# Types where the endpoint is irrelevant — one root cause per host
_HOST_WIDE_TYPES: set[str] = HOST_ONLY_DEDUP_TYPES | HTTP_METHOD_AGNOSTIC_TYPES


# ═══════════════════════════════════════════════════════════════════════════════
# Key generation
# ═══════════════════════════════════════════════════════════════════════════════


def _canonical_endpoint(url: str) -> str:
    """Strip query params, fragment, and trailing slash for grouping."""
    if not url:
        return ""
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    return path


def _normalize_confidence(value: Any) -> float:
    """Normalize confidence to 0–100 float."""
    if isinstance(value, str):
        word_map = {
            "very high": 95.0,
            "high": 85.0,
            "medium": 65.0,
            "moderate": 65.0,
            "low": 45.0,
            "very low": 25.0,
        }
        return word_map.get(value.lower(), 50.0)
    if isinstance(value, (int, float)):
        return float(value) if value > 1 else value * 100
    return 50.0


def _evidence_fingerprint(finding: dict) -> str:
    """Compute evidence fingerprint from payload class and response status."""
    metadata = finding.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}
    payload = str(metadata.get("payload", ""))[:100]
    resp_status = str(metadata.get("response_status", ""))
    return hashlib.md5(f"{payload}:{resp_status}".encode()).hexdigest()[:8]


def generate_cluster_key(finding: dict) -> str:
    """Generate a coarse clustering key that groups findings by root cause.

    Intentionally coarser than dedup key:
    - Ignores detection_method (union vs boolean = same root cause)
    - Ignores HTTP method (GET vs POST to same endpoint = same root cause)
    - Uses canonical endpoint (strips query params)
    """
    finding_type = finding.get("vuln_type", finding.get("type", "unknown"))
    normalized_type = TYPE_NORMALIZATION.get(finding_type, finding_type).lower()

    host = finding.get("host", "")
    endpoint = finding.get(
        "endpoint", finding.get("matched_at", finding.get("url", ""))
    )
    canonical_ep = _canonical_endpoint(endpoint)

    metadata = finding.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}
    param = (
        finding.get("parameter", "")
        or metadata.get("param_name")
        or metadata.get("parameter")
        or metadata.get("vulnerable_param", "")
    )

    # Host-wide types: cluster by host alone
    if normalized_type in _HOST_WIDE_TYPES:
        return f"{normalized_type}:{host}"

    # Parameter-bearing types: cluster by type+host+endpoint+param
    if normalized_type in PARAM_BASED_TYPES and param:
        return f"{normalized_type}:{host}:{canonical_ep}:{param}"

    # Default: type+host+endpoint
    return f"{normalized_type}:{host}:{canonical_ep}"


# ═══════════════════════════════════════════════════════════════════════════════
# Root cause label
# ═══════════════════════════════════════════════════════════════════════════════


def _generate_root_cause(cluster_key: str, representative: dict) -> str:
    """Generate a human-readable root cause description."""
    name = representative.get(
        "name", representative.get("title", cluster_key.split(":")[0])
    )
    param = representative.get("parameter", "")
    endpoint = representative.get(
        "endpoint", representative.get("matched_at", "")
    )

    if param and endpoint:
        return f"{name} in parameter '{param}' at {endpoint}"
    if endpoint:
        return f"{name} at {endpoint}"
    return name


# ═══════════════════════════════════════════════════════════════════════════════
# Core clustering
# ═══════════════════════════════════════════════════════════════════════════════


def cluster_findings(findings: list[dict]) -> list[dict]:
    """Cluster findings by root cause and annotate with ``metadata["cluster"]``.

    Args:
        findings: List of finding dicts (post-dedup).

    Returns:
        Same list, with each finding's ``metadata["cluster"]`` populated.
        Order is preserved (findings are NOT reordered).
    """
    if not findings:
        return findings

    # Phase 1: Group by cluster key
    clusters: dict[str, list[int]] = defaultdict(list)
    for idx, finding in enumerate(findings):
        try:
            key = generate_cluster_key(finding)
        except Exception:
            key = f"fallback:{idx}"
        clusters[key].append(idx)

    # Phase 2: For each cluster, pick representative and annotate
    multi_clusters = 0

    for key, indices in clusters.items():
        cluster_size = len(indices)

        # Representative: highest severity, then highest confidence
        best_idx = max(
            indices,
            key=lambda i: (
                _SEVERITY_RANK.get(
                    str(findings[i].get("severity", "INFO")).upper(), 0
                ),
                _normalize_confidence(
                    findings[i].get(
                        "confidence_score", findings[i].get("confidence", 50)
                    )
                ),
            ),
        )

        # Cluster-level metrics
        max_sev_rank = max(
            _SEVERITY_RANK.get(
                str(findings[i].get("severity", "INFO")).upper(), 0
            )
            for i in indices
        )
        max_confidence = max(
            _normalize_confidence(
                findings[i].get(
                    "confidence_score", findings[i].get("confidence", 50)
                )
            )
            for i in indices
        )
        cluster_severity = _RANK_TO_SEVERITY.get(max_sev_rank, "INFO")
        cluster_id = "CLU-" + hashlib.md5(key.encode()).hexdigest()[:8]
        root_cause = _generate_root_cause(key, findings[best_idx])

        # Annotate each finding
        for member_idx, finding_idx in enumerate(indices):
            finding = findings[finding_idx]
            finding.setdefault("metadata", {})["cluster"] = {
                "cluster_id": cluster_id,
                "cluster_key": key,
                "root_cause": root_cause,
                "is_representative": finding_idx == best_idx,
                "cluster_size": cluster_size,
                "cluster_severity": cluster_severity,
                "cluster_confidence": max_confidence,
                "evidence_fingerprint": _evidence_fingerprint(finding),
                "member_index": member_idx,
            }

        if cluster_size > 1:
            multi_clusters += 1

    total_clusters = len(clusters)
    logger.info(
        f"[Clustering] {len(findings)} findings -> {total_clusters} clusters "
        f"({multi_clusters} multi-member, "
        f"{total_clusters - multi_clusters} standalone)"
    )

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers for consumers
# ═══════════════════════════════════════════════════════════════════════════════


def get_cluster_summary(findings: list[dict]) -> dict[str, Any]:
    """Generate summary statistics about clusters."""
    clusters: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        cid = ((f.get("metadata") or {}).get("cluster") or {}).get(
            "cluster_id", ""
        )
        if cid:
            clusters[cid].append(f)

    multi = {k: v for k, v in clusters.items() if len(v) > 1}
    return {
        "total_clusters": len(clusters),
        "multi_member_clusters": len(multi),
        "largest_cluster": max(
            (len(v) for v in clusters.values()), default=0
        ),
        "findings_in_multi_clusters": sum(len(v) for v in multi.values()),
    }


def get_clustered_findings(findings: list[dict]) -> list[dict]:
    """Return findings reordered by cluster: representatives first,
    followed by their sub-findings.  Useful for report rendering.

    Multi-member clusters come first (sorted by severity desc),
    then standalone findings (sorted by severity desc).
    """
    clusters: dict[str, list[dict]] = defaultdict(list)
    standalone: list[dict] = []

    for f in findings:
        cluster_info = ((f.get("metadata") or {}).get("cluster") or {})
        cid = cluster_info.get("cluster_id")
        if cid and cluster_info.get("cluster_size", 1) > 1:
            clusters[cid].append(f)
        else:
            standalone.append(f)

    # Sort clusters by representative severity
    sorted_clusters = sorted(
        clusters.values(),
        key=lambda group: max(
            _SEVERITY_RANK.get(
                str(f.get("severity", "INFO")).upper(), 0
            )
            for f in group
        ),
        reverse=True,
    )

    result: list[dict] = []
    for group in sorted_clusters:
        # Representative first
        rep = next(
            (
                f
                for f in group
                if ((f.get("metadata") or {}).get("cluster") or {}).get(
                    "is_representative"
                )
            ),
            group[0],
        )
        others = [f for f in group if f is not rep]
        # Sort others by confidence desc
        others.sort(
            key=lambda f: _normalize_confidence(
                f.get("confidence_score", f.get("confidence", 50))
            ),
            reverse=True,
        )
        result.append(rep)
        result.extend(others)

    # Standalone findings sorted by severity desc
    standalone.sort(
        key=lambda f: _SEVERITY_RANK.get(
            str(f.get("severity", "INFO")).upper(), 0
        ),
        reverse=True,
    )
    result.extend(standalone)

    return result
