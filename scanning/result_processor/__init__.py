"""
Result Processor Module - Finding Processing and Sharing.

Provides components for processing scan results:
- FindingDeduplicator: Cross-module deduplication
- FindingSharer: Cross-module finding sharing
- Type normalization and key generation utilities

Extracted from full_scanner.py for modularization.
"""

from .deduplicate import (
    TYPE_NORMALIZATION,
    NAME_BASED_TYPES,
    PARAM_BASED_TYPES,
    METHOD_BASED_TYPES,
    HTTP_METHOD_AGNOSTIC_TYPES,
    normalize_detection_method,
    generate_dedup_key,
    FindingDeduplicator,
    deduplicate_findings,
)
from .sharing import (
    EARLY_SHARE_THRESHOLD,
    VALIDATED_SHARE_THRESHOLD,
    SharedFindingsStoreProtocol,
    AuditLoggerProtocol,
    share_findings_early,
    share_validated_findings,
    FindingSharer,
)
from .aggregator import (
    ResultAggregator,
    aggregate_results,
)
from .cluster import (
    generate_cluster_key,
    cluster_findings,
    get_cluster_summary,
    get_clustered_findings,
)

__all__ = [
    # Deduplication
    "TYPE_NORMALIZATION",
    "NAME_BASED_TYPES",
    "PARAM_BASED_TYPES",
    "METHOD_BASED_TYPES",
    "HTTP_METHOD_AGNOSTIC_TYPES",
    "normalize_detection_method",
    "generate_dedup_key",
    "FindingDeduplicator",
    "deduplicate_findings",
    # Sharing
    "EARLY_SHARE_THRESHOLD",
    "VALIDATED_SHARE_THRESHOLD",
    "SharedFindingsStoreProtocol",
    "AuditLoggerProtocol",
    "share_findings_early",
    "share_validated_findings",
    "FindingSharer",
    # Aggregation
    "ResultAggregator",
    "aggregate_results",
    # Clustering
    "generate_cluster_key",
    "cluster_findings",
    "get_cluster_summary",
    "get_clustered_findings",
]
