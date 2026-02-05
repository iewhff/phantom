"""
Endpoint Map - Enterprise Edition

Central registry for all discovered endpoints.
Shared singleton across all scanner modules.

Features:
- Multi-source endpoint discovery tracking
- Semantic categorization for scanner routing
- Confidence scoring based on source
- Parameter and method tracking
- Verification status tracking

Usage:
    from utils.endpoint_map import EndpointMap, EndpointCategory

    # Get singleton instance
    endpoint_map = EndpointMap.get_instance()

    # Add discovered endpoint
    endpoint_map.add_endpoint(DiscoveredEndpoint(
        path="/api/users",
        methods={HTTPMethod.GET, HTTPMethod.POST},
        source=EndpointSource.OPENAPI_SPEC,
        confidence=0.95,
    ))

    # Query by scanner
    api_endpoints = endpoint_map.get_for_scanner("api_scanner")

    # Query by category
    auth_endpoints = endpoint_map.get_by_category(EndpointCategory.AUTH)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from utils.logger import get_logger

logger = get_logger(__name__)


class EndpointSource(Enum):
    """Origin of endpoint discovery - affects confidence scoring."""
    SITEMAP_XML = auto()            # sitemap.xml parsing (0.9 confidence)
    ROBOTS_TXT = auto()             # robots.txt parsing (0.7 confidence)
    OPENAPI_SPEC = auto()           # OpenAPI/Swagger parsed (0.95 confidence)
    GRAPHQL_INTROSPECTION = auto()  # GraphQL schema introspection (0.95 confidence)
    CRAWL_HTML = auto()             # HTML link extraction (0.8 confidence)
    CRAWL_JS = auto()               # JavaScript regex extraction (0.7 confidence)
    CRAWL_SPA = auto()              # Headless browser SPA crawl (0.85 confidence)
    WAYBACK_MACHINE = auto()        # Historical archive (0.5 confidence)
    TECH_INFERENCE = auto()         # Technology-based inference (0.7 confidence)
    RESPONSE_INFERENCE = auto()     # Response-based inference (0.6 confidence)
    USER_PROVIDED = auto()          # Manually provided (1.0 confidence)
    FORM_DISCOVERY = auto()         # HTML form action (0.9 confidence)
    API_PROBE = auto()              # Active probing verification (0.95 confidence)


class HTTPMethod(Enum):
    """HTTP methods."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


class EndpointCategory(Enum):
    """Semantic categorization for scanner routing."""
    AUTH = auto()           # Login, logout, register, password reset, OAuth
    USER_DATA = auto()      # User profiles, settings, personal data
    ADMIN = auto()          # Admin panels, management interfaces
    API_REST = auto()       # REST API endpoints
    API_GRAPHQL = auto()    # GraphQL endpoints
    FILE_UPLOAD = auto()    # Upload endpoints
    SEARCH = auto()         # Search functionality
    PAYMENT = auto()        # Payment/checkout flows
    PUBLIC = auto()         # Public content
    STATIC = auto()         # Static resources (JS, CSS, images)
    WEBSOCKET = auto()      # WebSocket endpoints
    UNKNOWN = auto()        # Uncategorized


# Default confidence scores by source
SOURCE_CONFIDENCE = {
    EndpointSource.OPENAPI_SPEC: 0.95,
    EndpointSource.GRAPHQL_INTROSPECTION: 0.95,
    EndpointSource.API_PROBE: 0.95,
    EndpointSource.USER_PROVIDED: 1.0,
    EndpointSource.SITEMAP_XML: 0.9,
    EndpointSource.FORM_DISCOVERY: 0.9,
    EndpointSource.CRAWL_SPA: 0.85,
    EndpointSource.CRAWL_HTML: 0.8,
    EndpointSource.TECH_INFERENCE: 0.7,
    EndpointSource.CRAWL_JS: 0.7,
    EndpointSource.ROBOTS_TXT: 0.7,
    EndpointSource.RESPONSE_INFERENCE: 0.6,
    EndpointSource.WAYBACK_MACHINE: 0.5,
}


@dataclass
class DiscoveredParameter:
    """Parameter discovered for an endpoint."""
    name: str
    location: str = "query"  # query, body, path, header, cookie
    param_type: str = "string"  # string, integer, boolean, array, object
    required: bool = False
    example_value: Optional[str] = None
    constraints: Dict[str, Any] = field(default_factory=dict)  # min, max, pattern, enum

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location,
            "type": self.param_type,
            "required": self.required,
            "example": self.example_value,
        }


@dataclass
class DiscoveredEndpoint:
    """A discovered endpoint with full metadata."""
    path: str                                    # /api/v1/users/{id}
    methods: Set[HTTPMethod] = field(default_factory=lambda: {HTTPMethod.GET})
    source: EndpointSource = EndpointSource.CRAWL_HTML
    confidence: float = 0.5                      # 0.0 - 1.0
    category: EndpointCategory = EndpointCategory.UNKNOWN
    parameters: List[DiscoveredParameter] = field(default_factory=list)
    requires_auth: bool = False
    auth_type: Optional[str] = None              # bearer, basic, cookie, apikey
    content_types: List[str] = field(default_factory=list)  # request content types
    response_types: List[str] = field(default_factory=list)  # response content types
    verified: bool = False                       # Has been verified to exist
    last_status_code: Optional[int] = None
    technology_hint: Optional[str] = None        # Framework/CMS hint
    raw_evidence: Optional[str] = None           # Evidence of discovery
    operation_id: Optional[str] = None           # OpenAPI operationId
    description: Optional[str] = None            # Endpoint description

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "path": self.path,
            "methods": [m.value for m in self.methods],
            "source": self.source.name,
            "confidence": self.confidence,
            "category": self.category.name,
            "parameters": [p.to_dict() for p in self.parameters],
            "requires_auth": self.requires_auth,
            "auth_type": self.auth_type,
            "verified": self.verified,
            "last_status_code": self.last_status_code,
            "technology_hint": self.technology_hint,
        }

    def get_full_url(self, host: str, scheme: str = "https") -> str:
        """Construct full URL from path and host."""
        if not host:
            return self.path
        # Ensure path starts with /
        path = self.path if self.path.startswith("/") else f"/{self.path}"
        return f"{scheme}://{host}{path}"

    def merge_with(self, other: DiscoveredEndpoint) -> None:
        """Merge another endpoint's data into this one."""
        # Combine methods
        self.methods.update(other.methods)

        # Add new parameters (by name)
        existing_param_names = {p.name for p in self.parameters}
        for param in other.parameters:
            if param.name not in existing_param_names:
                self.parameters.append(param)

        # Update confidence if higher
        if other.confidence > self.confidence:
            self.confidence = other.confidence
            self.source = other.source

        # Update verified status
        if other.verified:
            self.verified = True
            self.last_status_code = other.last_status_code

        # Update auth info if discovered
        if other.requires_auth and not self.requires_auth:
            self.requires_auth = True
            self.auth_type = other.auth_type

        # Update category if was unknown
        if self.category == EndpointCategory.UNKNOWN and other.category != EndpointCategory.UNKNOWN:
            self.category = other.category


class EndpointMap:
    """
    Central registry of all discovered endpoints.

    Singleton pattern - shared across all scanners.

    Usage:
        endpoint_map = EndpointMap.get_instance()

        # Add discovered endpoints
        endpoint_map.add_endpoint(DiscoveredEndpoint(...))

        # Query by category
        auth_endpoints = endpoint_map.get_by_category(EndpointCategory.AUTH)

        # Query by method
        post_endpoints = endpoint_map.get_by_method(HTTPMethod.POST)

        # Get all for scanner
        for ep in endpoint_map.get_for_scanner("api_scanner"):
            ...
    """

    _instance: Optional[EndpointMap] = None

    # Scanner to category mapping
    SCANNER_CATEGORIES: Dict[str, List[EndpointCategory]] = {
        "api_scanner": [
            EndpointCategory.API_REST,
            EndpointCategory.API_GRAPHQL,
            EndpointCategory.FILE_UPLOAD,
            EndpointCategory.SEARCH,
        ],
        "authorization_engine": [
            EndpointCategory.ADMIN,
            EndpointCategory.USER_DATA,
            EndpointCategory.AUTH,
            EndpointCategory.API_REST,
        ],
        "business_logic_scanner": [
            EndpointCategory.PAYMENT,
            EndpointCategory.USER_DATA,
            EndpointCategory.AUTH,
            EndpointCategory.API_REST,
        ],
        "creative_exploiter": [
            EndpointCategory.PAYMENT,
            EndpointCategory.USER_DATA,
            EndpointCategory.AUTH,
            EndpointCategory.ADMIN,
            EndpointCategory.API_REST,
            EndpointCategory.SEARCH,
        ],
        "auth_scanner": [
            EndpointCategory.AUTH,
        ],
        "auth_jwt_scanner": [
            EndpointCategory.AUTH,
            EndpointCategory.API_REST,
        ],
        "auth_bypass_scanner": [
            EndpointCategory.ADMIN,
            EndpointCategory.AUTH,
            EndpointCategory.API_REST,
        ],
        "sqli_scanner": [
            EndpointCategory.API_REST,
            EndpointCategory.SEARCH,
            EndpointCategory.AUTH,
        ],
        "xss_scanner": [
            EndpointCategory.SEARCH,
            EndpointCategory.USER_DATA,
            EndpointCategory.API_REST,
        ],
        "nosql_scanner": [
            EndpointCategory.API_REST,
            EndpointCategory.AUTH,
            EndpointCategory.SEARCH,
        ],
        "ssrf_scanner": [
            EndpointCategory.API_REST,
            EndpointCategory.FILE_UPLOAD,
        ],
        "file_upload_scanner": [
            EndpointCategory.FILE_UPLOAD,
        ],
        "dir_scanner": [
            EndpointCategory.ADMIN,
            EndpointCategory.STATIC,
        ],
    }

    def __init__(self) -> None:
        self._endpoints: Dict[str, DiscoveredEndpoint] = {}  # path -> endpoint
        self._by_category: Dict[EndpointCategory, List[str]] = {}
        self._by_source: Dict[EndpointSource, List[str]] = {}
        self._by_method: Dict[HTTPMethod, Set[str]] = {}
        self._verified_paths: Set[str] = set()
        self._host: str = ""

    @classmethod
    def get_instance(cls) -> EndpointMap:
        """Get singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset for new scan."""
        cls._instance = None
        logger.debug("[EndpointMap] Reset - cleared all endpoints")

    def set_host(self, host: str) -> None:
        """Set target host for this map."""
        self._host = host
        logger.debug(f"[EndpointMap] Host set to: {host}")

    def get_host(self) -> str:
        """Get target host."""
        return self._host

    def add_endpoint(self, endpoint: DiscoveredEndpoint) -> None:
        """Add or merge endpoint."""
        path = self._normalize_path(endpoint.path)

        if path in self._endpoints:
            # Merge with existing
            existing = self._endpoints[path]
            existing.merge_with(endpoint)
            logger.debug(f"[EndpointMap] Merged endpoint: {path}")
        else:
            # Add new endpoint
            endpoint.path = path  # Use normalized path
            self._endpoints[path] = endpoint

            # Index by category
            if endpoint.category not in self._by_category:
                self._by_category[endpoint.category] = []
            self._by_category[endpoint.category].append(path)

            # Index by source
            if endpoint.source not in self._by_source:
                self._by_source[endpoint.source] = []
            self._by_source[endpoint.source].append(path)

            # Index by methods
            for method in endpoint.methods:
                if method not in self._by_method:
                    self._by_method[method] = set()
                self._by_method[method].add(path)

            logger.debug(f"[EndpointMap] Added endpoint: {path} ({endpoint.source.name})")

        # Track verified
        if endpoint.verified:
            self._verified_paths.add(path)

    def _normalize_path(self, path: str) -> str:
        """Normalize path for consistent storage."""
        # Remove query string
        if "?" in path:
            path = path.split("?")[0]

        # Remove trailing slash (except root)
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")

        # Ensure starts with /
        if not path.startswith("/"):
            path = "/" + path

        return path

    def get_by_category(self, category: EndpointCategory) -> List[DiscoveredEndpoint]:
        """Get endpoints by category."""
        paths = self._by_category.get(category, [])
        return [self._endpoints[p] for p in paths if p in self._endpoints]

    def get_by_source(self, source: EndpointSource) -> List[DiscoveredEndpoint]:
        """Get endpoints by discovery source."""
        paths = self._by_source.get(source, [])
        return [self._endpoints[p] for p in paths if p in self._endpoints]

    def get_by_method(self, method: HTTPMethod) -> List[DiscoveredEndpoint]:
        """Get endpoints supporting a specific method."""
        paths = self._by_method.get(method, set())
        return [self._endpoints[p] for p in paths if p in self._endpoints]

    def get_auth_endpoints(self) -> List[DiscoveredEndpoint]:
        """Get endpoints requiring authentication."""
        return [ep for ep in self._endpoints.values() if ep.requires_auth]

    def get_verified(self) -> List[DiscoveredEndpoint]:
        """Get verified endpoints only."""
        return [self._endpoints[p] for p in self._verified_paths if p in self._endpoints]

    def get_unverified(self) -> List[DiscoveredEndpoint]:
        """Get unverified endpoints."""
        return [ep for ep in self._endpoints.values() if not ep.verified]

    def get_high_confidence(self, min_confidence: float = 0.8) -> List[DiscoveredEndpoint]:
        """Get endpoints with high confidence score."""
        return [ep for ep in self._endpoints.values() if ep.confidence >= min_confidence]

    def get_all(self) -> List[DiscoveredEndpoint]:
        """Get all endpoints."""
        return list(self._endpoints.values())

    def get_paths(self) -> List[str]:
        """Get all paths."""
        return list(self._endpoints.keys())

    def get_for_scanner(self, scanner_name: str) -> List[DiscoveredEndpoint]:
        """Get endpoints relevant to a specific scanner."""
        categories = self.SCANNER_CATEGORIES.get(scanner_name.lower().replace("-", "_"), [])

        if not categories:
            # Return all for unknown scanners
            logger.debug(f"[EndpointMap] No category mapping for {scanner_name}, returning all")
            return self.get_all()

        result = []
        seen_paths = set()

        for cat in categories:
            for endpoint in self.get_by_category(cat):
                if endpoint.path not in seen_paths:
                    result.append(endpoint)
                    seen_paths.add(endpoint.path)

        logger.debug(f"[EndpointMap] {scanner_name}: {len(result)} relevant endpoints")
        return result

    def get_for_testing(self, min_confidence: float = 0.6) -> List[DiscoveredEndpoint]:
        """Get endpoints suitable for testing (verified or high confidence)."""
        return [
            ep for ep in self._endpoints.values()
            if ep.verified or ep.confidence >= min_confidence
        ]

    def mark_verified(self, path: str, status_code: int) -> None:
        """Mark an endpoint as verified."""
        normalized = self._normalize_path(path)
        if normalized in self._endpoints:
            self._endpoints[normalized].verified = True
            self._endpoints[normalized].last_status_code = status_code
            self._verified_paths.add(normalized)

    def mark_nonexistent(self, path: str) -> None:
        """Mark an endpoint as non-existent (remove from map)."""
        normalized = self._normalize_path(path)
        if normalized in self._endpoints:
            endpoint = self._endpoints[normalized]

            # Remove from all indexes
            if endpoint.category in self._by_category:
                try:
                    self._by_category[endpoint.category].remove(normalized)
                except ValueError:
                    pass

            if endpoint.source in self._by_source:
                try:
                    self._by_source[endpoint.source].remove(normalized)
                except ValueError:
                    pass

            for method in endpoint.methods:
                if method in self._by_method:
                    self._by_method[method].discard(normalized)

            self._verified_paths.discard(normalized)

            del self._endpoints[normalized]
            logger.debug(f"[EndpointMap] Removed non-existent: {normalized}")

    def has_endpoint(self, path: str) -> bool:
        """Check if path exists in map."""
        return self._normalize_path(path) in self._endpoints

    def get_endpoint(self, path: str) -> Optional[DiscoveredEndpoint]:
        """Get specific endpoint by path."""
        return self._endpoints.get(self._normalize_path(path))

    def get_statistics(self) -> Dict[str, Any]:
        """Get discovery statistics."""
        return {
            "total_endpoints": len(self._endpoints),
            "verified": len(self._verified_paths),
            "unverified": len(self._endpoints) - len(self._verified_paths),
            "by_category": {
                cat.name: len(paths)
                for cat, paths in self._by_category.items()
            },
            "by_source": {
                src.name: len(paths)
                for src, paths in self._by_source.items()
            },
            "by_method": {
                method.value: len(paths)
                for method, paths in self._by_method.items()
            },
            "avg_confidence": (
                sum(ep.confidence for ep in self._endpoints.values()) / len(self._endpoints)
                if self._endpoints else 0
            ),
            "auth_required": len([ep for ep in self._endpoints.values() if ep.requires_auth]),
        }

    # =========================================================================
    # PHANTOM AI ENHANCEMENTS
    # =========================================================================

    def get_attack_surface_score(self) -> Dict[str, Any]:
        """
        Calculate attack surface score based on discovered endpoints.

        Returns:
            Dictionary with:
            - overall_score: 0.0-10.0 attack surface score
            - category_scores: breakdown by category
            - risk_factors: identified risk factors
            - recommendations: security recommendations
        """
        if not self._endpoints:
            return {
                "overall_score": 0.0,
                "category_scores": {},
                "risk_factors": [],
                "recommendations": ["No endpoints discovered yet"],
            }

        # Category weights for attack surface calculation
        category_weights = {
            EndpointCategory.AUTH: 2.0,        # Authentication is high value
            EndpointCategory.ADMIN: 2.5,       # Admin access is critical
            EndpointCategory.API_REST: 1.5,    # APIs often have vulnerabilities
            EndpointCategory.API_GRAPHQL: 1.8, # GraphQL has specific attack vectors
            EndpointCategory.FILE_UPLOAD: 2.0, # File upload is risky
            EndpointCategory.PAYMENT: 2.2,     # Payment is sensitive
            EndpointCategory.USER_DATA: 1.7,   # User data needs protection
            EndpointCategory.SEARCH: 1.3,      # Search often vulnerable to injection
            EndpointCategory.WEBSOCKET: 1.4,   # WebSockets can be tricky
            EndpointCategory.PUBLIC: 0.5,      # Public content is lower risk
            EndpointCategory.STATIC: 0.2,      # Static files are low risk
            EndpointCategory.UNKNOWN: 1.0,     # Unknown is neutral
        }

        # Calculate category scores
        category_counts: Dict[EndpointCategory, int] = {}
        category_scores: Dict[str, float] = {}

        for ep in self._endpoints.values():
            cat = ep.category
            category_counts[cat] = category_counts.get(cat, 0) + 1

        # Calculate weighted scores
        total_weight = 0.0
        for cat, count in category_counts.items():
            weight = category_weights.get(cat, 1.0)
            score = min(10.0, count * weight * 0.5)  # Cap at 10
            category_scores[cat.name] = round(score, 2)
            total_weight += score

        # Overall score (normalized to 0-10)
        num_categories = len(category_counts) or 1
        overall_score = min(10.0, total_weight / num_categories)

        # Identify risk factors
        risk_factors = []

        if category_counts.get(EndpointCategory.ADMIN, 0) > 0:
            risk_factors.append({
                "factor": "Admin endpoints exposed",
                "severity": "high",
                "count": category_counts[EndpointCategory.ADMIN],
            })

        if category_counts.get(EndpointCategory.FILE_UPLOAD, 0) > 0:
            risk_factors.append({
                "factor": "File upload functionality present",
                "severity": "high",
                "count": category_counts[EndpointCategory.FILE_UPLOAD],
            })

        auth_count = category_counts.get(EndpointCategory.AUTH, 0)
        if auth_count > 5:
            risk_factors.append({
                "factor": "Multiple authentication endpoints",
                "severity": "medium",
                "count": auth_count,
            })

        # Check for unverified endpoints
        unverified = len([ep for ep in self._endpoints.values() if not ep.verified])
        if unverified > len(self._endpoints) * 0.5:
            risk_factors.append({
                "factor": "Many unverified endpoints",
                "severity": "info",
                "count": unverified,
            })

        # Check for low confidence endpoints
        low_confidence = len([ep for ep in self._endpoints.values() if ep.confidence < 0.5])
        if low_confidence > 0:
            risk_factors.append({
                "factor": "Low confidence endpoints present",
                "severity": "info",
                "count": low_confidence,
            })

        # Generate recommendations
        recommendations = []

        if EndpointCategory.ADMIN in category_counts:
            recommendations.append("Verify admin endpoints are properly protected")

        if EndpointCategory.AUTH in category_counts:
            recommendations.append("Test authentication mechanisms thoroughly")

        if EndpointCategory.FILE_UPLOAD in category_counts:
            recommendations.append("Check file upload for bypass vulnerabilities")

        if EndpointCategory.API_GRAPHQL in category_counts:
            recommendations.append("Test GraphQL for introspection and injection")

        if EndpointCategory.PAYMENT in category_counts:
            recommendations.append("Audit payment flow for business logic flaws")

        if not recommendations:
            recommendations.append("Perform comprehensive security scan")

        return {
            "overall_score": round(overall_score, 2),
            "category_scores": category_scores,
            "risk_factors": risk_factors,
            "recommendations": recommendations,
            "endpoint_count": len(self._endpoints),
            "verified_count": len(self._verified_paths),
        }

    def get_priority_endpoints(
        self,
        limit: int = 50,
        min_confidence: float = 0.5,
        include_categories: Optional[List[EndpointCategory]] = None,
        exclude_categories: Optional[List[EndpointCategory]] = None,
    ) -> List[DiscoveredEndpoint]:
        """
        Get prioritized endpoints for security testing.

        Priority is calculated based on:
        - Category risk weight
        - Confidence score
        - Authentication requirements
        - Parameter count
        - HTTP methods available

        Args:
            limit: Maximum number of endpoints to return
            min_confidence: Minimum confidence threshold
            include_categories: Only include these categories (None = all)
            exclude_categories: Exclude these categories

        Returns:
            List of endpoints sorted by priority (highest first)
        """
        # Default exclusions
        if exclude_categories is None:
            exclude_categories = [EndpointCategory.STATIC]

        # Priority weights
        category_priority = {
            EndpointCategory.ADMIN: 10,
            EndpointCategory.AUTH: 9,
            EndpointCategory.PAYMENT: 9,
            EndpointCategory.FILE_UPLOAD: 8,
            EndpointCategory.USER_DATA: 7,
            EndpointCategory.API_GRAPHQL: 7,
            EndpointCategory.API_REST: 6,
            EndpointCategory.SEARCH: 6,
            EndpointCategory.WEBSOCKET: 5,
            EndpointCategory.PUBLIC: 3,
            EndpointCategory.UNKNOWN: 4,
            EndpointCategory.STATIC: 1,
        }

        def calculate_priority(ep: DiscoveredEndpoint) -> float:
            """Calculate priority score for an endpoint."""
            score = 0.0

            # Base category score
            score += category_priority.get(ep.category, 5)

            # Confidence bonus
            score += ep.confidence * 3

            # Verified bonus
            if ep.verified:
                score += 2

            # Auth required bonus (interesting for bypass testing)
            if ep.requires_auth:
                score += 1.5

            # Parameters bonus (more attack surface)
            score += min(len(ep.parameters), 5) * 0.5

            # Multiple methods bonus
            score += (len(ep.methods) - 1) * 0.3

            # POST/PUT/DELETE bonus
            if HTTPMethod.POST in ep.methods:
                score += 1
            if HTTPMethod.PUT in ep.methods or HTTPMethod.DELETE in ep.methods:
                score += 0.5

            return score

        # Filter endpoints
        filtered = []
        for ep in self._endpoints.values():
            # Confidence filter
            if ep.confidence < min_confidence:
                continue

            # Category filters
            if include_categories and ep.category not in include_categories:
                continue
            if exclude_categories and ep.category in exclude_categories:
                continue

            filtered.append(ep)

        # Sort by priority (descending)
        filtered.sort(key=calculate_priority, reverse=True)

        return filtered[:limit]

    def export_to_burp(self, output_path: Optional[str] = None) -> str:
        """
        Export endpoints in Burp Suite XML format.

        This format can be imported into Burp Suite via:
        Target > Site map > right-click > Import from file

        Args:
            output_path: Optional file path to write XML

        Returns:
            XML string in Burp format
        """
        import xml.etree.ElementTree as ET
        from xml.dom import minidom

        # Create root element
        root = ET.Element("items", burpVersion="2023.1", exportTime=str(__import__('time').time()))

        for ep in self._endpoints.values():
            for method in ep.methods:
                item = ET.SubElement(root, "item")

                # Build full URL
                scheme = "https"
                host = self._host or "target.com"
                port = "443" if scheme == "https" else "80"
                path = ep.path

                ET.SubElement(item, "time").text = ""
                ET.SubElement(item, "url").text = f"{scheme}://{host}{path}"
                ET.SubElement(item, "host", ip="").text = host
                ET.SubElement(item, "port").text = port
                ET.SubElement(item, "protocol").text = scheme
                ET.SubElement(item, "method").text = method.value
                ET.SubElement(item, "path").text = path
                ET.SubElement(item, "extension").text = ""
                ET.SubElement(item, "request", base64="false").text = self._build_request(
                    method.value, path, host, ep
                )
                ET.SubElement(item, "status").text = str(ep.last_status_code or 200)
                ET.SubElement(item, "responselength").text = "0"
                ET.SubElement(item, "mimetype").text = ""
                ET.SubElement(item, "response", base64="false").text = ""
                ET.SubElement(item, "comment").text = f"Category: {ep.category.name}, Confidence: {ep.confidence}"

        # Convert to string with pretty printing
        xml_str = ET.tostring(root, encoding='unicode')
        pretty_xml = minidom.parseString(xml_str).toprettyxml(indent="  ")

        # Remove extra blank lines
        pretty_xml = '\n'.join(line for line in pretty_xml.split('\n') if line.strip())

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(pretty_xml)
            logger.info(f"[EndpointMap] Exported {len(self._endpoints)} endpoints to {output_path}")

        return pretty_xml

    def _build_request(
        self,
        method: str,
        path: str,
        host: str,
        endpoint: DiscoveredEndpoint,
    ) -> str:
        """Build a sample HTTP request for Burp export."""
        lines = [
            f"{method} {path} HTTP/1.1",
            f"Host: {host}",
            "User-Agent: PHANTOM-AI/3.0",
            "Accept: */*",
        ]

        # Add content-type for POST/PUT
        if method in ("POST", "PUT", "PATCH"):
            if endpoint.content_types:
                lines.append(f"Content-Type: {endpoint.content_types[0]}")
            else:
                lines.append("Content-Type: application/json")

        # Add auth header placeholder
        if endpoint.requires_auth:
            if endpoint.auth_type == "bearer":
                lines.append("Authorization: Bearer <token>")
            elif endpoint.auth_type == "basic":
                lines.append("Authorization: Basic <credentials>")
            else:
                lines.append("Authorization: <auth>")

        lines.append("")  # Empty line before body

        # Add body for POST/PUT with parameters
        if method in ("POST", "PUT", "PATCH") and endpoint.parameters:
            body_params = {p.name: p.example_value or "" for p in endpoint.parameters if p.location == "body"}
            if body_params:
                import json
                lines.append(json.dumps(body_params))

        return "\r\n".join(lines)

    def export_to_openapi(self) -> Dict[str, Any]:
        """
        Export endpoints as OpenAPI 3.0 specification.

        Returns:
            OpenAPI spec dictionary
        """
        spec = {
            "openapi": "3.0.3",
            "info": {
                "title": f"Discovered API - {self._host}",
                "description": "Auto-discovered endpoints by PHANTOM AI",
                "version": "1.0.0",
            },
            "servers": [
                {"url": f"https://{self._host}" if self._host else "https://target.com"}
            ],
            "paths": {},
        }

        for ep in self._endpoints.values():
            # Skip GraphQL virtual endpoints
            if "#" in ep.path:
                continue

            path_item = spec["paths"].get(ep.path, {})

            for method in ep.methods:
                method_lower = method.value.lower()
                operation = {
                    "summary": ep.description or f"{method.value} {ep.path}",
                    "operationId": ep.operation_id or f"{method_lower}_{ep.path.replace('/', '_')}",
                    "tags": [ep.category.name],
                    "responses": {
                        "200": {"description": "Successful response"},
                    },
                }

                # Add parameters
                if ep.parameters:
                    operation["parameters"] = []
                    for param in ep.parameters:
                        operation["parameters"].append({
                            "name": param.name,
                            "in": param.location,
                            "required": param.required,
                            "schema": {"type": param.param_type},
                        })

                # Add security if auth required
                if ep.requires_auth:
                    operation["security"] = [{"bearerAuth": []}]

                path_item[method_lower] = operation

            spec["paths"][ep.path] = path_item

        # Add security schemes if any endpoint requires auth
        if any(ep.requires_auth for ep in self._endpoints.values()):
            spec["components"] = {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                    }
                }
            }

        return spec

    def to_dict(self) -> Dict[str, Any]:
        """Export full map as dictionary."""
        return {
            "host": self._host,
            "statistics": self.get_statistics(),
            "endpoints": [ep.to_dict() for ep in self._endpoints.values()],
        }

    def __len__(self) -> int:
        return len(self._endpoints)

    def __bool__(self) -> bool:
        return len(self._endpoints) > 0

    def __iter__(self):
        return iter(self._endpoints.values())


# Utility functions for categorization
def categorize_path(path: str, method: str = "GET") -> EndpointCategory:
    """Categorize a path based on patterns."""
    path_lower = path.lower()
    method_upper = method.upper()

    # Auth patterns
    auth_patterns = [
        "/login", "/logout", "/auth", "/signin", "/signout", "/register",
        "/signup", "/password", "/reset", "/verify", "/oauth", "/token",
        "/session", "/jwt", "/refresh", "/2fa", "/mfa", "/otp",
        "/forgot", "/recover", "/activate", "/confirm",
    ]
    if any(p in path_lower for p in auth_patterns):
        return EndpointCategory.AUTH

    # Admin patterns
    admin_patterns = [
        "/admin", "/dashboard", "/manage", "/control", "/settings",
        "/config", "/system", "/internal", "/staff", "/moderator",
        "/console", "/panel", "/superuser", "/root", "/backoffice",
    ]
    if any(p in path_lower for p in admin_patterns):
        return EndpointCategory.ADMIN

    # GraphQL
    if "/graphql" in path_lower or "#query:" in path_lower or "#mutation:" in path_lower:
        return EndpointCategory.API_GRAPHQL

    # WebSocket
    if "/ws" in path_lower or "/socket" in path_lower or "/realtime" in path_lower:
        return EndpointCategory.WEBSOCKET

    # File upload
    upload_patterns = [
        "/upload", "/file", "/image", "/media", "/attachment",
        "/document", "/import", "/asset", "/blob", "/storage",
    ]
    if any(p in path_lower for p in upload_patterns):
        return EndpointCategory.FILE_UPLOAD

    # Payment
    payment_patterns = [
        "/pay", "/checkout", "/cart", "/order", "/invoice",
        "/subscription", "/billing", "/transaction", "/stripe",
        "/paypal", "/purchase", "/refund", "/wallet",
    ]
    if any(p in path_lower for p in payment_patterns):
        return EndpointCategory.PAYMENT

    # User data
    user_patterns = [
        "/user", "/profile", "/account", "/me", "/self", "/my",
        "/preference", "/notification", "/inbox", "/message",
    ]
    if any(p in path_lower for p in user_patterns):
        return EndpointCategory.USER_DATA

    # Search
    if "/search" in path_lower or "/query" in path_lower or "?q=" in path_lower:
        return EndpointCategory.SEARCH

    # API patterns
    api_patterns = ["/api/", "/rest/", "/v1/", "/v2/", "/v3/", "/json/"]
    if any(p in path_lower for p in api_patterns):
        return EndpointCategory.API_REST

    # Static resources
    static_extensions = [
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico",
        ".woff", ".woff2", ".ttf", ".svg", ".map", ".webp",
    ]
    if any(path_lower.endswith(ext) for ext in static_extensions):
        return EndpointCategory.STATIC

    # Static paths
    static_paths = ["/static", "/assets", "/public", "/dist", "/build"]
    if any(p in path_lower for p in static_paths):
        return EndpointCategory.STATIC

    return EndpointCategory.PUBLIC


def infer_methods_from_path(path: str) -> Set[HTTPMethod]:
    """Infer likely HTTP methods from path patterns."""
    path_lower = path.lower()
    methods = {HTTPMethod.GET}

    # ID patterns suggest CRUD
    if "{id}" in path_lower or "/{" in path_lower or path_lower.endswith(("/1", "/2")):
        methods.update({HTTPMethod.PUT, HTTPMethod.PATCH, HTTPMethod.DELETE})

    # Auth endpoints
    if any(p in path_lower for p in ["/login", "/register", "/auth", "/token"]):
        methods.add(HTTPMethod.POST)

    # Create/update patterns
    if any(p in path_lower for p in ["/create", "/new", "/add", "/update", "/edit"]):
        methods.add(HTTPMethod.POST)

    # Delete patterns
    if "/delete" in path_lower or "/remove" in path_lower:
        methods.add(HTTPMethod.DELETE)

    # Upload
    if "/upload" in path_lower:
        methods.add(HTTPMethod.POST)

    # Search
    if "/search" in path_lower:
        methods.add(HTTPMethod.POST)

    return methods
