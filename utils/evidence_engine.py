"""
Evidence Engine v3.0 - PHANTOM AI Enterprise Edition
=====================================================

Systematic evidence collection for ironclad proof of vulnerabilities.

Key Features:
- Automatic screenshot capture at key moments
- HTTP request/response pair recording with timing
- Timeline reconstruction of attack sequences
- curl command generation for reproduction
- Evidence package compilation for findings
- Video-like replay capability

Philosophy:
"Capture everything, filter for reports later."
Evidence collection is PROACTIVE - we capture before we know if it's relevant.

Usage:
    from utils.evidence_engine import EvidenceEngine, get_evidence_engine

    engine = get_evidence_engine()

    # Start evidence session
    session = engine.start_session(target="https://example.com", scan_id="scan_123")

    # Capture HTTP evidence
    evidence_id = await engine.capture_http(
        request=request_data,
        response=response_data,
        context="SQLi test on login endpoint"
    )

    # Capture screenshot
    screenshot_id = await engine.capture_screenshot(
        url="https://example.com/admin",
        context="Admin panel access after auth bypass"
    )

    # Generate evidence package for finding
    package = engine.compile_evidence_package(
        finding_id="FINDING_001",
        evidence_ids=[evidence_id, screenshot_id]
    )

Author: PHANTOM AI Enterprise Division
Version: 3.0.0
"""

from __future__ import annotations

import base64
import json
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from utils.logger import get_logger

logger = get_logger(__name__)


class EvidenceType(Enum):
    """Types of evidence that can be collected."""
    HTTP_REQUEST_RESPONSE = auto()  # Full HTTP transaction
    SCREENSHOT = auto()              # Browser screenshot
    DOM_SNAPSHOT = auto()            # DOM state capture
    CONSOLE_LOG = auto()             # Browser console output
    NETWORK_HAR = auto()             # HAR file from browser
    TIMING_DATA = auto()             # Response timing information
    DIFF_COMPARISON = auto()         # Before/after comparison
    VIDEO_RECORDING = auto()         # Screen recording
    CURL_COMMAND = auto()            # Reproducible curl command
    RAW_RESPONSE = auto()            # Raw response bytes
    INJECTED_PAYLOAD = auto()        # The payload that triggered the vuln
    ERROR_MESSAGE = auto()           # Error messages captured
    STACK_TRACE = auto()             # Stack traces exposed


class EvidenceConfidence(Enum):
    """Confidence level of evidence."""
    DEFINITIVE = "definitive"    # 100% proves the vulnerability
    STRONG = "strong"            # Very strong indication
    MODERATE = "moderate"        # Supports the finding
    WEAK = "weak"                # Circumstantial evidence
    SUPPLEMENTARY = "supplementary"  # Additional context only


@dataclass
class HTTPEvidence:
    """Evidence from an HTTP transaction."""
    request_method: str
    request_url: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    response_status: int
    response_headers: Dict[str, str]
    response_body: str
    response_time_ms: float
    timestamp: datetime = field(default_factory=datetime.now)

    # Analysis fields
    payload_reflected: bool = False
    error_triggered: bool = False
    timing_anomaly: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request": {
                "method": self.request_method,
                "url": self.request_url,
                "headers": self.request_headers,
                "body": self.request_body,
            },
            "response": {
                "status": self.response_status,
                "headers": self.response_headers,
                "body": self.response_body[:10000] if self.response_body else None,  # Truncate large bodies
                "time_ms": self.response_time_ms,
            },
            "timestamp": self.timestamp.isoformat(),
            "analysis": {
                "payload_reflected": self.payload_reflected,
                "error_triggered": self.error_triggered,
                "timing_anomaly": self.timing_anomaly,
            }
        }


@dataclass
class ScreenshotEvidence:
    """Evidence from a screenshot capture."""
    url: str
    screenshot_path: str
    screenshot_base64: Optional[str] = None  # For embedding in reports
    width: int = 0
    height: int = 0
    timestamp: datetime = field(default_factory=datetime.now)
    context: str = ""
    highlighted_elements: List[str] = field(default_factory=list)  # CSS selectors

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "path": self.screenshot_path,
            "dimensions": {"width": self.width, "height": self.height},
            "timestamp": self.timestamp.isoformat(),
            "context": self.context,
            "highlights": self.highlighted_elements,
        }


@dataclass
class TimelineEvent:
    """A single event in the attack timeline."""
    timestamp: datetime
    event_type: str  # e.g., "request", "response", "screenshot", "finding"
    description: str
    evidence_id: Optional[str] = None
    url: Optional[str] = None
    severity: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "time_offset_ms": 0,  # Will be calculated relative to session start
            "type": self.event_type,
            "description": self.description,
            "evidence_id": self.evidence_id,
            "url": self.url,
            "severity": self.severity,
            "details": self.details,
        }


@dataclass
class EvidenceItem:
    """A single piece of evidence."""
    id: str
    type: EvidenceType
    confidence: EvidenceConfidence
    timestamp: datetime
    context: str
    data: Union[HTTPEvidence, ScreenshotEvidence, Dict[str, Any]]
    finding_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data_dict = self.data.to_dict() if hasattr(self.data, 'to_dict') else self.data
        return {
            "id": self.id,
            "type": self.type.name,
            "confidence": self.confidence.value,
            "timestamp": self.timestamp.isoformat(),
            "context": self.context,
            "data": data_dict,
            "finding_id": self.finding_id,
            "tags": self.tags,
        }


@dataclass
class EvidencePackage:
    """Compiled evidence package for a finding."""
    finding_id: str
    finding_type: str
    severity: str
    target_url: str
    evidence_items: List[EvidenceItem]
    timeline: List[TimelineEvent]
    curl_commands: List[str]
    reproduction_steps: List[str]
    impact_demonstration: str
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "target_url": self.target_url,
            "evidence_count": len(self.evidence_items),
            "evidence": [e.to_dict() for e in self.evidence_items],
            "timeline": [t.to_dict() for t in self.timeline],
            "curl_commands": self.curl_commands,
            "reproduction_steps": self.reproduction_steps,
            "impact_demonstration": self.impact_demonstration,
            "created_at": self.created_at.isoformat(),
        }

    def to_markdown(self) -> str:
        """Generate markdown report for evidence package."""
        md = []
        md.append(f"# Evidence Package: {self.finding_id}")
        md.append(f"\n**Finding Type:** {self.finding_type}")
        md.append(f"\n**Severity:** {self.severity}")
        md.append(f"\n**Target:** {self.target_url}")
        md.append(f"\n**Generated:** {self.created_at.isoformat()}")

        md.append("\n\n## Timeline")
        md.append("\n| Time | Event | Description |")
        md.append("| ---- | ----- | ----------- |")
        for event in sorted(self.timeline, key=lambda x: x.timestamp):
            md.append(f"| {event.timestamp.strftime('%H:%M:%S.%f')[:-3]} | {event.event_type} | {event.description} |")

        md.append("\n\n## Reproduction Steps")
        for i, step in enumerate(self.reproduction_steps, 1):
            md.append(f"\n{i}. {step}")

        md.append("\n\n## curl Commands")
        for cmd in self.curl_commands:
            md.append(f"\n```bash\n{cmd}\n```")

        md.append("\n\n## Impact Demonstration")
        md.append(f"\n{self.impact_demonstration}")

        md.append("\n\n## Evidence Items")
        for evidence in self.evidence_items:
            md.append(f"\n### {evidence.id} ({evidence.type.name})")
            md.append(f"\n**Confidence:** {evidence.confidence.value}")
            md.append(f"\n**Context:** {evidence.context}")

            if evidence.type == EvidenceType.HTTP_REQUEST_RESPONSE:
                data = evidence.data
                if isinstance(data, HTTPEvidence):
                    md.append(f"\n\n**Request:** `{data.request_method} {data.request_url}`")
                    md.append(f"\n**Response:** `{data.response_status}` ({data.response_time_ms:.0f}ms)")
            elif evidence.type == EvidenceType.SCREENSHOT:
                data = evidence.data
                if isinstance(data, ScreenshotEvidence):
                    md.append(f"\n\n**Screenshot:** {data.url}")
                    md.append(f"\n![Screenshot]({data.screenshot_path})")

        return "\n".join(md)


@dataclass
class EvidenceSession:
    """Active evidence collection session."""
    session_id: str
    target: str
    scan_id: str
    started_at: datetime
    evidence_items: Dict[str, EvidenceItem] = field(default_factory=dict)
    timeline: List[TimelineEvent] = field(default_factory=list)
    findings_evidence: Dict[str, List[str]] = field(default_factory=dict)  # finding_id -> evidence_ids
    storage_path: Path = field(default_factory=lambda: Path(tempfile.mkdtemp(prefix="phantom_evidence_")))

    def add_evidence(self, evidence: EvidenceItem) -> None:
        """Add evidence to session."""
        self.evidence_items[evidence.id] = evidence

        # Add to timeline
        self.timeline.append(TimelineEvent(
            timestamp=evidence.timestamp,
            event_type=evidence.type.name.lower(),
            description=evidence.context,
            evidence_id=evidence.id,
        ))

    def link_evidence_to_finding(self, evidence_id: str, finding_id: str) -> None:
        """Link evidence to a specific finding."""
        if finding_id not in self.findings_evidence:
            self.findings_evidence[finding_id] = []
        if evidence_id not in self.findings_evidence[finding_id]:
            self.findings_evidence[finding_id].append(evidence_id)

        # Update evidence item
        if evidence_id in self.evidence_items:
            self.evidence_items[evidence_id].finding_id = finding_id


class EvidenceEngine:
    """
    Enterprise Evidence Engine for PHANTOM AI.

    Provides systematic, proactive evidence collection:
    - Automatic screenshot capture
    - HTTP request/response recording
    - Timeline reconstruction
    - curl command generation
    - Evidence package compilation
    """

    VERSION = "3.0.0"

    def __init__(self, storage_base: Optional[Path] = None):
        """Initialize Evidence Engine."""
        self.storage_base = storage_base or Path.home() / ".phantom" / "evidence"
        self.storage_base.mkdir(parents=True, exist_ok=True)

        self._sessions: Dict[str, EvidenceSession] = {}
        self._active_session: Optional[EvidenceSession] = None
        self._evidence_counter = 0
        self._browser_available = False

        # Check for browser availability
        self._check_browser_availability()

        logger.info(f"EvidenceEngine v{self.VERSION} initialized (screenshots: {self._browser_available})")

    def _check_browser_availability(self) -> None:
        """Check if headless browser is available for screenshots."""
        try:
            from utils.headless_browser import is_playwright_available
            self._browser_available = is_playwright_available()
        except ImportError:
            self._browser_available = False

    def _generate_evidence_id(self) -> str:
        """Generate unique evidence ID."""
        self._evidence_counter += 1
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        return f"EV_{timestamp}_{self._evidence_counter:04d}"

    def start_session(self, target: str, scan_id: str) -> EvidenceSession:
        """Start a new evidence collection session."""
        session_id = f"SESSION_{scan_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}"

        # Create session storage directory
        session_path = self.storage_base / session_id
        session_path.mkdir(parents=True, exist_ok=True)

        session = EvidenceSession(
            session_id=session_id,
            target=target,
            scan_id=scan_id,
            started_at=datetime.now(),
            storage_path=session_path,
        )

        self._sessions[session_id] = session
        self._active_session = session

        # Add session start event to timeline
        session.timeline.append(TimelineEvent(
            timestamp=session.started_at,
            event_type="session_start",
            description=f"Evidence collection started for {target}",
            url=target,
        ))

        logger.info(f"Evidence session started: {session_id}")
        return session

    def get_active_session(self) -> Optional[EvidenceSession]:
        """Get the currently active session."""
        return self._active_session

    def get_session(self, session_id: str) -> Optional[EvidenceSession]:
        """Get a specific session by ID."""
        return self._sessions.get(session_id)

    async def capture_http(
        self,
        request_method: str,
        request_url: str,
        request_headers: Dict[str, str],
        request_body: Optional[str],
        response_status: int,
        response_headers: Dict[str, str],
        response_body: str,
        response_time_ms: float,
        context: str = "",
        payload: Optional[str] = None,
        confidence: EvidenceConfidence = EvidenceConfidence.MODERATE,
        tags: Optional[List[str]] = None,
    ) -> str:
        """
        Capture HTTP request/response as evidence.

        Returns:
            Evidence ID
        """
        session = self._active_session
        if not session:
            logger.warning("No active evidence session - creating temporary session")
            session = self.start_session(request_url, "temp")

        evidence_id = self._generate_evidence_id()

        # Analyze the response
        payload_reflected = False
        error_triggered = False
        timing_anomaly = False

        if payload and response_body:
            payload_reflected = payload in response_body

        # Check for error indicators
        error_patterns = [
            "error", "exception", "warning", "fatal", "syntax",
            "mysql", "postgresql", "oracle", "sql", "stack trace",
            "undefined", "null reference", "traceback"
        ]
        response_lower = response_body.lower() if response_body else ""
        error_triggered = any(p in response_lower for p in error_patterns)

        # Check for timing anomaly (>5s response time)
        timing_anomaly = response_time_ms > 5000

        http_evidence = HTTPEvidence(
            request_method=request_method,
            request_url=request_url,
            request_headers=request_headers,
            request_body=request_body,
            response_status=response_status,
            response_headers=response_headers,
            response_body=response_body,
            response_time_ms=response_time_ms,
            payload_reflected=payload_reflected,
            error_triggered=error_triggered,
            timing_anomaly=timing_anomaly,
        )

        evidence_item = EvidenceItem(
            id=evidence_id,
            type=EvidenceType.HTTP_REQUEST_RESPONSE,
            confidence=confidence,
            timestamp=datetime.now(),
            context=context or f"{request_method} {request_url}",
            data=http_evidence,
            tags=tags or [],
        )

        # Add payload tag if provided
        if payload:
            evidence_item.tags.append("has_payload")
            if payload_reflected:
                evidence_item.tags.append("payload_reflected")
        if error_triggered:
            evidence_item.tags.append("error_triggered")
        if timing_anomaly:
            evidence_item.tags.append("timing_anomaly")

        session.add_evidence(evidence_item)

        # Save raw evidence to disk
        evidence_file = session.storage_path / f"{evidence_id}.json"
        evidence_file.write_text(json.dumps(evidence_item.to_dict(), indent=2, default=str))

        logger.debug(f"HTTP evidence captured: {evidence_id}")
        return evidence_id

    async def capture_screenshot(
        self,
        url: str,
        context: str = "",
        full_page: bool = True,
        highlight_selectors: Optional[List[str]] = None,
        wait_for_selector: Optional[str] = None,
        confidence: EvidenceConfidence = EvidenceConfidence.STRONG,
        tags: Optional[List[str]] = None,
    ) -> Optional[str]:
        """
        Capture screenshot as evidence.

        Returns:
            Evidence ID or None if screenshot failed
        """
        if not self._browser_available:
            logger.warning("Browser not available for screenshots")
            return None

        session = self._active_session
        if not session:
            logger.warning("No active evidence session")
            return None

        evidence_id = self._generate_evidence_id()
        screenshot_path = session.storage_path / f"{evidence_id}.png"

        try:
            from utils.headless_browser import (
                HeadlessBrowserEngine,
                BrowserConfig,
                BrowserType,
                SecurityLevel,
            )

            config = BrowserConfig(
                browser_type=BrowserType.CHROMIUM,
                headless=True,
                security_level=SecurityLevel.RELAXED,
                timeout=30000,
            )

            async with HeadlessBrowserEngine(config) as browser:
                # Navigate to URL
                await browser.navigate(url, wait_until="networkidle")

                # Wait for specific selector if provided
                if wait_for_selector:
                    try:
                        page = browser._page
                        await page.wait_for_selector(wait_for_selector, timeout=5000)
                    except Exception:
                        pass

                # Highlight elements if selectors provided
                if highlight_selectors:
                    page = browser._page
                    for selector in highlight_selectors:
                        try:
                            await page.evaluate(f'''
                                document.querySelectorAll("{selector}").forEach(el => {{
                                    el.style.border = "3px solid red";
                                    el.style.backgroundColor = "rgba(255, 0, 0, 0.1)";
                                }});
                            ''')
                        except Exception:
                            pass

                # Take screenshot
                page = browser._page
                screenshot_bytes = await page.screenshot(
                    path=str(screenshot_path),
                    full_page=full_page,
                )

                # Get viewport size
                viewport = page.viewport_size or {"width": 1280, "height": 720}

                # Encode to base64 for embedding
                screenshot_base64 = base64.b64encode(screenshot_bytes).decode('utf-8')

            screenshot_evidence = ScreenshotEvidence(
                url=url,
                screenshot_path=str(screenshot_path),
                screenshot_base64=screenshot_base64[:1000] + "..." if len(screenshot_base64) > 1000 else screenshot_base64,
                width=viewport["width"],
                height=viewport["height"],
                context=context,
                highlighted_elements=highlight_selectors or [],
            )

            evidence_item = EvidenceItem(
                id=evidence_id,
                type=EvidenceType.SCREENSHOT,
                confidence=confidence,
                timestamp=datetime.now(),
                context=context or f"Screenshot of {url}",
                data=screenshot_evidence,
                tags=tags or ["screenshot"],
            )

            session.add_evidence(evidence_item)

            logger.info(f"Screenshot captured: {evidence_id} -> {screenshot_path}")
            return evidence_id

        except Exception as e:
            logger.error(f"Screenshot capture failed: {e}")
            return None

    async def capture_dom_snapshot(
        self,
        url: str,
        context: str = "",
        confidence: EvidenceConfidence = EvidenceConfidence.MODERATE,
    ) -> Optional[str]:
        """Capture DOM snapshot as evidence."""
        if not self._browser_available:
            return None

        session = self._active_session
        if not session:
            return None

        evidence_id = self._generate_evidence_id()

        try:
            from utils.headless_browser import (
                HeadlessBrowserEngine,
                BrowserConfig,
                BrowserType,
                SecurityLevel,
            )

            config = BrowserConfig(
                browser_type=BrowserType.CHROMIUM,
                headless=True,
                security_level=SecurityLevel.RELAXED,
                timeout=30000,
            )

            async with HeadlessBrowserEngine(config) as browser:
                await browser.navigate(url, wait_until="networkidle")
                page = browser._page

                # Get full DOM
                dom_content = await page.content()

                # Get computed styles for key elements
                styles_info = await page.evaluate('''() => {
                    const elements = document.querySelectorAll('input, form, a, button');
                    return Array.from(elements).slice(0, 50).map(el => ({
                        tag: el.tagName,
                        id: el.id,
                        name: el.name,
                        type: el.type,
                        href: el.href,
                        action: el.action,
                    }));
                }''')

            dom_data = {
                "url": url,
                "dom_html": dom_content[:50000],  # Truncate large DOMs
                "elements": styles_info,
                "timestamp": datetime.now().isoformat(),
            }

            evidence_item = EvidenceItem(
                id=evidence_id,
                type=EvidenceType.DOM_SNAPSHOT,
                confidence=confidence,
                timestamp=datetime.now(),
                context=context or f"DOM snapshot of {url}",
                data=dom_data,
                tags=["dom"],
            )

            session.add_evidence(evidence_item)

            # Save to disk
            dom_file = session.storage_path / f"{evidence_id}_dom.html"
            dom_file.write_text(dom_content)

            logger.debug(f"DOM snapshot captured: {evidence_id}")
            return evidence_id

        except Exception as e:
            logger.error(f"DOM snapshot failed: {e}")
            return None

    def generate_curl_command(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[str] = None,
        include_cookies: bool = True,
    ) -> str:
        """
        Generate curl command for reproducing a request.

        Returns:
            curl command string
        """
        parts = ["curl", "-X", method]

        # Add URL
        parts.append(f"'{url}'")

        # Add headers
        for key, value in headers.items():
            # Skip certain headers
            if key.lower() in ['host', 'content-length', 'connection']:
                continue
            # Escape single quotes in header values
            escaped_value = value.replace("'", "'\\''")
            parts.append(f"-H '{key}: {escaped_value}'")

        # Add body if present
        if body:
            # Escape single quotes
            escaped_body = body.replace("'", "'\\''")
            parts.append(f"-d '{escaped_body}'")

        # Add common options
        parts.append("-i")  # Include response headers
        parts.append("-s")  # Silent mode
        parts.append("-k")  # Allow insecure

        return " \\\n  ".join(parts)

    def add_timeline_event(
        self,
        event_type: str,
        description: str,
        url: Optional[str] = None,
        severity: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add a custom event to the timeline."""
        session = self._active_session
        if not session:
            return

        event = TimelineEvent(
            timestamp=datetime.now(),
            event_type=event_type,
            description=description,
            url=url,
            severity=severity,
            details=details or {},
        )
        session.timeline.append(event)

    def link_to_finding(self, evidence_id: str, finding_id: str) -> None:
        """Link evidence to a finding."""
        session = self._active_session
        if session:
            session.link_evidence_to_finding(evidence_id, finding_id)

    def compile_evidence_package(
        self,
        finding_id: str,
        finding_type: str,
        severity: str,
        target_url: str,
        evidence_ids: Optional[List[str]] = None,
        reproduction_steps: Optional[List[str]] = None,
        impact_demonstration: str = "",
    ) -> EvidencePackage:
        """
        Compile evidence package for a finding.

        Args:
            finding_id: ID of the finding
            finding_type: Type of vulnerability (e.g., "SQLi", "XSS")
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
            target_url: Target URL
            evidence_ids: Specific evidence IDs to include (None = auto-detect)
            reproduction_steps: Manual reproduction steps
            impact_demonstration: Description of impact

        Returns:
            EvidencePackage with all compiled evidence
        """
        session = self._active_session
        if not session:
            logger.warning("No active session for evidence package")
            return EvidencePackage(
                finding_id=finding_id,
                finding_type=finding_type,
                severity=severity,
                target_url=target_url,
                evidence_items=[],
                timeline=[],
                curl_commands=[],
                reproduction_steps=reproduction_steps or [],
                impact_demonstration=impact_demonstration,
            )

        # Get evidence IDs - either explicit or linked to finding
        if evidence_ids is None:
            evidence_ids = session.findings_evidence.get(finding_id, [])

        # Collect evidence items
        evidence_items = []
        curl_commands = []

        for eid in evidence_ids:
            if eid in session.evidence_items:
                item = session.evidence_items[eid]
                evidence_items.append(item)

                # Generate curl command for HTTP evidence
                if item.type == EvidenceType.HTTP_REQUEST_RESPONSE:
                    data = item.data
                    if isinstance(data, HTTPEvidence):
                        curl_cmd = self.generate_curl_command(
                            method=data.request_method,
                            url=data.request_url,
                            headers=data.request_headers,
                            body=data.request_body,
                        )
                        curl_commands.append(curl_cmd)

        # Get relevant timeline events
        timeline = []
        for event in session.timeline:
            # Include session start, all linked evidence, and findings
            if (event.evidence_id in evidence_ids or
                event.event_type in ["session_start", "finding", "vulnerability"]):
                timeline.append(event)

        # Calculate time offsets
        if timeline:
            start_time = min(e.timestamp for e in timeline)
            for event in timeline:
                offset_ms = (event.timestamp - start_time).total_seconds() * 1000
                event.details["time_offset_ms"] = offset_ms

        # Generate default reproduction steps if not provided
        if not reproduction_steps:
            reproduction_steps = self._generate_reproduction_steps(
                finding_type, target_url, evidence_items
            )

        # Generate impact demonstration if not provided
        if not impact_demonstration:
            impact_demonstration = self._generate_impact_description(
                finding_type, severity, evidence_items
            )

        package = EvidencePackage(
            finding_id=finding_id,
            finding_type=finding_type,
            severity=severity,
            target_url=target_url,
            evidence_items=evidence_items,
            timeline=sorted(timeline, key=lambda x: x.timestamp),
            curl_commands=curl_commands,
            reproduction_steps=reproduction_steps,
            impact_demonstration=impact_demonstration,
        )

        # Save package to disk
        package_file = session.storage_path / f"package_{finding_id}.json"
        package_file.write_text(json.dumps(package.to_dict(), indent=2, default=str))

        # Also save markdown report
        md_file = session.storage_path / f"package_{finding_id}.md"
        md_file.write_text(package.to_markdown())

        logger.info(f"Evidence package compiled: {finding_id} ({len(evidence_items)} items)")
        return package

    def _generate_reproduction_steps(
        self,
        finding_type: str,
        target_url: str,
        evidence_items: List[EvidenceItem],
    ) -> List[str]:
        """Generate reproduction steps from evidence."""
        steps = []
        steps.append(f"Navigate to: {target_url}")

        for item in evidence_items:
            if item.type == EvidenceType.HTTP_REQUEST_RESPONSE:
                data = item.data
                if isinstance(data, HTTPEvidence):
                    steps.append(f"Send {data.request_method} request to {data.request_url}")
                    if data.request_body:
                        steps.append(f"With body: {data.request_body[:100]}...")
                    steps.append(f"Observe response (status {data.response_status})")
                    if data.payload_reflected:
                        steps.append("Note: Payload is reflected in response")
                    if data.error_triggered:
                        steps.append("Note: Error message visible in response")
            elif item.type == EvidenceType.SCREENSHOT:
                data = item.data
                if isinstance(data, ScreenshotEvidence):
                    steps.append(f"Observe visual result (see screenshot: {data.screenshot_path})")

        return steps

    def _generate_impact_description(
        self,
        finding_type: str,
        severity: str,
        evidence_items: List[EvidenceItem],
    ) -> str:
        """Generate impact description based on finding type and evidence."""
        impact_templates = {
            "sqli": "SQL Injection allows attackers to read, modify, or delete database contents. "
                    "In severe cases, it can lead to complete database compromise or remote code execution.",
            "xss": "Cross-Site Scripting allows attackers to execute malicious scripts in users' browsers, "
                   "potentially stealing session tokens, credentials, or performing actions on behalf of victims.",
            "idor": "Insecure Direct Object Reference allows unauthorized access to other users' data "
                    "by manipulating object identifiers. This can lead to mass data exposure.",
            "ssrf": "Server-Side Request Forgery allows attackers to make requests from the server, "
                    "potentially accessing internal services, cloud metadata, or sensitive endpoints.",
            "lfi": "Local File Inclusion allows attackers to read arbitrary files from the server, "
                   "including configuration files, source code, or sensitive data.",
            "rce": "Remote Code Execution allows attackers to execute arbitrary commands on the server, "
                   "leading to complete system compromise.",
            "auth_bypass": "Authentication Bypass allows attackers to access protected resources "
                          "without valid credentials, potentially compromising all user accounts.",
        }

        base_impact = impact_templates.get(
            finding_type.lower().replace(" ", "_").replace("-", "_"),
            f"This {finding_type} vulnerability can be exploited by attackers to compromise application security."
        )

        # Add severity context
        severity_context = {
            "CRITICAL": "This is a critical severity issue requiring immediate remediation.",
            "HIGH": "This high severity issue should be addressed as a priority.",
            "MEDIUM": "This medium severity issue should be scheduled for remediation.",
            "LOW": "This low severity issue should be addressed when resources allow.",
        }

        return f"{base_impact} {severity_context.get(severity.upper(), '')}"

    def end_session(self, session_id: Optional[str] = None) -> Optional[Path]:
        """
        End evidence collection session.

        Returns:
            Path to session storage directory
        """
        session = self._sessions.get(session_id) if session_id else self._active_session
        if not session:
            return None

        # Add session end event
        session.timeline.append(TimelineEvent(
            timestamp=datetime.now(),
            event_type="session_end",
            description="Evidence collection completed",
        ))

        # Save session summary
        summary = {
            "session_id": session.session_id,
            "target": session.target,
            "scan_id": session.scan_id,
            "started_at": session.started_at.isoformat(),
            "ended_at": datetime.now().isoformat(),
            "evidence_count": len(session.evidence_items),
            "findings_documented": len(session.findings_evidence),
            "timeline_events": len(session.timeline),
        }

        summary_file = session.storage_path / "session_summary.json"
        summary_file.write_text(json.dumps(summary, indent=2))

        # Save full timeline
        timeline_file = session.storage_path / "timeline.json"
        timeline_file.write_text(json.dumps(
            [e.to_dict() for e in session.timeline],
            indent=2,
            default=str
        ))

        logger.info(f"Evidence session ended: {session.session_id} ({len(session.evidence_items)} items)")

        if self._active_session == session:
            self._active_session = None

        return session.storage_path

    def get_statistics(self) -> Dict[str, Any]:
        """Get evidence collection statistics."""
        session = self._active_session
        if not session:
            return {"active": False}

        type_counts = {}
        for item in session.evidence_items.values():
            type_name = item.type.name
            type_counts[type_name] = type_counts.get(type_name, 0) + 1

        return {
            "active": True,
            "session_id": session.session_id,
            "target": session.target,
            "evidence_count": len(session.evidence_items),
            "timeline_events": len(session.timeline),
            "findings_documented": len(session.findings_evidence),
            "evidence_by_type": type_counts,
            "storage_path": str(session.storage_path),
        }


# Singleton instance
_evidence_engine: Optional[EvidenceEngine] = None


def get_evidence_engine() -> EvidenceEngine:
    """Get the global Evidence Engine instance."""
    global _evidence_engine
    if _evidence_engine is None:
        _evidence_engine = EvidenceEngine()
    return _evidence_engine


def reset_evidence_engine() -> None:
    """Reset the global Evidence Engine instance."""
    global _evidence_engine
    _evidence_engine = None
