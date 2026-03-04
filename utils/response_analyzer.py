"""
Response Analyzer - False Positive Prevention Engine v1.1.0

This module provides intelligent response analysis to prevent false positives:
1. Response Fingerprinting - baseline per endpoint for comparison
2. Payload Echo Detection - detect escaped/reflected payloads
3. Confidence Engine - real scoring system with +/- points
4. SPA Normalization (GAP-1) - handles SPAs that return 200+homepage for any path
5. Framework-Aware Analysis - adapts to modern frameworks (Next.js, Nuxt, etc.)

Without this, scanners would flag any 200 OK as a finding.

Author: PenTester AI
Date: Janeiro 2026
Updated: 2026-02-13 (GAP-1 Sprint 4 - SPA Normalization)
"""

from __future__ import annotations

import hashlib
import html
import json
import re
import statistics
import time
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from enum import Enum, auto
from typing import Any

import httpx

from utils.logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# VERSION & CONSTANTS
# =============================================================================

RESPONSE_ANALYZER_VERSION = "1.1.0-ENTERPRISE"

# Similarity thresholds
BODY_SIMILARITY_THRESHOLD = 0.95  # 95% similar = same response
TIMING_ANOMALY_THRESHOLD = 3.0    # 3x baseline = timing anomaly
CONTENT_LENGTH_TOLERANCE = 0.10   # 10% tolerance

# GAP-1 FIX: SPA Detection patterns
SPA_INDICATORS = [
    r"<div\s+id=['\"](?:root|app|__next|__nuxt)['\"]",
    r"<script[^>]*type=['\"]module['\"]",
    r"window\.__(?:NEXT|NUXT|INITIAL)_",
    r"data-(?:react|vue|svelte|angular)",
    r"<noscript>.*(?:enable|requires?).*javascript",
    r"ng-version",  # Angular
    r"<app-root",  # Angular root component
    r"_nghost",  # Angular attribute
]

# GAP-1 FIX: Dynamic content patterns to strip for normalization
DYNAMIC_CONTENT_PATTERNS = [
    (r'name=["\']csrf[_-]?token["\'][^>]*value=["\'][^"\']+["\']', 'name="csrf_token" value="STRIPPED"'),
    (r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', 'TIMESTAMP'),
    (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'UUID'),
    (r'nonce=["\'][^"\']+["\']', 'nonce="STRIPPED"'),
    (r'"_csrf"\s*:\s*"[^"]+"', '"_csrf": "STRIPPED"'),
    (r'"token"\s*:\s*"[^"]+"', '"token": "STRIPPED"'),
]


# =============================================================================
# ENUMS
# =============================================================================

class ConfidenceLevel(Enum):
    """Confidence level for findings."""
    NONE = 0           # No evidence
    LOW = 1            # Weak indicators
    MEDIUM = 2         # Some evidence
    HIGH = 3           # Strong evidence
    CONFIRMED = 4      # Verified vulnerability
    
    @classmethod
    def from_score(cls, score: int) -> ConfidenceLevel:
        """Convert numeric score to confidence level."""
        if score >= 90:
            return cls.CONFIRMED
        elif score >= 70:
            return cls.HIGH
        elif score >= 50:
            return cls.MEDIUM
        elif score >= 25:
            return cls.LOW
        else:
            return cls.NONE


class EchoType(Enum):
    """Type of payload reflection/echo."""
    NOT_REFLECTED = auto()        # Payload not found in response
    REFLECTED_RAW = auto()        # Payload reflected as-is (dangerous)
    REFLECTED_ESCAPED = auto()    # Payload HTML-escaped (safe)
    REFLECTED_URL_ENCODED = auto() # Payload URL-encoded
    REFLECTED_JSON_ESCAPED = auto() # Payload JSON-escaped
    REFLECTED_IN_COMMENT = auto()  # Payload in HTML/JS comment
    REFLECTED_IN_ATTRIBUTE = auto() # Payload in HTML attribute
    REFLECTED_IN_JS = auto()       # Payload in JavaScript context
    REFLECTED_PARTIAL = auto()     # Only part of payload reflected


class ResponseDiffType(Enum):
    """Type of difference from baseline."""
    IDENTICAL = auto()           # Exactly the same
    SIMILAR = auto()             # Minor differences (noise)
    STATUS_CHANGED = auto()      # Different status code
    LENGTH_CHANGED = auto()      # Significant length difference
    STRUCTURE_CHANGED = auto()   # Different HTML/JSON structure
    ERROR_TRIGGERED = auto()     # Error message appeared
    TIMING_ANOMALY = auto()      # Unusual response time
    HEADERS_CHANGED = auto()     # Different headers


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class ResponseFingerprint:
    """
    Fingerprint of a baseline response.
    Used to compare test responses against normal behavior.
    """
    url: str
    method: str
    status_code: int
    content_length: int
    content_type: str
    body_hash: str              # SHA256 of body
    body_fuzzy_hash: str        # Fuzzy hash for similarity
    structure_hash: str         # Hash of HTML/JSON structure
    headers_hash: str           # Hash of stable headers
    response_time_ms: float
    
    # Statistical data (updated over multiple requests)
    response_times: list[float] = field(default_factory=list)
    content_lengths: list[int] = field(default_factory=list)
    sample_count: int = 1
    
    # Content analysis
    has_error_page: bool = False
    is_json: bool = False
    is_html: bool = False
    
    def avg_response_time(self) -> float:
        """Get average response time."""
        if self.response_times:
            return statistics.mean(self.response_times)
        return self.response_time_ms
    
    def stddev_response_time(self) -> float:
        """Get standard deviation of response time."""
        if len(self.response_times) >= 2:
            return statistics.stdev(self.response_times)
        return 0.0
    
    def avg_content_length(self) -> float:
        """Get average content length."""
        if self.content_lengths:
            return statistics.mean(self.content_lengths)
        return float(self.content_length)
    
    def update(self, response: httpx.Response, response_time_ms: float) -> None:
        """Update fingerprint with new sample."""
        self.response_times.append(response_time_ms)
        self.content_lengths.append(len(response.content))
        self.sample_count += 1
        
        # Keep only last 10 samples
        if len(self.response_times) > 10:
            self.response_times = self.response_times[-10:]
            self.content_lengths = self.content_lengths[-10:]


@dataclass
class EchoAnalysis:
    """Result of payload echo/reflection analysis."""
    payload: str
    echo_type: EchoType
    reflected_value: str = ""
    context: str = ""           # Where it was found (tag, attribute, etc.)
    is_executable: bool = False # Would it execute?
    escape_method: str = ""     # How it was escaped
    position: int = -1          # Position in response
    
    def is_dangerous(self) -> bool:
        """Check if reflection is potentially dangerous."""
        return self.echo_type == EchoType.REFLECTED_RAW and self.is_executable


@dataclass
class ResponseDiff:
    """Difference analysis between baseline and test response."""
    diff_type: ResponseDiffType
    baseline: ResponseFingerprint
    
    # Specific differences
    status_diff: tuple[int, int] | None = None       # (baseline, test)
    length_diff: tuple[int, int] | None = None       # (baseline, test)
    timing_diff: tuple[float, float] | None = None   # (baseline, test)
    similarity_score: float = 1.0                    # 0.0-1.0
    
    # Detected changes
    new_errors: list[str] = field(default_factory=list)
    new_headers: list[str] = field(default_factory=list)
    removed_headers: list[str] = field(default_factory=list)
    structure_changes: list[str] = field(default_factory=list)


@dataclass
class ConfidenceScore:
    """
    Detailed confidence scoring for a finding.
    Uses a point system instead of simple if/else.
    """
    total_score: int = 0
    level: ConfidenceLevel = ConfidenceLevel.NONE
    
    # Point breakdown
    points: dict[str, int] = field(default_factory=dict)
    
    # Reasoning
    positive_indicators: list[str] = field(default_factory=list)
    negative_indicators: list[str] = field(default_factory=list)
    
    def add_points(self, reason: str, points: int) -> None:
        """Add points to the score."""
        self.points[reason] = points
        self.total_score += points
        
        if points > 0:
            self.positive_indicators.append(f"+{points}: {reason}")
        else:
            self.negative_indicators.append(f"{points}: {reason}")
        
        # Update level
        self.level = ConfidenceLevel.from_score(self.total_score)
    
    def get_breakdown(self) -> str:
        """Get human-readable score breakdown."""
        lines = [f"Total Score: {self.total_score} ({self.level.name})"]
        lines.append("\nPositive Indicators:")
        for indicator in self.positive_indicators:
            lines.append(f"  {indicator}")
        lines.append("\nNegative Indicators:")
        for indicator in self.negative_indicators:
            lines.append(f"  {indicator}")
        return "\n".join(lines)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_score": self.total_score,
            "level": self.level.name,
            "points": self.points,
            "positive_indicators": self.positive_indicators,
            "negative_indicators": self.negative_indicators,
        }


@dataclass
class AnalysisResult:
    """Complete analysis result for a test request."""
    # Echo analysis
    echo: EchoAnalysis | None = None
    
    # Baseline comparison
    diff: ResponseDiff | None = None
    
    # Confidence scoring
    confidence: ConfidenceScore = field(default_factory=ConfidenceScore)
    
    # Final verdict
    is_finding: bool = False
    finding_type: str = ""
    evidence: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "is_finding": self.is_finding,
            "finding_type": self.finding_type,
            "confidence": self.confidence.to_dict(),
            "evidence": self.evidence,
            "echo_type": self.echo.echo_type.name if self.echo else None,
            "diff_type": self.diff.diff_type.name if self.diff else None,
        }


# =============================================================================
# RESPONSE FINGERPRINTER
# =============================================================================

class ResponseFingerprinter:
    """
    Creates and manages baseline fingerprints for endpoints.
    
    Usage:
        fingerprinter = ResponseFingerprinter()
        
        # Create baseline
        baseline = await fingerprinter.create_baseline(url)
        
        # Compare test response
        diff = fingerprinter.compare(baseline, test_response)
    """
    
    # Headers that are stable and should be tracked
    STABLE_HEADERS = {
        "content-type", "server", "x-powered-by", "x-frame-options",
        "x-content-type-options", "x-xss-protection", "content-security-policy",
        "strict-transport-security", "cache-control", "vary",
    }
    
    # Error patterns
    ERROR_PATTERNS = [
        # SQL errors
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"PostgreSQL.*ERROR",
        r"ORA-\d{5}",
        r"Microsoft.*ODBC.*SQL Server",
        r"sqlite3\.OperationalError",
        r"pg_query\(\)",
        r"System\.Data\.SqlClient",
        
        # NoSQL errors
        r"MongoError",
        r"MongoDB.*Error",
        r"CastError.*ObjectId",
        r"BSON",
        
        # Generic errors
        r"Fatal error",
        r"Uncaught exception",
        r"Stack trace:",
        r"Traceback \(most recent call last\)",
        r"Exception in thread",
        r"NullPointerException",
        r"IndexOutOfBoundsException",
        
        # Framework errors
        r"Django.*Error",
        r"Rails.*Error",
        r"Laravel.*Exception",
        r"Express.*Error",
        r"Spring.*Exception",
        
        # XML/XXE errors
        r"XML Parsing Error",
        r"SAXParseException",
        r"xmlParseEntityRef",
        r"DOMDocument::loadXML",
        
        # Path/File errors
        r"No such file or directory",
        r"failed to open stream",
        r"Permission denied",
        r"FileNotFoundException",
    ]
    
    def __init__(self):
        self._error_patterns = [re.compile(p, re.IGNORECASE) for p in self.ERROR_PATTERNS]
        self._baselines: dict[str, ResponseFingerprint] = {}
    
    async def create_baseline(
        self,
        url: str,
        method: str = "GET",
        client: httpx.AsyncClient | None = None,
        samples: int = 3,
    ) -> ResponseFingerprint:
        """
        Create a baseline fingerprint for an endpoint.
        
        Args:
            url: Target URL
            method: HTTP method
            client: Optional HTTP client
            samples: Number of samples for statistics
            
        Returns:
            ResponseFingerprint baseline
        """
        # Input validation - ensure at least 1 sample
        if samples < 1:
            samples = 1

        should_close = False
        if client is None:
            client = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                verify=False,
            )
            should_close = True

        try:
            # Collect samples
            responses: list[tuple[httpx.Response, float]] = []

            for _ in range(samples):
                try:
                    start = time.time()
                    response = await client.request(method, url)
                    elapsed = (time.time() - start) * 1000
                    responses.append((response, elapsed))

                    # Small delay between samples
                    if samples > 1:
                        await asyncio.sleep(0.1)
                except (httpx.RequestError, httpx.TimeoutException) as e:
                    logger.debug(f"Request failed during baseline sampling: {e}")
                    continue

            # Check if we have any successful responses
            if not responses:
                raise ValueError(f"Failed to collect any baseline samples for {url}")

            # Use first response for fingerprint
            response, elapsed = responses[0]
            
            fingerprint = ResponseFingerprint(
                url=url,
                method=method,
                status_code=response.status_code,
                content_length=len(response.content),
                content_type=response.headers.get("content-type", ""),
                body_hash=self._hash_body(response.content),
                body_fuzzy_hash=self._fuzzy_hash(response.content),
                structure_hash=self._structure_hash(response.content, response.headers.get("content-type", "")),
                headers_hash=self._hash_headers(response.headers),
                response_time_ms=elapsed,
                has_error_page=self._detect_error_page(response.content),
                is_json="json" in response.headers.get("content-type", "").lower(),
                is_html="html" in response.headers.get("content-type", "").lower(),
            )
            
            # Add all samples
            for resp, time_ms in responses:
                fingerprint.response_times.append(time_ms)
                fingerprint.content_lengths.append(len(resp.content))
            
            fingerprint.sample_count = len(responses)
            
            # Cache baseline
            cache_key = f"{method}:{url}"
            self._baselines[cache_key] = fingerprint
            
            logger.debug(
                f"Baseline created for {url}: "
                f"status={fingerprint.status_code}, "
                f"length={fingerprint.content_length}, "
                f"avg_time={fingerprint.avg_response_time():.0f}ms"
            )
            
            return fingerprint
            
        finally:
            if should_close:
                await client.aclose()
    
    def compare(
        self,
        baseline: ResponseFingerprint,
        response: httpx.Response,
        response_time_ms: float,
    ) -> ResponseDiff:
        """
        Compare a test response against baseline.
        
        Args:
            baseline: Baseline fingerprint
            response: Test response
            response_time_ms: Response time in ms
            
        Returns:
            ResponseDiff analysis
        """
        diff = ResponseDiff(
            diff_type=ResponseDiffType.IDENTICAL,
            baseline=baseline,
        )
        
        # Check status code - only flag MEANINGFUL status changes
        if response.status_code != baseline.status_code:
            baseline_status = baseline.status_code
            new_status = response.status_code
            diff.status_diff = (baseline_status, new_status)

            # Define meaningful security boundary crossings
            is_meaningful = False

            # 401/403 → 200/201/204 = authentication/authorization bypass
            if baseline_status in (401, 403) and new_status in (200, 201, 204):
                is_meaningful = True

            # 200/201 → 500+ = server error triggered
            elif baseline_status in (200, 201, 204) and new_status >= 500:
                is_meaningful = True

            # Any → 429 = rate limiting triggered
            elif new_status == 429:
                is_meaningful = True

            # 2xx → 4xx (not 403/401) = potential validation bypass detection
            elif 200 <= baseline_status < 300 and 400 <= new_status < 500:
                is_meaningful = True

            if is_meaningful:
                diff.diff_type = ResponseDiffType.STATUS_CHANGED
                return diff
            # Non-meaningful status change (e.g., 200→201) - continue checking other diffs
        
        # Check content length
        test_length = len(response.content)
        baseline_avg = baseline.avg_content_length()
        length_diff_pct = abs(test_length - baseline_avg) / max(baseline_avg, 1)
        
        if length_diff_pct > CONTENT_LENGTH_TOLERANCE:
            diff.diff_type = ResponseDiffType.LENGTH_CHANGED
            diff.length_diff = (int(baseline_avg), test_length)
        
        # Check timing
        baseline_avg_time = baseline.avg_response_time()
        baseline_stddev = baseline.stddev_response_time()
        
        # Use 3 standard deviations or 3x baseline (whichever is larger)
        timing_threshold = max(
            baseline_avg_time + (3 * baseline_stddev),
            baseline_avg_time * TIMING_ANOMALY_THRESHOLD
        )
        
        if response_time_ms > timing_threshold:
            diff.diff_type = ResponseDiffType.TIMING_ANOMALY
            diff.timing_diff = (baseline_avg_time, response_time_ms)
        
        # Check body similarity
        test_body_hash = self._hash_body(response.content)
        
        if test_body_hash == baseline.body_hash:
            # Identical body
            diff.similarity_score = 1.0
        else:
            # Calculate fuzzy similarity
            diff.similarity_score = self._calculate_similarity(
                baseline.body_fuzzy_hash,
                self._fuzzy_hash(response.content)
            )
            
            if diff.similarity_score < BODY_SIMILARITY_THRESHOLD:
                # Check if structure changed
                test_structure = self._structure_hash(
                    response.content,
                    response.headers.get("content-type", "")
                )
                
                if test_structure != baseline.structure_hash:
                    diff.diff_type = ResponseDiffType.STRUCTURE_CHANGED
                    diff.structure_changes = self._detect_structure_changes(
                        baseline, response
                    )
        
        # Check for new errors
        if not baseline.has_error_page:
            errors = self._extract_errors(response.content)
            if errors:
                diff.diff_type = ResponseDiffType.ERROR_TRIGGERED
                diff.new_errors = errors
        
        # Check headers
        test_headers = set(h.lower() for h in response.headers.keys())
        baseline_headers = self._get_stable_headers_from_hash(baseline.headers_hash)
        
        new_headers = test_headers - baseline_headers - {"date", "age", "x-request-id"}
        removed_headers = baseline_headers - test_headers
        
        if new_headers or removed_headers:
            if diff.diff_type == ResponseDiffType.IDENTICAL:
                diff.diff_type = ResponseDiffType.HEADERS_CHANGED
            diff.new_headers = list(new_headers)
            diff.removed_headers = list(removed_headers)
        
        # If no significant differences, mark as similar
        if diff.diff_type == ResponseDiffType.IDENTICAL and diff.similarity_score < 1.0:
            diff.diff_type = ResponseDiffType.SIMILAR
        
        return diff
    
    def get_baseline(self, url: str, method: str = "GET") -> ResponseFingerprint | None:
        """Get cached baseline for URL."""
        return self._baselines.get(f"{method}:{url}")
    
    def _hash_body(self, content: bytes) -> str:
        """Create SHA256 hash of body."""
        return hashlib.sha256(content).hexdigest()
    
    def _fuzzy_hash(self, content: bytes) -> str:
        """Create fuzzy hash for similarity comparison."""
        # Normalize content
        text = content.decode("utf-8", errors="ignore")
        
        # Remove dynamic content
        text = re.sub(r'\d{10,}', 'TIMESTAMP', text)  # Unix timestamps
        text = re.sub(r'[a-f0-9]{32,}', 'HASH', text)  # Hashes/tokens
        text = re.sub(r'\d{4}-\d{2}-\d{2}', 'DATE', text)  # Dates
        text = re.sub(r'\d+\.\d+\.\d+', 'VERSION', text)  # Versions
        text = re.sub(r'"id"\s*:\s*\d+', '"id": ID', text)  # JSON IDs
        text = re.sub(r'csrf[_-]?token["\']?\s*[=:]\s*["\']?[\w-]+', 'CSRF', text)
        
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text)
        
        return hashlib.sha256(text.encode()).hexdigest()
    
    def _structure_hash(self, content: bytes, content_type: str) -> str:
        """Create hash of document structure (ignoring content)."""
        text = content.decode("utf-8", errors="ignore")
        
        if "json" in content_type.lower():
            # JSON structure
            structure = re.sub(r'"[^"]*"', '""', text)  # Remove string values
            structure = re.sub(r'\d+\.?\d*', '0', structure)  # Remove numbers
        elif "html" in content_type.lower():
            # HTML structure - keep only tags
            structure = re.sub(r'>[^<]+<', '><', text)  # Remove text content
            structure = re.sub(r'="[^"]*"', '=""', structure)  # Remove attributes
        else:
            # Generic - just get alphanumeric structure
            structure = re.sub(r'[^a-zA-Z<>/{}[\]()]', '', text)
        
        return hashlib.sha256(structure.encode()).hexdigest()[:16]
    
    def _hash_headers(self, headers: httpx.Headers) -> str:
        """Create hash of stable headers."""
        stable = {}
        for name in self.STABLE_HEADERS:
            if name in headers:
                stable[name] = headers[name]
        
        return hashlib.sha256(
            json.dumps(stable, sort_keys=True).encode()
        ).hexdigest()[:16]
    
    def _get_stable_headers_from_hash(self, headers_hash: str) -> set[str]:
        """Get set of stable headers (simplified)."""
        # In a real implementation, we'd store this separately
        return self.STABLE_HEADERS.copy()
    
    def _detect_error_page(self, content: bytes) -> bool:
        """Detect if response is an error page."""
        text = content.decode("utf-8", errors="ignore")
        return any(p.search(text) for p in self._error_patterns)
    
    def _extract_errors(self, content: bytes) -> list[str]:
        """Extract error messages from response."""
        text = content.decode("utf-8", errors="ignore")
        errors = []
        
        for pattern in self._error_patterns:
            matches = pattern.findall(text)
            errors.extend(matches[:3])  # Limit to 3 per pattern
        
        return errors[:10]  # Max 10 errors
    
    def _calculate_similarity(self, hash1: str, hash2: str) -> float:
        """Calculate similarity between two fuzzy hashes."""
        # Use sequence matcher on the hashes
        return SequenceMatcher(None, hash1, hash2).ratio()
    
    def _detect_structure_changes(
        self,
        baseline: ResponseFingerprint,
        response: httpx.Response,
    ) -> list[str]:
        """Detect structural changes in response."""
        changes = []
        
        content = response.content.decode("utf-8", errors="ignore")
        
        # Check for new elements that might indicate injection
        suspicious_patterns = [
            (r'<script[^>]*>', "New script tag detected"),
            (r'onerror\s*=', "Event handler detected"),
            (r'onclick\s*=', "Event handler detected"),
            (r'<iframe[^>]*>', "Iframe detected"),
            (r'javascript:', "JavaScript URL detected"),
            (r'<form[^>]*action', "Form action changed"),
        ]
        
        for pattern, message in suspicious_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                changes.append(message)
        
        return changes


# =============================================================================
# PAYLOAD ECHO DETECTOR
# =============================================================================

class PayloadEchoDetector:
    """
    Detects if and how a payload is reflected in the response.
    
    Critical for avoiding XSS/injection false positives:
    - Escaped payload = NOT vulnerable
    - Raw payload in wrong context = NOT vulnerable
    - Raw payload in executable context = VULNERABLE
    """
    
    # HTML escape mappings
    HTML_ESCAPES = {
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '&': '&amp;',
    }
    
    # Common XSS payloads for detection
    XSS_MARKERS = [
        '<script>',
        'javascript:',
        'onerror=',
        'onclick=',
        '<img src=',
        '<svg onload=',
    ]
    
    def analyze(
        self,
        payload: str,
        response_body: str,
        content_type: str = "",
    ) -> EchoAnalysis:
        """
        Analyze how a payload is reflected in the response.
        
        Args:
            payload: The injected payload
            response_body: Response body as string
            content_type: Content-Type header
            
        Returns:
            EchoAnalysis result
        """
        result = EchoAnalysis(
            payload=payload,
            echo_type=EchoType.NOT_REFLECTED,
        )
        
        # Check for raw reflection first
        if payload in response_body:
            result.echo_type = EchoType.REFLECTED_RAW
            result.reflected_value = payload
            result.position = response_body.find(payload)
            
            # Analyze context
            result.context = self._detect_context(response_body, result.position, len(payload))
            result.is_executable = self._is_executable_context(result.context, payload)
            
            return result
        
        # Check for HTML-escaped reflection
        escaped_payload = html.escape(payload)
        if escaped_payload in response_body and escaped_payload != payload:
            result.echo_type = EchoType.REFLECTED_ESCAPED
            result.reflected_value = escaped_payload
            result.escape_method = "HTML entity encoding"
            result.position = response_body.find(escaped_payload)
            result.is_executable = False
            return result
        
        # Check for URL-encoded reflection
        url_encoded = self._url_encode(payload)
        if url_encoded in response_body and url_encoded != payload:
            result.echo_type = EchoType.REFLECTED_URL_ENCODED
            result.reflected_value = url_encoded
            result.escape_method = "URL encoding"
            result.position = response_body.find(url_encoded)
            result.is_executable = False
            return result
        
        # Check for JSON-escaped reflection
        try:
            json_escaped = json.dumps(payload)[1:-1]  # Remove quotes
            if json_escaped in response_body and json_escaped != payload:
                result.echo_type = EchoType.REFLECTED_JSON_ESCAPED
                result.reflected_value = json_escaped
                result.escape_method = "JSON escaping"
                result.position = response_body.find(json_escaped)
                result.is_executable = False
                return result
        except Exception:
            pass
        
        # Check for reflection in HTML comment
        comment_pattern = rf'<!--[^>]*{re.escape(payload)}[^>]*-->'
        match = re.search(comment_pattern, response_body, re.IGNORECASE)
        if match:
            result.echo_type = EchoType.REFLECTED_IN_COMMENT
            result.reflected_value = match.group(0)
            result.context = "HTML comment"
            result.is_executable = False
            return result
        
        # Check for partial reflection
        partial = self._check_partial_reflection(payload, response_body)
        if partial:
            result.echo_type = EchoType.REFLECTED_PARTIAL
            result.reflected_value = partial
            result.is_executable = False
            return result
        
        return result
    
    def _detect_context(self, body: str, position: int, length: int) -> str:
        """Detect the context where payload was reflected."""
        # Get surrounding text
        start = max(0, position - 100)
        end = min(len(body), position + length + 100)
        surrounding = body[start:end]
        
        # Check context patterns
        contexts = [
            (r'<script[^>]*>[^<]*$', "JavaScript block"),
            (r'<[a-z]+[^>]*\s+on\w+\s*=\s*["\']?[^"\']*$', "Event handler"),
            (r'<[a-z]+[^>]*\s+(?:href|src|action)\s*=\s*["\']?[^"\']*$', "URL attribute"),
            (r'<[a-z]+[^>]*\s+\w+\s*=\s*["\'][^"\']*$', "HTML attribute (quoted)"),
            (r'<[a-z]+[^>]*\s+\w+\s*=\s*[^"\'\s>]*$', "HTML attribute (unquoted)"),
            (r'<style[^>]*>[^<]*$', "CSS block"),
            (r'>[^<]*$', "HTML text content"),
        ]
        
        before_payload = surrounding[:position - start]
        
        for pattern, context in contexts:
            if re.search(pattern, before_payload, re.IGNORECASE | re.DOTALL):
                return context
        
        return "Unknown context"
    
    def _is_executable_context(self, context: str, payload: str) -> bool:
        """Check if the context allows code execution."""
        dangerous_contexts = {
            "JavaScript block",
            "Event handler",
            "HTML attribute (unquoted)",
        }
        
        if context in dangerous_contexts:
            return True
        
        # URL attribute with javascript: is dangerous
        if context == "URL attribute" and "javascript:" in payload.lower():
            return True
        
        # Check for executable XSS patterns in the payload
        if context == "HTML text content":
            for marker in self.XSS_MARKERS:
                if marker.lower() in payload.lower():
                    return True
        
        return False
    
    def _url_encode(self, text: str) -> str:
        """URL encode special characters."""
        result = ""
        for char in text:
            if char.isalnum() or char in "-_.~":
                result += char
            else:
                result += f"%{ord(char):02X}"
        return result
    
    def _check_partial_reflection(self, payload: str, body: str) -> str | None:
        """Check if part of the payload was reflected."""
        # Check for significant portions (at least 50%)
        min_length = max(5, len(payload) // 2)
        
        for i in range(len(payload) - min_length + 1):
            for j in range(i + min_length, len(payload) + 1):
                substring = payload[i:j]
                if substring in body:
                    return substring
        
        return None


# =============================================================================
# CONFIDENCE ENGINE
# =============================================================================

class ConfidenceEngine:
    """
    Sophisticated confidence scoring for vulnerability findings.
    
    Uses a point-based system instead of simple if/else:
    - Positive points for indicators of vulnerability
    - Negative points for indicators of false positive
    
    Final score determines confidence level:
    - 90+: CONFIRMED
    - 70-89: HIGH
    - 50-69: MEDIUM
    - 25-49: LOW
    - <25: NONE
    """
    
    # Point values for different indicators
    POINTS = {
        # Positive indicators (evidence of vulnerability)
        "structure_change": 40,
        "specific_error": 35,
        "error_triggered": 30,
        "timing_anomaly_5x": 35,
        "timing_anomaly_3x": 25,
        "status_change_500": 30,
        "status_change_403": 15,
        "payload_executed": 50,
        "payload_reflected_raw": 25,
        "payload_in_dangerous_context": 35,
        "db_error_message": 40,
        "stack_trace": 35,
        "command_output": 45,
        "file_content": 45,
        "header_injection": 30,
        "new_cookie_set": 20,
        
        # Negative indicators (evidence of false positive)
        "response_identical": -50,
        "response_similar": -30,
        "payload_escaped": -40,
        "payload_in_comment": -35,
        "payload_not_reflected": -20,
        "generic_error": -15,
        "rate_limited": -25,
        "waf_blocked": -30,
        "payload_partial_reflection": -25,
    }
    
    # Error patterns with specificity
    SPECIFIC_ERRORS = {
        "sql": [
            r"SQL syntax.*MySQL",
            r"pg_query\(\).*failed",
            r"ORA-\d{5}",
            r"Microsoft.*ODBC.*SQL Server",
            r"sqlite3\.OperationalError",
            r"unterminated quoted string",
            r"quoted string not properly terminated",
        ],
        "nosql": [
            r"MongoError",
            r"MongoDB.*Error",
            r"CastError.*ObjectId",
            r"\$where.*function",
        ],
        "xml": [
            r"XML Parsing Error",
            r"SAXParseException",
            r"xmlParseEntityRef",
            r"Start tag expected",
            r"EntityRef: expecting",
        ],
        "command": [
            r"sh: \d+:",
            r"command not found",
            r"/bin/.*: Permission denied",
            r"not recognized as.*command",
            r"The system cannot find",
        ],
        "path": [
            r"No such file or directory",
            r"failed to open stream",
            r"FileNotFoundException",
            r"include\(\).*Failed opening",
        ],
        "template": [
            r"TemplateSyntaxError",
            r"UndefinedError",
            r"Jinja2.*Error",
            r"Twig.*Error",
        ],
    }
    
    def __init__(self):
        self._patterns = {}
        for category, patterns in self.SPECIFIC_ERRORS.items():
            self._patterns[category] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]
    
    def calculate(
        self,
        vuln_type: str,
        response_body: str,
        echo_analysis: EchoAnalysis | None = None,
        response_diff: ResponseDiff | None = None,
        extra_indicators: dict[str, bool] | None = None,
    ) -> ConfidenceScore:
        """
        Calculate confidence score for a finding.
        
        Args:
            vuln_type: Type of vulnerability (sqli, xss, cmdi, etc.)
            response_body: Response body as string
            echo_analysis: Payload echo analysis result
            response_diff: Baseline comparison result
            extra_indicators: Additional indicators from scanner
            
        Returns:
            ConfidenceScore with detailed breakdown
        """
        score = ConfidenceScore()
        
        # Analyze baseline diff
        if response_diff:
            self._score_response_diff(score, response_diff)
        
        # Analyze echo
        if echo_analysis:
            self._score_echo_analysis(score, echo_analysis, vuln_type)
        
        # Analyze error messages
        self._score_error_messages(score, response_body, vuln_type)
        
        # Apply extra indicators
        if extra_indicators:
            self._score_extra_indicators(score, extra_indicators)
        
        # Ensure minimum score is 0
        if score.total_score < 0:
            score.total_score = 0
            score.level = ConfidenceLevel.NONE
        
        return score
    
    def _score_response_diff(self, score: ConfidenceScore, diff: ResponseDiff) -> None:
        """Score based on response difference from baseline."""
        
        if diff.diff_type == ResponseDiffType.IDENTICAL:
            score.add_points("Response identical to baseline", self.POINTS["response_identical"])
            
        elif diff.diff_type == ResponseDiffType.SIMILAR:
            score.add_points("Response similar to baseline", self.POINTS["response_similar"])
            
        elif diff.diff_type == ResponseDiffType.STATUS_CHANGED:
            if diff.status_diff:
                _, new_status = diff.status_diff
                if new_status == 500:
                    score.add_points("500 Internal Server Error triggered", self.POINTS["status_change_500"])
                elif new_status == 403:
                    score.add_points("403 Forbidden (possible WAF/filter)", self.POINTS["status_change_403"])
                elif new_status == 429:
                    score.add_points("Rate limited", self.POINTS["rate_limited"])
                    
        elif diff.diff_type == ResponseDiffType.STRUCTURE_CHANGED:
            score.add_points("Response structure changed", self.POINTS["structure_change"])
            
        elif diff.diff_type == ResponseDiffType.ERROR_TRIGGERED:
            score.add_points("Error triggered in response", self.POINTS["error_triggered"])
            
        elif diff.diff_type == ResponseDiffType.TIMING_ANOMALY:
            if diff.timing_diff:
                baseline_time, test_time = diff.timing_diff
                ratio = test_time / max(baseline_time, 1)
                
                if ratio >= 5.0:
                    score.add_points(f"Major timing anomaly ({ratio:.1f}x baseline)", self.POINTS["timing_anomaly_5x"])
                elif ratio >= 3.0:
                    score.add_points(f"Timing anomaly ({ratio:.1f}x baseline)", self.POINTS["timing_anomaly_3x"])
    
    def _score_echo_analysis(
        self,
        score: ConfidenceScore,
        echo: EchoAnalysis,
        vuln_type: str,
    ) -> None:
        """Score based on payload echo analysis."""
        
        if echo.echo_type == EchoType.NOT_REFLECTED:
            # For reflection-based vulns (XSS, SSTI), no reflection = likely FP
            if vuln_type in ("xss", "ssti", "crlf"):
                score.add_points("Payload not reflected", self.POINTS["payload_not_reflected"])
                
        elif echo.echo_type == EchoType.REFLECTED_RAW:
            score.add_points("Payload reflected without encoding", self.POINTS["payload_reflected_raw"])
            
            if echo.is_executable:
                score.add_points("Payload in executable context", self.POINTS["payload_in_dangerous_context"])
            if echo.echo_type == EchoType.REFLECTED_RAW and vuln_type == "xss":
                # For XSS, raw reflection in right context = high confidence
                score.add_points("Raw XSS payload executed", self.POINTS["payload_executed"])
                
        elif echo.echo_type == EchoType.REFLECTED_ESCAPED:
            score.add_points("Payload HTML-escaped", self.POINTS["payload_escaped"])
            
        elif echo.echo_type == EchoType.REFLECTED_IN_COMMENT:
            score.add_points("Payload reflected in HTML comment", self.POINTS["payload_in_comment"])
            
        elif echo.echo_type == EchoType.REFLECTED_PARTIAL:
            score.add_points("Only partial payload reflected", self.POINTS["payload_partial_reflection"])
    
    def _score_error_messages(
        self,
        score: ConfidenceScore,
        body: str,
        vuln_type: str,
    ) -> None:
        """Score based on error messages in response."""
        
        # Map vuln types to error categories
        vuln_to_category = {
            "sqli": "sql",
            "nosql": "nosql",
            "xxe": "xml",
            "cmdi": "command",
            "lfi": "path",
            "rfi": "path",
            "ssti": "template",
        }
        
        # Check for specific errors related to vuln type
        category = vuln_to_category.get(vuln_type)
        if category and category in self._patterns:
            for pattern in self._patterns[category]:
                match = pattern.search(body)
                if match:
                    score.add_points(
                        f"Specific {category} error: {match.group(0)[:50]}",
                        self.POINTS["specific_error"]
                    )
                    break
        
        # Check for stack traces
        if re.search(r'Traceback \(most recent call last\)', body):
            score.add_points("Python stack trace", self.POINTS["stack_trace"])
        elif re.search(r'at\s+\w+\.\w+\([^)]*\.java:\d+\)', body):
            score.add_points("Java stack trace", self.POINTS["stack_trace"])
        elif re.search(r'#\d+\s+[\w/]+\.php\(\d+\)', body):
            score.add_points("PHP stack trace", self.POINTS["stack_trace"])
    
    def _score_extra_indicators(
        self,
        score: ConfidenceScore,
        indicators: dict[str, bool],
    ) -> None:
        """Score based on additional indicators."""
        
        indicator_points = {
            "db_error": ("Database error detected", self.POINTS["db_error_message"]),
            "command_output": ("Command output detected", self.POINTS["command_output"]),
            "file_content": ("File content detected", self.POINTS["file_content"]),
            "header_injection": ("Header injection successful", self.POINTS["header_injection"]),
            "new_cookie": ("New cookie set", self.POINTS["new_cookie_set"]),
            "waf_blocked": ("WAF blocked request", self.POINTS["waf_blocked"]),
            "generic_error": ("Generic error (not specific)", self.POINTS["generic_error"]),
        }
        
        for indicator, (description, points) in indicator_points.items():
            if indicators.get(indicator):
                score.add_points(description, points)


# =============================================================================
# SPA NORMALIZER (GAP-1 FIX)
# =============================================================================

class SPANormalizer:
    """
    GAP-1 FIX: Normalizes SPA responses for accurate comparison.

    Problem: SPAs return 200 + homepage HTML for ANY path (client-side routing).
    This causes massive false positives when scanner thinks "200 = accessible".

    Solution: Detect SPA behavior and normalize responses for comparison.
    """

    def __init__(self):
        self._homepage_hash: str | None = None
        self._homepage_content: str | None = None
        self._is_spa: bool = False
        self._spa_indicators_compiled = [re.compile(p, re.IGNORECASE) for p in SPA_INDICATORS]
        self._framework_detected: str = ""

    def set_homepage(self, content: str) -> None:
        """
        Store homepage content for comparison.

        Args:
            content: Homepage HTML content
        """
        self._homepage_content = content
        self._homepage_hash = hashlib.md5(content.encode()).hexdigest()
        self._is_spa = self._detect_spa(content)
        self._framework_detected = self._detect_framework(content)

        if self._is_spa:
            logger.debug(
                f"[SPANormalizer] SPA detected: framework={self._framework_detected}, "
                f"homepage_hash={self._homepage_hash[:8]}..."
            )

    def _detect_spa(self, content: str) -> bool:
        """Check if content indicates a SPA."""
        for pattern in self._spa_indicators_compiled:
            if pattern.search(content):
                return True

        # Additional heuristic: minimal HTML + lots of scripts
        html_without_scripts = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.DOTALL)
        script_count = len(re.findall(r'<script[^>]*src=', content))

        if len(html_without_scripts) < 5000 and script_count > 3:
            return True

        return False

    def _detect_framework(self, content: str) -> str:
        """Detect the frontend framework."""
        patterns = {
            "nextjs": [r"__NEXT_DATA__", r"_next/"],
            "nuxt": [r"__NUXT__", r"_nuxt/"],
            "react": [r"react-root", r"data-reactroot"],
            "vue": [r"data-v-", r"__VUE__"],
            "angular": [r"ng-version", r"_nghost"],
            "svelte": [r"data-svelte", r"__sveltekit"],
        }

        for framework, framework_patterns in patterns.items():
            for pattern in framework_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return framework

        return "unknown"

    @property
    def is_spa(self) -> bool:
        """Check if target is a SPA."""
        return self._is_spa

    @property
    def framework(self) -> str:
        """Get detected framework."""
        return self._framework_detected

    def is_homepage_clone(self, content: str) -> bool:
        """
        Check if response is a clone of the homepage.

        SPAs return the same HTML for all routes and do client-side routing.
        This detects that behavior.

        Args:
            content: Response content to check

        Returns:
            True if content matches homepage (SPA catch-all behavior)
        """
        if not self._homepage_hash:
            return False

        content_hash = hashlib.md5(content.encode()).hexdigest()
        return content_hash == self._homepage_hash

    def normalize(self, content: str, strip_scripts: bool = True) -> str:
        """
        Normalize response content for comparison.

        Strips dynamic content that varies between requests:
        - CSRF tokens
        - Timestamps
        - UUIDs
        - Nonces

        Args:
            content: Raw response content
            strip_scripts: Whether to strip inline scripts (for SPA comparison)

        Returns:
            Normalized content
        """
        normalized = content

        # Strip dynamic content patterns
        for pattern, replacement in DYNAMIC_CONTENT_PATTERNS:
            normalized = re.sub(pattern, replacement, normalized, flags=re.IGNORECASE)

        # Strip inline scripts for SPA comparison (they contain hydration data)
        if strip_scripts and self._is_spa:
            normalized = re.sub(
                r'<script[^>]*>.*?</script>',
                '',
                normalized,
                flags=re.DOTALL | re.IGNORECASE
            )

        # Normalize whitespace
        normalized = re.sub(r'\s+', ' ', normalized)

        return normalized.strip()

    def compare_normalized(self, content1: str, content2: str) -> float:
        """
        Compare two normalized responses.

        Args:
            content1: First response (normalized)
            content2: Second response (normalized)

        Returns:
            Similarity score 0.0-1.0
        """
        norm1 = self.normalize(content1)
        norm2 = self.normalize(content2)

        return SequenceMatcher(None, norm1, norm2).ratio()

    def should_skip_finding(self, response_content: str, path: str) -> tuple[bool, str]:
        """
        Determine if a finding should be skipped due to SPA behavior.

        Args:
            response_content: Response body
            path: Request path

        Returns:
            Tuple of (should_skip, reason)
        """
        # Don't skip homepage findings
        if path in ("/", "/index.html", ""):
            return False, ""

        # If not SPA, don't skip
        if not self._is_spa:
            return False, ""

        # If response is homepage clone, skip
        if self.is_homepage_clone(response_content):
            return True, f"SPA catch-all: response identical to homepage (framework: {self._framework_detected})"

        return False, ""


# =============================================================================
# MAIN RESPONSE ANALYZER
# =============================================================================

class ResponseAnalyzer:
    """
    Main class that combines all analysis components.
    
    Usage:
        analyzer = ResponseAnalyzer()
        
        # Create baseline for endpoint
        await analyzer.create_baseline(url)
        
        # Analyze test response
        result = await analyzer.analyze(
            url=url,
            payload=payload,
            response=response,
            vuln_type="sqli",
        )
        
        if result.is_finding and result.confidence.level >= ConfidenceLevel.MEDIUM:
            report_vulnerability(result)
    """
    
    def __init__(self):
        self.fingerprinter = ResponseFingerprinter()
        self.echo_detector = PayloadEchoDetector()
        self.confidence_engine = ConfidenceEngine()
        self.spa_normalizer = SPANormalizer()  # GAP-1 FIX

        logger.info(f"ResponseAnalyzer v{RESPONSE_ANALYZER_VERSION} initialized")
    
    async def create_baseline(
        self,
        url: str,
        method: str = "GET",
        client: httpx.AsyncClient | None = None,
    ) -> ResponseFingerprint:
        """
        Create baseline fingerprint for an endpoint.
        
        Args:
            url: Target URL
            method: HTTP method
            client: Optional HTTP client
            
        Returns:
            ResponseFingerprint baseline
        """
        return await self.fingerprinter.create_baseline(url, method, client)
    
    def analyze(
        self,
        url: str,
        payload: str,
        response: httpx.Response,
        response_time_ms: float,
        vuln_type: str,
        baseline: ResponseFingerprint | None = None,
        extra_indicators: dict[str, bool] | None = None,
    ) -> AnalysisResult:
        """
        Analyze a test response for potential vulnerability.
        
        Args:
            url: Target URL
            payload: Injected payload
            response: HTTP response
            response_time_ms: Response time in ms
            vuln_type: Type of vulnerability being tested
            baseline: Optional baseline fingerprint
            extra_indicators: Additional indicators from scanner
            
        Returns:
            AnalysisResult with verdict
        """
        result = AnalysisResult()
        
        # Get response body as string
        body = response.content.decode("utf-8", errors="ignore")
        content_type = response.headers.get("content-type", "")
        
        # 1. Analyze payload echo/reflection
        result.echo = self.echo_detector.analyze(payload, body, content_type)
        
        # 2. Compare against baseline (if available)
        if baseline:
            result.diff = self.fingerprinter.compare(baseline, response, response_time_ms)
        else:
            # Try to get cached baseline
            cached = self.fingerprinter.get_baseline(url)
            if cached:
                result.diff = self.fingerprinter.compare(cached, response, response_time_ms)
        
        # 3. Calculate confidence score
        result.confidence = self.confidence_engine.calculate(
            vuln_type=vuln_type,
            response_body=body,
            echo_analysis=result.echo,
            response_diff=result.diff,
            extra_indicators=extra_indicators,
        )
        
        # 4. Determine if this is a finding
        result.is_finding = result.confidence.level.value >= ConfidenceLevel.MEDIUM.value
        result.finding_type = vuln_type if result.is_finding else ""
        
        # 5. Collect evidence
        if result.is_finding:
            result.evidence = self._collect_evidence(result, body, payload)
        
        return result
    
    async def calibrate_for_target(
        self,
        homepage_url: str,
        client: httpx.AsyncClient | None = None,
    ) -> dict[str, Any]:
        """
        GAP-1 FIX: Calibrate analyzer for a specific target.

        This should be called at scan start to:
        1. Detect if target is a SPA
        2. Store homepage hash for clone detection
        3. Adjust thresholds based on target behavior

        Args:
            homepage_url: Target homepage URL
            client: HTTP client

        Returns:
            Calibration info dict
        """
        should_close = False
        if client is None:
            client = httpx.AsyncClient(timeout=30.0, follow_redirects=True, verify=False)
            should_close = True

        calibration_info = {
            "is_spa": False,
            "framework": "unknown",
            "homepage_hash": None,
            "calibrated": False,
        }

        try:
            response = await client.get(homepage_url)
            if response.status_code == 200:
                content = response.text
                self.spa_normalizer.set_homepage(content)

                calibration_info["is_spa"] = self.spa_normalizer.is_spa
                calibration_info["framework"] = self.spa_normalizer.framework
                calibration_info["homepage_hash"] = hashlib.md5(content.encode()).hexdigest()[:16]
                calibration_info["calibrated"] = True

                logger.info(
                    f"[ResponseAnalyzer] Calibrated for target: "
                    f"SPA={calibration_info['is_spa']}, "
                    f"framework={calibration_info['framework']}"
                )

        except Exception as e:
            logger.warning(f"[ResponseAnalyzer] Calibration failed: {e}")
        finally:
            if should_close:
                await client.aclose()

        return calibration_info

    def analyze_with_spa_check(
        self,
        url: str,
        payload: str,
        response: httpx.Response,
        response_time_ms: float,
        vuln_type: str,
        baseline: ResponseFingerprint | None = None,
        extra_indicators: dict[str, bool] | None = None,
    ) -> AnalysisResult:
        """
        GAP-1 FIX: Analyze with SPA-aware checks.

        Same as analyze() but also checks for SPA false positives.

        Args:
            url: Target URL
            payload: Injected payload
            response: HTTP response
            response_time_ms: Response time in ms
            vuln_type: Type of vulnerability being tested
            baseline: Optional baseline fingerprint
            extra_indicators: Additional indicators from scanner

        Returns:
            AnalysisResult with verdict (may be adjusted for SPA)
        """
        # First, do regular analysis
        result = self.analyze(
            url=url,
            payload=payload,
            response=response,
            response_time_ms=response_time_ms,
            vuln_type=vuln_type,
            baseline=baseline,
            extra_indicators=extra_indicators,
        )

        # Then check for SPA false positive
        if result.is_finding:
            from urllib.parse import urlparse
            path = urlparse(url).path

            body = response.content.decode("utf-8", errors="ignore")
            should_skip, reason = self.spa_normalizer.should_skip_finding(body, path)

            if should_skip:
                # Demote to non-finding due to SPA behavior
                result.is_finding = False
                result.confidence.add_points(
                    f"SPA false positive: {reason}",
                    -50  # Heavy penalty
                )
                result.evidence.append(f"⚠️ Skipped: {reason}")
                logger.debug(f"[ResponseAnalyzer] Finding demoted due to SPA: {reason}")

        return result

    def is_spa_homepage_clone(self, response_body: str) -> bool:
        """
        GAP-1 FIX: Check if response is a SPA homepage clone.

        Args:
            response_body: Response content

        Returns:
            True if response matches homepage (SPA catch-all)
        """
        return self.spa_normalizer.is_homepage_clone(response_body)

    def normalize_response(self, response_body: str) -> str:
        """
        GAP-1 FIX: Normalize response for comparison.

        Strips dynamic content (CSRF tokens, timestamps, etc.)

        Args:
            response_body: Raw response content

        Returns:
            Normalized content
        """
        return self.spa_normalizer.normalize(response_body)

    def quick_check(
        self,
        payload: str,
        response_body: str,
        vuln_type: str,
    ) -> tuple[bool, ConfidenceLevel]:
        """
        Quick check without baseline comparison.
        
        Args:
            payload: Injected payload
            response_body: Response body
            vuln_type: Vulnerability type
            
        Returns:
            Tuple of (is_potential_finding, confidence_level)
        """
        # Echo analysis
        echo = self.echo_detector.analyze(payload, response_body)
        
        # Confidence calculation
        confidence = self.confidence_engine.calculate(
            vuln_type=vuln_type,
            response_body=response_body,
            echo_analysis=echo,
        )
        
        is_finding = confidence.level.value >= ConfidenceLevel.MEDIUM.value
        return is_finding, confidence.level
    
    def _collect_evidence(
        self,
        result: AnalysisResult,
        body: str,
        payload: str,
    ) -> list[str]:
        """Collect evidence for the finding."""
        evidence = []
        
        # Add confidence breakdown
        evidence.append(f"Confidence Score: {result.confidence.total_score} ({result.confidence.level.name})")
        
        # Add echo info
        if result.echo:
            evidence.append(f"Payload Reflection: {result.echo.echo_type.name}")
            if result.echo.context:
                evidence.append(f"Reflection Context: {result.echo.context}")
            if result.echo.is_executable:
                evidence.append("⚠️ Payload is in executable context")
        
        # Add diff info
        if result.diff:
            evidence.append(f"Response Comparison: {result.diff.diff_type.name}")
            if result.diff.new_errors:
                evidence.append(f"Errors Triggered: {', '.join(result.diff.new_errors[:3])}")
            if result.diff.timing_diff:
                baseline, test = result.diff.timing_diff
                evidence.append(f"Timing: {baseline:.0f}ms → {test:.0f}ms ({test/baseline:.1f}x)")
        
        # Add positive indicators
        for indicator in result.confidence.positive_indicators[:5]:
            evidence.append(f"✓ {indicator}")
        
        return evidence


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def should_report_finding(result: AnalysisResult, min_confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM) -> bool:
    """Check if finding should be reported based on confidence."""
    return result.is_finding and result.confidence.level.value >= min_confidence.value


def get_confidence_color(level: ConfidenceLevel) -> str:
    """Get color for confidence level (for terminal output)."""
    colors = {
        ConfidenceLevel.NONE: "\033[90m",      # Gray
        ConfidenceLevel.LOW: "\033[33m",       # Yellow
        ConfidenceLevel.MEDIUM: "\033[93m",    # Light yellow
        ConfidenceLevel.HIGH: "\033[91m",      # Red
        ConfidenceLevel.CONFIRMED: "\033[31m", # Bright red
    }
    return colors.get(level, "")


# =============================================================================
# ASYNC IMPORT HANDLING
# =============================================================================

import asyncio  # noqa: E402 (imported here for _create_baseline async)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Version
    "RESPONSE_ANALYZER_VERSION",

    # Enums
    "ConfidenceLevel",
    "EchoType",
    "ResponseDiffType",

    # Data classes
    "ResponseFingerprint",
    "EchoAnalysis",
    "ResponseDiff",
    "ConfidenceScore",
    "AnalysisResult",

    # Main classes
    "ResponseFingerprinter",
    "PayloadEchoDetector",
    "ConfidenceEngine",
    "ResponseAnalyzer",
    "SPANormalizer",  # GAP-1 FIX

    # Helper functions
    "should_report_finding",
    "get_confidence_color",

    # GAP-1 Constants
    "SPA_INDICATORS",
    "DYNAMIC_CONTENT_PATTERNS",
]
