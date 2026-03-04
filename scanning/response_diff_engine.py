"""
Response Diff Engine - Subtle Response Difference Detection

Detects security vulnerabilities through response comparison:
- Timing-based user enumeration
- Content-length leakage (valid vs invalid users)
- Error message differences
- Header state differences
- Behavioral fingerprinting

MEDIUM Priority - 2 days effort

CWE Coverage:
- CWE-203: Observable Discrepancy (Information Exposure Through Discrepancy)
- CWE-204: Observable Response Discrepancy
- CWE-208: Observable Timing Discrepancy
- CWE-209: Information Exposure Through Error Message
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import statistics
import time
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from enum import Enum, auto
from typing import Any
from urllib.parse import urljoin, urlparse

from utils.logger import get_logger

logger = get_logger(__name__)

RESPONSE_DIFF_VERSION = "1.0.0"


class DiffVulnType(Enum):
    """Types of response difference vulnerabilities."""
    TIMING_ENUMERATION = auto()       # Different timing for valid vs invalid
    LENGTH_ENUMERATION = auto()       # Different content-length
    ERROR_MESSAGE_DIFF = auto()       # Different error messages
    HEADER_STATE_LEAK = auto()        # Headers reveal internal state
    STATUS_CODE_ORACLE = auto()       # Status codes reveal validity
    BEHAVIORAL_FINGERPRINT = auto()   # Response behavior reveals info
    REDIRECT_ORACLE = auto()          # Redirects reveal state
    CACHE_TIMING_ORACLE = auto()      # Cache headers reveal info


class DiffContext(Enum):
    """Context where diffing is applied."""
    USERNAME_ENUM = "username_enumeration"
    PASSWORD_RESET = "password_reset"
    EMAIL_VALIDATION = "email_validation"
    TOKEN_VALIDATION = "token_validation"
    ID_ENUMERATION = "id_enumeration"
    PERMISSION_CHECK = "permission_check"
    RATE_LIMIT_CHECK = "rate_limit_check"
    API_KEY_VALIDATION = "api_key_validation"


@dataclass
class ResponseSnapshot:
    """Snapshot of an HTTP response for comparison."""
    url: str
    method: str
    input_value: str
    input_type: str  # "valid", "invalid", "baseline"

    # Response data
    status_code: int
    content_length: int
    response_time_ms: float
    body_hash: str
    body_preview: str

    # Headers
    headers: dict[str, str]
    set_cookie_count: int
    cache_control: str
    content_type: str

    # Derived metrics
    word_count: int = 0
    line_count: int = 0
    json_keys: list[str] = field(default_factory=list)
    error_message: str = ""


@dataclass
class DiffResult:
    """Result of comparing two responses."""
    baseline: ResponseSnapshot
    test: ResponseSnapshot

    # Differences detected
    timing_diff_ms: float = 0.0
    timing_diff_percent: float = 0.0
    length_diff: int = 0
    length_diff_percent: float = 0.0
    status_code_diff: bool = False
    header_diffs: list[str] = field(default_factory=list)
    body_similarity: float = 1.0
    error_message_diff: bool = False

    # Analysis
    is_anomaly: bool = False
    anomaly_score: float = 0.0
    vuln_type: DiffVulnType | None = None
    confidence: int = 0
    evidence: list[str] = field(default_factory=list)


@dataclass
class EnumerationFinding:
    """Finding from enumeration analysis."""
    vuln_type: DiffVulnType
    context: DiffContext
    url: str
    method: str
    severity: str
    confidence: int

    # Evidence
    valid_input: str
    invalid_input: str
    timing_diff_ms: float
    length_diff: int
    error_diff: str
    header_diffs: list[str]

    evidence: list[str] = field(default_factory=list)
    cwe: str = "CWE-203"


class ResponseDiffEngine:
    """
    Engine for detecting security vulnerabilities through response differences.

    Philosophy: "Small differences reveal big secrets."

    Attackers use timing oracles, length oracles, and error message differences
    to enumerate users, validate tokens, and bypass security controls.

    This engine provides:
    1. Statistical timing analysis (detect microsecond differences)
    2. Content-length comparison (detect byte-level differences)
    3. Error message fingerprinting
    4. Header state analysis
    5. Behavioral pattern detection
    """

    # Timing thresholds
    MIN_TIMING_SAMPLES = 5           # Minimum samples for statistical analysis
    TIMING_VARIANCE_THRESHOLD = 0.15  # 15% variance is suspicious
    TIMING_DIFF_THRESHOLD_MS = 50    # 50ms difference is notable
    TIMING_STATISTICAL_P = 0.05      # p-value for significance

    # Length thresholds
    LENGTH_DIFF_THRESHOLD = 10       # 10 byte difference is suspicious
    LENGTH_DIFF_PERCENT_THRESHOLD = 0.05  # 5% difference

    # Body similarity
    SIMILARITY_THRESHOLD = 0.95      # 95% similar is "same"

    # Error patterns that reveal information
    ERROR_PATTERNS = {
        "user_exists": [
            r"password.*incorrect",
            r"wrong.*password",
            r"invalid.*password",
            r"password.*wrong",
            r"password.*invalid",
            r"authentication failed",
        ],
        "user_not_exists": [
            r"user.*not.*found",
            r"user.*does.*not.*exist",
            r"invalid.*user",
            r"unknown.*user",
            r"no.*such.*user",
            r"account.*not.*found",
            r"email.*not.*registered",
        ],
        "rate_limited": [
            r"too.*many.*requests",
            r"rate.*limit",
            r"try.*again.*later",
            r"throttled",
        ],
        "token_invalid": [
            r"token.*invalid",
            r"token.*expired",
            r"invalid.*token",
            r"expired.*token",
        ],
        "token_valid": [
            r"reset.*sent",
            r"email.*sent",
            r"check.*your.*email",
            r"link.*sent",
        ],
    }

    # Headers that may leak state
    STATE_HEADERS = [
        "x-request-id",
        "x-trace-id",
        "x-session-id",
        "x-user-id",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "retry-after",
        "x-powered-by",
        "server",
        "x-debug",
    ]

    def __init__(self):
        self._snapshots: dict[str, list[ResponseSnapshot]] = {}
        self._baselines: dict[str, ResponseSnapshot] = {}
        self._findings: list[EnumerationFinding] = []

    async def capture_response(
        self,
        client: Any,
        url: str,
        method: str = "POST",
        input_value: str = "",
        input_type: str = "test",
        data: dict | None = None,
        headers: dict | None = None,
    ) -> ResponseSnapshot:
        """
        Capture a response snapshot for comparison.

        Args:
            client: HTTP client (httpx or aiohttp)
            url: Target URL
            method: HTTP method
            input_value: The input being tested (username, email, etc.)
            input_type: "valid", "invalid", or "baseline"
            data: Request body
            headers: Request headers

        Returns:
            ResponseSnapshot with captured data
        """
        start_time = time.perf_counter()

        try:
            if method.upper() == "GET":
                response = await client.get(url, headers=headers)
            elif method.upper() == "POST":
                if data:
                    response = await client.post(url, json=data, headers=headers)
                else:
                    response = await client.post(url, headers=headers)
            else:
                response = await client.request(method, url, json=data, headers=headers)

            elapsed_ms = (time.perf_counter() - start_time) * 1000

            body = response.text if hasattr(response, 'text') else str(response.content)

            # Extract response data
            snapshot = ResponseSnapshot(
                url=url,
                method=method,
                input_value=input_value,
                input_type=input_type,
                status_code=response.status_code,
                content_length=len(body),
                response_time_ms=elapsed_ms,
                body_hash=hashlib.md5(body.encode()).hexdigest()[:16],
                body_preview=body[:500],
                headers=dict(response.headers),
                set_cookie_count=len([h for h in response.headers if h.lower() == 'set-cookie']),
                cache_control=response.headers.get('cache-control', ''),
                content_type=response.headers.get('content-type', ''),
                word_count=len(body.split()),
                line_count=len(body.splitlines()),
            )

            # Extract JSON keys if applicable
            if 'application/json' in snapshot.content_type:
                try:
                    import json
                    json_data = json.loads(body)
                    if isinstance(json_data, dict):
                        snapshot.json_keys = list(json_data.keys())
                except Exception:
                    pass

            # Extract error message
            snapshot.error_message = self._extract_error_message(body)

            # Store snapshot
            key = f"{url}:{method}"
            if key not in self._snapshots:
                self._snapshots[key] = []
            self._snapshots[key].append(snapshot)

            if input_type == "baseline":
                self._baselines[key] = snapshot

            return snapshot

        except Exception as e:
            logger.debug(f"Response capture error: {e}")
            raise

    def _extract_error_message(self, body: str) -> str:
        """Extract error message from response body."""
        body_lower = body.lower()

        # Check for common error patterns
        patterns = [
            r'"error"\s*:\s*"([^"]+)"',
            r'"message"\s*:\s*"([^"]+)"',
            r'"msg"\s*:\s*"([^"]+)"',
            r'<div[^>]*class="[^"]*error[^"]*"[^>]*>([^<]+)',
            r'<span[^>]*class="[^"]*error[^"]*"[^>]*>([^<]+)',
            r'<p[^>]*class="[^"]*error[^"]*"[^>]*>([^<]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                return match.group(1).strip()[:200]

        return ""

    def compare(
        self,
        baseline: ResponseSnapshot,
        test: ResponseSnapshot,
    ) -> DiffResult:
        """
        Compare two response snapshots for differences.

        Args:
            baseline: The baseline response (e.g., invalid user)
            test: The test response (e.g., valid user)

        Returns:
            DiffResult with all detected differences
        """
        result = DiffResult(baseline=baseline, test=test)

        # Timing difference
        result.timing_diff_ms = test.response_time_ms - baseline.response_time_ms
        if baseline.response_time_ms > 0:
            result.timing_diff_percent = result.timing_diff_ms / baseline.response_time_ms

        # Length difference
        result.length_diff = test.content_length - baseline.content_length
        if baseline.content_length > 0:
            result.length_diff_percent = result.length_diff / baseline.content_length

        # Status code difference
        result.status_code_diff = test.status_code != baseline.status_code

        # Header differences
        result.header_diffs = self._compare_headers(baseline.headers, test.headers)

        # Body similarity
        result.body_similarity = SequenceMatcher(
            None,
            baseline.body_preview,
            test.body_preview
        ).ratio()

        # Error message difference
        result.error_message_diff = (
            baseline.error_message != test.error_message and
            bool(baseline.error_message) and bool(test.error_message)
        )

        # Calculate anomaly score
        result.anomaly_score = self._calculate_anomaly_score(result)
        result.is_anomaly = result.anomaly_score >= 0.5

        # Determine vulnerability type
        result.vuln_type = self._determine_vuln_type(result)
        result.confidence = self._calculate_confidence(result)

        # Build evidence
        result.evidence = self._build_evidence(result)

        return result

    def _compare_headers(
        self,
        headers1: dict[str, str],
        headers2: dict[str, str],
    ) -> list[str]:
        """Compare headers for significant differences."""
        diffs = []

        # Normalize headers
        h1 = {k.lower(): v for k, v in headers1.items()}
        h2 = {k.lower(): v for k, v in headers2.items()}

        for header in self.STATE_HEADERS:
            if header in h1 and header in h2:
                if h1[header] != h2[header]:
                    diffs.append(f"{header}: {h1[header]} → {h2[header]}")
            elif header in h1:
                diffs.append(f"{header}: {h1[header]} → (missing)")
            elif header in h2:
                diffs.append(f"{header}: (missing) → {h2[header]}")

        return diffs

    def _calculate_anomaly_score(self, result: DiffResult) -> float:
        """Calculate overall anomaly score (0-1)."""
        score = 0.0

        # Timing (30% weight)
        if abs(result.timing_diff_percent) > self.TIMING_VARIANCE_THRESHOLD:
            score += 0.3
        elif abs(result.timing_diff_ms) > self.TIMING_DIFF_THRESHOLD_MS:
            score += 0.2

        # Length (25% weight)
        if abs(result.length_diff) > self.LENGTH_DIFF_THRESHOLD:
            score += 0.25
        elif abs(result.length_diff_percent) > self.LENGTH_DIFF_PERCENT_THRESHOLD:
            score += 0.15

        # Status code (20% weight)
        if result.status_code_diff:
            score += 0.2

        # Error message (15% weight)
        if result.error_message_diff:
            score += 0.15

        # Headers (10% weight)
        if result.header_diffs:
            score += min(0.1, len(result.header_diffs) * 0.03)

        return min(score, 1.0)

    def _determine_vuln_type(self, result: DiffResult) -> DiffVulnType | None:
        """Determine the type of vulnerability based on differences."""

        # Timing-based
        if abs(result.timing_diff_percent) > self.TIMING_VARIANCE_THRESHOLD:
            return DiffVulnType.TIMING_ENUMERATION

        # Length-based
        if abs(result.length_diff) > self.LENGTH_DIFF_THRESHOLD:
            return DiffVulnType.LENGTH_ENUMERATION

        # Status code
        if result.status_code_diff:
            return DiffVulnType.STATUS_CODE_ORACLE

        # Error message
        if result.error_message_diff:
            return DiffVulnType.ERROR_MESSAGE_DIFF

        # Header state
        if result.header_diffs:
            return DiffVulnType.HEADER_STATE_LEAK

        # Body difference
        if result.body_similarity < self.SIMILARITY_THRESHOLD:
            return DiffVulnType.BEHAVIORAL_FINGERPRINT

        return None

    def _calculate_confidence(self, result: DiffResult) -> int:
        """Calculate confidence level (0-100)."""
        confidence = 50  # Base confidence

        # Timing confidence
        if abs(result.timing_diff_percent) > 0.3:
            confidence += 15
        elif abs(result.timing_diff_percent) > self.TIMING_VARIANCE_THRESHOLD:
            confidence += 10

        # Length confidence
        if abs(result.length_diff) > 50:
            confidence += 15
        elif abs(result.length_diff) > self.LENGTH_DIFF_THRESHOLD:
            confidence += 10

        # Status code (high confidence)
        if result.status_code_diff:
            confidence += 20

        # Error message (high confidence)
        if result.error_message_diff:
            confidence += 15

        # Headers
        if result.header_diffs:
            confidence += min(10, len(result.header_diffs) * 3)

        return min(confidence, 95)

    def _build_evidence(self, result: DiffResult) -> list[str]:
        """Build evidence list for the finding."""
        evidence = []

        if result.timing_diff_ms != 0:
            evidence.append(
                f"Timing difference: {result.timing_diff_ms:.2f}ms "
                f"({result.timing_diff_percent*100:.1f}%)"
            )

        if result.length_diff != 0:
            evidence.append(
                f"Content-length difference: {result.length_diff} bytes "
                f"({result.length_diff_percent*100:.1f}%)"
            )

        if result.status_code_diff:
            evidence.append(
                f"Status code changed: {result.baseline.status_code} → "
                f"{result.test.status_code}"
            )

        if result.error_message_diff:
            evidence.append(
                f"Error message changed: '{result.baseline.error_message}' → "
                f"'{result.test.error_message}'"
            )

        for header_diff in result.header_diffs[:5]:
            evidence.append(f"Header difference: {header_diff}")

        if result.body_similarity < 1.0:
            evidence.append(
                f"Body similarity: {result.body_similarity*100:.1f}%"
            )

        return evidence

    async def test_username_enumeration(
        self,
        client: Any,
        login_url: str,
        valid_users: list[str],
        invalid_users: list[str] | None = None,
        username_field: str = "username",
        password_field: str = "password",
        test_password: str = "WrongPassword123!",
        samples_per_user: int = 5,
    ) -> list[EnumerationFinding]:
        """
        Test for username enumeration vulnerabilities.

        Strategy:
        1. Establish baseline with invalid usernames
        2. Test valid usernames for timing/length/error differences
        3. Statistical analysis of timing distributions

        Args:
            client: HTTP client
            login_url: Login endpoint URL
            valid_users: Known valid usernames to test
            invalid_users: Invalid usernames (generated if not provided)
            username_field: Name of username field
            password_field: Name of password field
            test_password: Password to use in tests
            samples_per_user: Number of samples for timing analysis

        Returns:
            List of enumeration findings
        """
        findings = []

        # Generate invalid users if not provided
        if invalid_users is None:
            invalid_users = [
                f"nonexistent{i}_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
                for i in range(3)
            ]

        # Collect baseline samples (invalid users)
        baseline_timings = []
        baseline_lengths = []
        baseline_errors = []

        logger.debug(f"Collecting {len(invalid_users) * samples_per_user} baseline samples")

        for invalid_user in invalid_users:
            for _ in range(samples_per_user):
                try:
                    data = {
                        username_field: invalid_user,
                        password_field: test_password,
                    }
                    snapshot = await self.capture_response(
                        client=client,
                        url=login_url,
                        method="POST",
                        input_value=invalid_user,
                        input_type="invalid",
                        data=data,
                    )
                    baseline_timings.append(snapshot.response_time_ms)
                    baseline_lengths.append(snapshot.content_length)
                    baseline_errors.append(snapshot.error_message)

                    await asyncio.sleep(0.1)  # Small delay to avoid rate limiting

                except Exception as e:
                    logger.debug(f"Baseline sample error: {e}")

        if len(baseline_timings) < self.MIN_TIMING_SAMPLES:
            logger.warning("Insufficient baseline samples for statistical analysis")
            return findings

        # Calculate baseline statistics
        baseline_timing_mean = statistics.mean(baseline_timings)
        baseline_timing_stdev = statistics.stdev(baseline_timings) if len(baseline_timings) > 1 else 0
        baseline_length_mode = max(set(baseline_lengths), key=baseline_lengths.count)
        baseline_error_mode = max(set(baseline_errors), key=baseline_errors.count) if baseline_errors else ""

        logger.debug(
            f"Baseline: timing={baseline_timing_mean:.2f}ms (σ={baseline_timing_stdev:.2f}), "
            f"length={baseline_length_mode}, error='{baseline_error_mode}'"
        )

        # Test valid users
        for valid_user in valid_users:
            valid_timings = []
            valid_lengths = []
            valid_errors = []
            valid_snapshots = []

            for _ in range(samples_per_user):
                try:
                    data = {
                        username_field: valid_user,
                        password_field: test_password,
                    }
                    snapshot = await self.capture_response(
                        client=client,
                        url=login_url,
                        method="POST",
                        input_value=valid_user,
                        input_type="valid",
                        data=data,
                    )
                    valid_timings.append(snapshot.response_time_ms)
                    valid_lengths.append(snapshot.content_length)
                    valid_errors.append(snapshot.error_message)
                    valid_snapshots.append(snapshot)

                    await asyncio.sleep(0.1)

                except Exception as e:
                    logger.debug(f"Valid user sample error: {e}")

            if len(valid_timings) < self.MIN_TIMING_SAMPLES:
                continue

            # Calculate valid user statistics
            valid_timing_mean = statistics.mean(valid_timings)
            valid_timing_stdev = statistics.stdev(valid_timings) if len(valid_timings) > 1 else 0
            valid_length_mode = max(set(valid_lengths), key=valid_lengths.count)
            valid_error_mode = max(set(valid_errors), key=valid_errors.count) if valid_errors else ""

            # Analyze differences
            evidence = []
            vuln_types = []
            severity = "MEDIUM"

            # Timing analysis
            timing_diff = valid_timing_mean - baseline_timing_mean
            timing_diff_percent = timing_diff / baseline_timing_mean if baseline_timing_mean > 0 else 0

            if abs(timing_diff_percent) > self.TIMING_VARIANCE_THRESHOLD:
                evidence.append(
                    f"Timing: valid={valid_timing_mean:.2f}ms vs invalid={baseline_timing_mean:.2f}ms "
                    f"(diff={timing_diff:.2f}ms, {timing_diff_percent*100:.1f}%)"
                )
                vuln_types.append(DiffVulnType.TIMING_ENUMERATION)

                # Statistical significance (simplified t-test)
                if baseline_timing_stdev > 0 and valid_timing_stdev > 0:
                    pooled_std = ((baseline_timing_stdev**2 + valid_timing_stdev**2) / 2) ** 0.5
                    t_stat = abs(timing_diff) / (pooled_std / (samples_per_user ** 0.5))
                    if t_stat > 2.0:  # Roughly p < 0.05
                        evidence.append(f"Statistically significant (t={t_stat:.2f})")
                        severity = "HIGH"

            # Length analysis
            length_diff = valid_length_mode - baseline_length_mode
            if abs(length_diff) > self.LENGTH_DIFF_THRESHOLD:
                evidence.append(
                    f"Content-length: valid={valid_length_mode} vs invalid={baseline_length_mode} "
                    f"(diff={length_diff} bytes)"
                )
                vuln_types.append(DiffVulnType.LENGTH_ENUMERATION)

            # Error message analysis
            if valid_error_mode != baseline_error_mode:
                evidence.append(
                    f"Error message: valid='{valid_error_mode}' vs invalid='{baseline_error_mode}'"
                )
                vuln_types.append(DiffVulnType.ERROR_MESSAGE_DIFF)
                severity = "HIGH"  # Error message diff is very reliable

                # Check for specific patterns
                valid_lower = valid_error_mode.lower()
                invalid_lower = baseline_error_mode.lower()

                for pattern in self.ERROR_PATTERNS.get("user_exists", []):
                    if re.search(pattern, valid_lower):
                        evidence.append(
                            f"Valid user error suggests password check: '{valid_error_mode}'"
                        )
                        break

                for pattern in self.ERROR_PATTERNS.get("user_not_exists", []):
                    if re.search(pattern, invalid_lower):
                        evidence.append(
                            f"Invalid user error reveals non-existence: '{baseline_error_mode}'"
                        )
                        break

            # Create finding if vulnerabilities detected
            if vuln_types:
                primary_vuln = vuln_types[0]

                finding = EnumerationFinding(
                    vuln_type=primary_vuln,
                    context=DiffContext.USERNAME_ENUM,
                    url=login_url,
                    method="POST",
                    severity=severity,
                    confidence=75 + (10 if len(vuln_types) > 1 else 0),
                    valid_input=valid_user,
                    invalid_input=invalid_users[0],
                    timing_diff_ms=timing_diff,
                    length_diff=length_diff,
                    error_diff=f"'{baseline_error_mode}' → '{valid_error_mode}'",
                    header_diffs=[],
                    evidence=evidence,
                    cwe="CWE-203" if primary_vuln == DiffVulnType.TIMING_ENUMERATION else "CWE-209",
                )
                findings.append(finding)

                logger.info(
                    f"Username enumeration detected: {valid_user} "
                    f"| Type: {primary_vuln.name} | Severity: {severity}"
                )

        self._findings.extend(findings)
        return findings

    async def test_password_reset_enumeration(
        self,
        client: Any,
        reset_url: str,
        valid_emails: list[str],
        invalid_emails: list[str] | None = None,
        email_field: str = "email",
        samples_per_email: int = 3,
    ) -> list[EnumerationFinding]:
        """
        Test for user enumeration in password reset flow.

        Password reset flows often leak whether an email is registered
        through timing, error messages, or response differences.
        """
        findings = []

        # Generate invalid emails if not provided
        if invalid_emails is None:
            invalid_emails = [
                f"nonexistent{i}_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}@example.com"
                for i in range(3)
            ]

        # Collect baseline samples
        baseline_timings = []
        baseline_responses = []

        for invalid_email in invalid_emails:
            for _ in range(samples_per_email):
                try:
                    snapshot = await self.capture_response(
                        client=client,
                        url=reset_url,
                        method="POST",
                        input_value=invalid_email,
                        input_type="invalid",
                        data={email_field: invalid_email},
                    )
                    baseline_timings.append(snapshot.response_time_ms)
                    baseline_responses.append(snapshot)

                    await asyncio.sleep(0.2)  # Longer delay for email operations

                except Exception as e:
                    logger.debug(f"Baseline error: {e}")

        if len(baseline_timings) < 3:
            return findings

        baseline_mean = statistics.mean(baseline_timings)
        baseline_snapshot = baseline_responses[0] if baseline_responses else None

        # Test valid emails
        for valid_email in valid_emails:
            valid_timings = []
            valid_snapshots = []

            for _ in range(samples_per_email):
                try:
                    snapshot = await self.capture_response(
                        client=client,
                        url=reset_url,
                        method="POST",
                        input_value=valid_email,
                        input_type="valid",
                        data={email_field: valid_email},
                    )
                    valid_timings.append(snapshot.response_time_ms)
                    valid_snapshots.append(snapshot)

                    await asyncio.sleep(0.2)

                except Exception as e:
                    logger.debug(f"Valid email error: {e}")

            if not valid_timings or not valid_snapshots:
                continue

            valid_mean = statistics.mean(valid_timings)
            valid_snapshot = valid_snapshots[0]

            # Compare
            if baseline_snapshot:
                diff_result = self.compare(baseline_snapshot, valid_snapshot)

                if diff_result.is_anomaly:
                    # Check for "email sent" success patterns
                    success_indicators = [
                        "email sent", "check your email", "reset link",
                        "instructions sent", "email has been sent"
                    ]
                    valid_lower = valid_snapshot.body_preview.lower()
                    invalid_lower = baseline_snapshot.body_preview.lower()

                    shows_success = any(ind in valid_lower for ind in success_indicators)
                    shows_generic = any(ind in invalid_lower for ind in success_indicators)

                    # Different behavior = enumeration
                    if shows_success and not shows_generic:
                        diff_result.evidence.append(
                            "Valid email shows success message while invalid doesn't"
                        )

                    finding = EnumerationFinding(
                        vuln_type=diff_result.vuln_type or DiffVulnType.BEHAVIORAL_FINGERPRINT,
                        context=DiffContext.PASSWORD_RESET,
                        url=reset_url,
                        method="POST",
                        severity="HIGH" if diff_result.error_message_diff else "MEDIUM",
                        confidence=diff_result.confidence,
                        valid_input=valid_email,
                        invalid_input=invalid_emails[0],
                        timing_diff_ms=diff_result.timing_diff_ms,
                        length_diff=diff_result.length_diff,
                        error_diff=f"'{baseline_snapshot.error_message}' → '{valid_snapshot.error_message}'",
                        header_diffs=diff_result.header_diffs,
                        evidence=diff_result.evidence,
                        cwe="CWE-204",
                    )
                    findings.append(finding)

        self._findings.extend(findings)
        return findings

    async def test_token_validation_oracle(
        self,
        client: Any,
        validation_url: str,
        valid_tokens: list[str],
        token_param: str = "token",
        samples: int = 5,
    ) -> list[EnumerationFinding]:
        """
        Test for token validation oracles.

        Token validation endpoints may reveal:
        - Whether a token exists
        - Whether a token is expired
        - Whether a token was already used
        """
        findings = []

        # Generate invalid tokens
        invalid_tokens = [
            hashlib.md5(str(i).encode()).hexdigest()
            for i in range(3)
        ]

        # Baseline with invalid tokens
        baseline_snapshots = []
        for invalid_token in invalid_tokens:
            for _ in range(samples):
                try:
                    snapshot = await self.capture_response(
                        client=client,
                        url=f"{validation_url}?{token_param}={invalid_token}",
                        method="GET",
                        input_value=invalid_token,
                        input_type="invalid",
                    )
                    baseline_snapshots.append(snapshot)
                    await asyncio.sleep(0.1)
                except Exception:
                    pass

        if not baseline_snapshots:
            return findings

        baseline = baseline_snapshots[0]

        # Test valid tokens
        for valid_token in valid_tokens:
            try:
                snapshot = await self.capture_response(
                    client=client,
                    url=f"{validation_url}?{token_param}={valid_token}",
                    method="GET",
                    input_value=valid_token,
                    input_type="valid",
                )

                diff_result = self.compare(baseline, snapshot)

                if diff_result.is_anomaly:
                    finding = EnumerationFinding(
                        vuln_type=diff_result.vuln_type or DiffVulnType.STATUS_CODE_ORACLE,
                        context=DiffContext.TOKEN_VALIDATION,
                        url=validation_url,
                        method="GET",
                        severity="MEDIUM",
                        confidence=diff_result.confidence,
                        valid_input=valid_token[:20] + "...",
                        invalid_input=invalid_tokens[0][:20] + "...",
                        timing_diff_ms=diff_result.timing_diff_ms,
                        length_diff=diff_result.length_diff,
                        error_diff="",
                        header_diffs=diff_result.header_diffs,
                        evidence=diff_result.evidence,
                        cwe="CWE-203",
                    )
                    findings.append(finding)

            except Exception as e:
                logger.debug(f"Token validation error: {e}")

        self._findings.extend(findings)
        return findings

    def get_findings(self) -> list[EnumerationFinding]:
        """Get all accumulated findings."""
        return self._findings

    def get_statistics(self) -> dict[str, Any]:
        """Get statistics about captured responses."""
        stats = {
            "total_snapshots": sum(len(s) for s in self._snapshots.values()),
            "endpoints_tested": len(self._snapshots),
            "findings_count": len(self._findings),
            "baselines_established": len(self._baselines),
        }

        # Timing statistics per endpoint
        timing_stats = {}
        for key, snapshots in self._snapshots.items():
            if snapshots:
                timings = [s.response_time_ms for s in snapshots]
                timing_stats[key] = {
                    "mean": statistics.mean(timings),
                    "stdev": statistics.stdev(timings) if len(timings) > 1 else 0,
                    "min": min(timings),
                    "max": max(timings),
                    "samples": len(timings),
                }

        stats["timing_stats"] = timing_stats
        return stats

    def reset(self) -> None:
        """Reset the engine state."""
        self._snapshots.clear()
        self._baselines.clear()
        self._findings.clear()


# Convenience function
async def quick_enumeration_test(
    client: Any,
    login_url: str,
    valid_users: list[str],
) -> list[EnumerationFinding]:
    """
    Quick username enumeration test.

    Args:
        client: HTTP client
        login_url: Login endpoint
        valid_users: Known valid usernames

    Returns:
        List of enumeration findings
    """
    engine = ResponseDiffEngine()
    return await engine.test_username_enumeration(
        client=client,
        login_url=login_url,
        valid_users=valid_users,
    )


# Export
__all__ = [
    "ResponseDiffEngine",
    "ResponseSnapshot",
    "DiffResult",
    "DiffVulnType",
    "DiffContext",
    "EnumerationFinding",
    "quick_enumeration_test",
    "RESPONSE_DIFF_VERSION",
]
