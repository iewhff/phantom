"""
Tests for utils/evidence_engine.py

Comprehensive tests for the Evidence Engine v3.0.
Tests cover:
- EvidenceType enum
- EvidenceConfidence enum
- HTTPEvidence dataclass
- ScreenshotEvidence dataclass
- TimelineEvent dataclass
- EvidenceItem dataclass
- EvidencePackage dataclass
- EvidenceSession dataclass
- EvidenceEngine class
- Convenience functions
"""

import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import tempfile

from utils.evidence_engine import (
    # Enums
    EvidenceType,
    EvidenceConfidence,
    # Dataclasses
    HTTPEvidence,
    ScreenshotEvidence,
    TimelineEvent,
    EvidenceItem,
    EvidencePackage,
    EvidenceSession,
    # Classes
    EvidenceEngine,
    # Functions
    get_evidence_engine,
    reset_evidence_engine,
)


class TestEvidenceType:
    """Tests for EvidenceType enum."""

    def test_all_types_present(self):
        """Test that all evidence types are defined."""
        types = {t.name for t in EvidenceType}
        expected = {
            "HTTP_REQUEST_RESPONSE",
            "SCREENSHOT",
            "DOM_SNAPSHOT",
            "CONSOLE_LOG",
            "NETWORK_HAR",
            "TIMING_DATA",
            "DIFF_COMPARISON",
            "VIDEO_RECORDING",
            "CURL_COMMAND",
            "RAW_RESPONSE",
            "INJECTED_PAYLOAD",
            "ERROR_MESSAGE",
            "STACK_TRACE",
        }
        assert types == expected

    def test_unique_values(self):
        """Test that all types have unique values."""
        values = [t.value for t in EvidenceType]
        assert len(values) == len(set(values))


class TestEvidenceConfidence:
    """Tests for EvidenceConfidence enum."""

    def test_all_levels_present(self):
        """Test that all confidence levels are defined."""
        levels = {c.name for c in EvidenceConfidence}
        expected = {
            "DEFINITIVE",
            "STRONG",
            "MODERATE",
            "WEAK",
            "SUPPLEMENTARY",
        }
        assert levels == expected

    def test_confidence_values(self):
        """Test confidence level string values."""
        assert EvidenceConfidence.DEFINITIVE.value == "definitive"
        assert EvidenceConfidence.STRONG.value == "strong"
        assert EvidenceConfidence.MODERATE.value == "moderate"
        assert EvidenceConfidence.WEAK.value == "weak"
        assert EvidenceConfidence.SUPPLEMENTARY.value == "supplementary"


class TestHTTPEvidence:
    """Tests for HTTPEvidence dataclass."""

    def test_creation(self):
        """Test HTTPEvidence creation."""
        evidence = HTTPEvidence(
            request_method="POST",
            request_url="https://example.com/login",
            request_headers={"Content-Type": "application/json"},
            request_body='{"user": "admin", "pass": "test"}',
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"success": true}',
            response_time_ms=150.5,
        )

        assert evidence.request_method == "POST"
        assert evidence.response_status == 200
        assert evidence.response_time_ms == 150.5

    def test_default_values(self):
        """Test HTTPEvidence default values."""
        evidence = HTTPEvidence(
            request_method="GET",
            request_url="https://example.com/",
            request_headers={},
            request_body=None,
            response_status=200,
            response_headers={},
            response_body="OK",
            response_time_ms=50.0,
        )

        assert evidence.payload_reflected is False
        assert evidence.error_triggered is False
        assert evidence.timing_anomaly is False
        assert isinstance(evidence.timestamp, datetime)

    def test_to_dict(self):
        """Test HTTPEvidence to_dict method."""
        evidence = HTTPEvidence(
            request_method="GET",
            request_url="https://example.com/api",
            request_headers={"Authorization": "Bearer token"},
            request_body=None,
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"data": "test"}',
            response_time_ms=100.0,
            payload_reflected=True,
            error_triggered=False,
        )

        d = evidence.to_dict()

        assert d["request"]["method"] == "GET"
        assert d["request"]["url"] == "https://example.com/api"
        assert d["response"]["status"] == 200
        assert d["response"]["time_ms"] == 100.0
        assert d["analysis"]["payload_reflected"] is True

    def test_to_dict_truncates_large_body(self):
        """Test to_dict truncates large response bodies."""
        large_body = "x" * 20000  # 20KB body
        evidence = HTTPEvidence(
            request_method="GET",
            request_url="https://example.com/",
            request_headers={},
            request_body=None,
            response_status=200,
            response_headers={},
            response_body=large_body,
            response_time_ms=50.0,
        )

        d = evidence.to_dict()

        # Should be truncated to 10000 chars
        assert len(d["response"]["body"]) == 10000


class TestScreenshotEvidence:
    """Tests for ScreenshotEvidence dataclass."""

    def test_creation(self):
        """Test ScreenshotEvidence creation."""
        evidence = ScreenshotEvidence(
            url="https://example.com/admin",
            screenshot_path="/tmp/screenshot.png",
            width=1920,
            height=1080,
            context="Admin panel after auth bypass",
        )

        assert evidence.url == "https://example.com/admin"
        assert evidence.width == 1920
        assert evidence.context == "Admin panel after auth bypass"

    def test_default_values(self):
        """Test ScreenshotEvidence default values."""
        evidence = ScreenshotEvidence(
            url="https://example.com/",
            screenshot_path="/tmp/shot.png",
        )

        assert evidence.screenshot_base64 is None
        assert evidence.width == 0
        assert evidence.height == 0
        assert evidence.context == ""
        assert evidence.highlighted_elements == []

    def test_to_dict(self):
        """Test ScreenshotEvidence to_dict method."""
        evidence = ScreenshotEvidence(
            url="https://example.com/profile",
            screenshot_path="/evidence/shot001.png",
            width=1280,
            height=720,
            context="User profile page",
            highlighted_elements=["#user-data", ".sensitive-info"],
        )

        d = evidence.to_dict()

        assert d["url"] == "https://example.com/profile"
        assert d["dimensions"]["width"] == 1280
        assert d["dimensions"]["height"] == 720
        assert d["highlights"] == ["#user-data", ".sensitive-info"]


class TestTimelineEvent:
    """Tests for TimelineEvent dataclass."""

    def test_creation(self):
        """Test TimelineEvent creation."""
        event = TimelineEvent(
            timestamp=datetime.now(),
            event_type="request",
            description="POST request to /login",
            url="https://example.com/login",
        )

        assert event.event_type == "request"
        assert event.url == "https://example.com/login"

    def test_default_values(self):
        """Test TimelineEvent default values."""
        event = TimelineEvent(
            timestamp=datetime.now(),
            event_type="finding",
            description="SQLi vulnerability detected",
        )

        assert event.evidence_id is None
        assert event.url is None
        assert event.severity is None
        assert event.details == {}

    def test_to_dict(self):
        """Test TimelineEvent to_dict method."""
        now = datetime.now()
        event = TimelineEvent(
            timestamp=now,
            event_type="vulnerability",
            description="XSS found in search parameter",
            url="https://example.com/search",
            severity="HIGH",
            details={"payload": "<script>alert(1)</script>"},
        )

        d = event.to_dict()

        assert d["type"] == "vulnerability"
        assert d["timestamp"] == now.isoformat()
        assert d["severity"] == "HIGH"
        assert d["details"]["payload"] == "<script>alert(1)</script>"


class TestEvidenceItem:
    """Tests for EvidenceItem dataclass."""

    def test_creation(self):
        """Test EvidenceItem creation."""
        http_evidence = HTTPEvidence(
            request_method="GET",
            request_url="https://example.com/",
            request_headers={},
            request_body=None,
            response_status=200,
            response_headers={},
            response_body="OK",
            response_time_ms=50.0,
        )

        item = EvidenceItem(
            id="EV_001",
            type=EvidenceType.HTTP_REQUEST_RESPONSE,
            confidence=EvidenceConfidence.STRONG,
            timestamp=datetime.now(),
            context="Baseline request",
            data=http_evidence,
            finding_id="FINDING_001",
            tags=["baseline", "initial"],
        )

        assert item.id == "EV_001"
        assert item.type == EvidenceType.HTTP_REQUEST_RESPONSE
        assert item.confidence == EvidenceConfidence.STRONG

    def test_to_dict(self):
        """Test EvidenceItem to_dict method."""
        http_evidence = HTTPEvidence(
            request_method="POST",
            request_url="https://example.com/api",
            request_headers={"Content-Type": "application/json"},
            request_body='{"test": true}',
            response_status=200,
            response_headers={},
            response_body='{"result": "ok"}',
            response_time_ms=100.0,
        )

        item = EvidenceItem(
            id="EV_002",
            type=EvidenceType.HTTP_REQUEST_RESPONSE,
            confidence=EvidenceConfidence.MODERATE,
            timestamp=datetime.now(),
            context="API test request",
            data=http_evidence,
            tags=["api", "test"],
        )

        d = item.to_dict()

        assert d["id"] == "EV_002"
        assert d["type"] == "HTTP_REQUEST_RESPONSE"
        assert d["confidence"] == "moderate"
        assert "data" in d


class TestEvidencePackage:
    """Tests for EvidencePackage dataclass."""

    def test_creation(self):
        """Test EvidencePackage creation."""
        package = EvidencePackage(
            finding_id="FINDING_001",
            finding_type="SQLi",
            severity="CRITICAL",
            target_url="https://example.com/login",
            evidence_items=[],
            timeline=[],
            curl_commands=[],
            reproduction_steps=["Step 1", "Step 2"],
            impact_demonstration="Database access achieved",
        )

        assert package.finding_id == "FINDING_001"
        assert package.severity == "CRITICAL"

    def test_to_dict(self):
        """Test EvidencePackage to_dict method."""
        package = EvidencePackage(
            finding_id="FINDING_002",
            finding_type="XSS",
            severity="HIGH",
            target_url="https://example.com/search",
            evidence_items=[],
            timeline=[],
            curl_commands=["curl -X GET 'https://example.com/search?q=<script>'"],
            reproduction_steps=["Navigate to search", "Enter payload"],
            impact_demonstration="Script execution in user browser",
        )

        d = package.to_dict()

        assert d["finding_id"] == "FINDING_002"
        assert d["finding_type"] == "XSS"
        assert d["evidence_count"] == 0
        assert len(d["reproduction_steps"]) == 2

    def test_to_markdown(self):
        """Test EvidencePackage to_markdown method."""
        package = EvidencePackage(
            finding_id="FINDING_003",
            finding_type="IDOR",
            severity="HIGH",
            target_url="https://example.com/users/123",
            evidence_items=[],
            timeline=[],
            curl_commands=["curl 'https://example.com/users/456'"],
            reproduction_steps=["Change user ID in URL", "Observe other user data"],
            impact_demonstration="Unauthorized data access",
        )

        md = package.to_markdown()

        assert "# Evidence Package: FINDING_003" in md
        assert "**Finding Type:** IDOR" in md
        assert "**Severity:** HIGH" in md
        assert "## Reproduction Steps" in md
        assert "## curl Commands" in md


class TestEvidenceSession:
    """Tests for EvidenceSession dataclass."""

    def test_creation(self):
        """Test EvidenceSession creation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            session = EvidenceSession(
                session_id="SESSION_001",
                target="https://example.com",
                scan_id="SCAN_001",
                started_at=datetime.now(),
                storage_path=Path(tmpdir),
            )

            assert session.session_id == "SESSION_001"
            assert session.target == "https://example.com"
            assert session.evidence_items == {}
            assert session.timeline == []

    def test_add_evidence(self):
        """Test add_evidence method."""
        with tempfile.TemporaryDirectory() as tmpdir:
            session = EvidenceSession(
                session_id="SESSION_002",
                target="https://example.com",
                scan_id="SCAN_002",
                started_at=datetime.now(),
                storage_path=Path(tmpdir),
            )

            evidence = EvidenceItem(
                id="EV_TEST",
                type=EvidenceType.HTTP_REQUEST_RESPONSE,
                confidence=EvidenceConfidence.MODERATE,
                timestamp=datetime.now(),
                context="Test evidence",
                data={"test": True},
            )

            session.add_evidence(evidence)

            assert "EV_TEST" in session.evidence_items
            assert len(session.timeline) == 1
            assert session.timeline[0].event_type == "http_request_response"

    def test_link_evidence_to_finding(self):
        """Test link_evidence_to_finding method."""
        with tempfile.TemporaryDirectory() as tmpdir:
            session = EvidenceSession(
                session_id="SESSION_003",
                target="https://example.com",
                scan_id="SCAN_003",
                started_at=datetime.now(),
                storage_path=Path(tmpdir),
            )

            evidence = EvidenceItem(
                id="EV_LINK",
                type=EvidenceType.SCREENSHOT,
                confidence=EvidenceConfidence.STRONG,
                timestamp=datetime.now(),
                context="Screenshot evidence",
                data={"url": "https://example.com"},
            )

            session.add_evidence(evidence)
            session.link_evidence_to_finding("EV_LINK", "FINDING_100")

            assert "FINDING_100" in session.findings_evidence
            assert "EV_LINK" in session.findings_evidence["FINDING_100"]
            assert session.evidence_items["EV_LINK"].finding_id == "FINDING_100"


class TestEvidenceEngine:
    """Tests for EvidenceEngine class."""

    def test_creation(self):
        """Test EvidenceEngine creation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))

            assert engine.VERSION == "3.0.0"
            assert engine.storage_base == Path(tmpdir)

    def test_start_session(self):
        """Test start_session method."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))

            session = engine.start_session(
                target="https://example.com",
                scan_id="SCAN_TEST"
            )

            assert session is not None
            assert session.target == "https://example.com"
            assert session.scan_id == "SCAN_TEST"
            assert len(session.timeline) == 1  # session_start event
            assert session.timeline[0].event_type == "session_start"

    def test_get_active_session(self):
        """Test get_active_session method."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))

            # No session yet
            assert engine.get_active_session() is None

            # Start session
            session = engine.start_session("https://example.com", "SCAN")

            assert engine.get_active_session() == session

    def test_generate_evidence_id(self):
        """Test evidence ID generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))

            id1 = engine._generate_evidence_id()
            id2 = engine._generate_evidence_id()

            assert id1.startswith("EV_")
            assert id2.startswith("EV_")
            assert id1 != id2

    def test_generate_curl_command_get(self):
        """Test curl command generation for GET request."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))

            curl = engine.generate_curl_command(
                method="GET",
                url="https://example.com/api",
                headers={"Authorization": "Bearer token123"},
            )

            assert "curl" in curl
            assert "-X" in curl
            assert "GET" in curl
            assert "https://example.com/api" in curl
            assert "Authorization: Bearer token123" in curl

    def test_generate_curl_command_post(self):
        """Test curl command generation for POST request."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))

            curl = engine.generate_curl_command(
                method="POST",
                url="https://example.com/login",
                headers={"Content-Type": "application/json"},
                body='{"user": "admin"}',
            )

            assert "-X" in curl
            assert "POST" in curl
            assert "-d" in curl
            assert "Content-Type: application/json" in curl

    def test_add_timeline_event(self):
        """Test add_timeline_event method."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))
            session = engine.start_session("https://example.com", "SCAN")

            initial_events = len(session.timeline)

            engine.add_timeline_event(
                event_type="finding",
                description="XSS vulnerability found",
                url="https://example.com/search",
                severity="HIGH",
            )

            assert len(session.timeline) == initial_events + 1
            last_event = session.timeline[-1]
            assert last_event.event_type == "finding"
            assert last_event.severity == "HIGH"

    def test_link_to_finding(self):
        """Test link_to_finding method."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))
            session = engine.start_session("https://example.com", "SCAN")

            # Add evidence
            evidence = EvidenceItem(
                id="EV_LINK_TEST",
                type=EvidenceType.HTTP_REQUEST_RESPONSE,
                confidence=EvidenceConfidence.STRONG,
                timestamp=datetime.now(),
                context="Test",
                data={"test": True},
            )
            session.add_evidence(evidence)

            # Link to finding
            engine.link_to_finding("EV_LINK_TEST", "FINDING_XYZ")

            assert "FINDING_XYZ" in session.findings_evidence
            assert "EV_LINK_TEST" in session.findings_evidence["FINDING_XYZ"]

    def test_compile_evidence_package(self):
        """Test compile_evidence_package method."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))
            session = engine.start_session("https://example.com", "SCAN")

            # Create HTTP evidence
            http_evidence = HTTPEvidence(
                request_method="GET",
                request_url="https://example.com/vuln",
                request_headers={},
                request_body=None,
                response_status=200,
                response_headers={},
                response_body="<html>sensitive data</html>",
                response_time_ms=100.0,
            )

            evidence = EvidenceItem(
                id="EV_PKG_001",
                type=EvidenceType.HTTP_REQUEST_RESPONSE,
                confidence=EvidenceConfidence.STRONG,
                timestamp=datetime.now(),
                context="Vulnerability proof",
                data=http_evidence,
            )
            session.add_evidence(evidence)
            engine.link_to_finding("EV_PKG_001", "FINDING_PKG")

            # Compile package
            package = engine.compile_evidence_package(
                finding_id="FINDING_PKG",
                finding_type="IDOR",
                severity="HIGH",
                target_url="https://example.com/vuln",
            )

            assert package.finding_id == "FINDING_PKG"
            assert package.finding_type == "IDOR"
            assert len(package.evidence_items) == 1
            assert len(package.curl_commands) == 1

    def test_end_session(self):
        """Test end_session method."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))
            session = engine.start_session("https://example.com", "SCAN")

            storage_path = engine.end_session()

            assert storage_path is not None
            assert storage_path.exists()
            assert engine.get_active_session() is None

            # Check files were created
            assert (storage_path / "session_summary.json").exists()
            assert (storage_path / "timeline.json").exists()

    def test_get_statistics(self):
        """Test get_statistics method."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))

            # No session
            stats = engine.get_statistics()
            assert stats["active"] is False

            # With session
            session = engine.start_session("https://example.com", "SCAN")
            stats = engine.get_statistics()

            assert stats["active"] is True
            assert stats["session_id"] == session.session_id
            assert stats["evidence_count"] == 0

    @pytest.mark.asyncio
    async def test_capture_http(self):
        """Test capture_http method."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))
            engine.start_session("https://example.com", "SCAN")

            evidence_id = await engine.capture_http(
                request_method="GET",
                request_url="https://example.com/test",
                request_headers={"User-Agent": "Test"},
                request_body=None,
                response_status=200,
                response_headers={"Content-Type": "text/html"},
                response_body="<html>test</html>",
                response_time_ms=50.0,
                context="Test capture",
                tags=["test"],
            )

            assert evidence_id.startswith("EV_")
            session = engine.get_active_session()
            assert evidence_id in session.evidence_items

    @pytest.mark.asyncio
    async def test_capture_http_with_payload_reflection(self):
        """Test capture_http detects payload reflection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))
            engine.start_session("https://example.com", "SCAN")

            payload = "<script>alert(1)</script>"
            evidence_id = await engine.capture_http(
                request_method="GET",
                request_url=f"https://example.com/search?q={payload}",
                request_headers={},
                request_body=None,
                response_status=200,
                response_headers={},
                response_body=f"<html>Search: {payload}</html>",
                response_time_ms=50.0,
                payload=payload,
            )

            session = engine.get_active_session()
            evidence = session.evidence_items[evidence_id]
            assert "payload_reflected" in evidence.tags

    @pytest.mark.asyncio
    async def test_capture_http_detects_errors(self):
        """Test capture_http detects error responses."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))
            engine.start_session("https://example.com", "SCAN")

            evidence_id = await engine.capture_http(
                request_method="GET",
                request_url="https://example.com/test",
                request_headers={},
                request_body=None,
                response_status=500,
                response_headers={},
                response_body="MySQL error: syntax error near 'test'",
                response_time_ms=50.0,
            )

            session = engine.get_active_session()
            evidence = session.evidence_items[evidence_id]
            assert "error_triggered" in evidence.tags

    @pytest.mark.asyncio
    async def test_capture_http_detects_timing_anomaly(self):
        """Test capture_http detects timing anomalies."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))
            engine.start_session("https://example.com", "SCAN")

            evidence_id = await engine.capture_http(
                request_method="GET",
                request_url="https://example.com/test",
                request_headers={},
                request_body=None,
                response_status=200,
                response_headers={},
                response_body="OK",
                response_time_ms=6000.0,  # 6 seconds - anomaly threshold is 5s
            )

            session = engine.get_active_session()
            evidence = session.evidence_items[evidence_id]
            assert "timing_anomaly" in evidence.tags


class TestImpactDescriptions:
    """Tests for impact description generation."""

    def test_generate_impact_sqli(self):
        """Test SQLi impact description."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))

            impact = engine._generate_impact_description(
                finding_type="SQLi",
                severity="CRITICAL",
                evidence_items=[],
            )

            assert "SQL Injection" in impact
            assert "database" in impact.lower()

    def test_generate_impact_xss(self):
        """Test XSS impact description."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))

            impact = engine._generate_impact_description(
                finding_type="XSS",
                severity="HIGH",
                evidence_items=[],
            )

            assert "Cross-Site Scripting" in impact or "script" in impact.lower()

    def test_generate_impact_unknown_type(self):
        """Test impact description for unknown finding type."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))

            impact = engine._generate_impact_description(
                finding_type="CustomVuln",
                severity="MEDIUM",
                evidence_items=[],
            )

            assert "CustomVuln" in impact
            assert "vulnerability" in impact.lower()


class TestReproductionSteps:
    """Tests for reproduction steps generation."""

    def test_generate_reproduction_steps(self):
        """Test reproduction steps generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))

            http_evidence = HTTPEvidence(
                request_method="POST",
                request_url="https://example.com/login",
                request_headers={},
                request_body='{"user": "admin"}',
                response_status=200,
                response_headers={},
                response_body="OK",
                response_time_ms=100.0,
                payload_reflected=True,
            )

            evidence = EvidenceItem(
                id="EV_001",
                type=EvidenceType.HTTP_REQUEST_RESPONSE,
                confidence=EvidenceConfidence.STRONG,
                timestamp=datetime.now(),
                context="Login test",
                data=http_evidence,
            )

            steps = engine._generate_reproduction_steps(
                finding_type="Auth Bypass",
                target_url="https://example.com",
                evidence_items=[evidence],
            )

            assert len(steps) > 0
            assert any("Navigate" in s for s in steps)
            assert any("POST" in s for s in steps)


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_get_evidence_engine_singleton(self):
        """Test get_evidence_engine returns singleton."""
        reset_evidence_engine()

        engine1 = get_evidence_engine()
        engine2 = get_evidence_engine()

        assert engine1 is engine2

    def test_reset_evidence_engine(self):
        """Test reset_evidence_engine clears singleton."""
        engine1 = get_evidence_engine()
        reset_evidence_engine()
        engine2 = get_evidence_engine()

        assert engine1 is not engine2


class TestEdgeCases:
    """Tests for edge cases."""

    def test_capture_http_without_session(self):
        """Test capture_http creates temp session if none active."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))

            # Don't start session - should auto-create

            import asyncio
            evidence_id = asyncio.run(engine.capture_http(
                request_method="GET",
                request_url="https://example.com/",
                request_headers={},
                request_body=None,
                response_status=200,
                response_headers={},
                response_body="OK",
                response_time_ms=50.0,
            ))

            assert evidence_id is not None
            assert engine.get_active_session() is not None

    def test_compile_package_without_session(self):
        """Test compile_evidence_package without active session."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))

            package = engine.compile_evidence_package(
                finding_id="NO_SESSION",
                finding_type="Test",
                severity="LOW",
                target_url="https://example.com",
            )

            assert package.finding_id == "NO_SESSION"
            assert len(package.evidence_items) == 0

    def test_add_timeline_event_without_session(self):
        """Test add_timeline_event without session does nothing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))

            # Should not raise
            engine.add_timeline_event(
                event_type="test",
                description="Test event",
            )

    def test_end_session_not_found(self):
        """Test end_session with invalid session ID."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))

            result = engine.end_session("NONEXISTENT")

            assert result is None

    def test_curl_escapes_quotes(self):
        """Test curl command properly escapes quotes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = EvidenceEngine(storage_base=Path(tmpdir))

            curl = engine.generate_curl_command(
                method="POST",
                url="https://example.com/",
                headers={"X-Custom": "value with 'quotes'"},
                body='{"key": "value\'s"}',
            )

            # Should have escaped quotes
            assert "'" in curl
