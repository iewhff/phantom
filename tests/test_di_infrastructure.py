"""
Tests for Dependency Injection Infrastructure.

Tests for:
- scanning/protocols.py - Protocol interfaces
- scanning/container.py - DI container
- scanning/scanner_factory.py - Scanner factory

Part of Phase 8: Dependency Inversion (2026-02-26)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from scanning.protocols import (
    HttpClientProtocol,
    HttpResponseProtocol,
    RateLimiterProtocol,
    PayloadLibraryProtocol,
    PayloadProtocol,
    OOBEngineProtocol,
    OOBTokenProtocol,
    WAFBypassEngineProtocol,
    WAFDetectionProtocol,
    LoggerProtocol,
    FindingProtocol,
    FindingsStoreProtocol,
    ScanContextProtocol,
    ScannerModuleProtocol,
)
from scanning.container import (
    ScanContainer,
    ScanScope,
    Lifetime,
    Registration,
    create_default_container,
    get_container,
    set_container,
    reset_container,
)
from scanning.scanner_factory import (
    ScannerFactory,
    ScannerInfo,
    SCANNER_REGISTRY,
    get_scanner_factory,
    create_scanner,
)


# =============================================================================
# MOCK IMPLEMENTATIONS FOR TESTING
# =============================================================================


@dataclass
class MockHttpResponse:
    """Mock HTTP response for testing."""

    status_code: int = 200
    text: str = ""
    content: bytes = b""
    headers: Dict[str, str] = field(default_factory=dict)
    url: str = ""
    elapsed: float = 0.1

    def json(self) -> Any:
        import json
        return json.loads(self.text) if self.text else {}


class MockHttpClient:
    """Mock HTTP client for testing."""

    def __init__(self) -> None:
        self.requests: List[Dict[str, Any]] = []
        self.response = MockHttpResponse()

    async def get(self, url: str, **kwargs) -> MockHttpResponse:
        self.requests.append({"method": "GET", "url": url, **kwargs})
        return self.response

    async def post(self, url: str, **kwargs) -> MockHttpResponse:
        self.requests.append({"method": "POST", "url": url, **kwargs})
        return self.response

    async def put(self, url: str, **kwargs) -> MockHttpResponse:
        self.requests.append({"method": "PUT", "url": url, **kwargs})
        return self.response

    async def delete(self, url: str, **kwargs) -> MockHttpResponse:
        self.requests.append({"method": "DELETE", "url": url, **kwargs})
        return self.response

    async def patch(self, url: str, **kwargs) -> MockHttpResponse:
        self.requests.append({"method": "PATCH", "url": url, **kwargs})
        return self.response

    async def head(self, url: str, **kwargs) -> MockHttpResponse:
        self.requests.append({"method": "HEAD", "url": url, **kwargs})
        return self.response

    async def options(self, url: str, **kwargs) -> MockHttpResponse:
        self.requests.append({"method": "OPTIONS", "url": url, **kwargs})
        return self.response

    async def request(self, method: str, url: str, **kwargs) -> MockHttpResponse:
        self.requests.append({"method": method, "url": url, **kwargs})
        return self.response


class MockRateLimiter:
    """Mock rate limiter for testing."""

    def __init__(self) -> None:
        self._request_count = 0
        self._rates: Dict[str, float] = {}

    async def acquire(self, domain: str = "default") -> None:
        self._request_count += 1

    async def try_acquire(self, domain: str = "default") -> bool:
        self._request_count += 1
        return True

    async def set_rate(self, domain: str, rate: float) -> None:
        self._rates[domain] = rate

    async def signal_rate_limited(self, domain: str = "default") -> float:
        return 1.0

    @property
    def request_count(self) -> int:
        return self._request_count


@dataclass
class MockPayload:
    """Mock payload for testing."""

    raw: str
    category: Any = None
    description: str = ""
    success_indicators: List[str] = field(default_factory=list)

    def get_variants(self, max_variants: int = 5) -> List[str]:
        return [self.raw]


class MockPayloadLibrary:
    """Mock payload library for testing."""

    def get_payloads(self, category, **kwargs) -> List[MockPayload]:
        return [MockPayload(raw="test_payload")]

    def get_raw_payloads(self, category, **kwargs) -> List[str]:
        return ["test_payload"]

    def get_success_indicators(self, category) -> List[str]:
        return ["success"]

    def encode_payload(self, payload: str, encoding: str) -> str:
        return payload


@dataclass
class MockOOBToken:
    """Mock OOB token for testing."""

    token: str = "test_token"
    correlation_id: str = "test_correlation"
    has_callback: bool = False
    is_expired: bool = False
    callbacks_received: List[Dict[str, Any]] = field(default_factory=list)


class MockOOBEngine:
    """Mock OOB engine for testing."""

    def __init__(self) -> None:
        self.tokens: Dict[str, MockOOBToken] = {}

    def generate_token(self, scan_id, payload_type, target_url, parameter) -> MockOOBToken:
        token = MockOOBToken(token=f"token_{len(self.tokens)}")
        self.tokens[token.token] = token
        return token

    def get_callback_url(self, token: str, protocol: str = "http") -> str:
        return f"{protocol}://callback.test/{token}"

    def get_dns_callback_domain(self, token: str) -> str:
        return f"{token}.callback.test"

    async def check_callback(self, token: str, timeout: float = 5.0) -> bool:
        return token in self.tokens and self.tokens[token].has_callback

    def get_token_info(self, token: str) -> Optional[MockOOBToken]:
        return self.tokens.get(token)

    def generate_payload(self, template_name: str, token: str) -> str:
        return f"payload_{template_name}_{token}"


@dataclass
class MockWAFDetection:
    """Mock WAF detection result for testing."""

    detected: bool = False
    waf_name: Optional[str] = None
    behaviour_family: Optional[str] = None
    confidence: float = 0.0


class MockWAFBypassEngine:
    """Mock WAF bypass engine for testing."""

    async def detect_waf(self, target_url: str, timeout: float = 15.0) -> MockWAFDetection:
        return MockWAFDetection()

    def apply_bypass(self, payload: str, detection, max_variants: int = 10) -> List[str]:
        return [payload]

    def mutate_payload(self, payload: str, technique: str) -> str:
        return payload

    def get_bypass_techniques(self, detection) -> List[str]:
        return []


@dataclass
class MockFinding:
    """Mock finding for testing."""

    id: str = "test_finding"
    name: str = "Test Finding"
    severity: str = "HIGH"
    url: str = "http://test.com"
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity,
            "url": self.url,
            "evidence": self.evidence,
        }


class MockFindingsStore:
    """Mock findings store for testing."""

    def __init__(self) -> None:
        self.findings: Dict[str, MockFinding] = {}
        self.shared_data: Dict[str, List[Any]] = {}

    def add_finding(self, finding) -> str:
        self.findings[finding.id] = finding
        return finding.id

    def get_finding(self, finding_id: str) -> Optional[MockFinding]:
        return self.findings.get(finding_id)

    def get_all_findings(self) -> List[MockFinding]:
        return list(self.findings.values())

    def get_findings_by_severity(self, severity: str) -> List[MockFinding]:
        return [f for f in self.findings.values() if f.severity == severity]

    def get_findings_by_type(self, vuln_type: str) -> List[MockFinding]:
        return list(self.findings.values())

    def deduplicate(self) -> int:
        return 0

    def share_extracted_data(self, data_type: str, value: Any, source_module: str) -> None:
        if data_type not in self.shared_data:
            self.shared_data[data_type] = []
        self.shared_data[data_type].append(value)

    def get_shared_data(self, data_type: str) -> List[Any]:
        return self.shared_data.get(data_type, [])


# =============================================================================
# PROTOCOL TESTS
# =============================================================================


class TestProtocolCompliance:
    """Test that mock implementations comply with protocols."""

    def test_http_response_protocol(self):
        """Test MockHttpResponse complies with HttpResponseProtocol."""
        response = MockHttpResponse(
            status_code=200,
            text='{"key": "value"}',
            content=b'{"key": "value"}',
            headers={"Content-Type": "application/json"},
            url="http://test.com",
            elapsed=0.1,
        )

        assert isinstance(response, HttpResponseProtocol)
        assert response.status_code == 200
        assert response.text == '{"key": "value"}'
        assert response.json() == {"key": "value"}

    def test_http_client_protocol(self):
        """Test MockHttpClient complies with HttpClientProtocol."""
        client = MockHttpClient()
        assert isinstance(client, HttpClientProtocol)

    def test_rate_limiter_protocol(self):
        """Test MockRateLimiter complies with RateLimiterProtocol."""
        limiter = MockRateLimiter()
        assert isinstance(limiter, RateLimiterProtocol)

    def test_payload_library_protocol(self):
        """Test MockPayloadLibrary complies with PayloadLibraryProtocol."""
        library = MockPayloadLibrary()
        assert isinstance(library, PayloadLibraryProtocol)

    def test_oob_engine_protocol(self):
        """Test MockOOBEngine complies with OOBEngineProtocol."""
        engine = MockOOBEngine()
        assert isinstance(engine, OOBEngineProtocol)

    def test_waf_bypass_engine_protocol(self):
        """Test MockWAFBypassEngine complies with WAFBypassEngineProtocol."""
        engine = MockWAFBypassEngine()
        assert isinstance(engine, WAFBypassEngineProtocol)

    def test_findings_store_protocol(self):
        """Test MockFindingsStore complies with FindingsStoreProtocol."""
        store = MockFindingsStore()
        assert isinstance(store, FindingsStoreProtocol)


# =============================================================================
# CONTAINER TESTS
# =============================================================================


class TestScanContainer:
    """Test DI container functionality."""

    def test_register_and_resolve_transient(self):
        """Test transient registration creates new instances."""
        container = ScanContainer()
        call_count = 0

        def factory(scope):
            nonlocal call_count
            call_count += 1
            return MockRateLimiter()

        container.register(RateLimiterProtocol, factory, Lifetime.TRANSIENT)

        # Each resolve creates new instance
        scope = container.create_scope_sync()
        instance1 = scope.resolve(RateLimiterProtocol)
        instance2 = scope.resolve(RateLimiterProtocol)

        assert instance1 is not instance2
        assert call_count == 2

    def test_register_and_resolve_singleton(self):
        """Test singleton registration reuses instance."""
        container = ScanContainer()
        call_count = 0

        def factory(scope):
            nonlocal call_count
            call_count += 1
            return MockRateLimiter()

        container.register(RateLimiterProtocol, factory, Lifetime.SINGLETON)

        # Each resolve returns same instance
        scope = container.create_scope_sync()
        instance1 = scope.resolve(RateLimiterProtocol)
        instance2 = scope.resolve(RateLimiterProtocol)

        assert instance1 is instance2
        assert call_count == 1

    def test_register_and_resolve_scoped(self):
        """Test scoped registration shares within scope."""
        container = ScanContainer()
        call_count = 0

        def factory(scope):
            nonlocal call_count
            call_count += 1
            return MockRateLimiter()

        container.register(RateLimiterProtocol, factory, Lifetime.SCOPED)

        # Same scope = same instance
        scope1 = container.create_scope_sync()
        instance1a = scope1.resolve(RateLimiterProtocol)
        instance1b = scope1.resolve(RateLimiterProtocol)
        assert instance1a is instance1b
        assert call_count == 1

        # Different scope = different instance
        scope2 = container.create_scope_sync()
        instance2 = scope2.resolve(RateLimiterProtocol)
        assert instance2 is not instance1a
        assert call_count == 2

    def test_register_instance(self):
        """Test registering existing instance."""
        container = ScanContainer()
        limiter = MockRateLimiter()

        container.register_instance(RateLimiterProtocol, limiter)

        scope = container.create_scope_sync()
        resolved = scope.resolve(RateLimiterProtocol)
        assert resolved is limiter

    def test_is_registered(self):
        """Test checking if interface is registered."""
        container = ScanContainer()

        assert not container.is_registered(RateLimiterProtocol)

        container.register(RateLimiterProtocol, lambda s: MockRateLimiter())

        assert container.is_registered(RateLimiterProtocol)

    def test_unregistered_raises(self):
        """Test resolving unregistered interface raises."""
        container = ScanContainer()
        scope = container.create_scope_sync()

        with pytest.raises(KeyError, match="No registration found"):
            scope.resolve(RateLimiterProtocol)

    @pytest.mark.asyncio
    async def test_create_scope_context_manager(self):
        """Test scope context manager."""
        container = ScanContainer()
        container.register(RateLimiterProtocol, lambda s: MockRateLimiter(), Lifetime.SCOPED)

        async with container.create_scope() as scope:
            limiter = scope.resolve(RateLimiterProtocol)
            assert isinstance(limiter, RateLimiterProtocol)

    @pytest.mark.asyncio
    async def test_scope_dispose(self):
        """Test scope disposal."""
        container = ScanContainer()

        # Mock with aclose method
        mock_client = MagicMock()
        mock_client.aclose = AsyncMock()

        container.register(
            HttpClientProtocol,
            lambda s: mock_client,
            Lifetime.SCOPED,
        )

        async with container.create_scope() as scope:
            scope.resolve(HttpClientProtocol)

        # aclose should be called on dispose
        mock_client.aclose.assert_called_once()

    def test_resolve_from_disposed_scope_raises(self):
        """Test resolving from disposed scope raises."""
        container = ScanContainer()
        container.register(RateLimiterProtocol, lambda s: MockRateLimiter())

        scope = container.create_scope_sync()
        asyncio.get_event_loop().run_until_complete(scope.dispose())

        with pytest.raises(RuntimeError, match="disposed scope"):
            scope.resolve(RateLimiterProtocol)


class TestGlobalContainer:
    """Test global container functions."""

    def setup_method(self):
        """Reset global container before each test."""
        reset_container()

    def test_get_container_creates_default(self):
        """Test get_container creates default if none exists."""
        container = get_container()
        assert container is not None
        assert isinstance(container, ScanContainer)

    def test_get_container_returns_same_instance(self):
        """Test get_container returns same instance."""
        container1 = get_container()
        container2 = get_container()
        assert container1 is container2

    def test_set_container(self):
        """Test setting custom container."""
        custom = ScanContainer()
        set_container(custom)

        assert get_container() is custom

    def test_reset_container(self):
        """Test resetting container."""
        container1 = get_container()
        reset_container()
        container2 = get_container()

        assert container1 is not container2


# =============================================================================
# SCANNER FACTORY TESTS
# =============================================================================


class TestScannerFactory:
    """Test scanner factory functionality."""

    def test_list_scanners(self):
        """Test listing available scanners."""
        factory = ScannerFactory()
        scanners = factory.list_scanners()

        assert "sqli" in scanners
        assert "xss" in scanners
        assert len(scanners) > 5

    def test_list_scanners_by_category(self):
        """Test listing scanners by category."""
        factory = ScannerFactory()
        injection_scanners = factory.list_scanners(category="injection")

        assert "sqli" in injection_scanners
        assert "xss" in injection_scanners
        assert "cors" not in injection_scanners

    def test_list_categories(self):
        """Test listing scanner categories."""
        factory = ScannerFactory()
        categories = factory.list_categories()

        assert "injection" in categories
        assert "auth" in categories
        assert "network" in categories

    def test_get_scanner_info(self):
        """Test getting scanner info."""
        factory = ScannerFactory()
        info = factory.get_scanner_info("sqli")

        assert info.name == "sqli"
        assert info.category == "injection"
        assert "http_client" in info.dependencies

    def test_unknown_scanner_raises(self):
        """Test unknown scanner raises ValueError."""
        factory = ScannerFactory()

        with pytest.raises(ValueError, match="Unknown scanner"):
            factory.get_scanner_info("nonexistent")


class TestScannerInfo:
    """Test ScannerInfo dataclass."""

    def test_scanner_info_defaults(self):
        """Test ScannerInfo default values."""
        info = ScannerInfo(
            name="test",
            module_path="test.module",
            class_name="TestScanner",
            category="test",
        )

        assert info.description == ""
        assert info.requires_auth is False
        assert info.is_destructive is False
        assert info.dependencies == []


class TestScannerRegistry:
    """Test scanner registry."""

    def test_registry_has_common_scanners(self):
        """Test registry contains common scanners."""
        assert "sqli" in SCANNER_REGISTRY
        assert "xss" in SCANNER_REGISTRY
        assert "ssrf" in SCANNER_REGISTRY
        assert "jwt" in SCANNER_REGISTRY

    def test_registry_info_complete(self):
        """Test registry entries have required fields."""
        for name, info in SCANNER_REGISTRY.items():
            assert info.name == name
            assert info.module_path
            assert info.class_name
            assert info.category


# =============================================================================
# INTEGRATION TESTS
# =============================================================================


class TestIntegration:
    """Integration tests for DI infrastructure."""

    def test_mock_implementations_work_together(self):
        """Test mock implementations work together."""
        # Create container with mocks
        container = ScanContainer()
        container.register(RateLimiterProtocol, lambda s: MockRateLimiter(), Lifetime.SINGLETON)
        container.register(PayloadLibraryProtocol, lambda s: MockPayloadLibrary(), Lifetime.SINGLETON)
        container.register(OOBEngineProtocol, lambda s: MockOOBEngine(), Lifetime.SINGLETON)
        container.register(WAFBypassEngineProtocol, lambda s: MockWAFBypassEngine(), Lifetime.SINGLETON)
        container.register(FindingsStoreProtocol, lambda s: MockFindingsStore(), Lifetime.SCOPED)

        # Resolve and use
        scope = container.create_scope_sync()

        limiter = scope.resolve(RateLimiterProtocol)
        payloads = scope.resolve(PayloadLibraryProtocol)
        oob = scope.resolve(OOBEngineProtocol)
        waf = scope.resolve(WAFBypassEngineProtocol)
        store = scope.resolve(FindingsStoreProtocol)

        # Use the dependencies
        payloads_list = payloads.get_raw_payloads("sqli")
        assert len(payloads_list) > 0

        token = oob.generate_token("scan1", "ssrf", "http://test", "param")
        callback_url = oob.get_callback_url(token.token)
        assert callback_url.startswith("http://")

        store.add_finding(MockFinding())
        assert len(store.get_all_findings()) == 1

    @pytest.mark.asyncio
    async def test_scoped_dependencies_isolated(self):
        """Test scoped dependencies are isolated between scans."""
        container = ScanContainer()
        container.register(FindingsStoreProtocol, lambda s: MockFindingsStore(), Lifetime.SCOPED)

        # First scan
        async with container.create_scope() as scope1:
            store1 = scope1.resolve(FindingsStoreProtocol)
            store1.add_finding(MockFinding(id="finding1"))
            assert len(store1.get_all_findings()) == 1

        # Second scan - should have fresh store
        async with container.create_scope() as scope2:
            store2 = scope2.resolve(FindingsStoreProtocol)
            assert len(store2.get_all_findings()) == 0

    @pytest.mark.asyncio
    async def test_singleton_shared_between_scopes(self):
        """Test singleton dependencies are shared between scopes."""
        container = ScanContainer()
        limiter_instance = MockRateLimiter()
        container.register_instance(RateLimiterProtocol, limiter_instance)

        async with container.create_scope() as scope1:
            limiter1 = scope1.resolve(RateLimiterProtocol)
            await limiter1.acquire()

        async with container.create_scope() as scope2:
            limiter2 = scope2.resolve(RateLimiterProtocol)
            # Should see request from scope1
            assert limiter2.request_count == 1


# =============================================================================
# RUN TESTS
# =============================================================================


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
