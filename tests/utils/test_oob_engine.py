"""
Tests for utils/oob_engine.py - Out-of-Band Detection Engine.

Covers:
- OOBProtocol enum
- CallbackType enum
- OOBToken dataclass
- OOBCallback dataclass
- OOBPayloadGenerator class
- OOBCallbackStore class
- OOBEngine class
- ExternalOOBService class
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, AsyncMock
import time

from utils.oob_engine import (
    OOBProtocol,
    CallbackType,
    OOBToken,
    OOBCallback,
    OOBPayloadGenerator,
    OOBCallbackStore,
    OOBEngine,
    ExternalOOBService,
    SimpleHTTPCallbackServer,
)


# =============================================================================
# OOB PROTOCOL ENUM TESTS
# =============================================================================

class TestOOBProtocol:
    """Tests for OOBProtocol enum."""

    def test_all_protocols_defined(self):
        """Test all expected protocols are defined."""
        assert OOBProtocol.DNS.value == "dns"
        assert OOBProtocol.HTTP.value == "http"
        assert OOBProtocol.HTTPS.value == "https"
        assert OOBProtocol.SMTP.value == "smtp"
        assert OOBProtocol.FTP.value == "ftp"
        assert OOBProtocol.LDAP.value == "ldap"

    def test_protocol_count(self):
        """Test expected number of protocols."""
        assert len(OOBProtocol) == 6


# =============================================================================
# CALLBACK TYPE ENUM TESTS
# =============================================================================

class TestCallbackType:
    """Tests for CallbackType enum."""

    def test_all_callback_types_defined(self):
        """Test all callback types are defined."""
        assert CallbackType.DNS_LOOKUP.value == "dns_lookup"
        assert CallbackType.HTTP_GET.value == "http_get"
        assert CallbackType.HTTP_POST.value == "http_post"
        assert CallbackType.SMTP_CONNECTION.value == "smtp_connection"
        assert CallbackType.GENERIC.value == "generic"

    def test_callback_type_count(self):
        """Test expected number of callback types."""
        assert len(CallbackType) == 5


# =============================================================================
# OOB TOKEN DATACLASS TESTS
# =============================================================================

class TestOOBToken:
    """Tests for OOBToken dataclass."""

    @pytest.fixture
    def token(self):
        """Create a basic OOB token."""
        return OOBToken(
            token="abc123",
            correlation_id="corr456",
            scan_id="scan789",
            payload_type="ssrf",
            target_url="https://example.com/api",
            parameter="url"
        )

    def test_token_creation(self, token):
        """Test basic token creation."""
        assert token.token == "abc123"
        assert token.correlation_id == "corr456"
        assert token.scan_id == "scan789"
        assert token.payload_type == "ssrf"

    def test_token_default_created_at(self, token):
        """Test token has default created_at."""
        assert isinstance(token.created_at, datetime)

    def test_token_default_expires_at(self, token):
        """Test token has default expires_at (1 hour)."""
        assert isinstance(token.expires_at, datetime)
        assert token.expires_at > token.created_at

    def test_token_default_callbacks_empty(self, token):
        """Test token starts with no callbacks."""
        assert token.callbacks_received == []
        assert token.first_callback_at is None

    def test_is_expired_fresh_token(self, token):
        """Test fresh token is not expired."""
        assert token.is_expired is False

    def test_is_expired_expired_token(self):
        """Test expired token is detected."""
        token = OOBToken(
            token="test",
            correlation_id="corr",
            scan_id="scan",
            payload_type="ssrf",
            target_url="https://example.com",
            parameter="url",
            expires_at=datetime.now() - timedelta(hours=1)
        )
        assert token.is_expired is True

    def test_has_callback_no_callbacks(self, token):
        """Test has_callback is False with no callbacks."""
        assert token.has_callback is False

    def test_has_callback_with_callback(self, token):
        """Test has_callback is True after callback."""
        token.record_callback(CallbackType.HTTP_GET, "1.2.3.4", {})
        assert token.has_callback is True

    def test_record_callback(self, token):
        """Test recording a callback."""
        token.record_callback(
            CallbackType.HTTP_GET,
            "192.168.1.100",
            {"path": "/test"}
        )
        assert len(token.callbacks_received) == 1
        assert token.callbacks_received[0]["type"] == "http_get"
        assert token.callbacks_received[0]["source_ip"] == "192.168.1.100"

    def test_record_callback_sets_first_callback(self, token):
        """Test first callback sets first_callback_at."""
        assert token.first_callback_at is None
        token.record_callback(CallbackType.DNS_LOOKUP, "1.1.1.1", {})
        assert token.first_callback_at is not None

    def test_record_multiple_callbacks(self, token):
        """Test recording multiple callbacks."""
        token.record_callback(CallbackType.HTTP_GET, "1.1.1.1", {})
        token.record_callback(CallbackType.HTTP_POST, "2.2.2.2", {})
        assert len(token.callbacks_received) == 2

    def test_to_dict(self, token):
        """Test token serialization."""
        result = token.to_dict()
        assert result["token"] == "abc123"
        assert result["correlation_id"] == "corr456"
        assert result["scan_id"] == "scan789"
        assert result["payload_type"] == "ssrf"
        assert "created_at" in result
        assert "expires_at" in result


# =============================================================================
# OOB CALLBACK DATACLASS TESTS
# =============================================================================

class TestOOBCallback:
    """Tests for OOBCallback dataclass."""

    @pytest.fixture
    def callback(self):
        """Create a basic callback."""
        return OOBCallback(
            token="abc123",
            callback_type=CallbackType.HTTP_GET,
            protocol=OOBProtocol.HTTP,
            source_ip="192.168.1.100",
            received_at=datetime.now(),
            raw_data="GET /abc123 HTTP/1.1"
        )

    def test_callback_creation(self, callback):
        """Test basic callback creation."""
        assert callback.token == "abc123"
        assert callback.callback_type == CallbackType.HTTP_GET
        assert callback.protocol == OOBProtocol.HTTP

    def test_callback_default_parsed_data(self, callback):
        """Test callback has default empty parsed_data."""
        assert callback.parsed_data == {}

    def test_callback_to_dict(self, callback):
        """Test callback serialization."""
        result = callback.to_dict()
        assert result["token"] == "abc123"
        assert result["callback_type"] == "http_get"
        assert result["protocol"] == "http"
        assert result["source_ip"] == "192.168.1.100"

    def test_callback_to_dict_truncates_raw_data(self):
        """Test raw_data is truncated in to_dict."""
        long_data = "x" * 2000
        callback = OOBCallback(
            token="test",
            callback_type=CallbackType.HTTP_POST,
            protocol=OOBProtocol.HTTP,
            source_ip="1.1.1.1",
            received_at=datetime.now(),
            raw_data=long_data
        )
        result = callback.to_dict()
        assert len(result["raw_data"]) <= 1000


# =============================================================================
# OOB PAYLOAD GENERATOR TESTS
# =============================================================================

class TestOOBPayloadGenerator:
    """Tests for OOBPayloadGenerator class."""

    @pytest.fixture
    def generator(self):
        """Create payload generator."""
        return OOBPayloadGenerator(
            callback_host="oob.example.com:8888",
            callback_domain="oob.example.com"
        )

    def test_generator_initialization(self, generator):
        """Test generator initialization."""
        assert generator.callback_host == "oob.example.com:8888"
        assert generator.callback_domain == "oob.example.com"

    def test_templates_not_empty(self, generator):
        """Test templates are defined."""
        assert len(generator.TEMPLATES) > 0

    def test_generate_token(self, generator):
        """Test token generation."""
        token = generator.generate_token()
        assert len(token) == 16  # 8 bytes = 16 hex chars

    def test_generate_token_custom_length(self, generator):
        """Test custom token length."""
        token = generator.generate_token(length=32)
        assert len(token) == 32

    def test_generate_unique_tokens(self, generator):
        """Test tokens are unique."""
        tokens = [generator.generate_token() for _ in range(100)]
        assert len(set(tokens)) == 100

    def test_generate_correlation_id(self, generator):
        """Test correlation ID generation."""
        corr_id = generator.generate_correlation_id(
            scan_id="scan123",
            target="https://example.com",
            param="url"
        )
        assert len(corr_id) == 16

    def test_generate_payload_ssrf_http(self, generator):
        """Test SSRF HTTP payload generation."""
        payload = generator.generate_payload("ssrf_http", "testtoken")
        assert "http://oob.example.com:8888/testtoken" in payload

    def test_generate_payload_ssrf_dns(self, generator):
        """Test SSRF DNS payload generation."""
        payload = generator.generate_payload("ssrf_dns", "testtoken")
        assert "testtoken.oob.example.com" in payload

    def test_generate_payload_xxe_http(self, generator):
        """Test XXE HTTP payload generation."""
        payload = generator.generate_payload("xxe_http", "testtoken")
        assert "<!DOCTYPE" in payload
        assert "ENTITY" in payload
        assert "testtoken" in payload

    def test_generate_payload_rce_nslookup(self, generator):
        """Test RCE nslookup payload."""
        payload = generator.generate_payload("rce_nslookup", "testtoken")
        assert "nslookup" in payload
        assert "testtoken" in payload

    def test_generate_payload_jndi_ldap(self, generator):
        """Test JNDI LDAP payload."""
        payload = generator.generate_payload("jndi_ldap", "testtoken")
        assert "${jndi:ldap://" in payload
        assert "testtoken" in payload

    def test_generate_payload_unknown_template(self, generator):
        """Test unknown template raises error."""
        with pytest.raises(ValueError):
            generator.generate_payload("unknown_template", "token")

    def test_generate_all_payloads_ssrf(self, generator):
        """Test generating all SSRF payloads."""
        payloads = generator.generate_all_payloads("ssrf", "testtoken")
        assert len(payloads) >= 3  # ssrf_http, ssrf_https, ssrf_dns
        for p in payloads:
            assert "template" in p
            assert "payload" in p
            assert "testtoken" in p["payload"]

    def test_generate_all_payloads_xxe(self, generator):
        """Test generating all XXE payloads."""
        payloads = generator.generate_all_payloads("xxe", "testtoken")
        assert len(payloads) >= 3
        for p in payloads:
            assert p["template"].startswith("xxe_")

    def test_generate_all_payloads_sqli(self, generator):
        """Test generating all SQLi OOB payloads."""
        payloads = generator.generate_all_payloads("sqli", "testtoken")
        assert len(payloads) >= 6  # Multiple DB types


class TestOOBPayloadTemplates:
    """Tests for specific payload templates."""

    @pytest.fixture
    def generator(self):
        return OOBPayloadGenerator()

    def test_ssrf_templates_exist(self, generator):
        """Test SSRF templates exist."""
        assert "ssrf_http" in generator.TEMPLATES
        assert "ssrf_https" in generator.TEMPLATES
        assert "ssrf_dns" in generator.TEMPLATES

    def test_xxe_templates_exist(self, generator):
        """Test XXE templates exist."""
        assert "xxe_http" in generator.TEMPLATES
        assert "xxe_dns" in generator.TEMPLATES
        assert "xxe_param" in generator.TEMPLATES

    def test_rce_templates_exist(self, generator):
        """Test RCE templates exist."""
        assert "rce_nslookup" in generator.TEMPLATES
        assert "rce_curl" in generator.TEMPLATES
        assert "rce_wget" in generator.TEMPLATES

    def test_sqli_oracle_templates_exist(self, generator):
        """Test Oracle SQLi OOB templates exist."""
        assert "sqli_oracle_http" in generator.TEMPLATES
        assert "sqli_oracle_dns" in generator.TEMPLATES

    def test_sqli_mssql_templates_exist(self, generator):
        """Test MSSQL SQLi OOB templates exist."""
        assert "sqli_mssql_dns" in generator.TEMPLATES

    def test_sqli_postgres_templates_exist(self, generator):
        """Test PostgreSQL SQLi OOB templates exist."""
        assert "sqli_postgres_dns" in generator.TEMPLATES

    def test_sqli_mysql_templates_exist(self, generator):
        """Test MySQL SQLi OOB templates exist."""
        assert "sqli_mysql_dns" in generator.TEMPLATES

    def test_jndi_templates_exist(self, generator):
        """Test JNDI templates exist."""
        assert "jndi_ldap" in generator.TEMPLATES
        assert "jndi_dns" in generator.TEMPLATES


# =============================================================================
# OOB CALLBACK STORE TESTS
# =============================================================================

class TestOOBCallbackStore:
    """Tests for OOBCallbackStore class."""

    @pytest.fixture
    def store(self):
        """Create callback store."""
        return OOBCallbackStore(token_ttl_hours=1)

    def test_store_initialization(self, store):
        """Test store initialization."""
        assert len(store.tokens) == 0
        assert len(store.callbacks) == 0

    def test_register_token(self, store):
        """Test token registration."""
        token = store.register_token(
            scan_id="scan123",
            payload_type="ssrf",
            target_url="https://example.com",
            parameter="url"
        )
        assert token.token in store.tokens
        assert token.scan_id == "scan123"
        assert token.payload_type == "ssrf"

    def test_register_token_correlation_id(self, store):
        """Test registered token has correlation ID."""
        token = store.register_token(
            scan_id="scan123",
            payload_type="xxe",
            target_url="https://example.com",
            parameter="data"
        )
        assert len(token.correlation_id) == 16

    def test_register_multiple_tokens(self, store):
        """Test registering multiple tokens."""
        t1 = store.register_token("scan1", "ssrf", "http://a.com", "p1")
        t2 = store.register_token("scan1", "xxe", "http://b.com", "p2")
        assert t1.token != t2.token
        assert len(store.tokens) == 2

    def test_record_callback_success(self, store):
        """Test successful callback recording."""
        token = store.register_token("scan", "ssrf", "http://test.com", "url")

        result = store.record_callback(
            token_str=token.token,
            callback_type=CallbackType.HTTP_GET,
            protocol=OOBProtocol.HTTP,
            source_ip="1.2.3.4",
            raw_data="GET /token HTTP/1.1"
        )
        assert result is True
        assert token.has_callback is True

    def test_record_callback_unknown_token(self, store):
        """Test callback with unknown token."""
        result = store.record_callback(
            token_str="nonexistent",
            callback_type=CallbackType.HTTP_GET,
            protocol=OOBProtocol.HTTP,
            source_ip="1.1.1.1",
            raw_data="GET /test"
        )
        assert result is False

    def test_record_callback_expired_token(self, store):
        """Test callback with expired token."""
        token = store.register_token("scan", "ssrf", "http://test.com", "url")
        # Force expiration
        token.expires_at = datetime.now() - timedelta(hours=1)

        result = store.record_callback(
            token_str=token.token,
            callback_type=CallbackType.HTTP_GET,
            protocol=OOBProtocol.HTTP,
            source_ip="1.1.1.1",
            raw_data="GET /test"
        )
        assert result is False

    def test_get_token(self, store):
        """Test getting token by string."""
        token = store.register_token("scan", "ssrf", "http://test.com", "url")
        retrieved = store.get_token(token.token)
        assert retrieved is token

    def test_get_token_not_found(self, store):
        """Test getting non-existent token."""
        result = store.get_token("nonexistent")
        assert result is None

    def test_get_callbacks_for_token(self, store):
        """Test getting callbacks for a token."""
        token = store.register_token("scan", "ssrf", "http://test.com", "url")
        store.record_callback(token.token, CallbackType.HTTP_GET, OOBProtocol.HTTP, "1.1.1.1", "data1")
        store.record_callback(token.token, CallbackType.HTTP_POST, OOBProtocol.HTTP, "2.2.2.2", "data2")

        callbacks = store.get_callbacks_for_token(token.token)
        assert len(callbacks) == 2

    def test_check_callback(self, store):
        """Test check_callback method."""
        token = store.register_token("scan", "ssrf", "http://test.com", "url")
        assert store.check_callback(token.token) is False

        store.record_callback(token.token, CallbackType.HTTP_GET, OOBProtocol.HTTP, "1.1.1.1", "data")
        assert store.check_callback(token.token) is True

    def test_wait_for_callback_immediate(self, store):
        """Test wait_for_callback with immediate callback."""
        token = store.register_token("scan", "ssrf", "http://test.com", "url")
        store.record_callback(token.token, CallbackType.HTTP_GET, OOBProtocol.HTTP, "1.1.1.1", "data")

        result = store.wait_for_callback(token.token, timeout_seconds=1)
        assert result is True

    def test_wait_for_callback_timeout(self, store):
        """Test wait_for_callback timeout."""
        token = store.register_token("scan", "ssrf", "http://test.com", "url")

        start = time.time()
        result = store.wait_for_callback(token.token, timeout_seconds=0.5, poll_interval=0.1)
        elapsed = time.time() - start

        assert result is False
        assert elapsed >= 0.5

    def test_cleanup_expired(self, store):
        """Test cleanup_expired removes old tokens."""
        # Create expired token
        token = store.register_token("scan", "ssrf", "http://test.com", "url")
        token.expires_at = datetime.now() - timedelta(hours=1)

        # Create fresh token
        fresh = store.register_token("scan", "xxe", "http://test.com", "data")

        assert len(store.tokens) == 2
        store.cleanup_expired()
        assert len(store.tokens) == 1
        assert fresh.token in store.tokens


class TestOOBCallbackStoreStatistics:
    """Tests for OOBCallbackStore statistics."""

    @pytest.fixture
    def populated_store(self):
        """Create store with various tokens."""
        store = OOBCallbackStore()

        # SSRF tokens - 2 with callbacks
        for i in range(3):
            t = store.register_token(f"scan{i}", "ssrf", f"http://test{i}.com", "url")
            if i < 2:
                store.record_callback(t.token, CallbackType.HTTP_GET, OOBProtocol.HTTP, "1.1.1.1", "data")

        # XXE tokens - 1 with callback
        for i in range(2):
            t = store.register_token(f"scan{i}", "xxe", f"http://test{i}.com", "data")
            if i < 1:
                store.record_callback(t.token, CallbackType.DNS_LOOKUP, OOBProtocol.DNS, "2.2.2.2", "dns")

        return store

    def test_get_statistics(self, populated_store):
        """Test statistics generation."""
        stats = populated_store.get_statistics()
        assert stats["total_tokens"] == 5
        assert stats["tokens_with_callbacks"] == 3
        assert stats["total_callbacks"] == 3

    def test_callback_rate(self, populated_store):
        """Test callback rate calculation."""
        stats = populated_store.get_statistics()
        # 3 callbacks out of 5 tokens = 60%
        assert stats["callback_rate"] == 60.0

    def test_by_payload_type(self, populated_store):
        """Test breakdown by payload type."""
        stats = populated_store.get_statistics()
        assert stats["by_payload_type"]["ssrf"]["total"] == 3
        assert stats["by_payload_type"]["ssrf"]["callbacks"] == 2
        assert stats["by_payload_type"]["xxe"]["total"] == 2
        assert stats["by_payload_type"]["xxe"]["callbacks"] == 1


# =============================================================================
# OOB ENGINE TESTS
# =============================================================================

class TestOOBEngine:
    """Tests for OOBEngine class."""

    @pytest.fixture
    def engine(self):
        """Create OOB engine without server."""
        return OOBEngine(
            callback_host="oob.test.com",
            callback_port=8888,
            callback_domain="oob.test.com",
            start_server=False
        )

    def test_engine_initialization(self, engine):
        """Test engine initialization."""
        assert engine.callback_host == "oob.test.com:8888"
        assert engine.callback_domain == "oob.test.com"
        assert engine._server is None

    def test_engine_version(self, engine):
        """Test engine has version."""
        assert "ENTERPRISE" in engine.VERSION

    def test_generate_oob_payloads(self, engine):
        """Test generating OOB payloads."""
        payloads = engine.generate_oob_payloads(
            scan_id="scan123",
            payload_type="ssrf",
            target_url="https://example.com/fetch",
            parameter="url"
        )

        assert len(payloads) >= 3  # Multiple SSRF templates
        for p in payloads:
            assert "oob_token" in p
            assert "correlation_id" in p
            assert "payload" in p

    def test_generate_oob_payloads_registers_token(self, engine):
        """Test payloads register token in store."""
        payloads = engine.generate_oob_payloads(
            scan_id="scan123",
            payload_type="xxe",
            target_url="https://example.com/api",
            parameter="data"
        )

        token_str = payloads[0]["oob_token"]
        token = engine.store.get_token(token_str)
        assert token is not None
        assert token.payload_type == "xxe"

    def test_check_callback(self, engine):
        """Test check_callback method."""
        payloads = engine.generate_oob_payloads("scan", "ssrf", "http://test.com", "url")
        token = payloads[0]["oob_token"]

        assert engine.check_callback(token) is False

        engine.store.record_callback(
            token, CallbackType.HTTP_GET, OOBProtocol.HTTP, "1.1.1.1", "data"
        )
        assert engine.check_callback(token) is True

    def test_get_callback_evidence_no_callback(self, engine):
        """Test get_callback_evidence with no callback."""
        payloads = engine.generate_oob_payloads("scan", "ssrf", "http://test.com", "url")
        token = payloads[0]["oob_token"]

        evidence = engine.get_callback_evidence(token)
        assert evidence is None

    def test_get_callback_evidence_with_callback(self, engine):
        """Test get_callback_evidence with callback."""
        payloads = engine.generate_oob_payloads("scan", "ssrf", "http://test.com", "url")
        token = payloads[0]["oob_token"]

        engine.store.record_callback(
            token, CallbackType.HTTP_GET, OOBProtocol.HTTP, "192.168.1.1", "GET /token"
        )

        evidence = engine.get_callback_evidence(token)
        assert evidence is not None
        assert evidence["token"] == token
        assert evidence["callback_count"] == 1
        assert evidence["first_callback"] is not None

    def test_get_statistics(self, engine):
        """Test get_statistics method."""
        # Generate some payloads
        engine.generate_oob_payloads("scan1", "ssrf", "http://a.com", "url")
        engine.generate_oob_payloads("scan2", "xxe", "http://b.com", "data")

        stats = engine.get_statistics()
        assert stats["version"] == engine.VERSION
        assert stats["callback_host"] == engine.callback_host
        assert stats["total_tokens"] >= 2

    def test_shutdown(self, engine):
        """Test shutdown method."""
        # Should not raise
        engine.shutdown()


class TestOOBEngineAsync:
    """Async tests for OOBEngine."""

    @pytest.fixture
    def engine(self):
        return OOBEngine(
            callback_host="oob.test.com",
            callback_port=8888,
            callback_domain="oob.test.com",
            start_server=False
        )

    @pytest.mark.asyncio
    async def test_wait_for_callback_async_immediate(self, engine):
        """Test async wait with immediate callback."""
        payloads = engine.generate_oob_payloads("scan", "ssrf", "http://test.com", "url")
        token = payloads[0]["oob_token"]

        engine.store.record_callback(
            token, CallbackType.HTTP_GET, OOBProtocol.HTTP, "1.1.1.1", "data"
        )

        result = await engine.wait_for_callback_async(token, timeout=1.0)
        assert result is True

    @pytest.mark.asyncio
    async def test_wait_for_callback_async_timeout(self, engine):
        """Test async wait timeout."""
        payloads = engine.generate_oob_payloads("scan", "ssrf", "http://test.com", "url")
        token = payloads[0]["oob_token"]

        result = await engine.wait_for_callback_async(token, timeout=0.5)
        assert result is False


# =============================================================================
# SIMPLE HTTP CALLBACK SERVER TESTS
# =============================================================================

class TestSimpleHTTPCallbackServer:
    """Tests for SimpleHTTPCallbackServer class."""

    def test_server_initialization(self):
        """Test server initialization."""
        store = OOBCallbackStore()
        server = SimpleHTTPCallbackServer(
            host="0.0.0.0",
            port=9999,
            callback_store=store
        )
        assert server.host == "0.0.0.0"
        assert server.port == 9999
        assert server.store is store

    def test_server_default_store(self):
        """Test server creates default store."""
        server = SimpleHTTPCallbackServer()
        assert server.store is not None
        assert isinstance(server.store, OOBCallbackStore)

    def test_server_not_running_initially(self):
        """Test server is not running initially."""
        server = SimpleHTTPCallbackServer()
        assert server._running is False


# =============================================================================
# EXTERNAL OOB SERVICE TESTS
# =============================================================================

class TestExternalOOBService:
    """Tests for ExternalOOBService class."""

    def test_interactsh_service(self):
        """Test Interactsh service configuration."""
        service = ExternalOOBService(service="interactsh")
        assert service.service == "interactsh"
        assert "interact.sh" in service.config["base_url"]

    def test_burp_collaborator_service(self):
        """Test Burp Collaborator service configuration."""
        service = ExternalOOBService(service="burp_collaborator")
        assert service.service == "burp_collaborator"
        assert "burpcollaborator.net" in service.config["base_url"]

    def test_unknown_service_raises_error(self):
        """Test unknown service raises ValueError."""
        with pytest.raises(ValueError):
            ExternalOOBService(service="unknown_service")

    def test_generate_payload_url_http(self):
        """Test HTTP payload URL generation."""
        service = ExternalOOBService(service="interactsh")
        url = service.generate_payload_url("mytoken", protocol="http")
        assert "http://" in url
        assert "mytoken" in url
        assert "interact.sh" in url

    def test_generate_payload_url_dns(self):
        """Test DNS payload URL generation."""
        service = ExternalOOBService(service="interactsh")
        url = service.generate_payload_url("mytoken", protocol="dns")
        assert "mytoken.interact.sh" in url

    def test_services_defined(self):
        """Test all expected services are defined."""
        assert "interactsh" in ExternalOOBService.SERVICES
        assert "burp_collaborator" in ExternalOOBService.SERVICES


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestOOBIntegration:
    """Integration tests for OOB engine."""

    def test_complete_oob_workflow(self):
        """Test complete OOB detection workflow."""
        # 1. Create engine
        engine = OOBEngine(
            callback_host="127.0.0.1",
            callback_port=8888,
            callback_domain="oob.local",
            start_server=False
        )

        # 2. Generate payloads for SSRF scan
        payloads = engine.generate_oob_payloads(
            scan_id="vuln-scan-001",
            payload_type="ssrf",
            target_url="https://vulnerable.example.com/proxy",
            parameter="url"
        )

        assert len(payloads) > 0
        token = payloads[0]["oob_token"]

        # 3. Simulate callback received
        engine.store.record_callback(
            token_str=token,
            callback_type=CallbackType.HTTP_GET,
            protocol=OOBProtocol.HTTP,
            source_ip="10.0.0.50",  # Internal IP - confirms SSRF
            raw_data="GET /token HTTP/1.1\nHost: 127.0.0.1:8888"
        )

        # 4. Verify callback
        assert engine.check_callback(token) is True

        # 5. Get evidence for report
        evidence = engine.get_callback_evidence(token)
        assert evidence is not None
        assert evidence["payload_type"] == "ssrf"
        assert evidence["callback_count"] == 1
        assert evidence["first_callback"]["source_ip"] == "10.0.0.50"

        # 6. Check statistics
        stats = engine.get_statistics()
        assert stats["tokens_with_callbacks"] == 1

        # 7. Cleanup
        engine.shutdown()

    def test_multiple_payload_types(self):
        """Test engine with multiple payload types."""
        engine = OOBEngine(start_server=False)

        # Generate payloads for different vuln types
        ssrf_payloads = engine.generate_oob_payloads("scan", "ssrf", "http://test.com", "url")
        xxe_payloads = engine.generate_oob_payloads("scan", "xxe", "http://test.com", "data")
        rce_payloads = engine.generate_oob_payloads("scan", "rce", "http://test.com", "cmd")

        assert len(ssrf_payloads) > 0
        assert len(xxe_payloads) > 0
        assert len(rce_payloads) > 0

        # Tokens should be different
        all_tokens = set()
        for p in ssrf_payloads + xxe_payloads + rce_payloads:
            all_tokens.add(p["oob_token"])

        # At minimum we should have different tokens for each type
        assert len(all_tokens) >= 3

    def test_token_expiration_workflow(self):
        """Test token expiration handling."""
        store = OOBCallbackStore(token_ttl_hours=1)

        # Create token
        token = store.register_token("scan", "ssrf", "http://test.com", "url")
        assert token.is_expired is False

        # Force expiration
        token.expires_at = datetime.now() - timedelta(minutes=1)
        assert token.is_expired is True

        # Callback should fail on expired token
        result = store.record_callback(
            token.token,
            CallbackType.HTTP_GET,
            OOBProtocol.HTTP,
            "1.1.1.1",
            "data"
        )
        assert result is False

        # Cleanup should remove it
        store.cleanup_expired()
        assert token.token not in store.tokens

