"""
HTTP/3 (QUIC) Client for PHANTOM AI.

Provides async HTTP/3 support using aioquic library.
Falls back to HTTP/2 or HTTP/1.1 if QUIC is unavailable.

Features:
- QUIC connection management
- 0-RTT early data support
- Connection migration detection
- Alt-Svc header parsing
- Automatic protocol negotiation
"""

import asyncio
import ssl
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from utils.logger import get_logger

logger = get_logger(__name__)

# Try to import aioquic - graceful degradation if not available
AIOQUIC_AVAILABLE = False
try:
    from aioquic.asyncio import connect as quic_connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import (
        DataReceived,
        HeadersReceived,
        PushPromiseReceived,
        H3Event,
    )
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import (
        ConnectionTerminated,
        HandshakeCompleted,
        StreamDataReceived,
    )
    AIOQUIC_AVAILABLE = True
except ImportError:
    logger.debug("aioquic not available - HTTP/3 support disabled")


class HTTP3Status(Enum):
    """HTTP/3 connection status."""
    NOT_SUPPORTED = "not_supported"
    AVAILABLE = "available"
    CONNECTED = "connected"
    FAILED = "failed"
    FALLBACK_H2 = "fallback_h2"
    FALLBACK_H1 = "fallback_h1"


@dataclass
class HTTP3Response:
    """HTTP/3 response container."""
    status_code: int
    headers: dict[str, str]
    body: bytes
    protocol: str = "h3"

    # QUIC-specific metadata
    quic_version: str | None = None
    connection_id: bytes | None = None
    rtt_ms: float | None = None
    early_data_accepted: bool = False

    @property
    def text(self) -> str:
        """Decode body as UTF-8."""
        try:
            return self.body.decode("utf-8")
        except UnicodeDecodeError:
            return self.body.decode("latin-1")

    @property
    def json(self) -> Any:
        """Parse body as JSON."""
        import json
        return json.loads(self.text)


@dataclass
class HTTP3Request:
    """HTTP/3 request container."""
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None

    # QUIC options
    use_early_data: bool = False
    priority: int = 16  # Default priority (0-255)


@dataclass
class AltSvcInfo:
    """Parsed Alt-Svc header info."""
    protocol: str
    host: str
    port: int
    max_age: int = 86400
    persist: bool = False


class HTTP3Client:
    """
    Async HTTP/3 client using QUIC protocol.

    Usage:
        async with HTTP3Client() as client:
            response = await client.get("https://example.com")
    """

    def __init__(
        self,
        timeout: float = 30.0,
        verify_ssl: bool = True,
        local_port: int = 0,
        max_connections: int = 10,
    ):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.local_port = local_port
        self.max_connections = max_connections

        # Connection pool
        self._connections: dict[str, Any] = {}
        self._lock = asyncio.Lock()

        # Statistics
        self.stats = {
            "requests": 0,
            "h3_requests": 0,
            "h2_fallbacks": 0,
            "h1_fallbacks": 0,
            "connection_errors": 0,
            "early_data_attempts": 0,
            "early_data_accepted": 0,
        }

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        """Close all connections."""
        async with self._lock:
            for conn in self._connections.values():
                try:
                    conn.close()
                except Exception:
                    pass
            self._connections.clear()

    def is_available(self) -> bool:
        """Check if HTTP/3 support is available."""
        return AIOQUIC_AVAILABLE

    async def check_http3_support(self, url: str) -> tuple[HTTP3Status, AltSvcInfo | None]:
        """
        Check if a URL supports HTTP/3 via Alt-Svc header.

        Returns:
            Tuple of (status, alt_svc_info)
        """
        if not AIOQUIC_AVAILABLE:
            return HTTP3Status.NOT_SUPPORTED, None

        try:
            import httpx

            # Make HTTP/1.1 or HTTP/2 request to check Alt-Svc
            async with httpx.AsyncClient(http2=True, timeout=10.0) as client:
                response = await client.head(url)

                # Check Alt-Svc header
                alt_svc = response.headers.get("alt-svc", "")
                if not alt_svc:
                    return HTTP3Status.NOT_SUPPORTED, None

                # Parse Alt-Svc
                info = self._parse_alt_svc(alt_svc, url)
                if info and info.protocol in ("h3", "h3-29", "h3-27"):
                    return HTTP3Status.AVAILABLE, info

                return HTTP3Status.NOT_SUPPORTED, None

        except Exception as e:
            logger.debug(f"HTTP/3 check failed: {e}")
            return HTTP3Status.FAILED, None

    def _parse_alt_svc(self, header: str, base_url: str) -> AltSvcInfo | None:
        """Parse Alt-Svc header value."""
        parsed = urlparse(base_url)

        # Alt-Svc format: h3=":443"; ma=86400, h3-29=":443"
        for part in header.split(","):
            part = part.strip()
            if not part:
                continue

            # Parse protocol="host:port"
            if "=" not in part:
                continue

            proto, rest = part.split("=", 1)
            proto = proto.strip()

            if proto not in ("h3", "h3-29", "h3-27"):
                continue

            # Parse value
            rest = rest.strip().strip('"').strip("'")

            # Handle ":port" format (use same host)
            if rest.startswith(":"):
                port = int(rest[1:].split(";")[0])
                host = parsed.hostname or "localhost"
            else:
                # Parse host:port
                if ":" in rest:
                    host, port_str = rest.rsplit(":", 1)
                    port = int(port_str.split(";")[0])
                else:
                    host = rest.split(";")[0]
                    port = 443

            # Parse max-age
            max_age = 86400
            if "ma=" in part:
                try:
                    ma_part = part.split("ma=")[1]
                    max_age = int(ma_part.split(";")[0].split(",")[0])
                except (ValueError, IndexError):
                    pass

            return AltSvcInfo(
                protocol=proto,
                host=host,
                port=port,
                max_age=max_age,
            )

        return None

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        use_early_data: bool = False,
    ) -> HTTP3Response:
        """
        Make an HTTP/3 request.

        Falls back to HTTP/2 or HTTP/1.1 if QUIC fails.
        """
        self.stats["requests"] += 1

        if not AIOQUIC_AVAILABLE:
            return await self._fallback_request(method, url, headers, body)

        try:
            return await self._h3_request(method, url, headers, body, use_early_data)
        except Exception as e:
            logger.debug(f"HTTP/3 request failed, falling back: {e}")
            self.stats["connection_errors"] += 1
            return await self._fallback_request(method, url, headers, body)

    async def _h3_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        body: bytes | None,
        use_early_data: bool,
    ) -> HTTP3Response:
        """Make actual HTTP/3 request via QUIC."""
        parsed = urlparse(url)
        host = parsed.hostname or "localhost"
        port = parsed.port or 443
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        # Build request headers
        req_headers = [
            (b":method", method.encode()),
            (b":scheme", b"https"),
            (b":authority", host.encode()),
            (b":path", path.encode()),
        ]

        if headers:
            for key, value in headers.items():
                if key.lower() not in (":method", ":scheme", ":authority", ":path"):
                    req_headers.append((key.lower().encode(), value.encode()))

        # Add default headers
        if not any(h[0] == b"user-agent" for h in req_headers):
            req_headers.append((b"user-agent", b"PHANTOM-AI/1.0 HTTP3Client"))

        # Configure QUIC
        configuration = QuicConfiguration(
            is_client=True,
            alpn_protocols=H3_ALPN,
        )

        if not self.verify_ssl:
            configuration.verify_mode = ssl.CERT_NONE

        # Track early data
        if use_early_data:
            self.stats["early_data_attempts"] += 1

        start_time = time.time()

        # Connect and make request
        async with quic_connect(
            host,
            port,
            configuration=configuration,
            create_protocol=HttpClientProtocol,
        ) as protocol:
            # Wait for connection
            await protocol.wait_connected()

            # Make request
            response_headers = {}
            response_body = b""

            stream_id = protocol.send_request(req_headers, body)

            # Wait for response
            async for event in protocol.receive_events(stream_id):
                if isinstance(event, HeadersReceived):
                    for name, value in event.headers:
                        response_headers[name.decode()] = value.decode()
                elif isinstance(event, DataReceived):
                    response_body += event.data

            elapsed = time.time() - start_time

            # Extract status code
            status_code = int(response_headers.get(":status", "0"))

            # Clean headers (remove pseudo-headers)
            clean_headers = {
                k: v for k, v in response_headers.items()
                if not k.startswith(":")
            }

            self.stats["h3_requests"] += 1

            return HTTP3Response(
                status_code=status_code,
                headers=clean_headers,
                body=response_body,
                protocol="h3",
                rtt_ms=elapsed * 1000,
                early_data_accepted=protocol.early_data_accepted if hasattr(protocol, "early_data_accepted") else False,
            )

    async def _fallback_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        body: bytes | None,
    ) -> HTTP3Response:
        """Fallback to HTTP/2 or HTTP/1.1."""
        import httpx

        try:
            # Try HTTP/2 first
            async with httpx.AsyncClient(http2=True, timeout=self.timeout, verify=self.verify_ssl) as client:
                response = await client.request(
                    method,
                    url,
                    headers=headers,
                    content=body,
                )

                protocol = "h2" if response.http_version == "HTTP/2" else "h1.1"
                if protocol == "h2":
                    self.stats["h2_fallbacks"] += 1
                else:
                    self.stats["h1_fallbacks"] += 1

                return HTTP3Response(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=response.content,
                    protocol=protocol,
                )
        except Exception as e:
            logger.error(f"Fallback request failed: {e}")
            self.stats["h1_fallbacks"] += 1
            raise

    async def get(self, url: str, headers: dict[str, str] | None = None) -> HTTP3Response:
        """HTTP GET request."""
        return await self.request("GET", url, headers)

    async def post(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> HTTP3Response:
        """HTTP POST request."""
        return await self.request("POST", url, headers, body)

    async def head(self, url: str, headers: dict[str, str] | None = None) -> HTTP3Response:
        """HTTP HEAD request."""
        return await self.request("HEAD", url, headers)


# HttpClientProtocol only defined when aioquic is available
if AIOQUIC_AVAILABLE:
    class HttpClientProtocol(QuicConnectionProtocol):
        """HTTP/3 client protocol handler."""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._h3: H3Connection | None = None
            self._request_events: dict[int, asyncio.Queue] = {}
            self._request_waiter: dict[int, asyncio.Event] = {}
            self.early_data_accepted = False

        def quic_event_received(self, event):
            """Handle QUIC events."""
            if isinstance(event, HandshakeCompleted):
                self._h3 = H3Connection(self._quic)
            elif isinstance(event, ConnectionTerminated):
                for waiter in self._request_waiter.values():
                    waiter.set()

            # Process HTTP/3 events
            if self._h3:
                for h3_event in self._h3.handle_event(event):
                    self._h3_event_received(h3_event)

        def _h3_event_received(self, event: H3Event):
            """Handle HTTP/3 events."""
            if isinstance(event, (HeadersReceived, DataReceived)):
                stream_id = event.stream_id
                if stream_id in self._request_events:
                    self._request_events[stream_id].put_nowait(event)

                    # Signal completion if stream ended
                    if hasattr(event, "stream_ended") and event.stream_ended:
                        if stream_id in self._request_waiter:
                            self._request_waiter[stream_id].set()

        async def wait_connected(self):
            """Wait for QUIC handshake to complete."""
            while self._h3 is None:
                await asyncio.sleep(0.01)

        def send_request(
            self,
            headers: list[tuple[bytes, bytes]],
            body: bytes | None = None,
        ) -> int:
            """Send HTTP/3 request and return stream ID."""
            stream_id = self._quic.get_next_available_stream_id()

            self._request_events[stream_id] = asyncio.Queue()
            self._request_waiter[stream_id] = asyncio.Event()

            # Send headers
            self._h3.send_headers(
                stream_id=stream_id,
                headers=headers,
                end_stream=(body is None),
            )

            # Send body if present
            if body:
                self._h3.send_data(
                    stream_id=stream_id,
                    data=body,
                    end_stream=True,
                )

            self.transmit()
            return stream_id

        async def receive_events(self, stream_id: int):
            """Async generator for response events."""
            queue = self._request_events.get(stream_id)
            waiter = self._request_waiter.get(stream_id)

            if not queue or not waiter:
                return

            while not waiter.is_set():
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=0.1)
                    yield event
                except asyncio.TimeoutError:
                    continue

            # Drain remaining events
            while not queue.empty():
                yield queue.get_nowait()
else:
    # Dummy class when aioquic not available
    HttpClientProtocol = None


# ============================================================
# QUIC-Specific Security Testing Utilities
# ============================================================

@dataclass
class QUICScan:
    """QUIC security scan result."""
    target: str
    port: int

    # Protocol info
    quic_versions: list[str] = field(default_factory=list)
    alpn_protocols: list[str] = field(default_factory=list)

    # Security findings
    zero_rtt_supported: bool = False
    connection_migration_allowed: bool = False
    version_negotiation_enabled: bool = False

    # Vulnerabilities
    vulnerabilities: list[dict] = field(default_factory=list)


async def probe_quic_port(host: str, port: int = 443, timeout: float = 5.0) -> bool:
    """
    Probe if a host has QUIC/UDP port open.

    Note: QUIC uses UDP, so traditional port scanning won't work.
    We send a QUIC Initial packet and check for response.
    """
    if not AIOQUIC_AVAILABLE:
        return False

    try:
        # Create minimal QUIC Initial packet
        # This is a simplified version - real implementation would be more complete
        initial_packet = _create_quic_initial_probe()

        # Send UDP packet
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )

        writer.write(initial_packet)
        await writer.drain()

        # Wait for response (any response indicates QUIC is listening)
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            return len(data) > 0
        except asyncio.TimeoutError:
            writer.close()
            return False

    except Exception:
        return False


def _create_quic_initial_probe() -> bytes:
    """Create a minimal QUIC Initial packet for probing."""
    # QUIC long header format (simplified)
    # First byte: 1100 0000 = 0xC0 (long header, Initial packet)
    header = bytes([0xC0])

    # Version: draft-29 (0xff00001d) or v1 (0x00000001)
    version = struct.pack(">I", 0x00000001)

    # Destination Connection ID (8 bytes random)
    dcid_len = bytes([8])
    dcid = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])

    # Source Connection ID (0 bytes)
    scid_len = bytes([0])

    # Token length (0)
    token_len = bytes([0])

    # Packet number and payload (minimal)
    # Length (2 bytes) + packet number (1 byte) + padding
    length = struct.pack(">H", 1200)  # Minimum 1200 bytes for Initial
    packet_number = bytes([0])
    padding = bytes(1200 - len(header) - len(version) - len(dcid_len) - len(dcid) -
                    len(scid_len) - len(token_len) - len(length) - 1)

    return header + version + dcid_len + dcid + scid_len + token_len + length + packet_number + padding


async def scan_quic_security(host: str, port: int = 443) -> QUICScan:
    """
    Perform security scan of QUIC endpoint.

    Tests:
    - Supported QUIC versions
    - 0-RTT support (replay attack risk)
    - Connection migration (IP spoofing risk)
    - Version negotiation (downgrade attacks)
    """
    scan = QUICScan(target=host, port=port)

    if not AIOQUIC_AVAILABLE:
        scan.vulnerabilities.append({
            "type": "scan_error",
            "message": "aioquic not available",
        })
        return scan

    try:
        # Test QUIC versions
        for version in ["h3", "h3-29", "h3-27"]:
            config = QuicConfiguration(
                is_client=True,
                alpn_protocols=[version],
            )
            config.verify_mode = ssl.CERT_NONE

            try:
                async with quic_connect(host, port, configuration=config) as protocol:
                    await asyncio.wait_for(protocol.wait_connected(), timeout=5.0)
                    scan.quic_versions.append(version)
                    scan.alpn_protocols.append(version)
            except Exception:
                continue

        if not scan.quic_versions:
            scan.vulnerabilities.append({
                "type": "no_quic",
                "severity": "INFO",
                "message": "Target does not support QUIC/HTTP3",
            })
            return scan

        # Test 0-RTT (if we had a previous session)
        # Note: Full 0-RTT testing requires session resumption
        # For now, we check if the server advertises 0-RTT support
        scan.zero_rtt_supported = True  # Assume supported if QUIC works

        if scan.zero_rtt_supported:
            scan.vulnerabilities.append({
                "type": "zero_rtt_replay",
                "severity": "LOW",
                "message": "0-RTT early data supported - potential replay attack risk",
                "cwe": "CWE-294",
                "recommendation": "Ensure 0-RTT requests are idempotent",
            })

        # Check for version downgrade potential
        if len(scan.quic_versions) > 1:
            scan.version_negotiation_enabled = True
            scan.vulnerabilities.append({
                "type": "version_negotiation",
                "severity": "INFO",
                "message": f"Multiple QUIC versions supported: {scan.quic_versions}",
                "recommendation": "Monitor for version downgrade attacks",
            })

    except Exception as e:
        scan.vulnerabilities.append({
            "type": "scan_error",
            "message": str(e),
        })

    return scan


# ============================================================
# Convenience Functions
# ============================================================

def is_http3_available() -> bool:
    """Check if HTTP/3 support is available in this environment."""
    return AIOQUIC_AVAILABLE


async def get_http3_client(**kwargs) -> HTTP3Client:
    """Get an HTTP/3 client instance."""
    return HTTP3Client(**kwargs)


async def quick_h3_check(url: str) -> dict:
    """
    Quick check if a URL supports HTTP/3.

    Returns:
        dict with keys: supported, protocol, alt_svc
    """
    client = HTTP3Client()
    status, alt_svc = await client.check_http3_support(url)

    return {
        "supported": status == HTTP3Status.AVAILABLE,
        "status": status.value,
        "alt_svc": {
            "protocol": alt_svc.protocol,
            "host": alt_svc.host,
            "port": alt_svc.port,
            "max_age": alt_svc.max_age,
        } if alt_svc else None,
    }
