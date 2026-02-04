"""
Parameter Context Analyzer v1.0.0-ENTERPRISE
=============================================

Análise inteligente de parâmetros - payloads certos para contextos certos!

Features:
- Deteção de tipo (int, email, url, uuid, date, json, etc.)
- Análise de entropia (passwords vs IDs)
- Deteção de reflexão
- Recomendação de payloads por contexto
- Profile completo por parâmetro

Princípio: id=1 → NÃO METAS <script>!
"""

import re
import json
import math
import hashlib
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, List, Dict, Set, Any, Tuple, Union
from urllib.parse import urlparse, parse_qs, unquote
from collections import Counter


class ParameterType(Enum):
    """Detected parameter types with security implications"""
    
    # Numeric types
    INTEGER = "integer"
    FLOAT = "float"
    
    # String types
    STRING = "string"
    EMAIL = "email"
    PHONE = "phone"
    USERNAME = "username"
    PASSWORD = "password"
    
    # Identifiers
    UUID = "uuid"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    BASE64 = "base64"
    JWT = "jwt"
    
    # URLs and paths
    URL = "url"
    PATH = "path"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    
    # Dates and times
    DATE = "date"
    DATETIME = "datetime"
    TIMESTAMP = "timestamp"
    
    # Structured data
    JSON = "json"
    XML = "xml"
    HTML = "html"
    
    # Special
    BOOLEAN = "boolean"
    ENUM = "enum"
    SEARCH = "search"
    FILENAME = "filename"
    COMMAND = "command"  # Potential command injection
    SQL = "sql"  # Potential SQL fragment
    
    # Unknown
    UNKNOWN = "unknown"


class EntropyLevel(Enum):
    """Entropy classification"""
    VERY_LOW = "very_low"      # 0-1 bits - predictable (1, true, yes)
    LOW = "low"                # 1-2 bits - enumerable (status codes, small IDs)
    MEDIUM = "medium"          # 2-3 bits - moderate randomness
    HIGH = "high"              # 3-4 bits - good randomness
    VERY_HIGH = "very_high"    # 4+ bits - cryptographic/passwords


class ReflectionType(Enum):
    """How parameter is reflected in response"""
    NOT_REFLECTED = "not_reflected"
    REFLECTED_RAW = "reflected_raw"
    REFLECTED_ENCODED = "reflected_encoded"
    REFLECTED_IN_ATTRIBUTE = "reflected_in_attribute"
    REFLECTED_IN_SCRIPT = "reflected_in_script"
    REFLECTED_IN_COMMENT = "reflected_in_comment"
    REFLECTED_IN_URL = "reflected_in_url"
    REFLECTED_IN_JSON = "reflected_in_json"


class AttackRecommendation(Enum):
    """Recommended attack type based on context"""
    SQLI = "sql_injection"
    SQLI_NUMERIC = "sql_injection_numeric"
    SQLI_STRING = "sql_injection_string"
    XSS = "xss"
    XSS_ATTRIBUTE = "xss_attribute"
    XSS_SCRIPT = "xss_script"
    SSRF = "ssrf"
    OPEN_REDIRECT = "open_redirect"
    LFI = "lfi"
    RFI = "rfi"
    CMDI = "command_injection"
    XXE = "xxe"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    NOSQL = "nosql"
    LDAP = "ldap"
    XPATH = "xpath"
    SSTI = "ssti"
    PATH_TRAVERSAL = "path_traversal"
    FORMAT_STRING = "format_string"
    BUFFER_OVERFLOW = "buffer_overflow"
    NONE = "none"


@dataclass
class ParameterProfile:
    """
    Complete profile of a parameter
    
    Contains all information needed to select appropriate payloads
    """
    name: str
    value: str
    detected_type: ParameterType
    entropy: EntropyLevel
    entropy_bits: float
    reflected: bool
    reflection_type: ReflectionType
    recommended_attacks: List[AttackRecommendation]
    confidence: float  # 0.0 - 1.0
    
    # Additional metadata
    is_required: bool = False
    is_array: bool = False
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    pattern: Optional[str] = None
    sample_values: List[str] = field(default_factory=list)
    
    # Context
    location: str = "query"  # query, body, header, cookie, path
    content_type: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "detected_type": self.detected_type.value,
            "entropy": self.entropy.value,
            "entropy_bits": round(self.entropy_bits, 2),
            "reflected": self.reflected,
            "reflection_type": self.reflection_type.value,
            "recommended_attacks": [a.value for a in self.recommended_attacks],
            "confidence": round(self.confidence, 2),
            "is_required": self.is_required,
            "is_array": self.is_array,
            "location": self.location,
            "content_type": self.content_type
        }
    
    def should_test_xss(self) -> bool:
        """Should we test XSS on this parameter?"""
        # Don't XSS integers or non-reflected params
        if self.detected_type == ParameterType.INTEGER:
            return False
        if not self.reflected:
            return False
        if self.detected_type in {ParameterType.BOOLEAN, ParameterType.TIMESTAMP}:
            return False
        return AttackRecommendation.XSS in self.recommended_attacks or \
               AttackRecommendation.XSS_ATTRIBUTE in self.recommended_attacks
    
    def should_test_sqli(self) -> bool:
        """Should we test SQLi on this parameter?"""
        return AttackRecommendation.SQLI in self.recommended_attacks or \
               AttackRecommendation.SQLI_NUMERIC in self.recommended_attacks or \
               AttackRecommendation.SQLI_STRING in self.recommended_attacks
    
    def should_test_ssrf(self) -> bool:
        """Should we test SSRF on this parameter?"""
        return AttackRecommendation.SSRF in self.recommended_attacks or \
               self.detected_type in {ParameterType.URL, ParameterType.DOMAIN, ParameterType.IP_ADDRESS}
    
    def should_test_lfi(self) -> bool:
        """Should we test LFI on this parameter?"""
        return AttackRecommendation.LFI in self.recommended_attacks or \
               self.detected_type in {ParameterType.PATH, ParameterType.FILENAME}
    
    def get_sqli_type(self) -> str:
        """Get SQLi type (numeric vs string)"""
        if self.detected_type == ParameterType.INTEGER:
            return "numeric"
        return "string"


@dataclass
class ContextAnalysisResult:
    """Result of analyzing all parameters in a request"""
    url: str
    profiles: List[ParameterProfile]
    total_params: int
    testable_params: int
    skip_recommendations: Dict[str, List[str]]  # param -> reasons to skip
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "profiles": [p.to_dict() for p in self.profiles],
            "total_params": self.total_params,
            "testable_params": self.testable_params,
            "skip_recommendations": self.skip_recommendations
        }
    
    def get_xss_candidates(self) -> List[ParameterProfile]:
        """Get parameters suitable for XSS testing"""
        return [p for p in self.profiles if p.should_test_xss()]
    
    def get_sqli_candidates(self) -> List[ParameterProfile]:
        """Get parameters suitable for SQLi testing"""
        return [p for p in self.profiles if p.should_test_sqli()]
    
    def get_ssrf_candidates(self) -> List[ParameterProfile]:
        """Get parameters suitable for SSRF testing"""
        return [p for p in self.profiles if p.should_test_ssrf()]


class ParameterContextAnalyzer:
    """
    Parameter Context Analyzer - Intelligent Parameter Profiling
    
    Analyzes parameters to understand their type, purpose, and 
    appropriate attack vectors.
    
    Principle: Don't send XSS payloads to integer parameters!
    """
    
    VERSION = "1.0.0-ENTERPRISE"
    
    # Type detection patterns
    TYPE_PATTERNS = {
        # Identifiers
        ParameterType.UUID: [
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            r'^[0-9a-f]{32}$',
        ],
        ParameterType.HASH_MD5: [r'^[0-9a-f]{32}$'],
        ParameterType.HASH_SHA1: [r'^[0-9a-f]{40}$'],
        ParameterType.HASH_SHA256: [r'^[0-9a-f]{64}$'],
        
        # JWT
        ParameterType.JWT: [r'^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'],
        
        # Base64
        ParameterType.BASE64: [r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'],
        
        # Network
        ParameterType.EMAIL: [r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'],
        ParameterType.IP_ADDRESS: [
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
            r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$',
        ],
        ParameterType.URL: [
            r'^https?://[^\s<>"{}|\\^`\[\]]+$',
            r'^//[^\s<>"{}|\\^`\[\]]+$',
        ],
        ParameterType.DOMAIN: [r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'],
        ParameterType.PHONE: [
            r'^\+?[0-9]{10,15}$',
            r'^\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$',
        ],
        
        # Dates
        ParameterType.DATE: [
            r'^\d{4}-\d{2}-\d{2}$',
            r'^\d{2}/\d{2}/\d{4}$',
            r'^\d{2}-\d{2}-\d{4}$',
        ],
        ParameterType.DATETIME: [
            r'^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}',
            r'^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}$',
        ],
        ParameterType.TIMESTAMP: [r'^[0-9]{10,13}$'],
        
        # Structured data
        ParameterType.JSON: [r'^\s*[\[{]'],
        ParameterType.XML: [r'^\s*<\?xml|^\s*<[a-zA-Z]'],
        ParameterType.HTML: [r'<[a-z]+[^>]*>'],
        
        # Files and paths
        ParameterType.PATH: [
            r'^[./\\]',
            r'[/\\]',
            r'\.\./',
        ],
        ParameterType.FILENAME: [r'^[\w-]+\.[a-zA-Z0-9]{1,5}$'],
        
        # Booleans
        ParameterType.BOOLEAN: [r'^(true|false|yes|no|1|0|on|off)$'],
        
        # Numbers (checked last due to broad matching)
        ParameterType.FLOAT: [r'^-?[0-9]+\.[0-9]+$'],
        ParameterType.INTEGER: [r'^-?[0-9]+$'],
    }
    
    # Name-based type hints
    NAME_HINTS = {
        ParameterType.INTEGER: ["id", "page", "limit", "offset", "count", "num", "qty", "quantity", "index", "size", "width", "height", "year", "month", "day", "age"],
        ParameterType.EMAIL: ["email", "mail", "e-mail", "user_email", "contact"],
        ParameterType.PASSWORD: ["password", "passwd", "pass", "pwd", "secret", "key", "token"],
        ParameterType.USERNAME: ["username", "user", "login", "account", "name", "nick"],
        ParameterType.URL: ["url", "link", "href", "redirect", "return", "callback", "next", "goto", "dest", "destination", "target", "continue", "return_url", "redirect_uri"],
        ParameterType.PATH: ["path", "file", "filename", "filepath", "dir", "directory", "folder", "template", "page", "include", "view"],
        ParameterType.SEARCH: ["search", "query", "q", "keyword", "keywords", "term", "s", "filter"],
        ParameterType.COMMAND: ["cmd", "command", "exec", "execute", "run", "shell", "system", "ping", "host"],
        ParameterType.SQL: ["sql", "query", "select", "where", "order", "sort", "filter"],
        ParameterType.DOMAIN: ["domain", "host", "hostname", "server"],
        ParameterType.IP_ADDRESS: ["ip", "ipaddr", "ip_address", "remote", "client"],
        ParameterType.PHONE: ["phone", "tel", "telephone", "mobile", "cell", "fax"],
        ParameterType.DATE: ["date", "dob", "birthday", "created", "updated", "start_date", "end_date"],
        ParameterType.UUID: ["uuid", "guid", "uid"],
        ParameterType.BOOLEAN: ["active", "enabled", "disabled", "visible", "hidden", "public", "private", "admin", "is_", "has_", "can_"],
    }
    
    # Attack recommendations per type
    TYPE_TO_ATTACKS = {
        ParameterType.INTEGER: [AttackRecommendation.SQLI_NUMERIC, AttackRecommendation.IDOR],
        ParameterType.FLOAT: [AttackRecommendation.SQLI_NUMERIC],
        ParameterType.STRING: [AttackRecommendation.SQLI_STRING, AttackRecommendation.XSS],
        ParameterType.EMAIL: [AttackRecommendation.SQLI_STRING, AttackRecommendation.XSS],
        ParameterType.USERNAME: [AttackRecommendation.SQLI_STRING, AttackRecommendation.AUTH_BYPASS],
        ParameterType.PASSWORD: [AttackRecommendation.AUTH_BYPASS],
        ParameterType.UUID: [AttackRecommendation.IDOR],
        ParameterType.URL: [AttackRecommendation.SSRF, AttackRecommendation.OPEN_REDIRECT],
        ParameterType.PATH: [AttackRecommendation.LFI, AttackRecommendation.PATH_TRAVERSAL],
        ParameterType.FILENAME: [AttackRecommendation.LFI, AttackRecommendation.PATH_TRAVERSAL],
        ParameterType.DOMAIN: [AttackRecommendation.SSRF],
        ParameterType.IP_ADDRESS: [AttackRecommendation.SSRF],
        ParameterType.JSON: [AttackRecommendation.NOSQL, AttackRecommendation.XXE],
        ParameterType.XML: [AttackRecommendation.XXE, AttackRecommendation.XPATH],
        ParameterType.SEARCH: [AttackRecommendation.SQLI_STRING, AttackRecommendation.XSS, AttackRecommendation.LDAP],
        ParameterType.COMMAND: [AttackRecommendation.CMDI],
        ParameterType.SQL: [AttackRecommendation.SQLI],
        ParameterType.BOOLEAN: [],
        ParameterType.DATE: [AttackRecommendation.SQLI_STRING],
        ParameterType.DATETIME: [AttackRecommendation.SQLI_STRING],
        ParameterType.TIMESTAMP: [AttackRecommendation.SQLI_NUMERIC],
        ParameterType.JWT: [AttackRecommendation.AUTH_BYPASS],
        ParameterType.HASH_MD5: [AttackRecommendation.IDOR],
        ParameterType.HASH_SHA1: [AttackRecommendation.IDOR],
        ParameterType.HASH_SHA256: [AttackRecommendation.IDOR],
        ParameterType.BASE64: [AttackRecommendation.IDOR, AttackRecommendation.SQLI_STRING],
        ParameterType.HTML: [AttackRecommendation.XSS, AttackRecommendation.SSTI],
        ParameterType.ENUM: [AttackRecommendation.SQLI_STRING],
        ParameterType.PHONE: [],
        ParameterType.UNKNOWN: [AttackRecommendation.SQLI_STRING, AttackRecommendation.XSS],
    }
    
    def __init__(self):
        # Compile patterns for performance
        self._compiled_patterns = {}
        for param_type, patterns in self.TYPE_PATTERNS.items():
            self._compiled_patterns[param_type] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]
    
    def analyze_parameter(
        self,
        name: str,
        value: str,
        response_body: Optional[str] = None,
        location: str = "query",
        content_type: Optional[str] = None
    ) -> ParameterProfile:
        """
        Analyze a single parameter and create its profile
        
        Args:
            name: Parameter name
            value: Parameter value
            response_body: Response to check reflection
            location: Where parameter is (query, body, header, cookie, path)
            content_type: Content-Type of request
            
        Returns:
            Complete ParameterProfile
        """
        # Detect type
        detected_type, type_confidence = self._detect_type(name, value)
        
        # Calculate entropy
        entropy_bits = self._calculate_entropy(value)
        entropy_level = self._classify_entropy(entropy_bits)
        
        # Check reflection
        reflected, reflection_type = self._check_reflection(value, response_body)
        
        # Get attack recommendations
        recommended_attacks = self._get_attack_recommendations(
            detected_type, reflected, location, name
        )
        
        # Detect if array
        is_array = name.endswith("[]") or name.endswith("[0]")
        
        return ParameterProfile(
            name=name,
            value=value,
            detected_type=detected_type,
            entropy=entropy_level,
            entropy_bits=entropy_bits,
            reflected=reflected,
            reflection_type=reflection_type,
            recommended_attacks=recommended_attacks,
            confidence=type_confidence,
            is_array=is_array,
            location=location,
            content_type=content_type,
            sample_values=[value]
        )
    
    def analyze_url(
        self,
        url: str,
        response_body: Optional[str] = None,
        body_params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> ContextAnalysisResult:
        """
        Analyze all parameters in a request
        
        Args:
            url: Full URL with query string
            response_body: Response for reflection checking
            body_params: POST body parameters
            headers: Request headers
            cookies: Cookies
            
        Returns:
            ContextAnalysisResult with all profiles
        """
        profiles: List[ParameterProfile] = []
        skip_recommendations: Dict[str, List[str]] = {}
        
        # Parse URL query parameters
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        
        for name, values in query_params.items():
            value = values[0] if values else ""
            profile = self.analyze_parameter(
                name, value, response_body, "query"
            )
            profiles.append(profile)
            
            # Track skip reasons
            skip_reasons = self._get_skip_reasons(profile)
            if skip_reasons:
                skip_recommendations[name] = skip_reasons
        
        # Analyze body parameters
        if body_params:
            for name, value in body_params.items():
                if isinstance(value, list):
                    value = value[0] if value else ""
                profile = self.analyze_parameter(
                    name, str(value), response_body, "body"
                )
                profiles.append(profile)
                
                skip_reasons = self._get_skip_reasons(profile)
                if skip_reasons:
                    skip_recommendations[name] = skip_reasons
        
        # Analyze headers
        if headers:
            testable_headers = [
                "X-Forwarded-For", "X-Real-IP", "X-Custom-IP-Authorization",
                "X-Originating-IP", "X-Remote-IP", "X-Client-IP",
                "Referer", "Origin", "User-Agent", "X-Forwarded-Host",
                "X-Requested-With"
            ]
            for name, value in headers.items():
                if name in testable_headers:
                    profile = self.analyze_parameter(
                        name, value, response_body, "header"
                    )
                    profiles.append(profile)
        
        # Analyze cookies
        if cookies:
            for name, value in cookies.items():
                profile = self.analyze_parameter(
                    name, value, response_body, "cookie"
                )
                profiles.append(profile)
        
        # Count testable
        testable = sum(1 for p in profiles if p.recommended_attacks)
        
        return ContextAnalysisResult(
            url=url,
            profiles=profiles,
            total_params=len(profiles),
            testable_params=testable,
            skip_recommendations=skip_recommendations
        )
    
    def _detect_type(self, name: str, value: str) -> Tuple[ParameterType, float]:
        """
        Detect parameter type from name and value
        
        Returns (type, confidence)
        """
        # Empty value - use name hints
        if not value:
            return self._detect_from_name(name)
        
        # Decode URL encoding
        try:
            decoded_value = unquote(value)
        except Exception:
            decoded_value = value
        
        # Try pattern matching
        for param_type, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                if pattern.match(decoded_value):
                    return (param_type, 0.9)
        
        # Try name hints
        name_type, name_confidence = self._detect_from_name(name)
        if name_type != ParameterType.UNKNOWN:
            return (name_type, name_confidence)
        
        # Default to string
        return (ParameterType.STRING, 0.5)
    
    def _detect_from_name(self, name: str) -> Tuple[ParameterType, float]:
        """Detect type from parameter name"""
        name_lower = name.lower()
        
        for param_type, hints in self.NAME_HINTS.items():
            for hint in hints:
                if hint in name_lower or name_lower.startswith(hint) or name_lower.endswith(hint):
                    return (param_type, 0.7)
        
        return (ParameterType.UNKNOWN, 0.3)
    
    def _calculate_entropy(self, value: str) -> float:
        """
        Calculate Shannon entropy of value
        
        Higher entropy = more random = likely token/password
        Lower entropy = predictable = likely ID/status
        """
        if not value:
            return 0.0
        
        # Count character frequencies
        freq = Counter(value)
        length = len(value)
        
        # Calculate entropy
        entropy = 0.0
        for count in freq.values():
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _classify_entropy(self, entropy_bits: float) -> EntropyLevel:
        """Classify entropy into levels"""
        if entropy_bits < 1.0:
            return EntropyLevel.VERY_LOW
        elif entropy_bits < 2.0:
            return EntropyLevel.LOW
        elif entropy_bits < 3.0:
            return EntropyLevel.MEDIUM
        elif entropy_bits < 4.0:
            return EntropyLevel.HIGH
        else:
            return EntropyLevel.VERY_HIGH
    
    def _check_reflection(
        self,
        value: str,
        response_body: Optional[str]
    ) -> Tuple[bool, ReflectionType]:
        """
        Check if parameter value is reflected in response
        
        Returns (is_reflected, reflection_type)
        """
        if not response_body or not value:
            return (False, ReflectionType.NOT_REFLECTED)
        
        # Check raw reflection
        if value in response_body:
            # Determine context
            value_pos = response_body.find(value)
            
            # Check if in script tag
            script_start = response_body.rfind("<script", 0, value_pos)
            script_end = response_body.find("</script>", value_pos)
            if script_start != -1 and (script_end == -1 or script_end > value_pos):
                return (True, ReflectionType.REFLECTED_IN_SCRIPT)
            
            # Check if in HTML comment
            comment_start = response_body.rfind("<!--", 0, value_pos)
            comment_end = response_body.find("-->", value_pos)
            if comment_start != -1 and (comment_end == -1 or comment_end > value_pos):
                return (True, ReflectionType.REFLECTED_IN_COMMENT)
            
            # Check if in attribute
            before_value = response_body[max(0, value_pos - 50):value_pos]
            if re.search(r'[a-z]+=[\'"]\s*$', before_value, re.IGNORECASE):
                return (True, ReflectionType.REFLECTED_IN_ATTRIBUTE)
            
            # Check if in URL
            if re.search(r'(href|src|action)=', before_value, re.IGNORECASE):
                return (True, ReflectionType.REFLECTED_IN_URL)
            
            # Check if in JSON
            if '"' in response_body[max(0, value_pos - 5):value_pos]:
                try:
                    json.loads(response_body)
                    return (True, ReflectionType.REFLECTED_IN_JSON)
                except json.JSONDecodeError:
                    pass
            
            return (True, ReflectionType.REFLECTED_RAW)
        
        # Check encoded reflection
        import html
        encoded_variants = [
            html.escape(value),
            value.replace("<", "&lt;").replace(">", "&gt;"),
            value.replace('"', "&quot;"),
            value.replace("'", "&#39;"),
        ]
        
        for encoded in encoded_variants:
            if encoded != value and encoded in response_body:
                return (True, ReflectionType.REFLECTED_ENCODED)
        
        return (False, ReflectionType.NOT_REFLECTED)
    
    def _get_attack_recommendations(
        self,
        detected_type: ParameterType,
        reflected: bool,
        location: str,
        name: str
    ) -> List[AttackRecommendation]:
        """Get recommended attacks based on context"""
        recommendations = list(self.TYPE_TO_ATTACKS.get(detected_type, []))
        
        # Add XSS only if reflected
        if reflected and AttackRecommendation.XSS not in recommendations:
            recommendations.append(AttackRecommendation.XSS)
        
        # Remove XSS if not reflected and type doesn't warrant testing
        if not reflected and detected_type not in {ParameterType.STRING, ParameterType.SEARCH, ParameterType.HTML}:
            recommendations = [r for r in recommendations if r not in {AttackRecommendation.XSS, AttackRecommendation.XSS_ATTRIBUTE, AttackRecommendation.XSS_SCRIPT}]
        
        # Add SSTI for template-like params
        name_lower = name.lower()
        if any(hint in name_lower for hint in ["template", "render", "view", "format"]):
            recommendations.append(AttackRecommendation.SSTI)
        
        # Add command injection for suspicious names
        if any(hint in name_lower for hint in ["cmd", "command", "exec", "run", "shell", "system"]):
            if AttackRecommendation.CMDI not in recommendations:
                recommendations.append(AttackRecommendation.CMDI)
        
        return list(set(recommendations))  # Deduplicate
    
    def _get_skip_reasons(self, profile: ParameterProfile) -> List[str]:
        """Get reasons why certain tests should be skipped"""
        reasons = []
        
        # Integer + XSS
        if profile.detected_type == ParameterType.INTEGER:
            reasons.append("Skip XSS: integer parameter")
        
        # Not reflected + XSS
        if not profile.reflected:
            reasons.append("Skip reflected XSS: value not reflected")
        
        # Boolean + most attacks
        if profile.detected_type == ParameterType.BOOLEAN:
            reasons.append("Skip most attacks: boolean parameter (limited values)")
        
        # High entropy + IDOR
        if profile.entropy == EntropyLevel.VERY_HIGH:
            reasons.append("Skip IDOR brute force: high entropy value")
        
        # JWT + SQLi
        if profile.detected_type == ParameterType.JWT:
            reasons.append("Skip SQLi: JWT token (test JWT-specific attacks)")
        
        # Phone + most attacks
        if profile.detected_type == ParameterType.PHONE:
            reasons.append("Skip most attacks: phone number format")
        
        return reasons
    
    def get_payload_context(self, profile: ParameterProfile) -> Dict[str, Any]:
        """
        Get context information for payload generation
        
        Returns dict with info for payload selection
        """
        return {
            "type": profile.detected_type.value,
            "is_numeric": profile.detected_type in {ParameterType.INTEGER, ParameterType.FLOAT, ParameterType.TIMESTAMP},
            "is_string": profile.detected_type not in {ParameterType.INTEGER, ParameterType.FLOAT, ParameterType.TIMESTAMP, ParameterType.BOOLEAN},
            "is_url": profile.detected_type in {ParameterType.URL, ParameterType.DOMAIN, ParameterType.IP_ADDRESS},
            "is_path": profile.detected_type in {ParameterType.PATH, ParameterType.FILENAME},
            "is_reflected": profile.reflected,
            "reflection_context": profile.reflection_type.value,
            "sqli_type": "numeric" if profile.detected_type == ParameterType.INTEGER else "string",
            "xss_context": profile.reflection_type.value if profile.reflected else None,
            "entropy": profile.entropy.value,
            "recommended_attacks": [a.value for a in profile.recommended_attacks],
        }


# Convenience function
def analyze_parameters(url: str, response: Optional[str] = None, **kwargs) -> ContextAnalysisResult:
    """Quick parameter analysis"""
    analyzer = ParameterContextAnalyzer()
    return analyzer.analyze_url(url, response, **kwargs)


# Export
__all__ = [
    "ParameterContextAnalyzer",
    "ParameterProfile",
    "ContextAnalysisResult",
    "ParameterType",
    "EntropyLevel",
    "ReflectionType",
    "AttackRecommendation",
    "analyze_parameters"
]
