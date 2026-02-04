"""
Unified Payload Encoder - Enterprise Edition

Consolidates ~400 lines of duplicate encoding functions from:
- cmdi_scanner.py
- lfi_scanner.py
- xss_scanner.py
- ssrf_scanner.py
- sqli_scanner.py

Provides:
- URL encoding (single, double, triple)
- Unicode encoding (various formats)
- Hex encoding (various formats)
- Base64 encoding
- HTML entity encoding
- Case variations
- WAF bypass techniques
- Null byte insertion
- Comment insertion (SQL)

Usage:
    from utils.payload_encoder import PayloadEncoder, EncodingChain

    encoder = PayloadEncoder()
    encoded = encoder.url_encode("' OR '1'='1")
    double_encoded = encoder.double_url_encode(payload)

    # Chain multiple encodings
    chain = EncodingChain()
    result = chain.add(EncodingType.URL_ENCODE).add(EncodingType.BASE64).encode(payload)
"""

from enum import Enum, auto
from typing import List, Optional, Callable
from urllib.parse import quote, quote_plus, unquote
import base64
import html
import codecs
import re


class EncodingType(Enum):
    """Types of encoding/obfuscation available."""
    # URL encodings
    URL_ENCODE = auto()
    URL_ENCODE_ALL = auto()
    DOUBLE_URL_ENCODE = auto()
    TRIPLE_URL_ENCODE = auto()

    # Unicode encodings
    UNICODE_ESCAPE = auto()      # \u0041
    UNICODE_FULL_WIDTH = auto()  # ％３Ｃ
    UTF7 = auto()                # +ADw-
    UTF8_OVERLONG = auto()       # Overlong UTF-8

    # Hex encodings
    HEX_ENCODE = auto()          # %41
    HEX_ENCODE_0X = auto()       # 0x41
    HEX_ENCODE_CHAR = auto()     # \x41

    # Base64
    BASE64 = auto()
    BASE64_URL_SAFE = auto()

    # HTML
    HTML_ENTITY = auto()         # &lt;
    HTML_ENTITY_DEC = auto()     # &#60;
    HTML_ENTITY_HEX = auto()     # &#x3c;

    # Case variations
    CASE_UPPER = auto()
    CASE_LOWER = auto()
    CASE_MIXED = auto()          # SeLeCt

    # SQL-specific
    SQL_COMMENT = auto()         # SEL/**/ECT
    SQL_CONCAT = auto()          # 'SEL'||'ECT'
    SQL_CHAR = auto()            # CHAR(83,69,76,69,67,84)

    # Whitespace
    WHITESPACE_TAB = auto()
    WHITESPACE_NEWLINE = auto()
    WHITESPACE_NULL = auto()

    # Special
    NULL_BYTE = auto()           # %00
    DOUBLE_ENCODE_SELECTIVE = auto()


class PayloadEncoder:
    """Static and instance methods for payload encoding."""

    # Characters safe from URL encoding
    URL_SAFE_CHARS = ""

    # SQL keywords for case variation
    SQL_KEYWORDS = [
        'SELECT', 'UNION', 'AND', 'OR', 'FROM', 'WHERE', 'INSERT',
        'UPDATE', 'DELETE', 'DROP', 'TABLE', 'DATABASE', 'EXEC',
        'EXECUTE', 'DECLARE', 'CAST', 'CONVERT', 'ORDER', 'BY',
        'GROUP', 'HAVING', 'LIMIT', 'OFFSET', 'JOIN', 'LEFT',
        'RIGHT', 'INNER', 'OUTER', 'INTO', 'VALUES', 'SET'
    ]

    # XSS keywords for case variation
    XSS_KEYWORDS = [
        'SCRIPT', 'ALERT', 'ONERROR', 'ONLOAD', 'ONMOUSEOVER',
        'ONCLICK', 'ONFOCUS', 'IMG', 'SVG', 'BODY', 'IFRAME',
        'OBJECT', 'EMBED', 'STYLE', 'EVAL', 'JAVASCRIPT'
    ]

    # ====================
    # URL Encodings
    # ====================

    @staticmethod
    def url_encode(payload: str, safe: str = "") -> str:
        """Standard URL encode."""
        return quote(payload, safe=safe)

    @staticmethod
    def url_encode_all(payload: str) -> str:
        """URL encode ALL characters including alphanumeric."""
        return ''.join(f'%{ord(c):02X}' for c in payload)

    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encode (encode % as %25)."""
        return quote(quote(payload, safe=''), safe='')

    @staticmethod
    def triple_url_encode(payload: str) -> str:
        """Triple URL encode."""
        return quote(quote(quote(payload, safe=''), safe=''), safe='')

    @staticmethod
    def url_decode(payload: str) -> str:
        """URL decode."""
        return unquote(payload)

    # ====================
    # Unicode Encodings
    # ====================

    @staticmethod
    def unicode_escape(payload: str) -> str:
        """Convert to Unicode escape sequences: \\u0041."""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)

    @staticmethod
    def unicode_full_width(payload: str) -> str:
        """Convert ASCII to full-width Unicode."""
        result = ""
        for c in payload:
            code = ord(c)
            # Convert printable ASCII (0x21-0x7E) to full-width (0xFF01-0xFF5E)
            if 0x21 <= code <= 0x7E:
                result += chr(code + 0xFEE0)
            elif c == ' ':
                result += '\u3000'  # Full-width space
            else:
                result += c
        return result

    @staticmethod
    def utf7_encode(payload: str) -> str:
        """Encode as UTF-7 (for legacy XSS)."""
        try:
            return payload.encode('utf-7').decode('ascii')
        except:
            return payload

    @staticmethod
    def utf8_overlong(char: str) -> bytes:
        """
        Generate overlong UTF-8 encoding for a character.
        Used to bypass filters checking for specific bytes.
        """
        if len(char) != 1:
            return char.encode('utf-8')

        code = ord(char)
        if code < 0x80:
            # 2-byte overlong: 110xxxxx 10xxxxxx
            return bytes([0xC0 | (code >> 6), 0x80 | (code & 0x3F)])
        return char.encode('utf-8')

    # ====================
    # Hex Encodings
    # ====================

    @staticmethod
    def hex_encode(payload: str) -> str:
        """Hex encode: %XX format."""
        return ''.join(f'%{ord(c):02x}' for c in payload)

    @staticmethod
    def hex_encode_0x(payload: str) -> str:
        """Hex encode: 0xXX format."""
        return ''.join(f'0x{ord(c):02x}' for c in payload)

    @staticmethod
    def hex_encode_char(payload: str) -> str:
        """Hex encode: \\xXX format."""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)

    @staticmethod
    def hex_decode(payload: str) -> str:
        """Decode hex-encoded string."""
        # Handle %XX format
        result = re.sub(
            r'%([0-9a-fA-F]{2})',
            lambda m: chr(int(m.group(1), 16)),
            payload
        )
        # Handle \xXX format
        result = re.sub(
            r'\\x([0-9a-fA-F]{2})',
            lambda m: chr(int(m.group(1), 16)),
            result
        )
        return result

    # ====================
    # Base64 Encodings
    # ====================

    @staticmethod
    def base64_encode(payload: str) -> str:
        """Standard Base64 encode."""
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def base64_url_safe(payload: str) -> str:
        """URL-safe Base64 encode (no +, /, =)."""
        return base64.urlsafe_b64encode(payload.encode()).decode().rstrip('=')

    @staticmethod
    def base64_decode(payload: str) -> str:
        """Base64 decode."""
        # Add padding if needed
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        return base64.b64decode(payload).decode()

    # ====================
    # HTML Entity Encodings
    # ====================

    @staticmethod
    def html_entity_encode(payload: str) -> str:
        """HTML entity encode: &lt; &gt; etc."""
        return html.escape(payload)

    @staticmethod
    def html_entity_decimal(payload: str) -> str:
        """HTML decimal entity encode: &#60;."""
        return ''.join(f'&#{ord(c)};' for c in payload)

    @staticmethod
    def html_entity_hex(payload: str) -> str:
        """HTML hex entity encode: &#x3c;."""
        return ''.join(f'&#x{ord(c):x};' for c in payload)

    @staticmethod
    def html_entity_mixed(payload: str) -> str:
        """Mix decimal and hex encoding randomly."""
        import random
        result = ""
        for c in payload:
            if random.choice([True, False]):
                result += f'&#{ord(c)};'
            else:
                result += f'&#x{ord(c):x};'
        return result

    # ====================
    # Case Variations
    # ====================

    @staticmethod
    def case_upper(payload: str) -> str:
        """Convert to uppercase."""
        return payload.upper()

    @staticmethod
    def case_lower(payload: str) -> str:
        """Convert to lowercase."""
        return payload.lower()

    @staticmethod
    def case_mixed(payload: str) -> str:
        """Alternating case: SeLeCt."""
        return ''.join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(payload)
        )

    @staticmethod
    def case_random(payload: str) -> str:
        """Random case variation."""
        import random
        return ''.join(
            c.upper() if random.choice([True, False]) else c.lower()
            for c in payload
        )

    @staticmethod
    def sql_keyword_case_bypass(payload: str) -> str:
        """Apply mixed case to SQL keywords only."""
        result = payload
        for keyword in PayloadEncoder.SQL_KEYWORDS:
            pattern = re.compile(re.escape(keyword), re.IGNORECASE)
            mixed = PayloadEncoder.case_mixed(keyword)
            result = pattern.sub(mixed, result)
        return result

    @staticmethod
    def xss_keyword_case_bypass(payload: str) -> str:
        """Apply mixed case to XSS keywords only."""
        result = payload
        for keyword in PayloadEncoder.XSS_KEYWORDS:
            pattern = re.compile(re.escape(keyword), re.IGNORECASE)
            mixed = PayloadEncoder.case_mixed(keyword)
            result = pattern.sub(mixed, result)
        return result

    # ====================
    # SQL-specific Encodings
    # ====================

    @staticmethod
    def sql_comment_insertion(payload: str) -> str:
        """Insert SQL comments to break patterns: SEL/**/ECT."""
        result = payload
        for keyword in PayloadEncoder.SQL_KEYWORDS:
            if keyword.upper() in result.upper():
                # Find keyword position
                idx = result.upper().find(keyword.upper())
                mid = len(keyword) // 2
                original = result[idx:idx + len(keyword)]
                commented = original[:mid] + '/**/' + original[mid:]
                result = result[:idx] + commented + result[idx + len(keyword):]
        return result

    @staticmethod
    def sql_concat_bypass(payload: str, db_type: str = "mysql") -> str:
        """
        Convert string to concatenation for bypass.
        MySQL: CONCAT('SEL','ECT')
        PostgreSQL: 'SEL'||'ECT'
        MSSQL: 'SEL'+'ECT'
        """
        if db_type == "mysql":
            parts = [f"'{c}'" for c in payload]
            return f"CONCAT({','.join(parts)})"
        elif db_type == "postgresql":
            parts = [f"'{c}'" for c in payload]
            return '||'.join(parts)
        elif db_type == "mssql":
            parts = [f"'{c}'" for c in payload]
            return '+'.join(parts)
        return payload

    @staticmethod
    def sql_char_encode(payload: str, db_type: str = "mysql") -> str:
        """
        Encode string as CHAR() function calls.
        MySQL: CHAR(83,69,76,69,67,84)
        """
        char_codes = [str(ord(c)) for c in payload]
        if db_type == "mysql":
            return f"CHAR({','.join(char_codes)})"
        elif db_type == "mssql":
            return '+'.join(f"CHAR({code})" for code in char_codes)
        elif db_type == "postgresql":
            return '||'.join(f"CHR({code})" for code in char_codes)
        return payload

    @staticmethod
    def sql_hex_encode(payload: str) -> str:
        """Encode as hex for SQL: 0x53454C454354."""
        return '0x' + payload.encode().hex()

    # ====================
    # Whitespace Variations
    # ====================

    @staticmethod
    def whitespace_tab(payload: str) -> str:
        """Replace spaces with tabs."""
        return payload.replace(' ', '\t')

    @staticmethod
    def whitespace_newline(payload: str) -> str:
        """Replace spaces with newlines."""
        return payload.replace(' ', '\n')

    @staticmethod
    def whitespace_carriage(payload: str) -> str:
        """Replace spaces with carriage returns."""
        return payload.replace(' ', '\r')

    @staticmethod
    def whitespace_vertical_tab(payload: str) -> str:
        """Replace spaces with vertical tabs."""
        return payload.replace(' ', '\v')

    @staticmethod
    def whitespace_form_feed(payload: str) -> str:
        """Replace spaces with form feeds."""
        return payload.replace(' ', '\f')

    @staticmethod
    def whitespace_sql_comment(payload: str) -> str:
        """Replace spaces with SQL comments: /**/."""
        return payload.replace(' ', '/**/')

    @staticmethod
    def whitespace_random(payload: str) -> str:
        """Replace spaces with random whitespace."""
        import random
        whitespace_chars = ['\t', '\n', '\r', '\v', '\f', '/**/']
        return ''.join(
            random.choice(whitespace_chars) if c == ' ' else c
            for c in payload
        )

    # ====================
    # Special Encodings
    # ====================

    @staticmethod
    def null_byte_insertion(payload: str) -> str:
        """Insert null bytes: %00."""
        return payload.replace(' ', '%00')

    @staticmethod
    def null_byte_terminate(payload: str) -> str:
        """Append null byte at end."""
        return payload + '%00'

    @staticmethod
    def backslash_escape(payload: str) -> str:
        """Escape special characters with backslash."""
        special_chars = "'\"\\/;|&<>"
        return ''.join(
            f'\\{c}' if c in special_chars else c
            for c in payload
        )

    @staticmethod
    def bash_variable_bypass(payload: str) -> str:
        """
        Use bash variable expansion for bypass.
        id → $()
        cat /etc/passwd → ca${var}t /etc/passwd
        """
        # Insert empty variable expansion
        result = payload
        if len(payload) >= 2:
            mid = len(payload) // 2
            result = payload[:mid] + '${x}' + payload[mid:]
        return result

    @staticmethod
    def bash_ifs_bypass(payload: str) -> str:
        """Use IFS variable for space bypass."""
        return payload.replace(' ', '${IFS}')

    @staticmethod
    def bash_brace_expansion(payload: str) -> str:
        """Use brace expansion: {cat,/etc/passwd}."""
        parts = payload.split()
        if len(parts) >= 2:
            return '{' + ','.join(parts) + '}'
        return payload

    # ====================
    # Encoding Detection
    # ====================

    @staticmethod
    def detect_encoding(payload: str) -> List[str]:
        """Detect what encodings are applied to a payload."""
        detected = []

        # Check for URL encoding
        if '%' in payload and re.search(r'%[0-9a-fA-F]{2}', payload):
            detected.append('url_encoded')
            # Check for double encoding
            if '%25' in payload:
                detected.append('double_url_encoded')

        # Check for Base64
        if re.match(r'^[A-Za-z0-9+/]*={0,2}$', payload) and len(payload) % 4 == 0:
            try:
                base64.b64decode(payload)
                detected.append('base64')
            except:
                pass

        # Check for HTML entities
        if '&' in payload and ';' in payload:
            if re.search(r'&[a-z]+;', payload):
                detected.append('html_entity_named')
            if re.search(r'&#\d+;', payload):
                detected.append('html_entity_decimal')
            if re.search(r'&#x[0-9a-fA-F]+;', payload):
                detected.append('html_entity_hex')

        # Check for Unicode escape
        if '\\u' in payload:
            detected.append('unicode_escape')

        # Check for hex encoding
        if '\\x' in payload:
            detected.append('hex_char')
        if '0x' in payload:
            detected.append('hex_0x')

        return detected

    # ====================
    # Apply by Encoding Type
    # ====================

    @classmethod
    def apply(cls, payload: str, encoding_type: EncodingType) -> str:
        """Apply a specific encoding type."""
        encoding_map = {
            EncodingType.URL_ENCODE: cls.url_encode,
            EncodingType.URL_ENCODE_ALL: cls.url_encode_all,
            EncodingType.DOUBLE_URL_ENCODE: cls.double_url_encode,
            EncodingType.TRIPLE_URL_ENCODE: cls.triple_url_encode,
            EncodingType.UNICODE_ESCAPE: cls.unicode_escape,
            EncodingType.UNICODE_FULL_WIDTH: cls.unicode_full_width,
            EncodingType.UTF7: cls.utf7_encode,
            EncodingType.HEX_ENCODE: cls.hex_encode,
            EncodingType.HEX_ENCODE_0X: cls.hex_encode_0x,
            EncodingType.HEX_ENCODE_CHAR: cls.hex_encode_char,
            EncodingType.BASE64: cls.base64_encode,
            EncodingType.BASE64_URL_SAFE: cls.base64_url_safe,
            EncodingType.HTML_ENTITY: cls.html_entity_encode,
            EncodingType.HTML_ENTITY_DEC: cls.html_entity_decimal,
            EncodingType.HTML_ENTITY_HEX: cls.html_entity_hex,
            EncodingType.CASE_UPPER: cls.case_upper,
            EncodingType.CASE_LOWER: cls.case_lower,
            EncodingType.CASE_MIXED: cls.case_mixed,
            EncodingType.SQL_COMMENT: cls.sql_comment_insertion,
            EncodingType.WHITESPACE_TAB: cls.whitespace_tab,
            EncodingType.WHITESPACE_NEWLINE: cls.whitespace_newline,
            EncodingType.WHITESPACE_NULL: cls.whitespace_sql_comment,
            EncodingType.NULL_BYTE: cls.null_byte_terminate,
        }

        func = encoding_map.get(encoding_type)
        if func:
            return func(payload)
        return payload


class EncodingChain:
    """Chain multiple encodings together."""

    def __init__(self):
        self._encodings: List[EncodingType] = []

    def add(self, encoding_type: EncodingType) -> "EncodingChain":
        """Add an encoding to the chain."""
        self._encodings.append(encoding_type)
        return self

    def encode(self, payload: str) -> str:
        """Apply all encodings in order."""
        result = payload
        for encoding in self._encodings:
            result = PayloadEncoder.apply(result, encoding)
        return result

    def reset(self) -> "EncodingChain":
        """Reset the chain."""
        self._encodings = []
        return self


class WAFBypassEncoder:
    """
    Specialized encoder for WAF bypass.
    Applies combinations of techniques based on WAF type.
    """

    # Known WAF bypass techniques
    WAF_PROFILES = {
        "cloudflare": [
            EncodingType.UNICODE_FULL_WIDTH,
            EncodingType.CASE_MIXED,
            EncodingType.SQL_COMMENT,
        ],
        "akamai": [
            EncodingType.DOUBLE_URL_ENCODE,
            EncodingType.CASE_MIXED,
            EncodingType.WHITESPACE_TAB,
        ],
        "aws_waf": [
            EncodingType.UNICODE_ESCAPE,
            EncodingType.HTML_ENTITY_HEX,
            EncodingType.CASE_MIXED,
        ],
        "imperva": [
            EncodingType.DOUBLE_URL_ENCODE,
            EncodingType.SQL_COMMENT,
            EncodingType.WHITESPACE_NEWLINE,
        ],
        "f5_bigip": [
            EncodingType.URL_ENCODE_ALL,
            EncodingType.CASE_MIXED,
        ],
        "modsecurity": [
            EncodingType.SQL_COMMENT,
            EncodingType.CASE_MIXED,
            EncodingType.DOUBLE_URL_ENCODE,
        ],
        "sucuri": [
            EncodingType.UNICODE_FULL_WIDTH,
            EncodingType.CASE_MIXED,
        ],
        "generic": [
            EncodingType.URL_ENCODE,
            EncodingType.CASE_MIXED,
            EncodingType.SQL_COMMENT,
        ],
    }

    @classmethod
    def get_bypass_variants(
        cls,
        payload: str,
        waf_type: str = "generic",
        max_variants: int = 5
    ) -> List[str]:
        """Generate WAF bypass variants for a payload."""
        variants = [payload]
        encodings = cls.WAF_PROFILES.get(waf_type, cls.WAF_PROFILES["generic"])

        for encoding in encodings[:max_variants - 1]:
            variant = PayloadEncoder.apply(payload, encoding)
            if variant not in variants:
                variants.append(variant)

        return variants[:max_variants]

    @classmethod
    def generate_all_variants(cls, payload: str) -> List[str]:
        """Generate variants for all known WAF types."""
        all_variants = set([payload])

        for waf_type in cls.WAF_PROFILES:
            variants = cls.get_bypass_variants(payload, waf_type)
            all_variants.update(variants)

        return list(all_variants)


# Convenience functions
def url_encode(payload: str) -> str:
    """URL encode a payload."""
    return PayloadEncoder.url_encode(payload)


def double_url_encode(payload: str) -> str:
    """Double URL encode a payload."""
    return PayloadEncoder.double_url_encode(payload)


def base64_encode(payload: str) -> str:
    """Base64 encode a payload."""
    return PayloadEncoder.base64_encode(payload)


def html_encode(payload: str) -> str:
    """HTML entity encode a payload."""
    return PayloadEncoder.html_entity_encode(payload)


def get_waf_bypass_variants(payload: str, waf_type: str = "generic") -> List[str]:
    """Get WAF bypass variants for a payload."""
    return WAFBypassEncoder.get_bypass_variants(payload, waf_type)
