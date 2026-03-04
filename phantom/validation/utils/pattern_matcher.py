"""
PHANTOM AI - Pattern Matcher for Vulnerability Indicators
==========================================================

Extracted from phantom/validation_pipeline.py (lines 678-1258).
"""

import re
from typing import Dict, List, Tuple

from phantom.validation.models import VulnerabilityType


class PatternMatcher:
    """
    Pattern matching for vulnerability indicators.
    """

    # Success indicators by vulnerability type
    SUCCESS_INDICATORS: Dict[VulnerabilityType, List[Tuple[str, float]]] = {
        VulnerabilityType.SQLI: [
            (r"SQL syntax.*MySQL", 0.9),
            (r"mysql_fetch_array\(\)", 0.85),
            (r"ORA-\d{5}", 0.9),
            (r"PostgreSQL.*ERROR", 0.9),
            (r"Warning.*mssql_", 0.85),
            (r"sqlite3\.OperationalError", 0.85),
            (r"You have an error in your SQL syntax", 0.9),
            (r"Unclosed quotation mark", 0.85),
            (r"quoted string not properly terminated", 0.85),
            (r"root:.*:0:0:", 0.95),  # /etc/passwd via SQLi
        ],
        # FN-C3 FIX: Expanded XSS patterns for modern frameworks
        VulnerabilityType.XSS: [
            # Classic script injection
            (r"<script[^>]*>alert\(", 0.95),
            (r"<script[^>]*>.*</script>", 0.85),
            (r"javascript:alert", 0.9),
            (r"javascript:", 0.7),
            # Event handlers (common)
            (r"onerror\s*=", 0.8),
            (r"onload\s*=", 0.8),
            (r"onclick\s*=", 0.75),
            (r"onmouseover\s*=", 0.75),
            (r"onfocus\s*=", 0.75),
            (r"onblur\s*=", 0.75),
            # Element-specific
            (r"<img[^>]*onerror", 0.85),
            (r"<svg[^>]*onload", 0.85),
            (r"<body[^>]*onload", 0.85),
            (r"<iframe[^>]*srcdoc", 0.8),
            (r"<object[^>]*data", 0.75),
            (r"<embed[^>]*src", 0.75),
            # Data URIs
            (r"data:text/html", 0.85),
            (r"data:image/svg\+xml", 0.8),
            # Modern framework XSS (Alpine.js, Vue, Angular, Svelte, HTMX)
            (r"x-on:[a-z]+\s*=", 0.8),  # Alpine.js
            (r"@click\s*=", 0.75),  # Vue shorthand
            (r"v-on:[a-z]+\s*=", 0.8),  # Vue
            (r"\(click\)\s*=", 0.8),  # Angular
            (r"on:[a-z]+\s*=", 0.75),  # Svelte
            (r"hx-on:[a-z]+\s*=", 0.8),  # HTMX
            (r"\{\{.*\}\}", 0.6),  # Template injection (Vue/Angular)
            # HTML entity encoded
            (r"&lt;script", 0.7),
            (r"&#x3c;script", 0.7),
            (r"&#60;script", 0.7),
        ],
        VulnerabilityType.CMDI: [
            (r"uid=\d+\(.*\)", 0.95),  # Unix id command
            (r"root:.*:0:0:", 0.95),   # /etc/passwd
            (r"Windows NT.*\d+\.\d+", 0.9),  # Windows version
            (r"Directory of", 0.85),    # Windows dir
            (r"Linux.*x86_64", 0.9),   # Linux uname
        ],
        VulnerabilityType.LFI: [
            (r"root:.*:0:0:", 0.95),
            (r"\[boot loader\]", 0.9),  # Windows boot.ini
            (r"\[fonts\]", 0.85),       # Windows win.ini
            (r"PD9waHA", 0.85),         # Base64 PHP
            (r"<\?php", 0.9),
        ],
        # FN-C4 FIX: Expanded SSRF patterns for all cloud providers
        VulnerabilityType.SSRF: [
            # AWS metadata
            (r"ami-[a-z0-9]{8,}", 0.95),
            (r"169\.254\.169\.254", 0.9),
            (r"AccessKeyId", 0.95),
            (r"SecretAccessKey", 0.95),
            (r"iam/security-credentials", 0.95),
            (r"ec2.*amazonaws\.com", 0.85),
            # GCP metadata
            (r"metadata\.google\.internal", 0.95),
            (r"computeMetadata/v1", 0.9),
            (r"169\.254\.169\.254.*Metadata-Flavor", 0.9),
            (r"X-Google-Metadata-Request", 0.85),
            (r"project-id.*gcp", 0.8),
            # Azure metadata
            (r"169\.254\.169\.254.*metadata/instance", 0.9),
            (r"Metadata:true", 0.85),
            (r"management\.azure\.com", 0.85),
            (r"\.blob\.core\.windows\.net", 0.8),
            # Kubernetes / Container
            (r"kubernetes\.default", 0.9),
            (r"serviceaccount.*token", 0.9),
            (r"/var/run/secrets/kubernetes", 0.95),
            (r"kube-system", 0.85),
            # Docker
            (r"/var/run/docker\.sock", 0.95),
            (r"docker\.internal", 0.85),
            # Internal services
            (r"localhost:\d{4,5}", 0.7),
            (r"127\.0\.0\.1:\d{4,5}", 0.7),
            (r"0\.0\.0\.0:\d{4,5}", 0.7),
            (r"internal\.", 0.6),
            (r"\.local:", 0.6),
            (r"metadata.*internal", 0.85),
            # Generic cloud
            (r"cloud-init", 0.7),
            (r"user-data", 0.65),
        ],
        # FN-C5 FIX: Expanded XXE patterns
        VulnerabilityType.XXE: [
            # File content extraction
            (r"root:.*:0:0:", 0.95),
            (r"\[boot loader\]", 0.9),  # Windows boot.ini
            (r"<\?php", 0.85),  # PHP source
            # XXE syntax indicators
            (r"ENTITY.*SYSTEM", 0.7),
            (r"<!DOCTYPE.*\[", 0.6),
            (r"ENTITY.*PUBLIC", 0.7),
            (r"<!ENTITY", 0.65),
            # XML parser errors (indicates XXE processing)
            (r"XML\s*parsing\s*error", 0.75),
            (r"SAXParseException", 0.8),
            (r"XMLStreamException", 0.8),
            (r"XMLSyntaxError", 0.8),
            (r"lxml\.etree", 0.75),
            (r"org\.xml\.sax", 0.8),
            (r"javax\.xml", 0.75),
            # External entity indicators
            (r"external.*entity", 0.7),
            (r"DTD.*not.*allowed", 0.65),
            (r"DOCTYPE.*not.*supported", 0.6),
            # OOB XXE indicators
            (r"parameter.*entity", 0.7),
            (r"DTD.*reference", 0.65),
        ],
        VulnerabilityType.SSTI: [
            (r"49", 0.6),  # 7*7
            (r"config\s*[:{]", 0.7),
            (r"SECRET_KEY", 0.9),
            (r"__class__", 0.85),
            (r"__mro__", 0.85),
        ],
        # Access Control / IDOR / Authorization patterns
        VulnerabilityType.IDOR: [
            # Response contains different user data (comparison-based detection)
            (r"\"user_?id\":\s*\d+", 0.7),  # User ID in response
            (r"\"id\":\s*\d+", 0.6),  # ID field in response
            (r"\"email\":\s*\"[^\"]+@", 0.75),  # Email exposed
            (r"\"username\":\s*\"", 0.7),  # Username exposed
            (r"\"account\":", 0.65),  # Account data
            (r"\"profile\":", 0.65),  # Profile data
            (r"\"user\":\s*\{", 0.7),  # User object
            (r"\"owner\":", 0.7),  # Owner field
            (r"\"created_by\":", 0.65),  # Creator field
            # Status code indicators
            (r"200 OK", 0.6),  # Successful access (combined with ID change)
        ],
        VulnerabilityType.AUTHORIZATION: [
            # Unauthorized access indicators
            (r"\"role\":\s*\"admin\"", 0.85),  # Admin role exposed
            (r"\"is_?admin\":\s*true", 0.9),  # Admin flag
            (r"\"permissions\":\s*\[", 0.75),  # Permissions array
            (r"\"privilege\":", 0.75),  # Privilege field
            (r"\"access_?level\":", 0.7),  # Access level
            (r"\"can_delete\":", 0.75),  # Delete permission
            (r"\"can_edit\":", 0.75),  # Edit permission
            (r"\"can_manage\":", 0.8),  # Manage permission
            # Admin panel access
            (r"admin.*dashboard", 0.85),  # Admin dashboard
            (r"manage.*users", 0.8),  # User management
            (r"configuration.*settings", 0.7),  # Config access
        ],
        VulnerabilityType.DESERIALIZATION: [
            # Java deserialization errors (specific, high confidence)
            (r"java\.io\.StreamCorruptedException", 0.90),
            (r"java\.io\.InvalidClassException", 0.90),
            (r"java\.lang\.ClassNotFoundException.*deserialize", 0.90),
            (r"ObjectInputStream.*readObject", 0.85),
            (r"ysoserial", 0.95),  # Known exploit tool
            (r"CommonsCollections\d*", 0.95),  # Known gadget chain
            (r"org\.apache\.commons\.collections", 0.85),
            (r"java\.rmi\.server\.UnicastRemoteObject", 0.90),
            # PHP deserialization errors
            (r"unserialize\(\).*error", 0.85),
            (r"unserialize\(\).*expects parameter", 0.80),
            (r"__wakeup.*called", 0.90),
            (r"__destruct.*called", 0.90),
            (r"Phar::loadPhar", 0.90),
            (r"phar://", 0.85),
            # Python deserialization errors
            (r"pickle\.UnpicklingError", 0.90),
            (r"_pickle\.UnpicklingError", 0.90),
            (r"pickle.*load.*error", 0.80),
            (r"yaml\.unsafe_load", 0.90),
            (r"yaml\.load.*Loader", 0.75),
            # .NET deserialization errors
            (r"BinaryFormatter.*deserialize", 0.90),
            (r"ObjectStateFormatter", 0.90),
            (r"LosFormatter", 0.90),
            (r"System\.Runtime\.Serialization", 0.85),
            (r"TypeNameHandling", 0.85),  # JSON.NET vulnerable setting
            (r"__type.*System\.", 0.90),  # JSON.NET type hint
            # Node.js deserialization errors
            (r"node-serialize", 0.90),
            (r"serialize-javascript", 0.85),
            (r"Function\([\"'].*[\"']\)\(\)", 0.90),  # IIFE in serialize
        ],
    }

    # False positive indicators (generic)
    # FIX 2026-02-18: Massively expanded FP patterns for better precision
    FALSE_POSITIVE_INDICATORS: List[Tuple[str, float]] = [
        # === HTTP Status Errors (page doesn't exist or blocked) ===
        (r"<title>404", 0.85),
        (r"Page Not Found", 0.8),
        (r"404 Not Found", 0.85),
        (r"Resource Not Found", 0.8),
        (r"The page you requested", 0.6),
        (r"does not exist", 0.7),
        (r"could not be found", 0.7),
        (r"<title>403", 0.85),
        (r"403 Forbidden", 0.85),
        (r"Access Denied", 0.75),
        (r"Access Forbidden", 0.8),
        (r"Permission Denied", 0.75),
        (r"Unauthorized Access", 0.75),
        (r"<title>401", 0.8),
        (r"401 Unauthorized", 0.8),
        (r"Authentication Required", 0.7),
        (r"<title>500", 0.6),  # Lower - could be vuln-triggered
        (r"<title>502", 0.75),
        (r"<title>503", 0.8),
        (r"Service Unavailable", 0.75),
        (r"Bad Gateway", 0.75),

        # === Security/WAF Interference ===
        (r"CSRF token", 0.6),
        (r"csrf.*invalid", 0.7),
        (r"csrf.*mismatch", 0.7),
        (r"rate limit", 0.75),
        (r"too many requests", 0.8),
        (r"429 Too Many", 0.85),
        (r"request.*blocked", 0.75),
        (r"captcha", 0.7),
        (r"recaptcha", 0.75),
        (r"hcaptcha", 0.75),
        (r"cloudflare.*ray", 0.8),
        (r"cf-ray", 0.8),
        (r"cloudflare.*challenge", 0.85),
        (r"attention required", 0.7),
        (r"checking your browser", 0.8),
        (r"please wait.*redirect", 0.7),
        (r"ddos.*protection", 0.85),
        (r"akamai.*ghost", 0.8),
        (r"sucuri.*firewall", 0.85),
        (r"wordfence", 0.85),
        (r"mod_security", 0.8),
        (r"web application firewall", 0.85),
        (r"waf.*blocked", 0.9),
        (r"request.*rejected", 0.75),
        (r"suspicious.*activity", 0.7),
        (r"malicious.*request", 0.8),
        (r"attack.*detected", 0.85),

        # === SPA/Framework Catch-All Responses ===
        (r"<div id=\"root\"></div>", 0.65),
        (r"<div id=\"app\"></div>", 0.65),
        (r"__NEXT_DATA__", 0.7),
        (r"__NUXT__", 0.7),
        (r"window\.__INITIAL_STATE__", 0.65),
        (r"ng-app", 0.6),
        (r"data-reactroot", 0.6),

        # === Generic Error Pages (not vuln-specific) ===
        (r"Something went wrong", 0.5),
        (r"An error occurred", 0.45),
        (r"Please try again", 0.4),
        (r"Contact support", 0.35),
        (r"Report this issue", 0.4),
        (r"Oops!", 0.4),
        (r"We're sorry", 0.4),

        # === Development/Test Indicators (not production) ===
        (r"localhost.*debug", 0.6),
        (r"debug.*mode", 0.5),
        (r"development.*server", 0.55),
        (r"werkzeug", 0.5),  # Flask dev server

        # === API Gateway / Proxy Errors ===
        (r"gateway.*timeout", 0.75),
        (r"upstream.*error", 0.7),
        (r"backend.*unavailable", 0.75),
        (r"no healthy upstream", 0.8),
        (r"kong.*error", 0.75),
        (r"nginx.*error", 0.6),
        (r"apache.*error", 0.6),
    ]

    # Type-specific false positive indicators
    # FIX 2026-02-18: Comprehensive FP patterns for all vulnerability types
    TYPE_SPECIFIC_FP_INDICATORS: Dict[VulnerabilityType, List[Tuple[str, float]]] = {
        # === SQL Injection FP Patterns ===
        VulnerabilityType.SQLI: [
            # Legitimate SQL-like content (not errors)
            (r"sql\s*syntax\s*highlighting", 0.85),
            (r"sql\s*tutorial", 0.85),
            (r"learn\s*sql", 0.8),
            (r"sql\s*documentation", 0.8),
            (r"sql\s*reference", 0.75),
            # ORM/Framework sanitized responses
            (r"parameterized\s*query", 0.7),
            (r"prepared\s*statement", 0.7),
            (r"sqlalchemy", 0.6),  # Python ORM
            (r"hibernate", 0.6),  # Java ORM
            (r"activerecord", 0.6),  # Ruby ORM
            (r"eloquent", 0.6),  # Laravel ORM
            # JSON/API error responses (not DB errors)
            (r'"error":\s*"invalid\s*input"', 0.7),
            (r'"error":\s*"validation\s*failed"', 0.7),
            (r'"status":\s*"error"', 0.5),
            # False SQL error patterns (in UI text, not actual errors)
            (r"<code>.*sql.*</code>", 0.65),  # Code examples
            (r"example.*query", 0.6),
            (r"syntax.*example", 0.6),
            # Framework-specific false positives
            (r"django.*debug.*false", 0.7),  # Django production
            (r"rails.*production", 0.65),
            # SQL in comments/docs (not execution errors)
            (r"//.*SELECT", 0.6),
            (r"/\*.*SELECT.*\*/", 0.65),
            (r"#.*INSERT", 0.6),
        ],

        # === XSS FP Patterns (covers all XSS types: reflected, stored, DOM) ===
        VulnerabilityType.XSS: [
            # Legitimate script content (not injection)
            (r"text/javascript", 0.5),  # JS MIME type
            (r"<script\s+src=", 0.6),  # External script (not reflected)
            (r"<script.*integrity=", 0.7),  # SRI protected
            (r"<script.*nonce=", 0.75),  # CSP nonce protected
            (r"<script\s+type=['\"]module['\"]", 0.65),  # ES module
            # Content Security Policy active
            (r"content-security-policy", 0.7),
            (r"script-src\s*'self'", 0.8),
            (r"unsafe-inline.*refused", 0.85),
            # HTML encoding visible (sanitized)
            (r"&lt;script&gt;", 0.8),  # Encoded, not reflected
            (r"&amp;lt;", 0.75),
            (r"&#x3c;script&#x3e;", 0.8),
            # Template/framework sanitization
            (r"{{.*escape.*}}", 0.7),
            (r"{%.*autoescape.*%}", 0.75),
            (r"dangerouslySetInnerHTML", 0.5),  # React explicit
            # Documentation/code examples
            (r"<pre>.*<script>.*</pre>", 0.8),
            (r"<code>.*&lt;script", 0.8),
            (r"xss.*prevention", 0.7),
            (r"sanitize.*input", 0.65),
            # Storage context FPs (stored XSS)
            (r"sanitized.*before.*storage", 0.75),
            (r"html.*entities.*encoded", 0.7),
            # DOM XSS: Legitimate DOM manipulation
            (r"\.innerText\s*=", 0.5),  # Safe assignment
            (r"\.textContent\s*=", 0.5),  # Safe assignment
            (r"DOMPurify", 0.85),  # Sanitizer library
            (r"sanitize-html", 0.8),
            (r"xss-filters", 0.8),
            # Framework-protected
            (r"v-text=", 0.65),  # Vue safe
            (r"\[innerText\]", 0.65),  # Angular safe
        ],

        # === SSRF FP Patterns ===
        VulnerabilityType.SSRF: [
            # Legitimate internal references
            (r"localhost.*documentation", 0.7),
            (r"127\.0\.0\.1.*example", 0.7),
            (r"internal.*api.*docs", 0.65),
            # Cloud provider documentation (not actual metadata)
            (r"169\.254\.169\.254.*example", 0.8),
            (r"metadata.*endpoint.*disabled", 0.85),
            (r"imdsv2.*required", 0.8),  # AWS IMDSv2 protection
            # Whitelisted/validated URLs
            (r"url.*whitelist", 0.7),
            (r"allowed.*hosts", 0.65),
            (r"url.*validation", 0.6),
            # Error indicating SSRF blocked
            (r"ssrf.*blocked", 0.9),
            (r"internal.*url.*forbidden", 0.85),
            (r"private.*ip.*rejected", 0.85),
            (r"localhost.*not.*allowed", 0.85),
        ],

        # === Command Injection FP Patterns ===
        VulnerabilityType.CMDI: [
            # Legitimate command examples (documentation)
            (r"<code>.*whoami.*</code>", 0.75),
            (r"<pre>.*ls -la.*</pre>", 0.75),
            (r"command.*example", 0.65),
            (r"terminal.*output", 0.6),
            # Sanitized/escaped
            (r"escapeshellcmd", 0.8),  # PHP sanitization
            (r"escapeshellarg", 0.8),
            (r"shlex\.quote", 0.8),  # Python sanitization
            (r"subprocess.*shell=False", 0.75),  # Python safe mode
            # Static text containing command patterns
            (r"man.*page", 0.6),
            (r"--help", 0.5),
            (r"usage:", 0.5),
        ],

        # === LFI/Path Traversal FP Patterns ===
        VulnerabilityType.LFI: [
            # Path traversal blocked/sanitized
            (r"path.*traversal.*blocked", 0.9),
            (r"directory.*traversal.*detected", 0.9),
            (r"invalid.*path", 0.7),
            (r"file.*not.*allowed", 0.75),
            (r"outside.*root", 0.8),
            # Legitimate file references
            (r"<code>.*/etc/passwd.*</code>", 0.8),  # Documentation
            (r"example.*path", 0.65),
            # Framework protection
            (r"realpath.*check", 0.75),
            (r"basename.*only", 0.7),
            (r"whitelist.*extensions", 0.7),
        ],

        # === SSTI FP Patterns ===
        VulnerabilityType.SSTI: [
            # Legitimate template syntax (not injection)
            (r"\{\{.*\}\}.*template", 0.6),  # Template documentation
            (r"jinja2.*documentation", 0.8),
            (r"twig.*template", 0.75),
            (r"handlebars.*example", 0.75),
            # Math expressions in legitimate context
            (r"calculator", 0.5),
            (r"compute.*result", 0.5),
            (r"<span>49</span>", 0.4),  # Just number display
            # Sandboxed/safe templates
            (r"sandbox.*mode", 0.8),
            (r"autoescape.*true", 0.75),
            (r"safe.*filter", 0.65),
        ],

        # === XXE FP Patterns ===
        VulnerabilityType.XXE: [
            # XML parsing disabled/secured
            (r"external.*entities.*disabled", 0.9),
            (r"xxe.*protection", 0.85),
            (r"dtd.*processing.*disabled", 0.85),
            (r"expand.*entities.*false", 0.8),
            # Legitimate XML errors (parsing, not XXE)
            (r"invalid.*xml", 0.5),
            (r"xml.*well-formed", 0.5),
            (r"missing.*closing.*tag", 0.6),
            # XML in documentation
            (r"<code>.*<!ENTITY.*</code>", 0.8),
            (r"xml.*tutorial", 0.75),
        ],

        # === Deserialization FP Patterns (existing, expanded) ===
        VulnerabilityType.DESERIALIZATION: [
            # Training apps (known vulnerable by design)
            (r"webgoat", 0.95),
            (r"dvwa", 0.95),
            (r"juice.?shop", 0.95),
            (r"hackthebox", 0.90),
            (r"portswigger.*lab", 0.95),
            (r"pentester.*lab", 0.90),
            (r"vulnhub", 0.90),
            # Tutorial/documentation context
            (r"<title>.*tutorial", 0.80),
            (r"lesson.*insecure.*deserialization", 0.90),
            (r"example.*vulnerable", 0.85),
            (r"demo.*serialization", 0.80),
            (r"practice.*exploit", 0.85),
            # Static content (JS files, documentation)
            (r"\.js\s*$", 0.75),
            (r"function\s+\w+\s*\(", 0.60),
            (r"api.*documentation", 0.70),
            (r"swagger", 0.65),
            # Generic error pages (not deserialization-specific)
            (r"500 Internal Server Error", 0.60),
            (r"Application Error", 0.50),
            (r"Fatal error:(?!.*unserialize)", 0.55),
            # Safe serialization
            (r"json\.loads", 0.6),  # JSON is safe
            (r"JSON\.parse", 0.6),
            (r"jackson.*databind.*safe", 0.7),
        ],

        # === IDOR FP Patterns ===
        VulnerabilityType.IDOR: [
            # Legitimate ID access (same user)
            (r"your.*profile", 0.5),
            (r"your.*account", 0.5),
            (r"my.*data", 0.5),
            # Public data (not sensitive)
            (r"public.*profile", 0.7),
            (r"is_public.*true", 0.75),
            (r"visibility.*public", 0.7),
            # Authorization check present
            (r"unauthorized", 0.7),
            (r"access.*denied", 0.75),
            (r"not.*your.*resource", 0.8),
            (r"permission.*denied", 0.75),
        ],

        # === Authorization FP Patterns ===
        VulnerabilityType.AUTHORIZATION: [
            # Role check working correctly
            (r"insufficient.*privileges", 0.8),
            (r"admin.*required", 0.75),
            (r"not.*authorized", 0.75),
            (r"role.*check.*failed", 0.8),
            # Public endpoints
            (r"public.*endpoint", 0.7),
            (r"no.*auth.*required", 0.7),
            (r"anonymous.*allowed", 0.65),
        ],
    }

    @classmethod
    def check_indicators(
        cls,
        response: str,
        vuln_type: VulnerabilityType,
    ) -> Tuple[bool, float, List[str]]:
        """
        Check for vulnerability indicators in response.

        Returns:
            (has_indicators, confidence, matched_patterns)
        """
        indicators = cls.SUCCESS_INDICATORS.get(vuln_type, [])
        matched = []
        max_confidence = 0.0

        for pattern, confidence in indicators:
            if re.search(pattern, response, re.IGNORECASE):
                matched.append(pattern)
                max_confidence = max(max_confidence, confidence)

        return len(matched) > 0, max_confidence, matched

    @classmethod
    def check_false_positives(
        cls,
        response: str,
        vuln_type: VulnerabilityType = None,
    ) -> Tuple[bool, float, List[str]]:
        """
        Check for false positive indicators.

        Args:
            response: The response text to check
            vuln_type: Optional vulnerability type for type-specific FP patterns

        Returns:
            (has_fp_indicators, fp_confidence, matched_patterns)
        """
        matched = []
        max_confidence = 0.0

        # Check generic FP indicators
        for pattern, confidence in cls.FALSE_POSITIVE_INDICATORS:
            if re.search(pattern, response, re.IGNORECASE):
                matched.append(pattern)
                max_confidence = max(max_confidence, confidence)

        # Check type-specific FP indicators if vuln_type provided
        if vuln_type and vuln_type in cls.TYPE_SPECIFIC_FP_INDICATORS:
            for pattern, confidence in cls.TYPE_SPECIFIC_FP_INDICATORS[vuln_type]:
                if re.search(pattern, response, re.IGNORECASE):
                    matched.append(f"[{vuln_type.value}] {pattern}")
                    max_confidence = max(max_confidence, confidence)

        return len(matched) > 0, max_confidence, matched
