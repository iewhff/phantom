"""
XSS Scanner - Template Injection Strategy.

Tests for Client-Side Template Injection (CSTI) in
Angular, Vue, React, and other modern frameworks.

Extracted from xss_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urlparse

from utils.logger import get_logger
from utils.scan_client import get_scan_client

from scanning.modules.xss.xss_base import (
    XSSContext,
    XSSEvidence,
    WAFType,
    TEMPLATE_INJECTION_PAYLOADS,
    TEMPLATE_MATH_RESULT,
)
from scanning.modules.xss.strategies.base import (
    BaseXSSStrategy,
    XSSStrategyContext,
    XSSStrategyResult,
)

if TYPE_CHECKING:
    import httpx

logger = get_logger(__name__)


# Static file extensions to skip
STATIC_EXTENSIONS = {
    ".js", ".css", ".map", ".woff", ".woff2", ".ttf", ".eot",
    ".svg", ".png", ".jpg", ".gif", ".ico", ".webp"
}

# Payload-to-server compatibility map
# Key = payload type, Value = (valid server techs, valid client techs)
PAYLOAD_SERVER_MAP = {
    "angular": ([], ["angular", "angularjs"]),  # Client-side only
    "vue": ([], ["vue", "vue.js", "nuxt"]),     # Client-side only
    "ejs": (["node", "express"], []),           # Node.js only
    "pug": (["node", "express"], []),           # Node.js only
}


class TemplateInjectionStrategy(BaseXSSStrategy):
    """Template injection XSS detection strategy.

    Tests for Client-Side Template Injection (CSTI) in:
    - Angular ({{}} expressions)
    - Vue.js ({{}} expressions)
    - React (dangerouslySetInnerHTML)
    - EJS (<%=%> templates)
    - Pug/Jade templates

    Uses tech fingerprinting to prevent false positives
    (e.g., EJS payload on PHP server).
    """

    @property
    def name(self) -> str:
        return "template_injection"

    async def test(self, ctx: XSSStrategyContext) -> XSSStrategyResult:
        """Test for template injection XSS.

        Strategy:
        1. Get test URLs from context or discover common params
        2. Test {{7*7}} expression payloads
        3. Verify framework compatibility with fingerprinting
        4. Test sandbox escape if expression works
        """
        evidence_list: list[XSSEvidence] = []
        attempts = 0
        errors: list[str] = []

        # Get test URLs
        test_urls = self._build_test_urls(ctx)
        if not test_urls:
            return XSSStrategyResult.not_found(0, ["No URLs to test"])

        # Dedup: (framework, path) → list of affected param names
        detected: dict[tuple[str, str], list[str]] = {}
        sandbox_escaped: set[tuple[str, str]] = set()

        async with get_scan_client(timeout=ctx.timeout) as client:
            for url_template in test_urls[:10]:
                for payload, payload_name in TEMPLATE_INJECTION_PAYLOADS:
                    # Only test expression payloads first
                    if not payload_name.endswith("_expression"):
                        continue

                    await ctx.acquire_rate_limit()
                    attempts += 1

                    parsed = urlparse(url_template)
                    params = parse_qs(parsed.query)
                    if not params:
                        continue

                    param_name = list(params.keys())[0]
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

                    try:
                        response = await client.get(
                            test_url,
                            headers=ctx.auth_headers,
                        )

                        # Skip static files
                        content_type = response.headers.get("content-type", "").lower()
                        if "javascript" in content_type or "css" in content_type:
                            continue

                        # Skip JS-looking responses
                        text_start = response.text[:200].strip()
                        if text_start.startswith(("function", "var ", "const ", "let ", "import ", "export ", "(function", "!function", "window.")):
                            continue

                        # Check for template evaluation
                        if TEMPLATE_MATH_RESULT in response.text and payload not in response.text:
                            # Validate framework compatibility
                            framework = self._detect_framework(
                                payload_name, ctx, response
                            )

                            if not framework:
                                # Skip - cannot verify vulnerability
                                logger.debug(f"[XSS-CSTI] Skipped: no framework for {payload_name}")
                                continue

                            key = (framework, parsed.path)
                            detected.setdefault(key, [])
                            if param_name not in detected[key]:
                                detected[key].append(param_name)
                                logger.info(f"[XSS-CSTI] Found {framework} at {parsed.path} param={param_name}")

                            # Try sandbox escape
                            if key not in sandbox_escaped:
                                escaped = await self._test_sandbox_escape(
                                    client, ctx, framework, parsed, param_name, test_params
                                )
                                if escaped:
                                    sandbox_escaped.add(key)

                            break  # Found injection, try next URL

                    except asyncio.TimeoutError:
                        errors.append(f"Timeout testing {url_template}")
                    except Exception as e:
                        errors.append(f"Error: {e}")
                        logger.debug(f"[XSS-CSTI] Test error: {e}")

        # Build evidence from detected injections
        for (framework, path), affected_params in detected.items():
            if not affected_params:
                continue

            is_escaped = (framework, path) in sandbox_escaped
            evidence_list.append(XSSEvidence(
                payload="{{7*7}}",
                context=XSSContext.ANGULAR_BINDING if "angular" in framework.lower() else XSSContext.VUE_DIRECTIVE,
                reflected_in="template_expression",
                encoding_used="none",
                waf_bypassed=ctx.detected_waf is not None and ctx.detected_waf != WAFType.NONE,
                response_snippet=f"{{{{7*7}}}} evaluated to {TEMPLATE_MATH_RESULT}",
                confirmation_count=len(affected_params),
                metadata={
                    "template_injection": True,
                    "sandbox_escape": is_escaped,
                    "framework": framework,
                    "affected_parameters": affected_params,
                    "path": path,
                    "severity": "CRITICAL" if is_escaped else "HIGH",
                }
            ))

        if evidence_list:
            return XSSStrategyResult.vulnerable(evidence_list, attempts)
        return XSSStrategyResult.not_found(attempts, errors)

    def _build_test_urls(self, ctx: XSSStrategyContext) -> list[str]:
        """Build URLs to test for template injection."""
        test_urls = []
        test_params = ["q", "search", "query", "name", "title", "message", "text", "value", "input", "data"]

        # Get endpoints from context
        endpoints = ctx.asset_data.get("endpoints", [])[:5] if ctx.asset_data else []
        if not endpoints:
            endpoints = [ctx.base_url]

        for ep in endpoints:
            parsed = urlparse(ep)
            path_lower = parsed.path.lower()

            # Skip static files
            if any(path_lower.endswith(ext) for ext in STATIC_EXTENSIONS):
                logger.debug(f"[XSS-CSTI] Skipping static file: {ep}")
                continue

            if parsed.query:
                test_urls.append(ep)
            else:
                for p in test_params[:5]:
                    test_urls.append(f"{ep}?{p}=TEMPLATE_TEST")

        if not test_urls:
            test_urls = [f"{ctx.base_url}/?q=TEMPLATE_TEST"]

        return test_urls

    def _detect_framework(
        self,
        payload_name: str,
        ctx: XSSStrategyContext,
        response: "httpx.Response",
    ) -> str | None:
        """Detect and validate framework for template injection.

        Returns framework name if valid, None to skip (prevents FP).
        """
        # Get detected technologies
        detected_frameworks = []
        detected_server = None

        if ctx.asset_data:
            tech = ctx.asset_data.get("technologies", [])
            if tech:
                detected_frameworks = [str(t).lower() for t in tech]
            server_info = ctx.asset_data.get("server", "")
            if server_info:
                detected_server = str(server_info).lower()

        # Detect server from headers
        if not detected_server:
            server_header = response.headers.get("server", "").lower()
            x_powered = response.headers.get("x-powered-by", "").lower()
            if "php" in x_powered or "php" in server_header:
                detected_server = "php"
            elif "express" in x_powered or "node" in x_powered:
                detected_server = "node.js"
            elif "apache" in server_header and any("php" in f for f in detected_frameworks):
                detected_server = "php"

        # Get payload type
        payload_type = None
        for pt in ["angular", "vue", "ejs", "pug"]:
            if pt in payload_name:
                payload_type = pt
                break

        if not payload_type:
            return None

        # Check compatibility
        valid_servers, valid_clients = PAYLOAD_SERVER_MAP.get(payload_type, ([], []))

        # Check client-side framework
        client_match = None
        for det in detected_frameworks:
            for vc in valid_clients:
                if vc in det:
                    client_match = det
                    break
            if client_match:
                break

        # Check server-side framework
        server_match = None
        if detected_server:
            for vs in valid_servers:
                if vs in detected_server:
                    server_match = detected_server
                    break

        if client_match:
            return client_match.title().replace(".Js", ".js")
        elif server_match:
            return payload_type.upper() if payload_type == "ejs" else payload_type.title()
        elif detected_server == "php":
            # PHP + {{}} = FALSE POSITIVE
            logger.info(f"[AUDIT][XSS-CSTI] FP prevented: {payload_type} on PHP server")
            return None
        elif detected_server and payload_type in ["ejs", "pug"]:
            # EJS/Pug require Node.js
            logger.info(f"[AUDIT][XSS-CSTI] FP prevented: {payload_type} requires Node.js")
            return None

        # Check for any JS framework
        js_frameworks = ["react", "vue", "angular", "svelte", "next", "nuxt"]
        for det in detected_frameworks:
            for jf in js_frameworks:
                if jf in det:
                    if "react" in det:
                        return "React (Server-Side)"
                    elif "vue" in det:
                        return "Vue.js"
                    elif "angular" in det:
                        return "Angular"
                    elif "svelte" in det:
                        return "Svelte"
                    elif "next" in det:
                        return "Next.js"
                    elif "nuxt" in det:
                        return "Nuxt.js"

        return None

    async def _test_sandbox_escape(
        self,
        client: "httpx.AsyncClient",
        ctx: XSSStrategyContext,
        framework: str,
        parsed: Any,
        param_name: str,
        test_params: dict,
    ) -> bool:
        """Test if sandbox escape is possible."""
        for exploit_payload, exploit_name in TEMPLATE_INJECTION_PAYLOADS:
            if exploit_name.endswith("_expression"):
                continue
            if framework.lower() not in exploit_name:
                continue

            await ctx.acquire_rate_limit()
            test_params[param_name] = exploit_payload
            exploit_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

            try:
                response = await client.get(exploit_url, headers=ctx.auth_headers)
                if response.status_code == 200 and exploit_payload not in response.text:
                    return True
            except (asyncio.TimeoutError, Exception):
                continue

        return False


__all__ = ["TemplateInjectionStrategy"]
