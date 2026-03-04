from __future__ import annotations

import base64
import re
from typing import Any

from scanning.findings import Finding, Severity
from scanning.modules.deserialization.deser_base import (
    DeserVulnType, GadgetChainType, SerializationFormat,
    DeserTestResult, logger,
)
from utils.rate_limiter import RateLimiter


async def _test_viewstate(
    self,
    client: Any,
    base_url: str,
    urls: list[str],
    rate_limiter: RateLimiter,
) -> list[Finding]:
    """Test for .NET ViewState deserialization vulnerabilities."""
    findings = []

    # Look for .aspx pages
    aspx_urls = [u for u in urls if ".aspx" in u.lower()]
    test_urls = aspx_urls or [base_url]

    for url in test_urls[:10]:
        await rate_limiter.acquire()

        try:
            response = await client.get(url)

            # Look for ViewState
            viewstate_match = re.search(
                r'<input[^>]*name="__VIEWSTATE"[^>]*value="([^"]*)"',
                response.text,
                re.IGNORECASE
            )

            if viewstate_match:
                viewstate = viewstate_match.group(1)

                # Check if ViewState is encrypted/MAC protected
                generator_match = re.search(
                    r'<input[^>]*name="__VIEWSTATEGENERATOR"[^>]*value="([^"]*)"',
                    response.text,
                    re.IGNORECASE
                )

                mac_match = re.search(
                    r'<input[^>]*name="__VIEWSTATEMAC"',
                    response.text,
                    re.IGNORECASE
                )

                eventvalidation_match = re.search(
                    r'<input[^>]*name="__EVENTVALIDATION"[^>]*value="([^"]*)"',
                    response.text,
                    re.IGNORECASE
                )

                if not mac_match:
                    # ViewState without MAC - serious vulnerability
                    findings.append(Finding(
                        name="ViewState Without MAC Protection",
                        severity=Severity.CRITICAL,
                        confidence_score=85.0,
                        description="ASP.NET ViewState is not MAC protected, enabling deserialization attacks",
                        endpoint=url,
                        evidence=[
                            "ViewState found without MAC validation",
                            f"ViewState length: {len(viewstate)} chars",
                            f"Generator: {generator_match.group(1) if generator_match else 'Not found'}",
                        ],
                        cwe_id="CWE-502",
                        cvss_score=9.8,
                        remediation="Enable ViewState MAC validation in web.config: "
                                   '<pages enableViewStateMac="true" />. '
                                   "Set machineKey with random keys.",
                    ))

                    self.test_results.append(DeserTestResult(
                        vuln_type=DeserVulnType.DOTNET_VIEWSTATE,
                        endpoint=url,
                        evidence=["MAC disabled"],
                        cve_ids=["CVE-2020-0688", "CVE-2020-16952"],
                    ))

                # Try to decode ViewState
                try:
                    # Remove URL encoding if present
                    vs_clean = viewstate.replace("%2B", "+").replace("%2F", "/").replace("%3D", "=")
                    decoded = base64.b64decode(vs_clean)

                    # Check for .NET serialization markers
                    if decoded.startswith(self.DOTNET_VIEWSTATE_PREFIX_V1) or \
                       decoded.startswith(self.DOTNET_VIEWSTATE_PREFIX_V2):
                        findings.append(Finding(
                            name="ASP.NET ViewState Structure Analyzed",
                            severity=Severity.MEDIUM,
                            confidence_score=85.0,
                            description="ViewState structure identified - potential attack surface",
                            endpoint=url,
                            evidence=[
                                "ViewState uses LosFormatter/ObjectStateFormatter",
                                f"Size: {len(decoded)} bytes",
                            ],
                            cwe_id="CWE-502",
                            remediation="Ensure ViewState MAC is enabled with strong keys.",
                        ))

                    if b'\x00\x01' in decoded or b'System.' in decoded:
                        findings.append(Finding(
                            name="ViewState Contains .NET Serialized Objects",
                            severity=Severity.HIGH,
                            confidence_score=65.0,
                            description="ViewState appears to contain .NET serialized objects",
                            endpoint=url,
                            evidence=["Binary .NET serialization markers detected"],
                            cwe_id="CWE-502",
                            remediation="Use ViewStateUserKey and enable MAC protection.",
                        ))

                except Exception:
                    pass

                # Check for known vulnerable ASP.NET patterns
                if "Exchange" in response.text or "OWA" in response.text:
                    findings.append(Finding(
                        name="Potential Exchange Server ViewState (CVE-2020-0688)",
                        severity=Severity.CRITICAL,
                        confidence_score=65.0,
                        description="Exchange Server detected - check for CVE-2020-0688",
                        endpoint=url,
                        evidence=["Exchange/OWA patterns detected with ViewState"],
                        cwe_id="CWE-502",
                        cvss_score=8.8,
                        remediation="Apply Exchange Server security updates immediately.",
                    ))

        except Exception as e:
            logger.debug(f"Error testing ViewState: {e}")

    return findings


async def _test_dotnet_jsonnet(
    self,
    client: Any,
    base_url: str,
    urls: list[str],
    rate_limiter: RateLimiter,
) -> list[Finding]:
    """Test for .NET Json.NET TypeNameHandling vulnerabilities."""
    findings = []

    jsonnet_payloads = self.DOTNET_PAYLOADS["jsonnet"]["detection_payloads"]

    for url in urls[:10]:
        # Test JSON endpoints
        for param in ["data", "json", "body", "payload", "request", "object"]:
            await rate_limiter.acquire()

            try:
                for payload in jsonnet_payloads[:2]:
                    headers = {"Content-Type": "application/json"}

                    # POST with type information
                    response = await client.post(
                        url,
                        content=payload,
                        headers=headers
                    )

                    # Check for TypeNameHandling indicators
                    jsonnet_indicators = [
                        "TypeNameHandling",
                        "$type",
                        "ObjectDataProvider",
                        "System.Windows.Data",
                        "PresentationFramework",
                        "JsonSerializationException",
                        "Type specified in JSON",
                        "Error resolving type",
                    ]

                    for indicator in jsonnet_indicators:
                        if indicator in response.text:
                            findings.append(Finding(
                                name=".NET Json.NET TypeNameHandling Vulnerability",
                                severity=Severity.CRITICAL,
                                confidence_score=85.0,
                                description="Json.NET processes $type metadata enabling RCE",
                                endpoint=url,
                                evidence=[
                                    f"Indicator: {indicator}",
                                    "TypeNameHandling appears to be enabled",
                                ],
                                cwe_id="CWE-502",
                                cvss_score=9.8,
                                remediation="Set TypeNameHandling.None in JsonSerializerSettings. "
                                           "Never use TypeNameHandling.All or Auto.",
                            ))

                            self.test_results.append(DeserTestResult(
                                vuln_type=DeserVulnType.DOTNET_JSON,
                                parameter=param,
                                endpoint=url,
                                evidence=[indicator],
                                error_based=True,
                            ))
                            break

            except Exception as e:
                logger.debug(f"Error testing Json.NET: {e}")

    return findings
