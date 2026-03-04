from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from scanning.findings import Finding, Severity
from scanning.modules.deserialization.deser_base import (
    DeserVulnType, GadgetChainType, SerializationFormat,
    DeserTestResult, logger,
)
from utils.rate_limiter import RateLimiter


async def _test_node_serialize(
    self,
    client: Any,
    base_url: str,
    urls: list[str],
    rate_limiter: RateLimiter,
) -> list[Finding]:
    """Test for Node.js deserialization vulnerabilities."""
    findings = []

    node_payloads = [
        ("node-serialize", self.NODEJS_PAYLOADS["node-serialize"]["payloads"]["detect"]),
        ("funcster", self.NODEJS_PAYLOADS["funcster"]["payloads"]["rce"]),
    ]

    for url in urls[:10]:
        for param in self.SERIALIZATION_POINTS[:8]:
            for payload_name, payload in node_payloads:
                await rate_limiter.acquire()

                try:
                    # Try in cookie
                    cookies = {param: payload}
                    response = await client.get(url, cookies=cookies)

                    node_indicators = [
                        "_$$ND_FUNC$$_",
                        "__js_function",
                        "SyntaxError: Unexpected token",
                        "ReferenceError",
                        "TypeError: Cannot read property",
                        "node-serialize",
                        "unserialize",
                    ]

                    for indicator in node_indicators:
                        if indicator in response.text:
                            marker = self.NODEJS_PAYLOADS[payload_name.split("-")[0] if "-" in payload_name else payload_name].get("marker", "")

                            findings.append(Finding(
                                name=f"Node.js {payload_name} Vulnerability",
                                severity=Severity.CRITICAL,
                                confidence_score=85.0,
                                description=f"{payload_name} processes cookie '{param}'",
                                endpoint=url,
                                evidence=[
                                    f"Cookie: {param}",
                                    f"Indicator: {indicator}",
                                    f"Marker: {marker}" if marker else "",
                                ],
                                cwe_id="CWE-502",
                                cvss_score=9.8,
                                remediation=f"Remove {payload_name} package. Use JSON.parse/stringify.",
                            ))

                            self.test_results.append(DeserTestResult(
                                vuln_type=DeserVulnType.NODE_SERIALIZE,
                                parameter=param,
                                endpoint=url,
                                evidence=[indicator],
                                cve_ids=["CVE-2017-5941"] if payload_name == "node-serialize" else [],
                            ))
                            break

                    # Check for RCE
                    if "uid=" in response.text:
                        findings.append(Finding(
                            name="Node.js Deserialization RCE Confirmed",
                            severity=Severity.CRITICAL,
                            confidence_score=85.0,
                            description=f"RCE via {payload_name} in cookie '{param}'",
                            endpoint=url,
                            evidence=["Command execution detected"],
                            cwe_id="CWE-502",
                            cvss_score=10.0,
                            remediation=f"CRITICAL: Remove {payload_name} immediately.",
                        ))

                    # Try in query parameter
                    await rate_limiter.acquire()
                    test_url = f"{url}?{param}={quote(payload)}"
                    response = await client.get(test_url)

                    for indicator in node_indicators:
                        if indicator in response.text:
                            findings.append(Finding(
                                name=f"Node.js {payload_name} in Parameter",
                                severity=Severity.CRITICAL,
                                confidence_score=85.0,
                                description=f"{payload_name} processes parameter '{param}'",
                                endpoint=url,
                                evidence=[f"Parameter: {param}"],
                                cwe_id="CWE-502",
                                cvss_score=9.8,
                                remediation="Never deserialize user-controlled input.",
                            ))
                            break

                except Exception as e:
                    logger.debug(f"Error testing {payload_name}: {e}")

    return findings
