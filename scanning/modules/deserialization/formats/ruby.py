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


async def _test_ruby_deserialization(
    self,
    client: Any,
    base_url: str,
    urls: list[str],
    rate_limiter: RateLimiter,
) -> list[Finding]:
    """Test for Ruby Marshal and YAML deserialization."""
    findings = []

    # Test Ruby Marshal
    marshal_payload = self.RUBY_PAYLOADS["marshal"]["detection_gem_installer"]

    for url in urls[:10]:
        for param in self.SERIALIZATION_POINTS[:6]:
            await rate_limiter.acquire()

            try:
                test_url = f"{url}?{param}={quote(marshal_payload)}"
                response = await client.get(test_url)

                ruby_indicators = [
                    "Marshal",
                    "TypeError",
                    "dump format error",
                    "instance variable",
                    "ArgumentError",
                    "Gem::Installer",
                    "undefined class",
                    "incompatible marshal",
                ]

                for indicator in ruby_indicators:
                    if indicator in response.text:
                        findings.append(Finding(
                            name="Ruby Marshal Deserialization",
                            severity=Severity.CRITICAL,
                            confidence_score=85.0,
                            description=f"Ruby Marshal.load processes parameter '{param}'",
                            endpoint=url,
                            evidence=[
                                f"Parameter: {param}",
                                f"Ruby indicator: {indicator}",
                            ],
                            cwe_id="CWE-502",
                            cvss_score=9.8,
                            remediation="Use JSON instead of Marshal. Never Marshal.load untrusted data.",
                        ))

                        self.test_results.append(DeserTestResult(
                            vuln_type=DeserVulnType.RUBY_MARSHAL,
                            parameter=param,
                            endpoint=url,
                            evidence=[indicator],
                            error_based=True,
                            cve_ids=["CVE-2013-0156", "CVE-2019-5420"],
                        ))
                        break

            except Exception as e:
                logger.debug(f"Error testing Ruby Marshal: {e}")

    # Test Ruby YAML
    yaml_payload = self.RUBY_PAYLOADS["yaml"]["simple_rce"]

    for url in urls[:8]:
        await rate_limiter.acquire()

        try:
            headers = {"Content-Type": "application/x-yaml"}
            response = await client.post(url, content=yaml_payload, headers=headers)

            if "Gem::" in response.text or "Psych::" in response.text:
                findings.append(Finding(
                    name="Ruby YAML Deserialization",
                    severity=Severity.CRITICAL,
                    confidence_score=85.0,
                    description="Ruby YAML.load processes untrusted input",
                    endpoint=url,
                    evidence=["Ruby Gem/Psych classes detected in response"],
                    cwe_id="CWE-502",
                    cvss_score=9.8,
                    remediation="Use YAML.safe_load instead of YAML.load.",
                ))

        except Exception as e:
            logger.debug(f"Error testing Ruby YAML: {e}")

    return findings
