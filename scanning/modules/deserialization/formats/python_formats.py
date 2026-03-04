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


async def _test_python_pickle(
    self,
    client: Any,
    base_url: str,
    urls: list[str],
    rate_limiter: RateLimiter,
) -> list[Finding]:
    """Test for Python pickle deserialization vulnerabilities."""
    findings = []

    pickle_payloads = [
        ("safe_detect", self.PYTHON_PAYLOADS["pickle"]["safe_detect"]),
        ("rce_v0", self.PYTHON_PAYLOADS["pickle"]["rce_exec_v0"]),
    ]

    for url in urls[:10]:
        for param in self.SERIALIZATION_POINTS[:8]:
            for payload_name, payload in pickle_payloads:
                await rate_limiter.acquire()

                try:
                    # Test in query parameter
                    test_url = f"{url}?{param}={quote(payload)}"
                    response = await client.get(test_url)

                    # Check for pickle-related errors
                    pickle_indicators = [
                        "pickle",
                        "unpickle",
                        "cPickle",
                        "_pickle",
                        "loads()",
                        "UnpicklingError",
                        "could not find MARK",
                        "invalid load key",
                        "EOFError",
                        "insecure string pickle",
                        "GLOBAL",
                        "REDUCE",
                    ]

                    found_indicator = None
                    for indicator in pickle_indicators:
                        if indicator.lower() in response.text.lower():
                            found_indicator = indicator
                            break

                    if found_indicator:
                        findings.append(Finding(
                            name="Python Pickle Deserialization",
                            severity=Severity.CRITICAL,
                            confidence_score=85.0,
                            description=f"Python pickle processes parameter '{param}'",
                            endpoint=url,
                            evidence=[
                                f"Parameter: {param}",
                                f"Pickle indicator: {found_indicator}",
                                f"Payload type: {payload_name}",
                            ],
                            cwe_id="CWE-502",
                            cvss_score=9.8,
                            remediation="Never use pickle.loads() on untrusted data. "
                                       "Use JSON or other safe formats.",
                        ))

                        self.test_results.append(DeserTestResult(
                            vuln_type=DeserVulnType.PYTHON_PICKLE,
                            parameter=param,
                            endpoint=url,
                            evidence=[found_indicator],
                            error_based=True,
                        ))
                        break

                    # Check for successful command execution
                    if "uid=" in response.text and "gid=" in response.text:
                        findings.append(Finding(
                            name="Python Pickle RCE Confirmed",
                            severity=Severity.CRITICAL,
                            confidence_score=85.0,
                            description="Remote code execution via pickle deserialization confirmed",
                            endpoint=url,
                            evidence=[
                                f"Parameter: {param}",
                                "Command execution successful (id output detected)",
                            ],
                            cwe_id="CWE-502",
                            cvss_score=10.0,
                            remediation="CRITICAL: Remove pickle deserialization immediately.",
                        ))

                        self.test_results.append(DeserTestResult(
                            vuln_type=DeserVulnType.PYTHON_PICKLE,
                            parameter=param,
                            endpoint=url,
                            rce_confirmed=True,
                        ))

                    # Test in POST body
                    await rate_limiter.acquire()
                    response = await client.post(url, data={param: payload})

                    for indicator in pickle_indicators:
                        if indicator.lower() in response.text.lower():
                            findings.append(Finding(
                                name="Python Pickle POST Parameter",
                                severity=Severity.CRITICAL,
                                confidence_score=85.0,
                                description=f"Pickle processes POST parameter '{param}'",
                                endpoint=url,
                                evidence=[f"POST parameter: {param}"],
                                cwe_id="CWE-502",
                                cvss_score=9.8,
                                remediation="Remove pickle deserialization from POST handlers.",
                            ))
                            break

                except Exception as e:
                    logger.debug(f"Error testing pickle: {e}")

    return findings


async def _test_python_yaml(
    self,
    client: Any,
    base_url: str,
    urls: list[str],
    rate_limiter: RateLimiter,
) -> list[Finding]:
    """Test for Python PyYAML unsafe load vulnerabilities."""
    findings = []

    yaml_payloads = [
        ("basic", self.PYTHON_PAYLOADS["yaml"]["rce_basic"]),
        ("subprocess", self.PYTHON_PAYLOADS["yaml"]["rce_subprocess"]),
    ]

    for url in urls[:10]:
        for param in ["yaml", "config", "data", "settings", "content"]:
            for payload_name, payload in yaml_payloads:
                await rate_limiter.acquire()

                try:
                    # Test YAML content type
                    headers = {"Content-Type": "application/x-yaml"}
                    response = await client.post(url, content=payload, headers=headers)

                    yaml_indicators = [
                        "yaml",
                        "YAMLError",
                        "scanner error",
                        "could not determine a constructor",
                        "expected a single document",
                        "!!python/object",
                        "tag:yaml.org",
                        "safe_load",
                        "FullLoader",
                    ]

                    for indicator in yaml_indicators:
                        if indicator.lower() in response.text.lower():
                            findings.append(Finding(
                                name="Python YAML Deserialization",
                                severity=Severity.CRITICAL,
                                confidence_score=85.0 if "!!python" in response.text else "MEDIUM",
                                description="PyYAML unsafe load detected",
                                endpoint=url,
                                evidence=[
                                    f"YAML indicator: {indicator}",
                                    f"Payload: {payload_name}",
                                ],
                                cwe_id="CWE-502",
                                cvss_score=9.8,
                                remediation="Use yaml.safe_load() instead of yaml.load(). "
                                           "Never use yaml.full_load() or yaml.unsafe_load().",
                            ))

                            self.test_results.append(DeserTestResult(
                                vuln_type=DeserVulnType.PYTHON_YAML,
                                endpoint=url,
                                evidence=[indicator],
                                error_based=True,
                                cve_ids=["CVE-2020-1747", "CVE-2017-18342"],
                            ))
                            break

                    # Check for RCE
                    if "uid=" in response.text:
                        findings.append(Finding(
                            name="Python YAML RCE Confirmed",
                            severity=Severity.CRITICAL,
                            confidence_score=85.0,
                            description="Remote code execution via PyYAML confirmed",
                            endpoint=url,
                            evidence=["Command execution detected"],
                            cwe_id="CWE-502",
                            cvss_score=10.0,
                            remediation="CRITICAL: Switch to yaml.safe_load() immediately.",
                        ))

                except Exception as e:
                    logger.debug(f"Error testing YAML: {e}")

    return findings
