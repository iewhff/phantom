from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote, urljoin

from scanning.findings import Finding, Severity
from scanning.modules.deserialization.deser_base import (
    DeserVulnType, GadgetChainType, SerializationFormat,
    DeserTestResult, logger,
)
from utils.rate_limiter import RateLimiter


async def _test_php_object_injection(
    self,
    client: Any,
    base_url: str,
    urls: list[str],
    rate_limiter: RateLimiter,
) -> list[Finding]:
    """
    Test for PHP object injection vulnerabilities.

    FP MITIGATION (v2.0):
    - Validates HTTP status code (skip 404/500 error pages)
    - Checks content-type (skip HTML error pages)
    - Runs negative control (compare with baseline response)
    - Separates SPECIFIC vs GENERIC PHP error indicators
    - Detects training apps and reduces confidence
    """
    findings = []

    # Test different PHP gadget chains
    php_payloads = [
        ("basic", self.DETECTION_PAYLOADS["php"]["basic"]),
        ("guzzle", self.DETECTION_PAYLOADS["php"]["guzzle"]),
        ("monolog", self.DETECTION_PAYLOADS["php"]["monolog"]),
        ("symfony", self.DETECTION_PAYLOADS["php"]["symfony"]),
    ]

    # FP MITIGATION: Separate SPECIFIC indicators (high confidence) from GENERIC ones
    php_specific_indicators = [
        "unserialize()",       # Direct reference to unserialize
        "__wakeup",            # Magic method specific to unserialization
        "__destruct",          # Magic method called on unserialization
        "O:\\d+:",             # PHP serialized object pattern
    ]

    php_generic_indicators = [
        "Object of class",                    # Could be any class error
        "could not be converted to string",   # Generic type error
        "Allowed memory size",                # Memory limit error
        "Call to undefined method",           # Generic method error
        "Call to a member function",          # Generic method error
        "Fatal error",                        # Very generic
    ]

    for url in urls[:15]:
        # FP MITIGATION: Skip static assets
        if self._is_static_asset(url):
            continue

        # FP MITIGATION: Get baseline for negative control
        baseline_text = await self._get_baseline_response(client, url, rate_limiter)

        for param in self.SERIALIZATION_POINTS[:8]:
            for payload_name, payload in php_payloads:
                await rate_limiter.acquire()

                try:
                    # GET request
                    test_url = f"{url}?{param}={quote(payload)}"
                    response = await client.get(test_url)
                    response_text = response.text
                    content_type = response.headers.get("content-type", "")

                    # FP MITIGATION: Skip error pages
                    if self._is_error_page(response.status_code, response_text, content_type):
                        continue

                    # Check for SPECIFIC indicators first (high confidence)
                    found_specific = None
                    for indicator in php_specific_indicators:
                        if re.search(indicator, response_text, re.IGNORECASE):
                            found_specific = indicator
                            break

                    # Check for GENERIC indicators (lower confidence)
                    found_generic = None
                    if not found_specific:
                        for indicator in php_generic_indicators:
                            if indicator in response_text:
                                found_generic = indicator
                                break

                    found_indicator = found_specific or found_generic

                    if found_indicator:
                        # FP MITIGATION: Negative control check
                        if found_indicator in baseline_text:
                            logger.debug(f"[PHP] Baseline has '{found_indicator}', skipping")
                            continue

                        # Calculate confidence
                        is_specific = found_specific is not None
                        confidence = self._calculate_confidence(
                            is_specific=is_specific,
                            status_code=response.status_code,
                            baseline_matches=False,
                        )

                        # Determine severity based on gadget type AND confidence
                        if confidence == "HIGH" and payload_name in ["guzzle", "monolog", "symfony"]:
                            severity = "CRITICAL"
                        elif confidence == "HIGH":
                            severity = "HIGH"
                        else:
                            severity = "MEDIUM"

                        findings.append(Finding(
                            name=f"PHP Object Injection ({payload_name})",
                            severity=severity,
                            confidence_score=confidence,
                            description=(
                                f"PHP unserialize() may process parameter '{param}'."
                            ),
                            endpoint=url,
                            evidence=[
                                f"Parameter: {param}",
                                f"Gadget tested: {payload_name}",
                                f"PHP indicator: {found_indicator}",
                                f"Indicator type: {'Specific' if is_specific else 'Generic'}",
                            ],
                            cwe_id="CWE-502",
                            cvss_score=9.8 if severity == "CRITICAL" else 7.5,
                            remediation="Use json_decode() instead of unserialize(). "
                                       "Never unserialize user-controlled input.",
                        ))

                        self.test_results.append(DeserTestResult(
                            vuln_type=DeserVulnType.PHP_OBJECT,
                            parameter=param,
                            endpoint=url,
                            evidence=[found_indicator],
                            error_based=True,
                        ))
                        break  # Found vulnerability, move to next parameter

                    # Also test POST data
                    await rate_limiter.acquire()
                    response = await client.post(url, data={param: payload})
                    resp_text = response.text
                    resp_ct = response.headers.get("content-type", "")

                    # FP MITIGATION: Same validation for POST
                    if self._is_error_page(response.status_code, resp_text, resp_ct):
                        continue

                    for indicator in php_specific_indicators + php_generic_indicators:
                        pattern = indicator if '\\' in indicator else re.escape(indicator)
                        if re.search(pattern, resp_text, re.IGNORECASE):
                            # Negative control
                            if indicator in baseline_text:
                                continue

                            is_specific = indicator in php_specific_indicators
                            confidence = self._calculate_confidence(is_specific, response.status_code, False)
                            severity = "CRITICAL" if confidence == "HIGH" else "HIGH"

                            findings.append(Finding(
                                name=f"PHP Object Injection POST ({payload_name})",
                                severity=severity,
                                confidence_score=confidence,
                                description=f"PHP unserialize() may process POST parameter '{param}'",
                                endpoint=url,
                                evidence=[f"POST parameter: {param}", f"Gadget: {payload_name}", f"Indicator: {indicator}"],
                                cwe_id="CWE-502",
                                cvss_score=9.8 if severity == "CRITICAL" else 7.5,
                                remediation="Never use unserialize() on POST data.",
                            ))
                            break

                except Exception as e:
                    logger.debug(f"Error testing PHP object injection: {e}")

    # Test PHP-specific endpoints
    for endpoint in self.PHP_ENDPOINTS[:10]:
        await rate_limiter.acquire()

        try:
            url = urljoin(base_url, endpoint)
            response = await client.get(url)

            # Check if endpoint exists and might be vulnerable
            if response.status_code == 200:
                if "laravel" in endpoint or "ignition" in endpoint:
                    if "_ignition" in response.text or "Ignition" in response.text:
                        findings.append(Finding(
                            name="Laravel Ignition Detected",
                            severity=Severity.HIGH,
                            confidence_score=85.0,
                            description="Laravel Ignition debug interface detected - potential CVE-2021-3129",
                            endpoint=url,
                            evidence=["Ignition interface accessible"],
                            cwe_id="CWE-502",
                            cvss_score=9.8,
                            remediation="Disable debug mode in production. Update to Ignition >= 2.5.2.",
                        ))

        except Exception as e:
            logger.debug(f"Error testing PHP endpoint: {e}")

    return findings
