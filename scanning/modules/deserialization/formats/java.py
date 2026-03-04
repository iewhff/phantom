from __future__ import annotations

import base64
import re
from typing import Any
from urllib.parse import quote, urljoin

from scanning.findings import Finding, Severity
from scanning.modules.deserialization.deser_base import (
    DeserVulnType, GadgetChainType, SerializationFormat,
    DeserTestResult, logger,
)
from utils.rate_limiter import RateLimiter


async def _test_java_deserialization(
    self,
    client: Any,
    base_url: str,
    urls: list[str],
    rate_limiter: RateLimiter,
) -> list[Finding]:
    """Test for Java deserialization vulnerabilities."""
    findings = []

    # Test common Java endpoints
    for endpoint in self.JAVA_ENDPOINTS[:15]:
        await rate_limiter.acquire()

        try:
            url = urljoin(base_url, endpoint)

            # Send Java serialized payload
            payload = base64.b64decode(self.DETECTION_PAYLOADS["java"]["urldns"])

            headers = {
                "Content-Type": "application/x-java-serialized-object",
            }

            response = await client.post(url, content=payload, headers=headers)

            # Check for deserialization indicators
            if response.status_code in [200, 500]:
                error_indicators = [
                    "ClassNotFoundException",
                    "InvalidClassException",
                    "StreamCorruptedException",
                    "java.io.ObjectInputStream",
                    "readObject",
                    "DeserializationException",
                    "org.apache.commons.collections",
                    "InvokerTransformer",
                    "UnmarshalException",
                ]

                for indicator in error_indicators:
                    if indicator in response.text:
                        # Determine likely gadget chains
                        gadgets = []
                        if "commons.collections" in response.text.lower():
                            gadgets.append("CommonsCollections")
                        if "springframework" in response.text.lower():
                            gadgets.append("Spring")

                        findings.append(Finding(
                            name="Java Deserialization Endpoint",
                            severity=Severity.CRITICAL,
                            confidence_score=85.0,
                            description=f"Endpoint accepts Java serialized objects: {endpoint}",
                            endpoint=url,
                            evidence=[
                                f"Error indicator: {indicator}",
                                f"Potential gadgets: {', '.join(gadgets) or 'Unknown'}",
                                "Endpoint processes serialized Java objects",
                            ],
                            cwe_id="CWE-502",
                            cvss_score=9.8,
                            remediation="Disable Java serialization endpoints or implement strict "
                                       "class filtering with ObjectInputFilter.",
                        ))

                        self.test_results.append(DeserTestResult(
                            vuln_type=DeserVulnType.JAVA_OBJECT,
                            endpoint=endpoint,
                            evidence=[indicator],
                            error_based=True,
                        ))
                        break

        except Exception as e:
            logger.debug(f"Error testing Java endpoint {endpoint}: {e}")

    # Test parameters that might accept serialized data
    for url in urls[:10]:
        for param in self.SERIALIZATION_POINTS[:10]:
            await rate_limiter.acquire()

            try:
                payload = self.DETECTION_PAYLOADS["java"]["urldns"]
                test_url = f"{url}?{param}={quote(payload)}"

                response = await client.get(test_url)

                java_indicators = [
                    "ClassNotFoundException",
                    "java.io",
                    "ObjectInputStream",
                    "InvalidClassException",
                    "readObject",
                ]

                if any(ind in response.text for ind in java_indicators):
                    findings.append(Finding(
                        name="Java Deserialization in Parameter",
                        severity=Severity.CRITICAL,
                        confidence_score=85.0,
                        description=f"Parameter '{param}' processes Java serialized data",
                        endpoint=url,
                        evidence=[f"Parameter: {param}", "Java deserialization detected"],
                        cwe_id="CWE-502",
                        cvss_score=9.8,
                        remediation="Never deserialize untrusted Java objects from user input.",
                    ))

            except Exception as e:
                logger.debug(f"Error testing Java param: {e}")

    return findings
