#!/usr/bin/env python3
"""
PHANTOM Scanner - Comprehensive Lab Testing
Tests all scanners against all available vulnerable labs

Usage:
    python scripts/test_all_labs.py                    # Test all running labs
    python scripts/test_all_labs.py --lab juice-shop  # Test specific lab
    python scripts/test_all_labs.py --scanner sqli    # Test specific scanner
"""

import asyncio
import os
import sys
import time
import argparse
import socket
from datetime import datetime
from urllib.parse import urlparse

# Set environment for aggressive testing
os.environ["PHANTOM_ALLOW_AGGRESSIVE"] = "authorized"
os.environ["PHANTOM_NO_TOR"] = "1"
os.environ["PHANTOM_SAFE_MODE"] = "aggressive"
os.environ["PHANTOM_NO_CIRCUIT_BREAKER"] = "1"

import logging
logging.basicConfig(level=logging.WARNING)

LABS = {
    "juice-shop": {
        "url": "http://localhost:3000",
        "port": 3000,
        "expected": {
            "sqli_scanner": True,
            "xss_scanner": True,
            "jwt_scanner": True,
            "api_logic_profiler": True,
            "business_logic_scanner": True,
            "file_upload_scanner": True,
            "open_redirect_scanner": True,
            "cors_checker": True,
        }
    },
    "dvwa": {
        "url": "http://localhost:80",
        "port": 80,
        "expected": {
            "sqli_scanner": True,
            "xss_scanner": True,
            "csrf_scanner": True,
            "lfi_scanner": True,
            "cmdi_scanner": True,
            "file_upload_scanner": True,
        }
    },
    "webgoat": {
        "url": "http://localhost:8080",
        "port": 8080,
        "expected": {
            "xxe_scanner": True,
            "jwt_scanner": True,
            "ssrf_scanner": True,
            "deserialization_scanner": True,
        }
    },
    "nodegoat": {
        "url": "http://localhost:4000",
        "port": 4000,
        "expected": {
            "nosql_scanner": True,
            "ssrf_scanner": True,
            "xss_scanner": True,
            "api_logic_profiler": True,
        }
    },
    "dvga": {
        "url": "http://localhost:5013",
        "port": 5013,
        "expected": {
            "graphql_advanced_scanner": True,
        }
    },
    "flask-vuln": {
        "url": "http://localhost:5000",
        "port": 5000,
        "expected": {
            "ssti_scanner": True,
            "cmdi_scanner": True,
            "sqli_scanner": True,
        }
    },
}

SCANNER_MODULES = [
    ("sqli_scanner", "SQLiScanner"),
    ("xss_scanner", "XSSScanner"),
    ("ssti_scanner", "SSTIScanner"),
    ("cmdi_scanner", "CommandInjectionScanner"),
    ("lfi_scanner", "LFIScanner"),
    ("ssrf_scanner", "SSRFScanner"),
    ("nosql_scanner", "NoSQLScanner"),
    ("xxe_scanner", "XXEScanner"),
    ("jwt_scanner", "JWTScanner"),
    ("csrf_scanner", "CSRFScanner"),
    ("cors_checker", "CORSChecker"),
    ("api_logic_profiler", "APILogicProfiler"),
    ("business_logic_scanner", "BusinessLogicScanner"),
    ("file_upload_scanner", "FileUploadScanner"),
    ("session_abuse_scanner", "SessionAbuseScanner"),
    ("open_redirect_scanner", "OpenRedirectScanner"),
    ("graphql_advanced_scanner", "GraphQLAdvancedScanner"),
    ("deserialization_scanner", "DeserializationScanner"),
]


def is_port_open(port: int, host: str = "localhost") -> bool:
    """Check if a port is open (lab is running)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


async def test_scanner(module_name: str, class_name: str, url: str, timeout: float = 60.0):
    """Test a single scanner against a URL."""
    from utils.rate_limiter import RateLimiter
    from core.config_manager import Settings

    try:
        module = __import__(f"scanning.modules.{module_name}", fromlist=[class_name])
        ScannerClass = getattr(module, class_name)
    except (ImportError, AttributeError) as e:
        return {"status": "IMPORT_ERROR", "error": str(e), "time": 0, "findings": 0}

    settings = Settings()
    rate_limiter = RateLimiter(settings=None, default_rate=10.0)

    # Special handling for scanners that don't follow ScanModule(settings) pattern
    if module_name == "file_upload_scanner":
        scanner = ScannerClass(http_client=None)  # Uses internal http client
    else:
        scanner = ScannerClass(settings)

    # Parse host from URL
    parsed = urlparse(url)
    host = f"{parsed.netloc}"

    asset_data = {
        "endpoints": [url],
        "forms": [],
        "urls": [url],
        "auth_context": {},
    }

    start = time.time()
    try:
        result = await asyncio.wait_for(
            scanner.scan(host, asset_data, rate_limiter),
            timeout=timeout
        )
        elapsed = time.time() - start
        findings = len(result.get('findings', []))
        return {"status": "OK", "time": elapsed, "findings": findings}
    except asyncio.TimeoutError:
        return {"status": "TIMEOUT", "time": timeout, "findings": 0}
    except Exception as e:
        elapsed = time.time() - start
        return {"status": "ERROR", "error": str(e)[:50], "time": elapsed, "findings": 0}


async def test_lab(lab_name: str, lab_config: dict, scanner_filter: str = None):
    """Test all scanners against a lab."""
    url = lab_config["url"]
    expected = lab_config.get("expected", {})
    port = lab_config.get("port", 80)

    # Check if lab is running
    if not is_port_open(port):
        print(f"\n{'='*60}")
        print(f"SKIPPED: {lab_name} (port {port} not open)")
        print(f"Start with: docker run -d -p {port}:{port} ...")
        print(f"{'='*60}")
        return None

    print(f"\n{'='*60}")
    print(f"Testing: {lab_name} ({url})")
    print(f"{'='*60}")

    results = {}
    for module_name, class_name in SCANNER_MODULES:
        # Filter by scanner name if specified
        if scanner_filter and scanner_filter not in module_name:
            continue

        result = await test_scanner(module_name, class_name, url)
        results[module_name] = result

        # Status indicator
        status_icon = {
            "OK": "✅" if result["findings"] > 0 else "⚪",
            "TIMEOUT": "⏰",
            "ERROR": "❌",
            "IMPORT_ERROR": "🔧",
        }.get(result["status"], "❓")

        expected_finding = expected.get(module_name, False)
        if expected_finding and result["findings"] == 0:
            status_icon = "⚠️"  # Expected finding but got 0

        print(f"  {status_icon} {module_name}: {result['status']} "
              f"({result['time']:.1f}s, {result['findings']} findings)")

    return results


async def main():
    """Run all lab tests."""
    parser = argparse.ArgumentParser(description="Test PHANTOM scanners against vulnerable labs")
    parser.add_argument("--lab", help="Test specific lab only (e.g., juice-shop)")
    parser.add_argument("--scanner", help="Test specific scanner only (e.g., sqli)")
    args = parser.parse_args()

    print("\n" + "="*60)
    print("PHANTOM Scanner - Comprehensive Lab Testing")
    print(f"Date: {datetime.now().isoformat()}")
    print("="*60)

    # Filter labs if specified
    labs_to_test = LABS
    if args.lab:
        if args.lab in LABS:
            labs_to_test = {args.lab: LABS[args.lab]}
        else:
            print(f"Unknown lab: {args.lab}")
            print(f"Available labs: {', '.join(LABS.keys())}")
            sys.exit(1)

    all_results = {}
    for lab_name, lab_config in labs_to_test.items():
        try:
            results = await test_lab(lab_name, lab_config, args.scanner)
            if results:
                all_results[lab_name] = results
        except Exception as e:
            print(f"  ❌ Lab {lab_name} failed: {e}")

    # Summary
    if all_results:
        print("\n" + "="*60)
        print("SUMMARY")
        print("="*60)

        for lab_name, results in all_results.items():
            total = len(results)
            ok = sum(1 for r in results.values() if r["status"] == "OK")
            with_findings = sum(1 for r in results.values() if r["findings"] > 0)
            timeouts = sum(1 for r in results.values() if r["status"] == "TIMEOUT")
            errors = sum(1 for r in results.values() if r["status"] in ("ERROR", "IMPORT_ERROR"))

            expected = LABS[lab_name].get("expected", {})
            missed = []
            for scanner, should_find in expected.items():
                if should_find and scanner in results and results[scanner]["findings"] == 0:
                    missed.append(scanner)

            print(f"\n{lab_name}:")
            print(f"  OK: {ok}/{total}, With Findings: {with_findings}, "
                  f"Timeouts: {timeouts}, Errors: {errors}")
            if missed:
                print(f"  ⚠️  Missed Expected: {', '.join(missed)}")


if __name__ == "__main__":
    asyncio.run(main())
