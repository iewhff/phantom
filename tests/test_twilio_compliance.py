#!/usr/bin/env python3
"""
Twilio Bug Bounty Compliance Test Suite
=======================================

This script verifies that all bug bounty rules are being enforced:
1. X-Bug-Bounty header is included in ALL requests
2. Private IPs are blocked (10.x, 172.16.x, 192.168.x)
3. Cloud metadata IPs are blocked (169.254.169.254)
4. Kill switch works correctly
5. Rate limiting is enforced
6. DoS protection is active
7. Scope enforcement works

Author: canigetrichpls
Target: Twilio HackerOne Bug Bounty
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx

from utils.http_client import (
    get_http_client,
    get_http_client_kwargs,
    create_protected_client,
    set_required_headers,
    get_required_headers,
    load_bug_bounty_preset,
    get_available_presets,
    activate_kill_switch,
    deactivate_kill_switch,
    is_kill_switch_active,
    print_protection_banner,
    KillSwitchActive,
)
from utils.scope_guard import ScopeGuard, ScopeMode


class ComplianceTest:
    """Test suite for Twilio bug bounty compliance."""
    
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.warnings = 0
        
    def test(self, name: str, condition: bool, critical: bool = False) -> None:
        """Run a single test."""
        if condition:
            print(f"  ✅ PASS: {name}")
            self.passed += 1
        else:
            if critical:
                print(f"  ❌ FAIL (CRITICAL): {name}")
            else:
                print(f"  ❌ FAIL: {name}")
            self.failed += 1
            
    def warn(self, name: str, message: str) -> None:
        """Issue a warning."""
        print(f"  ⚠️  WARN: {name}: {message}")
        self.warnings += 1
        
    def summary(self) -> bool:
        """Print test summary and return success status."""
        total = self.passed + self.failed
        print(f"\n{'=' * 60}")
        print(f"COMPLIANCE TEST SUMMARY")
        print(f"{'=' * 60}")
        print(f"  Passed:   {self.passed}/{total}")
        print(f"  Failed:   {self.failed}/{total}")
        print(f"  Warnings: {self.warnings}")
        print(f"{'=' * 60}")
        
        if self.failed == 0:
            print("✅ ALL COMPLIANCE TESTS PASSED - Safe to scan Twilio!")
            return True
        else:
            print("❌ COMPLIANCE TESTS FAILED - Do NOT scan until fixed!")
            return False


def test_preset_loading(tests: ComplianceTest) -> None:
    """Test 1: Bug bounty preset loading."""
    print("\n" + "=" * 60)
    print("TEST 1: Bug Bounty Preset Loading")
    print("=" * 60)
    
    # Check available presets
    presets = get_available_presets()
    tests.test("Presets available", len(presets) > 0)
    tests.test("Twilio preset exists", "twilio" in presets, critical=True)
    
    # Load Twilio preset
    result = load_bug_bounty_preset("twilio")
    tests.test("Twilio preset loaded successfully", result, critical=True)
    
    # Check required headers
    headers = get_required_headers()
    tests.test("Required headers set", len(headers) > 0, critical=True)
    tests.test("X-Bug-Bounty header present", "X-Bug-Bounty" in headers, critical=True)
    
    if "X-Bug-Bounty" in headers:
        value = headers["X-Bug-Bounty"]
        tests.test("X-Bug-Bounty has correct value", value == "canigetrichpls-twilio", critical=True)
        print(f"    → Header value: {value}")


def test_headers_in_requests(tests: ComplianceTest) -> None:
    """Test 2: Headers included in HTTP client."""
    print("\n" + "=" * 60)
    print("TEST 2: Headers Included in HTTP Requests")
    print("=" * 60)
    
    # Ensure preset is loaded
    load_bug_bounty_preset("twilio")
    
    # Get HTTP client kwargs
    kwargs = get_http_client_kwargs()
    
    tests.test("Headers in kwargs", "headers" in kwargs)
    
    if "headers" in kwargs:
        headers = kwargs["headers"]
        tests.test("X-Bug-Bounty in request headers", "X-Bug-Bounty" in headers, critical=True)
        
        if "X-Bug-Bounty" in headers:
            print(f"    → Request will include: X-Bug-Bounty: {headers['X-Bug-Bounty']}")


def test_scope_guard_private_ips(tests: ComplianceTest) -> None:
    """Test 3: Scope guard blocks private IPs."""
    print("\n" + "=" * 60)
    print("TEST 3: Scope Guard - Private IP Blocking")
    print("=" * 60)
    
    guard = ScopeGuard(mode=ScopeMode.STRICT)
    
    # Private IPs that MUST be blocked
    private_ips = [
        "http://10.0.0.1",
        "http://10.255.255.255",
        "http://172.16.0.1",
        "http://172.31.255.255",
        "http://192.168.0.1",
        "http://192.168.255.255",
        "http://127.0.0.1",
        "http://localhost",
    ]
    
    for ip in private_ips:
        is_allowed, _ = guard.is_allowed(ip)
        tests.test(f"Blocks {ip}", not is_allowed, critical=True)


def test_scope_guard_cloud_metadata(tests: ComplianceTest) -> None:
    """Test 4: Scope guard blocks cloud metadata."""
    print("\n" + "=" * 60)
    print("TEST 4: Scope Guard - Cloud Metadata Blocking")
    print("=" * 60)
    
    guard = ScopeGuard(mode=ScopeMode.STRICT)
    
    # Cloud metadata endpoints that MUST be blocked
    cloud_metadata = [
        "http://169.254.169.254",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://100.100.100.200",  # Alibaba
        "http://metadata.google.internal",
        "http://metadata.google.internal/computeMetadata/v1/",
    ]
    
    for url in cloud_metadata:
        is_allowed, reason = guard.is_allowed(url)
        tests.test(f"Blocks {url}", not is_allowed, critical=True)
        if not is_allowed:
            print(f"    → Blocked: {reason}")


def test_kill_switch(tests: ComplianceTest) -> None:
    """Test 5: Kill switch functionality."""
    print("\n" + "=" * 60)
    print("TEST 5: Kill Switch Functionality")
    print("=" * 60)
    
    # Make sure it's off first
    deactivate_kill_switch()
    tests.test("Kill switch initially off", not is_kill_switch_active())
    
    # Activate
    activate_kill_switch("Compliance test")
    tests.test("Kill switch can be activated", is_kill_switch_active())
    
    # Try to get HTTP client - should raise
    try:
        kwargs = get_http_client_kwargs()
        tests.test("Kill switch blocks HTTP client", False, critical=True)
    except KillSwitchActive:
        tests.test("Kill switch blocks HTTP client", True, critical=True)
    
    # Deactivate
    deactivate_kill_switch()
    tests.test("Kill switch can be deactivated", not is_kill_switch_active())


def test_rate_limiting_config(tests: ComplianceTest) -> None:
    """Test 6: Rate limiting configuration."""
    print("\n" + "=" * 60)
    print("TEST 6: Rate Limiting Configuration")
    print("=" * 60)
    
    import yaml
    
    config_path = Path(__file__).parent.parent / "config" / "settings.yaml"
    
    if config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f)
        
        bug_bounty = config.get("bug_bounty", {})
        rate_limits = bug_bounty.get("rate_limits", {})
        
        # Check global rate limit
        global_limit = rate_limits.get("requests_per_second", 10)
        tests.test("Global rate limit <= 2 req/sec", global_limit <= 2)
        print(f"    → Global rate limit: {global_limit} req/sec")
        
        # Check Twilio preset rate limit
        presets = bug_bounty.get("presets", {})
        twilio = presets.get("twilio", {})
        twilio_rate = twilio.get("rate_limit", 10)
        tests.test("Twilio rate limit <= 2 req/sec", twilio_rate <= 2)
        print(f"    → Twilio rate limit: {twilio_rate} req/sec")
    else:
        tests.warn("Config file", "settings.yaml not found")


def test_dos_protection(tests: ComplianceTest) -> None:
    """Test 7: DoS protection is enabled."""
    print("\n" + "=" * 60)
    print("TEST 7: DoS Protection Configuration")
    print("=" * 60)
    
    import yaml
    
    config_path = Path(__file__).parent.parent / "config" / "settings.yaml"
    
    if config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f)
        
        bug_bounty = config.get("bug_bounty", {})
        dos_protection = bug_bounty.get("dos_protection", {})
        
        tests.test("DoS protection enabled", dos_protection.get("enabled", False), critical=True)
        tests.test("Max concurrent requests limited", dos_protection.get("max_concurrent", 100) <= 10)
        tests.test("Max requests per minute limited", dos_protection.get("max_requests_per_minute", 1000) <= 100)
        
        print(f"    → Max concurrent: {dos_protection.get('max_concurrent', 'N/A')}")
        print(f"    → Max req/min: {dos_protection.get('max_requests_per_minute', 'N/A')}")
    else:
        tests.warn("Config file", "settings.yaml not found")


def test_ssrf_protection(tests: ComplianceTest) -> None:
    """Test 8: SSRF protection configuration."""
    print("\n" + "=" * 60)
    print("TEST 8: SSRF Protection Configuration")
    print("=" * 60)
    
    import yaml
    
    config_path = Path(__file__).parent.parent / "config" / "settings.yaml"
    
    if config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f)
        
        bug_bounty = config.get("bug_bounty", {})
        ssrf = bug_bounty.get("ssrf_protection", {})
        
        tests.test("Block private IPs enabled", ssrf.get("block_private_ips", False), critical=True)
        tests.test("Block cloud metadata enabled", ssrf.get("block_cloud_metadata", False), critical=True)
        tests.test("Block localhost enabled", ssrf.get("block_localhost", False), critical=True)
        
        # Check excluded IPs list
        excluded = ssrf.get("excluded_ips", [])
        has_private = any("10." in ip or "172.16" in ip or "192.168" in ip for ip in excluded)
        tests.test("Private IPs in exclusion list", has_private)
        
        print(f"    → Excluded IPs: {len(excluded)} entries")
    else:
        tests.warn("Config file", "settings.yaml not found")


def test_brute_force_protection(tests: ComplianceTest) -> None:
    """Test 9: Brute force protection."""
    print("\n" + "=" * 60)
    print("TEST 9: Brute Force Protection")
    print("=" * 60)
    
    import yaml
    
    config_path = Path(__file__).parent.parent / "config" / "settings.yaml"
    
    if config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f)
        
        bug_bounty = config.get("bug_bounty", {})
        brute = bug_bounty.get("brute_force", {})
        
        tests.test("Brute force disabled", not brute.get("enabled", True))
        tests.test("Max auth attempts limited", brute.get("max_auth_attempts", 100) <= 10)
        
        print(f"    → Max auth attempts: {brute.get('max_auth_attempts', 'N/A')}")
    else:
        tests.warn("Config file", "settings.yaml not found")


async def test_real_request_headers(tests: ComplianceTest) -> None:
    """Test 10: Real request includes required headers."""
    print("\n" + "=" * 60)
    print("TEST 10: Real Request Header Verification (httpbin.org)")
    print("=" * 60)
    
    # Load preset
    load_bug_bounty_preset("twilio")
    
    try:
        async with get_http_client() as client:
            # httpbin.org returns the headers we sent
            response = await client.get("https://httpbin.org/headers", timeout=10.0)
            
            if response.status_code == 200:
                data = response.json()
                headers = data.get("headers", {})
                
                # Check for X-Bug-Bounty (httpbin returns headers with different case)
                header_found = False
                header_value = None
                for key, value in headers.items():
                    if key.lower() == "x-bug-bounty":
                        header_found = True
                        header_value = value
                        break
                
                tests.test("X-Bug-Bounty header sent in request", header_found, critical=True)
                if header_found:
                    tests.test("Header value correct", header_value == "canigetrichpls-twilio", critical=True)
                    print(f"    → Received by server: {header_value}")
            else:
                tests.warn("httpbin.org", f"Returned status {response.status_code}")
                
    except Exception as e:
        tests.warn("httpbin.org request", str(e))


def main():
    """Run all compliance tests."""
    print("""
╔════════════════════════════════════════════════════════════════╗
║  🔒 TWILIO BUG BOUNTY COMPLIANCE TEST SUITE                    ║
║                                                                 ║
║  Verifying all rules are enforced before scanning              ║
║  Target: Twilio HackerOne Bug Bounty                           ║
║  User: canigetrichpls                                          ║
╚════════════════════════════════════════════════════════════════╝
""")
    
    tests = ComplianceTest()
    
    # Run all tests
    test_preset_loading(tests)
    test_headers_in_requests(tests)
    test_scope_guard_private_ips(tests)
    test_scope_guard_cloud_metadata(tests)
    test_kill_switch(tests)
    test_rate_limiting_config(tests)
    test_dos_protection(tests)
    test_ssrf_protection(tests)
    test_brute_force_protection(tests)
    
    # Run async test
    print("\n" + "=" * 60)
    print("Running async tests...")
    print("=" * 60)
    asyncio.run(test_real_request_headers(tests))
    
    # Print banner
    print("\n" + "=" * 60)
    print("NETWORK PROTECTION STATUS")
    print("=" * 60)
    load_bug_bounty_preset("twilio")
    print_protection_banner()
    
    # Summary
    success = tests.summary()
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
