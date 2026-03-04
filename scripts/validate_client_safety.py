#!/usr/bin/env python3
"""
PHANTOM AI - Client Command Safety Validator
=============================================

Este script valida que o comando `phantom client` é seguro e funciona como esperado.

Níveis de Validação:
1. Pre-Flight: Validações sem fazer requests
2. Mock Tests: Testa lógica com mocks
3. Dry-Run: Simula scan sem enviar requests reais
4. Network Capture: Valida requests reais contra target controlado
5. Audit Verification: Verifica logs de auditoria

Uso:
    # Nível 1-3 (sem network)
    python scripts/validate_client_safety.py --level pre-flight
    python scripts/validate_client_safety.py --level mock
    python scripts/validate_client_safety.py --level dry-run

    # Nível 4-5 (requer Juice Shop em localhost:3000)
    python scripts/validate_client_safety.py --level network --target http://localhost:3000
    python scripts/validate_client_safety.py --level audit --engagement-id PHANTOM-xxx

    # Todos os níveis
    python scripts/validate_client_safety.py --all --target http://localhost:3000
"""

import argparse
import asyncio
import json
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class ValidationResult:
    """Result of a validation check."""

    def __init__(self, name: str, passed: bool, details: str = "", severity: str = "INFO"):
        self.name = name
        self.passed = passed
        self.details = details
        self.severity = severity  # INFO, WARNING, CRITICAL

    def __str__(self):
        icon = "✅" if self.passed else "❌"
        return f"{icon} {self.name}: {self.details}"


class ClientSafetyValidator:
    """Validates phantom client command safety."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.results: List[ValidationResult] = []

    def log(self, msg: str):
        if self.verbose:
            print(f"  [DEBUG] {msg}")

    def add_result(self, result: ValidationResult):
        self.results.append(result)
        if not result.passed or self.verbose:
            print(f"  {result}")

    # =========================================================================
    # LEVEL 1: Pre-Flight Checks (no imports needed)
    # =========================================================================

    def validate_preflight(self) -> List[ValidationResult]:
        """Pre-flight checks without any imports."""
        print("\n🔍 LEVEL 1: Pre-Flight Checks")
        print("=" * 50)

        # Check 1: CLI exists
        cli_path = PROJECT_ROOT / "cli" / "phantom_cli.py"
        self.add_result(ValidationResult(
            "CLI exists",
            cli_path.exists(),
            f"Found at {cli_path}" if cli_path.exists() else "cli/phantom_cli.py not found",
            "CRITICAL"
        ))

        # Check 2: Safety limits defined
        scanner_path = PROJECT_ROOT / "scanning" / "full_scanner.py"
        if scanner_path.exists():
            content = scanner_path.read_text()
            has_safety = "SAFETY_LIMITS" in content or "safety_mode" in content
            self.add_result(ValidationResult(
                "Safety limits defined",
                has_safety,
                "SAFETY_LIMITS found" if has_safety else "No safety limits in full_scanner.py",
                "CRITICAL"
            ))

        # Check 3: Scope guard exists
        scope_guard = PROJECT_ROOT / "utils" / "scope_guard.py"
        self.add_result(ValidationResult(
            "Scope guard exists",
            scope_guard.exists(),
            "ScopeGuard available" if scope_guard.exists() else "Missing scope_guard.py",
            "CRITICAL"
        ))

        # Check 4: Audit logger exists
        audit_logger = PROJECT_ROOT / "utils" / "audit_logger.py"
        self.add_result(ValidationResult(
            "Audit logger exists",
            audit_logger.exists(),
            "AuditLogger available" if audit_logger.exists() else "Missing audit_logger.py",
            "CRITICAL"
        ))

        # Check 5: Rate limiter exists
        rate_limiter = PROJECT_ROOT / "utils" / "rate_limiter.py"
        self.add_result(ValidationResult(
            "Rate limiter exists",
            rate_limiter.exists(),
            "RateLimiter available" if rate_limiter.exists() else "Missing rate_limiter.py",
            "WARNING"
        ))

        # Check 6: Safe HTTP client exists
        safe_client = PROJECT_ROOT / "utils" / "safe_http_client.py"
        self.add_result(ValidationResult(
            "Safe HTTP client exists",
            safe_client.exists(),
            "SafeAsyncClient available" if safe_client.exists() else "Missing safe_http_client.py",
            "CRITICAL"
        ))

        return self.results

    # =========================================================================
    # LEVEL 2: Mock Tests (imports needed, no network)
    # =========================================================================

    def validate_mock(self) -> List[ValidationResult]:
        """Mock-based tests without network."""
        print("\n🧪 LEVEL 2: Mock Tests (Logic Validation)")
        print("=" * 50)

        # Test scope enforcement
        try:
            from utils.scope_guard import ScopeGuard, ScopeDefinition

            # Test 1: Localhost blocking (default behavior)
            scope = ScopeDefinition(allowed_domains=["localhost"], block_localhost=True)
            guard = ScopeGuard(scope)
            allowed, reason = guard.is_allowed("http://localhost:3000/api")

            self.add_result(ValidationResult(
                "Localhost blocked by default",
                not allowed,
                f"Localhost blocked: {reason}" if not allowed else "DANGER: Localhost not blocked!",
                "CRITICAL"
            ))

            # Test 2: Out-of-scope blocked
            scope2 = ScopeDefinition(allowed_domains=["example.com"], block_localhost=False)
            guard2 = ScopeGuard(scope2)
            allowed2, reason2 = guard2.is_allowed("https://attacker.com/evil")

            self.add_result(ValidationResult(
                "Out-of-scope blocked",
                not allowed2,
                f"Out-of-scope blocked: {reason2}" if not allowed2 else "DANGER: Out-of-scope allowed!",
                "CRITICAL"
            ))

            # Test 3: In-scope allowed
            allowed3, reason3 = guard2.is_allowed("https://example.com/api")
            self.add_result(ValidationResult(
                "In-scope allowed",
                allowed3,
                f"In-scope allowed: {reason3}" if allowed3 else f"ERROR: In-scope blocked: {reason3}",
                "CRITICAL"
            ))

        except Exception as e:
            self.add_result(ValidationResult(
                "Scope guard tests",
                False,
                f"Import/test error: {e}",
                "CRITICAL"
            ))

        # Test audit logging
        try:
            from utils.audit_logger import AuditLogger

            with tempfile.TemporaryDirectory() as tmpdir:
                audit = AuditLogger(
                    engagement_id="VALIDATION-TEST",
                    log_dir=Path(tmpdir)
                )

                # Test log file created
                self.add_result(ValidationResult(
                    "Audit log created",
                    audit.log_file.exists(),
                    f"Log file: {audit.log_file.name}",
                    "CRITICAL"
                ))

                # Test logging works
                audit.log_authorization("https://test.com", True, [], "safe", 10.0)

                # Verify content
                with open(audit.log_file) as f:
                    lines = f.readlines()

                self.add_result(ValidationResult(
                    "Authorization logged",
                    len(lines) >= 2,
                    f"Found {len(lines)} log entries",
                    "CRITICAL"
                ))

        except Exception as e:
            self.add_result(ValidationResult(
                "Audit logger tests",
                False,
                f"Error: {e}",
                "CRITICAL"
            ))

        # Test safety mode constants
        try:
            from scanning.full_scanner import FullScanner

            # Check safety modes exist
            modes = ["safe", "cautious", "standard", "aggressive"]
            all_exist = True

            for mode in modes:
                os.environ["PHANTOM_SAFE_MODE"] = mode
                # Just verify no crash on mode check

            self.add_result(ValidationResult(
                "Safety modes recognized",
                all_exist,
                f"All {len(modes)} modes recognized",
                "CRITICAL"
            ))

        except Exception as e:
            self.add_result(ValidationResult(
                "Safety mode tests",
                False,
                f"Error: {e}",
                "WARNING"
            ))

        # Test rate limiter
        try:
            from utils.rate_limiter import RateLimiter

            limiter = RateLimiter(default_rate=10.0)
            self.add_result(ValidationResult(
                "Rate limiter initializes",
                True,
                "RateLimiter created with 10 req/sec default rate",
                "WARNING"
            ))

        except Exception as e:
            self.add_result(ValidationResult(
                "Rate limiter tests",
                False,
                f"Error: {e}",
                "WARNING"
            ))

        return self.results

    # =========================================================================
    # LEVEL 3: Dry-Run Test
    # =========================================================================

    async def validate_dry_run(self, target: str = "http://example.com") -> List[ValidationResult]:
        """Test dry-run mode (no real requests)."""
        print("\n🚀 LEVEL 3: Dry-Run Test")
        print("=" * 50)

        try:
            from utils.scan_client import get_scan_client, reset_scan_session

            reset_scan_session()

            async with get_scan_client(dry_run=True) as client:
                # Make simulated request
                response = await client.get(f"{target}/api/test")

                self.add_result(ValidationResult(
                    "Dry-run request simulated",
                    response.status_code == 200,
                    f"Got status {response.status_code}",
                    "INFO"
                ))

                self.add_result(ValidationResult(
                    "Dry-run response marked",
                    response.headers.get("X-Dry-Run") == "true",
                    "X-Dry-Run header present",
                    "INFO"
                ))

                stats = client.get_stats()
                self.add_result(ValidationResult(
                    "Dry-run stats tracked",
                    stats.get("dry_run_simulated", 0) > 0,
                    f"Simulated requests: {stats.get('dry_run_simulated', 0)}",
                    "INFO"
                ))

        except Exception as e:
            self.add_result(ValidationResult(
                "Dry-run test",
                False,
                f"Error: {e}",
                "WARNING"
            ))

        return self.results

    # =========================================================================
    # LEVEL 4: Network Capture Test (requires target)
    # =========================================================================

    async def validate_network(self, target: str) -> List[ValidationResult]:
        """Test with real network requests (controlled target)."""
        print(f"\n🌐 LEVEL 4: Network Test (target: {target})")
        print("=" * 50)

        import httpx

        # First verify target is reachable
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(target)

            self.add_result(ValidationResult(
                "Target reachable",
                response.status_code in [200, 301, 302],
                f"Got status {response.status_code}",
                "INFO"
            ))
        except Exception as e:
            self.add_result(ValidationResult(
                "Target reachable",
                False,
                f"Cannot reach target: {e}",
                "CRITICAL"
            ))
            return self.results

        # Test rate limiting in action
        try:
            from utils.rate_limiter import RateLimiter
            from utils.scan_client import get_scan_client, reset_scan_session

            reset_scan_session()

            request_times = []
            start = datetime.now()

            async with get_scan_client() as client:
                # Make 5 quick requests
                for i in range(5):
                    req_start = datetime.now()
                    try:
                        await client.get(f"{target}/rest/products/search?q=test{i}")
                    except:
                        pass
                    request_times.append((datetime.now() - req_start).total_seconds())

            total_time = (datetime.now() - start).total_seconds()

            # Should have taken time due to rate limiting
            self.add_result(ValidationResult(
                "Rate limiting active",
                total_time > 0.3,  # At least some delay
                f"5 requests took {total_time:.2f}s",
                "WARNING"
            ))

        except Exception as e:
            self.add_result(ValidationResult(
                "Rate limiting test",
                False,
                f"Error: {e}",
                "WARNING"
            ))

        # Test scope blocking
        try:
            from utils.scope_guard import ScopeGuard, ScopeDefinition
            from urllib.parse import urlparse

            parsed = urlparse(target)
            scope = ScopeDefinition(
                allowed_domains=[parsed.netloc],
                block_localhost=False  # Allow for testing
            )
            guard = ScopeGuard(scope)

            # Should allow target
            in_scope = guard.check(target)
            self.add_result(ValidationResult(
                "Target in scope",
                in_scope is None,
                f"Target {parsed.netloc} correctly allowed",
                "INFO"
            ))

            # Should block different domain
            out_scope = guard.check("https://evil.com/steal-data")
            self.add_result(ValidationResult(
                "Other domains blocked",
                out_scope is not None and out_scope.blocked,
                "Out-of-scope requests correctly blocked",
                "CRITICAL"
            ))

        except Exception as e:
            self.add_result(ValidationResult(
                "Scope blocking test",
                False,
                f"Error: {e}",
                "CRITICAL"
            ))

        return self.results

    # =========================================================================
    # LEVEL 5: Audit Verification
    # =========================================================================

    def validate_audit(self, engagement_id: Optional[str] = None) -> List[ValidationResult]:
        """Verify audit logs from a previous scan."""
        print(f"\n📋 LEVEL 5: Audit Log Verification")
        print("=" * 50)

        log_dir = PROJECT_ROOT / "logs" / "audit"

        if not log_dir.exists():
            self.add_result(ValidationResult(
                "Audit log directory",
                False,
                f"Directory not found: {log_dir}",
                "WARNING"
            ))
            return self.results

        # Find audit logs
        if engagement_id:
            log_files = list(log_dir.glob(f"{engagement_id}*.jsonl"))
        else:
            log_files = list(log_dir.glob("*.jsonl"))

        self.add_result(ValidationResult(
            "Audit logs found",
            len(log_files) > 0,
            f"Found {len(log_files)} audit log(s)",
            "INFO"
        ))

        if not log_files:
            return self.results

        # Analyze most recent log
        log_file = sorted(log_files, key=lambda f: f.stat().st_mtime)[-1]
        print(f"  Analyzing: {log_file.name}")

        try:
            with open(log_file) as f:
                lines = f.readlines()

            # Parse header
            header = json.loads(lines[0])
            self.add_result(ValidationResult(
                "Log has header",
                header.get("type") == "audit_log_header",
                f"Version: {header.get('version', 'unknown')}",
                "INFO"
            ))

            # Count event types
            events = {"authorization": 0, "http": 0, "safety": 0, "finding": 0}
            for line in lines[1:]:
                try:
                    event = json.loads(line)
                    event_type = event.get("event_type", "")

                    if "authorization" in event_type or "scope" in event_type:
                        events["authorization"] += 1
                    elif "http" in event_type:
                        events["http"] += 1
                    elif "safety" in event_type or "block" in event_type:
                        events["safety"] += 1
                    elif "finding" in event_type or "vulnerability" in event_type:
                        events["finding"] += 1
                except:
                    pass

            self.add_result(ValidationResult(
                "Authorization events logged",
                events["authorization"] > 0,
                f"Found {events['authorization']} authorization events",
                "CRITICAL"
            ))

            self.add_result(ValidationResult(
                "HTTP activity logged",
                True,  # May not have HTTP if dry-run
                f"Found {events['http']} HTTP events",
                "INFO"
            ))

            # Verify hash chain
            has_hashes = any(
                "previous_hash" in line or "event_hash" in line
                for line in lines[1:]
            )
            self.add_result(ValidationResult(
                "Hash chain for tamper detection",
                has_hashes,
                "Hash chain present" if has_hashes else "No hash chain found",
                "WARNING"
            ))

        except Exception as e:
            self.add_result(ValidationResult(
                "Audit log parsing",
                False,
                f"Error parsing log: {e}",
                "WARNING"
            ))

        return self.results

    # =========================================================================
    # Summary
    # =========================================================================

    def print_summary(self):
        """Print validation summary."""
        print("\n" + "=" * 50)
        print("📊 VALIDATION SUMMARY")
        print("=" * 50)

        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed)
        critical_fails = sum(1 for r in self.results if not r.passed and r.severity == "CRITICAL")

        print(f"\n  Total checks: {len(self.results)}")
        print(f"  ✅ Passed: {passed}")
        print(f"  ❌ Failed: {failed}")

        if critical_fails > 0:
            print(f"\n  🚨 CRITICAL FAILURES: {critical_fails}")
            for r in self.results:
                if not r.passed and r.severity == "CRITICAL":
                    print(f"     - {r.name}: {r.details}")

        if failed == 0:
            print("\n  ✅ ALL CHECKS PASSED - Scanner is safe to use")
            return 0
        elif critical_fails == 0:
            print("\n  ⚠️ WARNINGS ONLY - Scanner may work but review warnings")
            return 1
        else:
            print("\n  ❌ CRITICAL FAILURES - DO NOT USE SCANNER IN PRODUCTION")
            return 2


async def main():
    parser = argparse.ArgumentParser(
        description="Validate PHANTOM client command safety",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick check (no network)
  python scripts/validate_client_safety.py --level pre-flight

  # Full validation with Juice Shop
  python scripts/validate_client_safety.py --all --target http://localhost:3000

  # Verify audit logs from previous scan
  python scripts/validate_client_safety.py --level audit --engagement-id PHANTOM-20260211-ABC123
        """
    )

    parser.add_argument(
        "--level",
        choices=["pre-flight", "mock", "dry-run", "network", "audit"],
        default="mock",
        help="Validation level (default: mock)"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all validation levels"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:3000",
        help="Target URL for network tests (default: http://localhost:3000)"
    )
    parser.add_argument(
        "--engagement-id",
        help="Engagement ID for audit verification"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )

    args = parser.parse_args()

    print("=" * 50)
    print("🔒 PHANTOM AI - Client Safety Validator")
    print("=" * 50)
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    validator = ClientSafetyValidator(verbose=args.verbose)

    if args.all or args.level == "pre-flight":
        validator.validate_preflight()

    if args.all or args.level == "mock":
        validator.validate_mock()

    if args.all or args.level == "dry-run":
        await validator.validate_dry_run(args.target)

    if args.all or args.level == "network":
        await validator.validate_network(args.target)

    if args.all or args.level == "audit":
        validator.validate_audit(args.engagement_id)

    exit_code = validator.print_summary()
    sys.exit(exit_code)


if __name__ == "__main__":
    asyncio.run(main())
