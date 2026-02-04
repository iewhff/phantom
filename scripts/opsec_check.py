#!/usr/bin/env python3
"""
OPSEC Check v2.0 - Pre-Pentest Security Verification

Advanced security verification before pentesting:
- IP leak detection
- Tor/Proxy verification
- DNS leak check
- Kill switch test
- Canary system check
- Full OPSEC status

Usage:
    python scripts/opsec_check.py              # Basic check
    python scripts/opsec_check.py --test-tor   # Test Tor connection
    python scripts/opsec_check.py --full       # Full OPSEC verification
    python scripts/opsec_check.py --paranoid   # Maximum security check
"""

import asyncio
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.network_protection import (
    NetworkProtection,
    ProxyConfig,
    ProxyType,
    TorController,
    quick_anonymity_check,
    create_network_protection,
)


class Colors:
    """Terminal colors."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'


def print_banner():
    """Print security check banner."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════════════╗
║                   🔒 OPSEC PRE-FLIGHT CHECK v2.0 🔒                   ║
║              Advanced Security Verification for Pentesting             ║
╚═══════════════════════════════════════════════════════════════════════╝
{Colors.END}
"""
    print(banner)


def print_status(label: str, status: bool, detail: str = ""):
    """Print status line."""
    icon = f"{Colors.GREEN}✓{Colors.END}" if status else f"{Colors.RED}✗{Colors.END}"
    detail_str = f" - {detail}" if detail else ""
    print(f"  {icon} {label}{detail_str}")


async def check_current_ip():
    """Check and display current IP."""
    print(f"\n{Colors.BOLD}📍 Current IP Address:{Colors.END}")
    
    protection = NetworkProtection()
    ip = await protection.check_current_ip()
    
    if ip:
        print(f"  {Colors.YELLOW}Your visible IP: {ip}{Colors.END}")
        print(f"  {Colors.RED}⚠️  This IP will be logged by targets!{Colors.END}")
        return ip
    else:
        print(f"  {Colors.RED}Could not determine IP{Colors.END}")
        return None


async def check_tor_availability():
    """Check if Tor is available."""
    print(f"\n{Colors.BOLD}🧅 Tor Network:{Colors.END}")
    
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection('127.0.0.1', 9050),
            timeout=2.0
        )
        writer.close()
        await writer.wait_closed()
        
        print_status("Tor SOCKS proxy (9050)", True, "Available")
        
        # Check control port
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection('127.0.0.1', 9051),
                timeout=2.0
            )
            writer.close()
            await writer.wait_closed()
            print_status("Tor control port (9051)", True, "Available")
        except Exception:
            print_status("Tor control port (9051)", False, "Not available (optional)")
        
        return True
        
    except Exception:
        print_status("Tor service", False, "Not running")
        print(f"  {Colors.CYAN}Install Tor: sudo apt install tor && sudo systemctl start tor{Colors.END}")
        return False


async def check_proxy_connection(proxy_url: str):
    """Check if a proxy is working."""
    print(f"\n{Colors.BOLD}🔌 Proxy Connection Test:{Colors.END}")
    
    try:
        protection = create_network_protection(use_proxy=True, proxy_url=proxy_url)
        
        # Get original IP first
        protection.proxy_config.enabled = False
        original_ip = await protection.check_current_ip()
        
        # Then get proxied IP
        protection.proxy_config.enabled = True
        proxied_ip = await protection.check_current_ip()
        
        if original_ip and proxied_ip:
            if original_ip != proxied_ip:
                print_status("Proxy working", True, f"IP changed: {original_ip} → {proxied_ip}")
                return True
            else:
                print_status("Proxy working", False, "IP NOT CHANGED - LEAK DETECTED!")
                return False
        else:
            print_status("Proxy connection", False, "Could not verify")
            return False
            
    except Exception as e:
        print_status("Proxy connection", False, str(e))
        return False


async def test_tor_anonymity():
    """Test anonymity through Tor."""
    print(f"\n{Colors.BOLD}🧅 Testing Tor Anonymity:{Colors.END}")
    
    protection = create_network_protection(use_tor=True)
    
    # Get original IP
    protection.proxy_config.enabled = False
    original_ip = await protection.check_current_ip()
    print(f"  Original IP: {original_ip}")
    
    # Get Tor IP
    protection.proxy_config.enabled = True
    tor_ip = await protection.check_current_ip()
    
    if tor_ip:
        print(f"  Tor Exit IP: {Colors.GREEN}{tor_ip}{Colors.END}")
        
        if original_ip != tor_ip:
            print_status("Tor anonymity", True, "IP successfully hidden")
            return True
        else:
            print_status("Tor anonymity", False, "IP NOT HIDDEN - CHECK CONFIG!")
            return False
    else:
        print_status("Tor connection", False, "Could not connect through Tor")
        return False


async def check_advanced_opsec():
    """Run advanced OPSEC checks."""
    print(f"\n{Colors.BOLD}🔐 Advanced OPSEC Checks:{Colors.END}")
    
    try:
        from utils.advanced_opsec import (
            AdvancedOPSEC,
            OPSECConfig,
            ProtectionLevel,
            print_opsec_banner,
        )
        
        protection = create_network_protection(use_tor=True, rotate_ua=True)
        
        config = OPSECConfig(
            level=ProtectionLevel.HIGH,
            kill_switch_enabled=True,
        )
        
        print_opsec_banner(config)
        
        opsec = AdvancedOPSEC(protection, config)
        
        print(f"  Initializing Advanced OPSEC...")
        if await opsec.initialize():
            print_status("OPSEC Initialization", True, "All systems ready")
            
            print(f"\n  Running pre-scan checks...")
            if await opsec.pre_scan_check():
                print_status("Pre-scan Checks", True, "All checks passed")
            else:
                print_status("Pre-scan Checks", False, "Some checks failed")
            
            # Get status
            status = opsec.get_status()
            print(f"\n  {Colors.BOLD}OPSEC Status:{Colors.END}")
            print(f"    Protection Level: {status['protection_level']}")
            print(f"    Kill Switch: {'🔴 ARMED' if status['kill_switch_armed'] else '⚪ Disarmed'}")
            
            await opsec.shutdown()
            return True
        else:
            print_status("OPSEC Initialization", False, "Failed to initialize")
            return False
            
    except ImportError as e:
        print(f"  {Colors.YELLOW}⚠️ Advanced OPSEC not available: {e}{Colors.END}")
        return False
    except Exception as e:
        print(f"  {Colors.RED}❌ Error: {e}{Colors.END}")
        return False


async def check_dns_leaks():
    """Check for DNS leaks."""
    print(f"\n{Colors.BOLD}🌐 DNS Leak Check:{Colors.END}")
    
    protection = create_network_protection(use_tor=True)
    
    if await protection.check_dns_leaks():
        print_status("DNS Leak Check", True, "No leaks detected")
        return True
    else:
        print_status("DNS Leak Check", False, "Potential DNS leak!")
        return False


def print_recommendations(has_tor: bool, original_ip: str):
    """Print security recommendations."""
    print(f"\n{Colors.BOLD}📋 Security Recommendations:{Colors.END}")
    
    print(f"""
  {Colors.YELLOW}For SAFE pentesting, you should:{Colors.END}
  
  1. {Colors.CYAN}Use a VPN{Colors.END} - Basic protection, hides your IP
     Example: ProtonVPN, Mullvad, NordVPN
  
  2. {Colors.CYAN}Use Tor{Colors.END} - Maximum anonymity (if available)
     Enable in config: network_protection.tor.enabled: true
  
  3. {Colors.CYAN}Enable Kill Switch{Colors.END} - Stops traffic if protection fails
     network_protection.kill_switch.enabled: true
""")
    
    if has_tor:
        print(f"""  4. {Colors.GREEN}Tor is available!{Colors.END} For full test:
     python scripts/opsec_check.py --full
""")
    else:
        print(f"""  4. {Colors.RED}Install Tor{Colors.END}:
     sudo apt install tor
     sudo systemctl start tor
""")
    
    print(f"""  5. {Colors.CYAN}Use VPS/Cloud{Colors.END} - Run scans from a separate server
     
  6. {Colors.CYAN}Protection Levels{Colors.END} in config/settings.yaml:
     network_protection:
       level: "paranoid"  # minimal, standard, high, paranoid
       kill_switch:
         enabled: true
       timing:
         enabled: true
         min_delay_ms: 500
         max_delay_ms: 3000

  {Colors.RED}⚠️  WARNING:{Colors.END} Your current IP ({original_ip}) is VISIBLE to targets!
  {Colors.RED}    Logs, firewalls, and WAFs will record your IP address.{Colors.END}
""")


async def full_check():
    """Run full OPSEC verification."""
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}═══════════════════════════════════════════════════════════════════{Colors.END}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}                    FULL OPSEC VERIFICATION                         {Colors.END}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}═══════════════════════════════════════════════════════════════════{Colors.END}")
    
    results = {
        "ip_check": False,
        "tor_available": False,
        "tor_working": False,
        "dns_check": False,
        "advanced_opsec": False,
    }
    
    # 1. Current IP
    original_ip = await check_current_ip()
    results["ip_check"] = original_ip is not None
    
    # 2. Tor availability
    results["tor_available"] = await check_tor_availability()
    
    # 3. Tor anonymity test
    if results["tor_available"]:
        results["tor_working"] = await test_tor_anonymity()
    
    # 4. DNS leak check
    results["dns_check"] = await check_dns_leaks()
    
    # 5. Advanced OPSEC
    results["advanced_opsec"] = await check_advanced_opsec()
    
    # Summary
    print(f"\n{Colors.BOLD}═══════════════════════════════════════════════════════════════════{Colors.END}")
    print(f"{Colors.BOLD}                         VERIFICATION SUMMARY                        {Colors.END}")
    print(f"{Colors.BOLD}═══════════════════════════════════════════════════════════════════{Colors.END}")
    
    passed = sum(results.values())
    total = len(results)
    
    for check, result in results.items():
        icon = f"{Colors.GREEN}✅{Colors.END}" if result else f"{Colors.RED}❌{Colors.END}"
        print(f"  {icon} {check.replace('_', ' ').title()}")
    
    print(f"\n  {Colors.BOLD}Result: {passed}/{total} checks passed{Colors.END}")
    
    if passed == total:
        print(f"\n  {Colors.GREEN}🔒 FULL OPSEC PROTECTION VERIFIED{Colors.END}")
        print(f"  {Colors.GREEN}   You are ready for anonymous pentesting!{Colors.END}")
    elif passed >= 3:
        print(f"\n  {Colors.YELLOW}⚠️ PARTIAL PROTECTION{Colors.END}")
        print(f"  {Colors.YELLOW}   Some checks failed - review before scanning{Colors.END}")
    else:
        print(f"\n  {Colors.RED}❌ INSUFFICIENT PROTECTION{Colors.END}")
        print(f"  {Colors.RED}   Do NOT run scans with current configuration{Colors.END}")
    
    return passed == total


async def main():
    """Main OPSEC check routine."""
    print_banner()
    
    # Check arguments
    test_tor = "--test-tor" in sys.argv
    test_proxy = "--proxy" in sys.argv
    full_test = "--full" in sys.argv
    paranoid_test = "--paranoid" in sys.argv
    proxy_url = None
    
    if test_proxy:
        idx = sys.argv.index("--proxy")
        if idx + 1 < len(sys.argv):
            proxy_url = sys.argv[idx + 1]
    
    # Full verification
    if full_test or paranoid_test:
        await full_check()
        return
    
    # Run basic checks
    print(f"{Colors.BOLD}Running security checks...{Colors.END}")
    
    # Current IP
    original_ip = await check_current_ip()
    
    # Tor availability
    has_tor = await check_tor_availability()
    
    # Test Tor if requested
    if test_tor and has_tor:
        await test_tor_anonymity()
    
    # Test proxy if provided
    if test_proxy and proxy_url:
        await check_proxy_connection(proxy_url)
    
    # Recommendations
    if original_ip:
        print_recommendations(has_tor, original_ip)
    
    # Summary
    print(f"\n{Colors.BOLD}═══════════════════════════════════════════════════════════════════{Colors.END}")
    
    if has_tor:
        print(f"{Colors.GREEN}✅ Tor is available - you can run scans anonymously{Colors.END}")
        print(f"   Run full verification: python scripts/opsec_check.py --full")
    else:
        print(f"{Colors.YELLOW}⚠️ No anonymization configured - proceed with caution{Colors.END}")
    
    print(f"\n{Colors.CYAN}Usage:{Colors.END}")
    print(f"  python scripts/opsec_check.py              # Basic check")
    print(f"  python scripts/opsec_check.py --test-tor   # Test Tor connection")
    print(f"  python scripts/opsec_check.py --full       # Full OPSEC verification")
    print(f"  python scripts/opsec_check.py --proxy socks5://127.0.0.1:1080  # Test proxy")
    print()


if __name__ == "__main__":
    asyncio.run(main())
