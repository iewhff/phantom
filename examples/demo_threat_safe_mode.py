#!/usr/bin/env python3
"""
Example: Threat Modeling and Safe Mode Usage

Demonstrates:
1. Automatic STRIDE threat analysis
2. Abuse case generation per endpoint
3. Safe/Legal mode for non-destructive testing
4. Evidence collection without exploitation
"""

import asyncio
import json
from pathlib import Path

# Threat Modeling imports
from threat_modeling import (
    STRIDECategory,
    STRIDEAnalyzer,
    ThreatModeler,
    AbuseCaseGenerator,
)

# Safe Mode imports
from safe_mode import (
    SafetyLevel,
    SafeScanner,
    EvidenceCollector,
    SafePayloadGenerator,
    PayloadCategory,
)


def demo_stride_analysis():
    """Demonstrate STRIDE threat analysis."""
    print("\n" + "="*60)
    print("🎯 STRIDE THREAT ANALYSIS DEMO")
    print("="*60)
    
    analyzer = STRIDEAnalyzer()
    
    # Analyze different endpoint types
    endpoints = [
        ("POST", "/api/auth/login", ["username", "password"]),
        ("POST", "/api/payment/checkout", ["amount", "card_number", "cvv"]),
        ("GET", "/api/users/{id}/profile", ["id"]),
        ("POST", "/api/admin/users/delete", ["user_id"]),
        ("POST", "/api/files/upload", ["file", "filename"]),
    ]
    
    for method, path, params in endpoints:
        print(f"\n📍 Endpoint: {method} {path}")
        print("-" * 50)
        
        threats = analyzer.analyze_endpoint(method, path, params)
        
        # Show threats by STRIDE category
        for category in STRIDECategory:
            cat_threats = [t for t in threats if t.category == category]
            if cat_threats:
                print(f"\n  {category.value}:")
                for threat in cat_threats[:2]:  # Show first 2
                    print(f"    • {threat.name}")
                    print(f"      Risk: {threat.likelihood * threat.impact:.1f}")


def demo_abuse_case_generation():
    """Demonstrate abuse case generation."""
    print("\n" + "="*60)
    print("⚔️ ABUSE CASE GENERATION DEMO")
    print("="*60)
    
    generator = AbuseCaseGenerator()
    
    # Generate abuse cases for payment endpoint
    analysis = generator.analyze_endpoint(
        method="POST",
        path="/api/payment/process",
        parameters=["amount", "product_id", "coupon_code", "user_id"],
    )
    
    print(f"\n📊 Endpoint Analysis:")
    print(f"   Risk Score: {analysis.risk_score}/100")
    print(f"   Attack Surface: {analysis.attack_surface}")
    
    print(f"\n🎯 Generated Abuse Cases: {len(analysis.abuse_cases)}")
    for i, case in enumerate(analysis.abuse_cases[:5], 1):
        print(f"\n   {i}. {case.endpoint}")
        print(f"      Method: {case.method}")
        print(f"      STRIDE: {[c.value for c in case.stride_categories]}")
        print(f"      Business Impact: {case.business_impact[:60]}...")
        if case.test_payload:
            print(f"      Test Payload: {case.test_payload[:50]}...")


def demo_threat_model():
    """Demonstrate complete threat model generation."""
    print("\n" + "="*60)
    print("📋 THREAT MODEL GENERATION DEMO")
    print("="*60)
    
    modeler = ThreatModeler()
    
    # Create threat model for an application
    endpoints = [
        {"method": "POST", "path": "/login", "params": ["username", "password"]},
        {"method": "GET", "path": "/api/users/{id}", "params": ["id"]},
        {"method": "POST", "path": "/api/payment", "params": ["amount", "card"]},
        {"method": "POST", "path": "/admin/settings", "params": ["config"]},
    ]
    
    threat_model = modeler.create_threat_model(endpoints)
    
    print(f"\n📊 Threat Model Summary:")
    print(f"   Components: {len(threat_model.components)}")
    print(f"   Data Flows: {len(threat_model.data_flows)}")
    print(f"   Trust Boundaries: {len(threat_model.trust_boundaries)}")
    print(f"   Threats Identified: {len(threat_model.threats)}")
    print(f"   Abuse Cases: {len(threat_model.abuse_cases)}")
    
    print(f"\n🔒 Trust Boundaries:")
    for boundary in threat_model.trust_boundaries:
        print(f"   • {boundary.name} (Level {boundary.trust_level})")
        print(f"     Components: {boundary.components[:3]}...")
    
    print(f"\n💡 Top Recommendations:")
    for rec in threat_model.recommendations[:5]:
        print(f"   • {rec}")


def demo_safe_scanner():
    """Demonstrate safe/legal mode scanning."""
    print("\n" + "="*60)
    print("🛡️ SAFE MODE SCANNER DEMO")
    print("="*60)
    
    # Initialize scanner in SAFE mode (for banks/hospitals)
    scanner = SafeScanner(safety_level=SafetyLevel.SAFE)
    
    print(f"\n🔒 Safety Level: {scanner.safety_level.value}")
    print(f"   Rate Limit: {scanner.RATE_LIMITS[scanner.safety_level]} req/min")
    print(f"   Request Delay: {scanner.SAFE_DELAYS[scanner.safety_level]}s")
    
    # Test which operations are blocked
    print("\n📋 Operation Checks:")
    operations = [
        ("GET /api/users", True),
        ("DELETE /api/users/1", False),
        ("POST /api/login", True),
        ("'; DROP TABLE users; --", False),
        ("SELECT * FROM users", True),
        ("rm -rf /", False),
    ]
    
    for op, expected in operations:
        allowed = scanner.is_operation_allowed(op)
        status = "✅ Allowed" if allowed else "❌ Blocked"
        print(f"   {op[:30]:30s} → {status}")
    
    # Show safe SQL conversion
    print("\n🔄 SQL Payload Conversions:")
    dangerous_sqls = [
        "'; DROP TABLE users; --",
        "DELETE FROM accounts WHERE 1=1",
        "INSERT INTO admin VALUES('hacker', 'pass')",
    ]
    
    for sql in dangerous_sqls:
        safe = scanner.get_safe_sql_payload(sql)
        print(f"   Dangerous: {sql}")
        print(f"   Safe:      {safe}")
        print()


def demo_safe_payloads():
    """Demonstrate safe payload generation."""
    print("\n" + "="*60)
    print("💉 SAFE PAYLOAD GENERATOR DEMO")
    print("="*60)
    
    generator = SafePayloadGenerator()
    
    summary = generator.get_payload_summary()
    print(f"\n📊 Payload Summary:")
    print(f"   Total Safe Payloads: {summary['total_payloads']}")
    
    for category, info in summary['categories'].items():
        print(f"   • {category}: {info['count']} payloads")
    
    # Show examples from each category
    print("\n📝 Safe Payload Examples:")
    
    categories_to_show = [
        PayloadCategory.SQL_INJECTION,
        PayloadCategory.XSS,
        PayloadCategory.COMMAND_INJECTION,
        PayloadCategory.XXE,
    ]
    
    for cat in categories_to_show:
        payload = generator.get_safe_payload(cat)
        if payload:
            print(f"\n   {cat.value.upper()}:")
            print(f"   ❌ Dangerous: {payload.dangerous_payload[:50]}...")
            print(f"   ✅ Safe:      {payload.safe_payload[:50]}...")
            print(f"   📋 Evidence:  {payload.evidence_markers[:2]}")


def demo_evidence_collector():
    """Demonstrate evidence collection."""
    print("\n" + "="*60)
    print("🔍 EVIDENCE COLLECTOR DEMO")
    print("="*60)
    
    collector = EvidenceCollector()
    
    print(f"\n📋 Evidence Types Supported:")
    for etype in list(collector.ERROR_PATTERNS.keys()):
        patterns = collector.ERROR_PATTERNS[etype]
        print(f"   • {etype}: {len(patterns)} detection patterns")
    
    print(f"\n📋 Information Disclosure Detection:")
    for category, patterns in collector.INFO_DISCLOSURE_PATTERNS.items():
        print(f"   • {category}: {len(patterns)} patterns")
    
    # Simulate timing analysis
    print("\n⏱️ Timing Analysis Example:")
    evidence = collector.analyze_timing(
        baseline_time=0.5,
        test_time=5.8,
        test_type="sqli",
        threshold=5.0,
    )
    
    if evidence:
        print(f"   Type: {evidence.evidence_type.value}")
        print(f"   Strength: {evidence.strength.value}")
        print(f"   Description: {evidence.description}")
        print(f"   Indicators: {evidence.indicators}")


def demo_compliance_report():
    """Demonstrate compliance report generation."""
    print("\n" + "="*60)
    print("📄 COMPLIANCE REPORT DEMO")
    print("="*60)
    
    scanner = SafeScanner(safety_level=SafetyLevel.SAFE)
    
    # Simulate some operations
    scanner.is_operation_allowed("GET /api/users")
    scanner.is_operation_allowed("DELETE /api/users")  # Blocked
    scanner.is_operation_allowed("'; DROP TABLE; --")  # Blocked
    
    report = scanner.get_compliance_report()
    
    print("\n📋 Compliance Report Preview:")
    print(json.dumps({
        "report_type": report["report_type"],
        "safety_level": report["safety_level"],
        "compliance_notes": report["compliance_notes"],
        "statistics": report["statistics"],
    }, indent=2))


def main():
    """Run all demonstrations."""
    print("\n" + "="*60)
    print("🚀 AI PENTEST FRAMEWORK - NEW FEATURES DEMO")
    print("="*60)
    print("\nThis demo showcases:")
    print("1. 🎯 Threat Modeling Automático (STRIDE)")
    print("2. ⚔️ Abuse Case Generation")
    print("3. 🛡️ Safe/Legal Mode for Critical Infrastructure")
    print("4. 🔍 Evidence-Only PoCs")
    
    # Run demos
    demo_stride_analysis()
    demo_abuse_case_generation()
    demo_threat_model()
    demo_safe_scanner()
    demo_safe_payloads()
    demo_evidence_collector()
    demo_compliance_report()
    
    print("\n" + "="*60)
    print("✅ DEMO COMPLETE")
    print("="*60)
    print("\nNew modules implemented:")
    print("• threat_modeling/ - STRIDE analysis, abuse cases, DFDs")
    print("• safe_mode/ - Non-destructive testing for banks/hospitals")
    print("\nTotal: 47 modules (39 scanners + 4 analysis + 3 threat + 3 safe)")


if __name__ == "__main__":
    main()
