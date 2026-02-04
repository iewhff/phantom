"""
Chart generation for reports.
Generates SVG charts for HTML/PDF reports and ASCII charts for terminal.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any


@dataclass
class ChartColors:
    """Color scheme for charts."""
    CRITICAL: str = "#d32f2f"
    HIGH: str = "#f57c00"
    MEDIUM: str = "#fbc02d"
    LOW: str = "#388e3c"
    INFO: str = "#1976d2"
    BACKGROUND: str = "#ffffff"
    TEXT: str = "#333333"
    GRID: str = "#e0e0e0"


class ChartGenerator:
    """
    Generates charts for security reports.

    Chart types:
    - Severity distribution pie chart
    - Vulnerability type bar chart
    - OWASP Top 10 coverage radar chart
    - Timeline visualization
    - Risk score gauge
    """

    def __init__(self, colors: ChartColors | None = None):
        self.colors = colors or ChartColors()

    def severity_pie_chart(
        self,
        by_severity: dict[str, list[dict]],
        width: int = 400,
        height: int = 300,
    ) -> str:
        """Generate SVG pie chart for severity distribution."""
        counts = {sev: len(findings) for sev, findings in by_severity.items()}
        total = sum(counts.values())

        if total == 0:
            return self._empty_chart(width, height, "No findings")

        colors = {
            "CRITICAL": self.colors.CRITICAL,
            "HIGH": self.colors.HIGH,
            "MEDIUM": self.colors.MEDIUM,
            "LOW": self.colors.LOW,
            "INFO": self.colors.INFO,
        }

        cx, cy = width // 2, height // 2 - 20
        radius = min(cx, cy) - 40

        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}">',
            f'<rect width="{width}" height="{height}" fill="{self.colors.BACKGROUND}"/>',
            f'<text x="{width//2}" y="25" text-anchor="middle" font-size="16" font-weight="bold" fill="{self.colors.TEXT}">Findings by Severity</text>',
        ]

        start_angle = 0
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = counts.get(severity, 0)
            if count == 0:
                continue

            angle = (count / total) * 360
            end_angle = start_angle + angle

            # Calculate arc path
            large_arc = 1 if angle > 180 else 0
            start_rad = math.radians(start_angle - 90)
            end_rad = math.radians(end_angle - 90)

            x1 = cx + radius * math.cos(start_rad)
            y1 = cy + radius * math.sin(start_rad)
            x2 = cx + radius * math.cos(end_rad)
            y2 = cy + radius * math.sin(end_rad)

            if angle >= 360:
                # Full circle
                path = f'M {cx} {cy-radius} A {radius} {radius} 0 1 1 {cx-0.001} {cy-radius} Z'
            else:
                path = f'M {cx} {cy} L {x1} {y1} A {radius} {radius} 0 {large_arc} 1 {x2} {y2} Z'

            svg_parts.append(
                f'<path d="{path}" fill="{colors[severity]}" stroke="white" stroke-width="2"/>'
            )

            # Add percentage label
            mid_angle = math.radians((start_angle + end_angle) / 2 - 90)
            label_r = radius * 0.7
            lx = cx + label_r * math.cos(mid_angle)
            ly = cy + label_r * math.sin(mid_angle)
            pct = (count / total) * 100

            if pct >= 5:  # Only show label if segment is large enough
                svg_parts.append(
                    f'<text x="{lx:.1f}" y="{ly:.1f}" text-anchor="middle" '
                    f'font-size="12" fill="white" font-weight="bold">{pct:.0f}%</text>'
                )

            start_angle = end_angle

        # Add legend
        legend_y = height - 30
        legend_x = 20
        for i, (severity, color) in enumerate(colors.items()):
            x = legend_x + (i * 75)
            count = counts.get(severity, 0)
            svg_parts.extend([
                f'<rect x="{x}" y="{legend_y}" width="12" height="12" fill="{color}"/>',
                f'<text x="{x+16}" y="{legend_y+10}" font-size="10" fill="{self.colors.TEXT}">{severity[:1]}: {count}</text>',
            ])

        svg_parts.append('</svg>')
        return '\n'.join(svg_parts)

    def vulnerability_bar_chart(
        self,
        findings: list[dict],
        width: int = 500,
        height: int = 300,
        max_bars: int = 10,
    ) -> str:
        """Generate SVG bar chart for vulnerability types."""
        # Count by type
        type_counts: dict[str, int] = {}
        for f in findings:
            vtype = f.get("type", "Unknown")[:20]
            type_counts[vtype] = type_counts.get(vtype, 0) + 1

        if not type_counts:
            return self._empty_chart(width, height, "No vulnerabilities")

        # Sort by count and limit
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:max_bars]

        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}">',
            f'<rect width="{width}" height="{height}" fill="{self.colors.BACKGROUND}"/>',
            f'<text x="{width//2}" y="25" text-anchor="middle" font-size="16" font-weight="bold" fill="{self.colors.TEXT}">Vulnerability Types</text>',
        ]

        chart_left = 120
        chart_right = width - 20
        chart_top = 50
        chart_bottom = height - 30
        bar_height = (chart_bottom - chart_top) / len(sorted_types) - 5
        max_count = max(c for _, c in sorted_types)

        for i, (vtype, count) in enumerate(sorted_types):
            y = chart_top + i * (bar_height + 5)
            bar_width = ((chart_right - chart_left) * count / max_count) if max_count > 0 else 0

            # Bar
            svg_parts.append(
                f'<rect x="{chart_left}" y="{y}" width="{bar_width:.1f}" height="{bar_height}" '
                f'fill="{self.colors.HIGH}" rx="3"/>'
            )

            # Label
            svg_parts.append(
                f'<text x="{chart_left-5}" y="{y + bar_height/2 + 4}" text-anchor="end" '
                f'font-size="10" fill="{self.colors.TEXT}">{vtype}</text>'
            )

            # Count
            svg_parts.append(
                f'<text x="{chart_left + bar_width + 5}" y="{y + bar_height/2 + 4}" '
                f'font-size="10" fill="{self.colors.TEXT}">{count}</text>'
            )

        svg_parts.append('</svg>')
        return '\n'.join(svg_parts)

    def risk_gauge(
        self,
        risk_score: float,
        width: int = 200,
        height: int = 120,
    ) -> str:
        """Generate SVG gauge for risk score (0-10)."""
        risk_score = max(0, min(10, risk_score))

        cx, cy = width // 2, height - 20
        radius = min(cx, cy) - 10

        # Color based on risk level
        if risk_score >= 8:
            color = self.colors.CRITICAL
        elif risk_score >= 6:
            color = self.colors.HIGH
        elif risk_score >= 4:
            color = self.colors.MEDIUM
        else:
            color = self.colors.LOW

        # Calculate arc
        start_angle = -180
        end_angle = start_angle + (risk_score / 10) * 180

        start_rad = math.radians(start_angle)
        end_rad = math.radians(end_angle)

        x1 = cx + radius * math.cos(start_rad)
        y1 = cy + radius * math.sin(start_rad)
        x2 = cx + radius * math.cos(end_rad)
        y2 = cy + radius * math.sin(end_rad)

        large_arc = 1 if (end_angle - start_angle) > 180 else 0

        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}">',
            f'<rect width="{width}" height="{height}" fill="{self.colors.BACKGROUND}"/>',
            # Background arc
            f'<path d="M {cx-radius} {cy} A {radius} {radius} 0 0 1 {cx+radius} {cy}" '
            f'fill="none" stroke="{self.colors.GRID}" stroke-width="15"/>',
            # Value arc
            f'<path d="M {x1:.1f} {y1:.1f} A {radius} {radius} 0 {large_arc} 1 {x2:.1f} {y2:.1f}" '
            f'fill="none" stroke="{color}" stroke-width="15" stroke-linecap="round"/>',
            # Score text
            f'<text x="{cx}" y="{cy-10}" text-anchor="middle" font-size="24" font-weight="bold" fill="{color}">{risk_score:.1f}</text>',
            f'<text x="{cx}" y="{cy+10}" text-anchor="middle" font-size="10" fill="{self.colors.TEXT}">Risk Score</text>',
            '</svg>',
        ]

        return '\n'.join(svg_parts)

    def owasp_coverage_chart(
        self,
        findings: list[dict],
        width: int = 400,
        height: int = 400,
    ) -> str:
        """Generate radar chart showing OWASP Top 10 coverage."""
        owasp_mapping = {
            "A01": ("Broken Access Control", ["idor", "bac", "auth", "authz"]),
            "A02": ("Cryptographic Failures", ["ssl", "crypto", "tls"]),
            "A03": ("Injection", ["sqli", "xss", "cmdi", "nosql", "ssti", "ldap"]),
            "A04": ("Insecure Design", ["business_logic", "design"]),
            "A05": ("Security Misconfiguration", ["headers", "cors", "config"]),
            "A06": ("Vulnerable Components", ["nuclei", "component", "cve"]),
            "A07": ("Auth Failures", ["auth", "jwt", "mfa", "session"]),
            "A08": ("Data Integrity", ["csrf", "deserialization"]),
            "A09": ("Logging & Monitoring", ["logging", "monitoring"]),
            "A10": ("SSRF", ["ssrf"]),
        }

        # Calculate coverage for each category
        coverage = {}
        for code, (name, keywords) in owasp_mapping.items():
            count = sum(1 for f in findings if any(k in f.get("type", "").lower() for k in keywords))
            coverage[code] = min(100, count * 20)  # Scale 0-100

        cx, cy = width // 2, height // 2
        radius = min(cx, cy) - 60

        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}">',
            f'<rect width="{width}" height="{height}" fill="{self.colors.BACKGROUND}"/>',
            f'<text x="{cx}" y="25" text-anchor="middle" font-size="14" font-weight="bold" fill="{self.colors.TEXT}">OWASP Top 10 Coverage</text>',
        ]

        # Draw grid circles
        for r in [0.25, 0.5, 0.75, 1.0]:
            svg_parts.append(
                f'<circle cx="{cx}" cy="{cy}" r="{radius*r}" fill="none" stroke="{self.colors.GRID}" stroke-width="1"/>'
            )

        # Draw axes and labels
        num_axes = len(owasp_mapping)
        points = []

        for i, (code, (name, _)) in enumerate(owasp_mapping.items()):
            angle = math.radians(i * 360 / num_axes - 90)
            x = cx + radius * math.cos(angle)
            y = cy + radius * math.sin(angle)

            # Axis line
            svg_parts.append(
                f'<line x1="{cx}" y1="{cy}" x2="{x}" y2="{y}" stroke="{self.colors.GRID}" stroke-width="1"/>'
            )

            # Label
            label_x = cx + (radius + 25) * math.cos(angle)
            label_y = cy + (radius + 25) * math.sin(angle)
            anchor = "start" if math.cos(angle) > 0.1 else "end" if math.cos(angle) < -0.1 else "middle"

            svg_parts.append(
                f'<text x="{label_x:.1f}" y="{label_y:.1f}" text-anchor="{anchor}" '
                f'font-size="9" fill="{self.colors.TEXT}">{code}</text>'
            )

            # Calculate point for coverage
            pct = coverage.get(code, 0) / 100
            px = cx + radius * pct * math.cos(angle)
            py = cy + radius * pct * math.sin(angle)
            points.append(f"{px:.1f},{py:.1f}")

        # Draw coverage polygon
        if points:
            svg_parts.append(
                f'<polygon points="{" ".join(points)}" fill="{self.colors.HIGH}" fill-opacity="0.3" '
                f'stroke="{self.colors.HIGH}" stroke-width="2"/>'
            )

        svg_parts.append('</svg>')
        return '\n'.join(svg_parts)

    def _empty_chart(self, width: int, height: int, message: str) -> str:
        """Generate empty chart placeholder."""
        return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}">
            <rect width="{width}" height="{height}" fill="{self.colors.BACKGROUND}"/>
            <text x="{width//2}" y="{height//2}" text-anchor="middle"
                  font-size="14" fill="{self.colors.TEXT}">{message}</text>
        </svg>'''

    def generate_ascii_summary(
        self,
        by_severity: dict[str, list[dict]],
        width: int = 50,
    ) -> str:
        """Generate ASCII chart for terminal output."""
        counts = {sev: len(findings) for sev, findings in by_severity.items()}
        total = sum(counts.values())
        max_count = max(counts.values()) if counts.values() else 1

        lines = [
            "┌" + "─" * (width + 12) + "┐",
            "│" + " Findings by Severity".center(width + 12) + "│",
            "├" + "─" * (width + 12) + "┤",
        ]

        bar_chars = "█▓▒░"
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = counts.get(severity, 0)
            bar_len = int((count / max_count) * width) if max_count > 0 else 0
            bar = "█" * bar_len + " " * (width - bar_len)
            pct = (count / total * 100) if total > 0 else 0
            lines.append(f"│ {severity[:4]:4} │{bar}│ {count:3} ({pct:4.1f}%) │")

        lines.append("└" + "─" * (width + 12) + "┘")
        lines.append(f"  Total: {total} findings")

        return "\n".join(lines)


def integrate_charts_with_report(report_data: dict[str, Any]) -> dict[str, Any]:
    """Add chart SVGs to report data."""
    generator = ChartGenerator()

    report_data["charts"] = {
        "severity_pie": generator.severity_pie_chart(
            report_data.get("findings_by_severity", {})
        ),
        "vuln_types": generator.vulnerability_bar_chart(
            report_data.get("findings", [])
        ),
        "risk_gauge": generator.risk_gauge(
            report_data.get("stats", {}).get("risk_score", 0)
        ),
        "owasp_coverage": generator.owasp_coverage_chart(
            report_data.get("findings", [])
        ),
    }

    return report_data
