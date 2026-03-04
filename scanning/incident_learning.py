"""
PHANTOM AI - Incident-Based Learning Engine

The "next leap" in scanner intelligence: learning from REAL outcomes.

Current feedback_learning.py answers: "Was this a TP or FP?"
This module answers: "Did this actually get exploited in production?"

Three learning signals:
1. INCIDENT DATA — Real breaches, CVEs, disclosed chains
2. BOUNTY OUTCOMES — Was the report paid? How much? Rejected? Duplicate?
3. CHAIN SUCCESS — Which attack chains are actually seen in real incidents?

The goal: adjust chain probabilities, severity, and priority based on
what ACTUALLY happens, not just what COULD happen.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


# Storage paths
INCIDENT_DIR = Path.home() / ".phantom" / "incidents"
INCIDENT_FILE = INCIDENT_DIR / "real_incidents.jsonl"
BOUNTY_FILE = INCIDENT_DIR / "bounty_outcomes.jsonl"
CHAIN_STATS_FILE = INCIDENT_DIR / "chain_statistics.json"
LEARNING_STATE_FILE = INCIDENT_DIR / "incident_learning_state.json"


# =============================================================================
# ENUMS AND DATA CLASSES
# =============================================================================


class IncidentSource(Enum):
    """Source of incident data."""
    MANUAL = "manual"           # User-reported
    CVE_DATABASE = "cve"        # From CVE/NVD
    BREACH_REPORT = "breach"    # Public breach disclosure
    HACKERONE = "hackerone"     # HackerOne disclosed reports
    BUGCROWD = "bugcrowd"       # Bugcrowd disclosed reports
    CTI_FEED = "cti"            # Threat intelligence feed
    INTERNAL = "internal"       # Internal incident response


class BountyOutcome(Enum):
    """Outcome of a bug bounty report."""
    PAID = "paid"                  # Report paid out
    DUPLICATE = "duplicate"        # Duplicate of existing report
    INFORMATIVE = "informative"    # Marked informative, no payout
    NOT_APPLICABLE = "na"          # Out of scope / not applicable
    REJECTED = "rejected"          # Rejected as invalid
    PENDING = "pending"            # Still under review
    TRIAGED = "triaged"            # Accepted, awaiting payout


class ChainType(Enum):
    """Types of attack chains."""
    SQLI_TO_RCE = "sqli_to_rce"
    SQLI_TO_DATA_THEFT = "sqli_to_data"
    SQLI_TO_ADMIN = "sqli_to_admin"
    XSS_TO_ATO = "xss_to_ato"
    XSS_TO_DATA_THEFT = "xss_to_data"
    CORS_TO_DATA_THEFT = "cors_to_data"
    SSRF_TO_INTERNAL = "ssrf_to_internal"
    SSRF_TO_RCE = "ssrf_to_rce"
    IDOR_TO_DATA = "idor_to_data"
    IDOR_TO_PRIVESC = "idor_to_privesc"
    AUTH_BYPASS_TO_ADMIN = "auth_to_admin"
    SESSION_TO_ATO = "session_to_ato"
    BUSINESS_LOGIC_FRAUD = "business_fraud"
    CHAIN_UNKNOWN = "unknown"


@dataclass
class RealIncident:
    """A real-world security incident."""
    incident_id: str
    source: str                    # IncidentSource value
    date_occurred: str             # ISO format
    date_reported: str

    # What happened
    vulnerability_types: list[str]
    attack_chain: str              # ChainType value
    attack_description: str

    # Impact
    impact_type: str               # data_theft, rce, ato, financial, etc.
    records_affected: int = 0
    financial_impact_usd: float = 0.0

    # Target characteristics
    target_industry: str = ""      # e-commerce, fintech, saas, etc.
    target_stack: str = ""         # Node.js/Express, Java/Spring, etc.

    # For matching
    endpoint_patterns: list[str] = field(default_factory=list)
    payload_patterns: list[str] = field(default_factory=list)

    # Metadata
    reference_urls: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "RealIncident":
        return cls(**data)


@dataclass
class BountyReport:
    """A bug bounty report outcome."""
    # Required fields (no defaults) must come first
    report_id: str
    program: str                   # e.g., "hackerone-meta"
    submitted_date: str            # ISO format
    vulnerability_type: str
    severity: str                  # critical, high, medium, low
    outcome: str                   # BountyOutcome value

    # Optional fields (with defaults)
    resolved_date: str = ""
    attack_chain: str = ""         # If a chain was demonstrated
    payout_usd: float = 0.0
    rejection_reason: str = ""     # If rejected/na
    duplicate_of: str = ""         # If duplicate
    impact_demonstrated: str = ""  # What impact was proven
    endpoint_pattern: str = ""
    module_name: str = ""          # Which PHANTOM module found it

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "BountyReport":
        return cls(**data)


@dataclass
class ChainStatistics:
    """Statistics for an attack chain pattern."""
    chain_type: str

    # Counts
    times_seen_in_incidents: int = 0
    times_reported_bounty: int = 0
    times_paid_bounty: int = 0
    times_rejected: int = 0

    # Impact when successful
    avg_records_affected: float = 0.0
    avg_financial_impact: float = 0.0
    avg_payout_usd: float = 0.0
    max_payout_usd: float = 0.0

    # Probability adjustment
    base_probability: float = 0.5    # Default
    adjusted_probability: float = 0.5
    confidence: float = 0.0          # 0-1, based on sample size

    # Last update
    last_updated: float = 0.0


# =============================================================================
# INCIDENT STORE
# =============================================================================


class IncidentStore:
    """
    Persistent store for real-world incident data.

    Sources:
    - Manual entry from disclosed breaches
    - CVE/NVD imports
    - HackerOne Hacktivity (public disclosures)
    - Threat intelligence feeds
    """

    def __init__(self):
        self._ensure_dirs()
        self._incidents: list[RealIncident] = []
        self._loaded = False

    def _ensure_dirs(self) -> None:
        INCIDENT_DIR.mkdir(parents=True, exist_ok=True)

    def _load(self) -> None:
        if self._loaded:
            return

        if INCIDENT_FILE.exists():
            try:
                with open(INCIDENT_FILE, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                data = json.loads(line)
                                self._incidents.append(RealIncident.from_dict(data))
                            except (json.JSONDecodeError, TypeError):
                                continue
            except Exception as e:
                logger.warning(f"[INCIDENT] Error loading incidents: {e}")

        self._loaded = True
        logger.debug(f"[INCIDENT] Loaded {len(self._incidents)} real incidents")

    def record(self, incident: RealIncident) -> None:
        """Record a new real-world incident."""
        self._ensure_dirs()

        try:
            with open(INCIDENT_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(incident.to_dict()) + "\n")
        except Exception as e:
            logger.warning(f"[INCIDENT] Error saving incident: {e}")

        if self._loaded:
            self._incidents.append(incident)

    def get_all(self) -> list[RealIncident]:
        self._load()
        return self._incidents

    def query_by_chain(self, chain_type: str) -> list[RealIncident]:
        """Get incidents matching a chain type."""
        self._load()
        return [i for i in self._incidents if i.attack_chain == chain_type]

    def query_by_vuln_type(self, vuln_type: str) -> list[RealIncident]:
        """Get incidents involving a vulnerability type."""
        self._load()
        return [i for i in self._incidents if vuln_type in i.vulnerability_types]

    def query_by_industry(self, industry: str) -> list[RealIncident]:
        """Get incidents in a specific industry."""
        self._load()
        return [i for i in self._incidents if i.target_industry == industry]


# =============================================================================
# BOUNTY FEEDBACK STORE
# =============================================================================


class BountyFeedbackStore:
    """
    Tracks bug bounty report outcomes.

    Key insight: A PAID report proves REAL value.
    A REJECTED report with clear reason helps calibrate.
    """

    def __init__(self):
        self._ensure_dirs()
        self._reports: list[BountyReport] = []
        self._loaded = False

    def _ensure_dirs(self) -> None:
        INCIDENT_DIR.mkdir(parents=True, exist_ok=True)

    def _load(self) -> None:
        if self._loaded:
            return

        if BOUNTY_FILE.exists():
            try:
                with open(BOUNTY_FILE, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                data = json.loads(line)
                                self._reports.append(BountyReport.from_dict(data))
                            except (json.JSONDecodeError, TypeError):
                                continue
            except Exception as e:
                logger.warning(f"[BOUNTY] Error loading reports: {e}")

        self._loaded = True
        logger.debug(f"[BOUNTY] Loaded {len(self._reports)} bounty reports")

    def record(self, report: BountyReport) -> None:
        """Record a bounty report outcome."""
        self._ensure_dirs()

        try:
            with open(BOUNTY_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(report.to_dict()) + "\n")
        except Exception as e:
            logger.warning(f"[BOUNTY] Error saving report: {e}")

        if self._loaded:
            self._reports.append(report)

    def get_all(self) -> list[BountyReport]:
        self._load()
        return self._reports

    def get_by_module(self, module_name: str) -> list[BountyReport]:
        """Get reports from a specific scanner module."""
        self._load()
        return [r for r in self._reports if r.module_name == module_name]

    def get_by_outcome(self, outcome: BountyOutcome) -> list[BountyReport]:
        """Get reports with a specific outcome."""
        self._load()
        return [r for r in self._reports if r.outcome == outcome.value]

    def get_payout_stats(self) -> dict:
        """Get payout statistics."""
        self._load()

        paid = [r for r in self._reports if r.outcome == BountyOutcome.PAID.value]

        if not paid:
            return {"total_reports": len(self._reports), "paid": 0, "total_payout": 0}

        return {
            "total_reports": len(self._reports),
            "paid": len(paid),
            "rejected": len([r for r in self._reports if r.outcome == BountyOutcome.REJECTED.value]),
            "duplicate": len([r for r in self._reports if r.outcome == BountyOutcome.DUPLICATE.value]),
            "total_payout": sum(r.payout_usd for r in paid),
            "avg_payout": sum(r.payout_usd for r in paid) / len(paid),
            "max_payout": max(r.payout_usd for r in paid),
            "by_severity": self._payout_by_severity(paid),
        }

    def _payout_by_severity(self, paid_reports: list[BountyReport]) -> dict:
        by_sev: dict[str, list[float]] = defaultdict(list)
        for r in paid_reports:
            by_sev[r.severity].append(r.payout_usd)

        return {
            sev: {"count": len(payouts), "avg": sum(payouts) / len(payouts)}
            for sev, payouts in by_sev.items()
        }


# =============================================================================
# CHAIN PROBABILITY LEARNER
# =============================================================================


class ChainProbabilityLearner:
    """
    Adjusts attack chain probabilities based on real-world data.

    The key insight: theoretical chains that NEVER happen in real incidents
    should have lower probability than chains that happen regularly.

    Signals:
    1. Incident frequency — how often does this chain appear in breaches?
    2. Bounty payout rate — are reports for this chain getting paid?
    3. Severity consistency — does the chain lead to HIGH+ severity?
    4. Industry patterns — does e-commerce see different chains than SaaS?
    """

    # Default base probabilities for chain types
    DEFAULT_PROBABILITIES: dict[str, float] = {
        ChainType.SQLI_TO_DATA_THEFT.value: 0.75,
        ChainType.SQLI_TO_ADMIN.value: 0.60,
        ChainType.SQLI_TO_RCE.value: 0.30,
        ChainType.XSS_TO_ATO.value: 0.65,
        ChainType.XSS_TO_DATA_THEFT.value: 0.50,
        ChainType.CORS_TO_DATA_THEFT.value: 0.55,
        ChainType.SSRF_TO_INTERNAL.value: 0.70,
        ChainType.SSRF_TO_RCE.value: 0.25,
        ChainType.IDOR_TO_DATA.value: 0.80,
        ChainType.IDOR_TO_PRIVESC.value: 0.45,
        ChainType.AUTH_BYPASS_TO_ADMIN.value: 0.70,
        ChainType.SESSION_TO_ATO.value: 0.75,
        ChainType.BUSINESS_LOGIC_FRAUD.value: 0.60,
    }

    # Minimum samples before adjusting probability
    MIN_SAMPLES = 3

    # Maximum probability adjustment per iteration
    MAX_ADJUSTMENT = 0.20

    def __init__(self):
        self._incident_store = IncidentStore()
        self._bounty_store = BountyFeedbackStore()
        self._chain_stats: dict[str, ChainStatistics] = {}
        self._load_stats()

    def _load_stats(self) -> None:
        """Load chain statistics from file."""
        if CHAIN_STATS_FILE.exists():
            try:
                with open(CHAIN_STATS_FILE, encoding="utf-8") as f:
                    data = json.load(f)
                    for chain_type, stats in data.items():
                        self._chain_stats[chain_type] = ChainStatistics(
                            chain_type=chain_type,
                            **stats
                        )
            except Exception as e:
                logger.debug(f"[CHAIN_PROB] Error loading stats: {e}")

        # Initialize defaults for missing chains
        for chain_type, base_prob in self.DEFAULT_PROBABILITIES.items():
            if chain_type not in self._chain_stats:
                self._chain_stats[chain_type] = ChainStatistics(
                    chain_type=chain_type,
                    base_probability=base_prob,
                    adjusted_probability=base_prob,
                )

    def _save_stats(self) -> None:
        """Save chain statistics to file."""
        INCIDENT_DIR.mkdir(parents=True, exist_ok=True)

        try:
            data = {}
            for chain_type, stats in self._chain_stats.items():
                data[chain_type] = {
                    "times_seen_in_incidents": stats.times_seen_in_incidents,
                    "times_reported_bounty": stats.times_reported_bounty,
                    "times_paid_bounty": stats.times_paid_bounty,
                    "times_rejected": stats.times_rejected,
                    "avg_records_affected": stats.avg_records_affected,
                    "avg_financial_impact": stats.avg_financial_impact,
                    "avg_payout_usd": stats.avg_payout_usd,
                    "max_payout_usd": stats.max_payout_usd,
                    "base_probability": stats.base_probability,
                    "adjusted_probability": stats.adjusted_probability,
                    "confidence": stats.confidence,
                    "last_updated": stats.last_updated,
                }

            with open(CHAIN_STATS_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.debug(f"[CHAIN_PROB] Error saving stats: {e}")

    def recompute_probabilities(self) -> None:
        """
        Recompute chain probabilities from all available data.

        Algorithm:
        1. Count incidents per chain type
        2. Count bounty outcomes per chain type
        3. Calculate success rate (paid / total reported)
        4. Adjust probability based on:
           - Incident frequency (chains that happen often → higher)
           - Bounty success rate (chains that pay → higher)
           - Impact magnitude (high impact chains → higher)
        """
        incidents = self._incident_store.get_all()
        bounties = self._bounty_store.get_all()

        # Count incidents per chain
        incident_counts: dict[str, int] = defaultdict(int)
        impact_sums: dict[str, dict] = defaultdict(lambda: {"records": 0, "financial": 0})

        for incident in incidents:
            chain = incident.attack_chain
            incident_counts[chain] += 1
            impact_sums[chain]["records"] += incident.records_affected
            impact_sums[chain]["financial"] += incident.financial_impact_usd

        # Count bounty outcomes per chain
        bounty_counts: dict[str, dict] = defaultdict(
            lambda: {"total": 0, "paid": 0, "rejected": 0, "payouts": []}
        )

        for report in bounties:
            chain = report.attack_chain or self._infer_chain(report.vulnerability_type)
            bounty_counts[chain]["total"] += 1

            if report.outcome == BountyOutcome.PAID.value:
                bounty_counts[chain]["paid"] += 1
                bounty_counts[chain]["payouts"].append(report.payout_usd)
            elif report.outcome == BountyOutcome.REJECTED.value:
                bounty_counts[chain]["rejected"] += 1

        # Update chain statistics
        for chain_type in self._chain_stats:
            stats = self._chain_stats[chain_type]

            # Update counts
            stats.times_seen_in_incidents = incident_counts.get(chain_type, 0)
            stats.times_reported_bounty = bounty_counts[chain_type]["total"]
            stats.times_paid_bounty = bounty_counts[chain_type]["paid"]
            stats.times_rejected = bounty_counts[chain_type]["rejected"]

            # Update impact averages
            if stats.times_seen_in_incidents > 0:
                stats.avg_records_affected = (
                    impact_sums[chain_type]["records"] / stats.times_seen_in_incidents
                )
                stats.avg_financial_impact = (
                    impact_sums[chain_type]["financial"] / stats.times_seen_in_incidents
                )

            # Update payout stats
            payouts = bounty_counts[chain_type]["payouts"]
            if payouts:
                stats.avg_payout_usd = sum(payouts) / len(payouts)
                stats.max_payout_usd = max(payouts)

            # Calculate adjusted probability
            stats.adjusted_probability = self._calculate_adjusted_probability(stats)
            stats.confidence = self._calculate_confidence(stats)
            stats.last_updated = time.time()

        self._save_stats()
        logger.info(
            f"[CHAIN_PROB] Recomputed probabilities from "
            f"{len(incidents)} incidents, {len(bounties)} bounties"
        )

    def _calculate_adjusted_probability(self, stats: ChainStatistics) -> float:
        """
        Calculate adjusted probability for a chain.

        Formula:
        adjusted = base + incident_factor + bounty_factor + impact_factor

        Where:
        - incident_factor: +0.1 per 5 incidents, max +0.15
        - bounty_factor: +0.1 if >50% paid, -0.1 if >50% rejected
        - impact_factor: +0.05 if avg impact > $10K
        """
        base = stats.base_probability
        adjustment = 0.0

        # Incident factor
        if stats.times_seen_in_incidents >= 5:
            incident_boost = min(0.15, stats.times_seen_in_incidents * 0.02)
            adjustment += incident_boost

        # Bounty factor
        if stats.times_reported_bounty >= self.MIN_SAMPLES:
            pay_rate = stats.times_paid_bounty / stats.times_reported_bounty
            reject_rate = stats.times_rejected / stats.times_reported_bounty

            if pay_rate > 0.6:
                adjustment += 0.10
            elif pay_rate > 0.4:
                adjustment += 0.05
            elif reject_rate > 0.5:
                adjustment -= 0.10

        # Impact factor
        if stats.avg_financial_impact > 10000 or stats.avg_payout_usd > 1000:
            adjustment += 0.05

        # Clamp adjustment
        adjustment = max(-self.MAX_ADJUSTMENT, min(self.MAX_ADJUSTMENT, adjustment))

        # Final probability (clamped to 0.1-0.95)
        return max(0.10, min(0.95, base + adjustment))

    def _calculate_confidence(self, stats: ChainStatistics) -> float:
        """Calculate confidence in the probability estimate."""
        total_samples = stats.times_seen_in_incidents + stats.times_reported_bounty

        if total_samples < self.MIN_SAMPLES:
            return 0.0
        elif total_samples < 10:
            return 0.3
        elif total_samples < 25:
            return 0.5
        elif total_samples < 50:
            return 0.7
        else:
            return 0.9

    def _infer_chain(self, vuln_type: str) -> str:
        """Infer chain type from vulnerability type."""
        vuln_lower = vuln_type.lower()

        if "sql" in vuln_lower:
            return ChainType.SQLI_TO_DATA_THEFT.value
        elif "xss" in vuln_lower:
            return ChainType.XSS_TO_ATO.value
        elif "cors" in vuln_lower:
            return ChainType.CORS_TO_DATA_THEFT.value
        elif "ssrf" in vuln_lower:
            return ChainType.SSRF_TO_INTERNAL.value
        elif "idor" in vuln_lower or "bola" in vuln_lower:
            return ChainType.IDOR_TO_DATA.value
        elif "session" in vuln_lower or "jwt" in vuln_lower:
            return ChainType.SESSION_TO_ATO.value
        elif "business" in vuln_lower or "logic" in vuln_lower:
            return ChainType.BUSINESS_LOGIC_FRAUD.value
        elif "auth" in vuln_lower:
            return ChainType.AUTH_BYPASS_TO_ADMIN.value
        else:
            return ChainType.CHAIN_UNKNOWN.value

    def get_chain_probability(self, chain_type: str) -> tuple[float, float]:
        """
        Get probability for a chain type.

        Returns: (probability, confidence)
        """
        if chain_type in self._chain_stats:
            stats = self._chain_stats[chain_type]
            return stats.adjusted_probability, stats.confidence

        # Default for unknown chains
        return 0.5, 0.0

    def get_all_probabilities(self) -> dict[str, dict]:
        """Get all chain probabilities with metadata."""
        return {
            chain: {
                "probability": stats.adjusted_probability,
                "confidence": stats.confidence,
                "incidents": stats.times_seen_in_incidents,
                "bounties_paid": stats.times_paid_bounty,
                "avg_payout": stats.avg_payout_usd,
            }
            for chain, stats in self._chain_stats.items()
        }


# =============================================================================
# INCIDENT LEARNING ENGINE (Orchestrator)
# =============================================================================


class IncidentLearningEngine:
    """
    Main orchestrator for incident-based learning.

    Provides unified interface for:
    - Recording incidents and bounty outcomes
    - Querying learned patterns
    - Adjusting findings based on real-world data
    """

    def __init__(self):
        self._incident_store = IncidentStore()
        self._bounty_store = BountyFeedbackStore()
        self._chain_learner = ChainProbabilityLearner()
        self._state = self._load_state()

    def _load_state(self) -> dict:
        """Load learning state."""
        if LEARNING_STATE_FILE.exists():
            try:
                with open(LEARNING_STATE_FILE, encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass

        return {
            "total_incidents": 0,
            "total_bounties": 0,
            "last_recompute": 0,
            "version": "1.0.0",
        }

    def _save_state(self) -> None:
        """Save learning state."""
        INCIDENT_DIR.mkdir(parents=True, exist_ok=True)
        try:
            with open(LEARNING_STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(self._state, f, indent=2)
        except Exception as e:
            logger.debug(f"[INCIDENT_LEARN] Error saving state: {e}")

    # -------------------------------------------------------------------------
    # Recording Methods
    # -------------------------------------------------------------------------

    def record_incident(
        self,
        vulnerability_types: list[str],
        attack_chain: str,
        impact_type: str,
        description: str,
        source: IncidentSource = IncidentSource.MANUAL,
        records_affected: int = 0,
        financial_impact: float = 0.0,
        target_industry: str = "",
        cve_ids: list[str] | None = None,
        reference_urls: list[str] | None = None,
    ) -> str:
        """
        Record a real-world incident.

        Returns: incident_id
        """
        incident_id = hashlib.sha256(
            f"{time.time()}:{description[:50]}".encode()
        ).hexdigest()[:16]

        incident = RealIncident(
            incident_id=incident_id,
            source=source.value,
            date_occurred=datetime.now().isoformat(),
            date_reported=datetime.now().isoformat(),
            vulnerability_types=vulnerability_types,
            attack_chain=attack_chain,
            attack_description=description,
            impact_type=impact_type,
            records_affected=records_affected,
            financial_impact_usd=financial_impact,
            target_industry=target_industry,
            cve_ids=cve_ids or [],
            reference_urls=reference_urls or [],
        )

        self._incident_store.record(incident)
        self._state["total_incidents"] += 1
        self._save_state()

        # Trigger recompute if we have enough new data
        if self._should_recompute():
            self._chain_learner.recompute_probabilities()

        logger.info(f"[INCIDENT] Recorded incident {incident_id}: {attack_chain}")
        return incident_id

    def record_bounty_outcome(
        self,
        program: str,
        vulnerability_type: str,
        severity: str,
        outcome: BountyOutcome,
        payout: float = 0.0,
        attack_chain: str = "",
        module_name: str = "",
        rejection_reason: str = "",
        impact_demonstrated: str = "",
    ) -> str:
        """
        Record a bug bounty report outcome.

        Returns: report_id
        """
        report_id = hashlib.sha256(
            f"{time.time()}:{program}:{vulnerability_type}".encode()
        ).hexdigest()[:16]

        report = BountyReport(
            report_id=report_id,
            program=program,
            submitted_date=datetime.now().isoformat(),
            resolved_date=datetime.now().isoformat() if outcome != BountyOutcome.PENDING else "",
            vulnerability_type=vulnerability_type,
            severity=severity,
            attack_chain=attack_chain,
            outcome=outcome.value,
            payout_usd=payout,
            rejection_reason=rejection_reason,
            impact_demonstrated=impact_demonstrated,
            module_name=module_name,
        )

        self._bounty_store.record(report)
        self._state["total_bounties"] += 1
        self._save_state()

        # Trigger recompute if we have enough new data
        if self._should_recompute():
            self._chain_learner.recompute_probabilities()

        outcome_str = f"${payout}" if outcome == BountyOutcome.PAID else outcome.value
        logger.info(f"[BOUNTY] Recorded {program}: {vulnerability_type} → {outcome_str}")
        return report_id

    def _should_recompute(self) -> bool:
        """Check if we should recompute probabilities."""
        # Recompute every 10 new entries or 6 hours
        total = self._state["total_incidents"] + self._state["total_bounties"]
        entries_since = total % 10
        time_since = time.time() - self._state.get("last_recompute", 0)

        return entries_since == 0 or time_since > 21600

    # -------------------------------------------------------------------------
    # Query Methods
    # -------------------------------------------------------------------------

    def get_chain_probability(self, chain_type: str) -> tuple[float, float]:
        """Get probability and confidence for a chain type."""
        return self._chain_learner.get_chain_probability(chain_type)

    def adjust_finding_from_incidents(self, finding: dict) -> dict:
        """
        Adjust a finding's severity/confidence based on incident data.

        Looks for:
        1. Matching attack chains in incident history
        2. Bounty payout patterns for this vuln type
        3. Industry-specific patterns
        """
        vuln_type = finding.get("vulnerability_type", "")
        chain = finding.get("metadata", {}).get("attack_chain", "")

        if not chain:
            chain = self._chain_learner._infer_chain(vuln_type)

        probability, confidence = self.get_chain_probability(chain)

        # Only adjust if we have confidence
        if confidence < 0.3:
            return finding

        adjustments = {}

        # Probability boost/penalty
        base_prob = self._chain_learner.DEFAULT_PROBABILITIES.get(chain, 0.5)
        prob_diff = probability - base_prob

        if prob_diff > 0.1:
            # This chain is more common than expected → boost
            adjustments["confidence_boost"] = min(0.15, prob_diff * 0.5)
        elif prob_diff < -0.1:
            # This chain is less common than expected → penalty
            adjustments["confidence_penalty"] = max(-0.10, prob_diff * 0.5)

        # Check for matching incidents
        matching_incidents = self._incident_store.query_by_chain(chain)
        if matching_incidents:
            adjustments["incident_matches"] = len(matching_incidents)
            adjustments["max_impact_usd"] = max(
                i.financial_impact_usd for i in matching_incidents
            )

            # If we have high-impact incidents, boost severity
            if adjustments["max_impact_usd"] > 100000:
                adjustments["severity_boost"] = True

        # Apply adjustments
        if adjustments:
            finding.setdefault("metadata", {})["incident_learning"] = adjustments

            # ═══════════════════════════════════════════════════════════════════
            # FEEDBACK-04 FIX: Only apply boost if finding has validation evidence
            # Pattern matches alone are NOT sufficient to boost confidence
            # ═══════════════════════════════════════════════════════════════════
            metadata = finding.get("metadata", {})
            has_validation = (
                (isinstance(metadata, dict) and metadata.get("validated", False)) or
                (isinstance(metadata, dict) and metadata.get("proof", {}).get("can_repeat", False)) or
                (isinstance(metadata, dict) and metadata.get("exploitability") in ("PARTIAL", "FULL")) or
                finding.get("confidence_score", finding.get("confidence", 0)) >= 75.0  # Already high confidence
            )

            # Apply confidence adjustment
            boost = adjustments.get("confidence_boost", 0)
            penalty = adjustments.get("confidence_penalty", 0)

            # FEEDBACK-04: Boost only applied if finding has validation evidence
            if not has_validation:
                logger.debug(
                    f"[FEEDBACK-04] Skipping boost for unvalidated finding: {vuln_type}"
                )
                boost = 0  # Don't boost unvalidated findings

            current_conf = finding.get("confidence_score", finding.get("confidence", 0.5))
            if isinstance(current_conf, str):
                current_conf = {"critical": 0.95, "high": 0.85, "medium": 0.65, "low": 0.40}.get(current_conf.lower(), 0.5)
            new_conf = max(0.0, min(1.0, current_conf + boost + penalty))
            finding["confidence_score"] = new_conf
            finding["confidence"] = new_conf

            logger.debug(
                f"[INCIDENT_LEARN] Adjusted {vuln_type}: "
                f"conf {current_conf:.2f}→{new_conf:.2f}, "
                f"chain_prob={probability:.2f}, incidents={len(matching_incidents)}, "
                f"has_validation={has_validation}"
            )

        return finding

    def get_module_roi(self, module_name: str) -> dict:
        """
        Calculate ROI for a scanner module based on bounty payouts.

        Returns metrics on whether this module produces valuable findings.
        """
        reports = self._bounty_store.get_by_module(module_name)

        if not reports:
            return {"module": module_name, "reports": 0, "roi": "unknown"}

        paid = [r for r in reports if r.outcome == BountyOutcome.PAID.value]
        rejected = [r for r in reports if r.outcome == BountyOutcome.REJECTED.value]

        total_payout = sum(r.payout_usd for r in paid)
        avg_payout = total_payout / len(paid) if paid else 0

        return {
            "module": module_name,
            "total_reports": len(reports),
            "paid": len(paid),
            "rejected": len(rejected),
            "total_payout": total_payout,
            "avg_payout": avg_payout,
            "pay_rate": len(paid) / len(reports) if reports else 0,
            "roi": "high" if avg_payout > 500 else "medium" if avg_payout > 100 else "low",
        }

    def get_summary(self) -> dict:
        """Get summary of incident learning state."""
        payout_stats = self._bounty_store.get_payout_stats()
        chain_probs = self._chain_learner.get_all_probabilities()

        # Top chains by probability
        top_chains = sorted(
            chain_probs.items(),
            key=lambda x: x[1]["probability"],
            reverse=True
        )[:5]

        return {
            "total_incidents": self._state["total_incidents"],
            "total_bounties": self._state["total_bounties"],
            "bounty_stats": payout_stats,
            "top_chains": [
                {"chain": c, "probability": p["probability"], "confidence": p["confidence"]}
                for c, p in top_chains
            ],
            "last_recompute": datetime.fromtimestamp(
                self._state.get("last_recompute", 0)
            ).isoformat() if self._state.get("last_recompute") else "never",
        }


# =============================================================================
# GLOBAL INSTANCE AND CONVENIENCE FUNCTIONS
# =============================================================================


_global_engine: IncidentLearningEngine | None = None


def get_incident_engine() -> IncidentLearningEngine:
    """Get the global incident learning engine."""
    global _global_engine
    if _global_engine is None:
        _global_engine = IncidentLearningEngine()
    return _global_engine


def record_real_incident(
    vuln_types: list[str],
    chain: str,
    impact: str,
    description: str,
    **kwargs,
) -> str:
    """Convenience function to record an incident."""
    engine = get_incident_engine()
    return engine.record_incident(
        vulnerability_types=vuln_types,
        attack_chain=chain,
        impact_type=impact,
        description=description,
        **kwargs,
    )


def record_bounty(
    program: str,
    vuln_type: str,
    severity: str,
    outcome: BountyOutcome,
    payout: float = 0.0,
    **kwargs,
) -> str:
    """Convenience function to record a bounty outcome."""
    engine = get_incident_engine()
    return engine.record_bounty_outcome(
        program=program,
        vulnerability_type=vuln_type,
        severity=severity,
        outcome=outcome,
        payout=payout,
        **kwargs,
    )


def adjust_from_incidents(finding: dict) -> dict:
    """Apply incident-based learning to a finding."""
    engine = get_incident_engine()
    return engine.adjust_finding_from_incidents(finding)


# =============================================================================
# SEED DATA: Known Real-World Patterns
# =============================================================================

# These are well-known attack chains from real incidents
# Used to bootstrap the learning engine
KNOWN_CHAIN_PATTERNS: list[dict] = [
    {
        "chain": ChainType.SQLI_TO_DATA_THEFT.value,
        "description": "SQL injection leading to mass data exfiltration",
        "examples": ["Equifax 2017", "Sony Pictures", "Ashley Madison"],
        "avg_records": 50_000_000,
        "probability": 0.80,
    },
    {
        "chain": ChainType.XSS_TO_ATO.value,
        "description": "XSS stealing session/token leading to account takeover",
        "examples": ["Twitter (2010)", "eBay (2014)", "Steam"],
        "probability": 0.70,
    },
    {
        "chain": ChainType.SSRF_TO_INTERNAL.value,
        "description": "SSRF accessing internal services/metadata",
        "examples": ["Capital One 2019 (AWS metadata)", "Shopify"],
        "avg_financial": 100_000_000,
        "probability": 0.75,
    },
    {
        "chain": ChainType.IDOR_TO_DATA.value,
        "description": "IDOR exposing user data at scale",
        "examples": ["Facebook (2019)", "Parler", "Bumble"],
        "probability": 0.85,
    },
    {
        "chain": ChainType.BUSINESS_LOGIC_FRAUD.value,
        "description": "Business logic flaws enabling financial fraud",
        "examples": ["Uber price manipulation", "Gift card abuse"],
        "probability": 0.65,
    },
]


def seed_known_patterns() -> None:
    """Seed the learning engine with known patterns."""
    engine = get_incident_engine()

    for pattern in KNOWN_CHAIN_PATTERNS:
        for example in pattern.get("examples", []):
            engine.record_incident(
                vulnerability_types=[pattern["chain"].split("_to_")[0]],
                attack_chain=pattern["chain"],
                impact_type=pattern["chain"].split("_to_")[1] if "_to_" in pattern["chain"] else "unknown",
                description=f"Known incident: {example}",
                source=IncidentSource.BREACH_REPORT,
                records_affected=pattern.get("avg_records", 0),
                financial_impact=pattern.get("avg_financial", 0.0),
            )

    logger.info(f"[INCIDENT] Seeded {len(KNOWN_CHAIN_PATTERNS)} known chain patterns")
