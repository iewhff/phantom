"""
Result Aggregator - Aggregates module results with validation.

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional, Protocol

logger = logging.getLogger("phantom")


class ScanResultProtocol(Protocol):
    """Protocol for ScanResult objects."""

    findings: list
    info: list[dict]
    errors: list[dict]
    modules_run: list[str]
    tests_skipped: int
    negative_control_validations: int

    def add_finding(self, finding: Any) -> None:
        ...


class FocusLockProtocol(Protocol):
    """Protocol for focus lock."""

    def should_activate_focus(self, finding: Any) -> bool:
        ...

    def activate(self, finding: Any) -> None:
        ...

    def get_focused_modules(self) -> list[str]:
        ...


class ExhaustionTrackerProtocol(Protocol):
    """Protocol for exhaustion tracker."""

    def register_finding(self, finding: Any) -> str:
        ...

    def get_remaining_vectors(self, finding_id: str) -> list:
        ...


class ScanAmplifierProtocol(Protocol):
    """Protocol for scan amplifier."""

    def on_finding_discovered(self, finding: Any) -> list:
        ...


class ExplosionControllerProtocol(Protocol):
    """Protocol for explosion controller."""

    def create_amplification(
        self,
        trigger_finding: Any,
        target: str,
        vuln_type: str,
        params: dict,
        estimated_requests: int,
    ) -> Any:
        ...

    def enqueue(self, action: Any) -> bool:
        ...

    def record_finding(self, target: str) -> None:
        ...


class EvidenceEngineProtocol(Protocol):
    """Protocol for evidence engine."""

    def add_timeline_event(
        self,
        event_type: str,
        description: str,
        url: Optional[str] = None,
        severity: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> None:
        ...


class ResultAggregator:
    """
    Aggregates module results with intelligent validation.

    Handles:
    - Exception handling for failed modules
    - Finding validation through intelligent scanner
    - Focus lock activation for HIGH+ findings
    - Exhaustion tracking for finding completion
    - Scan amplification triggers
    - Evidence engine timeline events
    """

    def __init__(
        self,
        intelligent_mode: bool = False,
        intelligent_context: Optional[Any] = None,
        intelligent_scanner: Optional[Any] = None,
    ):
        self.intelligent_mode = intelligent_mode
        self.intelligent_context = intelligent_context
        self.intelligent_scanner = intelligent_scanner

        # Optional components
        self.focus_lock: Optional[FocusLockProtocol] = None
        self.exhaustion_tracker: Optional[ExhaustionTrackerProtocol] = None
        self.scan_amplifier: Optional[ScanAmplifierProtocol] = None
        self.explosion_controller: Optional[ExplosionControllerProtocol] = None
        self.evidence_engine: Optional[EvidenceEngineProtocol] = None
        self.evidence_session: bool = False

        # Callbacks
        self._validate_finding_func: Optional[Callable] = None
        self._enqueue_amplification_func: Optional[Callable] = None

        # Priority enum (imported on demand)
        self._Priority = None

    def register_components(
        self,
        focus_lock: Optional[FocusLockProtocol] = None,
        exhaustion_tracker: Optional[ExhaustionTrackerProtocol] = None,
        scan_amplifier: Optional[ScanAmplifierProtocol] = None,
        explosion_controller: Optional[ExplosionControllerProtocol] = None,
        evidence_engine: Optional[EvidenceEngineProtocol] = None,
        evidence_session: bool = False,
    ) -> "ResultAggregator":
        """Register optional components."""
        if focus_lock:
            self.focus_lock = focus_lock
        if exhaustion_tracker:
            self.exhaustion_tracker = exhaustion_tracker
        if scan_amplifier:
            self.scan_amplifier = scan_amplifier
        if explosion_controller:
            self.explosion_controller = explosion_controller
        if evidence_engine:
            self.evidence_engine = evidence_engine
        self.evidence_session = evidence_session
        return self

    def register_callbacks(
        self,
        validate_finding: Optional[Callable] = None,
        enqueue_amplification: Optional[Callable] = None,
    ) -> "ResultAggregator":
        """Register callbacks."""
        if validate_finding:
            self._validate_finding_func = validate_finding
        if enqueue_amplification:
            self._enqueue_amplification_func = enqueue_amplification
        return self

    def aggregate(
        self,
        result: ScanResultProtocol,
        module_names: list[str],
        module_results: list,
        on_progress: Optional[Callable] = None,
    ) -> None:
        """
        Aggregate module results into scan result.

        Args:
            result: ScanResult to update
            module_names: List of module names
            module_results: List of module results (dict or Exception)
            on_progress: Optional progress callback
        """
        for i, mod_result in enumerate(module_results):
            module_name = module_names[i]

            if isinstance(mod_result, Exception):
                result.errors.append({
                    "module": module_name,
                    "error": str(mod_result),
                })
                self._call_progress(on_progress, result)
                continue

            # Check for error dicts from timeout/exception handlers
            if isinstance(mod_result, dict) and mod_result.get("error"):
                result.errors.append({
                    "module": module_name,
                    "error": mod_result["error"],
                    "partial_findings": len(mod_result.get("findings", [])),
                })

            result.modules_run.append(module_name)

            for finding in mod_result.get("findings", []):
                # Enrich finding with module context if missing
                finding = self._enrich_finding(finding, module_name)

                # Apply intelligent validation
                if self.intelligent_mode and self.intelligent_context:
                    finding = self._validate_finding(finding)
                    if self._is_discarded(finding):
                        result.tests_skipped += 1
                        continue
                    result.negative_control_validations += 1

                result.add_finding(finding)

                # Process finding through components
                self._process_focus_lock(finding)
                self._process_exhaustion(finding)
                self._process_amplification(finding)
                self._record_evidence(finding, module_name)

            result.info.extend(mod_result.get("info", []))
            self._call_progress(on_progress, result)

    # Module name → default vuln_type for findings that lack one.
    # Includes both full class names (oauth_scanner) and short CLI names (oauth).
    _MODULE_VULN_DEFAULTS: dict[str, str] = {
        # Full names (from Python module classes)
        "oauth_scanner": "oauth_misconfiguration",
        "saml_scanner": "saml_vulnerability",
        "dns_rebinding_scanner": "dns_rebinding",
        "websocket_scanner": "websocket_vulnerability",
        "host_header_scanner": "host_header_injection",
        "email_security_scanner": "email_security",
        "cors_checker": "cors_misconfiguration",
        "csrf_scanner": "csrf",
        "clickjacking_scanner": "clickjacking",
        "ssl_checker": "ssl_misconfiguration",
        "header_security": "security_headers_missing",
        "rate_limit_scanner": "rate_limit_missing",
        "cache_poisoning_scanner": "cache_poisoning",
        "cache_deception_scanner": "cache_deception",
        "smuggling_scanner": "http_smuggling",
        "prototype_pollution_scanner": "prototype_pollution",
        "race_condition_scanner": "race_condition",
        "mass_assignment_scanner": "mass_assignment",
        "session_abuse_scanner": "session_hijacking",
        "open_redirect_scanner": "open_redirect",
        "info_disclosure_scanner": "info_disclosure",
        "dir_scanner": "directory_listing",
        "mfa_bypass_scanner": "mfa_bypass",
        # Short names (from pathfinder CLI module_names list)
        "oauth": "oauth_misconfiguration",
        "saml": "saml_vulnerability",
        "dns_rebind": "dns_rebinding",
        "websocket": "websocket_vulnerability",
        "host_header": "host_header_injection",
        "email": "info_disclosure",
        "cors": "cors_misconfiguration",
        "csrf": "csrf",
        "ssl": "ssl_misconfiguration",
        "headers": "security_headers_missing",
        "ratelimit": "rate_limit_bypass",
        "cache": "cache_poisoning",
        "smuggling": "http_smuggling",
        "prototype": "prototype_pollution",
        "race": "race_condition",
        "mass_assign": "mass_assignment",
        "session_abuse": "session_hijacking",
        "dir": "directory_listing",
        "mfa": "mfa_bypass",
        "mobile": "info_disclosure",
        "api": "info_disclosure",
        "sse": "info_disclosure",
        "cookie": "cookie_security",
        "file_upload": "file_upload",
        "deser": "deserialization",
        "cloud": "cloud_misconfiguration",
        "k8s": "kubernetes_vulnerability",
        "firebase": "cloud_misconfiguration",
        "cms": "info_disclosure",
        "backend": "info_disclosure",
        "graphql": "graphql_introspection",
        "grpc": "grpc_vulnerability",
    }

    def _enrich_finding(self, finding: Any, module_name: str) -> Any:
        """Enrich finding with module context if fields are missing."""
        if isinstance(finding, dict):
            # Set scanner/module_name if missing
            if not finding.get("scanner"):
                finding["scanner"] = module_name
            if not finding.get("module_name"):
                finding["module_name"] = module_name

            # Normalize non-standard field names from legacy scanners
            # (e.g., csrf_scanner uses "title" not "name", "url" not "endpoint")
            if not finding.get("name") and finding.get("title"):
                finding["name"] = finding["title"]
            if not finding.get("endpoint") and finding.get("url"):
                finding["endpoint"] = finding["url"]
            if not finding.get("endpoint") and finding.get("matched_at"):
                finding["endpoint"] = finding["matched_at"]
            # Reverse: ensure matched_at is always populated for downstream consumers
            if not finding.get("matched_at"):
                finding["matched_at"] = finding.get("endpoint") or finding.get("url") or ""
            if not finding.get("cwe_id") and finding.get("cwe"):
                finding["cwe_id"] = finding["cwe"]
            if finding.get("confidence_score") is None and finding.get("confidence") is not None:
                conf = finding["confidence"]
                if isinstance(conf, (int, float)):
                    finding["confidence_score"] = float(conf)

            # Infer vuln_type from module name if it's unknown/missing/None
            vt = finding.get("vuln_type")
            if not vt or (isinstance(vt, str) and vt.lower() in ("unknown", "")):
                default_vt = self._MODULE_VULN_DEFAULTS.get(module_name, "")
                if default_vt:
                    finding["vuln_type"] = default_vt
        else:
            # Object-style finding (Finding dataclass)
            if hasattr(finding, "scanner") and not finding.scanner:
                finding.scanner = module_name
            if hasattr(finding, "vuln_type"):
                vt = finding.vuln_type
                vt_val = vt.value if hasattr(vt, "value") else str(vt)
                if vt_val in ("unknown", "UNKNOWN", ""):
                    default_vt = self._MODULE_VULN_DEFAULTS.get(module_name, "")
                    if default_vt:
                        # Try to set as enum, fall back to string
                        try:
                            from scanning.findings import VulnType
                            finding.vuln_type = VulnType(default_vt)
                        except (ValueError, ImportError):
                            pass
        return finding

    def _validate_finding(self, finding: Any) -> Any:
        """Validate finding through intelligent scanner."""
        if self._validate_finding_func:
            try:
                return self._validate_finding_func(finding)
            except Exception as e:
                logger.warning(f"[Aggregator] Finding validation failed: {e}")
        return finding

    def _is_discarded(self, finding: Any) -> bool:
        """Check if finding was discarded by validation."""
        if hasattr(finding, 'metadata') and finding.metadata:
            return finding.metadata.get("_discarded", False)
        elif isinstance(finding, dict):
            return finding.get("_discarded", False)
        return False

    def _process_focus_lock(self, finding: Any) -> None:
        """Process finding through focus lock."""
        if not self.focus_lock:
            return

        try:
            if self.focus_lock.should_activate_focus(finding):
                self.focus_lock.activate(finding)
                focused_modules = self.focus_lock.get_focused_modules()
                finding_type = finding.get('vuln_type', finding.get('type', 'unknown')) if isinstance(finding, dict) else 'unknown'
                logger.info(
                    f"[FOCUS] Focus lock activated for {finding_type} - "
                    f"prioritizing modules: {focused_modules[:5]}"
                )
        except Exception as e:
            logger.debug(f"[FOCUS] Error checking focus lock: {e}")

    def _process_exhaustion(self, finding: Any) -> None:
        """Process finding through exhaustion tracker."""
        if not self.exhaustion_tracker:
            return

        try:
            if isinstance(finding, dict):
                severity = finding.get("severity", "").upper()
            else:
                sev = getattr(finding, "severity", "")
                severity = (sev.value if hasattr(sev, "value") else str(sev)).upper()
            if severity in ("HIGH", "CRITICAL"):
                finding_id = self.exhaustion_tracker.register_finding(finding)
                if isinstance(finding, dict):
                    finding.setdefault("metadata", {})
                    finding["metadata"]["exhaustion_id"] = finding_id
                    finding["metadata"]["vectors_remaining"] = (
                        self.exhaustion_tracker.get_remaining_vectors(finding_id)[:5]
                    )
        except Exception as e:
            logger.debug(f"[EXHAUSTION] Error registering finding: {e}")

    def _process_amplification(self, finding: Any) -> None:
        """Process finding through scan amplifier."""
        if not self.scan_amplifier:
            return

        try:
            actions = self.scan_amplifier.on_finding_discovered(finding)
            if not actions:
                return

            # Import Priority on demand
            if self._Priority is None:
                from scanning.state_explosion_controller import Priority
                self._Priority = Priority

            target = finding.get("matched_at", "") if isinstance(finding, dict) else ""
            for amp_action in actions:
                priority = self._Priority.HIGH if amp_action.priority >= 8 else self._Priority.MEDIUM
                if amp_action.priority >= 10:
                    priority = self._Priority.CRITICAL
                elif amp_action.priority <= 5:
                    priority = self._Priority.LOW

                if self.explosion_controller:
                    prio_action = self.explosion_controller.create_amplification(
                        trigger_finding=finding,
                        target=amp_action.target,
                        vuln_type=amp_action.trigger_type,
                        params=amp_action.params,
                        estimated_requests=5,
                    )
                    prio_action.priority = -priority.value

                    if self.explosion_controller.enqueue(prio_action):
                        if self._enqueue_amplification_func:
                            self._enqueue_amplification_func(amp_action)

                    self.explosion_controller.record_finding(target)

            if len(actions) > 0:
                finding_type = finding.get('vuln_type', finding.get('type', 'unknown')) if isinstance(finding, dict) else 'unknown'
                logger.debug(
                    f"[Amplifier] Finding {finding_type} triggered "
                    f"{len(actions)} amplification actions"
                )
        except Exception as e:
            logger.debug(f"[Amplifier] Error processing finding: {e}")

    def _record_evidence(self, finding: Any, module_name: str) -> None:
        """Record finding in evidence engine."""
        if not self.evidence_session or not self.evidence_engine:
            return

        if isinstance(finding, dict):
            finding_type = finding.get("vuln_type", finding.get("type", "unknown"))
            severity = finding.get("severity", "MEDIUM")
            url = finding.get("endpoint", finding.get("url", finding.get("matched_at", "")))
        else:
            vt = getattr(finding, "vuln_type", "unknown")
            finding_type = vt.value if hasattr(vt, "value") else str(vt)
            sev = getattr(finding, "severity", "MEDIUM")
            severity = sev.value if hasattr(sev, "value") else str(sev)
            url = getattr(finding, "endpoint", "") or getattr(finding, "host", "")

        self.evidence_engine.add_timeline_event(
            event_type="finding",
            description=f"[{severity}] {finding_type} discovered by {module_name}",
            url=url,
            severity=severity,
            details={"module": module_name, "finding_type": finding_type}
        )

    def _call_progress(self, on_progress: Optional[Callable], result: Any) -> None:
        """Call progress callback safely."""
        if on_progress:
            try:
                on_progress(result)
            except Exception as e:
                logger.debug(f"Progress callback error: {e}")


def aggregate_results(
    result: ScanResultProtocol,
    module_names: list[str],
    module_results: list,
    intelligent_mode: bool = False,
    intelligent_context: Optional[Any] = None,
    on_progress: Optional[Callable] = None,
    **kwargs,
) -> None:
    """
    Aggregate module results into scan result.

    Convenience function for simple aggregation.
    """
    aggregator = ResultAggregator(
        intelligent_mode=intelligent_mode,
        intelligent_context=intelligent_context,
    )

    # Register components from kwargs
    aggregator.register_components(
        focus_lock=kwargs.get("focus_lock"),
        exhaustion_tracker=kwargs.get("exhaustion_tracker"),
        scan_amplifier=kwargs.get("scan_amplifier"),
        explosion_controller=kwargs.get("explosion_controller"),
        evidence_engine=kwargs.get("evidence_engine"),
        evidence_session=kwargs.get("evidence_session", False),
    )

    aggregator.register_callbacks(
        validate_finding=kwargs.get("validate_finding"),
        enqueue_amplification=kwargs.get("enqueue_amplification"),
    )

    aggregator.aggregate(result, module_names, module_results, on_progress)
