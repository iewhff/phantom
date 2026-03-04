"""
Tests for the scanning/phase_executor/ module.

Tests PhaseInfo, PhaseTracker, and related components.
"""

import pytest
import time
from unittest.mock import Mock, MagicMock

from scanning.phase_executor import (
    # Enums and dataclasses
    PhaseCategory,
    PhaseInfo,
    PhaseExecution,
    # Classes
    PhaseTracker,
    PhaseContext,
    # Phase constants
    PHASE_0,
    PHASE_0_5,
    PHASE_3,
    PHASE_4_2,
    PHASE_5_1,
    # Collections
    ALL_PHASES,
    PHASES_BY_ID,
    PHASES_BY_CATEGORY,
    # Functions
    get_phase,
    get_phases_for_category,
    get_phase_count,
    get_typical_scan_duration,
    phase_context,
)


# ═══════════════════════════════════════════════════════════════════════════════
# PhaseCategory Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestPhaseCategory:
    """Tests for PhaseCategory enum."""

    def test_all_categories_exist(self):
        """Test all expected categories exist."""
        assert PhaseCategory.DISCOVERY
        assert PhaseCategory.INTELLIGENCE
        assert PhaseCategory.PREPARATION
        assert PhaseCategory.EXECUTION
        assert PhaseCategory.ANALYSIS
        assert PhaseCategory.VALIDATION
        assert PhaseCategory.REPORTING

    def test_category_values(self):
        """Test category values are strings."""
        assert PhaseCategory.DISCOVERY.value == "discovery"
        assert PhaseCategory.EXECUTION.value == "execution"


# ═══════════════════════════════════════════════════════════════════════════════
# PhaseInfo Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestPhaseInfo:
    """Tests for PhaseInfo dataclass."""

    def test_basic_creation(self):
        """Test basic PhaseInfo creation."""
        phase = PhaseInfo(
            phase_id="test",
            name="Test Phase",
            category=PhaseCategory.DISCOVERY,
        )
        assert phase.phase_id == "test"
        assert phase.name == "Test Phase"
        assert phase.category == PhaseCategory.DISCOVERY

    def test_default_values(self):
        """Test default values are set."""
        phase = PhaseInfo(
            phase_id="test",
            name="Test",
            category=PhaseCategory.DISCOVERY,
        )
        assert phase.description == ""
        assert phase.emoji == ""
        assert phase.min_duration == 0.0
        assert phase.typical_duration == 5.0
        assert phase.max_duration == 60.0
        assert phase.requires_auth is False
        assert phase.can_skip is True

    def test_log_prefix(self):
        """Test log_prefix property."""
        phase = PhaseInfo(
            phase_id="4.2",
            name="Proof Engine",
            category=PhaseCategory.ANALYSIS,
            emoji="💥",
        )
        assert phase.log_prefix == "💥 Phase 4.2: Proof Engine"

    def test_evidence_phase_id(self):
        """Test evidence_phase_id property."""
        phase = PhaseInfo(
            phase_id="4.2",
            name="Exploitation Proof Engine",
            category=PhaseCategory.ANALYSIS,
        )
        assert phase.evidence_phase_id == "4.2_exploitation_proof_engine"


# ═══════════════════════════════════════════════════════════════════════════════
# Phase Constants Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestPhaseConstants:
    """Tests for phase constants."""

    def test_phase_0_exists(self):
        """Test PHASE_0 is defined correctly."""
        assert PHASE_0.phase_id == "0"
        assert PHASE_0.name == "Target Classification"
        assert PHASE_0.category == PhaseCategory.DISCOVERY
        assert PHASE_0.emoji == "🎯"

    def test_phase_3_exists(self):
        """Test PHASE_3 is defined correctly."""
        assert PHASE_3.phase_id == "3"
        assert PHASE_3.name == "Module Execution"
        assert PHASE_3.category == PhaseCategory.EXECUTION
        assert PHASE_3.can_skip is False

    def test_all_phases_list(self):
        """Test ALL_PHASES contains all phases."""
        assert len(ALL_PHASES) >= 30  # We have 41 phases
        assert PHASE_0 in ALL_PHASES
        assert PHASE_3 in ALL_PHASES

    def test_phases_by_id(self):
        """Test PHASES_BY_ID lookup."""
        assert "0" in PHASES_BY_ID
        assert "4.2" in PHASES_BY_ID
        assert PHASES_BY_ID["0"] == PHASE_0

    def test_phases_by_category(self):
        """Test PHASES_BY_CATEGORY grouping."""
        assert PhaseCategory.DISCOVERY in PHASES_BY_CATEGORY
        assert PhaseCategory.EXECUTION in PHASES_BY_CATEGORY
        discovery_phases = PHASES_BY_CATEGORY[PhaseCategory.DISCOVERY]
        assert len(discovery_phases) >= 2


class TestPhaseFunctions:
    """Tests for phase utility functions."""

    def test_get_phase_existing(self):
        """Test get_phase with existing phase."""
        phase = get_phase("0")
        assert phase is not None
        assert phase.phase_id == "0"

    def test_get_phase_nonexistent(self):
        """Test get_phase with nonexistent phase."""
        phase = get_phase("999")
        assert phase is None

    def test_get_phases_for_category(self):
        """Test get_phases_for_category."""
        discovery = get_phases_for_category(PhaseCategory.DISCOVERY)
        assert len(discovery) >= 2
        for phase in discovery:
            assert phase.category == PhaseCategory.DISCOVERY

    def test_get_phase_count(self):
        """Test get_phase_count."""
        count = get_phase_count()
        assert count >= 30
        assert count == len(ALL_PHASES)

    def test_get_typical_scan_duration(self):
        """Test get_typical_scan_duration."""
        duration = get_typical_scan_duration()
        assert duration > 0
        # Should be sum of all typical_duration values
        expected = sum(p.typical_duration for p in ALL_PHASES)
        assert duration == expected


# ═══════════════════════════════════════════════════════════════════════════════
# PhaseExecution Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestPhaseExecution:
    """Tests for PhaseExecution dataclass."""

    def test_basic_creation(self):
        """Test basic creation."""
        execution = PhaseExecution(
            phase_id="0",
            phase_info=PHASE_0,
            start_time=time.time(),
        )
        assert execution.phase_id == "0"
        assert execution.status == "running"
        assert execution.end_time is None

    def test_duration_while_running(self):
        """Test duration calculation while running."""
        start = time.time()
        execution = PhaseExecution(
            phase_id="0",
            phase_info=PHASE_0,
            start_time=start,
        )
        time.sleep(0.01)
        assert execution.duration >= 0.01

    def test_duration_when_complete(self):
        """Test duration calculation when complete."""
        start = time.time()
        execution = PhaseExecution(
            phase_id="0",
            phase_info=PHASE_0,
            start_time=start,
            end_time=start + 5.0,
        )
        assert execution.duration == 5.0

    def test_complete_method(self):
        """Test complete() method."""
        execution = PhaseExecution(
            phase_id="0",
            phase_info=PHASE_0,
            start_time=time.time(),
        )
        execution.complete("completed")
        assert execution.status == "completed"
        assert execution.end_time is not None

    def test_is_slow(self):
        """Test is_slow property."""
        # Not slow
        execution = PhaseExecution(
            phase_id="0",
            phase_info=PHASE_0,
            start_time=time.time(),
            end_time=time.time() + 1.0,  # 1 second
        )
        assert execution.is_slow is False

        # Slow (exceeds max_duration)
        execution_slow = PhaseExecution(
            phase_id="0",
            phase_info=PHASE_0,
            start_time=time.time(),
            end_time=time.time() + 100.0,  # 100 seconds > max_duration
        )
        assert execution_slow.is_slow is True


# ═══════════════════════════════════════════════════════════════════════════════
# PhaseTracker Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestPhaseTracker:
    """Tests for PhaseTracker class."""

    def test_init(self):
        """Test tracker initialization."""
        tracker = PhaseTracker(target="https://example.com")
        assert tracker.target == "https://example.com"
        assert tracker.current_phase is None
        assert tracker.scan_duration == 0.0

    def test_start_scan(self):
        """Test start_scan method."""
        tracker = PhaseTracker()
        tracker.start_scan()
        assert tracker._scan_start is not None

    def test_end_scan(self):
        """Test end_scan method."""
        tracker = PhaseTracker()
        tracker.start_scan()
        time.sleep(0.01)
        tracker.end_scan()
        assert tracker._scan_end is not None
        assert tracker.scan_duration >= 0.01

    def test_start_phase(self):
        """Test start_phase method."""
        tracker = PhaseTracker()
        execution = tracker.start_phase("0")

        assert execution.phase_id == "0"
        assert execution.status == "running"
        assert tracker.current_phase == "0"

    def test_end_phase(self):
        """Test end_phase method."""
        tracker = PhaseTracker()
        tracker.start_phase("0")
        execution = tracker.end_phase("0")

        assert execution is not None
        assert execution.status == "completed"
        assert tracker.current_phase is None

    def test_end_phase_not_started(self):
        """Test end_phase for phase that wasn't started."""
        tracker = PhaseTracker()
        execution = tracker.end_phase("999")
        assert execution is None

    def test_skip_phase(self):
        """Test skip_phase method."""
        tracker = PhaseTracker()
        execution = tracker.skip_phase("0.75", reason="Not enabled")

        assert execution.phase_id == "0.75"
        assert execution.status == "skipped"
        assert execution.metadata["skip_reason"] == "Not enabled"

    def test_fail_phase(self):
        """Test fail_phase method."""
        tracker = PhaseTracker()
        tracker.start_phase("0")
        execution = tracker.fail_phase("0", "Connection error")

        assert execution.status == "failed"
        assert execution.error == "Connection error"

    def test_get_execution(self):
        """Test get_execution method."""
        tracker = PhaseTracker()
        tracker.start_phase("0")

        execution = tracker.get_execution("0")
        assert execution is not None
        assert execution.phase_id == "0"

        none_execution = tracker.get_execution("999")
        assert none_execution is None

    def test_get_all_executions(self):
        """Test get_all_executions method."""
        tracker = PhaseTracker()
        tracker.start_phase("0")
        tracker.end_phase("0")
        tracker.start_phase("0.5")
        tracker.end_phase("0.5")

        executions = tracker.get_all_executions()
        assert len(executions) == 2

    def test_get_stats(self):
        """Test get_stats method."""
        tracker = PhaseTracker()
        tracker.start_scan()
        tracker.start_phase("0")
        tracker.end_phase("0")
        tracker.skip_phase("0.75", "disabled")
        tracker.start_phase("1")
        tracker.fail_phase("1", "error")
        tracker.end_scan()

        stats = tracker.get_stats()
        assert stats["total_phases"] == 3
        assert stats["completed"] == 1
        assert stats["skipped"] == 1
        assert stats["failed"] == 1
        assert len(stats["failed_phases"]) == 1

    def test_get_timeline(self):
        """Test get_timeline method."""
        tracker = PhaseTracker()
        tracker.start_phase("0")
        tracker.end_phase("0")
        tracker.start_phase("0.5")
        tracker.end_phase("0.5")

        timeline = tracker.get_timeline()
        assert len(timeline) == 2
        assert timeline[0]["phase_id"] == "0"
        assert timeline[1]["phase_id"] == "0.5"

    def test_evidence_engine_integration(self):
        """Test evidence engine integration."""
        mock_evidence = Mock()
        tracker = PhaseTracker(
            target="https://example.com",
            evidence_engine=mock_evidence,
        )

        tracker.start_phase("0")
        mock_evidence.add_timeline_event.assert_called()

        tracker.end_phase("0")
        assert mock_evidence.add_timeline_event.call_count >= 2

    def test_progress_callback(self):
        """Test progress callback integration."""
        callback = Mock()
        tracker = PhaseTracker(progress_callback=callback)

        tracker.start_phase("0")
        callback.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════════
# PhaseContext Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestPhaseContext:
    """Tests for PhaseContext context manager."""

    def test_basic_usage(self):
        """Test basic context manager usage."""
        tracker = PhaseTracker()

        with phase_context(tracker, "0") as execution:
            assert execution.status == "running"
            assert tracker.current_phase == "0"

        assert tracker.current_phase is None
        completed = tracker.get_execution("0")
        assert completed.status == "completed"

    def test_with_metadata(self):
        """Test context manager with metadata."""
        tracker = PhaseTracker()

        with phase_context(tracker, "0", metadata={"key": "value"}) as execution:
            execution.metadata["findings"] = 5

        completed = tracker.get_execution("0")
        assert completed.metadata.get("key") == "value"
        assert completed.metadata.get("findings") == 5

    def test_exception_handling(self):
        """Test context manager handles exceptions."""
        tracker = PhaseTracker()

        with pytest.raises(ValueError):
            with phase_context(tracker, "0"):
                raise ValueError("Test error")

        failed = tracker.get_execution("0")
        assert failed.status == "failed"
        assert "Test error" in failed.error


# ═══════════════════════════════════════════════════════════════════════════════
# Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestPhaseExecutorIntegration:
    """Integration tests for phase executor."""

    def test_full_scan_simulation(self):
        """Test simulating a full scan with phase tracking."""
        tracker = PhaseTracker(target="https://example.com")
        tracker.start_scan()

        # Phase 0: Classification
        tracker.start_phase("0")
        tracker.end_phase("0", metadata={"target_type": "api"})

        # Phase 0.5: Tech Intelligence
        tracker.start_phase("0.5")
        tracker.end_phase("0.5", metadata={"technologies": ["python", "django"]})

        # Phase 3: Module Execution
        tracker.start_phase("3")
        tracker.end_phase("3", metadata={"modules_run": 50})

        # Phase 5.1: Validation
        tracker.start_phase("5.1")
        tracker.end_phase("5.1", metadata={"validated": 10})

        tracker.end_scan()

        stats = tracker.get_stats()
        assert stats["completed"] == 4
        assert stats["scan_duration"] > 0

        timeline = tracker.get_timeline()
        assert len(timeline) == 4
        assert timeline[0]["phase_id"] == "0"

    def test_category_distribution(self):
        """Test that phases are properly distributed across categories."""
        discovery_count = len(get_phases_for_category(PhaseCategory.DISCOVERY))
        execution_count = len(get_phases_for_category(PhaseCategory.EXECUTION))
        analysis_count = len(get_phases_for_category(PhaseCategory.ANALYSIS))

        assert discovery_count >= 3
        assert execution_count >= 2
        assert analysis_count >= 10  # Most phases are analysis
