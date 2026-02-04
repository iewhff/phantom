"""
Tests for core/state_manager.py

Tests checkpoint save/load functionality with secure JSON serialization.
Verifies that pickle vulnerabilities are properly mitigated.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Import after path setup in conftest
from core.state_manager import StateManager, ScanStatus


class TestStateManager:
    """Tests for StateManager class."""

    @pytest.fixture
    def state_manager(self, mock_settings, temp_dir):
        """Create StateManager with temp directory."""
        with patch.object(StateManager, '__init__', lambda self, s: None):
            manager = StateManager.__new__(StateManager)
            manager.settings = mock_settings
            manager.state_dir = temp_dir / "scans"
            manager.state_dir.mkdir(parents=True, exist_ok=True)
            return manager

    @pytest.fixture
    def mock_context(self):
        """Create mock ScanContext."""
        context = MagicMock()
        context.target = "http://example.com"
        context.findings = [{"name": "Test Finding"}]
        context.assets = {"http://example.com": {"ports": [80]}}
        context.__dict__ = {
            "target": "http://example.com",
            "findings": [{"name": "Test Finding"}],
            "assets": {"http://example.com": {"ports": [80]}},
        }
        return context

    @pytest.fixture
    def mock_phase(self):
        """Create mock ScanPhase."""
        phase = MagicMock()
        phase.name = "SCANNING"
        phase.value = 3
        return phase

    def test_save_checkpoint_creates_json_file(
        self, state_manager, mock_context, mock_phase
    ):
        """Test that checkpoint saves as JSON (not pickle)."""
        scan_id = "test-scan-001"

        with patch.object(state_manager, '_update_scan_status'):
            result = state_manager.save_checkpoint(
                scan_id, mock_phase, mock_context
            )

        # Verify JSON file created (not .pkl)
        assert result.suffix == ".json"
        assert result.exists()

        # Verify content is valid JSON
        with open(result) as f:
            data = json.load(f)

        assert "version" in data
        assert data["version"] == "2.0"
        assert "signature" in data
        assert "context" in data

    def test_save_checkpoint_includes_hmac_signature(
        self, state_manager, mock_context, mock_phase
    ):
        """Test that checkpoint includes HMAC signature for integrity."""
        scan_id = "test-scan-002"

        with patch.object(state_manager, '_update_scan_status'):
            result = state_manager.save_checkpoint(
                scan_id, mock_phase, mock_context
            )

        with open(result) as f:
            data = json.load(f)

        # Signature should be 64 char hex (SHA256)
        assert len(data["signature"]) == 64
        assert all(c in "0123456789abcdef" for c in data["signature"])

    def test_load_checkpoint_verifies_signature(
        self, state_manager, mock_context, mock_phase
    ):
        """Test that loading verifies HMAC signature."""
        scan_id = "test-scan-003"

        with patch.object(state_manager, '_update_scan_status'):
            state_manager.save_checkpoint(scan_id, mock_phase, mock_context)

        # Load should succeed with valid signature
        with patch.object(state_manager, '_find_latest_phase', return_value=mock_phase):
            context, phase = state_manager.load_checkpoint(scan_id)

        assert context is not None
        assert phase is not None

    def test_load_checkpoint_rejects_tampered_data(
        self, state_manager, mock_context, mock_phase
    ):
        """Test that tampered checkpoints are rejected."""
        scan_id = "test-scan-004"

        with patch.object(state_manager, '_update_scan_status'):
            result = state_manager.save_checkpoint(
                scan_id, mock_phase, mock_context
            )

        # Tamper with the file
        with open(result, 'r') as f:
            data = json.load(f)

        data["context"]["target"] = "http://evil.com"  # Tamper

        with open(result, 'w') as f:
            json.dump(data, f)

        # Load should fail due to signature mismatch
        with patch.object(state_manager, '_find_latest_phase', return_value=mock_phase):
            context, phase = state_manager.load_checkpoint(scan_id)

        assert context is None
        assert phase is None

    def test_no_pickle_files_created(
        self, state_manager, mock_context, mock_phase, temp_dir
    ):
        """Verify no .pkl files are created (security requirement)."""
        scan_id = "test-scan-005"

        with patch.object(state_manager, '_update_scan_status'):
            state_manager.save_checkpoint(scan_id, mock_phase, mock_context)

        # Check no pickle files exist
        pkl_files = list((temp_dir / "scans").rglob("*.pkl"))
        assert len(pkl_files) == 0

    def test_load_rejects_old_pickle_files(
        self, state_manager, mock_phase, temp_dir
    ):
        """Test that old pickle files are not loaded (security)."""
        scan_id = "test-scan-006"

        # Create a fake old pickle file
        checkpoint_dir = temp_dir / "scans" / scan_id
        checkpoint_dir.mkdir(parents=True)

        pkl_path = checkpoint_dir / f"context_{mock_phase.value}.pkl"
        pkl_path.write_bytes(b"fake pickle data")

        # Should refuse to load pickle
        with patch.object(state_manager, '_find_latest_phase', return_value=mock_phase):
            context, phase = state_manager.load_checkpoint(scan_id)

        assert context is None

    def test_serialize_context_handles_complex_objects(self, state_manager):
        """Test serialization of complex nested objects."""
        context = MagicMock()
        context.__dict__ = {
            "simple": "string",
            "number": 42,
            "nested": {"key": "value"},
            "list_data": [1, 2, 3],
            "complex_obj": object(),  # Non-serializable
        }

        result = state_manager._serialize_context(context)

        assert result["simple"] == "string"
        assert result["number"] == 42
        assert result["nested"] == {"key": "value"}
        assert result["list_data"] == [1, 2, 3]
        # Complex object should be converted to string
        assert isinstance(result["complex_obj"], str)


class TestScanStatus:
    """Tests for ScanStatus enum."""

    def test_status_values(self):
        """Test all status values exist."""
        assert ScanStatus.PENDING.value == "pending"
        assert ScanStatus.RUNNING.value == "running"
        assert ScanStatus.PAUSED.value == "paused"
        assert ScanStatus.COMPLETED.value == "completed"
        assert ScanStatus.FAILED.value == "failed"
        assert ScanStatus.CANCELLED.value == "cancelled"


class TestSignatureVerification:
    """Tests for HMAC signature functionality."""

    @pytest.fixture
    def state_manager(self, mock_settings, temp_dir):
        """Create StateManager for signature tests."""
        with patch.object(StateManager, '__init__', lambda self, s: None):
            manager = StateManager.__new__(StateManager)
            manager.settings = mock_settings
            manager.state_dir = temp_dir / "scans"
            manager.state_dir.mkdir(parents=True, exist_ok=True)
            return manager

    def test_compute_signature_deterministic(self, state_manager):
        """Test that signature computation is deterministic."""
        data = '{"test": "data"}'

        sig1 = state_manager._compute_signature(data)
        sig2 = state_manager._compute_signature(data)

        assert sig1 == sig2

    def test_different_data_different_signature(self, state_manager):
        """Test that different data produces different signatures."""
        sig1 = state_manager._compute_signature('{"a": 1}')
        sig2 = state_manager._compute_signature('{"a": 2}')

        assert sig1 != sig2

    def test_verify_signature_valid(self, state_manager):
        """Test verification of valid signature."""
        data = '{"test": "data"}'
        signature = state_manager._compute_signature(data)

        assert state_manager._verify_signature(data, signature) is True

    def test_verify_signature_invalid(self, state_manager):
        """Test rejection of invalid signature."""
        data = '{"test": "data"}'
        wrong_signature = "a" * 64

        assert state_manager._verify_signature(data, wrong_signature) is False
