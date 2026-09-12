"""
Tests for RPP.1 — Password Complexity & Expiry
================================================
Proves the parsing logic and ERROR vs FAIL distinction,
not just "it runs".

Usage:
    pytest tests/test_rpp1.py -v
"""

from unittest.mock import patch, MagicMock
import pytest

from msme_auditor.core.command_runner import CommandResult
from msme_auditor.core.policy_loader import load_policy


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def policy():
    """Load the default policy for tests."""
    return load_policy()


@pytest.fixture
def mock_run_command():
    """Patch run_command for controlled test scenarios."""
    with patch("msme_auditor.scanners.rpp.rpp1.run_command") as mock:
        yield mock


# =============================================================================
# Windows Scanner Tests
# =============================================================================

class TestWindowsScanner:
    """Test Windows password policy scanning."""

    @patch("msme_auditor.scanners.rpp.rpp1.RPP1Scanner._check_windows_complexity")
    @patch("msme_auditor.scanners.rpp.rpp1.run_command")
    def test_strong_policy_passes(self, mock_run, mock_complexity, policy):
        """Strong Windows policy should pass all checks."""
        mock_run.return_value = CommandResult(
            success=True,
            stdout=(
                "Minimum password length:              12\n"
                "Maximum password age (days):          60\n"
                "Minimum password age (days):          1\n"
                "Length of password history remembered: 5\n"
            ),
            stderr="",
            returncode=0,
        )
        mock_complexity.return_value = True

        from msme_auditor.scanners.rpp.rpp1 import RPP1Scanner
        scanner = RPP1Scanner()
        result = scanner._scan_windows(policy)

        # All checks should pass except education (manual input, always fails in OS scans)
        non_edu = [c for c in result if c.check_id != "education"]
        assert all(c.passed for c in non_edu)
        assert len(result) == 8

    @patch("msme_auditor.scanners.rpp.rpp1.run_command")
    def test_weak_policy_fails(self, mock_run, policy):
        """Weak Windows policy should fail relevant checks."""
        mock_run.return_value = CommandResult(
            success=True,
            stdout=(
                "Minimum password length:              4\n"
                "Maximum password age (days):          Never\n"
                "Minimum password age (days):          0\n"
                "Length of password history remembered: 0\n"
            ),
            stderr="",
            returncode=0,
        )

        from msme_auditor.scanners.rpp.rpp1 import RPP1Scanner
        scanner = RPP1Scanner()
        result = scanner._scan_windows(policy)

        # min_length check should FAIL
        min_len_check = next(c for c in result if c.check_id == "min_length")
        assert not min_len_check.passed
        assert "4 characters" in min_len_check.actual_value

        # expiry check should FAIL
        expiry_check = next(c for c in result if c.check_id == "expiry")
        assert not expiry_check.passed

    @patch("msme_auditor.scanners.rpp.rpp1.run_command")
    def test_command_failure_returns_error(self, mock_run, policy):
        """Command failure should return ERROR, not FAIL."""
        mock_run.return_value = CommandResult(
            success=False, stdout="", stderr="Access denied", returncode=1,
            error="permission_denied"
        )

        from msme_auditor.scanners.rpp.rpp1 import RPP1Scanner
        scanner = RPP1Scanner()
        result = scanner._scan_windows(policy)

        # Should return exactly 1 check: scan_error
        assert len(result) == 1
        assert result[0].check_id == "scan_error"
        assert not result[0].passed
        assert "permission" in result[0].actual_value.lower()


# =============================================================================
# Linux Scanner Tests
# =============================================================================

class TestLinuxScanner:
    """Test Linux password policy scanning."""

    @patch("msme_auditor.scanners.rpp.rpp1.Path")
    def test_strong_linux_policy(self, MockPath, policy):
        """Strong Linux policy should pass."""
        from pathlib import Path as RealPath

        def path_exists(path_val):
            return str(path_val) in [
                "/etc/security/pwquality.conf",
                "/etc/login.defs",
            ]

        def make_path(path_val):
            instance = MagicMock(spec=RealPath)
            instance.__str__ = lambda s: path_val
            instance.exists.return_value = path_exists(path_val)
            if path_val == "/etc/security/pwquality.conf":
                instance.read_text.return_value = "minlen = 12\nucredit = -1\nlcredit = -1\ndcredit = -1\nocredit = -1\n"
            elif path_val == "/etc/login.defs":
                instance.read_text.return_value = "PASS_MAX_DAYS  60\nPASS_MIN_DAYS  1\n"
            return instance

        MockPath.side_effect = make_path

        from msme_auditor.scanners.rpp.rpp1 import RPP1Scanner
        scanner = RPP1Scanner()
        result = scanner._scan_linux(policy)

        min_len_check = next(c for c in result if c.check_id == "min_length")
        assert min_len_check.passed

    @patch("msme_auditor.scanners.rpp.rpp1.Path")
    def test_missing_config_files(self, MockPath, policy):
        """Missing config files should return checks with detected=Nothing."""
        instance = MagicMock()
        instance.exists.return_value = False
        MockPath.return_value = instance

        from msme_auditor.scanners.rpp.rpp1 import RPP1Scanner
        scanner = RPP1Scanner()
        result = scanner._scan_linux(policy)

        # Should get a scan_error because min_len is None
        scan_error = next((c for c in result if c.check_id == "scan_error"), None)
        assert scan_error is not None
        assert not scan_error.passed


# =============================================================================
# Source Code Scanner Tests
# =============================================================================

class TestSourceCodeScanner:
    """Test source code scanning for password policy enforcement."""

    def test_valid_validators_pass(self):
        """Source code with all checks should pass."""
        from pathlib import Path
        import tempfile
        import os

        with tempfile.TemporaryDirectory() as tmpdir:
            auth_dir = Path(tmpdir) / "auth"
            auth_dir.mkdir()
            validators_file = auth_dir / "validators.py"
            validators_file.write_text('''
import bcrypt

def validate_password(password, password_history):
    if len(password) >= 8:
        raise ValueError("Password too short")
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    if password in password_history:
        raise ValueError("Password already used")
    return hashed
''')

            from msme_auditor.scanners.rpp.rpp1 import RPP1Scanner
            scanner = RPP1Scanner()
            result = scanner.scan_source_code(tmpdir)

            assert len(result) == 1
            assert result[0].passed

    def test_missing_validators_returns_error(self):
        """Missing validators file should return error."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            from msme_auditor.scanners.rpp.rpp1 import RPP1Scanner
            scanner = RPP1Scanner()
            result = scanner.scan_source_code(tmpdir)

            assert len(result) == 1
            assert result[0].check_id == "scan_error"
            assert not result[0].passed


# =============================================================================
# Policy Loader Tests
# =============================================================================

class TestPolicyLoader:
    """Test config-driven policy loading."""

    def test_load_default_policy(self):
        """Default policy should load successfully."""
        policy = load_policy()
        assert "min_length" in policy
        assert "max_password_age_days" in policy
        assert "password_history_count" in policy
        assert policy["min_length"] >= 8
        assert policy["max_password_age_days"] <= 90

    def test_missing_policy_raises_error(self):
        """Missing policy file should raise FileNotFoundError."""
        from msme_auditor.core.policy_loader import load_policy_for
        with pytest.raises(FileNotFoundError):
            load_policy_for("rpp1", path="/nonexistent/policy.yaml")


# =============================================================================
# Command Runner Tests
# =============================================================================

class TestCommandRunner:
    """Test safe subprocess wrapper."""

    def test_successful_command(self):
        """Successful command should return success=True."""
        from msme_auditor.core.command_runner import run_command
        result = run_command(["echo", "hello"])
        assert result.success
        assert "hello" in result.stdout

    def test_failed_command(self):
        """Failed command should return success=False with error info."""
        from msme_auditor.core.command_runner import run_command
        result = run_command(["false"])
        assert not result.success
        assert result.returncode != 0

    def test_missing_binary(self):
        """Missing binary should return error='binary_not_found'."""
        from msme_auditor.core.command_runner import run_command
        result = run_command(["nonexistent_binary_xyz_123"])
        assert not result.success
        assert result.error == "binary_not_found"

    def test_timeout(self):
        """Command exceeding timeout should return error='timeout'."""
        from msme_auditor.core.command_runner import run_command
        result = run_command(["sleep", "10"], timeout=1)
        assert not result.success
        assert result.error == "timeout"
