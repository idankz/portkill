"""Unit tests for portkill scanning, safety guards, and process resolution."""
import pytest
from unittest.mock import MagicMock, patch

from portkill.process import (
    CRITICAL_SYSTEM_PORTS,
    ContainerInfo,
    ProcessInfo,
    inspect_docker,
    is_critical,
    terminate_process,
)
from portkill.scanner import COMMON_DEV_PORTS, PortListener, scan_ports


def test_dev_ports_coverage():
    """Ensure standard web and database ports are included in COMMON_DEV_PORTS."""
    must_have = {3000, 5173, 8000, 8080, 5432, 6379, 27017, 3306}
    assert must_have.issubset(COMMON_DEV_PORTS)


def test_is_critical_checks():
    """Verify safety guards protect critical system ports and PID 1."""
    # Critical ports
    crit, reason = is_critical(22)
    assert crit is True
    assert "SSH" in reason or "22" in reason

    crit, reason = is_critical(53)
    assert crit is True

    # PID 1
    crit, reason = is_critical(3000, pid=1)
    assert crit is True
    assert "PID 1" in reason

    # Critical OS process name
    crit, reason = is_critical(3000, pid=999, proc_name="systemd")
    assert crit is True
    assert "critical operating system component" in reason

    # Non-critical normal dev server
    crit, reason = is_critical(3000, pid=1234, proc_name="node")
    assert crit is False
    assert reason == ""


def test_docker_proxy_inspection():
    """Verify docker-proxy inspection parses container IP and port correctly."""
    mock_proc = MagicMock()
    mock_proc.name.return_value = "docker-proxy"

    cmdline = [
        "/usr/bin/docker-proxy",
        "-proto", "tcp",
        "-host-ip", "0.0.0.0",
        "-host-port", "8080",
        "-container-ip", "172.17.0.2",
        "-container-port", "80"
    ]
    info = inspect_docker(mock_proc, cmdline)
    assert info.is_container is True
    assert info.runtime == "docker-proxy"
    assert "172.17.0.2:80" in info.container_name


def test_terminate_process_flow():
    """Verify terminate_process handles graceful wait and escalation."""
    with patch("portkill.process.psutil.Process") as mock_psutil_proc:
        mock_instance = MagicMock()
        mock_psutil_proc.return_value = mock_instance

        # Test force kill
        ok, msg = terminate_process(1234, force=True)
        assert ok is True
        mock_instance.kill.assert_called_once()
        assert "forced" in msg

        # Test graceful kill
        mock_instance.reset_mock()
        ok, msg = terminate_process(1234, force=False, timeout_ms=50)
        assert ok is True
        mock_instance.terminate.assert_called_once()
        mock_instance.wait.assert_called_once()
