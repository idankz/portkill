"""Unit tests for portkill scanning, safety guards, and process resolution."""
import psutil
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


def test_parse_lsof_output():
    """lsof field output yields IPv4, IPv6 and wildcard listeners, skipping peers."""
    from portkill.scanner import parse_lsof_output

    sockets = parse_lsof_output(
        "p101\nf12\nn127.0.0.1:3000\nf13\nn[::1]:3000\np202\nf5\nn*:8080\nf6\nn10.0.0.1:5000->10.0.0.2:80\n"
    )
    assert [(s.ip, s.port, s.pid) for s in sockets] == [
        ("127.0.0.1", 3000, 101),
        ("::1", 3000, 101),
        ("*", 8080, 202),
    ]


def test_scan_falls_back_to_lsof_when_psutil_denied():
    """An AccessDenied from psutil (macOS without root) must not look like an empty port."""
    from portkill.scanner import RawSocket

    with patch("portkill.scanner.psutil.net_connections", side_effect=psutil.AccessDenied()), \
         patch("portkill.scanner.shutil.which", return_value="/usr/sbin/lsof"), \
         patch("portkill.scanner._lsof_sockets", return_value=[RawSocket("127.0.0.1", 3000, 101, "LISTEN")]), \
         patch("portkill.scanner.get_process_info", return_value=None):
        listeners = scan_ports(ports_filter={3000}, protocol_filter="tcp")
    assert [(l.port, l.pid) for l in listeners] == [(3000, 101)]


def test_scan_raises_when_denied_without_fallback():
    """With no lsof available the permission failure is reported, not swallowed."""
    from portkill.scanner import ScanPermissionError

    with patch("portkill.scanner.psutil.net_connections", side_effect=psutil.AccessDenied()), \
         patch("portkill.scanner.shutil.which", return_value=None):
        with pytest.raises(ScanPermissionError):
            scan_ports(ports_filter={3000}, protocol_filter="tcp")


def test_free_port_is_success():
    """`portkill 3000 && npm run dev` must proceed when the port is already free."""
    from portkill.cli import kill_port_target

    with patch("portkill.cli.find_listener_by_port", return_value=[]):
        assert kill_port_target(3000) is True


def test_details_survive_markup_in_command_line():
    """A command line containing Rich-style tags must print, not crash."""
    from portkill.ui import render_process_details

    proc = ProcessInfo(pid=1234, name="node", cmdline=["node", "--flag=[/x]"])
    render_process_details(PortListener(3000, "TCP", "127.0.0.1", 1234, "LISTEN", proc))
