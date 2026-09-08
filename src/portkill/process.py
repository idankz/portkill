"""Process management, metadata inspection, Docker awareness, and termination handling."""
from __future__ import annotations

import os
import signal
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Tuple

import psutil

CRITICAL_SYSTEM_PORTS = {
    20, 21,    # FTP
    22,        # SSH
    23,        # Telnet
    25,        # SMTP
    53,        # DNS
    67, 68,    # DHCP
    123,       # NTP
    137, 138, 139, 445, # SMB/NetBIOS
    161,       # SNMP
    389, 636,  # LDAP
}

CRITICAL_SYSTEM_PROCESSES = {
    "systemd", "init", "sshd", "launchd", "csrss.exe", "smss.exe", "wininit.exe", "services.exe", "lsass.exe"
}


@dataclass
class ContainerInfo:
    is_container: bool = False
    runtime: Optional[str] = None
    container_id: Optional[str] = None
    container_name: Optional[str] = None


@dataclass
class ProcessInfo:
    pid: int
    name: str
    username: Optional[str] = None
    cmdline: List[str] = field(default_factory=list)
    cpu_percent: float = 0.0
    memory_rss_bytes: int = 0
    create_time: float = 0.0
    ppid: Optional[int] = None
    parent_name: Optional[str] = None
    container: ContainerInfo = field(default_factory=ContainerInfo)

    @property
    def cmdline_str(self) -> str:
        if self.cmdline:
            return " ".join(self.cmdline)
        return self.name

    @property
    def memory_mb(self) -> float:
        return self.memory_rss_bytes / (1024 * 1024)

    @property
    def uptime_str(self) -> str:
        if self.create_time <= 0:
            return "unknown"
        uptime_seconds = int(time.time() - self.create_time)
        if uptime_seconds < 0:
            return "just started"
        hours, remainder = divmod(uptime_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours > 0:
            return f"{hours}h {minutes}m"
        if minutes > 0:
            return f"{minutes}m {seconds}s"
        return f"{seconds}s"


def inspect_docker(proc: psutil.Process, cmdline: List[str]) -> ContainerInfo:
    """Inspect if the process is docker-proxy, containerd, or part of a container."""
    name = proc.name().lower()
    cmd_str = " ".join(cmdline)

    if "docker-proxy" in name or "docker-proxy" in cmd_str:
        # docker-proxy often has args: -container-ip 172.17.0.2 -container-port 80 -host-port 8080
        container_ip = ""
        container_port = ""
        for i, arg in enumerate(cmdline):
            if arg == "-container-ip" and i + 1 < len(cmdline):
                container_ip = cmdline[i + 1]
            elif arg == "-container-port" and i + 1 < len(cmdline):
                container_port = cmdline[i + 1]

        target = f"{container_ip}:{container_port}" if container_ip else "Docker Bridge"
        return ContainerInfo(
            is_container=True,
            runtime="docker-proxy",
            container_id=None,
            container_name=f"Docker Container -> {target}",
        )

    if "containerd-shim" in name or "containerd-shim" in cmd_str:
        # containerd-shim often passes -id <hash>
        cid = None
        for i, arg in enumerate(cmdline):
            if arg in ("-id", "--id") and i + 1 < len(cmdline):
                cid = cmdline[i + 1][:12]
        return ContainerInfo(
            is_container=True,
            runtime="containerd",
            container_id=cid,
            container_name=f"Container ({cid})" if cid else "Containerd Shim",
        )

    # Check Linux cgroup if available
    try:
        cgroup_path = f"/proc/{proc.pid}/cgroup"
        if os.path.exists(cgroup_path):
            with open(cgroup_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                if "docker" in content:
                    for line in content.splitlines():
                        if "docker" in line:
                            parts = line.split("/")
                            cid = parts[-1][:12] if parts else None
                            return ContainerInfo(
                                is_container=True,
                                runtime="docker",
                                container_id=cid,
                                container_name=f"Container ({cid})",
                            )
                elif "kubepods" in content:
                    return ContainerInfo(
                        is_container=True,
                        runtime="kubernetes",
                        container_name="Kubernetes Pod",
                    )
    except Exception:
        pass

    return ContainerInfo(is_container=False)


def get_process_info(pid: int) -> Optional[ProcessInfo]:
    """Retrieve process info safely using psutil."""
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            name = proc.name()
            try:
                username = proc.username()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                username = "unknown"

            try:
                cmdline = proc.cmdline()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cmdline = []

            try:
                mem = proc.memory_info().rss
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                mem = 0

            try:
                cpu = proc.cpu_percent(interval=0.0)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cpu = 0.0

            try:
                ctime = proc.create_time()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                ctime = 0.0

            try:
                ppid = proc.ppid()
                parent_proc = proc.parent()
                parent_name = parent_proc.name() if parent_proc else None
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                ppid = None
                parent_name = None

            container_info = inspect_docker(proc, cmdline)

            return ProcessInfo(
                pid=pid,
                name=name,
                username=username,
                cmdline=cmdline,
                cpu_percent=cpu,
                memory_rss_bytes=mem,
                create_time=ctime,
                ppid=ppid,
                parent_name=parent_name,
                container=container_info,
            )
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return None
    except psutil.AccessDenied:
        return ProcessInfo(
            pid=pid,
            name="<Access Denied>",
            username="<Restricted>",
            cmdline=[],
        )


def is_critical(port: int, pid: Optional[int] = None, proc_name: Optional[str] = None) -> Tuple[bool, str]:
    """Check if the port or process is considered critical system infrastructure."""
    if pid == 1:
        return True, "PID 1 (init / systemd / system init)"

    if port in CRITICAL_SYSTEM_PORTS:
        return True, f"Port {port} is a standard critical system service port (e.g., SSH/DNS/DHCP)"

    if port < 1024 and port not in (80, 443):
        return True, f"Port {port} is a privileged system port (< 1024)"

    if proc_name and proc_name.lower() in CRITICAL_SYSTEM_PROCESSES:
        return True, f"Process '{proc_name}' is a critical operating system component"

    return False, ""


def terminate_process(
    pid: int,
    force: bool = False,
    timeout_ms: int = 500,
) -> Tuple[bool, str]:
    """
    Terminates a process safely.
    Tries SIGTERM first, checks if dead after timeout_ms, and escalates to SIGKILL.
    If force=True, sends SIGKILL directly.
    """
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return True, f"Process {pid} already stopped."
    except psutil.AccessDenied:
        return False, f"Permission denied accessing PID {pid}."

    if force:
        try:
            proc.kill()
            return True, f"Process {pid} forced to terminate (SIGKILL)."
        except psutil.NoSuchProcess:
            return True, f"Process {pid} already terminated."
        except psutil.AccessDenied:
            return False, f"Permission denied killing PID {pid}."
        except Exception as e:
            return False, str(e)

    # Graceful attempt: SIGTERM
    try:
        proc.terminate()
    except psutil.NoSuchProcess:
        return True, f"Process {pid} already terminated."
    except psutil.AccessDenied:
        return False, f"Permission denied terminating PID {pid}."
    except Exception as e:
        return False, str(e)

    # Wait for process to exit
    wait_time = timeout_ms / 1000.0
    try:
        proc.wait(timeout=wait_time)
        return True, f"Process {pid} terminated gracefully."
    except psutil.TimeoutExpired:
        # Escalate to SIGKILL
        try:
            proc.kill()
            proc.wait(timeout=1.0)
            return True, f"Process {pid} did not respond to SIGTERM in {timeout_ms}ms. Force killed (SIGKILL)."
        except psutil.NoSuchProcess:
            return True, f"Process {pid} terminated."
        except psutil.AccessDenied:
            return False, f"SIGTERM sent, but lacked permissions to escalate to SIGKILL for PID {pid}."
        except Exception as e:
            return False, f"Error force killing PID {pid}: {e}"
    except psutil.NoSuchProcess:
        return True, f"Process {pid} terminated gracefully."
