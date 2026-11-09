"""Port and socket scanning logic across network connections."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Iterator, List, NamedTuple, Optional, Set, Tuple

import psutil

from portkill.process import ProcessInfo, get_process_info


class ScanPermissionError(Exception):
    """Raised when the OS refuses socket enumeration and no fallback is available."""


class RawSocket(NamedTuple):
    ip: str
    port: int
    pid: Optional[int]
    status: str


def parse_lsof_output(output: str) -> List[RawSocket]:
    """Parse `lsof -F pn` output into listening sockets."""
    sockets: List[RawSocket] = []
    pid: Optional[int] = None
    for line in output.splitlines():
        if line.startswith("p"):
            pid = int(line[1:])
        elif line.startswith("n") and "->" not in line:
            ip, _, port = line[1:].rpartition(":")
            if port.isdigit():
                sockets.append(RawSocket(ip.strip("[]"), int(port), pid, "LISTEN"))
    return sockets


def _lsof_sockets(kind: str) -> List[RawSocket]:
    """Enumerate the current user's sockets with lsof (used when psutil is denied)."""
    selector = ["-iTCP", "-sTCP:LISTEN"] if kind == "tcp" else ["-iUDP"]
    result = subprocess.run(
        ["lsof", "-nP", *selector, "-F", "pn"],
        capture_output=True,
        text=True,
        check=False,
    )
    return parse_lsof_output(result.stdout)


def _iter_sockets(kind: str) -> Iterator[RawSocket]:
    """Yield listening sockets, falling back to lsof where psutil needs root (macOS)."""
    try:
        connections = psutil.net_connections(kind=kind)
    except (psutil.AccessDenied, PermissionError):
        if not shutil.which("lsof"):
            raise ScanPermissionError(
                "The OS denied access to the socket table. Re-run with sudo."
            ) from None
        yield from _lsof_sockets(kind)
        return

    for conn in connections:
        if kind == "tcp" and conn.status != psutil.CONN_LISTEN:
            continue
        if conn.laddr:
            yield RawSocket(conn.laddr.ip, conn.laddr.port, conn.pid, conn.status or "OPEN")

# Common Dev Port Ranges and Specific Target Ports
COMMON_DEV_PORTS: Set[int] = {
    # Web & Fullstack dev servers (Next.js, Vite, React, Vue, Svelte, Angular, Astro)
    3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010,
    5173, 5174, 5175, 5176, 5177, 5178, 5179, 5180,
    4200, 4321, 8000, 8001, 8008, 8080, 8081, 8888, 9000, 9090, 9999,
    # Backend frameworks (Flask, Django, Rails, Phoenix, FastAPI, Spring Boot, Express)
    4000, 4567, 5000, 5001, 7000, 7070,
    # Databases & Caches
    3306,   # MySQL / MariaDB
    5432,   # PostgreSQL
    6379,   # Redis
    27017,  # MongoDB
    9200,   # Elasticsearch
    11211,  # Memcached
    8529,   # ArangoDB
    7474,   # Neo4j
    # Message Queues & Brokers
    5672, 15672, # RabbitMQ
    9092,        # Apache Kafka
    # Observability & Metrics
    3100,        # Loki
    9091,        # Pushgateway
    9411,        # Zipkin
}


@dataclass
class PortListener:
    port: int
    protocol: str  # "tcp" or "udp"
    ip: str
    pid: Optional[int]
    status: str
    process: Optional[ProcessInfo] = None

    @property
    def is_dev_port(self) -> bool:
        return self.port in COMMON_DEV_PORTS


def scan_ports(
    ports_filter: Optional[Set[int]] = None,
    protocol_filter: Optional[str] = None,  # "tcp", "udp", or None
    include_all: bool = False,
) -> List[PortListener]:
    """
    Scans for active listening ports.
    If include_all is False and ports_filter is None, defaults to COMMON_DEV_PORTS.
    """
    results: List[PortListener] = []
    seen_keys: Set[Tuple[str, int, Optional[int]]] = set()

    kinds = []
    if protocol_filter == "tcp":
        kinds = ["tcp"]
    elif protocol_filter == "udp":
        kinds = ["udp"]
    else:
        kinds = ["tcp", "udp"]

    for kind in kinds:
        for sock in _iter_sockets(kind):
            port = sock.port

            if ports_filter is not None:
                if port not in ports_filter:
                    continue
            elif not include_all:
                if port not in COMMON_DEV_PORTS:
                    continue

            key = (kind, port, sock.pid)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            proc_info = get_process_info(sock.pid) if sock.pid else None

            results.append(
                PortListener(
                    port=port,
                    protocol=kind.upper(),
                    ip=sock.ip,
                    pid=sock.pid,
                    status=sock.status,
                    process=proc_info,
                )
            )

    # Sort results by port number, then protocol
    results.sort(key=lambda x: (x.port, x.protocol))
    return results


def find_listener_by_port(port: int) -> List[PortListener]:
    """Find all active listeners for a specific port."""
    return scan_ports(ports_filter={port}, include_all=True)
