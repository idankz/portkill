"""Port and socket scanning logic across network connections."""
from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

import psutil

from portkill.process import ProcessInfo, get_process_info

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
        try:
            connections = psutil.net_connections(kind=kind)
        except (psutil.AccessDenied, PermissionError):
            # Fallback or reduced capability
            connections = []

        for conn in connections:
            # We are interested in LISTEN status for TCP, or NONE for UDP
            if kind == "tcp" and conn.status != psutil.CONN_LISTEN:
                continue

            if not conn.laddr:
                continue

            ip = conn.laddr.ip
            port = conn.laddr.port

            if ports_filter is not None:
                if port not in ports_filter:
                    continue
            elif not include_all:
                if port not in COMMON_DEV_PORTS:
                    continue

            key = (kind, port, conn.pid)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            proc_info = get_process_info(conn.pid) if conn.pid else None

            results.append(
                PortListener(
                    port=port,
                    protocol=kind.upper(),
                    ip=ip,
                    pid=conn.pid,
                    status=conn.status if conn.status else "OPEN",
                    process=proc_info,
                )
            )

    # Sort results by port number, then protocol
    results.sort(key=lambda x: (x.port, x.protocol))
    return results


def find_listener_by_port(port: int) -> List[PortListener]:
    """Find all active listeners for a specific port."""
    return scan_ports(ports_filter={port}, include_all=True)
