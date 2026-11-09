# -*- coding: utf-8 -*-
"""Yalla habibi, Rich terminal UI with pure Israeli English tech energy."""
from __future__ import annotations

import sys
from typing import List, Optional

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from portkill.process import ProcessInfo
from portkill.scanner import PortListener

console = Console()
err_console = Console(stderr=True)

RUNTIME_COLORS = {
    "node": "green",
    "npm": "green",
    "npx": "green",
    "yarn": "green",
    "pnpm": "green",
    "bun": "yellow",
    "deno": "bright_blue",
    "python": "bright_cyan",
    "python3": "bright_cyan",
    "uvicorn": "bright_cyan",
    "gunicorn": "bright_cyan",
    "flask": "bright_cyan",
    "django": "bright_cyan",
    "go": "bright_blue",
    "cargo": "bright_red",
    "rust": "bright_red",
    "docker": "blue",
    "docker-proxy": "blue",
    "containerd": "blue",
    "java": "red",
    "ruby": "magenta",
    "postgres": "bright_magenta",
    "redis-server": "red",
    "mongod": "bright_green",
}


def highlight_runtime(name: str) -> Text:
    """Format process name with solid colors, sababa style."""
    lower_name = name.lower()
    text = Text()

    color = "white"
    for runtime, rt_color in RUNTIME_COLORS.items():
        if runtime in lower_name:
            color = rt_color
            break

    text.append(name, style=f"bold {color}")
    return text


def build_listener_table(listeners: List[PortListener], title: str = "Active Port Listeners") -> Table:
    """Render a tachles table with all the processes hogging ports."""
    table = Table(
        title=f"[bold white]{title}[/bold white]",
        title_justify="left",
        header_style="bold cyan",
        border_style="dim white",
        show_lines=False,
    )

    table.add_column("Port", justify="right", style="bold yellow")
    table.add_column("Proto", justify="center", style="dim")
    table.add_column("Address", justify="left", style="dim")
    table.add_column("PID", justify="right", style="bold")
    table.add_column("Process", justify="left")
    table.add_column("User", justify="left", style="dim")
    table.add_column("RAM", justify="right")
    table.add_column("CPU", justify="right")
    table.add_column("Uptime", justify="right", style="dim")
    table.add_column("Docker / Context", justify="left", style="italic")

    for item in listeners:
        port_str = str(item.port)
        proto_str = item.protocol
        addr_str = item.ip
        pid_str = str(item.pid) if item.pid is not None else "-"

        proc = item.process
        if proc:
            proc_name = highlight_runtime(proc.name)
            user_str = proc.username or "unknown"
            mem_str = f"{proc.memory_mb:.1f} MB" if proc.memory_mb > 0 else "-"
            cpu_str = f"{proc.cpu_percent:.1f}%"
            uptime_str = proc.uptime_str

            container_str = ""
            if proc.container.is_container:
                container_str = f"[bold blue]🐳 {proc.container.container_name or proc.container.runtime}[/bold blue]"
        else:
            proc_name = Text("<Access denied>", style="dim red")
            user_str = "-"
            mem_str = "-"
            cpu_str = "-"
            uptime_str = "-"
            container_str = ""

        table.add_row(
            port_str,
            proto_str,
            addr_str,
            pid_str,
            proc_name,
            user_str,
            mem_str,
            cpu_str,
            uptime_str,
            container_str,
        )

    return table


def render_process_details(listener: PortListener, verbose: bool = False) -> None:
    """Print complete lineage tree - who is the father of who."""
    proc = listener.process
    if not proc:
        console.print(f"[bold red]Walla cannot get info for port {listener.port}, no permissions or process ran away.[/bold red]")
        return

    tree = Tree(f"[bold yellow]Port {listener.port}[/bold yellow] ({listener.protocol} on {listener.ip})")

    # Parent node if exists
    if proc.ppid and proc.parent_name:
        parent_branch = tree.add(f"[dim]Parent (PID {proc.ppid}): {proc.parent_name}[/dim]")
        proc_node = parent_branch.add(f"[bold green]Target PID {proc.pid}: {proc.name}[/bold green]")
    else:
        proc_node = tree.add(f"[bold green]Target PID {proc.pid}: {proc.name}[/bold green]")

    proc_node.add(f"User: [cyan]{proc.username}[/cyan]")
    proc_node.add(f"RAM footprint: [magenta]{proc.memory_mb:.2f} MB[/magenta]")
    proc_node.add(f"Uptime: [dim]{proc.uptime_str}[/dim]")

    if proc.container.is_container:
        proc_node.add(f"Docker Container: [bold blue]🐳 {proc.container.container_name or proc.container.runtime}[/bold blue]")

    if proc.cmdline:
        cmdline_text = " ".join(proc.cmdline)
        if not verbose and len(cmdline_text) > 120:
            cmdline_text = cmdline_text[:117] + "..."
        proc_node.add(f"Exact Command: [italic]{escape(cmdline_text)}[/italic]")

    console.print(tree)


def render_error_permission(port: int, pid: Optional[int] = None) -> None:
    """No permissions? Yalla run with sudo ahi."""
    panel = Panel(
        f"[bold red]Permission denied (EPERM)[/bold red]\n\n"
        f"Ahi, your terminal cannot touch port [bold yellow]{port}[/bold yellow]"
        + (f" (PID {pid})." if pid else ".")
        + f"\n\n[bold white]Tachles, what to do:[/bold white]\n"
        f"  Open terminal with sudo or Run as Administrator, al tid-ag:\n"
        f"  [bold green]sudo portkill {port}[/bold green]"
        + (f" (or right click CMD -> Run as Administrator)" if sys.platform == "win32" else ""),
        title="⚠️ Elevation Needed",
        border_style="red",
    )
    err_console.print(panel)


def render_critical_warning(port: int, reason: str) -> None:
    """Critical system guard - lo osim balagan."""
    panel = Panel(
        f"[bold red]CRITICAL SYSTEM PORT[/bold red]\n\n"
        f"{reason}\n\n"
        f"Bro, if you kill this you will destroy your network connection or crash the whole machine.\n\n"
        f"[bold white]You insist on doing balagan?[/bold white]\n"
        f"Pass --dangerous flag and take full responsibility:\n"
        f"  [bold yellow]portkill {port} --dangerous[/bold yellow]",
        title="🛑 Critical Guard",
        border_style="bright_red",
    )
    err_console.print(panel)
