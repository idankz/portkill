# -*- coding: utf-8 -*-
"""Command line interface and interactive TUI routing for portkill."""
from __future__ import annotations

import os
import sys
from typing import Optional, Tuple

import click
from rich.prompt import Confirm, Prompt

from portkill.process import (
    is_critical,
    terminate_process,
)
from portkill.scanner import (
    ScanPermissionError,
    find_listener_by_port,
    scan_ports,
)
from portkill.ui import (
    build_listener_table,
    console,
    err_console,
    render_critical_warning,
    render_error_permission,
    render_process_details,
)


def kill_port_target(
    port: int,
    force: bool = False,
    dangerous: bool = False,
    verbose: bool = False,
    yes: bool = False,
) -> bool:
    """Core logic to find, verify, and take down stubborn processes."""
    listeners = find_listener_by_port(port)
    if not listeners:
        console.print(f"[yellow]Walla, port [bold]{port}[/bold] is completely empty, nobody is home.[/yellow]")
        if sys.platform == "darwin" and os.geteuid() != 0:
            console.print("[dim]Processes owned by other users are only visible with sudo on macOS.[/dim]")
        # A free port is the outcome the caller wanted: `portkill 3000 && npm run dev`.
        return True

    success_all = True
    for listener in listeners:
        pid = listener.pid
        proc = listener.process
        proc_name = proc.name if proc else None

        if verbose:
            render_process_details(listener, verbose=True)

        if not pid:
            err_console.print(f"[bold red]Port {port} ({listener.protocol}) is open, but who is the PID? Mystery.[/bold red]")
            render_error_permission(port)
            success_all = False
            continue

        # Critical port / process check
        critical, reason = is_critical(port, pid, proc_name)
        if critical and not dangerous:
            render_critical_warning(port, reason)
            success_all = False
            continue

        # Killing the proxy only breaks the port mapping; the container keeps running.
        if proc and proc.container.runtime in ("docker-proxy", "containerd") and not dangerous:
            err_console.print(
                f"[bold yellow]Port {port} is held by {proc.container.runtime}.[/bold yellow] "
                "Stop the container with `docker stop`, or pass --dangerous to kill the proxy anyway."
            )
            success_all = False
            continue

        pname = proc.name if proc else "Stam-process"
        puser = f" (gever: {proc.username})" if proc and proc.username else ""
        cinfo = f" [🐳 {proc.container.container_name}]" if proc and proc.container.is_container else ""

        # Prompt if not --force / not -y
        if not force and not yes:
            console.print(
                f"\nTarget locked: [bold yellow]Port {port}[/bold yellow] -> "
                f"PID [bold green]{pid}[/bold green] ([bold cyan]{pname}[/bold cyan]{puser}{cinfo})"
            )
            confirmed = Confirm.ask(f"Tachles, terminate PID {pid}?", default=True)
            if not confirmed:
                console.print(f"[dim]Azavti, left PID {pid} alone.[/dim]")
                continue

        with console.status(f"[bold green]Yalla, taking down PID {pid}...[/bold green]"):
            ok, msg = terminate_process(pid, force=force)

        if ok:
            console.print(f"[bold green]✓ Sababa![/bold green] Port {port}: {msg}")
        else:
            err_console.print(f"[bold red]✗ Basa![/bold red] Port {port}: {msg}")
            if "Permission denied" in msg or "EPERM" in msg:
                render_error_permission(port, pid)
            success_all = False

    return success_all


def run_interactive_mode() -> None:
    """Interactive dashboard mode - tachles terminal management."""
    while True:
        with console.status("[bold cyan]Scanning who is holding which port...[/bold cyan]"):
            listeners = scan_ports(include_all=True)

        if not listeners:
            console.print("[dim]Sheket total. No open listening ports found.[/dim]")
            break

        table = build_listener_table(listeners, title="Interactive portkill")
        console.print(table)
        console.print(
            "\nOptions: enter [bold cyan]<port>[/bold cyan] to choose | "
            "[bold green]r[/bold green] (refresh) | "
            "[bold red]q[/bold red] (yalla bye)"
        )

        try:
            choice = Prompt.ask("Give me a port or command", default="q").strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Yalla bye.[/dim]")
            break

        if choice in ("q", "quit", "exit", "bye"):
            console.print("[dim]Yalla bye, see you later ahi.[/dim]")
            break

        if choice in ("r", "refresh"):
            continue

        if not choice.isdigit():
            console.print("[red]Ahi, enter a legit port number, or 'r' / 'q'.[/red]")
            continue

        target_port = int(choice)
        matching = [l for l in listeners if l.port == target_port]
        if not matching:
            console.print(f"[yellow]Port {target_port} lo kayam in this scan.[/yellow]")
            continue

        l = matching[0]
        render_process_details(l)

        try:
            action = Prompt.ask(
                f"Ma osim with Port {target_port}?",
                choices=["k", "f", "d", "q"],
                default="k",
            )
        except (EOFError, KeyboardInterrupt):
            break

        if action == "k":
            kill_port_target(target_port, force=False, yes=True)
        elif action == "f":
            kill_port_target(target_port, force=True, yes=True)
        elif action == "d":
            render_process_details(l, verbose=True)
            try:
                Prompt.ask("Press Enter to continue...")
            except (EOFError, KeyboardInterrupt):
                pass
        elif action == "q":
            continue


@click.group()
def cli() -> None:
    """Find and terminate the processes holding your ports.

    Run with no arguments for interactive mode, or use `portkill 3000 8080` as a
    shortcut for `portkill kill 3000 8080`.
    """


@cli.command("scan")
@click.option("-a", "--all", "all_ports", is_flag=True, help="Scan all listening ports, not only common dev ports.")
@click.option("-p", "--proto", "protocol", type=click.Choice(["tcp", "udp"], case_sensitive=False), help="Protocol: tcp or udp.")
def scan_command(all_ports: bool, protocol: Optional[str]) -> None:
    """Show active listening ports."""
    with console.status("[bold cyan]Bodek ports...[/bold cyan]"):
        listeners = scan_ports(protocol_filter=protocol, include_all=all_ports)

    if not listeners:
        scope = "any" if all_ports else "common development"
        console.print(f"[dim]Hakol naki! No {scope} listeners open.[/dim]")
        return

    title = "All Listening Ports" if all_ports else "Dev Ports"
    table = build_listener_table(listeners, title=title)
    console.print(table)


@cli.command("kill")
@click.argument("ports", nargs=-1, type=int, required=True)
@click.option("-f", "--force", is_flag=True, help="Force kill immediately with SIGKILL, without confirmation.")
@click.option("-v", "--verbose", is_flag=True, help="Print full process lineage and arguments.")
@click.option("--dangerous", is_flag=True, help="Allow killing critical ports/processes (SSH, DNS, PID 1).")
def kill_command(
    ports: Tuple[int, ...],
    force: bool,
    verbose: bool,
    dangerous: bool,
) -> None:
    """Terminate stubborn process listeners holding specified ports."""
    all_ok = True
    for port in ports:
        ok = kill_port_target(
            port=port,
            force=force,
            dangerous=dangerous,
            verbose=verbose,
            yes=force,
        )
        if not ok:
            all_ok = False

    if not all_ok:
        sys.exit(1)


def main() -> None:
    args = sys.argv[1:]
    known_commands = {"scan", "kill", "--help"}

    try:
        if not args or args[0] in ("-i", "--interactive"):
            run_interactive_mode()
            return

        # Allow options before ports too: `portkill -f 3000`.
        if args[0] not in known_commands and (
            not args[0].startswith("-") or any(a.isdigit() for a in args)
        ):
            sys.argv.insert(1, "kill")

        cli()
    except ScanPermissionError as exc:
        err_console.print(f"[bold red]{exc}[/bold red]")
        sys.exit(2)


if __name__ == "__main__":
    main()
