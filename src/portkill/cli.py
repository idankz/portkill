# -*- coding: utf-8 -*-
"""Command line interface and interactive TUI routing for portkill with Israeli English flair."""
from __future__ import annotations

import sys
from typing import List, Optional, Tuple

import click
from rich.prompt import Confirm, Prompt

from portkill.process import (
    get_process_info,
    is_critical,
    terminate_process,
)
from portkill.scanner import (
    PortListener,
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
        return False

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

        table = build_listener_table(listeners, title="Interactive Portkill - Hamal")
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


class PortkillGroup(click.Group):
    """Custom Click Group supporting both direct port arguments and subcommands."""

    def parse_args(self, ctx: click.Context, args: List[str]) -> List[str]:
        return super().parse_args(ctx, args)


@click.group(cls=PortkillGroup, invoke_without_command=True)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Tachles CLI and interactive utility to terminate stubborn port listeners without headache."""
    if ctx.invoked_subcommand is None:
        pass


@cli.command("scan")
@click.option("-a", "--all", "all_ports", is_flag=True, help="Scan all active listening ports, lo rak dev ports.")
@click.option("-p", "--proto", "protocol", type=click.Choice(["tcp", "udp"], case_sensitive=False), help="Protocol: tcp or udp.")
def scan_command(all_ports: bool, protocol: Optional[str]) -> None:
    """Scan and show active listening ports, no drama."""
    with console.status("[bold cyan]Bodek ports...[/bold cyan]"):
        listeners = scan_ports(protocol_filter=protocol, include_all=all_ports)

    if not listeners:
        scope = "any" if all_ports else "common development"
        console.print(f"[dim]Hakol naki! No {scope} listeners open.[/dim]")
        return

    title = "Kol HaPorts (All Active Listening Ports)" if all_ports else "Dev Ports Map"
    table = build_listener_table(listeners, title=title)
    console.print(table)


@cli.command("kill", hidden=True)
@click.argument("ports", nargs=-1, type=int, required=True)
@click.option("-f", "--force", is_flag=True, help="Force kill immediately with SIGKILL, בלי שאלות.")
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
    known_commands = {"scan", "kill", "--help", "-h"}

    if not args:
        run_interactive_mode()
        return

    if args[0] in ("-i", "--interactive"):
        run_interactive_mode()
        return

    if args[0] not in known_commands and not args[0].startswith("-"):
        sys.argv.insert(1, "kill")

    cli()


if __name__ == "__main__":
    main()
