#!/usr/bin/env python3
"""
OneFlare — Master Demo Runner
Runs all attack scenarios in sequence with narration for live demos.

Usage:
    pip install -r requirements.txt
    python demo.py                    # run all scenarios
    python demo.py --scenario sqli    # run one scenario
    python demo.py --list             # list available scenarios
"""
import argparse
import time
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich import box
from rich.table import Table

console = Console()

SCENARIOS = {
    "sqli":          ("01 — SQL Injection",           "scenarios.01_sqli"),
    "xss":           ("02 — XSS",                     "scenarios.02_xss"),
    "traversal":     ("03 — Path Traversal",          "scenarios.03_path_traversal"),
    "cred":          ("04 — Credential Stuffing",     "scenarios.04_cred_stuffing"),
    "dns":           ("05 — DNS Tunneling",            "scenarios.05_dns_tunnel"),
    "exfil":         ("06 — Data Exfiltration",       "scenarios.06_data_exfil"),
}


def print_intro():
    console.print(Panel.fit(
        "[bold red]ONEFLARE[/bold red] [white]Attack Simulation Suite[/white]\n"
        "[dim]Cloudflare + SentinelOne Detection Lab[/dim]\n\n"
        "[yellow]WARNING:[/yellow] For authorized lab use only.\n"
        "All traffic targets the NovaMind lab Workers only.",
        border_style="red",
        box=box.DOUBLE,
    ))


def print_s1_reminder(scenario_label: str, detection: str):
    console.print(f"\n[dim]  ↳ Check SentinelOne for detection: [bold]{detection}[/bold][/dim]")
    console.print(f"[dim]  ↳ Hyperautomation workflow should trigger automatically[/dim]\n")
    time.sleep(1)


def run_scenario(key: str) -> dict | None:
    label, module_path = SCENARIOS[key]
    console.print(Rule(f"[bold]{label}[/bold]", style="red"))
    try:
        import importlib
        mod = importlib.import_module(module_path)
        result = mod.run()
        print_s1_reminder(label, result.get("detection", "—"))
        return result
    except ImportError as e:
        console.print(f"[red]Failed to load {module_path}: {e}[/red]")
        return None
    except KeyboardInterrupt:
        console.print("\n[yellow]Scenario interrupted.[/yellow]")
        return None


def main():
    parser = argparse.ArgumentParser(description="OneFlare attack demo runner")
    parser.add_argument("--scenario", choices=list(SCENARIOS.keys()),
                        help="Run a single scenario")
    parser.add_argument("--list", action="store_true", help="List available scenarios")
    parser.add_argument("--delay", type=float, default=3.0,
                        help="Seconds between scenarios (default: 3)")
    args = parser.parse_args()

    # Add attack-scripts dir to path
    sys.path.insert(0, str(Path(__file__).parent))

    if args.list:
        table = Table(title="Available Scenarios", box=box.ROUNDED)
        table.add_column("Key")
        table.add_column("Name")
        table.add_column("Module")
        for key, (label, mod) in SCENARIOS.items():
            table.add_row(key, label, mod)
        console.print(table)
        return

    print_intro()
    time.sleep(1)

    results = []

    if args.scenario:
        result = run_scenario(args.scenario)
        if result:
            results.append(result)
    else:
        keys = list(SCENARIOS.keys())
        for i, key in enumerate(keys):
            result = run_scenario(key)
            if result:
                results.append(result)
            if i < len(keys) - 1:
                console.print(f"[dim]Next scenario in {args.delay:.0f}s...[/dim]")
                time.sleep(args.delay)

    # Final summary
    if results:
        console.print(Rule("[bold]Session Complete[/bold]", style="green"))
        table = Table(title="Attack Summary", box=box.ROUNDED, border_style="green")
        table.add_column("Scenario", style="bold")
        table.add_column("Total", justify="right")
        table.add_column("Blocked", justify="right", style="red")
        table.add_column("Passed", justify="right", style="yellow")
        table.add_column("Expected S1 Detection", style="cyan")
        for r in results:
            table.add_row(r["scenario"], str(r["total"]),
                          str(r.get("blocked", 0)), str(r.get("passed", 0)),
                          r.get("detection", "—"))
        console.print(table)
        console.print("\n[dim]Check SentinelOne → Alerts for detection events.[/dim]")
        console.print("[dim]Check attack-scripts/logs/ for per-session JSON logs.[/dim]\n")


if __name__ == "__main__":
    main()
