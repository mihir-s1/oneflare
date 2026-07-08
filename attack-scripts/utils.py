import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

# ── User agents (realistic browser rotation) ──────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "python-requests/2.31.0",
    "sqlmap/1.7.11#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "curl/8.4.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
    "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
]

# ── Source IPs for X-Forwarded-For simulation ─────────────────────────────────
ATTACKER_IPS = [
    "185.220.101.45",   # Tor exit node (EU)
    "185.220.101.182",  # Tor exit node (EU)
    "45.155.205.233",   # Known scanner (EU)
    "193.32.162.157",   # VPN exit (DE)
    "89.234.157.254",   # VPN exit (FR)
    "162.247.74.74",    # Tor exit (US)
    "198.51.100.1",     # Documentation range (simulated US)
    "203.0.113.42",     # Documentation range (simulated APAC)
    "104.244.73.29",    # VPN exit (US)
    "23.129.64.218",    # Tor exit (US)
]

GEO_IPS = {
    "US": ["198.51.100.1", "104.244.73.29", "162.247.74.74", "23.129.64.218"],
    "EU": ["185.220.101.45", "185.220.101.182", "193.32.162.157", "89.234.157.254"],
    "APAC": ["203.0.113.42", "43.229.53.1", "103.224.182.245"],
}


def random_headers(extra: dict = None) -> dict:
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "X-Forwarded-For": random.choice(ATTACKER_IPS),
        "X-Real-IP": random.choice(ATTACKER_IPS),
    }
    if extra:
        headers.update(extra)
    return headers


def jitter(base: float = 0.5, variance: float = 1.5) -> None:
    """Random delay to simulate human/tool timing.

    ATTACK_DELAY / ATTACK_JITTER env vars (set by the lab-ui backend from the
    Settings 'Attack delay' / 'Jitter' controls) act as a GLOBAL override of the
    per-call base/variance when present, so the UI timing knobs actually work.
    """
    import os
    env_base = os.getenv("ATTACK_DELAY")
    env_var = os.getenv("ATTACK_JITTER")
    if env_base is not None:
        try:
            base = float(env_base)
        except ValueError:
            pass
    if env_var is not None:
        try:
            variance = float(env_var)
        except ValueError:
            pass
    time.sleep(base + random.uniform(0, variance))


def print_banner(scenario: str, description: str) -> None:
    console.print(Panel(
        f"[bold red]{scenario}[/bold red]\n[dim]{description}[/dim]",
        title="[bold white]ONEFLARE ATTACK SIMULATION[/bold white]",
        border_style="red",
    ))


def print_request(method: str, url: str, status: int, note: str = "") -> None:
    color = "green" if status == 200 else "red" if status in (403, 401) else "yellow"
    console.print(f"  [{color}]{status}[/{color}] {method} {url}" + (f" [dim]— {note}[/dim]" if note else ""))


def print_summary(results: list[dict]) -> None:
    table = Table(title="Session Summary", box=box.ROUNDED, border_style="dim")
    table.add_column("Scenario", style="bold")
    table.add_column("Requests", justify="right")
    table.add_column("Blocked", justify="right", style="red")
    table.add_column("Passed", justify="right", style="green")
    table.add_column("Expected S1 Detection")
    for r in results:
        table.add_row(r["scenario"], str(r["total"]), str(r["blocked"]), str(r["passed"]), r["detection"])
    console.print(table)


# ── JSON session logger ───────────────────────────────────────────────────────
class SessionLog:
    def __init__(self, scenario: str, logs_dir: Path):
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.path = logs_dir / f"{ts}_{scenario}.json"
        self.entries = []
        self.scenario = scenario
        self.started_at = datetime.now(timezone.utc).isoformat()

    def log(self, method: str, url: str, status: int, payload: str = "", note: str = "") -> None:
        self.entries.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "url": url,
            "status": status,
            "payload": payload,
            "note": note,
        })

    def save(self) -> None:
        data = {
            "scenario": self.scenario,
            "started_at": self.started_at,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "total": len(self.entries),
            "blocked": sum(1 for e in self.entries if e["status"] in (403, 401, 429)),
            "passed": sum(1 for e in self.entries if e["status"] == 200),
            "entries": self.entries,
        }
        try:
            self.path.write_text(json.dumps(data, indent=2))
            console.print(f"[dim]  Log saved → {self.path}[/dim]")
        except OSError as exc:
            # Non-persistent/read-only filesystem (e.g. a container with no
            # attached volume) — don't crash the run over a log write.
            console.print(f"[dim yellow]  Log not persisted ({exc}) — continuing[/dim yellow]")
