#!/usr/bin/env python3
"""
Educational TCP port scanner.

A small learning tool that grows in three stages:
  Stage 1 - a single-threaded connect scan over a port range
  Stage 2 - a thread pool for speed
  Stage 3 - banner grabbing on open ports

Only run this against hosts you own or have written permission to test.
Unauthorized scanning of third-party systems may be illegal.

Usage:
    python3 scanner.py <host> [--start 1] [--end 1024] [--timeout 0.5]
                              [--threads 100] [--no-banner]

Examples:
    python3 scanner.py 127.0.0.1
    python3 scanner.py 127.0.0.1 --start 1 --end 65535 --threads 200
    python3 scanner.py scanme.nmap.org --start 20 --end 100
"""

import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


# ----------------------------------------------------------------------------
# Stage 1: scan one port with a plain blocking socket
# ----------------------------------------------------------------------------
def scan_port(host, port, timeout=0.5):
    """Return True if a TCP connection to (host, port) succeeds."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        # connect_ex returns 0 on success instead of raising, which is
        # convenient for scanning: any non-zero result means closed/filtered.
        return sock.connect_ex((host, port)) == 0


def scan_single_threaded(host, start, end, timeout=0.5):
    """Scan a port range one port at a time. Returns a sorted list of open ports."""
    open_ports = []
    for port in range(start, end + 1):
        if scan_port(host, port, timeout):
            open_ports.append(port)
    return open_ports


# ----------------------------------------------------------------------------
# Stage 2: scan the range in parallel with a thread pool
# ----------------------------------------------------------------------------
def scan_threaded(host, start, end, timeout=0.5, threads=100):
    """Scan a port range using a thread pool. Returns a sorted list of open ports."""
    open_ports = []
    ports = range(start, end + 1)
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(scan_port, host, p, timeout): p for p in ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                # A per-port error (e.g. transient resolution issue) just
                # means we treat that port as not-open; keep scanning.
                pass
    return sorted(open_ports)


# ----------------------------------------------------------------------------
# Stage 3: grab a service banner from an open port
# ----------------------------------------------------------------------------
def grab_banner(host, port, timeout=1.0):
    """
    Try to read a short banner from an open port.

    Many services announce themselves on connect (FTP, SSH, SMTP). For
    HTTP-style ports we nudge the server with a minimal request so it replies.
    Returns a cleaned one-line string, or None if nothing came back.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))

            # HTTP(S) and proxy-style ports usually stay silent until asked.
            if port in (80, 8080, 8000, 8888, 443):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")

            data = sock.recv(1024)
            if not data:
                return None
            text = data.decode("utf-8", errors="replace").strip()
            # Keep it to the first line so the output stays readable.
            return text.splitlines()[0] if text else None
    except Exception:
        return None


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def resolve_host(host):
    """Resolve a hostname to an IP, exiting cleanly on failure."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {host}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Educational TCP port scanner (authorized targets only)."
    )
    parser.add_argument("host", help="target hostname or IP address")
    parser.add_argument("--start", type=int, default=1, help="first port (default 1)")
    parser.add_argument("--end", type=int, default=1024, help="last port (default 1024)")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="per-port connect timeout in seconds (default 0.5)")
    parser.add_argument("--threads", type=int, default=100,
                        help="thread pool size (default 100); use 1 for the single-threaded path")
    parser.add_argument("--no-banner", action="store_true",
                        help="skip banner grabbing on open ports")
    args = parser.parse_args()

    if not (1 <= args.start <= args.end <= 65535):
        print("[!] Invalid range: need 1 <= start <= end <= 65535")
        sys.exit(1)

    ip = resolve_host(args.host)
    total = args.end - args.start + 1
    print(f"[*] Target: {args.host} ({ip})")
    print(f"[*] Ports:  {args.start}-{args.end} ({total} ports)")
    print(f"[*] Mode:   {'single-threaded' if args.threads == 1 else f'{args.threads} threads'}")
    print(f"[*] Started: {datetime.now():%Y-%m-%d %H:%M:%S}\n")

    start_time = datetime.now()
    if args.threads == 1:
        open_ports = scan_single_threaded(ip, args.start, args.end, args.timeout)
    else:
        open_ports = scan_threaded(ip, args.start, args.end, args.timeout, args.threads)
    elapsed = (datetime.now() - start_time).total_seconds()

    if not open_ports:
        print("[-] No open ports found in range.")
    else:
        print(f"[+] {len(open_ports)} open port(s):\n")
        print(f"    {'PORT':<8}{'SERVICE':<16}BANNER")
        print(f"    {'-'*4:<8}{'-'*7:<16}{'-'*6}")
        for port in open_ports:
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"
            banner = ""
            if not args.no_banner:
                banner = grab_banner(ip, port) or ""
            print(f"    {port:<8}{service:<16}{banner}")

    print(f"\n[*] Done in {elapsed:.2f}s")


if __name__ == "__main__":
    main()
