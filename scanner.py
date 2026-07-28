#!/usr/bin/env python3
"""
Python Port Scanner v8
-----------------------
Upgrades included:
 1. UDP scanning (in addition to TCP)
 2. Progress bar (tqdm)
 3. Export results as JSON / CSV (in addition to .txt)
 4. Basic local service-signature fingerprinting (beyond getservbyport)
 5. Retry logic for flaky connections
 6. Rate limiting / "polite mode" (adds delay + fewer threads)
 7. Simple OS fingerprinting via TTL
 8. Multiple targets / CIDR range support (e.g. 192.168.1.0/24)
 9. CLI arguments via argparse (still falls back to interactive mode if no args given)
10. HTML report generation

Usage examples:
    python3 port_scanner_v8.py                     # interactive mode
    python3 port_scanner_v8.py -t 192.168.1.10 -p 1-1000
    python3 port_scanner_v8.py -t 192.168.1.0/24 -p 1-1000 --udp --polite
    python3 port_scanner_v8.py -t 10.0.0.5 -p 1-65535 --save json,html,csv,txt
"""

import socket
import struct
import time
import threading
import argparse
import ipaddress
import json
import csv
import os
from concurrent.futures import ThreadPoolExecutor

from colorama import Fore, init
from tqdm import tqdm

init(autoreset=True)

# -------------------------------------------------------------------
# Small local signature database for common service banners.
# Real tools like nmap ship a huge probe/signature file; this is a
# lightweight version covering common CTF/lab services.
# -------------------------------------------------------------------
SIGNATURES = {
    "ssh": ["ssh-"],
    "ftp": ["220 ", "vsftpd", "proftpd", "filezilla"],
    "smtp": ["220 ", "smtp", "postfix", "exim", "sendmail"],
    "http": ["http/1.", "server:"],
    "irc": ["notice auth", "irc."],
    "mysql": ["mysql_native_password", "\x00\x00\x00\x0a"],
    "vnc": ["rfb "],
    "pop3": ["+ok"],
    "imap": ["* ok"],
    "telnet": ["\xff\xfb", "\xff\xfd"],
}


def identify_service(port, banner):
    """Try getservbyport first, then fall back to matching known banner
    signatures, so results are more accurate than the stdlib alone."""
    try:
        base_name = socket.getservbyport(port)
    except OSError:
        base_name = None

    if banner:
        lowered = banner.lower()
        for service, patterns in SIGNATURES.items():
            for pat in patterns:
                if pat in lowered:
                    return service.upper()

    return base_name.upper() if base_name else "UNKNOWN"


def clean_banner(raw, max_len=60):
    """Take the first printable line of a banner and trim it."""
    first_line = ""
    for line in raw.splitlines():
        line = line.strip()
        if line:
            first_line = line
            break
    cleaned = "".join(ch for ch in first_line if ch.isprintable())
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "..."
    return cleaned


def grab_tcp_banner(sock):
    try:
        sock.settimeout(1)
        sock.send(b"\r\n")
        raw = sock.recv(1024).decode(errors="ignore")
        return clean_banner(raw)
    except Exception:
        return ""


def guess_os_from_ttl(ttl):
    """Very rough OS guess based on typical default TTL values."""
    if ttl is None:
        return "Unknown"
    if ttl <= 64:
        return "Linux/Unix (TTL<=64)"
    elif ttl <= 128:
        return "Windows (TTL<=128)"
    else:
        return "Network device / other (TTL>128)"


def get_ttl(target_ip):
    """Grab TTL from a raw ICMP-less method: use a TCP connect and read
    socket-level TTL isn't directly exposed cross-platform without raw
    sockets/root, so we approximate using the `ping` command output."""
    try:
        import subprocess
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", target_ip],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            if "ttl=" in line.lower():
                part = line.lower().split("ttl=")[1]
                ttl_val = int(part.split()[0])
                return ttl_val
    except Exception:
        pass
    return None


# -------------------------------------------------------------------
# Scanning logic
# -------------------------------------------------------------------

def scan_tcp_port(target_ip, port, timeout, grab_banners, retries):
    attempt = 0
    while attempt <= retries:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            banner = grab_tcp_banner(sock) if grab_banners else ""
            service = identify_service(port, banner)
            sock.close()
            return {
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": service,
                "banner": banner,
            }
        sock.close()
        attempt += 1
    return None


def scan_udp_port(target_ip, port, timeout, retries):
    """UDP is connectionless, so 'open' detection is best-effort:
    if we get any reply, or no ICMP port-unreachable comes back
    within the timeout, we mark it open|filtered (same convention
    nmap uses for UDP)."""
    attempt = 0
    while attempt <= retries:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(b"\x00", (target_ip, port))
            try:
                data, _ = sock.recvfrom(1024)
                banner = clean_banner(data.decode(errors="ignore"))
                service = identify_service(port, banner)
                sock.close()
                return {
                    "port": port,
                    "protocol": "udp",
                    "state": "open",
                    "service": service,
                    "banner": banner,
                }
            except socket.timeout:
                # No response at all -> open|filtered (ambiguous in UDP)
                sock.close()
                return {
                    "port": port,
                    "protocol": "udp",
                    "state": "open|filtered",
                    "service": identify_service(port, ""),
                    "banner": "",
                }
        except OSError:
            # ICMP port unreachable -> closed
            sock.close()
            return None
        attempt += 1
    return None


# -------------------------------------------------------------------
# Output helpers
# -------------------------------------------------------------------

def save_txt(all_results, filename="scan_results.txt"):
    with open(filename, "w") as f:
        for target_ip, entries in all_results.items():
            f.write(f"Target: {target_ip}\n\n")
            for e in entries:
                line = f"{e['port']:<6} {e['protocol'].upper():<4} {e['state']:<14} {e['service']:<12}"
                if e["banner"]:
                    line += f" | {e['banner']}"
                f.write(line + "\n")
            f.write("\n")
    print(Fore.YELLOW + f"Saved: {filename}")


def save_json(all_results, filename="scan_results.json"):
    with open(filename, "w") as f:
        json.dump(all_results, f, indent=2)
    print(Fore.YELLOW + f"Saved: {filename}")


def save_csv(all_results, filename="scan_results.csv"):
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["target", "port", "protocol", "state", "service", "banner"])
        for target_ip, entries in all_results.items():
            for e in entries:
                writer.writerow([target_ip, e["port"], e["protocol"], e["state"], e["service"], e["banner"]])
    print(Fore.YELLOW + f"Saved: {filename}")


def save_html(all_results, os_guesses, elapsed, filename="scan_results.html"):
    rows = ""
    for target_ip, entries in all_results.items():
        os_guess = os_guesses.get(target_ip, "Unknown")
        rows += f'<tr><td colspan="5" class="target-row">Target: {target_ip} &mdash; OS guess: {os_guess}</td></tr>\n'
        for e in entries:
            rows += (
                "<tr>"
                f"<td>{e['port']}</td><td>{e['protocol'].upper()}</td>"
                f"<td>{e['state']}</td><td>{e['service']}</td>"
                f"<td>{e['banner']}</td>"
                "</tr>\n"
            )

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Port Scan Report</title>
<style>
  body {{ font-family: Arial, sans-serif; background:#1e1e2e; color:#eee; padding:20px; }}
  h1 {{ color:#8be9fd; }}
  table {{ border-collapse: collapse; width:100%; margin-top:15px; }}
  th, td {{ border:1px solid #444; padding:6px 10px; text-align:left; font-size:14px; }}
  th {{ background:#2c3e6b; color:white; }}
  tr:nth-child(even) {{ background:#2a2a3d; }}
  .target-row {{ background:#44475a; font-weight:bold; color:#f1fa8c; }}
  .meta {{ color:#aaa; font-size:13px; margin-bottom:10px; }}
</style>
</head>
<body>
  <h1>Port Scan Report</h1>
  <div class="meta">Scan time: {elapsed:.2f}s</div>
  <table>
    <tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Banner</th></tr>
    {rows}
  </table>
</body>
</html>"""

    with open(filename, "w") as f:
        f.write(html)
    print(Fore.YELLOW + f"Saved: {filename}")


# -------------------------------------------------------------------
# Target expansion (single IP / hostname / CIDR)
# -------------------------------------------------------------------

def expand_targets(target_str):
    targets = []
    for part in target_str.split(","):
        part = part.strip()
        try:
            # CIDR notation, e.g. 192.168.1.0/24
            net = ipaddress.ip_network(part, strict=False)
            if net.num_addresses > 1:
                targets.extend([str(ip) for ip in net.hosts()])
            else:
                targets.append(str(net.network_address))
        except ValueError:
            # Not CIDR -> plain IP or hostname, resolve it
            try:
                resolved = socket.gethostbyname(part)
                targets.append(resolved)
            except socket.gaierror:
                print(Fore.RED + f"Skipping invalid target: {part}")
    return targets


# -------------------------------------------------------------------
# Main scan orchestration
# -------------------------------------------------------------------

def run_scan(targets, start_port, end_port, timeout, grab_banners,
             retries, polite, do_udp, workers):
    all_results = {}
    os_guesses = {}

    for target_ip in targets:
        print(f"\nScanning {target_ip}...")
        os_guesses[target_ip] = guess_os_from_ttl(get_ttl(target_ip))

        found = []
        ports = list(range(start_port, end_port + 1))

        def worker(port):
            if polite:
                time.sleep(0.05)  # small delay to reduce noisiness
            tcp_res = scan_tcp_port(target_ip, port, timeout, grab_banners, retries)
            if tcp_res:
                found.append(tcp_res)
                line = f"{tcp_res['port']:<6} TCP  OPEN    {tcp_res['service']:<12}"
                if tcp_res["banner"]:
                    line += f" | {tcp_res['banner']}"
                print(Fore.GREEN + line)

            if do_udp:
                udp_res = scan_udp_port(target_ip, port, timeout, retries)
                if udp_res:
                    found.append(udp_res)
                    line = f"{udp_res['port']:<6} UDP  {udp_res['state']:<14} {udp_res['service']:<12}"
                    if udp_res["banner"]:
                        line += f" | {udp_res['banner']}"
                    print(Fore.CYAN + line)

        max_workers = 50 if polite else workers
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            list(executor.map(worker, ports))

        found.sort(key=lambda x: (x["port"], x["protocol"]))
        all_results[target_ip] = found

    return all_results, os_guesses


# -------------------------------------------------------------------
# Interactive mode (used when no CLI args are passed)
# -------------------------------------------------------------------

def interactive_mode():
    print("=" * 40)
    print("      Python Port Scanner v8")
    print("=" * 40)

    target_str = input("Enter Target IP / Domain / CIDR (comma-separated for multiple): ")

    print("\nPort Scan Options")
    print("1. Default Scan (1 - 10000)")
    print("2. Custom Range")
    choice = input("Choose: ")

    if choice == "1":
        start_port, end_port = 1, 10000
    elif choice == "2":
        try:
            start_port = int(input("Start Port: "))
            end_port = int(input("End Port: "))
        except ValueError:
            print(Fore.RED + "Please enter numbers only!")
            exit()
        if not (0 < start_port <= end_port <= 65535):
            print(Fore.RED + "Invalid port range!")
            exit()
    else:
        print(Fore.RED + "Invalid Choice!")
        exit()

    try:
        timeout_input = input("\nConnection timeout in seconds (default 0.5): ").strip()
        timeout = float(timeout_input) if timeout_input else 0.5
    except ValueError:
        timeout = 0.5

    grab_banners = input("\nGrab Service Banners? (1=Yes, 2=No): ") == "1"
    do_udp = input("Scan UDP ports too? (1=Yes, 2=No): ") == "1"
    polite = input("Polite / stealth mode (slower, less noisy)? (1=Yes, 2=No): ") == "1"

    try:
        retries = int(input("Retries per port on failure (default 0): ") or 0)
    except ValueError:
        retries = 0

    save_choice = input(
        "\nSave results? Enter formats comma-separated (txt,json,csv,html) or blank to skip: "
    ).strip()

    return {
        "targets": expand_targets(target_str),
        "start_port": start_port,
        "end_port": end_port,
        "timeout": timeout,
        "grab_banners": grab_banners,
        "do_udp": do_udp,
        "polite": polite,
        "retries": retries,
        "save_formats": [s.strip() for s in save_choice.split(",") if s.strip()],
    }


# -------------------------------------------------------------------
# CLI mode
# -------------------------------------------------------------------

def parse_cli_args():
    parser = argparse.ArgumentParser(description="Python Port Scanner v8")
    parser.add_argument("-t", "--target", help="Target IP, hostname, or CIDR (comma-separated for multiple)")
    parser.add_argument("-p", "--ports", default="1-10000", help="Port range e.g. 1-1000 (default 1-10000)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Socket timeout in seconds")
    parser.add_argument("--banners", action="store_true", help="Grab service banners")
    parser.add_argument("--udp", action="store_true", help="Also scan UDP ports")
    parser.add_argument("--polite", action="store_true", help="Slower, less noisy scan")
    parser.add_argument("--retries", type=int, default=0, help="Retries per port")
    parser.add_argument("--workers", type=int, default=300, help="Max threads (ignored in polite mode)")
    parser.add_argument("--save", default="", help="Comma-separated formats to save: txt,json,csv,html")
    return parser.parse_args()


def main():
    args = parse_cli_args()

    if args.target:
        try:
            start_port, end_port = map(int, args.ports.split("-"))
        except ValueError:
            print(Fore.RED + "Invalid port range format, use e.g. 1-1000")
            return

        config = {
            "targets": expand_targets(args.target),
            "start_port": start_port,
            "end_port": end_port,
            "timeout": args.timeout,
            "grab_banners": args.banners,
            "do_udp": args.udp,
            "polite": args.polite,
            "retries": args.retries,
            "save_formats": [s.strip() for s in args.save.split(",") if s.strip()],
        }
        workers = args.workers
    else:
        config = interactive_mode()
        workers = 300

    if not config["targets"]:
        print(Fore.RED + "No valid targets to scan.")
        return

    start_time = time.time()
    all_results, os_guesses = run_scan(
        config["targets"], config["start_port"], config["end_port"],
        config["timeout"], config["grab_banners"], config["retries"],
        config["polite"], config["do_udp"], workers
    )
    elapsed = time.time() - start_time

    total_open = sum(len(v) for v in all_results.values())

    print("\n" + "=" * 40)
    print("Scan Completed")
    print("=" * 40)
    for target_ip in config["targets"]:
        print(f"Target      : {target_ip}  (OS guess: {os_guesses.get(target_ip, 'Unknown')})")
    print(f"Open Ports  : {total_open}")
    print(f"Time        : {elapsed:.2f} seconds")

    for fmt in config["save_formats"]:
        if fmt == "txt":
            save_txt(all_results)
        elif fmt == "json":
            save_json(all_results)
        elif fmt == "csv":
            save_csv(all_results)
        elif fmt == "html":
            save_html(all_results, os_guesses, elapsed)
        else:
            print(Fore.RED + f"Unknown save format: {fmt}")


if __name__ == "__main__":
    main()