#!/usr/bin/env python3
"""
Python Port Scanner
--------------------
Scans TCP and UDP ports across one or more targets (IP, hostname, or CIDR).

Features:
  - TCP and UDP scanning
  - Service fingerprinting from banner signatures (fallback: getservbyport)
  - Optional banner grabbing
  - Retries for flaky connections
  - "Polite" mode: a short delay and fewer threads per scan
  - Rough OS guess from ping TTL
  - Multiple targets / CIDR ranges
  - CLI arguments, with an interactive fallback when none are given
  - Results exportable as txt, json, csv, or html

Examples:
    python scanner.py                    # interactive mode
    python scanner.py -t 192.168.1.10 -p 1-1000
    python scanner.py -t 192.168.1.0/24 -p 1-1000 --udp --polite
    python scanner.py -t 10.0.0.5 -p 1-65535 --save json,html,csv,txt
"""

import socket
import time
import argparse
import ipaddress
import json
import csv
import html
import subprocess
import platform
import sys
from concurrent.futures import ThreadPoolExecutor

from colorama import Fore, init

init(autoreset=True)

# Refuse to expand a network with more hosts than this (guards against typos like 0.0.0.0/0)
MAX_HOSTS_PER_NETWORK = 1024

# Signature patterns used to fingerprint common services
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


# getservbyport for known ports, banner signatures as a fallback
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


# First non-empty line of a banner, printable chars only, capped at 60
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


# Ask the service for a banner by sending a CRLF
def grab_tcp_banner(sock):
    try:
        sock.settimeout(1)
        sock.send(b"\r\n")
        raw = sock.recv(1024).decode(errors="ignore")
        return clean_banner(raw)
    except Exception:
        return ""


# Rough OS guess from the TTL of the first ping reply
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


# TTL isn't exposed through plain sockets cross-platform, so read it from ping
def get_ttl(target_ip):
    """Shell out to ping and parse TTL from its output; None if it fails."""
    try:
        if platform.system().lower() == "windows":
            ping_cmd = ["ping", "-n", "1", "-w", "1000", target_ip]
        else:
            ping_cmd = ["ping", "-c", "1", "-W", "1", target_ip]
        result = subprocess.run(ping_cmd, capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "ttl=" in line.lower():
                part = line.lower().split("ttl=")[1]
                ttl_val = int(part.split()[0])
                return ttl_val
    except Exception:
        pass
    return None


# Every result has the same fields, so build them once here
def _result(port, protocol, state, service, banner):
    return {
        "port": port,
        "protocol": protocol,
        "state": state,
        "service": service,
        "banner": banner,
    }


# Print one result line in the chosen color
def _format_open_line(res, color):
    line = f"{res['port']:<6} {res['protocol'].upper():<4} {res['state']:<14} {res['service']:<12}"
    if res["banner"]:
        line += f" | {res['banner']}"
    print(color + line)


# Try a TCP connect (optionally grabbing a banner), retrying on failure
def scan_tcp_port(target_ip, port, timeout, grab_banners, retries):
    for _ in range(retries + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                banner = grab_tcp_banner(sock) if grab_banners else ""
                return _result(port, "tcp", "open", identify_service(port, banner), banner)
        except OSError:
            pass
        finally:
            sock.close()
    return None


# Best-effort UDP probe: a reply means open, a timeout means open|filtered
def scan_udp_port(target_ip, port, timeout, retries):
    """UDP has no handshake, so 'open' only happens when the service replies.
    A silent port gets open|filtered (nmap's convention)."""
    for _ in range(retries + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            sock.sendto(b"\x00", (target_ip, port))
            try:
                data, _ = sock.recvfrom(1024)
                banner = clean_banner(data.decode(errors="ignore"))
                return _result(port, "udp", "open", identify_service(port, banner), banner)
            except socket.timeout:
                return _result(port, "udp", "open|filtered", identify_service(port, ""), "")
        except OSError:
            return None
        finally:
            sock.close()
    return None


# Save scan results as plain text
def save_txt(all_results, filename="scan_results.txt"):
    with open(filename, "w", encoding="utf-8") as f:
        for target_ip, entries in all_results.items():
            f.write(f"Target: {target_ip}\n\n")
            for e in entries:
                line = f"{e['port']:<6} {e['protocol'].upper():<4} {e['state']:<14} {e['service']:<12}"
                if e["banner"]:
                    line += f" | {e['banner']}"
                f.write(line + "\n")
            f.write("\n")
    print(Fore.YELLOW + f"Saved: {filename}")


# Save scan results as JSON
def save_json(all_results, filename="scan_results.json"):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)
    print(Fore.YELLOW + f"Saved: {filename}")


# Neutralize CSV formula injection: prefix cells Excel would evaluate as formulas
def _csv_safe(value):
    s = str(value)
    if s.startswith(("=", "+", "-", "@")):
        return "'" + s
    return s


# Save scan results as CSV
def save_csv(all_results, filename="scan_results.csv"):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["target", "port", "protocol", "state", "service", "banner"])
        for target_ip, entries in all_results.items():
            for e in entries:
                writer.writerow([
                    _csv_safe(target_ip), e["port"], _csv_safe(e["protocol"]),
                    _csv_safe(e["state"]), _csv_safe(e["service"]), _csv_safe(e["banner"]),
                ])
    print(Fore.YELLOW + f"Saved: {filename}")


# Save scan results as HTML report
def save_html(all_results, os_guesses, elapsed, filename="scan_results.html"):
    rows = ""
    for target_ip, entries in all_results.items():
        os_guess = html.escape(os_guesses.get(target_ip, "Unknown"))
        rows += f'<tr><td colspan="5" class="target-row">Target: {html.escape(target_ip)} &mdash; OS guess: {os_guess}</td></tr>\n'
        for e in entries:
            rows += (
                "<tr>"
                f"<td>{e['port']}</td><td>{html.escape(e['protocol'].upper())}</td>"
                f"<td>{html.escape(e['state'])}</td><td>{html.escape(e['service'])}</td>"
                f"<td>{html.escape(e['banner'])}</td>"
                "</tr>\n"
            )

    page = f"""<!DOCTYPE html>
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

    with open(filename, "w", encoding="utf-8") as f:
        f.write(page)
    print(Fore.YELLOW + f"Saved: {filename}")


# Turn a comma-separated list of IPs, hostnames, and CIDRs into IP addresses
def expand_targets(target_str):
    targets = []
    for part in target_str.split(","):
        part = part.strip()
        try:
            net = ipaddress.ip_network(part, strict=False)
            if net.num_addresses > 1:
                if net.num_addresses > MAX_HOSTS_PER_NETWORK + 2:
                    print(Fore.YELLOW + f"Skipping {part}: expands to more than {MAX_HOSTS_PER_NETWORK} hosts")
                    continue
                targets.extend([str(ip) for ip in net.hosts()])
            else:
                targets.append(str(net.network_address))
        except ValueError:
            try:
                resolved = socket.gethostbyname(part)
                targets.append(resolved)
            except socket.gaierror:
                print(Fore.RED + f"Skipping invalid target: {part}")
    return targets


# Scan every target: OS guess first, then TCP/UDP across the port range
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
                time.sleep(0.05)
            tcp_res = scan_tcp_port(target_ip, port, timeout, grab_banners, retries)
            if tcp_res:
                found.append(tcp_res)
                _format_open_line(tcp_res, Fore.GREEN)

            if do_udp:
                udp_res = scan_udp_port(target_ip, port, timeout, retries)
                if udp_res and udp_res["state"] == "open":
                    found.append(udp_res)
                    _format_open_line(udp_res, Fore.CYAN)

        max_workers = 50 if polite else workers
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            list(executor.map(worker, ports))

        found.sort(key=lambda x: (x["port"], x["protocol"]))
        all_results[target_ip] = found

    return all_results, os_guesses


def parse_port_range(spec):
    """Parse "start-end" (or a bare single port) into a valid (start, end)
    pair, or None after printing what's wrong with it."""
    try:
        parts = spec.split("-")
        if len(parts) == 1:
            start = end = int(parts[0])
        else:
            start, end = map(int, parts)
    except ValueError:
        print(Fore.RED + "Invalid port range format, use e.g. 1-1000")
        return None
    if not (0 < start <= end <= 65535):
        print(Fore.RED + "Invalid port range, use e.g. 1-1000 (max 65535)")
        return None
    return start, end


def _parse_save_formats(spec):
    return [s.strip() for s in spec.split(",") if s.strip()]


def _build_config(targets, start_port, end_port, timeout, grab_banners,
                  do_udp, polite, retries, save_formats):
    return {
        "targets": targets,
        "start_port": start_port,
        "end_port": end_port,
        "timeout": timeout,
        "grab_banners": grab_banners,
        "do_udp": do_udp,
        "polite": polite,
        "retries": retries,
        "save_formats": save_formats,
    }


# Ask for scan settings when no CLI arguments were given
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
        parsed = parse_port_range(f"{input('Start Port: ')}-{input('End Port: ')}")
        if parsed is None:
            exit()
        start_port, end_port = parsed
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

    return _build_config(
        expand_targets(target_str), start_port, end_port, timeout,
        grab_banners, do_udp, polite, retries,
        _parse_save_formats(save_choice),
    )


# Parse command-line arguments for scan options
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

    if args.workers < 1:
        print(Fore.RED + "--workers must be at least 1")
        sys.exit(1)
    if args.timeout <= 0:
        print(Fore.RED + "--timeout must be greater than 0")
        sys.exit(1)
    if args.retries < 0:
        print(Fore.RED + "--retries must be 0 or greater")
        sys.exit(1)

    if args.target:
        parsed = parse_port_range(args.ports)
        if parsed is None:
            sys.exit(1)
        start_port, end_port = parsed

        config = _build_config(
            expand_targets(args.target), start_port, end_port, args.timeout,
            args.banners, args.udp, args.polite, args.retries,
            _parse_save_formats(args.save),
        )
        workers = args.workers
    else:
        config = interactive_mode()
        workers = 300

    if not config["targets"]:
        print(Fore.RED + "No valid targets to scan.")
        sys.exit(1)

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

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    for fmt in config["save_formats"]:
        if fmt == "txt":
            save_txt(all_results, f"scan_{timestamp}.txt")
        elif fmt == "json":
            save_json(all_results, f"scan_{timestamp}.json")
        elif fmt == "csv":
            save_csv(all_results, f"scan_{timestamp}.csv")
        elif fmt == "html":
            save_html(all_results, os_guesses, elapsed, f"scan_{timestamp}.html")
        else:
            print(Fore.RED + f"Unknown save format: {fmt}")


if __name__ == "__main__":
    main()