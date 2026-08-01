# Port Scanner

![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge)
![CI](https://img.shields.io/github/actions/workflow/status/mahdy47/Port-Scanner-/tests.yml?style=for-the-badge)

Single-file Python port scanner for **authorized security testing**. Scans TCP and UDP ports across one or more targets (IP, hostname, or CIDR), grabs service banners, fingerprints services, and exports results to txt/json/csv/html.

> **Legal use only.** Use this tool only on systems you own or have explicit written authorization to test. Unauthorized port scanning may be illegal in most jurisdictions.

## Features

- **TCP scanning** — single ports and port ranges
- **UDP scanning** (`--udp`)
- **Multiple targets** — IP, hostname, or CIDR networks, with a built-in safety limit (max 1024 hosts) to prevent oversized scans
- **Service banner grabbing**
- **OS/service fingerprinting** from TTL and banners
- **Multiple output formats** — txt, json, csv, html
- **Interactive CLI mode** plus full command-line flags (`--workers`, `--timeout`, `--retries`, `--save`, `--polite`)

## Requirements

- Python 3.x
- `pip install -r requirements.txt` (colorama)

## Usage

```bash
python scanner.py                          # interactive mode
python scanner.py -t 192.168.1.10 -p 1-1000
python scanner.py -t 192.168.1.0/24 -p 1-1000 --udp --polite
python scanner.py -t 10.0.0.5 -p 1-65535 --save json,html,csv,txt
```

Run `python scanner.py --help` for the full option list.

## Example Output

Scan of localhost (`127.0.0.1`, ports 1-200):

```
Scanning 127.0.0.1...
135    TCP  open           EPMAP

========================================
Scan Completed
========================================
Target      : 127.0.0.1  (OS guess: Windows (TTL<=128))
Open Ports  : 1
Time        : 0.54 seconds
Saved: scan_20260801_220945.txt
```

## Testing

The test suite uses pytest (dev-only dependency):

```bash
pip install pytest
pytest
```

Coverage includes CIDR expansion limits, CLI argument validation, the port-range parser, the shared config builder, and localhost smoke scans. Tests run automatically on every push and pull request via GitHub Actions (Python 3.11, 3.12, and 3.13).

## License

MIT — see [LICENSE](LICENSE).
