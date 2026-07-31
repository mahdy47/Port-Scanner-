# Port Scanner

Single-file Python port scanner. Scans TCP and UDP ports across one or more
targets (IP, hostname, or CIDR), grabs service banners, fingerprints services,
and exports results to txt/json/csv/html.

## Requirements

- Python 3.x
- `pip install -r requirements.txt` (colorama)

## Usage

```
python scanner.py                          # interactive mode
python scanner.py -t 192.168.1.10 -p 1-1000
python scanner.py -t 192.168.1.0/24 -p 1-1000 --udp --polite
python scanner.py -t 10.0.0.5 -p 1-65535 --save json,html,csv,txt
```

Run `python scanner.py --help` for the full option list.

## Testing

The test suite uses pytest (dev-only dependency). To run it:

```
pip install pytest
pytest
```

Coverage includes CIDR expansion limits, CLI argument validation, the
port-range parser, the shared config builder, and localhost smoke scans.
