# NetProbe CLI

A lightweight Python command-line scanner for **authorized network inventory and learning**. It discovers responsive hosts, checks TCP ports, optionally reads basic service banners, and exports results to JSON or CSV.

> **Permission required:** Scan only networks and devices you own or have explicit written permission to assess. Scanning can trigger security alerts or violate network policies. NetProbe is a straightforward TCP connect scanner; it does not implement stealth, evasion, exploitation, or authentication.

## Features

- Single IPv4/IPv6 addresses and CIDR networks.
- Multi-threaded host and TCP port checks.
- Optional ICMP ping discovery; TCP responses also count as host evidence.
- Basic best-effort service banner collection. Sends HTTP `HEAD` on common cleartext HTTP ports.
- Common service-name hints.
- Rough OS guesses using ping TTL and open-port heuristics.
- JSON and CSV output.
- Python standard library only; no external dependencies.
- Bounded defaults: 4096 target addresses, 4096 ports, 500 threads.

## Requirements

Python 3.9+, Windows/Linux/macOS.

## Install

```bash
git clone https://github.com/Afternoon11/Simple-Network-Scanner.git
cd Simple-Network-Scanner
python -m venv .venv
```

Activate:
- Linux/macOS: `source .venv/bin/activate`
- Windows CMD: `.venv\Scripts\activate.bat`
- PowerShell: `.venv\Scripts\Activate.ps1`

Install command:
```bash
python -m pip install -e .
```

No-install alternative:
```bash
python -m netprobe --help
```

## Examples

Scan a lab subnet using common ports:
```bash
netprobe scan 192.168.1.0/24
```

Scan selected ports:
```bash
netprobe scan 192.168.1.10 --ports 22,80,443,445,3389
```

Scan a range:
```bash
netprobe scan 192.168.1.10 --ports 1-1024
```

Tune concurrency:
```bash
netprobe scan 192.168.1.0/24 --ports 22,80,443 --threads 100 --timeout 0.8
```

Skip ICMP (useful where ping is blocked):
```bash
netprobe scan 192.168.1.0/24 --no-ping
```

Disable banner collection:
```bash
netprobe scan 192.168.1.10 --no-banner
```

Export:
```bash
netprobe scan 192.168.1.0/24 --format json --output results.json
netprobe scan 192.168.1.0/24 --format csv --output results.csv
```

Help:
```bash
netprobe --help
netprobe scan --help
```

## Result fields

`ip`, `status`, `os_guess`, `open_ports[]` with `port`, `state`, `service`, and `banner`.

CSV flattens one row per open port. Hosts with no selected open ports still receive a row.

## OS guess caveat

TTL values are rough clues only: up to 64 often suggests Unix/Linux, up to 128 often suggests Windows, and higher values can suggest network devices or Unix-like systems. Routers decrement TTL; systems can change defaults. Port-based guesses are also weak. Treat all OS guesses as unverified hints.

## Limitations and safety

- TCP connect scanning establishes a normal TCP connection; it is not a SYN scan and is not stealthy.
- A host blocking ICMP and having no open selected ports may appear as `no-response`.
- UDP scanning is not implemented.
- TLS services usually do not provide readable banners to the simple plaintext probe.
- Port numbers do not prove service identity; banner collection is best-effort.
- Start with a small authorized lab range and modest thread counts. Scans create traffic and may trigger monitoring.
- `--allow-large` raises the target cap to 65,536 addresses. Do not use it unless the entire range is authorized.

## License

MIT. See [LICENSE](LICENSE).
