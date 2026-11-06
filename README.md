# shodanscope

Passive external service inventory using the [Shodan](https://www.shodan.io/) search API.

`shodanscope.py` reads individual IP addresses and CIDR ranges from a scope file, queries Shodan's existing index, and exports a per-host port/service inventory. **It does not scan target hosts.** Results reflect Shodan's historical observations and do not prove a service is currently reachable.

## Features

- IPv4, IPv6, and CIDR input; ignores blank lines and `#` comments
- Automatic `ip:<address>` and `net:<network>` queries
- Paginates search results and retries API errors with backoff
- Deduplicates overlapping results by IP, port, and transport, keeping the newest observation
- Exports CSV, JSON (including banners), per-host inventory, and endpoint lists
- Reports host/service/port counts and saves failed queries separately
- Uses an existing Shodan CLI API key or the `SHODAN_API_KEY` environment variable

## Requirements

- Python 3.9+
- Shodan Python package (`pip install -r requirements.txt`)
- A Shodan API key with access to the search endpoint and sufficient query credits

On Kali Linux, a virtual environment avoids system Python package restrictions:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
shodan init YOUR_API_KEY
```

Alternatively, set `SHODAN_API_KEY` in your shell rather than storing the key in a project file.

## Scope file

Create `scope.txt` with one IP address or CIDR range per line:

```text
# Example addresses (documentation ranges)
192.0.2.10
198.51.100.0/28
2001:db8::10
2001:db8:1::/64
```

Only include assets that belong to your authorized engagement scope. CIDRs are queried as networks; the script does not enumerate every address individually.

## Usage

```bash
python3 shodanscope.py -i scope.txt -o client-shodanscope
```

Additional options:

```bash
python3 shodanscope.py --help
python3 shodanscope.py -i scope.txt -o reports/client.txt --delay 2 --retries 3
```

If no arguments are specified, then `-i` defaults to `scope.txt` in your pwd; `-o` defaults to `shodan`.

## Output

For `-o client-shodanscope`, the script creates:

| File | Description |
| --- | --- |
| `client-shodanscope.csv` | IP, port, protocol, service, product, version, organization, hostname, country, timestamp |
| `client-shodanscope.json` | Structured records including raw service banners |
| `client-shodanscope-inventory.txt` | Ports and services grouped by IP |
| `client-shodanscope-ports.txt` | One `IP:port` endpoint per line; IPv6 uses `[IPv6]:port` |
| `client-shodanscope-failed.txt` | Only created if one or more queries fail |

Example inventory:

```text
192.0.2.10
  Ports: 22/tcp,443/tcp
  Services:
    22/tcp   OpenSSH 9.2
    443/tcp  nginx 1.24
```

Example ports output:

```text
192.0.2.10:22
192.0.2.10:443
[2001:db8::10]:443
```

**Note:** The endpoint-only file does not encode TCP versus UDP; use the inventory or CSV for protocol-aware workflows. JSON banners may contain sensitive information.

## Limitations

- Shodan may not have indexed every scoped host or exposed service.
- Search availability, rate limits, pagination, and credits depend on your Shodan plan.
- API failures are recorded in a failed-query file; a subsequent run does **not** automatically resume or merge earlier results.
- The tool does not perform active port validation or vulnerability assessment.
- Identical IP/port/protocol observations are deduplicated; only the latest timestamp is retained.

## License

MIT
