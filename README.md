# shodanscope

Passive external service inventory using the [Shodan](https://www.shodan.io/) search API.

`shodanscope.py` reads individual IP addresses, CIDR ranges, and fully qualified domain names (FQDNs) from a scope file, queries Shodan's existing index, and exports a per-host port/service inventory. FQDNs are automatically resolved to IPv4 and IPv6 addresses before querying Shodan. **It does not scan target hosts.** Results reflect Shodan's historical observations and do not prove a service is currently reachable.

## Features

- IPv4, IPv6, CIDR, and FQDN input; ignores blank lines and `#` comments
- Automatically resolves FQDNs using DNS A and AAAA records
- Automatic `ip:<address>` and `net:<network>` queries
- Deduplicates resolved IP addresses to avoid redundant Shodan queries
- Preserves FQDN-to-IP relationships and distinguishes explicit from DNS-derived scope
- Normalizes CIDR ranges and warns when supplied addresses contain host bits
- Paginates search results and retries API errors with backoff
- Deduplicates overlapping results by IP, port, and transport, keeping the newest observation
- Exports CSV, JSON (including banners), per-host inventory, endpoint lists, and DNS resolution results
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

Create `scope.txt` with one IP address, CIDR range, or FQDN per line:

```text
# Example addresses (documentation ranges)
192.0.2.10
198.51.100.0/28
2001:db8::10
2001:db8:1::/64

# Example domains
example.com
portal.example.com
```

Only include assets that belong to your authorized engagement scope. CIDRs are queried as networks; the script does not enumerate every address individually.

### Automatic DNS resolution

ShodanScope automatically resolves FQDNs using DNS A and AAAA records. Each resolved IP address is queried through the Shodan API, while the original FQDN-to-IP relationships are preserved.

When multiple FQDNs resolve to the same IP address, ShodanScope queries that IP only once, reducing unnecessary API requests.

DNS-derived hosts are distinguished from explicitly scoped IP addresses and CIDR ranges in the exported results.

**Note:** DNS-derived IP addresses may belong to shared hosting providers, CDNs, or other third-party infrastructure. DNS resolution alone does not establish ownership or authorization for active security testing.

### CIDR normalization and scope verification

ShodanScope automatically normalizes CIDR entries to their corresponding network addresses.

If a supplied CIDR contains host bits, the tool displays a warning identifying the original input, normalized network, and total number of addresses included.

For example:

```text
[!] CIDR normalized:
    Supplied:   192.0.2.10/29
    Effective:  192.0.2.8/29
    Addresses:  8

    Verify that the entire CIDR range is authorized.
```

CIDR normalization does not expand the mathematically defined network range. However, an incorrectly supplied CIDR prefix may include additional hosts beyond those intended by the client.

**Verify that the entire normalized CIDR range is authorized before conducting active security testing.**

## Usage

```bash
python3 shodanscope.py -i scope.txt -o client-shodanscope
```

Additional options:

```bash
python3 shodanscope.py --help
python3 shodanscope.py -i scope.txt -o reports/client.txt --delay 2 --retries 3
python3 shodanscope.py -i scope.txt -o client-shodanscope --no-banner
```

If no arguments are specified, `-i` defaults to `scope.txt` in the current working directory; `-o` defaults to `shodan`.

## Output

For `-o client-shodanscope`, the script creates:

| File | Description |
| --- | --- |
| `client-shodanscope.csv` | IP, port, protocol, service, product, version, organization, hostname, country, timestamp, and scope attribution |
| `client-shodanscope.json` | Structured records including service banners and scope attribution |
| `client-shodanscope-inventory.txt` | Ports and services grouped by IP, including explicit and DNS-derived scope information |
| `client-shodanscope-ports.txt` | One `IP:port` endpoint per line; IPv6 uses `[IPv6]:port` |
| `client-shodanscope-dns.txt` | FQDN-to-IP resolution results and DNS resolution status |
| `client-shodanscope-failed.txt` | Only created if one or more Shodan queries fail |

### Example inventory

```text
192.0.2.10
  Scope: explicit
  Explicit sources: 192.0.2.0/28
  DNS sources: -
  Ports: 22/tcp,443/tcp
  Services:
    22/tcp   OpenSSH 9.2
    443/tcp  nginx 1.24

198.51.100.20
  Scope: dns-derived
  Explicit sources: -
  DNS sources: example.com, portal.example.com
  Ports: 80/tcp,443/tcp
  Services:
    80/tcp   nginx
    443/tcp  nginx
```

### Scope classification

Discovered hosts are classified according to their relationship to the supplied scope:

| Classification | Description |
| --- | --- |
| `explicit` | IP address explicitly supplied or included within a supplied CIDR |
| `dns-derived` | IP address discovered through FQDN resolution |
| `explicit+dns` | IP address identified through both explicit scope and DNS resolution |
| `unattributed` | No matching scope attribution identified |

### Example DNS output

```text
FQDN                 IP_ADDRESS       STATUS
example.com          198.51.100.20    RESOLVED
portal.example.com   198.51.100.20    RESOLVED
```

The DNS inventory preserves multiple FQDNs resolving to the same IP address. Failed DNS resolutions are also recorded.

### Example ports output

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
- DNS resolution reflects the system resolver's response at execution time and may change.
- DNS-derived IP addresses may represent shared infrastructure or third-party services.
- CIDR inputs are normalized to their network addresses; the original host bits are not preserved in exported scope attribution.
- The tool does not perform active port validation or vulnerability assessment.
- Identical IP/port/protocol observations are deduplicated; only the latest timestamp is retained.

## Changelog

### v1.1.0
- Added automatic FQDN resolution using DNS A and AAAA records.
- Added support for mixed IP, CIDR, and FQDN scope files.
- Added deduplication of DNS-derived IP addresses and Shodan queries.
- Added FQDN-to-IP attribution and explicit/DNS-derived scope classification.
- Added DNS resolution inventory export.
- Added CIDR normalization warnings to improve scope awareness.

### v1.0.0
- Initial release with passive Shodan enumeration, host/service inventory, and CSV, JSON, and TXT exports.

## License

MIT
