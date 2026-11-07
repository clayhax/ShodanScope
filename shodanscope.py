
#!/usr/bin/env python3
"""shodanscope v1.1 — passive Shodan scope inventory."""
import argparse
import csv
import ipaddress
import json
import os
import socket
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import shodan

FIELDS = ('ip', 'port', 'transport', 'service', 'product', 'version',
          'org', 'hostname', 'country', 'timestamp', 'scope_class', 'scope_sources', 'dns_sources')


def print_banner():
    """Display the compact ShodanScope startup banner."""
    color = sys.stdout.isatty() and 'NO_COLOR' not in os.environ
    cyan = '\033[96m' if color else ''
    reset = '\033[0m' if color else ''
    art = (
        '╔══════════════════════════════════════════╗\n'
        '║                                          ║\n'
        '║            SHODAN // SCOPE               ║\n'
        '║                                          ║\n'
        '║   Passive Internet Exposure Enumeration  ║\n'
        '║                                          ║\n'
        '╚══════════════════════════════════════════╝'
    )
    print(f'{cyan}{art}{reset}')
    print('  v1.1.0 | cl4yh4x | Powered by Shodan\n')


def load_scope(path):
    """Return unique IPs, CIDRs and FQDNs; reject malformed inputs."""
    entries, seen = [], set()
    with open(path, encoding='utf-8') as handle:
        for line_no, line in enumerate(handle, 1):
            value = line.split('#', 1)[0].strip()
            if not value:
                continue
            try:
                if '/' in value:
                    network = ipaddress.ip_network(value, strict=False)
                    item = ('net', str(network))

                    if str(network) != value:
                        print(
                            f"\n[!] CIDR normalized:\n"
                            f"    Supplied:   {value}\n"
                            f"    Effective:  {network}\n"
                            f"    Addresses:  {network.num_addresses:,}\n"
                            f"\n"
                            f"    Verify that the entire CIDR range is authorized."
                        )
                else:
                    try:
                        item = ('ip', str(ipaddress.ip_address(value)))
                    except ValueError:
                        fqdn = value.rstrip('.').lower()
                        if (len(fqdn) > 253 or len(fqdn) < 3 or '.' not in fqdn
                                or any(not label or len(label) > 63 or
                                       label[0] == '-' or label[-1] == '-' or
                                       not all(c.isascii() and (c.isalnum() or c == '-') for c in label)
                                       for label in fqdn.split('.'))):
                            raise ValueError('Invalid hostname')
                        item = ('fqdn', fqdn)
            except ValueError:
                print(f'[!] Skipping invalid entry at line {line_no}: {value}', file=sys.stderr)
                continue
            if item not in seen:
                entries.append(item)
                seen.add(item)
    return entries


def resolve_fqdn(hostname):
    """Perform DNS A/AAAA resolution only; no HTTP or port probing."""
    answers = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    return sorted({str(ipaddress.ip_address(answer[4][0])) for answer in answers}, key=address_key)


def prepare_queries(entries):
    """Deduplicate Shodan queries and track the original scope provenance."""
    queries, seen = [], set()
    explicit_ips, explicit_nets = set(), []
    dns_sources = defaultdict(set)
    dns_rows = []
    for kind, value in entries:
        if kind == 'ip':
            explicit_ips.add(value)
            query = f'ip:{value}'
        elif kind == 'net':
            explicit_nets.append(ipaddress.ip_network(value))
            query = f'net:{value}'
        else:
            try:
                addresses = resolve_fqdn(value)
                if not addresses:
                    dns_rows.append((value, '', 'NO_RECORDS'))
                    print(f'[!] DNS returned no A/AAAA addresses for {value}')
            except (socket.gaierror, OSError) as exc:
                dns_rows.append((value, '', f'ERROR: {exc}'))
                print(f'[!] DNS resolution failed for {value}: {exc}', file=sys.stderr)
                continue
            for ip in addresses:
                dns_sources[ip].add(value)
                dns_rows.append((value, ip, 'RESOLVED'))
                query = f'ip:{ip}'
                if query not in seen:
                    queries.append(query)
                    seen.add(query)
            continue
        if query not in seen:
            queries.append(query)
            seen.add(query)
    return queries, explicit_ips, explicit_nets, dns_sources, dns_rows


def annotate_provenance(records, explicit_ips, explicit_nets, dns_sources):
    for row in records:
        ip = row['ip']
        address = ipaddress.ip_address(ip)
        explicit = set()
        if ip in explicit_ips:
            explicit.add(ip)
        for network in explicit_nets:
            if address in network:
                explicit.add(str(network))
        dns = dns_sources.get(ip, set())
        row['scope_class'] = ('explicit+dns' if explicit and dns else
                              'explicit' if explicit else 'dns-derived' if dns else 'unattributed')
        row['scope_sources'] = ', '.join(sorted(explicit))
        row['dns_sources'] = ', '.join(sorted(dns))


def normalize(match):
    data = match.get('_shodan') or {}
    location = match.get('location') or {}
    return {
        'ip': str(match.get('ip_str', '')),
        'port': int(match['port']),
        'transport': str(match.get('transport') or 'tcp').lower(),
        'service': str(data.get('module') or ''),
        'product': str(match.get('product') or ''),
        'version': str(match.get('version') or ''),
        'org': str(match.get('org') or ''),
        'hostname': ', '.join(match.get('hostnames') or []),
        'country': str(location.get('country_name') or ''),
        'timestamp': str(match.get('timestamp') or ''),
        'banner': str(match.get('data') or '').strip(),
    }


def query_shodan(api, query, delay, max_retries):
    page = 1
    results = []
    while True:
        for attempt in range(max_retries + 1):
            try:
                response = api.search(query, page=page)
                break
            except shodan.APIError as exc:
                if attempt == max_retries:
                    raise RuntimeError(f'{query} page {page}: {exc}') from exc
                wait = delay * (2 ** attempt) + 1
                print(f'    [!] API error: {exc}; retrying in {wait:.1f}s')
                time.sleep(wait)
        matches = response.get('matches') or []
        total = int(response.get('total') or 0)
        if not matches:
            if page == 1:
                print('    No indexed results')
            elif len(results) < total:
                raise RuntimeError(f'{query}: pagination stopped after {len(results)} of {total} results')
            break
        for match in matches:
            if match.get('ip_str') and match.get('port') is not None:
                results.append(normalize(match))
        print(f'    Page {page}: {len(matches)} results (reported total: {total})')
        if len(results) >= total:
            break
        page += 1
        time.sleep(delay)
    return results


def address_key(ip):
    addr = ipaddress.ip_address(ip)
    return (addr.version, int(addr))


def endpoint(ip, port):
    return f'[{ip}]:{port}' if ipaddress.ip_address(ip).version == 6 else f'{ip}:{port}'


def save_outputs(records, prefix, dns_rows):
    csv_path = Path(str(prefix) + '.csv')
    json_path = Path(str(prefix) + '.json')
    inventory_path = Path(str(prefix) + '-inventory.txt')
    ports_path = Path(str(prefix) + '-ports.txt')
    dns_path = Path(str(prefix) + '-dns.txt')
    with csv_path.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        for row in records:
            writer.writerow({field: row[field] for field in FIELDS})
    with json_path.open('w', encoding='utf-8') as handle:
        json.dump(records, handle, indent=2)
    grouped = defaultdict(list)
    for row in records:
        grouped[row['ip']].append(row)
    with inventory_path.open('w', encoding='utf-8') as handle:
        for ip in sorted(grouped, key=address_key):
            rows = grouped[ip]
            ports = ','.join(f"{r['port']}/{r['transport']}" for r in rows)
            first = rows[0]
            handle.write(f"{ip}\n  Scope: {first['scope_class']}\n"
                         f"  Explicit sources: {first['scope_sources'] or '-'}\n"
                         f"  DNS sources: {first['dns_sources'] or '-'}\n"
                         f'  Ports: {ports}\n  Services:\n')
            for r in rows:
                description = ' '.join(filter(None, (r['product'], r['version']))) or r['service'] or 'unknown'
                handle.write(f"    {r['port']}/{r['transport']:<5} {description}\n")
            handle.write('\n')
    with ports_path.open('w', encoding='utf-8') as handle:
        for row in records:
            handle.write(endpoint(row['ip'], row['port']) + '\n')
    with dns_path.open('w', encoding='utf-8') as handle:
        handle.write('FQDN\tIP_ADDRESS\tSTATUS\n')
        for fqdn, ip, status in dns_rows:
            handle.write(f'{fqdn}\t{ip}\t{status}\n')
    return csv_path, json_path, inventory_path, ports_path, dns_path


def main():
    parser = argparse.ArgumentParser(description='Passive Shodan inventory for IPs, CIDRs and FQDNs')
    parser.add_argument('-i', '--input', default='scope.txt', help='Scope file (default: scope.txt)')
    parser.add_argument('-o', '--output', default='shodan', help='Output prefix (file extension removed)')
    parser.add_argument('--delay', type=float, default=1.0, help='Seconds between requests')
    parser.add_argument('--retries', type=int, default=2, help='Retries per failed API page')
    parser.add_argument('--no-banner', action='store_true', help='Suppress startup banner')
    args = parser.parse_args()
    if args.delay < 0 or args.retries < 0:
        parser.error('--delay and --retries must be non-negative')
    prefix = Path(args.output)
    if prefix.suffix.lower() in ('.txt', '.csv', '.json'):
        prefix = prefix.with_suffix('')
    key = os.environ.get('SHODAN_API_KEY', '').strip()
    if not key:
        config = Path.home() / '.config/shodan/api_key'
        if config.exists():
            key = config.read_text(encoding='utf-8').strip()
    if not key:
        parser.error('Shodan API key missing; run shodan init or set SHODAN_API_KEY')
    if not args.no_banner:
        print_banner()

    try:
        entries = load_scope(args.input)
    except OSError as exc:
        parser.error(f'Cannot read scope file: {exc}')

    if not entries:
        parser.error('No valid scope entries found')

    prefix.parent.mkdir(parents=True, exist_ok=True)
    api = shodan.Shodan(key)
    records = {}
    failed = []

    print(f'[+] Loaded {len(entries)} scope entries')
    queries, explicit_ips, explicit_nets, dns_sources, dns_rows = prepare_queries(entries)
    print(f'[+] Prepared {len(queries)} unique Shodan queries')
    for index, query in enumerate(queries, 1):
        print(f'\n[+] [{index}/{len(queries)}] Searching {query}', flush=True)
        try:
            matches = query_shodan(api, query, args.delay, args.retries)
        except RuntimeError as exc:
            print(f'    [!] {exc}', file=sys.stderr)
            failed.append(query)
            time.sleep(args.delay)
            continue
        for match in matches:
            ident = (match['ip'], match['port'], match['transport'])
            previous = records.get(ident)
            if previous is None or match['timestamp'] > previous['timestamp']:
                records[ident] = match
        if index < len(queries):
            time.sleep(args.delay)
    ordered = sorted(records.values(), key=lambda r: (*address_key(r['ip']), r['port'], r['transport']))
    annotate_provenance(ordered, explicit_ips, explicit_nets, dns_sources)
    paths = save_outputs(ordered, prefix, dns_rows)
    hosts = {r['ip'] for r in ordered}
    counts = Counter((r['port'], r['transport']) for r in ordered)
    print('\n' + '=' * 45)
    print(' SHODAN SCOPE SUMMARY')
    print('=' * 45)
    print(f' Hosts discovered: {len(hosts)}')
    print(f' Service records:  {len(ordered)}')
    print(f' Unique ports:     {len(counts)}')
    print(f' Failed queries:   {len(failed)}')
    print('\n Most common ports:')
    for (port, transport), count in counts.most_common(10):
        print(f'   {port}/{transport:<5} {count} hosts')
    print('=' * 45)
    for path in paths:
        print(f'[+] Saved: {path}')
    if failed:
        failed_path = Path(str(prefix) + '-failed.txt')
        failed_path.write_text('\n'.join(failed) + '\n', encoding='utf-8')
        print(f'[!] Failed queries saved: {failed_path}')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
