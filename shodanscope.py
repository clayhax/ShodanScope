#!/usr/bin/env python3
"""shodanscope v1.0 — passive Shodan scope inventory."""
import argparse
import csv
import ipaddress
import json
import os
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import shodan

FIELDS = ('ip', 'port', 'transport', 'service', 'product', 'version',
          'org', 'hostname', 'country', 'timestamp')


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
    print('  v1.0.0 | cl4yh4x | Powered by Shodan\n')


def load_scope(path):
    queries = []
    seen = set()
    with open(path, encoding='utf-8') as handle:
        for line_no, line in enumerate(handle, 1):
            value = line.split('#', 1)[0].strip()
            if not value:
                continue
            try:
                target = (f'net:{ipaddress.ip_network(value, strict=False)}'
                          if '/' in value else f'ip:{ipaddress.ip_address(value)}')
            except ValueError:
                print(f'[!] Skipping invalid entry at line {line_no}: {value}', file=sys.stderr)
                continue
            if target not in seen:
                queries.append(target)
                seen.add(target)
    return queries


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


def save_outputs(records, prefix):
    csv_path = Path(str(prefix) + '.csv')
    json_path = Path(str(prefix) + '.json')
    inventory_path = Path(str(prefix) + '-inventory.txt')
    ports_path = Path(str(prefix) + '-ports.txt')
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
            handle.write(f'{ip}\n  Ports: {ports}\n  Services:\n')
            for r in rows:
                description = ' '.join(filter(None, (r['product'], r['version']))) or r['service'] or 'unknown'
                handle.write(f"    {r['port']}/{r['transport']:<5} {description}\n")
            handle.write('\n')
    with ports_path.open('w', encoding='utf-8') as handle:
        for row in records:
            handle.write(endpoint(row['ip'], row['port']) + '\n')
    return csv_path, json_path, inventory_path, ports_path


def main():
    parser = argparse.ArgumentParser(description='Passive Shodan inventory for scoped IPs and CIDRs')
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
    try:
        queries = load_scope(args.input)
    except OSError as exc:
        parser.error(f'Cannot read scope file: {exc}')
    if not queries:
        parser.error('No valid scope entries found')
    prefix.parent.mkdir(parents=True, exist_ok=True)
    api = shodan.Shodan(key)
    records = {}
    failed = []
    if not args.no_banner:
        print_banner()
    print(f'[+] Loaded {len(queries)} scope entries')
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
    paths = save_outputs(ordered, prefix)
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
