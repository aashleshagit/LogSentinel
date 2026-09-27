"""LogSentinel parsing, aggregation and explainable security heuristics."""
from __future__ import annotations
import csv
import io
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from urllib.parse import unquote

CUSTOM = re.compile(r'^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+(\d{3})\s+([\d.]+)\s+(\S+)(?:\s+(.*))?$', re.I)
COMBINED = re.compile(r'^(\S+)\s+\S+\s+\S+\s+\[([^]]+)\]\s+"(\S+)\s+(\S+)\s+[^\"]+"\s+(\d{3})\s+(\S+)(?:\s+"[^"]*"\s+"([^"]*)")?')
SUSPICIOUS = {
    'SQL injection probe': re.compile(r"(?:\bunion\s+(?:all\s+)?select\b|\bor\s+1\s*=\s*1\b|\bsleep\s*\(|\binformation_schema\b)", re.I),
    'Path traversal probe': re.compile(r'\.\./|\.\.\\|/etc/passwd|win\.ini', re.I),
    'XSS probe': re.compile(r'<script|javascript:|onerror\s*=|onload\s*=', re.I),
    'Sensitive path probe': re.compile(r'/(?:\.env|\.git|wp-admin|phpmyadmin|admin|config\.(?:php|json))(?:[/?]|$)', re.I),
}

def parse_line(line, line_no=0):
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    m = CUSTOM.match(line)
    if m:
        method, path, status, latency, ip, extra = m.groups()
        try:
            latency = float(latency)
            if not math.isfinite(latency) or latency < 0 or not 100 <= int(status) <= 599:
                return None
        except ValueError:
            return None
        return dict(method=method.upper(), path=path, status=int(status), latency_ms=latency,
                    ip=ip, timestamp=None, user_agent=extra or '', line_no=line_no)
    m = COMBINED.match(line)
    if m:
        ip, stamp, method, path, status, size, agent = m.groups()
        try:
            dt = datetime.strptime(stamp, '%d/%b/%Y:%H:%M:%S %z')
        except ValueError:
            return None
        return dict(method=method.upper(), path=path, status=int(status), latency_ms=None,
                    ip=ip, timestamp=dt.isoformat(), user_agent=agent or '', line_no=line_no)
    return None

def parse_text(text):
    records, invalid = [], []
    for i, line in enumerate(io.StringIO(text), 1):
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        rec = parse_line(line, i)
        if rec is None:
            invalid.append(i)
        else:
            records.append(rec)
    return records, invalid

def analyze(records, invalid=None, brute_threshold=5, scan_threshold=12):
    invalid = invalid or []
    ips = Counter(r['ip'] for r in records)
    statuses = Counter(str(r['status']) for r in records)
    methods = Counter(r['method'] for r in records)
    paths = Counter(r['path'].split('?')[0] for r in records)
    latencies = defaultdict(list)
    by_ip = defaultdict(list)
    timeline = Counter()
    alerts = []
    for r in records:
        by_ip[r['ip']].append(r)
        if r['latency_ms'] is not None:
            latencies[r['path'].split('?')[0]].append(r['latency_ms'])
        if r['timestamp']:
            timeline[r['timestamp'][:16]] += 1
        decoded = unquote(unquote(r['path']))
        for label, pattern in SUSPICIOUS.items():
            if pattern.search(decoded):
                alerts.append(dict(severity='High' if label != 'Sensitive path probe' else 'Medium',
                                   type=label, ip=r['ip'], evidence=r['path'][:180], line=r['line_no'],
                                   explanation='Request path matched a detection pattern; investigate before attributing intent.'))
    for ip, events in by_ip.items():
        failures = [r for r in events if r['status'] in (401, 403) and re.search(r'login|signin|auth', r['path'], re.I)]
        if len(failures) >= brute_threshold:
            alerts.append(dict(severity='High', type='Repeated authentication failures', ip=ip,
                               evidence=f'{len(failures)} failed login/auth requests', line=None,
                               explanation='Repeated authentication failures may indicate password guessing; thresholds are per input file, not per time window.'))
        unique = len(set(r['path'].split('?')[0] for r in events))
        if unique >= scan_threshold:
            alerts.append(dict(severity='Medium', type='Multi-endpoint scanning pattern', ip=ip,
                               evidence=f'{unique} distinct endpoints', line=None,
                               explanation='Many distinct endpoints from one IP may reflect scanning or legitimate crawling.'))
    alerts.sort(key=lambda a: (0 if a['severity']=='High' else 1, a['ip'], a['type']))
    count = len(records)
    errors = sum(r['status'] >= 400 for r in records)
    endpoints = [dict(endpoint=k, requests=paths[k], avg_ms=round(sum(v)/len(v), 2),
                      max_ms=round(max(v), 2)) for k, v in latencies.items()]
    endpoints.sort(key=lambda e: e['avg_ms'], reverse=True)
    return dict(total_requests=count, error_count=errors, error_rate_pct=round(100*errors/count, 2) if count else 0,
                unique_ips=len(ips), invalid_lines=len(invalid), invalid_line_numbers=invalid[:100],
                status_codes=dict(sorted(statuses.items())), methods=dict(methods),
                top_ips=ips.most_common(10), top_endpoints=paths.most_common(10),
                endpoint_latency=endpoints, timeline=dict(sorted(timeline.items())),
                alerts=alerts, alert_count=len(alerts),
                format_note='Custom format includes latency; Apache/Nginx combined format does not. Heuristic alerts are not proof of an attack.')

def report_json(report):
    return json.dumps(report, indent=2, ensure_ascii=False)

def alerts_csv(alerts):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=['severity','type','ip','evidence','line','explanation'])
    writer.writeheader()
    writer.writerows(alerts)
    return buf.getvalue()
