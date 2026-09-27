"""Command line report generation."""
import argparse
from pathlib import Path
from engine import analyze, parse_text, report_json, alerts_csv

def main():
    parser = argparse.ArgumentParser(description='LogSentinel security log analyzer')
    parser.add_argument('logfile', help='Path to a log file')
    parser.add_argument('--json', dest='json_path', help='Save a JSON report')
    parser.add_argument('--csv', dest='csv_path', help='Save a CSV of alerts')
    args = parser.parse_args()
    try:
        text = Path(args.logfile).read_text(encoding='utf-8', errors='replace')
    except OSError as exc:
        parser.error(str(exc))
    report = analyze(*parse_text(text))
    print(f"Requests: {report['total_requests']} | Errors: {report['error_count']} | Error rate: {report['error_rate_pct']}% | Alerts: {report['alert_count']}")
    for alert in report['alerts'][:20]:
        print(f"[{alert['severity']}] {alert['type']} | {alert['ip']} | {alert['evidence']}")
    if args.json_path:
        Path(args.json_path).write_text(report_json(report), encoding='utf-8')
    if args.csv_path:
        Path(args.csv_path).write_text(alerts_csv(report['alerts']), encoding='utf-8')

if __name__ == '__main__':
    main()
