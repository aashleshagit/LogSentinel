# 🛡️ LogSentinel — Security Log Analytics

An explainable, rule-based cybersecurity analytics project built by extending a basic Python log analyzer. It processes custom access logs and Apache/Nginx combined access logs, visualizes HTTP activity, flags potential threat indicators, and exports reports.

## Features
- Streamlit dashboard: request volume, status codes, methods, IPs and endpoints
- Heuristic indicators: SQL injection probes, path traversal, XSS probes, sensitive paths, repeated failed logins and multi-endpoint scanning
- Configurable thresholds for failed logins and distinct endpoints
- Per-endpoint average and maximum latency for custom logs
- Timestamp-based per-minute traffic visualization for combined logs
- JSON summary and CSV alert exports; CLI mode; malformed-line tracking
- Automated `unittest` coverage and synthetic demo log

**Important:** Matches are *indicators*, not proof of an attack. Authentication and scan thresholds aggregate over the entire uploaded file; they are not time-window detectors. No IP reputation lookup, geo-IP, machine learning, live monitoring or attack blocking is implemented. Combined logs do not provide latency. Do not upload sensitive production logs to public Streamlit deployments.

## Quick start (Windows PowerShell)

```powershell
cd LogSentinel
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

If PowerShell blocks activation, skip it and run `.\.venv\Scripts\python.exe -m pip install -r requirements.txt` followed by `.\.venv\Scripts\python.exe -m streamlit run app.py`.

Select the included demo log or upload your own `.log` / `.txt` file.

## Command-line mode

```powershell
python cli.py logs/sample.log --json reports/summary.json --csv reports/alerts.csv
```

## Test

```powershell
python -m unittest discover -s tests -v
```

## Supported formats

Custom: `POST /login 401 15 10.0.0.3` (method, path, status, latency in milliseconds, IP).

Apache/Nginx combined: `127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 "-" "Mozilla/5.0"`.

Other formats (JSON, syslog, CloudTrail) are not supported. Very large logs are not streaming in this version: the entire file is read into memory. Dashboard upload limit is 20 MB.

## Project structure

```
LogSentinel/
├── app.py               # Streamlit dashboard
├── engine.py            # Parser, metrics and security heuristics
├── cli.py               # CLI report exporter
├── logs/sample.log      # Synthetic demo events
├── tests/test_engine.py # Unit tests
├── requirements.txt
└── README.md
```

## Resume description

**LogSentinel | Python, Streamlit, Pandas, Cybersecurity** — Developed a security log analytics dashboard supporting custom and Apache/Nginx access logs. Implemented explainable detection rules for suspicious request patterns, authentication failures and endpoint scanning; visualized traffic/error trends and exported JSON/CSV investigation reports.

Only describe features you have run and can demonstrate. The included sample data is synthetic.
