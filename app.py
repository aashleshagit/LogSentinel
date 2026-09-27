"""Streamlit frontend for LogSentinel."""
import json
from pathlib import Path
import pandas as pd
import streamlit as st
from engine import analyze, parse_text, report_json, alerts_csv

st.set_page_config(page_title='LogSentinel | Security Analytics', page_icon='🛡️', layout='wide')
st.markdown('''<style>
.block-container{padding-top:2rem} .hero{padding:1.5rem;border-radius:16px;background:linear-gradient(110deg,#14253c,#184d60);color:#fff;margin-bottom:1rem}
.hero h1{margin:0;font-size:2.5rem}.hero p{color:#bce5ef;margin:.5rem 0 0}
</style>''', unsafe_allow_html=True)
st.markdown('<div class="hero"><h1>🛡️ LogSentinel</h1><p>Security log intelligence · Traffic analytics · Explainable threat indicators</p></div>', unsafe_allow_html=True)
st.sidebar.header('Analysis settings')
threshold = st.sidebar.slider('Failed login alert threshold', 2, 30, 5)
scan = st.sidebar.slider('Distinct endpoint scan threshold', 3, 50, 12)
upload = st.file_uploader('Upload a server log (.log or .txt)', type=['log','txt'])
use_sample = st.checkbox('Use included demo log', value=upload is None)
if upload is not None:
    if upload.size > 20 * 1024 * 1024:
        st.error('Maximum upload size for this demo is 20 MB.')
        st.stop()
    content = upload.getvalue().decode('utf-8', errors='replace')
elif use_sample:
    content = (Path(__file__).parent / 'logs' / 'sample.log').read_text(encoding='utf-8')
else:
    st.info('Upload a log file or select the demo log to begin.')
    st.stop()
records, invalid = parse_text(content)
report = analyze(records, invalid, threshold, scan)
a,b,c,d,e = st.columns(5)
a.metric('Requests', f"{report['total_requests']:,}")
b.metric('Error rate', f"{report['error_rate_pct']}%")
c.metric('Unique IPs', report['unique_ips'])
d.metric('Security alerts', report['alert_count'])
e.metric('Invalid lines', report['invalid_lines'])
t1,t2,t3,t4 = st.tabs(['🚨 Threat indicators','📊 Traffic','⚡ Performance','📁 Export & methodology'])
with t1:
    st.subheader('Explainable security indicators')
    st.caption('Heuristic matches only. Investigate context before classifying traffic as malicious.')
    alerts = report['alerts']
    if alerts:
        severities = st.multiselect('Severity', ['High','Medium'], default=['High','Medium'])
        filtered = [x for x in alerts if x['severity'] in severities]
        st.dataframe(pd.DataFrame(filtered), use_container_width=True, hide_index=True)
        st.bar_chart(pd.Series(dict(pd.Series([x['type'] for x in filtered]).value_counts()), name='Alerts')) if filtered else st.info('No alerts match the filter.')
    else:
        st.success('No indicators matched the configured rules in this file.')
with t2:
    left,right = st.columns(2)
    with left:
        st.subheader('HTTP status distribution')
        st.bar_chart(pd.Series(report['status_codes'], name='Requests'))
        st.subheader('Top client IPs')
        st.bar_chart(pd.Series(dict(report['top_ips']), name='Requests'))
    with right:
        st.subheader('HTTP methods')
        st.bar_chart(pd.Series(report['methods'], name='Requests'))
        st.subheader('Top endpoints')
        st.bar_chart(pd.Series(dict(report['top_endpoints']), name='Requests'))
    if report['timeline']:
        st.subheader('Request volume by minute (timestamped logs)')
        st.line_chart(pd.Series(report['timeline'], name='Requests'))
with t3:
    st.subheader('Endpoint response latency')
    if report['endpoint_latency']:
        frame = pd.DataFrame(report['endpoint_latency'])
        st.dataframe(frame, use_container_width=True, hide_index=True)
        st.bar_chart(frame.set_index('endpoint')['avg_ms'])
    else:
        st.info('Latency is available for the custom log format only. Apache combined logs do not include request duration.')
with t4:
    st.download_button('⬇️ Download JSON report', report_json(report), 'logsentinel-report.json', 'application/json')
    st.download_button('⬇️ Download alert CSV', alerts_csv(report['alerts']), 'logsentinel-alerts.csv', 'text/csv')
    st.code('METHOD /path STATUS LATENCY_MS IP\nPOST /login 401 15 10.0.0.3', language='text')
    st.markdown('Also accepts Apache/Nginx **combined** access logs with timestamps. Files are processed locally in the running Streamlit process; avoid uploading sensitive logs to untrusted deployments. This is a rule-based educational tool, not an intrusion prevention system.')
    if invalid:
        st.warning(f"Skipped {len(invalid)} malformed lines; first line numbers: {invalid[:20]}")
