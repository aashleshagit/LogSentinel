import unittest
from engine import analyze, parse_text, parse_line, alerts_csv

class EngineTests(unittest.TestCase):
    def test_custom_and_invalid(self):
        rows, invalid = parse_text('# comment\nGET / 200 12 1.2.3.4\ninvalid\n')
        self.assertEqual((len(rows), invalid), (1, [3]))
    def test_combined(self):
        line = '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 "-" "Mozilla/5.0"'
        row = parse_line(line)
        self.assertEqual((row['ip'], row['status'], row['latency_ms']), ('127.0.0.1', 200, None))
    def test_full_aggregation(self):
        rows, bad = parse_text('GET /a 200 10 1.1.1.1\nGET /a 500 30 1.1.1.2')
        result = analyze(rows, bad)
        self.assertEqual((result['total_requests'], result['error_count'], result['error_rate_pct']), (2, 1, 50.0))
        self.assertEqual(result['endpoint_latency'][0]['avg_ms'], 20)
    def test_indicators(self):
        rows, bad = parse_text(('POST /login 401 10 1.1.1.1\n' * 5) + 'GET /../../etc/passwd 404 10 2.2.2.2')
        kinds = {a['type'] for a in analyze(rows, bad)['alerts']}
        self.assertIn('Repeated authentication failures', kinds)
        self.assertIn('Path traversal probe', kinds)
    def test_empty(self):
        self.assertEqual(analyze([])['error_rate_pct'], 0)
        self.assertIn('severity', alerts_csv([]))

if __name__ == '__main__':
    unittest.main()
