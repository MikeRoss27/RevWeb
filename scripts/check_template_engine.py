#!/usr/bin/env python3
"""Check the real CLI against vulnerable/safe local Jinja2 rendering.

Requires Jinja2 in the test environment; it is not a webrev runtime dependency.
No downloads, external targets, OS commands on the target or generated files.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import threading
from urllib.parse import parse_qs, urlsplit

from jinja2 import Environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    args = parser.parse_args()
    engine = Environment(autoescape=True)
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            url = urlsplit(self.path)
            value = parse_qs(url.query).get('q', ['hello'])[0]
            status = 200
            if url.path == '/vulnerable':
                body = engine.from_string(value).render()
            elif url.path == '/safe':
                body = engine.from_string('{{ value }}').render(value=value)
            else:
                status, body = 404, 'missing'
            body = body.encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Security-Policy', "frame-ancestors 'none'")
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    results = {}
    try:
        for route, expected in [('vulnerable', 1), ('safe', 0)]:
            requests.clear()
            seed = f'http://127.0.0.1:{server.server_port}/{route}?q=hello'
            run = subprocess.run([
                str(args.binary.resolve()), 'active', '--seed', seed,
                '--delay-min-ms', '0', '--delay-max-ms', '0',
                '--max-active-requests', '60', '--report', '-',
            ], capture_output=True, text=True, encoding='utf-8', timeout=30, check=True)
            report = json.loads(run.stdout)
            evidence = [f['evidence'] for f in report['findings']
                        if f.get('evidence', {}).get('check') == 'template_arithmetic']
            coverage = next(f['coverage'] for f in report['findings'] if 'coverage' in f)
            assert len(evidence) == expected, (route, evidence)
            assert coverage['requests'] == len(requests), (coverage, requests)
            for proof in evidence:
                assert proof['verdict'] == 'evaluation_confirmed'
                assert len(proof['observations']) == 4
                first, second = proof['observations'][1:3]
                assert first['excerpt'] != second['excerpt']
                assert proof['observations'][3]['role'] == 'payload_free_control'
            results[route] = {'expression_findings': len(evidence), 'coverage': coverage,
                              'evidence': evidence}
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
