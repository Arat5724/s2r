"""Paired AI requests retain the selected GET route and bounded transport."""

import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from review import runtime
from review.ai_scripts import evaluate_observation
from review.scripts import render_script
from verify import check


SCENARIO = 'a' * 16


def _routes(candidate='../private/example.txt'):
    common = {'method': 'GET', 'path': '/api/files', 'endpoint_id': 'endpoint',
              'scenario_id': SCENARIO, 'probe_kind': 'ai_generic', 'query_key': 'name'}
    return [
        {**common, 'probe_label': 'baseline', 'probe_value': 'guide.txt'},
        {**common, 'probe_label': 'candidate', 'probe_value': candidate},
    ]


@pytest.fixture
def echo_server(monkeypatch):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            target = urlsplit(self.path)
            seen.append((target.path, parse_qs(target.query), dict(self.headers)))
            value = parse_qs(target.query).get('name', [''])[0]
            if value == 'https://example.invalid/out':
                self.send_response(302)
                self.send_header('Location', value)
                self.end_headers()
                return
            if value == 'missing.txt':
                self.send_response(404)
                self.end_headers()
                return
            body = value.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv('NO_PROXY', '127.0.0.1,localhost')
    try:
        yield f'http://127.0.0.1:{server.server_port}', seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _config(origin, routes):
    return {'connection_origin': origin, 'host_header': urlsplit(origin).netloc,
            'routes': routes}


def test_paired_requests_keep_exact_route_and_encode_value(echo_server):
    origin, seen = echo_server
    observed = check(_config(origin, _routes()))
    assert [row['probe_label'] for row in observed] == ['baseline', 'candidate']
    assert [row['status_code'] for row in observed] == [200, 200]
    assert observed[1]['body_text'] == '../private/example.txt'
    assert [(path, query) for path, query, _ in seen] == [
        ('/api/files', {'name': ['guide.txt']}),
        ('/api/files', {'name': ['../private/example.txt']}),
    ]
    assert all('Cookie' not in headers and 'Authorization' not in headers
               for _, _, headers in seen)


def test_paired_redirect_is_observed_without_following(echo_server):
    origin, seen = echo_server
    result = check(_config(origin, _routes('https://example.invalid/out')))
    assert result[1]['status_code'] == 302
    assert result[1]['headers']['Location'] == 'https://example.invalid/out'
    assert len(seen) == 2


@pytest.mark.parametrize('mutation', [
    lambda rows: [{**rows[0], 'method': 'POST'}, rows[1]],
    lambda rows: [{**rows[0], 'path': '/other'}, rows[1]],
    lambda rows: [{**rows[0], 'probe_label': 'candidate'}, rows[1]],
    lambda rows: [{**rows[0], 'query_key': 'other'}, rows[1]],
    lambda rows: [{**rows[0], 'probe_value': 'bad\nheader'}, rows[1]],
    lambda rows: [{**rows[0], 'probe_value': '한글'}, rows[1]],
    lambda rows: [{**rows[0], 'probe_value': '<script>alert(1)</script>'}, rows[1]],
    lambda rows: [{**rows[0], 'probe_value': 'javascript:alert(1)'}, rows[1]],
    lambda rows: [{**rows[0], 'probe_value': 'https://other.invalid/'}, rows[1]],
    lambda rows: [rows[0], {**rows[1], 'probe_value': 'guide.txt'}],
])
def test_invalid_pair_rejected_before_any_request(echo_server, mutation):
    origin, seen = echo_server
    with pytest.raises(ValueError):
        check(_config(origin, mutation(_routes())))
    assert seen == []


def test_host_route_plan_binds_pair_to_selected_get(monkeypatch):
    monkeypatch.setattr(runtime, 'prove_probe_safe', lambda *_: (True, ''))
    endpoint = {'id': 'endpoint', 'path': '/api/files', 'method': 'GET',
                'inputs': [{'name': 'name', 'in': 'query'}],
                'handler': {'file': 'app.py', 'line': 5, 'end_line': 8}}
    scenario = {'id': SCENARIO, 'path': '/api/files', 'method': 'GET',
                'input_name': 'name', 'automatable': True,
                'endpoint_ids': ['endpoint'],
                'source_evidence': [{'file': 'app.py', 'line': 6}]}
    selection = {'scenario_ids': [SCENARIO], 'endpoint_ids': ['endpoint']}
    plan = {'probe': {'requests': [
        {'label': 'baseline', 'query_key': 'name', 'probe_value': 'guide.txt'},
        {'label': 'candidate', 'query_key': 'name',
         'probe_value': '../private/example.txt'},
    ]}}
    assert runtime.validate_ai_routes([scenario], [endpoint], selection,
                                      {SCENARIO: plan}, {'app.py': ''}) == _routes()
    runtime._validate_transport_routes(_routes())


def test_downloaded_script_sends_same_pair_without_exposing_body(echo_server, tmp_path):
    origin, seen = echo_server
    scenario = {'id': SCENARIO, 'title': '파일 응답 비교', 'method': 'GET',
                'path': '/api/files', 'automatable': True,
                'source_context': 'FILE app.py\nL00001 def read_file(name: str):'}
    assignments = ''.join(f"    {name} = response.get('{name}')\n" for name in (
        'status', 'error', 'body_text', 'body_within_limit', 'headers',
        'baseline_status', 'baseline_error', 'baseline_body_text',
        'baseline_body_within_limit', 'baseline_headers'))
    plan = {'probe': {'requests': [
        {'label': 'baseline', 'query_key': 'name', 'probe_value': 'guide.txt'},
        {'label': 'candidate', 'query_key': 'name',
         'probe_value': '../private/example.txt'},
    ]}, 'source': 'def evaluate(response):\n' + assignments
                  + "    return ('inconclusive', '응답만으로 판단할 수 없습니다.')\n",
            'reason': '입력에 따른 파일 응답을 비교합니다.'}
    script = tmp_path / 'check.py'
    script.write_text(render_script(origin, [scenario], {SCENARIO: plan}), encoding='utf-8')
    completed = subprocess.run([sys.executable, '-I', str(script)], capture_output=True,
                               text=True, encoding='utf-8', timeout=20)
    assert completed.returncode == 1, completed.stderr
    result = json.loads(completed.stdout)
    assert result['status'] == 'inconclusive'
    assert result['baseline_http_status'] == result['http_status'] == 200
    assert [(path, query) for path, query, _ in seen] == [
        ('/api/files', {'name': ['guide.txt']}),
        ('/api/files', {'name': ['../private/example.txt']}),
    ]
    assert '../private/example.txt' not in completed.stdout


def test_downloaded_pair_interprets_candidate_404_like_host(echo_server, tmp_path):
    origin, _ = echo_server
    scenario = {'id': SCENARIO, 'title': '파일 응답 비교', 'method': 'GET',
                'path': '/api/files', 'automatable': True,
                'source_context': 'FILE app.py\nL00001 def read_file(name: str):'}
    assignments = ''.join(f"    {name} = response.get('{name}')\n" for name in (
        'status', 'error', 'body_text', 'body_within_limit', 'headers',
        'baseline_status', 'baseline_error', 'baseline_body_text',
        'baseline_body_within_limit', 'baseline_headers'))
    plan = {'probe': {'requests': [
        {'label': 'baseline', 'query_key': 'name', 'probe_value': 'guide.txt'},
        {'label': 'candidate', 'query_key': 'name', 'probe_value': 'missing.txt'},
    ]}, 'source': 'def evaluate(response):\n' + assignments
                  + "    if baseline_status == 200 and status == 404:\n"
                  + "        return ('pass', '후보 파일이 차단되었습니다.')\n"
                  + "    return ('inconclusive', '응답만으로 판단할 수 없습니다.')\n",
            'reason': '기준 요청은 성공하고 후보 요청은 차단되는지 비교합니다.'}
    script = tmp_path / 'check.py'
    script.write_text(render_script(origin, [scenario], {SCENARIO: plan}), encoding='utf-8')
    completed = subprocess.run([sys.executable, '-I', str(script)], capture_output=True,
                               text=True, encoding='utf-8', timeout=20)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)['status'] == 'pass'
    host_status, _ = evaluate_observation(plan, scenario, {
        'baseline': {'status_code': 200, 'error': None, 'body_text': 'guide',
                     'body_within_limit': True, 'headers': {}},
        'candidate': {'status_code': 404, 'error': None, 'body_text': '',
                      'body_within_limit': True, 'headers': {}},
    })
    assert host_status == 'pass'
