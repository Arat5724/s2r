import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from review.scripts import render_review_script, render_script


SOURCE = '''def evaluate(response):
    status = response.get('status')
    error = response.get('error')
    body_text = response.get('body_text')
    body_within_limit = response.get('body_within_limit')
    headers = response.get('headers')
    content_type = headers.get('content-type', '')
    is_html = 'text/html' in content_type
    if status == 200 and body_within_limit and is_html and '<strong>s2r_probe_12345678</strong>' in body_text:
        return ('fail', '고유 마커가 응답에 있습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''
OFFLINE_SOURCE = (SOURCE.replace("    content_type = headers.get('content-type', '')\n"
                                 "    is_html = 'text/html' in content_type\n", '')
                  .replace(' and is_html and ', ' and ')
                  .replace('<strong>s2r_probe_12345678</strong>', 'TECHLAB_PRIVATE_CANARY'))


def scenario(identifier, path='/search', method='GET', automatable=True):
    return {'id': identifier, 'title': f'{method} {path}', 'path': path,
            'method': method, 'automatable': automatable,
            'category': 'custom', 'execution_kind': 'ai_source_check',
            'source_context': 'FILE app.py\nL00007     return "TECHLAB_PRIVATE_CANARY"'}


def plan(query=True):
    return {'probe': {'query_key': 'term' if query else None,
                      'probe_value': '<strong>s2r_probe_12345678</strong>' if query else None},
            'source': SOURCE, 'reason': '소스의 응답 생성 코드를 점검합니다.'}


def test_downloaded_script_sends_only_selected_get_and_uses_ai_evaluator(tmp_path):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.command, self.path, dict(self.headers)))
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<strong>s2r_probe_12345678</strong> sensitive body')

        def do_POST(self):
            raise AssertionError('POST must not be sent')

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    row = scenario('a' * 16)
    try:
        file = tmp_path / 'check.py'
        file.write_text(render_script(f'http://127.0.0.1:{server.server_port}',
                                      [row], {row['id']: plan()}), encoding='utf-8')
        process = subprocess.run([sys.executable, '-I', str(file)],
                                 capture_output=True, text=True, encoding='utf-8', timeout=20)
    finally:
        server.shutdown()
        server.server_close()
    assert process.returncode == 1, process.stderr
    result = json.loads(process.stdout)
    assert result['status'] == 'fail'
    assert result['http_status'] == 200
    assert len(seen) == 1 and seen[0][0] == 'GET'
    parts = urlsplit(seen[0][1])
    assert parts.path == '/search'
    assert parse_qs(parts.query) == {'term': ['<strong>s2r_probe_12345678</strong>']}
    assert not {'Authorization', 'Cookie', 'Content-Length'} & seen[0][2].keys()
    assert 'sensitive body' not in process.stdout


@pytest.mark.parametrize('origin', ['http://user@127.0.0.1:8010', 'http://127.0.0.1:8010/private'])
def test_script_rejects_non_origin_targets(origin):
    row = scenario('a' * 16)
    with pytest.raises(ValueError):
        render_script(origin, [row], {row['id']: plan()})


def test_script_rejects_nonliteral_or_unapproved_routes():
    row = scenario('a' * 16)
    with pytest.raises(ValueError):
        render_script('http://127.0.0.1:8010', [{**row, 'path': '/{id}'}],
                      {row['id']: plan()})
    with pytest.raises(ValueError):
        render_script('http://127.0.0.1:8010', [{**row, 'method': 'TRACE'}],
                      {row['id']: plan()})
    with pytest.raises(ValueError):
        render_script('http://127.0.0.1:8010', [{**row, 'automatable': False}],
                      {row['id']: plan()})


def test_downloaded_script_sends_selected_post_with_bounded_json_body(tmp_path):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            size = int(self.headers['Content-Length'])
            seen.append((self.command, self.path, dict(self.headers), self.rfile.read(size)))
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<strong>s2r_probe_12345678</strong>')

        def do_GET(self):
            raise AssertionError('GET must not be sent for a selected POST')

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    row = scenario('e' * 16, path='/submit', method='POST')
    body_plan = plan()
    body_plan['probe']['input_location'] = 'body'
    try:
        file = tmp_path / 'post-check.py'
        file.write_text(render_script(f'http://127.0.0.1:{server.server_port}',
                                      [row], {row['id']: body_plan}), encoding='utf-8')
        process = subprocess.run([sys.executable, '-I', str(file)],
                                 capture_output=True, text=True, encoding='utf-8', timeout=20)
    finally:
        server.shutdown()
        server.server_close()
    assert process.returncode == 1, process.stderr
    assert json.loads(process.stdout)['method'] == 'POST'
    assert len(seen) == 1
    method, path, headers, body = seen[0]
    assert (method, path) == ('POST', '/submit')
    assert headers['Content-Type'] == 'application/json'
    assert len(body) <= 512
    assert json.loads(body) == {'term': '<strong>s2r_probe_12345678</strong>'}
    assert not {'Authorization', 'Cookie'} & headers.keys()


def test_downloaded_script_keeps_baseline_and_candidate_on_same_post_body(tmp_path):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            seen.append((self.path, body))
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(body['term'].encode('utf-8'))

        def log_message(self, *_):
            pass

    source = '''def evaluate(response):
    status = response.get('status')
    error = response.get('error')
    body_text = response.get('body_text')
    body_within_limit = response.get('body_within_limit')
    headers = response.get('headers')
    baseline_status = response.get('baseline_status')
    baseline_error = response.get('baseline_error')
    baseline_body_text = response.get('baseline_body_text')
    baseline_body_within_limit = response.get('baseline_body_within_limit')
    baseline_headers = response.get('baseline_headers')
    content_type = headers.get('content-type', '')
    if '<strong>s2r_probe_12345678</strong>' not in baseline_body_text and 'text/html' in content_type and '<strong>s2r_probe_12345678</strong>' in body_text:
        return ('fail', '후보 응답에서만 태그가 관찰되었습니다.')
    return ('inconclusive', '두 응답만으로 판단할 수 없습니다.')
'''
    pair = {'probe': {'requests': [
        {'label': 'baseline', 'query_key': 'term', 'probe_value': 's2r_probe_12345678',
         'input_location': 'body'},
        {'label': 'candidate', 'query_key': 'term',
         'probe_value': '<strong>s2r_probe_12345678</strong>', 'input_location': 'body'},
    ]}, 'source': source, 'reason': '같은 본문 입력의 기준값과 후보값을 비교합니다.'}
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    row = {**scenario('c' * 16, path='/submit', method='POST'),
           'source_context': 'FILE app.py\nL00007 def submit(term):\nL00008     return term'}
    try:
        file = tmp_path / 'post-pair.py'
        file.write_text(render_script(f'http://127.0.0.1:{server.server_port}',
                                      [row], {row['id']: pair}), encoding='utf-8')
        process = subprocess.run([sys.executable, '-I', str(file)],
                                 capture_output=True, text=True, encoding='utf-8', timeout=20)
    finally:
        server.shutdown()
        server.server_close()
    assert process.returncode == 1, process.stderr
    assert json.loads(process.stdout)['method'] == 'POST'
    assert seen == [('/submit', {'term': 's2r_probe_12345678'}),
                    ('/submit', {'term': '<strong>s2r_probe_12345678</strong>'})]


@pytest.mark.parametrize('method', ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])
def test_live_script_records_exact_approved_method(method):
    row = scenario('f' * 16, method=method)
    script = render_script('http://127.0.0.1:8010', [row], {row['id']: plan()})
    namespace = {'__name__': 'test_download'}
    exec(compile(script, '<download>', 'exec'), namespace)
    assert namespace['CONFIG']['scenarios'][0]['method'] == method


def test_offline_script_uses_ai_code_but_never_contains_network_transport(tmp_path):
    row = scenario('b' * 16, path='/items/{item_id}', method='POST', automatable=False)
    offline_plan = {**plan(query=False), 'source': OFFLINE_SOURCE}
    offline = render_review_script(row, offline_plan)
    assert 'ai_evaluate_' + row['id'] in offline
    assert 'http.client' not in offline
    assert 'connection.request' not in offline
    file = tmp_path / 'offline.py'
    file.write_text(offline, encoding='utf-8')
    response = subprocess.run(
        [sys.executable, '-I', str(file)],
        input=json.dumps({'status': 200, 'error': None,
                          'body_text': 'TECHLAB_PRIVATE_CANARY', 'body_within_limit': True,
                          'headers': {}}),
        capture_output=True, text=True, encoding='utf-8', timeout=10)
    assert response.returncode == 0, response.stderr
    assert json.loads(response.stdout)['status'] == 'fail'


def test_get_scenario_with_null_probe_can_be_reviewed_offline():
    row = scenario('d' * 16, automatable=True)
    offline_plan = {**plan(query=False), 'source': OFFLINE_SOURCE}
    source = render_review_script(row, offline_plan)
    assert f'ai_evaluate_{row["id"]}' in source
    assert 'connection.request' not in source
