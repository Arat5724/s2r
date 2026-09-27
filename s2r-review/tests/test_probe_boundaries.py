"""AI probe boundaries: selected route, inert marker, bounded evidence."""

import copy
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from review import runtime
from review.ai_scripts import evaluate_observation, validate_plan
from review.scripts import render_review_script, render_script
from verify import MAX_BODY, check


MARKER = '<strong>s2r_unique_12345678</strong>'
IDENTIFIER = 'a' * 16
APP_FILES = {'app.py': 'from fastapi import FastAPI\nfrom fastapi.responses import HTMLResponse\n'
                       'app = FastAPI()\n@app.get("/echo")\ndef echo(q: str = ""):\n'
                       '    return HTMLResponse(q)\n'}
SOURCE = '''def evaluate(response):
    status = response.get('status')
    error = response.get('error')
    body_text = response.get('body_text')
    body_within_limit = response.get('body_within_limit')
    headers = response.get('headers')
    content_type = headers.get('content-type', '')
    is_html = 'text/html' in content_type
    if status == 200 and body_within_limit and is_html and '<strong>s2r_unique_12345678</strong>' in body_text:
        return ('fail', '고유 마커가 응답에 있습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''
OFFLINE_SOURCE = (SOURCE.replace("    content_type = headers.get('content-type', '')\n"
                                 "    is_html = 'text/html' in content_type\n", '')
                  .replace(' and is_html and ', ' and ')
                  .replace(MARKER, 'TECHLAB_PRIVATE_CANARY'))


def scenario(*, method='GET', path='/echo', automatable=True):
    return {
        'id': IDENTIFIER, 'title': '선택한 함수의 응답 확인',
        'method': method, 'path': path, 'category': 'custom',
        'endpoint_ids': ['ep-1'], 'input_name': 'q',
        'source_evidence': [{'file': 'app.py', 'line': 6}],
        'automatable': automatable,
        'source_context': 'FILE app.py\nL00006     return "TECHLAB_PRIVATE_CANARY"',
    }


def endpoint():
    return {
        'id': 'ep-1', 'method': 'GET', 'path': '/echo', 'framework': 'FastAPI',
        'inputs': [{'name': 'q', 'in': 'query', 'required': False}],
        'conditions': [], 'guards': [], 'dependencies': [],
        'effects': {'assessment': 'no_write_detected'},
        'handler': {'file': 'app.py', 'line': 5, 'end_line': 6,
                    'symbol': 'echo',
                    'snippet': 'def echo(q: str = ""):\n    return HTMLResponse(q)\n'},
    }


def plan():
    return {'probe': {'query_key': 'q', 'probe_value': MARKER},
            'source': SOURCE, 'reason': 'echo 함수가 q를 응답에 포함합니다.'}


def route():
    return {'method': 'GET', 'path': '/echo', 'endpoint_id': 'ep-1',
            'scenario_id': IDENTIFIER, 'probe_kind': 'ai_generic',
            'query_key': 'q', 'probe_value': MARKER}


@pytest.fixture
def probe_server(monkeypatch):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.do_GET()

        def do_GET(self):
            parts = urlsplit(self.path)
            query = parse_qs(parts.query).get('q', [''])[0]
            seen.append((self.command, parts.path, query, dict(self.headers)))
            if parts.path == '/redirect':
                self.send_response(302)
                self.send_header('Location', '/never-visit')
                self.end_headers()
                return
            if parts.path == '/big':
                body = b'X' * (MAX_BODY + 8)
            elif parts.path == '/echo':
                body = f'<p>{query} private-response-marker</p>'.encode()
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
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


def config(origin, routes):
    return {'connection_origin': origin, 'host_header': urlsplit(origin).netloc,
            'routes': routes}


def test_ai_probe_sends_one_selected_get_and_returns_bounded_observation(probe_server):
    origin, seen = probe_server
    observations = check(config(origin, [route()]))
    assert len(observations) == 1
    observation = observations[0]
    assert observation['scenario_id'] == IDENTIFIER
    assert observation['status_code'] == 200
    assert observation['body_within_limit'] is True
    assert MARKER in observation['body_text']
    assert [(method, path, query) for method, path, query, _ in seen] == [
        ('GET', '/echo', MARKER)]
    assert 'Authorization' not in seen[0][3] and 'Cookie' not in seen[0][3]
    verdict = evaluate_observation(validate_plan(plan(), scenario()), scenario(), observation)
    assert verdict[0] == 'fail'


def test_ai_probe_sends_selected_post_query(probe_server):
    origin, seen = probe_server
    [observation] = check(config(origin, [{**route(), 'method': 'POST'}]))
    assert (observation['method'], observation['path'], observation['input_location']) == (
        'POST', '/echo', 'query')
    assert [(method, path, query) for method, path, query, _ in seen] == [
        ('POST', '/echo', MARKER)]


@pytest.mark.parametrize('changed', [
    {'method': 'post'}, {'path': '/echo?q=other'},
    {'path': '/a/../echo'}, {'probe_value': 'x;delete'},
    {'probe_value': 'x\nheader'},
    {'probe_value': 'x`command`'},
    {'query_key': 'q&evil=1'}, {'scenario_id': 'not-an-id'},
])
def test_worker_rejects_unapproved_ai_request_before_network(probe_server, changed):
    origin, seen = probe_server
    with pytest.raises(ValueError):
        check(config(origin, [{**route(), **changed}]))
    assert seen == []


def test_worker_rejects_duplicate_or_oversized_ai_requests(probe_server):
    origin, seen = probe_server
    with pytest.raises(ValueError):
        check(config(origin, [route(), route()]))
    with pytest.raises(ValueError):
        check(config(origin, [route()] * 11))
    assert seen == []


def test_worker_limits_body_and_never_follows_redirect(probe_server):
    origin, seen = probe_server
    first = {**route(), 'path': '/big'}
    second = {**route(), 'path': '/redirect', 'scenario_id': 'b' * 16}
    observed = check(config(origin, [first, second]))
    assert observed[0]['body_within_limit'] is False
    assert observed[0]['body_text'] == ''
    assert observed[1]['status_code'] == 302
    assert [path for _, path, _, _ in seen] == ['/big', '/redirect']


def test_runtime_binds_probe_to_selected_source_supported_get():
    selected = scenario()
    chosen = {'scenario_ids': [IDENTIFIER], 'endpoint_ids': ['ep-1']}
    approved = validate_plan(plan(), selected)
    assert runtime.validate_ai_routes([selected], [endpoint()], chosen,
                                      {IDENTIFIER: approved}, APP_FILES) == [route()]
    blocked = copy.deepcopy(endpoint())
    blocked['effects']['database_write_detected'] = True
    with pytest.raises(ValueError):
        runtime.validate_ai_routes([selected], [blocked], chosen, {IDENTIFIER: approved}, APP_FILES)
    assert runtime.validate_ai_routes([selected], [endpoint()],
                                      {**chosen, 'endpoint_ids': []},
                                      {IDENTIFIER: approved}, APP_FILES) == []


def test_downloaded_script_uses_same_model_probe_and_evaluator_without_body_leak(
        probe_server, tmp_path):
    origin, seen = probe_server
    selected = scenario()
    script = tmp_path / 'check.py'
    script.write_text(render_script(origin, [selected], {IDENTIFIER: plan()}), encoding='utf-8')
    result = subprocess.run([sys.executable, '-I', str(script)], capture_output=True,
                            text=True, encoding='utf-8', timeout=20)
    assert result.returncode == 1, result.stderr
    output = json.loads(result.stdout)
    assert output['status'] == 'fail' and output['http_status'] == 200
    assert [(method, path, query) for method, path, query, _ in seen] == [
        ('GET', '/echo', MARKER)]
    assert 'private-response-marker' not in result.stdout


def test_non_get_dynamic_route_gets_offline_ai_script_without_network(tmp_path):
    selected = scenario(method='POST', path='/items/{item_id}', automatable=False)
    offline = {**plan(), 'probe': {'query_key': None, 'probe_value': None},
               'source': OFFLINE_SOURCE}
    source = render_review_script(selected, offline)
    assert 'http.client' not in source
    assert 'connection.request' not in source
    file = tmp_path / 'review.py'
    file.write_text(source, encoding='utf-8')
    process = subprocess.run(
        [sys.executable, '-I', str(file)],
        input=json.dumps({'status': 200, 'error': None, 'body_text': 'TECHLAB_PRIVATE_CANARY',
                          'body_within_limit': True, 'headers': {}}),
        capture_output=True, text=True, encoding='utf-8', timeout=10)
    assert process.returncode == 0, process.stderr
    assert json.loads(process.stdout)['status'] == 'fail'
