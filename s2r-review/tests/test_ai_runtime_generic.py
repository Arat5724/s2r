"""AI probes retain selected HTTP method and bounded host/worker transport."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from review import runtime
from verify import MAX_BODY, check


FIRST_ID = 'a' * 16
SECOND_ID = 'b' * 16
PROBE_VALUE = 's2r_probe12345'
FILES = {'app.py': 'from fastapi import FastAPI\nfrom fastapi.responses import HTMLResponse\n'
                   'app = FastAPI()\n@app.get("/echo")\ndef echo(q: str = ""):\n'
                   '    return HTMLResponse(q)\n'}


def _endpoint(identifier='endpoint-one', path='/echo', query_key='q'):
    return {
        'id': identifier, 'framework': 'FastAPI', 'method': 'GET', 'path': path,
        'inputs': [{'name': query_key, 'in': 'query', 'required': False}],
        'conditions': [], 'guards': [], 'dependencies': [],
        'handler': {'file': 'app.py', 'line': 5, 'end_line': 6,
                    'symbol': 'echo', 'reason': 'handler',
                    'snippet': 'def echo(q: str = ""):\n    return HTMLResponse(q)\n'},
        'call_chain': [{'file': 'app.py', 'line': 5}],
    }


def _scenario(identifier=FIRST_ID, endpoint_id='endpoint-one', path='/echo', query_key='q'):
    return {
        'id': identifier, 'method': 'GET', 'path': path,
        'endpoint_ids': [endpoint_id], 'input_name': query_key,
        'automatable': True,
        'source_evidence': [{'file': 'app.py', 'line': 6}],
    }


def _plan(query_key='q', value=PROBE_VALUE):
    return {'probe': {'query_key': query_key, 'probe_value': value}}


def _selection(scenarios, endpoints):
    return {'scenario_ids': [item['id'] for item in scenarios],
            'endpoint_ids': [item['id'] for item in endpoints]}


def test_host_routes_only_the_selected_scenario_and_selected_endpoint():
    one, two = _scenario(), _scenario(SECOND_ID, 'endpoint-two', '/other', 'token')
    endpoints = [_endpoint(), _endpoint('endpoint-two', '/other', 'token')]
    plans = {FIRST_ID: _plan(), SECOND_ID: _plan('token')}
    chosen = {'scenario_ids': [FIRST_ID], 'endpoint_ids': [row['id'] for row in endpoints]}
    assert runtime.validate_ai_routes([one, two], endpoints, chosen, plans, FILES) == [{
        'method': 'GET', 'path': '/echo', 'endpoint_id': 'endpoint-one',
        'scenario_id': FIRST_ID, 'probe_kind': 'ai_generic',
        'query_key': 'q', 'probe_value': PROBE_VALUE}]
    assert runtime.validate_ai_routes([one], endpoints,
                                      {'scenario_ids': [FIRST_ID], 'endpoint_ids': []}, plans, FILES) == []
    assert runtime.validate_ai_routes([one], endpoints,
                                      {'scenario_ids': [], 'endpoint_ids': ['endpoint-one']}, plans, FILES) == []


@pytest.mark.parametrize('query_key,value', [
    ('other', PROBE_VALUE),
    ('q', 'https://attacker.invalid'),
    ('q', '<script>s2r_probe12345</script>'),
    ('q', '<strong>s2r_probe12345</em>'),
    ('q', 'x;DROP'),
])
def test_host_rejects_wrong_query_key_and_unsafe_ai_values(query_key, value):
    scenario, endpoint = _scenario(), _endpoint()
    with pytest.raises(ValueError):
        runtime.validate_ai_routes([scenario], [endpoint], _selection([scenario], [endpoint]),
                                   {FIRST_ID: _plan(query_key, value)}, FILES)


def test_host_allows_distinct_selected_scenarios_on_one_endpoint():
    one, two = _scenario(), _scenario(SECOND_ID)
    endpoint = _endpoint()
    routes = runtime.validate_ai_routes([one, two], [endpoint],
                                        _selection([one, two], [endpoint]),
                                        {FIRST_ID: _plan(), SECOND_ID: _plan()}, FILES)
    assert [item['scenario_id'] for item in routes] == [FIRST_ID, SECOND_ID]


@pytest.fixture
def local_site(monkeypatch):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.do_GET()

        def do_GET(self):
            parts = urlsplit(self.path)
            seen.append((parts.path, parse_qs(parts.query), self.command))
            if parts.path == '/redirect':
                self.send_response(302)
                self.send_header('Location', '/private')
                self.end_headers()
                return
            if parts.path == '/private':
                body = b'private response should not be fetched'
            elif parts.path == '/large':
                body = b'X' * (MAX_BODY + 20)
            else:
                body = b'<p>safe fixture</p>'
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except ConnectionResetError:
                pass

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv('NO_PROXY', '127.0.0.1,localhost')
    try:
        yield {'connection_origin': f'http://127.0.0.1:{server.server_port}',
               'host_header': f'127.0.0.1:{server.server_port}'}, seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _route(path='/echo', query_key='q', value=PROBE_VALUE, identifier=FIRST_ID):
    return {'method': 'GET', 'path': path, 'probe_kind': 'ai_generic',
            'scenario_id': identifier, 'query_key': query_key, 'probe_value': value}


def test_worker_sends_one_get_with_only_selected_query_key(local_site):
    config, seen = local_site
    observations = check({**config, 'routes': [_route()]})
    assert len(observations) == 1
    assert observations[0]['scenario_id'] == FIRST_ID
    assert observations[0]['status_code'] == 200
    assert seen == [('/echo', {'q': [PROBE_VALUE]}, 'GET')]


def test_worker_sends_selected_post_on_exact_path(local_site):
    config, seen = local_site
    [observation] = check({**config, 'routes': [{**_route(), 'method': 'POST'}]})
    assert observation['method'] == 'POST'
    assert observation['input_location'] == 'query'
    assert seen == [('/echo', {'q': [PROBE_VALUE]}, 'POST')]


@pytest.mark.parametrize('mutation', [
    {'method': 'post'},
    {'path': '/private?admin=1'},
    {'path': '/../private'},
    {'path': '//private'},
    {'query_key': 'bad-key'},
    {'query_key': 'admin&root'},
    {'probe_value': 'x;DROP'},
    {'probe_value': '<script>s2r_probe12345</script>'},
    {'probe_value': '<strong>s2r_probe12345</em>'},
    {'scenario_id': 'not-a-valid-id'},
])
def test_worker_rejects_malicious_ai_route_before_any_request(local_site, mutation):
    config, seen = local_site
    route = {**_route(), **mutation}
    with pytest.raises(ValueError):
        check({**config, 'routes': [route]})
    assert seen == []


def test_worker_rejects_duplicate_same_scenario_route_before_any_request(local_site):
    config, seen = local_site
    route = _route()
    duplicate = {**route, 'scenario_id': FIRST_ID}
    with pytest.raises(ValueError, match='[Dd]uplicate|중복'):
        check({**config, 'routes': [route, duplicate]})
    assert seen == []


def test_worker_allows_distinct_scenarios_on_one_route(local_site):
    config, seen = local_site
    route = _route()
    second = {**route, 'scenario_id': SECOND_ID}
    observed = check({**config, 'routes': [route, second]})
    assert len(observed) == 2
    assert [item['scenario_id'] for item in observed] == [FIRST_ID, SECOND_ID]
    assert len(seen) == 2


def test_worker_bounds_response_body_and_does_not_follow_redirect(local_site):
    config, seen = local_site
    observations = check({**config, 'routes': [_route('/large'), _route('/redirect', identifier=SECOND_ID)]})
    assert [(row['path'], row['status_code']) for row in observations] == [
        ('/large', 200), ('/redirect', 302)]
    assert observations[0]['body_within_limit'] is False
    assert observations[0]['body_text'] == ''
    assert observations[1]['headers']['Location'] == '/private'
    assert '/private' not in [path for path, _, _ in seen]
    assert seen == [('/large', {'q': [PROBE_VALUE]}, 'GET'),
                    ('/redirect', {'q': [PROBE_VALUE]}, 'GET')]
