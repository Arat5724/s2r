"""Selected HTTP methods and declared input locations drive live probes."""

import copy
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from review import runtime
from verify import check


SCENARIO = 'c' * 16


@pytest.fixture
def target_server(monkeypatch):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.handle_probe()

        def do_POST(self):
            self.handle_probe()

        def handle_probe(self):
            parts = urlsplit(self.path)
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            seen.append((self.command, parts.path, parse_qs(parts.query), body,
                         dict(self.headers)))
            if parts.path == '/redirect':
                self.send_response(302)
                self.send_header('Location', '/unexpected')
            else:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{}')

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


def _route(value='baseline', *, method='POST', location='body', path='/inspect'):
    route = {'method': method, 'path': path, 'endpoint_id': 'ep',
             'scenario_id': SCENARIO, 'probe_kind': 'ai_generic',
             'query_key': 'term', 'probe_value': value}
    if location == 'body':
        route['input_location'] = 'body'
    return route


def _config(origin, routes):
    return {'connection_origin': origin, 'host_header': urlsplit(origin).netloc,
            'routes': routes}


def test_post_query_uses_selected_method_and_url_encoding(target_server):
    origin, seen = target_server
    [observation] = check(_config(origin, [_route('a b&c', location='query')]))
    assert (observation['method'], observation['input_location']) == ('POST', 'query')
    assert [(method, path, query, body) for method, path, query, body, _ in seen] == [
        ('POST', '/inspect', {'term': ['a b&c']}, b'')]


@pytest.mark.parametrize('candidate_change', [
    {'method': 'GET'}, {'path': '/other'}, {'input_location': 'query'},
    {'query_key': 'other'}, {'endpoint_id': 'another'},
])
def test_comparison_cannot_change_selected_route_before_network(target_server, candidate_change):
    origin, seen = target_server
    routes = [_route('base'), {**_route('candidate'), **candidate_change}]
    routes[0]['probe_label'] = 'baseline'
    routes[1]['probe_label'] = 'candidate'
    with pytest.raises(ValueError, match='comparison'):
        check(_config(origin, routes))
    assert seen == []


def test_post_json_body_has_one_field_and_no_credentials_or_redirect(target_server):
    origin, seen = target_server
    [observation] = check(_config(origin, [_route('candidate', path='/redirect')]))
    assert observation['status_code'] == 302
    assert (observation['method'], observation['input_location']) == ('POST', 'body')
    assert len(seen) == 1
    method, path, query, body, headers = seen[0]
    assert (method, path, query) == ('POST', '/redirect', {})
    assert json.loads(body) == {'term': 'candidate'}
    assert len(body) <= 512
    assert headers['Content-Type'] == 'application/json'
    assert 'Cookie' not in headers and 'Authorization' not in headers


def test_host_binds_post_body_to_selected_endpoint_and_probe(monkeypatch):
    monkeypatch.setattr(runtime, 'prove_probe_safe', lambda *_: (True, ''))
    endpoint = {'id': 'ep', 'method': 'POST', 'path': '/inspect',
                'inputs': [{'name': 'term', 'in': 'body', 'required': True}],
                'handler': {'file': 'app.py', 'line': 2, 'end_line': 4}}
    scenario = {'id': SCENARIO, 'method': 'POST', 'path': '/inspect',
                'endpoint_ids': ['ep'], 'input_name': 'term', 'input_location': 'body',
                'source_evidence': [{'file': 'app.py', 'line': 3}],
                'automatable': True}
    selection = {'scenario_ids': [SCENARIO], 'endpoint_ids': ['ep']}
    plan = {'probe': {'requests': [
        {'label': 'baseline', 'query_key': 'term', 'probe_value': 'base',
         'input_location': 'body'},
        {'label': 'candidate', 'query_key': 'term', 'probe_value': 'candidate',
         'input_location': 'body'},
    ]}}
    routes = runtime.validate_ai_routes([scenario], [endpoint], selection,
                                        {SCENARIO: plan}, {'app.py': ''})
    assert [(r['method'], r['input_location'], r['query_key']) for r in routes] == [
        ('POST', 'body', 'term'), ('POST', 'body', 'term')]
    runtime._validate_transport_routes(routes)
    [single] = runtime.validate_ai_routes(
        [scenario], [endpoint], selection,
        {SCENARIO: {'probe': {'query_key': 'term', 'probe_value': 'candidate',
                              'input_location': 'body'}}}, {'app.py': ''})
    assert single['method'] == 'POST' and single['input_location'] == 'body'
    assert runtime.validate_ai_routes([scenario], [endpoint],
                                      {**selection, 'endpoint_ids': []},
                                      {SCENARIO: plan}, {'app.py': ''}) == []
    with pytest.raises(ValueError):
        runtime.validate_ai_routes([{**scenario, 'method': 'GET'}], [endpoint],
                                   selection, {SCENARIO: plan}, {'app.py': ''})
    with pytest.raises(ValueError):
        runtime.validate_ai_routes([scenario], [endpoint], selection,
                                   {SCENARIO: {'probe': {'requests': [
                                       {**plan['probe']['requests'][0], 'input_location': 'query'},
                                       plan['probe']['requests'][1],
                                   ]}}}, {'app.py': ''})
    with pytest.raises(ValueError):
        runtime.validate_ai_routes([scenario], [{**endpoint, 'inputs': [
            *endpoint['inputs'], {'name': 'token', 'in': 'query', 'required': True},
        ]}], selection, {SCENARIO: plan}, {'app.py': ''})


def test_policy_uses_exact_selected_method_and_path(tmp_path, monkeypatch):
    run = tmp_path / 'job' / 'runs' / 'r1'
    run.mkdir(parents=True)
    baseline = {'network_policies': {'managed_inference': {'name': 'managed_inference'}}}
    current = {'policy': copy.deepcopy(baseline)}
    applied = []

    def command(*args, **_kwargs):
        if args[:2] == ('sandbox', 'get'):
            return json.dumps({'policy': current['policy']})
        if args[:2] == ('sandbox', 'download'):
            (run / 'observations.json').write_text('{"observations": []}', encoding='utf-8')
        return ''

    def set_policy(policy, *_args, **_kwargs):
        current['policy'] = copy.deepcopy(policy)
        applied.append(copy.deepcopy(policy))

    monkeypatch.setattr(runtime.bridge, 'sandbox_for_job', lambda _job: 'sandbox')
    monkeypatch.setattr(runtime.bridge, 'probe', lambda **_kwargs: None)
    monkeypatch.setattr(runtime.bridge, 'stage_input', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(runtime.bridge, 'wsl_path', lambda path: str(path))
    monkeypatch.setattr(runtime.bridge, 'command', command)
    monkeypatch.setattr(runtime, 'set_policy', set_policy)
    target = {'policy_host': 'example.test', 'port': 8080,
              'connection_origin': 'http://example.test:8080',
              'host_header': 'example.test:8080'}
    routes = [_route('base', method='POST'),
              {**_route('candidate', method='POST'), 'scenario_id': 'd' * 16},
              {**_route('more', method='GET', location='query'), 'scenario_id': 'e' * 16}]
    _, scope = runtime.observe(run, target, routes, lambda *_args: None)
    assert applied[0]['network_policies']['runtime_target']['endpoints'][0]['rules'] == [
        {'allow': {'method': 'GET', 'path': '/inspect'}},
        {'allow': {'method': 'POST', 'path': '/inspect'}}]
    assert scope['allowed_routes'] == [
        {'method': 'GET', 'path': '/inspect'},
        {'method': 'POST', 'path': '/inspect'}]
    assert scope['method'] == 'MIXED' and scope['policy_restored'] is True
    assert current['policy'] == baseline


def test_no_live_route_does_not_claim_get_method(tmp_path):
    observations, scope = runtime.observe(tmp_path, {}, [], lambda *_args: None)
    assert observations == []
    assert scope['method'] is None
    assert scope['allowed_routes'] == []


@pytest.mark.parametrize('mutation', [
    {'method': 'post'}, {'input_location': 'form'}, {'path': '/inspect/{id}'},
    {'query_key': 'term[]'}, {'probe_value': 'x;delete'},
])
def test_worker_rejects_invalid_route_before_network(target_server, mutation):
    origin, seen = target_server
    with pytest.raises(ValueError):
        check(_config(origin, [{**_route(), **mutation}]))
    assert seen == []
