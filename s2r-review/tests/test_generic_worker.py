"""The worker executes bounded, selected model-generated HTTP observations."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from verify import check


IDENTIFIER = 'a' * 16
PROBE = '<strong>s2r_probe12345678</strong>'


@pytest.fixture
def generic_server(monkeypatch):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.do_GET()

        def do_GET(self):
            parts = urlsplit(self.path)
            seen.append((parts.path, parse_qs(parts.query), dict(self.headers)))
            if parts.path == '/leave':
                self.send_response(302)
                self.send_header('Location', '/never-visit')
                self.end_headers()
                return
            value = parse_qs(parts.query).get('term', [''])[0]
            body = f'<html><main>{value}</main></html>'.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
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


def _route(path='/preview'):
    return {'method': 'GET', 'path': path, 'probe_kind': 'ai_generic',
            'scenario_id': IDENTIFIER, 'query_key': 'term', 'probe_value': PROBE}


def test_model_generated_marker_uses_only_selected_get_and_query(generic_server):
    origin, seen = generic_server
    [observation] = check(_config(origin, [_route()]))
    assert observation['path'] == '/preview'
    assert observation['probe_kind'] == 'ai_generic'
    assert observation['scenario_id'] == IDENTIFIER
    assert observation['status_code'] == 200
    assert observation['body_within_limit'] is True
    assert PROBE in observation['body_text']
    assert seen[0][:2] == ('/preview', {'term': [PROBE]})
    assert len(seen) == 1
    assert 'Cookie' not in seen[0][2] and 'Authorization' not in seen[0][2]


def test_selected_post_query_keeps_exact_method_and_path(generic_server):
    origin, seen = generic_server
    [observation] = check(_config(origin, [{**_route(), 'method': 'POST'}]))
    assert observation['method'] == 'POST'
    assert observation['path'] == '/preview'
    assert observation['input_location'] == 'query'
    assert len(seen) == 1 and seen[0][:2] == ('/preview', {'term': [PROBE]})


@pytest.mark.parametrize('kind', [
    None, 'xss', 'sqli', 'path_traversal', 'open_redirect',
    'xss_generic', 'open_redirect_generic', 'unknown',
])
def test_worker_rejects_non_ai_probe_kinds_before_network(generic_server, kind):
    origin, seen = generic_server
    with pytest.raises(ValueError, match='AI-generated'):
        check(_config(origin, [_route(), {**_route(), 'probe_kind': kind}]))
    assert seen == []


@pytest.mark.parametrize('mutation', [
    {'method': 'post'}, {'path': '/preview?other=1'},
    {'path': '/preview/../private'}, {'query_key': 'term[]'},
    {'probe_value': 'x;delete'}, {'probe_value': 'x\nheader'},
    {'probe_value': 'x`command`'}, {'scenario_id': 'wrong-id'},
])
def test_worker_rejects_unapproved_ai_route_before_network(generic_server, mutation):
    origin, seen = generic_server
    with pytest.raises(ValueError):
        check(_config(origin, [{**_route(), **mutation}]))
    assert seen == []


def test_worker_does_not_follow_redirect(generic_server):
    origin, seen = generic_server
    [observation] = check(_config(origin, [_route('/leave')]))
    assert observation['status_code'] == 302
    assert observation['headers']['Location'] == '/never-visit'
    assert [path for path, _, _ in seen] == ['/leave']


def test_worker_rejects_duplicate_and_oversized_batches_before_network(generic_server):
    origin, seen = generic_server
    with pytest.raises(ValueError, match='Duplicate'):
        check(_config(origin, [_route(), _route()]))
    with pytest.raises(ValueError, match='scope'):
        check(_config(origin, [_route()] * 11))
    assert seen == []
