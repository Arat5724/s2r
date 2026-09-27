import threading
import time

import pytest
from fastapi.testclient import TestClient

from review import main


@pytest.fixture
def client(tmp_path, monkeypatch):
    data = tmp_path / 'data'
    data.mkdir()
    (data / 'jobs').mkdir()
    monkeypatch.setattr(main, 'DATA', data)
    # These API checks intentionally exercise the archived TeamShelf fixture.
    # The application now registers TechLab as its built-in default.
    main.write_json(data / 'projects.json', [
        {'id': 'teamshelf', 'name': 'TeamShelf (legacy test)', 'path': str(main.SAMPLE)}])
    main.RUNNING = threading.Lock()
    with TestClient(main.app) as client:
        client.headers['X-S2R-Token'] = client.get('/api/config').json()['token']
        futures = []
        original_submit = main.POOL.submit
        def submit(*args, **kwargs):
            future = original_submit(*args, **kwargs)
            futures.append(future)
            return future
        monkeypatch.setattr(main.POOL, 'submit', submit)
        yield client
        for future in futures:
            future.result(timeout=15)


def wait(client, job):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        status = client.get('/api/jobs/' + job).json()
        if status['state'] in {'completed', 'failed'}:
            return status
        time.sleep(0.02)
    raise AssertionError(f'Test job did not complete: {status}')


def fake_worker(folder, update, project_root):
    # This API test checks transport, history and report handling. Source
    # discovery belongs to the model tests, so the worker result is explicit.
    return {
        'analysis_mode': 'ai', 'framework': 'FastAPI',
        'endpoints': [{'id': 'model-order-route', 'method': 'GET', 'path': '/api/orders',
                       'handler': {'file': 'app/routers/orders.py', 'line': 13,
                                   'symbol': 'list_orders'}, 'conditions': [],
                       'inputs': [], 'call_chain': [], 'auth': 'needs_review'}],
        'counts': {'total': 1, 'by_method': {'GET': 1}},
        'ai_scenarios': [],
        'ai': {'status': 'completed', 'project_summary': 'API 테스트 프로젝트',
               'endpoints': [{'id': 'model-order-route', 'summary': '주문 목록'}]},
        'boundary': {'passed': True}, 'diagnostics': [], 'limitations': [],
    }


def test_request_origin_and_csrf_are_enforced(client):
    payload = {'project_id': 'teamshelf', 'ai': False}
    assert client.post('/api/jobs', json=payload, headers={'X-S2R-Token': ''}).status_code == 403
    assert client.post('/api/jobs', json=payload, headers={'Origin': 'http://unrelated.invalid'}).status_code == 403
    assert client.get('/', headers={'host': 'unrelated.invalid'}).status_code == 400
    assert "frame-ancestors 'none'" in client.get('/').headers['content-security-policy']


def test_unknown_project_and_extra_path_input_rejected(client):
    assert client.post('/api/jobs', json={'project_id': 'not-registered'}).status_code == 404
    assert client.post('/api/jobs', json={'project_id': 'teamshelf', 'path': 'C:/'}).status_code == 422
    assert client.post('/api/jobs', json={'project_id': 'teamshelf', 'ai': False}).status_code == 400
    assert client.get('/api/jobs/not-a-uuid').status_code == 404


def test_result_evidence_history_and_downloads(client, monkeypatch):
    monkeypatch.setattr(main.bridge, 'run', fake_worker)
    response = client.post('/api/jobs', json={'project_id': 'teamshelf', 'ai': True})
    assert response.status_code == 202
    job = response.json()['id']
    assert wait(client, job)['state'] == 'completed'
    result = client.get(f'/api/jobs/{job}/result').json()
    assert result['counts']['total'] == 1 and result['source_unchanged']
    assert client.get('/api/jobs').json()['items'][0]['id'] == job
    source = client.get(f'/api/jobs/{job}/source', params={'file': 'app/main.py'})
    assert source.status_code == 200 and 'FastAPI' in source.json()['content']
    assert client.get(f'/api/jobs/{job}/source', params={'file': '../teamshelf-evaluation/expected-endpoints.json'}).status_code == 404
    assert client.get(f'/api/jobs/{job}/source', params={'file': 'C:/Windows/win.ini'}).status_code == 404
    assert client.get(f'/api/jobs/{job}/download/json').json()['id'] == job
    report = client.get(f'/api/jobs/{job}/download/report')
    assert report.status_code == 200 and '/api/orders' in report.text
    assert client.get(f'/api/jobs/{job}/download/bundle').status_code == 404


def test_one_job_at_a_time_and_failures_release_lock(client, monkeypatch):
    started, release = threading.Event(), threading.Event()
    def blocked_worker(*args):
        started.set()
        release.wait(5)
        raise RuntimeError('Simulated worker unavailable')
    monkeypatch.setattr(main.bridge, 'run', blocked_worker)
    job = client.post('/api/jobs', json={'project_id': 'teamshelf', 'ai': True}).json()['id']
    try:
        assert started.wait(5)
        assert client.post('/api/jobs', json={'project_id': 'teamshelf'}).status_code == 409
    finally:
        release.set()
    assert wait(client, job)['state'] == 'failed'
    assert client.get(f'/api/jobs/{job}/result').status_code == 409
    assert not main.RUNNING.locked()
