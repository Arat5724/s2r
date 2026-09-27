import json
import threading
import uuid

import pytest
from fastapi.testclient import TestClient

from review import main, runtime
from review.dependencies import audit_dependencies
from review.dependency_scenarios import build_dependency_scenarios
from review.snapshot import snapshot


def sample():
    bundle = snapshot(main.TECHLAB)
    files = bundle['files']
    lines = files['app/main.py'].splitlines()
    endpoints = []
    for identifier, path, symbol in [
        ('preview-route', '/search/preview', 'search_preview'),
        ('file-route', '/api/files', 'read_file'),
    ]:
        line = next(index for index, text in enumerate(lines, 1)
                    if text.strip().startswith(f'def {symbol}('))
        endpoints.append({'id': identifier, 'framework': 'FastAPI',
                          'method': 'GET', 'path': path,
                          'handler': {'file': 'app/main.py', 'line': line,
                                      'symbol': symbol}})
    facts = {'analysis_mode': 'deterministic', 'framework': 'FastAPI',
             'endpoints': endpoints, 'counts': {'total': len(endpoints)}}
    return facts, files


def test_target_is_only_an_origin_and_blocks_metadata():
    assert runtime.validate_target('http://127.0.0.1:8010')['policy_host'] == 'host.docker.internal'
    for value in ['file:///tmp/data', 'http://user:pass@localhost:8010',
                  'http://127.0.0.1:8020', 'http://169.254.169.254',
                  'http://127.0.0.2:8010', 'http://metadata.google.internal',
                  'http://localhost:8010/private']:
        try:
            runtime.validate_target(value)
        except ValueError:
            pass
        else:
            raise AssertionError(value)


def test_osv_query_sends_only_exact_public_name_versions():
    seen = []
    def fetch(payload):
        seen.append(payload)
        return {'results': [{'vulns': [{'id': 'GHSA-test-1234'}]}]}
    audit = audit_dependencies({'requirements.txt': 'fastapi==0.141.1\nfastapi==0.141.1\nflask>=3\n',
                                'requirements-private.txt': '--index-url https://private.invalid\nsecret-lib==1.0\n'}, fetch)
    assert seen == [{'queries': [{'package': {'name': 'fastapi', 'ecosystem': 'PyPI'}, 'version': '0.141.1'}]}]
    assert audit['status'] == 'partial'
    assert audit['packages'][0]['advisories'][0]['id'] == 'GHSA-test-1234'
    assert len(audit['unresolved']) == 2


def test_advisory_creates_manual_code_grounded_scenario():
    facts, files = sample()
    files['requirements.txt'] = 'fastapi==0.141.1\n'
    audit = {'packages': [{'name': 'fastapi', 'version': '0.141.1', 'source_files': ['requirements.txt'],
                           'advisories': [{'id': 'GHSA-test-1234', 'url': 'https://osv.dev/vulnerability/GHSA-test-1234'}]}]}
    scenarios = build_dependency_scenarios(audit, files)
    assert len(scenarios) == 1 and scenarios[0]['category'] == 'dependency_advisory'
    assert scenarios[0]['endpoint_ids'] == [] and not scenarios[0]['automatable']
    assert scenarios[0]['source_evidence'][0]['file'] == 'requirements.txt'
    assert scenarios[0]['source_evidence'][0]['line'] > 0


def test_runtime_restores_policy_if_activation_reports_failure(tmp_path, monkeypatch):
    original = {'network_policies': {'managed_inference': {'name': 'managed_inference'}}}
    current = {'value': original}
    calls = []
    def command(*args, **kwargs):
        assert args[:2] == ('sandbox', 'get')
        return json.dumps({'policy': current['value']})
    def set_policy(policy, folder, suffix):
        calls.append(suffix)
        current['value'] = policy
        if suffix == 'active':
            raise RuntimeError('activation reply lost')
    monkeypatch.setattr(runtime.bridge, 'command', command)
    monkeypatch.setattr(runtime.bridge, 'stage_input', lambda *_, **__: None)
    monkeypatch.setattr(runtime.bridge, 'probe', lambda *_, **__: {'passed': True})
    monkeypatch.setattr(runtime, 'set_policy', set_policy)
    target = runtime.validate_target('http://127.0.0.1:8010')
    with pytest.raises(RuntimeError, match='activation reply lost'):
        runtime.observe(tmp_path, target, [{'method': 'GET', 'path': '/',
                                            'endpoint_id': 'one',
                                            'scenario_id': 'a' * 16,
                                            'probe_kind': 'ai_generic',
                                            'query_key': 'q',
                                            'probe_value': 's2r_probe_12345678'}],
                        lambda *_: None)
    assert calls == ['active', 'restored'] and current['value'] == original


@pytest.fixture
def workflow_client(tmp_path, monkeypatch):
    data = tmp_path / 'data'
    job = data / 'jobs' / str(uuid.uuid4())
    job.mkdir(parents=True)
    monkeypatch.setattr(main, 'DATA', data)
    monkeypatch.setattr(main, 'RUNNING', threading.Lock())
    facts, files = sample()
    facts.update(id=job.name, project={'id': 'techlab', 'name': 'TechLab', 'path': str(main.TECHLAB)},
                 created_at=main.stamp(), source_hash='test-source-hash', source_unchanged=True,
                 boundary={'passed': True}, ai={'status': 'not_requested'})
    main.write_json(job / 'result.json', facts)
    main.write_json(job / 'bundle.json', {'files': files})
    main.write_json(job / 'status.json', {'id': job.name, 'state': 'completed', 'created_at': main.stamp()})
    # Archived catalogs remain readable without re-running retired detectors.
    routes = {row['path']: row for row in facts['endpoints']}
    archived = [{'id': identifier, 'category': category,
                 'endpoint_ids': [routes[path]['id']], 'method': 'GET', 'path': path,
                 'automatable': False, 'disabled_reason': '이전 분석 기록',
                 'source_evidence': [{'file': routes[path]['handler']['file'],
                                      'line': routes[path]['handler']['line']}],
                 'title': title}
                for identifier, category, path, title in (
                    ('aaaaaaaaaaaaaaaa', 'xss', '/search/preview', '이전 표시 항목'),
                    ('bbbbbbbbbbbbbbbb', 'path_traversal', '/api/files', '이전 파일 항목'))]
    main.write_json(job / 'scenarios.json', {'version': 7, 'scenarios': archived})
    with TestClient(main.app) as client:
        client.headers['X-S2R-Token'] = client.get('/api/config').json()['token']
        yield client, job.name


def test_archived_scenario_categories_and_selection_keep_endpoint_boundary(workflow_client):
    client, job = workflow_client
    root = f'/api/jobs/{job}'
    workflow = client.get(root + '/workflow').json()
    scenarios = workflow['scenarios']
    stored = main.read_json(main.job_path(job) / 'scenarios.json')
    assert {row['id']: row['category'] for row in stored['scenarios']} == {
        row['id']: row['category'] for row in scenarios}
    assert {row['category'] for row in scenarios} == {'xss', 'path_traversal'}

    # A category-wide UI choice persists as scenario IDs. Endpoint consent is
    # saved separately, so choosing a category alone cannot create requests.
    category_ids = [row['id'] for row in scenarios if row['category'] == 'xss']
    saved = client.put(root + '/selection', json={
        'revision': 0, 'scenario_ids': category_ids, 'endpoint_ids': [],
        'target_base_url': 'http://127.0.0.1:8010'})
    assert saved.status_code == 200
    assert saved.json()['scenario_ids'] == category_ids
    assert saved.json()['endpoint_ids'] == []
    assert client.get(root + '/workflow').json()['selection'] == saved.json()


def test_legacy_workflow_selection_persists_but_run_is_read_only(workflow_client, monkeypatch):
    client, job = workflow_client
    root = f'/api/jobs/{job}'
    workflow = client.get(root + '/workflow').json()
    xss = next(s for s in workflow['scenarios'] if s['category'] == 'xss')
    traversal = next(s for s in workflow['scenarios'] if s['category'] == 'path_traversal')
    assert client.put(root + '/selection', json={'revision': 0, 'scenario_ids': ['unknown'],
        'endpoint_ids': [], 'target_base_url': 'http://127.0.0.1:8010'}).status_code == 400
    data = {'revision': 0, 'scenario_ids': [xss['id'], traversal['id']],
            'endpoint_ids': [], 'target_base_url': 'http://127.0.0.1:8010'}
    saved = client.put(root + '/selection', json=data)
    assert saved.status_code == 200 and saved.json()['revision'] == 1
    assert client.put(root + '/selection', json=data).status_code == 409
    assert client.post(root + '/runs', json={'selection_revision': 0}).status_code == 422
    called = []
    monkeypatch.setattr(main.runtime, 'observe', lambda *args: called.append(args))
    denied = client.post(root + '/runs', json={'selection_revision': 1})
    assert denied.status_code == 400
    assert '열람만' in denied.json()['detail']
    assert called == []
    assert client.get(root + '/workflow').json()['runs'] == []
    next_selection = {**saved.json(), 'endpoint_ids': xss['endpoint_ids']}
    saved2 = client.put(root + '/selection', json=next_selection)
    assert saved2.status_code == 200 and saved2.json()['revision'] == 2
    assert client.post(root + '/runs', json={'selection_revision': 1}).status_code == 409
    assert client.post(root + '/runs', json={'selection_revision': 2}).status_code == 400
    assert called == []
    assert client.get(root + '/workflow').json()['runs'] == []
    audit = {'status': 'completed', 'message': 'lookup complete', 'packages': [
        {'name': 'fastapi', 'version': '0.141.1', 'status': 'no_known_advisories', 'advisories': []}],
        'unresolved': []}
    monkeypatch.setattr(main, 'audit_dependencies', lambda *_: audit)
    assert client.post(root + '/dependency-audit').status_code == 200
    assert client.get(root + '/workflow').json()['dependency_audit'] == audit
    assert client.get(root + '/workflow').json()['selection']['revision'] == 2


def test_archived_run_without_script_files_is_readable_but_not_regenerated(workflow_client):
    client, job = workflow_client
    scenario = client.get(f'/api/jobs/{job}/workflow').json()['scenarios'][0]
    run_id = str(uuid.uuid4())
    folder = main.job_path(job) / 'runs' / run_id
    folder.mkdir(parents=True)
    main.write_json(folder / 'status.json', {'id': run_id, 'state': 'completed'})
    main.write_json(folder / 'result.json', {
        'source': {'analysis_mode': 'deterministic'},
        'results': [{'scenario_id': scenario['id'], 'script_available': True,
                     'scenario': scenario}],
        'target_base_url': 'http://127.0.0.1:8010',
    })
    root = f'/api/jobs/{job}/runs/{run_id}/download'
    assert client.get(root + '/json').status_code == 200
    for params in ({'scenario_id': scenario['id']}, None):
        response = client.get(root + '/script', params=params)
        assert response.status_code == 404
        assert '스크립트 파일이 남아 있지 않습니다' in response.json()['detail']


def test_advisory_can_be_selected_without_a_network_request(workflow_client, monkeypatch):
    client, job = workflow_client
    root = f'/api/jobs/{job}'
    bundle_path = main.job_path(job) / 'bundle.json'
    bundle = main.read_json(bundle_path)
    bundle['files']['requirements.txt'] = 'fastapi==0.141.1\n'
    main.write_json(bundle_path, bundle)
    audit = {'status': 'completed', 'message': 'lookup complete', 'packages': [
        {'name': 'fastapi', 'version': '0.141.1', 'source_files': ['requirements.txt'],
         'status': 'advisories_found', 'advisories': [{'id': 'GHSA-test-1234',
          'url': 'https://osv.dev/vulnerability/GHSA-test-1234'}]}], 'unresolved': []}
    monkeypatch.setattr(main, 'audit_dependencies', lambda *_: audit)
    assert client.post(root + '/dependency-audit').status_code == 200
    scenario = next(s for s in client.get(root + '/workflow').json()['scenarios']
                    if s['category'] == 'dependency_advisory')
    saved = client.put(root + '/selection', json={'revision': 0, 'scenario_ids': [scenario['id']],
        'endpoint_ids': [], 'target_base_url': 'http://127.0.0.1:8010'})
    assert saved.status_code == 200
    called = []
    monkeypatch.setattr(main.runtime, 'observe', lambda *args: called.append(args))
    run = client.post(root + '/runs', json={'selection_revision': 1})
    assert run.status_code == 400
    assert '열람만' in run.json()['detail']
    assert called == []
    current = client.get(root + '/workflow').json()
    assert current['selection']['scenario_ids'] == [scenario['id']]
    assert current['runs'] == []
    assert scenario['source_evidence'][0]['file'] == 'requirements.txt'
