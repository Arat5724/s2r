"""AI proposals must become source-backed scenarios without gaining probe authority."""

import copy
import ast
import threading
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from review import main, runtime
from review.ai_scenarios import normalize_ai_scenarios


SOURCE = '''from fastapi import FastAPI
app = FastAPI()
@app.get("/api/widgets")
def list_widgets(q: str):
    query = f"SELECT * FROM widgets WHERE name = '{q}'"
    return query
'''
FILES = {'app.py': SOURCE, 'requirements.txt': 'fastapi==0.141.1\n'}


def ai_result():
    endpoint = {
        'id': 'model-identified-widget-route',
        'framework': 'FastAPI', 'method': 'GET', 'path': '/api/widgets',
        'handler': {'file': 'app.py', 'line': 4, 'end_line': 6,
                    'symbol': 'list_widgets', 'snippet': SOURCE.splitlines()[3] + '\n'
                    + SOURCE.splitlines()[4] + '\n' + SOURCE.splitlines()[5],
                    'reason': 'handler'},
        'inputs': [{'in': 'query', 'name': 'q', 'type': 'str', 'required': True,
                    'constraints': {}}],
        'call_chain': [{'file': 'app.py', 'line': 4, 'symbol': 'list_widgets',
                        'reason': 'handler'}],
        'guards': [], 'conditions': [], 'dependencies': [],
        'effects': {'assessment': 'no_write_detected', 'database_write_detected': False,
                    'session_change_detected': False},
        'auth': 'no_auth_dependency_detected',
    }
    proposal = {
        'endpoint_id': endpoint['id'], 'category': 'sqli', 'input_name': 'q',
        'title': '상품 검색 SQL 문자열 결합',
        'description': 'q가 SQL 문자열에 직접 삽입되어 검색 조건을 바꿀 수 있는 후보입니다.',
        'risk_hypothesis': '입력값이 SQL 구문으로 해석될 수 있습니다.',
        'verification_expectation': '실제 DB 호출 경로와 바인딩 여부를 확인합니다.',
        'uncertainty': '이 샘플 함수는 SQL 실행까지 연결되지 않아 영향이 미확인입니다.',
        'remediation_summary': '문자열 결합 대신 바인딩 파라미터를 사용합니다.',
        'source_evidence': [{'file': 'app.py', 'line': 4, 'symbol': 'list_widgets'},
                            {'file': 'app.py', 'line': 5, 'symbol': 'query'}],
        # Untrusted model output must never turn this into an HTTP probe.
        'automatable': True, 'execution_kind': 'http_sqli_boolean',
        'probe': {'query_key': 'q'},
    }
    return {
        'analysis_mode': 'ai', 'framework': 'FastAPI', 'endpoints': [endpoint],
        'ai_scenarios': [proposal],
        'ai': {'status': 'completed', 'project_summary': '위젯 검색 API',
               'endpoints': [{'id': endpoint['id'], 'summary': '위젯 검색'}]},
        'counts': {'total': 1, 'by_method': {'GET': 1}},
        'boundary': {'passed': True}, 'diagnostics': [],
        'limitations': ['실행 여부는 소스만으로 확정할 수 없습니다.'],
    }


def test_ai_candidates_keep_model_category_and_evidence_but_not_probe_authority():
    result = ai_result()
    scenarios = normalize_ai_scenarios(result, FILES)
    assert len(scenarios) == 1
    candidate = scenarios[0]
    assert candidate['generation'] == 'ai'
    assert candidate['endpoint_ids'] == [result['endpoints'][0]['id']]
    assert (candidate['category'], candidate['method'], candidate['path']) == (
        'sqli', 'GET', '/api/widgets')
    assert {(e['file'], e['line']) for e in candidate['source_evidence']} == {
        ('app.py', 4), ('app.py', 5)}
    assert candidate['automatable'] is False
    assert candidate['execution_kind'] == 'manual'
    assert runtime.validate_ai_routes(scenarios, result['endpoints'], {
        'scenario_ids': [candidate['id']], 'endpoint_ids': [result['endpoints'][0]['id']]}, {}, FILES) == []


@pytest.mark.parametrize('category,source,path,key', [
    ('xss', 'from fastapi import FastAPI\nfrom fastapi.responses import HTMLResponse\n'
     'app = FastAPI()\n@app.get("/echo")\ndef echo(q: str = ""):\n'
     '    return HTMLResponse(f"<p>{q}</p>")\n', '/echo', 'q'),
    ('open_redirect', 'from fastapi import FastAPI\nfrom fastapi.responses import RedirectResponse\n'
     'app = FastAPI()\n@app.get("/go")\ndef go(next: str = "/"):\n'
     '    return RedirectResponse(url=next, status_code=307)\n', '/go', 'next'),
])
def test_ai_fastapi_candidate_requires_independent_simple_get_gate(category, source, path, key):
    files = {'app.py': source}
    function = next(node for node in ast.walk(ast.parse(source))
                    if isinstance(node, ast.FunctionDef))
    endpoint = {
        'id': 'ai-identified-route', 'framework': 'FastAPI', 'method': 'GET', 'path': path,
        'handler': {'file': 'app.py', 'line': function.lineno,
                    'end_line': function.end_lineno, 'symbol': function.name,
                    'snippet': ast.get_source_segment(source, function), 'reason': 'handler'},
        'inputs': [{'in': 'query', 'name': key, 'type': 'str', 'required': False,
                    'constraints': {}}],
    }
    sink_line = len(source.splitlines())
    proposal = {
        'endpoint_id': endpoint['id'], 'category': category, 'input_name': key,
        'title': '검증 가능한 단순 처리 함수', 'description': '입력이 응답에 직접 사용됩니다.',
        'risk_hypothesis': '입력값을 검증해야 합니다.',
        'verification_expectation': '응답의 값을 관찰합니다.',
        'uncertainty': '배포 버전은 확인되지 않았습니다.',
        'remediation_summary': '입력을 검증합니다.',
        'source_evidence': [{'file': 'app.py', 'line': sink_line, 'symbol': 'response'}],
    }
    result = {'analysis_mode': 'ai', 'ai': {'status': 'completed'},
              'endpoints': [endpoint], 'ai_scenarios': [proposal]}
    candidate = normalize_ai_scenarios(result, files)[0]
    assert candidate['automatable'] is True
    assert candidate['execution_kind'] == 'ai_request'
    plan = {'probe': {'query_key': key, 'probe_value': 's2r_probe_2026abcd'}}
    assert runtime.validate_ai_routes([candidate], [endpoint], {
        'scenario_ids': [candidate['id']], 'endpoint_ids': [endpoint['id']]},
        {candidate['id']: plan}, files) == [
            {'method': 'GET', 'path': path, 'endpoint_id': endpoint['id'],
             'scenario_id': candidate['id'], 'probe_kind': 'ai_generic',
             'query_key': key, 'probe_value': 's2r_probe_2026abcd'}]
    unsafe_files = {'app.py': source.replace('    return ', '    write_database()\n    return ')}
    assert runtime.ai_get_eligibility(endpoint, candidate, unsafe_files)[0] is False


@pytest.mark.parametrize('change', [
    lambda value: value['ai_scenarios'][0]['source_evidence'][1].update(line=99),
    lambda value: value['ai_scenarios'][0].update(endpoint_id='invented-route'),
    lambda value: value['ai_scenarios'][0].update(input_name='invented-parameter'),
])
def test_ai_candidate_rejects_evidence_or_endpoint_outside_snapshot(change):
    result = ai_result()
    change(result)
    with pytest.raises(ValueError):
        normalize_ai_scenarios(result, FILES)


def _wait(client, url):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        response = client.get(url)
        assert response.status_code == 200
        data = response.json()
        if data['state'] in {'completed', 'failed'}:
            return data
        time.sleep(0.02)
    raise AssertionError(f'Background task did not finish: {url}')


def test_ai_job_uses_model_routes_and_scenarios_through_selection_and_run(tmp_path, monkeypatch):
    project = tmp_path / 'widget-project'
    project.mkdir()
    (project / 'app.py').write_text(SOURCE, encoding='utf-8')
    (project / 'requirements.txt').write_text(FILES['requirements.txt'], encoding='utf-8')
    data = tmp_path / 'data'
    (data / 'jobs').mkdir(parents=True)
    main.write_json(data / 'projects.json', [{'id': 'widgets', 'name': 'Widgets',
                                             'path': str(project)}])
    monkeypatch.setattr(main, 'DATA', data)
    monkeypatch.setattr(main, 'RUNNING', threading.Lock())

    def fake_worker(folder, update, project_root):
        captured = main.read_json(folder / 'bundle.json')['files']
        assert project_root == project
        assert {name: text.replace('\r\n', '\n') for name, text in captured.items()} == FILES
        return ai_result()

    observed_routes = []

    def no_network(folder, target, routes, update):
        observed_routes.append(routes)
        return [], {'allowed_paths': [], 'policy_applied': False,
                    'policy_restored': True}

    monkeypatch.setattr(main.bridge, 'run', fake_worker)
    monkeypatch.setattr(runtime, 'observe', no_network)
    def offline_plan(_folder, selected, *, label):
        identifier = selected[0]['id']
        return {identifier: {'probe': {'query_key': None, 'probe_value': None},
            'source': '''def evaluate(response):
    status = response.get('status')
    error = response.get('error')
    body_text = response.get('body_text')
    body_within_limit = response.get('body_within_limit')
    headers = response.get('headers')
    return ('inconclusive', 'SQL 실행 흐름을 수동으로 확인해야 합니다.')
''', 'reason': '실제 DB 호출이 확인되지 않아 오프라인 응답만 평가합니다.'}}
    monkeypatch.setattr(main.bridge, 'generate_ai_checks', offline_plan)
    monkeypatch.setattr(main.bridge, 'generate_ai_patches', lambda _folder, payload, *, label: {
        'patches': [{'id': payload['scenarios'][0]['id'], 'file': None, 'edits': [],
                     'reason': 'DB 호출이 없는 예제이므로 정확한 diff는 수동 검토합니다.'}]})
    with TestClient(main.app) as client:
        client.headers['X-S2R-Token'] = client.get('/api/config').json()['token']
        response = client.post('/api/jobs', json={'project_id': 'widgets', 'ai': True})
        assert response.status_code == 202
        job_id = response.json()['id']
        root = f'/api/jobs/{job_id}'
        status = _wait(client, root)
        assert status['state'] == 'completed', status['message']
        result = client.get(root + '/result').json()
        assert result['analysis_mode'] == 'ai'
        assert [e['id'] for e in result['endpoints']] == ['model-identified-widget-route']
        assert main.read_json(data / 'jobs' / job_id / 'scenarios.json')['version'] == 8

        workflow = client.get(root + '/workflow').json()
        candidate = workflow['scenarios'][0]
        assert candidate['generation'] == 'ai'
        assert candidate['category'] == 'sqli'
        assert workflow['endpoint_options'][0]['scenario_ids'] == [candidate['id']]
        saved = client.put(root + '/selection', json={
            'revision': 0, 'scenario_ids': [candidate['id']],
            'endpoint_ids': ['model-identified-widget-route'],
            'target_base_url': 'http://127.0.0.1:8010'})
        assert saved.status_code == 200, saved.text
        started = client.post(root + '/runs', json={'selection_revision': 1})
        assert started.status_code == 202, started.text
        completed = _wait(client, root + '/runs/' + started.json()['id'])
        assert completed['state'] == 'completed', completed
        assert completed['results'][0]['status'] == 'manual_review'
        assert completed['results'][0]['scenario']['category'] == 'sqli'
        assert completed['scope']['allowed_paths'] == []
        assert observed_routes == [[]]
        script = client.get(root + '/runs/' + started.json()['id'] + '/download/script',
                            params={'scenario_id': candidate['id']})
        assert script.status_code == 200
        assert 'offline-only' in script.text
        assert '상품 검색 SQL 문자열 결합' in client.get(
            root + '/runs/' + started.json()['id'] + '/download/report').text


def test_legacy_v7_scenario_cache_remains_unchanged(tmp_path):
    folder = tmp_path / 'legacy'
    folder.mkdir()
    main.write_json(folder / 'bundle.json', {'files': FILES})
    original = {'version': 7, 'scenarios': [{'id': 'archived-rule-scenario'}]}
    main.write_json(folder / 'scenarios.json', copy.deepcopy(original))
    assert main.catalog(folder) == original['scenarios']
    assert main.read_json(folder / 'scenarios.json') == original


def test_legacy_job_without_catalog_never_recreates_retired_rule_scenarios(tmp_path):
    folder = tmp_path / 'legacy'
    folder.mkdir()
    main.write_json(folder / 'bundle.json', {'files': FILES})
    main.write_json(folder / 'result.json', {'analysis_mode': 'deterministic',
                                           'endpoints': ai_result()['endpoints']})
    assert main.catalog(folder) == []
    assert not (folder / 'scenarios.json').exists()


def test_invalid_ai_proposal_fails_job_without_rule_fallback(tmp_path, monkeypatch):
    project = tmp_path / 'source'
    project.mkdir()
    (project / 'app.py').write_text(SOURCE, encoding='utf-8')
    (project / 'requirements.txt').write_text(FILES['requirements.txt'], encoding='utf-8')
    folder = tmp_path / 'job'
    folder.mkdir()
    invalid = ai_result()
    invalid['ai_scenarios'][0]['source_evidence'][1]['line'] = 999
    monkeypatch.setattr(main.bridge, 'run', lambda *_: invalid)
    lock = threading.Lock()
    lock.acquire()
    monkeypatch.setattr(main, 'RUNNING', lock)
    status = {'id': str(uuid.uuid4()), 'project': {'id': 'sample', 'name': 'Sample',
              'path': str(project)}, 'created_at': main.stamp(), 'ai_requested': True}
    main.analyze(folder, project, status)
    stored = main.read_json(folder / 'status.json')
    assert stored['state'] == 'failed'
    assert '코드 근거' in stored['message']
    assert not (folder / 'result.json').exists()
    assert not (folder / 'scenarios.json').exists()
    assert not lock.locked()
