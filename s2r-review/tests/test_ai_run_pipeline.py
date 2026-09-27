"""An AI run keeps model proposals, live observations and downloads connected."""

import json
import subprocess
import sys
import threading
import uuid

from fastapi.testclient import TestClient

import patch_agent
from review import main, runtime
from review.ai_scenarios import normalize_ai_scenarios


SOURCE = '''from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from html import escape

app = FastAPI()

@app.get("/echo")
def echo(q: str = ''):
    return HTMLResponse(f"<p>{q}</p>")

@app.post("/update")
def update(value: str):
    save(value)
    return {"ok": True}
'''
MARKER = '<strong>s2r_source_12345678</strong>'
CHECK_SOURCE = '''def evaluate(response):
    status = response.get('status')
    error = response.get('error')
    body_text = response.get('body_text')
    body_within_limit = response.get('body_within_limit')
    headers = response.get('headers')
    content_type = headers.get('content-type', '')
    if status == 200 and body_within_limit and 'text/html' in content_type and '<strong>s2r_source_12345678</strong>' in body_text:
        return ('fail', '이스케이프되지 않은 HTML 태그가 응답에 나타났습니다.')
    return ('inconclusive', '이 응답만으로는 판단할 수 없습니다.')
'''
OFFLINE_CHECK_SOURCE = '''def evaluate(response):
    status = response.get('status')
    error = response.get('error')
    body_text = response.get('body_text')
    body_within_limit = response.get('body_within_limit')
    headers = response.get('headers')
    if error is not None:
        return ('unavailable', '응답을 확인할 수 없습니다.')
    return ('inconclusive', '운영 요청 없이 저장된 응답만으로는 판단할 수 없습니다.')
'''


def test_owner_fixture_hints_require_an_actual_single_token_canary():
    files = {
        's2r-review-fixtures.json': json.dumps({'version': 1, 'probe_files': [
            {'path': 'data/public/guide.txt', 'purpose': 'public_control'},
            {'path': 'data/private/canary.txt', 'purpose': 'synthetic_canary',
             'marker': 'SYNTHETIC_CANARY'},
        ]}),
        'data/public/guide.txt': 'public guide',
        'data/private/canary.txt': 'SYNTHETIC_CANARY\n',
    }
    assert main._fixture_hints(files)[1]['marker'] == 'SYNTHETIC_CANARY'
    files['data/private/canary.txt'] = 'unrelated private data\nSYNTHETIC_CANARY'
    assert main._fixture_hints(files) == []


def test_only_paired_live_model_plans_are_reused_within_one_analysis(tmp_path):
    previous = tmp_path / 'runs' / str(uuid.uuid4())
    previous.mkdir(parents=True)
    identifier = 'a' * 16
    plan = {'id': identifier,
            'probe': {'requests': [
                {'label': 'baseline', 'query_key': 'q', 'probe_value': 'control'},
                {'label': 'candidate', 'query_key': 'q', 'probe_value': MARKER},
            ]}, 'source': CHECK_SOURCE, 'reason': '함수 응답을 비교합니다.'}
    output = previous / f'scripts-{identifier}-worker-result.json'
    output.write_text(json.dumps({'checks': [plan]}), encoding='utf-8')
    assert main._cached_ai_plan(tmp_path, identifier)['probe'] == plan['probe']
    plan['probe'] = {'requests': []}
    output.write_text(json.dumps({'checks': [plan]}), encoding='utf-8')
    assert main._cached_ai_plan(tmp_path, identifier) is None


def _endpoint(identifier, method, path, line, end_line, input_name, required):
    return {
        'id': identifier, 'framework': 'FastAPI', 'method': method, 'path': path,
        'handler': {'file': 'app.py', 'line': line, 'end_line': end_line,
                    'symbol': identifier, 'reason': 'handler',
                    'snippet': '\n'.join(SOURCE.splitlines()[line - 1:end_line])},
        'inputs': [{'in': 'query', 'name': input_name, 'type': 'str',
                    'required': required, 'constraints': {}}],
        'call_chain': [{'file': 'app.py', 'line': line, 'symbol': identifier,
                        'reason': 'handler'}],
        'guards': [], 'conditions': [], 'dependencies': [],
        'effects': {'assessment': 'unknown', 'database_write_detected': method == 'POST',
                    'session_change_detected': False},
        'auth': 'no_auth_dependency_detected',
    }


def _proposal(endpoint_id, category, input_name, evidence_line):
    return {
        'endpoint_id': endpoint_id, 'category': category, 'input_name': input_name,
        'title': f'{endpoint_id} 함수의 입력 처리',
        'description': '요청 입력이 함수 안에서 처리되는 방식을 검토합니다.',
        'risk_hypothesis': '입력 처리로 인해 의도하지 않은 응답이 생길 수 있습니다.',
        'verification_expectation': '응답 본문의 고유 마커를 확인합니다.',
        'uncertainty': '배포 버전과 실제 영향은 별도로 확인해야 합니다.',
        'remediation_summary': '코드에서 입력 처리 방식을 수정합니다.',
        'source_evidence': [{'file': 'app.py', 'line': evidence_line,
                             'symbol': endpoint_id}],
    }


def _run_fixture(tmp_path, monkeypatch):
    data = tmp_path / 'data'
    jobs = data / 'jobs'
    jobs.mkdir(parents=True)
    monkeypatch.setattr(main, 'DATA', data)
    lock = threading.Lock()
    assert lock.acquire(blocking=False)
    monkeypatch.setattr(main, 'RUNNING', lock)

    job_id, run_id = str(uuid.uuid4()), str(uuid.uuid4())
    job = jobs / job_id
    run = job / 'runs' / run_id
    run.mkdir(parents=True)
    main.write_json(job / 'status.json', {'id': job_id, 'state': 'completed'})
    main.write_json(job / 'bundle.json', {'files': {'app.py': SOURCE}})
    endpoints = [
        _endpoint('echo', 'GET', '/echo', 8, 9, 'q', False),
        _endpoint('update', 'POST', '/update', 12, 14, 'value', True),
    ]
    result = {
        'analysis_mode': 'ai', 'framework': 'FastAPI',
        'project': {'name': 'Demo'}, 'endpoints': endpoints,
        'ai': {'status': 'completed', 'project_summary': '두 경로를 가진 테스트 앱'},
        'ai_scenarios': [
            _proposal('echo', 'xss', 'q', 9),
            _proposal('update', 'other_technical', 'value', 13),
        ],
    }
    main.write_json(job / 'result.json', result)
    scenarios = normalize_ai_scenarios(result, {'app.py': SOURCE})
    assert scenarios[0]['automatable'] is True
    assert scenarios[1]['automatable'] is False
    saved = {
        'revision': 1, 'scenario_ids': [row['id'] for row in scenarios],
        'endpoint_ids': [row['id'] for row in endpoints],
        'target_base_url': 'http://127.0.0.1:8010',
    }
    target = runtime.validate_target(saved['target_base_url'])
    status = {'id': run_id, 'analysis_id': job_id, 'created_at': main.stamp(),
              'state': 'queued', 'stage': 'queued'}
    main.write_json(run / 'status.json', status)
    return job_id, run_id, run, saved, scenarios, endpoints, target, status, lock


def test_ai_run_plans_before_observation_then_writes_model_diff_and_downloads(tmp_path, monkeypatch):
    job_id, run_id, run, saved, scenarios, endpoints, target, status, lock = _run_fixture(
        tmp_path, monkeypatch)
    live, offline = scenarios
    events = []

    def fake_checks(_folder, selected, *, label):
        scenario = selected[0]
        events.append(('plan', scenario['id']))
        context = scenario['source_context']
        assert 'def echo' in context if scenario['id'] == live['id'] else 'def update' in context
        return {scenario['id']: {
            'probe': {'query_key': 'q', 'probe_value': MARKER}
                     if scenario['id'] == live['id'] else
                     {'query_key': None, 'probe_value': None},
            'source': CHECK_SOURCE if scenario['id'] == live['id'] else OFFLINE_CHECK_SOURCE,
            'reason': '함수 응답을 고유 마커와 비교합니다.',
        }}

    def fake_observe(_folder, _target, routes, _update):
        events.append(('observe', routes))
        assert routes == [{
            'method': 'GET', 'path': '/echo', 'endpoint_id': 'echo',
            'scenario_id': live['id'], 'probe_kind': 'ai_generic',
            'query_key': 'q', 'probe_value': MARKER,
        }]
        return [{
            'scenario_id': live['id'], 'path': '/echo', 'probe_kind': 'ai_generic',
            'query_key': 'q',
            'status_code': 200, 'error': None, 'headers': {'content-type': 'text/html'},
            'body_text': f'<p>{MARKER}</p>', 'body_within_limit': True,
        }], {'allowed_paths': ['/echo'], 'method': 'GET', 'policy_applied': True,
             'policy_restored': True}

    def fake_patches(_folder, payload, *, label):
        item = payload['scenarios'][0]
        events.append(('patch', item['id'], item['outcome']['status']))
        if item['id'] == offline['id']:
            return {'patches': [{'id': item['id'], 'file': None, 'edits': [],
                                'reason': '이 상태 변경 함수는 별도 수동 검토가 필요합니다.'}]}
        candidate = {
            'file': 'app.py', 'reason': 'HTML 응답 전에 입력을 이스케이프합니다.',
            'edits': [{'start_line': 9,
                       'old_lines': ['    return HTMLResponse(f"<p>{q}</p>")'],
                       'new_lines': ['    return HTMLResponse(f"<p>{escape(q)}</p>")']}],
        }
        return {'patches': [patch_agent.validate_model_patch(
            candidate, item, payload['sources'])]}

    monkeypatch.setattr(main.bridge, 'generate_ai_checks', fake_checks)
    monkeypatch.setattr(main.bridge, 'generate_ai_patches', fake_patches)
    monkeypatch.setattr(runtime, 'observe', fake_observe)
    assert not hasattr(main, 'assess')
    assert not hasattr(main, 'propose_patch')

    main.execute_ai_run(run, saved, scenarios, endpoints, target, [], status)
    assert status['state'] == 'completed', status.get('message')
    assert not lock.locked()
    assert [event[0] for event in events] == ['plan', 'plan', 'observe', 'patch', 'patch']

    result = main.read_json(run / 'result.json')
    by_id = {row['scenario_id']: row for row in result['results']}
    observed = by_id[live['id']]
    manual = by_id[offline['id']]
    assert observed['status'] == 'fail'
    assert observed['script_mode'] == 'live_get'
    assert observed['evidence']['status_code'] == 200
    assert 'body_text' not in observed['evidence']
    assert '-    return HTMLResponse(f"<p>{q}</p>")' in observed['patch']['diff']
    assert '+    return HTMLResponse(f"<p>{escape(q)}</p>")' in observed['patch']['diff']
    assert observed['patch']['applicability'] == 'review_required'
    assert manual['status'] == 'manual_review'
    assert manual['script_mode'] == 'offline'
    assert manual['patch']['diff'] is None
    assert '수동 검토' in manual['patch']['reason']
    assert result['scope']['allowed_paths'] == ['/echo']
    assert result['script_generation']['status'] == 'completed'
    assert result['counts']['fail'] == 1 and result['counts']['manual_review'] == 1
    assert '```diff' in (run / 'report.md').read_text(encoding='utf-8')
    assert 'ai_evaluate_' in (run / 'check.py').read_text(encoding='utf-8')
    assert 'http.client' not in (run / 'scripts' / f'{offline["id"]}.py').read_text(encoding='utf-8')

    with TestClient(main.app) as client:
        client.headers['X-S2R-Token'] = client.get('/api/config').json()['token']
        base = f'/api/jobs/{job_id}/runs/{run_id}/download'
        for scenario in scenarios:
            script = client.get(base + '/script', params={'scenario_id': scenario['id']})
            assert script.status_code == 200, script.text
            assert f'ai_evaluate_{scenario["id"]}' in script.text
        assert client.get(base + '/script').status_code == 200
        assert client.get(base + '/report').status_code == 200
        assert client.get(base + '/json').json()['results'][0]['status'] == 'fail'

    offline_script = run / 'scripts' / f'{offline["id"]}.py'
    completed = subprocess.run([sys.executable, str(offline_script)],
                               input=json.dumps({'status': 200, 'error': None,
                                   'body_text': MARKER, 'body_within_limit': True,
                                   'headers': {}}), text=True, capture_output=True, timeout=5)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)['status'] == 'inconclusive'


def test_ai_run_binds_two_live_responses_to_one_selected_scenario(tmp_path, monkeypatch):
    _, _, run, saved, scenarios, endpoints, target, status, lock = _run_fixture(
        tmp_path, monkeypatch)
    live = scenarios[0]
    saved['scenario_ids'] = [live['id']]
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
    if '<strong>s2r_source_12345678</strong>' not in baseline_body_text and 'text/html' in content_type and '<strong>s2r_source_12345678</strong>' in body_text:
        return ('fail', '후보 요청에서 원문 HTML 태그가 관찰되었습니다.')
    return ('inconclusive', '두 응답만으로는 판단할 수 없습니다.')
'''
    plan = {'probe': {'requests': [
        {'label': 'baseline', 'query_key': 'q', 'probe_value': 's2r_source_12345678'},
        {'label': 'candidate', 'query_key': 'q', 'probe_value': MARKER},
    ]}, 'source': source, 'reason': 'q 입력이 HTML에 삽입됩니다.'}

    monkeypatch.setattr(main.bridge, 'generate_ai_checks',
                        lambda _folder, rows, **_kwargs: {rows[0]['id']: plan})
    monkeypatch.setattr(main.bridge, 'generate_ai_patches',
                        lambda _folder, payload, **_kwargs: {'patches': [
                            {'id': payload['scenarios'][0]['id'], 'file': None,
                             'edits': [], 'reason': '수정안은 별도로 검토합니다.'}]})

    def fake_observe(_folder, _target, routes, _update):
        assert [route['probe_label'] for route in routes] == ['baseline', 'candidate']
        assert {route['scenario_id'] for route in routes} == {live['id']}
        return [{
            'scenario_id': live['id'], 'path': '/echo', 'probe_kind': 'ai_generic',
            'query_key': 'q', 'probe_label': route['probe_label'],
            'status_code': 200, 'error': None, 'body_within_limit': True,
            'headers': {'content-type': 'text/html'},
            'body_text': '<p>' + (MARKER if route['probe_label'] == 'candidate' else 'safe') + '</p>',
        } for route in routes], {'allowed_paths': ['/echo'], 'method': 'GET',
                                 'policy_applied': True, 'policy_restored': True}

    monkeypatch.setattr(runtime, 'observe', fake_observe)
    main.execute_ai_run(run, saved, scenarios, endpoints, target, [], status)
    assert status['state'] == 'completed', status.get('message')
    assert not lock.locked()
    row = main.read_json(run / 'result.json')['results'][0]
    assert row['status'] == 'fail'
    assert row['request']['count'] == 2
    assert set(row['evidence']) == {'baseline', 'candidate'}
    assert all('body_text' not in response for response in row['evidence'].values())
    assert row['script_mode'] == 'live_get'
    assert (run / 'scripts' / f'{live["id"]}.py').is_file()


def test_ai_run_keeps_invalid_model_plan_manual_and_exposes_no_script(tmp_path, monkeypatch):
    _, _, run, saved, scenarios, endpoints, target, status, lock = _run_fixture(tmp_path, monkeypatch)
    scenario = scenarios[0]
    saved['scenario_ids'] = [scenario['id']]
    seen = []

    def invalid_plan(*_args, **_kwargs):
        return {scenario['id']: {'probe': {'query_key': 'q', 'probe_value': '../../private'},
                                 'source': CHECK_SOURCE, 'reason': '범위 밖 값'}}

    def no_network(_folder, _target, routes, _update):
        seen.append(routes)
        return [], {'allowed_paths': [], 'policy_applied': False,
                    'policy_restored': True}

    monkeypatch.setattr(main.bridge, 'generate_ai_checks', invalid_plan)
    monkeypatch.setattr(main.bridge, 'generate_ai_patches',
                        lambda _folder, payload, **_kwargs: {'patches': [
                            {'id': payload['scenarios'][0]['id'], 'file': None, 'edits': [],
                             'reason': '모델 점검 계획을 검증하지 못해 소스 재검토가 필요합니다.'}]})
    monkeypatch.setattr(runtime, 'observe', no_network)
    main.execute_ai_run(run, saved, scenarios, endpoints, target, [], status)
    assert status['state'] == 'completed', status.get('message')
    assert not lock.locked()
    assert seen == [[]]
    result = main.read_json(run / 'result.json')
    row = result['results'][0]
    assert row['status'] == 'manual_review'
    assert row['script_available'] is False
    assert row['patch']['diff'] is None
    assert result['script_generation']['status'] == 'failed'
    assert list((run / 'scripts').iterdir()) == []


def test_ai_run_rechecks_offline_body_signal_against_reconstructed_source(tmp_path, monkeypatch):
    _, _, run, saved, scenarios, endpoints, target, status, lock = _run_fixture(tmp_path, monkeypatch)
    offline = scenarios[1]
    saved['scenario_ids'] = [offline['id']]
    invented = CHECK_SOURCE.replace(MARKER, 'CANARY_PRIVATE')
    observed_routes = []

    def fake_checks(_folder, selected, **_kwargs):
        request = selected[0]
        assert 'def update' in request['source_context']
        assert 'CANARY_PRIVATE' not in request['source_context']
        return {offline['id']: {'probe': {'query_key': None, 'probe_value': None},
                                'source': invented, 'reason': '본문 표식이 있다고 가정합니다.'}}

    def fake_observe(_folder, _target, routes, _update):
        observed_routes.extend(routes)
        return [], {'allowed_paths': [], 'policy_applied': False,
                    'policy_restored': True}

    monkeypatch.setattr(main.bridge, 'generate_ai_checks', fake_checks)
    monkeypatch.setattr(main.bridge, 'generate_ai_patches',
                        lambda _folder, payload, **_kwargs: {'patches': [
                            {'id': payload['scenarios'][0]['id'], 'file': None, 'edits': [],
                             'reason': '코드 검토가 필요합니다.'}]})
    monkeypatch.setattr(runtime, 'observe', fake_observe)
    main.execute_ai_run(run, saved, scenarios, endpoints, target, [], status)
    assert status['state'] == 'completed', status.get('message')
    assert not lock.locked()
    assert observed_routes == []
    row = main.read_json(run / 'result.json')['results'][0]
    assert row['scenario_id'] == offline['id']
    assert row['status'] == 'manual_review'
    assert row['script_available'] is False
    assert '문자열 리터럴' in row['summary']
