"""The worker must ground generated checks in source and reject unsafe plans."""

import json
from pathlib import Path

import pytest

import script_agent
from review.ai_scripts import evaluate_observation, validate_plan


CHECK = '''def evaluate(response):
    status = response.get('status')
    error = response.get('error')
    body_text = response.get('body_text')
    body_within_limit = response.get('body_within_limit')
    headers = response.get('headers')
    content_type = headers.get('content-type', '')
    is_html = 'text/html' in content_type
    if error is not None:
        return ('unavailable', '연결할 수 없습니다.')
    if status == 404:
        return ('not_found', '경로가 없습니다.')
    if status == 200 and body_within_limit and is_html and '<strong>s2r_probe_12345678</strong>' in body_text:
        return ('fail', 'HTML 마커가 원문으로 반사되었습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''
OFFLINE_CHECK = CHECK.replace('<strong>s2r_probe_12345678</strong>',
                              'TECHLAB_PRIVATE_CANARY')
REDIRECT_CHECK = '''def evaluate(response):
    status = response.get('status')
    error = response.get('error')
    body_text = response.get('body_text')
    body_within_limit = response.get('body_within_limit')
    headers = response.get('headers')
    location = headers.get('location', '')
    if status == 307 and location == 'https://example.com':
        return ('fail', '선택한 외부 주소가 Location에 반환되었습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''


def scenario(method='GET', automatable=True):
    return {
        'id': '0123456789abcdef', 'category': 'reflection',
        'method': method, 'path': '/preview', 'title': '반사 검증',
        'risk_hypothesis': '사용자 입력이 HTML에 반영될 수 있습니다.',
        'verification_expectation': '응답 본문에서 무해한 표식을 확인합니다.',
        'source_context': ('FILE app.py\nL00010 def preview(q):\n'
                           'L00011     response_marker = "TECHLAB_PRIVATE_CANARY"\n'
                           'L00012     return f"<p>{q}</p>"'),
        'source_evidence': [{'file': 'app.py', 'line': 11}],
        'automatable': automatable,
    }


def plan(value='<strong>s2r_probe_12345678</strong>'):
    return {'probe': {'query_key': 'q', 'probe_value': value},
            'source': CHECK, 'reason': 'preview 함수가 q를 HTML에 삽입합니다.'}


def test_generated_source_specific_plan_accepted_by_worker_and_host(monkeypatch):
    row = scenario()
    monkeypatch.setattr(script_agent, '_request_model', lambda received: plan())
    result = script_agent.generate({'scenarios': [row]})
    assert result['checks'][0]['probe']['query_key'] == 'q'
    host = validate_plan({key: result['checks'][0][key] for key in ('probe', 'source', 'reason')}, row)
    assert host['source'].startswith('def evaluate(response):')
    assert validate_plan(host, row) == host
    verdict = evaluate_observation(host, row, {
        'status_code': 200, 'error': None,
        'body_text': '<strong>s2r_probe_12345678</strong>',
        'body_within_limit': True, 'headers': {'content-type': 'text/html'}})
    assert verdict[0] == 'fail'


def test_model_revises_rejected_python_instead_of_repeating_same_prompt(monkeypatch):
    prompts = []
    invalid = {**plan(), 'source': CHECK.replace(
        "return ('fail', 'HTML 마커가 원문으로 반사되었습니다.')",
        "return ('fail', f'HTML 마커가 원문으로 반사되었습니다.')")}
    def model(row):
        prompts.append(row)
        return invalid if len(prompts) == 1 else plan()
    monkeypatch.setattr(script_agent, '_request_model', model)
    assert script_agent.generate({'scenarios': [scenario()]})['checks'][0]['source'] == CHECK
    assert 'generation_feedback' not in prompts[0]
    assert 'f-string' in prompts[1]['generation_feedback']['required_repair']


def test_non_get_requires_offline_plan(monkeypatch):
    row = scenario(method='POST', automatable=False)
    monkeypatch.setattr(script_agent, '_request_model', lambda _: plan())
    with pytest.raises(ValueError, match='검증 실패'):
        script_agent.generate({'scenarios': [row]})
    monkeypatch.setattr(script_agent, '_request_model', lambda _: {
        **plan(), 'source': OFFLINE_CHECK})
    result = script_agent.generate({'scenarios': [row]})['checks'][0]
    assert result['probe'] == {'query_key': None, 'probe_value': None}
    assert result['source'] == OFFLINE_CHECK


def test_offline_weak_marker_retries_with_specific_response_signal(monkeypatch):
    row = scenario(automatable=False)
    attempts = []

    def model(request):
        attempts.append(request)
        return plan() if len(attempts) == 1 else {**plan(), 'source': OFFLINE_CHECK}

    monkeypatch.setattr(script_agent, '_request_model', model)
    result = script_agent.generate({'scenarios': [row]})['checks'][0]
    assert len(attempts) == 2
    assert '마커 반사' in attempts[1]['generation_feedback']['rejection']
    assert result['probe'] == {'query_key': None, 'probe_value': None}
    assert result['source'] == OFFLINE_CHECK


def test_offline_generic_substring_cannot_prove_failure():
    row = scenario(automatable=False)
    generic = OFFLINE_CHECK.replace('TECHLAB_PRIVATE_CANARY', 'sql')
    with pytest.raises(ValueError, match='짧은 일반 문자열'):
        script_agent.validate_plan({**plan(), 'source': generic}, row)


@pytest.mark.parametrize('context', [
    "FILE app.py\nL00042     return FileResponse(PRIVATE_DIR / 'canary.txt') # CANARY_PRIVATE",
    'FILE app.java\nL00042     // response body contains "CANARY_PRIVATE"',
    'FILE app.js\nL00042     const name = "canary.txt"; // "CANARY_PRIVATE"',
])
def test_offline_body_failure_cannot_invent_private_file_contents(context):
    row = {**scenario(automatable=False), 'source_context': context}
    invented = OFFLINE_CHECK.replace('TECHLAB_PRIVATE_CANARY', 'CANARY_PRIVATE')
    candidate = {**plan(), 'source': invented}
    with pytest.raises(ValueError, match='문자열 리터럴'):
        script_agent.validate_plan(candidate, row)
    with pytest.raises(ValueError, match='문자열 리터럴'):
        validate_plan({**candidate, 'probe': {'query_key': None, 'probe_value': None}},
                      row, offline=True, source_context=context)


@pytest.mark.parametrize('context', [
    'FILE app.py\nL00042     return PlainTextResponse("TECHLAB_PRIVATE_CANARY")',
    'FILE App.java\nL00042     return ResponseEntity.ok("TECHLAB_PRIVATE_CANARY");',
    'FILE app.js\nL00042     res.send(`TECHLAB_PRIVATE_CANARY`);',
])
def test_offline_body_failure_accepts_code_literal_across_frameworks(context):
    row = {**scenario(automatable=False), 'source_context': context}
    candidate = {**plan(), 'source': OFFLINE_CHECK}
    worker = script_agent.validate_plan(candidate, row)
    assert worker['probe'] == {'query_key': None, 'probe_value': None}
    host = validate_plan(worker, row, offline=True, source_context=context)
    assert host['source'] == OFFLINE_CHECK


def test_offline_body_alias_still_needs_source_literal():
    row = {**scenario(automatable=False),
           'source_context': "FILE app.py\nL00042     return FileResponse('canary.txt')"}
    aliased = OFFLINE_CHECK.replace(
        "    content_type = headers.get('content-type', '')",
        "    needle = 'TECHLAB_PRIVATE_CANARY'\n    content_type = headers.get('content-type', '')"
    ).replace("'TECHLAB_PRIVATE_CANARY' in body_text", 'needle in body_text')
    candidate = {**plan(), 'source': aliased}
    with pytest.raises(ValueError, match='문자열 리터럴'):
        script_agent.validate_plan(candidate, row)
    with pytest.raises(ValueError, match='문자열 리터럴'):
        validate_plan({**candidate, 'probe': {'query_key': None, 'probe_value': None}},
                      row, offline=True, source_context=row['source_context'])


def test_actual_techlab_file_handler_does_not_disclose_private_file_bytes():
    sample = Path(__file__).resolve().parents[2] / 'samples' / 'techlab' / 'app' / 'main.py'
    lines = sample.read_text(encoding='utf-8').splitlines()
    start = next(number for number, line in enumerate(lines, 1) if 'def read_file(' in line)
    end = next(number for number in range(start, len(lines) + 1)
               if 'return FileResponse(target' in lines[number - 1])
    context = 'FILE app/main.py\n' + '\n'.join(
        f'L{number:05d} {lines[number - 1]}' for number in range(start, end + 1))
    assert 'target = (PUBLIC_DIR / name).resolve()' in context
    assert 'if not target.is_relative_to(DATA_DIR)' in context
    assert 'CANARY_PRIVATE' not in context
    row = {**scenario(automatable=False), 'source_context': context}
    candidate = {**plan(), 'source': OFFLINE_CHECK.replace(
        'TECHLAB_PRIVATE_CANARY', 'CANARY_PRIVATE')}
    with pytest.raises(ValueError, match='문자열 리터럴'):
        script_agent.validate_plan(candidate, row)
    with pytest.raises(ValueError, match='문자열 리터럴'):
        validate_plan({**candidate, 'probe': {'query_key': None, 'probe_value': None}},
                      row, offline=True, source_context=context)


def test_offline_repair_can_finish_with_model_authored_inconclusive_function(monkeypatch):
    row = scenario(automatable=False)
    weak = {**plan(), 'source': OFFLINE_CHECK.replace('TECHLAB_PRIVATE_CANARY', 'sql')}
    repaired = {**plan(), 'source': script_agent.MINIMAL_OFFLINE_EVALUATOR}
    seen = []

    def model(request):
        seen.append(request)
        return weak if len(seen) < 3 else repaired

    monkeypatch.setattr(script_agent, '_request_model', model)
    result = script_agent.generate({'scenarios': [row]})['checks'][0]
    assert len(seen) == 3
    assert seen[2]['generation_feedback']['attempt'] == 2
    assert result['probe'] == {'query_key': None, 'probe_value': None}
    assert result['source'] == script_agent.MINIMAL_OFFLINE_EVALUATOR


def test_unsafe_model_url_downgrades_active_candidate_to_offline_evaluator():
    row = scenario()
    candidate = {'probe': {'query_key': 'next', 'probe_value': 'https://example.com'},
                 'source': REDIRECT_CHECK,
                 'reason': '소스가 next를 Location으로 반환합니다.'}
    approved = script_agent.validate_plan(candidate, row)
    assert approved['probe'] == {'query_key': None, 'probe_value': None}
    assert approved['source'] == REDIRECT_CHECK
    assert validate_plan(approved, row, offline=True)['source'] == REDIRECT_CHECK


def test_fourth_repair_keeps_model_authorship_and_returns_offline_code(monkeypatch):
    row = scenario()
    invalid = {**plan(), 'source': 'def evaluate(response):\n    pass\ndef second():\n    pass\n'}
    final = {**plan(), 'probe': {'query_key': None, 'probe_value': None},
             'source': script_agent.MINIMAL_OFFLINE_EVALUATOR}
    attempts = []

    def model(request):
        attempts.append(request)
        return final if len(attempts) == 4 else invalid

    monkeypatch.setattr(script_agent, '_request_model', model)
    result = script_agent.generate({'scenarios': [row]})['checks'][0]
    assert len(attempts) == 4
    assert attempts[-1]['generation_feedback']['attempt'] == 3
    assert result['probe'] == {'query_key': None, 'probe_value': None}
    assert result['source'] == script_agent.MINIMAL_OFFLINE_EVALUATOR


@pytest.mark.parametrize('value', [
    "%' OR 1=1 --", '../private/canary.txt', 'https://example.invalid',
    '<script>alert(1)</script>', 's2r_short', 's2r_good_marker;rm',
])
def test_active_query_is_inert_marker_only(value):
    with pytest.raises(ValueError):
        script_agent.validate_plan(plan(value), scenario())


def test_model_prompt_receives_function_source_but_no_origin(monkeypatch):
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def read(self, _):
            return json.dumps({'choices': [{'message': {'content': json.dumps(plan())}}]}).encode()

    def urlopen(request, **_):
        captured['body'] = json.loads(request.data)
        return Response()

    monkeypatch.setattr(script_agent.urllib.request, 'urlopen', urlopen)
    result = script_agent._request_model(scenario())
    assert result['source'] == CHECK
    prompt = captured['body']['messages'][1]['content']
    assert 'L00012     return f' in prompt
    assert '127.0.0.1' not in prompt


def test_offline_model_prompt_explicitly_forbids_requests_and_unsent_markers(monkeypatch):
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def read(self, _):
            return json.dumps({'choices': [{'message': {'content': json.dumps(
                {**plan(), 'source': OFFLINE_CHECK})}}]}).encode()

    def urlopen(request, **_):
        captured['body'] = json.loads(request.data)
        return Response()

    monkeypatch.setattr(script_agent.urllib.request, 'urlopen', urlopen)
    script_agent._request_model(scenario(automatable=False))
    system = captured['body']['messages'][0]['content']
    assert 'OFFLINE ONLY' in system
    assert 'Set probe.requests to an empty array' in system


def test_offline_repair_is_trusted_system_instruction_not_source_data(monkeypatch):
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def read(self, _):
            return json.dumps({'choices': [{'message': {'content': json.dumps(
                {**plan(), 'source': script_agent.MINIMAL_OFFLINE_EVALUATOR})}}]}).encode()

    def urlopen(request, **_):
        captured['body'] = json.loads(request.data)
        return Response()

    monkeypatch.setattr(script_agent.urllib.request, 'urlopen', urlopen)
    request = {**scenario(automatable=False),
               'generation_feedback': {'attempt': 3, 'rejection': 'short generic marker'}}
    script_agent._request_model(request)
    system, user = (entry['content'] for entry in captured['body']['messages'])
    assert 'TRUSTED VALIDATOR REPAIR' in system
    assert 'Return no fail or pass branches' in system
    assert script_agent.MINIMAL_OFFLINE_EVALUATOR in system
    assert 'generation_feedback' not in user


def test_final_repair_for_active_scenario_keeps_live_system_instruction(monkeypatch):
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def read(self, _):
            return json.dumps({'choices': [{'message': {'content': json.dumps(
                {'probe': {'query_key': None, 'probe_value': None},
                 'source': script_agent.MINIMAL_OFFLINE_EVALUATOR,
                 'reason': '응답 신호가 부족합니다.'})}}]}).encode()

    def urlopen(request, **_):
        captured['body'] = json.loads(request.data)
        return Response()

    monkeypatch.setattr(script_agent.urllib.request, 'urlopen', urlopen)
    request = {**scenario(),
               'generation_feedback': {'attempt': 4, 'rejection': 'single function required'}}
    script_agent._request_model(request)
    system = captured['body']['messages'][0]['content']
    assert 'OFFLINE ONLY' not in system
    assert 'TRUSTED VALIDATOR REPAIR' in system
    assert 'TWO requests' in system


@pytest.mark.parametrize('unexpected', [
    {'origin': 'http://127.0.0.1:8010'},
    {'response_body': 'sensitive'},
    {'credentials': 'secret'},
])
def test_worker_rejects_target_and_live_response_fields(unexpected):
    row = {**scenario(), **unexpected}
    with pytest.raises(ValueError, match='메타데이터'):
        script_agent.validate_input({'scenarios': [row]})


@pytest.mark.parametrize('source', [
    CHECK + '\nimport os\n',
    CHECK.replace("status = response.get('status')", "status = open('/tmp/secret').read()"),
    CHECK.replace("return ('fail', 'HTML 마커가 원문으로 반사되었습니다.')",
                  "return ('fail', __import__('os').system('id'))"),
])
def test_worker_rejects_executable_python(source):
    with pytest.raises(ValueError):
        script_agent.validate_plan({**plan(), 'source': source}, scenario())
