"""The host validates generic model code and shares one evaluator with downloads."""

import pytest

from review.ai_scripts import evaluate_observation, validate_check, validate_plan
from review.scripts import render_script


SOURCE = '''def evaluate(response):
    status = response.get('status')
    error = response.get('error')
    body_text = response.get('body_text')
    body_within_limit = response.get('body_within_limit')
    headers = response.get('headers')
    content_type = headers.get('content-type', '')
    is_html = 'text/html' in content_type
    if status == 200 and body_within_limit and is_html and '<strong>s2r_source_12345678</strong>' in body_text:
        return ('fail', '고유 마커가 원문 응답에 있습니다.')
    if status == 200 and '&lt;strong&gt;' in body_text:
        return ('pass', '출력이 HTML 문자로 처리되었습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''


def scenario(category='any'):
    return {'id': 'c' * 16, 'title': 'GET /preview', 'category': category,
            'method': 'GET', 'path': '/preview', 'automatable': True}


def plan():
    return {'probe': {'query_key': 'text', 'probe_value': '<strong>s2r_source_12345678</strong>'},
            'source': SOURCE, 'reason': '함수가 text를 응답에 포함합니다.'}


@pytest.mark.parametrize('category', ['xss', 'sql_injection', 'other_custom_category'])
def test_category_does_not_gate_validated_model_code(category):
    row = scenario(category)
    approved = validate_plan(plan(), row)
    script = render_script('http://127.0.0.1:8010', [row], {row['id']: approved})
    assert f'ai_evaluate_{row["id"]}' in script
    result = evaluate_observation(approved, row, {
        'status_code': 200, 'error': None,
        'body_text': '<strong>s2r_source_12345678</strong>',
        'body_within_limit': True, 'headers': {'content-type': 'text/html'}})
    assert result[0] == 'fail'


@pytest.mark.parametrize('source', [
    'import os\n' + SOURCE,
    SOURCE.replace("status = response.get('status')", "status = open('/tmp/private').read()"),
    SOURCE.replace("status = response.get('status')", "status = __import__('os').system('id')"),
    SOURCE.replace("body_text = response.get('body_text')", "body_text = response.__class__"),
    SOURCE.replace("if status == 200", "for item in response:\n        pass\n    if status == 200", 1),
    SOURCE.replace("headers = response.get('headers')", "headers = response.get('secrets')"),
])
def test_host_rejects_unsafe_or_unbounded_model_code(source):
    with pytest.raises(ValueError):
        validate_check(source, scenario(), plan()['probe'])


def test_live_error_and_missing_path_override_ai_code():
    row = scenario()
    approved = validate_plan(plan(), row)
    unavailable = evaluate_observation(approved, row, {'status_code': 200,
        'error': 'connection_failed', 'body_text': 's2r_source_12345678',
        'body_within_limit': True, 'headers': {}})
    missing = evaluate_observation(approved, row, {'status_code': 404,
        'error': None, 'body_text': 's2r_source_12345678',
        'body_within_limit': True, 'headers': {}})
    assert unavailable[0] == 'unavailable'
    assert missing[0] == 'not_found'


def test_invalid_response_causes_inconclusive_not_crash():
    row = scenario()
    approved = validate_plan(plan(), row)
    result = evaluate_observation(approved, row, {'status_code': 200,
        'error': None, 'body_text': None, 'body_within_limit': False, 'headers': []})
    assert result[0] == 'inconclusive'


def test_offline_host_rejects_unsent_probe_marker_and_generic_failure_word():
    row = {**scenario(), 'method': 'POST', 'automatable': False}
    offline = {**plan(), 'probe': {'query_key': None, 'probe_value': None}}
    with pytest.raises(ValueError, match='마커 반사'):
        validate_plan(offline, row, offline=True)
    weak = {**offline, 'source': SOURCE.replace('<strong>s2r_source_12345678</strong>', 'sql')}
    with pytest.raises(ValueError, match='짧은 일반 문자열'):
        validate_plan(weak, row, offline=True)


def test_offline_host_accepts_ai_inconclusive_when_specific_signal_unavailable():
    row = {**scenario(), 'method': 'POST', 'automatable': False}
    source = '''def evaluate(response):
    status = response.get('status')
    error = response.get('error')
    body_text = response.get('body_text')
    body_within_limit = response.get('body_within_limit')
    headers = response.get('headers')
    if error is not None:
        return ('unavailable', '연결할 수 없습니다.')
    return ('inconclusive', '고유 응답 신호가 없어 수동 검토가 필요합니다.')
'''
    offline = {'probe': {'query_key': None, 'probe_value': None},
               'source': source, 'reason': '응답의 정확한 판별 내용을 코드에서 알 수 없습니다.'}
    assert validate_plan(offline, row, offline=True)['source'] == source
