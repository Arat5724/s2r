"""A model plan may compare bounded responses without executable probe code."""

import pytest

import script_agent
from review.ai_scripts import evaluate_observation, validate_plan


SCENARIO = {'id': 'f' * 16, 'method': 'GET', 'path': '/api/files',
            'automatable': True, 'source_context':
            'L00001 def read_file(name: str):\n'
            'L00002     target = (PUBLIC_DIR / name).resolve()\n'
            'L00003     if not target.is_relative_to(DATA_DIR):\n'
            'L00004         raise HTTPException(403)\n'
            'L00005     return FileResponse(target)\n'}
PREFIX = '''def evaluate(response):
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
'''


def plan(source):
    return {'probe': {'requests': [
        {'label': 'baseline', 'query_key': 'name', 'probe_value': 'missing-fixture.txt'},
        {'label': 'candidate', 'query_key': 'name',
         'probe_value': '../private/canary.txt'},
    ]}, 'source': source, 'reason': '함수에서 공개 폴더와 검사 기준 폴더가 다릅니다.'}


def observation(status, body='ok'):
    return {'status_code': status, 'error': None, 'body_text': body,
            'body_within_limit': True, 'headers': {'content-type': 'text/plain'}}


def test_worker_host_agree_on_pair_and_evaluate_both_responses():
    source = PREFIX + '''    if baseline_status == 404 and status == 200:
        return ('fail', '공개 영역 밖의 파일이 제공되었습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''
    candidate = plan(source)
    assert script_agent.validate_plan(candidate, SCENARIO)['probe'] == candidate['probe']
    assert validate_plan(candidate, SCENARIO)['probe'] == candidate['probe']
    assert evaluate_observation(candidate, SCENARIO, {
        'baseline': observation(404), 'candidate': observation(200),
    })[0] == 'fail'
    assert evaluate_observation(candidate, SCENARIO, {
        'baseline': observation(404), 'candidate': observation(404),
    })[0] == 'inconclusive'


def test_declared_canary_requires_exact_candidate_marker_and_control_absence():
    row = {**SCENARIO, 'fixture_hints': [
        {'path': 'app/data/public/guide.txt', 'purpose': 'public_control',
         'marker': None},
        {'path': 'app/data/private/canary.txt', 'purpose': 'synthetic_canary',
         'marker': 'TECHLAB_PRIVATE_CANARY'},
    ]}
    weak = PREFIX + '''    if baseline_status == 404 and status == 200:
        return ('fail', '상태 차이만으로 판단했습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''
    with pytest.raises(ValueError, match='기준/후보'):
        script_agent.validate_plan(plan(weak), row)
    with pytest.raises(ValueError, match='기준/후보'):
        validate_plan(plan(weak), row)
    strong = PREFIX + '''    if 'TECHLAB_PRIVATE_CANARY' not in baseline_body_text and 'TECHLAB_PRIVATE_CANARY' in body_text:
        return ('fail', '선언된 합성 카나리가 공개 영역 밖에서 제공되었습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''
    candidate = plan(strong)
    assert script_agent.validate_plan(candidate, row)['probe'] == candidate['probe']
    assert validate_plan(candidate, row)['probe'] == candidate['probe']
    assert evaluate_observation(candidate, row, {
        'baseline': observation(200, 'guide'),
        'candidate': observation(200, 'TECHLAB_PRIVATE_CANARY'),
    })[0] == 'fail'


def test_pair_rejects_single_response_200_as_failure():
    source = PREFIX + '''    if status == 200:
        return ('fail', '후보 응답만 보고 판단했습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''
    with pytest.raises(ValueError, match='기준/후보'):
        script_agent.validate_plan(plan(source), SCENARIO)
    with pytest.raises(ValueError, match='기준/후보'):
        validate_plan(plan(source), SCENARIO)


def test_pair_evaluator_cannot_execute_a_model_supplied_import_or_call():
    source = PREFIX + '''    import os
    if baseline_status == 404 and status == 200:
        return ('fail', '응답 차이를 확인했습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''
    with pytest.raises(ValueError):
        script_agent.validate_plan(plan(source), SCENARIO)
    with pytest.raises(ValueError):
        validate_plan(plan(source), SCENARIO)


@pytest.mark.parametrize('value', ['foo;DROP', 'foo`id', '$(id)', 'a&&b',
                                    'a||b', 'bad\nvalue', '한글',
                                    '<script>alert(1)</script>',
                                    'javascript:alert(1)',
                                    'http://127.0.0.1/private'])
def test_pair_rejects_unsafe_transport_values(value):
    source = PREFIX + "    return ('inconclusive', '판단할 수 없습니다.')\n"
    candidate = plan(source)
    candidate['probe']['requests'][1]['probe_value'] = value
    with pytest.raises(ValueError):
        script_agent.validate_plan(candidate, SCENARIO)
    with pytest.raises(ValueError):
        validate_plan(candidate, SCENARIO)


def test_pair_rejects_unknown_query_key_and_identical_values():
    source = PREFIX + "    return ('inconclusive', '판단할 수 없습니다.')\n"
    candidate = plan(source)
    for item in candidate['probe']['requests']:
        item['query_key'] = 'unseen'
    with pytest.raises(ValueError, match='입력명'):
        script_agent.validate_plan(candidate, SCENARIO)
    with pytest.raises(ValueError, match='입력명'):
        validate_plan(candidate, SCENARIO)
    candidate = plan(source)
    candidate['probe']['requests'][1]['probe_value'] = 'missing-fixture.txt'
    with pytest.raises(ValueError):
        script_agent.validate_plan(candidate, SCENARIO)
    with pytest.raises(ValueError):
        validate_plan(candidate, SCENARIO)


def test_pair_preserves_baseline_404_but_transport_error_is_unavailable():
    source = PREFIX + '''    if baseline_status == 404 and status == 200:
        return ('fail', '서로 다른 응답입니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''
    candidate = plan(source)
    assert evaluate_observation(candidate, SCENARIO, {
        'baseline': observation(404), 'candidate': observation(200),
    })[0] == 'fail'
    broken = observation(404)
    broken['error'] = 'timeout'
    assert evaluate_observation(candidate, SCENARIO, {
        'baseline': broken, 'candidate': observation(200),
    })[0] == 'unavailable'


def test_source_specific_redirect_pair_compares_location_headers():
    row = {**SCENARIO, 'path': '/go', 'source_context':
           'L00001 def go(next: str):\n'
           'L00002     return RedirectResponse(url=next, status_code=307)\n'}
    source = PREFIX + '''    prior = baseline_headers.get('location', '')
    current = headers.get('location', '')
    if prior == '/' and current == 'https://example.invalid/s2r':
        return ('fail', '외부 위치를 Location으로 반환했습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''
    candidate = {'probe': {'requests': [
        {'label': 'baseline', 'query_key': 'next', 'probe_value': '/'},
        {'label': 'candidate', 'query_key': 'next',
         'probe_value': 'https://example.invalid/s2r'},
    ]}, 'source': source, 'reason': 'next가 리다이렉트 위치에 전달됩니다.'}
    assert script_agent.validate_plan(candidate, row)['probe'] == candidate['probe']
    assert validate_plan(candidate, row)['probe'] == candidate['probe']
    control = observation(307)
    control['headers']['location'] = '/'
    changed = observation(307)
    changed['headers']['location'] = 'https://example.invalid/s2r'
    assert evaluate_observation(candidate, row, {'baseline': control,
                                                  'candidate': changed})[0] == 'fail'


def test_inert_html_tag_requires_html_content_type_and_baseline_absence():
    row = {**SCENARIO, 'path': '/search/preview', 'source_context':
           'L00001 def preview(q: str):\n'
           'L00002     return HTMLResponse(f"<p>{q}</p>")\n'}
    tag = '<strong>s2r_probe_2026abcd</strong>'
    source = PREFIX + f'''    content_type = headers.get('content-type', '')
    if '{tag}' not in baseline_body_text and 'text/html' in content_type and '{tag}' in body_text:
        return ('fail', 'HTML에 원문 태그가 반사되었습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''
    candidate = {'probe': {'requests': [
        {'label': 'baseline', 'query_key': 'q', 'probe_value': 's2r_probe_2026abcd'},
        {'label': 'candidate', 'query_key': 'q', 'probe_value': tag},
    ]}, 'source': source, 'reason': 'q가 HTML 문자열에 삽입됩니다.'}
    assert script_agent.validate_plan(candidate, row)['probe'] == candidate['probe']
    assert validate_plan(candidate, row)['probe'] == candidate['probe']
    plain = observation(200, '<p>' + tag + '</p>')
    assert evaluate_observation(candidate, row, {
        'baseline': observation(200), 'candidate': plain,
    })[0] == 'inconclusive'
    plain['headers']['content-type'] = 'text/html'
    assert evaluate_observation(candidate, row, {
        'baseline': observation(200), 'candidate': plain,
    })[0] == 'fail'


def test_read_only_query_pair_can_compare_source_specific_result_signal():
    row = {**SCENARIO, 'path': '/api/products', 'source_context':
           'L00001 def list_products(q: str):\n'
           'L00002     return {"items": find_products(q)}\n'
           'L00003 query = f"SELECT * FROM products WHERE name LIKE \'%{q}%\'"\n'}
    source = PREFIX + '''    if '"items":[]' in baseline_body_text and '"items":[]' not in body_text:
        return ('fail', '거짓 조건과 참 조건에서 결과 범위가 달라졌습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''
    candidate = {'probe': {'requests': [
        {'label': 'baseline', 'query_key': 'q', 'probe_value': "zz%' OR 1=0 --"},
        {'label': 'candidate', 'query_key': 'q', 'probe_value': "zz%' OR 1=1 --"},
    ]}, 'source': source, 'reason': 'q가 SQL LIKE 문자열에 직접 보간됩니다.'}
    assert script_agent.validate_plan(candidate, row)['probe'] == candidate['probe']
    assert validate_plan(candidate, row)['probe'] == candidate['probe']
    assert evaluate_observation(candidate, row, {
        'baseline': observation(200, '{"items":[]}'),
        'candidate': observation(200, '{"items":[{"id":1}]}'),
    })[0] == 'fail'
