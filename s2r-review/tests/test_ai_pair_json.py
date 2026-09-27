"""Bounded JSON response reasoning and alias-rich HTML checks stay pure."""

import pytest

import script_agent
from review.ai_scripts import evaluate_observation, validate_plan
from review.scripts import render_script


FIELDS = '''    status = response.get('status')
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
SQL_SCENARIO = {'id': 'a' * 16, 'method': 'GET', 'path': '/api/products',
                'automatable': True, 'title': 'Products',
                'source_context': 'L00001 def list_products(q: str):\n'
                                  'L00002     return {"items": find_products(q)}\n'
                                  'L00003 query = f"SELECT * FROM products WHERE name LIKE \'%{q}%\'"\n'}
SQL_PROBE = {'requests': [
    {'label': 'baseline', 'query_key': 'q', 'probe_value': "zz%' OR 1=0 --"},
    {'label': 'candidate', 'query_key': 'q', 'probe_value': "zz%' OR 1=1 --"},
]}
SQL_SOURCE = '''def evaluate(response):
    import json
''' + FIELDS + '''    try:
        baseline_data = json.loads(baseline_body_text)
        candidate_data = json.loads(body_text)
        baseline_items = baseline_data.get('items', [])
        candidate_items = candidate_data.get('items', [])
    except Exception:
        return ('inconclusive', 'JSON 응답을 해석할 수 없습니다.')
    if len(candidate_items) > len(baseline_items):
        return ('fail', '참 조건에서 결과 범위가 증가했습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''


def pair_plan(source=SQL_SOURCE, probe=SQL_PROBE):
    return {'probe': probe, 'source': source,
            'reason': 'q가 읽기 전용 목록 조회의 SQL 문자열에 직접 보간됩니다.'}


def observation(body, content_type='application/json'):
    return {'status_code': 200, 'error': None, 'body_text': body,
            'body_within_limit': True, 'headers': {'content-type': content_type}}


def test_import_json_is_normalized_and_bounded_parse_can_compare_array_lengths():
    plan = pair_plan()
    worker = script_agent.validate_plan(plan, SQL_SCENARIO)
    host = validate_plan(plan, SQL_SCENARIO)
    assert 'import json' not in worker['source']
    assert 'import json' not in host['source']
    assert worker['source'] == host['source']
    assert evaluate_observation(host, SQL_SCENARIO, {
        'baseline': observation('{"items":[]}'),
        'candidate': observation('{"items":[{"id":1}]}'),
    })[0] == 'fail'
    assert evaluate_observation(host, SQL_SCENARIO, {
        'baseline': observation('not-json'),
        'candidate': observation('{"items":[{"id":1}]}'),
    })[0] == 'inconclusive'
    script = render_script('http://127.0.0.1:8010', [SQL_SCENARIO],
                           {SQL_SCENARIO['id']: host})
    compile(script, '<download>', 'exec')


def test_observed_model_order_guards_then_json_try_and_two_sided_length():
    source = 'def evaluate(response):\n' + FIELDS + '''    if baseline_error or error:
        return ('inconclusive', '응답 연결 오류가 있습니다.')
    if baseline_status != 200 or status != 200:
        return ('inconclusive', '정상 응답을 확인하지 못했습니다.')
    if not baseline_body_within_limit or not body_within_limit:
        return ('inconclusive', '응답 크기 제한을 넘었습니다.')
    import json
    try:
        baseline_items = json.loads(baseline_body_text).get('items', [])
        candidate_items = json.loads(body_text).get('items', [])
    except Exception:
        return ('inconclusive', 'JSON을 해석할 수 없습니다.')
    if len(candidate_items) > len(baseline_items) and len(candidate_items) > 0:
        return ('fail', '참 조건에서 목록 범위가 증가했습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''
    approved = validate_plan(pair_plan(source), SQL_SCENARIO)
    assert script_agent.validate_plan(pair_plan(source), SQL_SCENARIO)['source'] == approved['source']
    assert 'import json' not in approved['source']
    assert evaluate_observation(approved, SQL_SCENARIO, {
        'baseline': observation('{"items":[]}'),
        'candidate': observation('{"items":[{"id":1}]}'),
    })[0] == 'fail'


def test_fresh_model_sql_import_inside_try_and_bounded_count_detail():
    source = 'def evaluate(response):\n' + FIELDS + '''    if baseline_error or error:
        return ('inconclusive', '연결 오류가 있습니다.')
    if baseline_status != 200 or status != 200:
        return ('inconclusive', '정상 응답이 아닙니다.')
    if not baseline_body_within_limit or not body_within_limit:
        return ('inconclusive', '응답이 잘렸습니다.')
    try:
        import json
        baseline_data = json.loads(baseline_body_text)
        candidate_data = json.loads(body_text)
        baseline_items = baseline_data.get('items', [])
        candidate_items = candidate_data.get('items', [])
        baseline_count = len(baseline_items)
        candidate_count = len(candidate_items)
    except Exception:
        return ('inconclusive', 'JSON을 해석할 수 없습니다.')
    if candidate_count > baseline_count and baseline_count >= 0:
        return ('fail', f'SQL 인젝션 의심: 기준 {baseline_count}개 → 후보 {candidate_count}개 제품 반환')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''
    worker = script_agent.validate_plan(pair_plan(source), SQL_SCENARIO)
    host = validate_plan(pair_plan(source), SQL_SCENARIO)
    assert worker['source'] == host['source']
    assert 'import json' not in host['source']
    assert 'baseline_count}개' not in host['source']
    assert evaluate_observation(host, SQL_SCENARIO, {
        'baseline': observation('{"items":[]}'),
        'candidate': observation('{"items":[{"id":1}]}'),
    })[0] == 'fail'
    compile(render_script('http://127.0.0.1:8010', [SQL_SCENARIO],
                          {SQL_SCENARIO['id']: host}), '<download>', 'exec')


def test_f_string_cannot_interpolate_response_body_or_unproven_alias():
    unsafe = SQL_SOURCE.replace(
        "return ('fail', '참 조건에서 결과 범위가 증가했습니다.')",
        "return ('fail', f'응답 본문: {body_text}')")
    with pytest.raises(ValueError):
        script_agent.validate_plan(pair_plan(unsafe), SQL_SCENARIO)
    with pytest.raises(ValueError):
        validate_plan(pair_plan(unsafe), SQL_SCENARIO)


def test_single_sided_json_length_cannot_prove_failure():
    source = SQL_SOURCE.replace('len(candidate_items) > len(baseline_items)',
                                'len(candidate_items) > 0')
    with pytest.raises(ValueError, match='기준/후보'):
        script_agent.validate_plan(pair_plan(source), SQL_SCENARIO)
    with pytest.raises(ValueError, match='기준/후보'):
        validate_plan(pair_plan(source), SQL_SCENARIO)


@pytest.mark.parametrize('bad', [
    'import os',
    'from json import loads',
    'import json as j',
])
def test_only_exact_json_import_is_normalized(bad):
    source = SQL_SOURCE.replace('import json', bad)
    with pytest.raises(ValueError):
        script_agent.validate_plan(pair_plan(source), SQL_SCENARIO)
    with pytest.raises(ValueError):
        validate_plan(pair_plan(source), SQL_SCENARIO)


@pytest.mark.parametrize('changed', [
    "json.loads('fixed text')",
    "json.loads(body_text).__class__",
    "baseline_data.get('__class__', [])",
    "len(body_text)",
    "open('/tmp/secret').read()",
])
def test_json_capability_rejects_other_calls(changed):
    source = SQL_SOURCE.replace('json.loads(baseline_body_text)', changed)
    with pytest.raises(ValueError):
        script_agent.validate_plan(pair_plan(source), SQL_SCENARIO)
    with pytest.raises(ValueError):
        validate_plan(pair_plan(source), SQL_SCENARIO)


def test_json_try_cannot_hide_a_failure_verdict():
    source = SQL_SOURCE.replace(
        "return ('inconclusive', 'JSON 응답을 해석할 수 없습니다.')",
        "return ('fail', 'JSON 오류만으로 실패 처리했습니다.')")
    with pytest.raises(ValueError):
        script_agent.validate_plan(pair_plan(source), SQL_SCENARIO)
    with pytest.raises(ValueError):
        validate_plan(pair_plan(source), SQL_SCENARIO)


def test_seven_boolean_aliases_and_negative_baseline_tag_are_proven():
    tag = '<strong>s2r_probe_2026abcd</strong>'
    row = {**SQL_SCENARIO, 'path': '/search/preview',
           'source_context': 'L00001 def preview(q: str):\n'
                             'L00002     return HTMLResponse(f"<p>{q}</p>")\n'}
    probe = {'requests': [
        {'label': 'baseline', 'query_key': 'q', 'probe_value': 's2r_probe_2026abcd'},
        {'label': 'candidate', 'query_key': 'q', 'probe_value': tag},
    ]}
    source = 'def evaluate(response):\n' + FIELDS + f'''    candidate_ct = headers.get('content-type', '')
    baseline_ct = baseline_headers.get('content-type', '')
    has_html = 'text/html' in candidate_ct
    baseline_has_html = 'text/html' in baseline_ct
    tag = '{tag}'
    candidate_has_tag = tag in body_text
    baseline_has_tag = tag in baseline_body_text
    if has_html and candidate_has_tag and not baseline_has_tag:
        return ('fail', '후보에서만 원문 태그가 HTML에 나타났습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''
    plan = {'probe': probe, 'source': source,
            'reason': 'q가 HTML 응답 본문에 들어갑니다.'}
    assert script_agent.validate_plan(plan, row)['probe'] == probe
    assert validate_plan(plan, row)['probe'] == probe
    assert evaluate_observation(plan, row, {
        'baseline': observation('safe', 'text/html'),
        'candidate': observation('<p>' + tag + '</p>', 'text/html'),
    })[0] == 'fail'


def test_fresh_redirect_plan_assigns_headers_after_early_guards():
    row = {**SQL_SCENARIO, 'path': '/go',
           'source_context': 'L00001 def go(next: str):\n'
                             'L00002     return RedirectResponse(url=next, status_code=307)\n'}
    probe = {'requests': [
        {'label': 'baseline', 'query_key': 'next', 'probe_value': '/'},
        {'label': 'candidate', 'query_key': 'next',
         'probe_value': 'https://example.invalid/'},
    ]}
    source = 'def evaluate(response):\n' + FIELDS + '''    if error or baseline_error:
        return ('inconclusive', '연결 오류가 있습니다.')
    if status != 307 or baseline_status != 307:
        return ('inconclusive', '리다이렉트 응답이 아닙니다.')
    loc = headers.get('location')
    base_loc = baseline_headers.get('location')
    if loc is None or base_loc is None:
        return ('inconclusive', 'Location을 확인할 수 없습니다.')
    if loc == 'https://example.invalid/' and base_loc == '/':
        return ('fail', '외부 URL이 Location으로 반환되었습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''
    plan = {'probe': probe, 'source': source, 'reason': 'next가 Location에 전달됩니다.'}
    assert script_agent.validate_plan(plan, row)['probe'] == probe
    assert validate_plan(plan, row)['probe'] == probe
    baseline = observation('', 'text/plain')
    baseline['status_code'] = 307
    baseline['headers']['location'] = '/'
    candidate = observation('', 'text/plain')
    candidate['status_code'] = 307
    candidate['headers']['location'] = 'https://example.invalid/'
    assert evaluate_observation(plan, row, {
        'baseline': baseline, 'candidate': candidate,
    })[0] == 'fail'


def test_fresh_xss_plan_uses_early_html_guard_then_tag_alias():
    tag = '<strong>s2r_probe_2026abcd</strong>'
    row = {**SQL_SCENARIO, 'path': '/search/preview',
           'source_context': 'L00001 def preview(q: str):\n'
                             'L00002     return HTMLResponse(f"<p>{q}</p>")\n'}
    probe = {'requests': [
        {'label': 'baseline', 'query_key': 'q', 'probe_value': 's2r_probe_2026abcd'},
        {'label': 'candidate', 'query_key': 'q', 'probe_value': tag},
    ]}
    source = 'def evaluate(response):\n' + FIELDS + f'''    if error or baseline_error:
        return ('inconclusive', '연결 오류가 있습니다.')
    if status != 200 or baseline_status != 200:
        return ('inconclusive', '정상 응답이 아닙니다.')
    if not body_within_limit or not baseline_body_within_limit:
        return ('inconclusive', '응답이 잘렸습니다.')
    ct = headers.get('content-type', '')
    if 'text/html' not in ct:
        return ('inconclusive', 'HTML 응답이 아닙니다.')
    candidate_tag = '{tag}'
    if candidate_tag in body_text and candidate_tag not in baseline_body_text:
        return ('fail', '후보에서만 원문 태그가 반사되었습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''
    plan = {'probe': probe, 'source': source, 'reason': 'q가 HTML 본문에 들어갑니다.'}
    assert script_agent.validate_plan(plan, row)['probe'] == probe
    assert validate_plan(plan, row)['probe'] == probe
    assert evaluate_observation(plan, row, {
        'baseline': observation('safe', 'text/html'),
        'candidate': observation('<p>' + tag + '</p>', 'text/html'),
    })[0] == 'fail'
