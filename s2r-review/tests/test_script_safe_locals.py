"""A real model's content_type local is safe; executable AST variants are not."""

import pytest

import script_agent
from review.ai_scripts import evaluate_observation, validate_check, validate_plan


SOURCE = '''def evaluate(response):
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
    if status == 200 and body_within_limit and is_html:
        if '<strong>s2r_probe_12345678</strong>' in body_text:
            return ('fail', 'HTML 마커가 원문으로 반사되었습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''

SCENARIO = {'id': 'a' * 16, 'method': 'GET', 'path': '/echo',
            'category': 'arbitrary_custom_category', 'automatable': True}
PLAN = {'probe': {'query_key': 'q', 'probe_value': '<strong>s2r_probe_12345678</strong>'},
        'source': SOURCE, 'reason': 'HTML 응답에 입력이 그대로 포함될 수 있습니다.'}


def test_real_model_header_local_passes_worker_and_host_and_evaluates():
    assert script_agent._validate_source(SOURCE) == SOURCE
    assert validate_check(SOURCE, SCENARIO, PLAN['probe']).startswith('def ai_evaluate_')
    approved = validate_plan(PLAN, SCENARIO)
    result = evaluate_observation(approved, SCENARIO, {
        'status_code': 200, 'error': None, 'body_text': '<strong>s2r_probe_12345678</strong>',
        'body_within_limit': True, 'headers': {'Content-Type': 'text/html'}})
    assert result[0] == 'fail'
    non_html = evaluate_observation(approved, SCENARIO, {
        'status_code': 200, 'error': None, 'body_text': '<strong>s2r_probe_12345678</strong>',
        'body_within_limit': True, 'headers': {'Content-Type': 'text/plain'}})
    assert non_html[0] == 'inconclusive'


def test_model_not_in_header_branch_is_accepted_without_extra_capabilities():
    source = SOURCE.replace("    is_html = 'text/html' in content_type\n",
                            "    if 'text/html' not in content_type:\n"
                            "        return ('inconclusive', 'HTML 응답이 아닙니다.')\n").replace(
        'and is_html:', ':')
    assert script_agent._validate_source(source)
    assert validate_check(source, SCENARIO, PLAN['probe'])


@pytest.mark.parametrize('replacement', [
    "content_type = headers.get('content-type', 'unsafe')",
    "content_type = headers.get('content-type', __import__('os'))",
    "content_type = headers.get('__class__', '')",
    'content_type = response.__class__',
    "content_type = open('/tmp/secret').read()",
    'content_type = headers.get(name)',
    'content_type = (lambda: 1)()',
])
def test_unsafe_local_expressions_rejected_by_worker_and_host(replacement):
    source = SOURCE.replace("content_type = headers.get('content-type', '')", replacement)
    with pytest.raises(ValueError):
        script_agent._validate_source(source)
    with pytest.raises(ValueError):
        validate_check(source, SCENARIO, PLAN['probe'])


@pytest.mark.parametrize('assignment', [
    'content_type = headers.get(\'content-type\', \'\')',  # duplicate
    'status = 200',  # required field overwrite
    '__dunder__ = True',
    'response = True',
    'a = b = True',
])
def test_duplicate_or_forbidden_local_targets_rejected(assignment):
    source = SOURCE.replace("    is_html = 'text/html' in content_type\n",
                            "    is_html = 'text/html' in content_type\n    " + assignment + '\n')
    with pytest.raises(ValueError):
        script_agent._validate_source(source)
    with pytest.raises(ValueError):
        validate_check(source, SCENARIO, PLAN['probe'])


def test_more_than_eight_locals_or_assignment_inside_branch_rejected():
    extra = SOURCE.replace("    is_html = 'text/html' in content_type\n",
                           "    is_html = 'text/html' in content_type\n"
                           "    first = True\n    second = True\n    third = True\n"
                           "    fourth = True\n    fifth = True\n    sixth = True\n"
                           "    seventh = True\n")
    branch = SOURCE.replace("    if error is not None:\n",
                            "    if error is not None:\n        hidden = True\n")
    for source in (extra, branch):
        with pytest.raises(ValueError):
            script_agent._validate_source(source)
        with pytest.raises(ValueError):
            validate_check(source, SCENARIO, PLAN['probe'])
