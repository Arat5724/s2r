"""An inert query marker is evidence only when HTML interprets its tag."""

import pytest

import script_agent
from review.ai_scripts import validate_plan as host_validate_plan


SCENARIO = {'id': 'a' * 16, 'method': 'GET', 'path': '/echo',
            'automatable': True, 'category': 'any'}
TAG = '<strong>s2r_probe_12345678</strong>'
PLAIN = 's2r_probe_12345678'
HTML_SOURCE = '''def evaluate(response):
    status = response.get('status')
    error = response.get('error')
    body_text = response.get('body_text')
    body_within_limit = response.get('body_within_limit')
    headers = response.get('headers')
    content_type = headers.get('content-type', '')
    is_html = 'text/html' in content_type
    marker = '<strong>s2r_probe_12345678</strong>'
    if status == 200 and body_within_limit and is_html and marker in body_text:
        return ('fail', 'HTML 태그가 원문으로 반사되었습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''


def plan(source, value):
    return {'probe': {'query_key': 'q', 'probe_value': value},
            'source': source, 'reason': '선택한 함수의 응답을 살핍니다.'}


def test_active_tagged_html_requires_both_content_type_and_exact_raw_tag():
    candidate = plan(HTML_SOURCE, TAG)
    assert script_agent.validate_plan(candidate, SCENARIO)['probe']['probe_value'] == TAG
    assert host_validate_plan(candidate, SCENARIO)['probe']['probe_value'] == TAG


def test_early_html_guard_proves_later_tag_branch():
    source = HTML_SOURCE.replace(
        '    if status == 200 and body_within_limit and is_html and marker in body_text:\n',
        "    if not is_html:\n        return ('inconclusive', 'HTML 응답이 아닙니다.')\n"
        '    if marker in body_text:\n')
    candidate = plan(source, TAG)
    assert script_agent.validate_plan(candidate, SCENARIO)['probe']['probe_value'] == TAG
    assert host_validate_plan(candidate, SCENARIO)['probe']['probe_value'] == TAG


def test_early_guard_without_return_does_not_prove_html():
    source = HTML_SOURCE.replace(
        '    if status == 200 and body_within_limit and is_html and marker in body_text:\n',
        "    if not is_html:\n        status = 200\n"
        '    if marker in body_text:\n')
    candidate = plan(source, TAG)
    with pytest.raises(ValueError):
        script_agent.validate_plan(candidate, SCENARIO)
    with pytest.raises(ValueError):
        host_validate_plan(candidate, SCENARIO)


@pytest.mark.parametrize('source', [
    HTML_SOURCE.replace(' and is_html', ''),
    HTML_SOURCE.replace(' and marker in body_text', ''),
    HTML_SOURCE.replace(' and is_html and marker in body_text',
                        ' and (is_html or marker in body_text)'),
    HTML_SOURCE.replace("marker = '<strong>s2r_probe_12345678</strong>'",
                        "marker = '<em>s2r_probe_12345678</em>'"),
])
def test_tagged_probe_rejects_fail_without_both_required_observations(source):
    candidate = plan(source, TAG)
    with pytest.raises(ValueError, match='HTML'):
        script_agent.validate_plan(candidate, SCENARIO)
    with pytest.raises(ValueError, match='HTML'):
        host_validate_plan(candidate, SCENARIO)


@pytest.mark.parametrize('source', [
    HTML_SOURCE.replace("marker = '<strong>s2r_probe_12345678</strong>'",
                        "marker = 's2r_probe_12345678'")
               .replace(' and is_html and marker in body_text',
                        ' and marker in body_text'),
    '''def evaluate(response):
    status = response.get('status')
    error = response.get('error')
    body_text = response.get('body_text')
    body_within_limit = response.get('body_within_limit')
    headers = response.get('headers')
    location = headers.get('location', '')
    if status == 302 and location == 's2r_probe_12345678':
        return ('fail', 'Location에 입력이 돌아왔습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
''',
])
def test_plain_body_or_location_reflection_never_becomes_active_failure(source):
    candidate = plan(source, PLAIN)
    with pytest.raises(ValueError, match='마커 반사'):
        script_agent.validate_plan(candidate, SCENARIO)
    with pytest.raises(ValueError, match='평문 마커'):
        host_validate_plan(candidate, SCENARIO)
