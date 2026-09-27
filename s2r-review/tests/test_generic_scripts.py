"""Generic AI scripts take their probe and evaluator from a checked plan."""

import pytest

from review.ai_scripts import validate_probe
from review.scripts import render_script


SOURCE = '''def evaluate(response):
    status = response.get('status')
    error = response.get('error')
    body_text = response.get('body_text')
    body_within_limit = response.get('body_within_limit')
    headers = response.get('headers')
    content_type = headers.get('content-type', '')
    is_html = 'text/html' in content_type
    if status == 200 and body_within_limit and is_html and '<strong>s2r_unique_12345678</strong>' in body_text:
        return ('fail', '고유 마커가 응답에 있습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''


def scenario(path='/preview'):
    return {'id': 'a' * 16, 'title': 'GET preview', 'method': 'GET',
            'path': path, 'automatable': True, 'category': 'custom',
            'execution_kind': 'ai_source_check'}


def plan(value='<strong>s2r_unique_12345678</strong>'):
    return {'probe': {'query_key': 'term', 'probe_value': value},
            'source': SOURCE, 'reason': '함수가 term을 응답에 포함합니다.'}


def test_model_selected_probe_and_evaluator_are_in_downloaded_script():
    candidate = scenario()
    script = render_script('http://127.0.0.1:8010', [candidate],
                           {candidate['id']: plan()})
    assert '<strong>s2r_unique_12345678</strong>' in script
    assert "connection.request(scenario['method'], request_path)" in script
    assert 'http_sqli_boolean' not in script
    assert 'TRAVERSAL_INPUT' not in script
    namespace = {'__name__': 'test_download'}
    exec(compile(script, '<download>', 'exec'), namespace)
    configured = namespace['CONFIG']['scenarios'][0]
    assert configured['method'] == 'GET'
    assert configured['requests'][0]['query_key'] == 'term'
    observed = namespace['assess'](configured, {'candidate': {
        'status': 200, 'error': None,
        'body_text': '<strong>s2r_unique_12345678</strong>',
        'body_within_limit': True, 'headers': {'content-type': 'text/html'}}})
    assert observed['status'] == 'fail'


@pytest.mark.parametrize('value', [
    'hello', "%' OR 1=1 --", '../private/canary.txt',
    '<script>alert(1)</script>', 'https://example.invalid/x',
])
def test_active_probe_rejects_non_marker_values(value):
    with pytest.raises(ValueError):
        validate_probe({'query_key': 'term', 'probe_value': value})


@pytest.mark.parametrize('query_key', ['q&evil=1', '../q', '', 'q\nOther: yes', 'a' * 65])
def test_active_probe_rejects_unsafe_query_key(query_key):
    with pytest.raises(ValueError):
        validate_probe({'query_key': query_key, 'probe_value': 's2r_unique_12345678'})


@pytest.mark.parametrize('path', ['//preview', '/a/../preview', '/a/./preview'])
def test_download_rejects_normalizing_path(path):
    candidate = scenario(path)
    with pytest.raises(ValueError, match='path'):
        render_script('http://127.0.0.1:8010', [candidate], {candidate['id']: plan()})
