"""The host validates a selected request's input location without a GET gate."""

import pytest

from review.ai_scripts import validate_plan, validate_probe


SCENARIO = {
    'id': 'e' * 16, 'method': 'POST', 'path': '/preview',
    'input_name': 'q', 'input_location': 'body',
    'source_context': 'L00001 def preview(q):\nL00002     return render(q)\n',
}
EVALUATOR = '''def evaluate(response):
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
    if baseline_status == 404 and status == 200:
        return ('fail', '기준과 후보의 응답 상태가 다릅니다.')
    return ('inconclusive', '두 응답만으로 판단할 수 없습니다.')
'''


def body_plan(location='body'):
    return {'probe': {'requests': [
        {'label': 'baseline', 'query_key': 'q', 'input_location': location,
         'probe_value': 'missing'},
        {'label': 'candidate', 'query_key': 'q', 'input_location': location,
         'probe_value': 'present'},
    ]}, 'source': EVALUATOR, 'reason': '선택한 본문 입력의 두 응답을 비교합니다.'}


def test_selected_post_body_plan_is_validated_without_method_gating():
    plan = body_plan()
    assert validate_plan(plan, SCENARIO)['probe'] == plan['probe']


def test_model_cannot_change_selected_input_location():
    with pytest.raises(ValueError, match='입력 위치'):
        validate_plan(body_plan('query'), SCENARIO)
    mixed = body_plan()
    del mixed['probe']['requests'][1]['input_location']
    with pytest.raises(ValueError, match='같은 입력'):
        validate_probe(mixed['probe'])
