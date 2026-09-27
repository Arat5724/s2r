"""Selected method and input location survive source, worker, and plan checks."""

import ast
import json

import pytest

import script_agent
from review.ai_get_safety import prove_probe_safe
from review.ai_scenarios import normalize_ai_scenarios


SOURCE = '''from fastapi import FastAPI, Body
from fastapi.responses import HTMLResponse
app = FastAPI()
@app.post('/echo')
def echo(q: str = Body(embed=True)):
    return HTMLResponse(f'<p>{q}</p>')
'''
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
        return ('fail', '선택 입력에서 구별되는 응답이 관찰되었습니다.')
    return ('inconclusive', '응답만으로 판단할 수 없습니다.')
'''


def endpoint(source=SOURCE, *, location='body', method='POST'):
    function = next(node for node in ast.walk(ast.parse(source))
                    if isinstance(node, ast.FunctionDef) and node.name == 'echo')
    return {
        'id': 'echo-route', 'framework': 'FastAPI', 'method': method,
        'path': '/echo', 'handler': {'file': 'app.py', 'line': function.lineno,
                                    'end_line': function.end_lineno, 'symbol': 'echo'},
        'inputs': [{'name': 'q', 'in': location, 'type': 'str', 'required': True}],
        'call_chain': [{'file': 'app.py', 'line': function.lineno - 1,
                        'reason': 'route registration'}],
        'guards': [], 'conditions': [], 'dependencies': [],
        'effects': {'database_write_detected': False,
                    'session_change_detected': False},
    }


def proposal():
    return {
        'endpoint_id': 'echo-route', 'category': 'xss', 'input_name': 'q',
        'title': '입력 응답 비교', 'description': '선택 입력이 응답에 삽입됩니다.',
        'risk_hypothesis': '응답에 값이 그대로 보일 수 있습니다.',
        'verification_expectation': '두 응답을 비교합니다.',
        'uncertainty': '실제 영향은 응답으로 확인합니다.',
        'remediation_summary': '출력값을 이스케이프합니다.',
        'source_evidence': [{'file': 'app.py', 'line': 6}],
    }


def worker_scenario():
    return {
        'id': 'a' * 16, 'method': 'POST', 'path': '/echo',
        'category': 'xss', 'title': '입력 응답 비교',
        'risk_hypothesis': '입력이 응답에 삽입됩니다.',
        'verification_expectation': '두 응답을 비교합니다.',
        'source_context': 'FILE app.py\nL00005 def echo(q):\nL00006     return q',
        'source_evidence': [{'file': 'app.py', 'line': 6}],
        'automatable': True, 'input_name': 'q', 'input_location': 'body',
    }


def plan(*, baseline_location='body', candidate_location='body'):
    return {
        'probe': {'requests': [
            {'label': 'baseline', 'input_location': baseline_location,
             'query_key': 'q', 'probe_value': 'control'},
            {'label': 'candidate', 'input_location': candidate_location,
             'query_key': 'q', 'probe_value': 'candidate'},
        ]}, 'source': EVALUATOR, 'reason': '함수의 q 입력을 비교합니다.',
    }


def test_post_json_string_body_is_source_bound_and_becomes_live_scenario():
    selected = endpoint()
    assert prove_probe_safe({'app.py': SOURCE}, selected, 'q', 'body') == (True, '')
    result = {'analysis_mode': 'ai', 'ai': {'status': 'completed'},
              'endpoints': [selected], 'ai_scenarios': [proposal()]}
    scenario = normalize_ai_scenarios(result, {'app.py': SOURCE})[0]
    assert scenario['method'] == 'POST'
    assert scenario['input_location'] == 'body'
    assert scenario['automatable'] is True
    assert scenario['execution_kind'] == 'ai_request'


def test_post_body_source_requires_exact_embedding_and_rejects_effect_call():
    assert prove_probe_safe({'app.py': SOURCE}, endpoint(location='query'), 'q', 'query')[0] is False
    unembedded = SOURCE.replace('Body(embed=True)', 'Body(embed=False)')
    assert prove_probe_safe({'app.py': unembedded}, endpoint(unembedded), 'q', 'body')[0] is False
    effect = SOURCE.replace("    return HTMLResponse(f'<p>{q}</p>')",
                            "    save(q)\n    return HTMLResponse(f'<p>{q}</p>')")
    assert prove_probe_safe({'app.py': effect}, endpoint(effect), 'q', 'body')[0] is False


def test_source_binding_works_for_query_on_post_and_other_frameworks():
    query_source = SOURCE.replace('FastAPI, Body', 'FastAPI').replace(
        'Body(embed=True)', "''")
    assert prove_probe_safe({'app.py': query_source},
                            endpoint(query_source, location='query'), 'q', 'query') == (True, '')
    spring = '''@RestController
class EchoController {
    @PostMapping("/echo")
    String echo(@RequestBody String q) { return q; }
}
'''
    selected = {
        'framework': 'Spring Boot', 'method': 'POST', 'path': '/echo',
        'handler': {'file': 'Echo.java', 'line': 4, 'end_line': 4,
                    'symbol': 'echo'},
        'inputs': [{'name': 'q', 'in': 'body'}],
        'call_chain': [{'file': 'Echo.java', 'line': 3,
                        'reason': 'route registration'}],
    }
    assert prove_probe_safe({'Echo.java': spring}, selected, 'q', 'body') == (True, '')
    changed = spring.replace('return q;', 'return repository.save(q);')
    assert prove_probe_safe({'Echo.java': changed}, selected, 'q', 'body')[0] is False


def test_worker_allows_selected_post_body_pair_but_rejects_location_change():
    row = worker_scenario()
    validated = script_agent.validate_plan(plan(), row)
    assert validated['probe']['requests'][0]['input_location'] == 'body'
    with pytest.raises(ValueError, match='입력 위치'):
        script_agent.validate_plan(plan(candidate_location='query'), row)
    with pytest.raises(ValueError, match='입력 위치'):
        script_agent.validate_plan(plan(baseline_location='query',
                                        candidate_location='query'), row)


def test_worker_prompt_uses_selected_post_method_and_json_location(monkeypatch):
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def read(self, _):
            return json.dumps({'choices': [{'message': {'content': json.dumps(plan())}}]}).encode()

    def urlopen(request, **_):
        captured['payload'] = json.loads(request.data)
        return Response()

    monkeypatch.setattr(script_agent.urllib.request, 'urlopen', urlopen)
    script_agent._request_model(worker_scenario())
    system = captured['payload']['messages'][0]['content']
    assert 'method POST at the fixed path /echo' in system
    assert 'selected input location is body' in system
    assert 'one JSON string field keyed by query_key' in system
    assert 'OFFLINE ONLY' not in system
