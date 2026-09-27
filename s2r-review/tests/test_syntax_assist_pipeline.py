"""Syntax facts guide the model; the model still supplies all proposals."""

import io
import json

import pytest

import ai_source


def test_ai_prompt_contains_numbered_source_and_ast_hints(monkeypatch):
    requests = []

    def fake_urlopen(request, **_):
        requests.append(json.loads(request.data))
        content = {'project_summary': '함수만 있는 모듈', 'endpoints': [], 'scenarios': []}
        return io.BytesIO(json.dumps({'choices': [{'message': {'content': json.dumps(content)}}],
                                      'model': 'test-managed-model'}).encode())

    monkeypatch.setattr(ai_source.urllib.request, 'urlopen', fake_urlopen)
    files = {'app.py': 'def lookup(q):\n    return normalize(q)\n\ndef normalize(q):\n    return q.strip()\n'}
    result = ai_source.infer_from_source(files)
    assert result['endpoints'] == [] and result['ai_scenarios'] == []
    assert len(requests) == 1
    prompt = requests[0]['messages'][1]['content']
    assert '### FILE app.py' in prompt and 'L00001 def lookup(q):' in prompt
    assert 'AST/구문 트리 탐색 단서' in prompt
    syntax = json.loads(prompt.split('AST/구문 트리 탐색 단서 (불완전할 수 있음; 근거는 위 원본 줄만 인용)\n', 1)[1])
    python_facts = syntax['python_ast']['facts']
    assert any(fact['symbol'] == 'lookup' for fact in python_facts)
    assert any(call.get('candidate_definition', {}).get('symbol') == 'normalize'
               for fact in python_facts for call in fact.get('calls', []))
    assert result['ai']['syntax_assist']['python_ast']['files_parsed'] == 1
    assert result['ai']['syntax_assist']['python_ast']['facts_included'] >= 2


def test_unshown_suffix_of_long_line_cannot_validate_citation():
    long_line = 'value = "' + 'x' * 1200 + 'SECRET_SUFFIX"'
    files = {'app.py': 'def helper():\n    ' + long_line + '\n    return value\n'}
    source, shown, _, _ = ai_source.prepare_source(files)
    assert 'TRUNCATED' in source
    assert ('app.py', 2) not in shown
    with pytest.raises(ValueError, match='모델에 제공되지 않은'):
        ai_source._check_evidence({'file': 'app.py', 'line': 2, 'symbol': 'helper',
                                   'quote': 'SECRET_SUFFIX'}, files, shown)
    context, _ = ai_source.syntax_context(files, shown)
    assert 'SECRET_SUFFIX' not in context


def test_large_file_shows_complete_handler_and_distant_helper_without_sink_hints():
    filler = '# ' + 'x' * 36_000
    files = {'app.py': (
        filler + '\n'
        '@app.get("/preview")\n'
        'def preview(q):\n'
        '    prepared = transform(q)\n'
        '    return publish(prepared)\n'
        + '\n' * 80 +
        'def transform(value):\n'
        '    result = value.strip()\n'
        '    return result\n'
    )}
    rendered, shown, omitted, _ = ai_source.prepare_source(files)
    assert 'def preview(q):' in rendered
    assert 'return publish(prepared)' in rendered
    assert 'def transform(value):' in rendered
    assert 'return result' in rendered
    assert ('app.py', 87) in shown
    assert omitted == ['app.py (일부 줄)']


def test_source_grounded_custom_wrapper_is_not_filtered_by_category_keyword_table():
    files = {'app.py': ('@app.get("/preview")\n'
                        'def preview(q):\n'
                        '    return bespoke_output(q)\n')}
    _, shown, omitted, manifests = ai_source.prepare_source(files)
    parsed = {
        'project_summary': '미리보기', 'review_notes': [],
        'endpoints': [{
            'key': 'e1', 'framework': 'FastAPI', 'method': 'GET', 'path': '/preview',
            'handler': {'file': 'app.py', 'line': 2, 'symbol': 'preview',
                        'quote': 'def preview(q):'},
            'route_evidence': [{'file': 'app.py', 'line': 1, 'symbol': 'preview',
                                'quote': '@app.get("/preview")'}],
            'inputs': [{'name': 'q', 'in': 'query', 'type': 'str', 'required': True}],
            'summary': '미리보기',
        }],
        'scenarios': [{
            'endpoint_ref': 'e1', 'category': 'xss', 'input_name': 'q',
            'title': '출력 안전성 가설', 'description': '입력이 별도 출력 함수를 거친다.',
            'risk_hypothesis': '출력 함수의 인코딩이 충분하지 않을 수 있다.',
            'verification_expectation': '비파괴적으로 출력 인코딩을 확인한다.',
            'uncertainty': '출력 함수의 본문이 여기에는 없다.',
            'remediation_summary': '출력 문맥에 맞게 인코딩한다.',
            'source_evidence': [{'file': 'app.py', 'line': 3, 'symbol': 'preview',
                                 'quote': 'return bespoke_output(q)'}],
        }],
    }
    result = ai_source.validate_response(parsed, files, shown, omitted, manifests)
    assert result['ai_scenarios'][0]['category'] == 'xss'


def test_large_java_source_keeps_complete_methods_without_sink_based_windows():
    pytest.importorskip('tree_sitter')
    pytest.importorskip('tree_sitter_java')
    files = {'src/Controller.java': (
        '// ' + 'x' * 36_000 + '\n'
        'class Controller {\n'
        '  @GetMapping("/preview")\n'
        '  String preview(String q) {\n'
        '    return transform(q);\n'
        '  }\n'
        + '\n' * 80 +
        '  String transform(String q) {\n'
        '    String result = q.trim();\n'
        '    return result;\n'
        '  }\n'
        '}\n'
    )}
    rendered, shown, omitted, _ = ai_source.prepare_source(files)
    assert 'String preview(String q)' in rendered
    assert 'return transform(q);' in rendered
    assert 'String transform(String q)' in rendered
    assert 'return result;' in rendered
    assert ('src/Controller.java', 89) in shown
    assert omitted == ['src/Controller.java (일부 줄)']


def test_helper_only_citation_cannot_attach_a_finding_to_an_unrelated_route():
    files = {'app.py': ('@app.get("/preview")\n'
                        'def preview(q):\n'
                        '    return transform(q)\n'
                        '\n'
                        'def transform(value):\n'
                        '    return value.strip()\n')}
    _, shown, omitted, manifests = ai_source.prepare_source(files)
    parsed = {
        'project_summary': '미리보기', 'review_notes': [],
        'endpoints': [{
            'key': 'e1', 'framework': 'FastAPI', 'method': 'GET', 'path': '/preview',
            'handler': {'file': 'app.py', 'line': 2, 'symbol': 'preview',
                        'quote': 'def preview(q):'},
            'route_evidence': [{'file': 'app.py', 'line': 1, 'symbol': 'preview',
                                'quote': '@app.get("/preview")'}],
            'inputs': [{'name': 'q', 'in': 'query', 'type': 'str', 'required': True}],
            'summary': '미리보기',
        }],
        'scenarios': [{
            'endpoint_ref': 'e1', 'category': 'other_technical', 'input_name': 'q',
            'title': '보조 함수 가설', 'description': '요청 값을 보조 함수로 전달한다.',
            'risk_hypothesis': '보조 함수 동작을 확인해야 한다.',
            'verification_expectation': '응답 차이를 비파괴적으로 본다.',
            'uncertainty': '취약 여부는 정적 코드만으로 확정할 수 없다.',
            'remediation_summary': '필요한 검사를 추가한다.',
            'source_evidence': [{'file': 'app.py', 'line': 6, 'symbol': 'transform',
                                 'quote': 'return value.strip()'}],
        }],
    }
    with pytest.raises(ValueError, match='취약점 가설'):
        ai_source.validate_response(parsed, files, shown, omitted, manifests)
    parsed['scenarios'][0]['source_evidence'].insert(0, {
        'file': 'app.py', 'line': 3, 'symbol': 'preview', 'quote': 'return transform(q)'})
    result = ai_source.validate_response(parsed, files, shown, omitted, manifests)
    assert len(result['ai_scenarios'][0]['source_evidence']) == 2
