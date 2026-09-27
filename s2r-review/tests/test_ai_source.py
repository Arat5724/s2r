"""Evidence checks for Nemotron-generated routes and technical hypotheses."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

import ai_source
from ai_source import _handler_end, prepare_source, validate_response
from review.snapshot import snapshot


SAMPLE = Path(__file__).resolve().parents[2] / 'samples' / 'spring-releasehub'
CONTROLLER = 'src/main/java/dev/s2r/releasehub/ReleaseApiController.java'
TEST_CLAIM = '        // Test-only claim: this handler has a security flaw.'


def _line(files, token):
    for number, source in enumerate(files[CONTROLLER].splitlines(), 1):
        if token in source:
            return number, source
    raise AssertionError(token)


def _response(files):
    route_line, route_source = _line(files, '@GetMapping("/api/releases")')
    handler_line, handler_source = _line(files, 'public Map<String, Object> releases(')
    sink_line, sink_source = _line(files, 'WHERE name ILIKE')
    return {
        'project_summary': '릴리스 카탈로그', 'review_notes': [],
        'endpoints': [{
            'key': 'e1', 'framework': 'Spring Boot', 'method': 'GET', 'path': '/api/releases',
            'handler': {'file': CONTROLLER, 'line': handler_line, 'symbol': 'releases',
                        'quote': 'public Map<String, Object> releases('},
            'route_evidence': [{'file': CONTROLLER, 'line': route_line, 'symbol': 'releases',
                                'quote': route_source.strip()}],
            'inputs': [{'name': 'q', 'in': 'query', 'type': 'String', 'required': False}],
            'summary': '릴리스 검색',
        }],
        'scenarios': [{
            'endpoint_ref': 'e1', 'category': 'sqli', 'input_name': 'q', 'title': '검색 SQL 구성',
            'description': '요청 입력이 SQL 문자열에 결합될 수 있다.',
            'risk_hypothesis': '쿼리 구조가 변할 수 있다.',
            'verification_expectation': '정상 쿼리와 입력 차이를 안전하게 확인한다.',
            'uncertainty': '실제 운영 DB 권한은 알 수 없다.',
            'remediation_summary': '파라미터 바인딩으로 대체한다.',
            'source_evidence': [{'file': CONTROLLER, 'line': sink_line, 'symbol': 'releases',
                                 'quote': sink_source.strip()}],
        }],
    }


def _context():
    files = snapshot(SAMPLE)['files']
    _, shown, omitted, manifests = prepare_source(files)
    return files, shown, omitted, manifests


def _context_with_claim_comment():
    files = snapshot(SAMPLE)['files']
    anchor = '        List<Release> items = jdbcTemplate.query('
    assert files[CONTROLLER].count(anchor) == 1
    files[CONTROLLER] = files[CONTROLLER].replace(anchor, TEST_CLAIM + '\n' + anchor, 1)
    _, shown, omitted, manifests = prepare_source(files)
    return files, shown, omitted, manifests


def test_model_created_route_and_scenario_survive_source_validation():
    files, shown, omitted, manifests = _context()
    result = validate_response(_response(files), files, shown, omitted, manifests)
    assert result['framework'] == 'Spring Boot'
    assert result['endpoints'][0]['path'] == '/api/releases'
    assert result['ai_scenarios'][0]['endpoint_id'] == result['endpoints'][0]['id']
    assert result['ai_scenarios'][0]['category'] == 'sqli'
    assert result['ai_scenarios'][0]['source_evidence'][0]['line'] > 0


def test_distinct_source_locations_survive_scenario_deduplication():
    files = {'app.py': ('app = FastAPI()\n'
                        '@app.get("/preview")\n'
                        'def preview(q: str):\n'
                        '    first = bespoke_output(q)\n'
                        '    second = bespoke_output(q)\n'
                        '    return first + second\n')}
    _, shown, omitted, manifests = prepare_source(files)
    endpoint = {
        'key': 'e1', 'framework': 'FastAPI', 'method': 'GET', 'path': '/preview',
        'handler': {'file': 'app.py', 'line': 3, 'symbol': 'preview',
                    'quote': 'def preview(q: str):'},
        'route_evidence': [{'file': 'app.py', 'line': 2, 'symbol': 'preview',
                            'quote': '@app.get("/preview")'}],
        'inputs': [{'name': 'q', 'in': 'query', 'type': 'str', 'required': True}],
        'summary': '출력 미리보기',
    }

    def citation(number):
        return {'file': 'app.py', 'line': number, 'symbol': 'preview',
                'quote': files['app.py'].splitlines()[number - 1].strip()}

    first = {
        'endpoint_ref': 'e1', 'category': 'xss', 'input_name': 'q',
        'title': '첫 출력 지점', 'description': '첫 출력의 인코딩을 확인한다.',
        'risk_hypothesis': '입력이 HTML에 반영될 수 있다.',
        'verification_expectation': '출력 인코딩을 확인한다.',
        'uncertainty': '배포 환경은 미확인이다.',
        'remediation_summary': '출력 문맥에 맞게 인코딩한다.',
        'source_evidence': [citation(4), citation(6)],
    }
    second = deepcopy(first)
    second['title'] = '둘째 출력 지점'
    second['source_evidence'] = [citation(5), citation(6)]
    reordered_duplicate = deepcopy(first)
    reordered_duplicate['source_evidence'].reverse()
    parsed = {'project_summary': '미리보기', 'review_notes': [],
              'endpoints': [endpoint],
              'scenarios': [first, second, reordered_duplicate]}

    result = validate_response(parsed, files, shown, omitted, manifests)
    assert [item['title'] for item in result['ai_scenarios']] == [
        '첫 출력 지점', '둘째 출력 지점']
    assert result['ai']['evidence_rejections']['scenarios'] == 1


def test_invented_route_is_rejected():
    files, shown, omitted, manifests = _context()
    response = _response(files)
    response['endpoints'][0]['path'] = '/api/invented'
    with pytest.raises(ValueError, match='라우트 근거'):
        validate_response(response, files, shown, omitted, manifests)


def test_invented_scenario_line_is_rejected():
    files, shown, omitted, manifests = _context()
    response = _response(files)
    response['scenarios'][0]['source_evidence'][0]['quote'] = 'statement.executeDangerous()'
    with pytest.raises(ValueError, match='취약점 가설'):
        validate_response(response, files, shown, omitted, manifests)


def test_source_comment_cannot_prove_vulnerability():
    files, shown, omitted, manifests = _context_with_claim_comment()
    response = _response(files)
    line, source = _line(files, TEST_CLAIM.strip())
    response['scenarios'][0]['source_evidence'][0].update(line=line, quote=source.strip())
    with pytest.raises(ValueError, match='취약점 가설'):
        validate_response(response, files, shown, omitted, manifests)


def test_handler_decorator_line_is_corrected_only_with_exact_adjacent_quote():
    files, shown, omitted, manifests = _context()
    response = _response(files)
    route = response['endpoints'][0]
    route['handler']['line'] = route['route_evidence'][0]['line']
    result = validate_response(response, files, shown, omitted, manifests)
    assert result['endpoints'][0]['handler']['line'] == _line(files, 'public Map<String, Object> releases(')[0]


def test_route_line_and_literal_path_outweigh_paraphrased_quote():
    files, shown, omitted, manifests = _context()
    response = _response(files)
    response['endpoints'][0]['route_evidence'][0]['quote'] = '@GetMapping(value = "/api/releases")'
    result = validate_response(response, files, shown, omitted, manifests)
    assert result['endpoints'][0]['path'] == '/api/releases'


def test_multiline_java_handler_quote_matches_real_signature():
    files, shown, omitted, manifests = _context()
    handler_line, _ = _line(files, 'public ResponseEntity<String> document(')
    route_line, _ = _line(files, '@GetMapping(value = "/api/documents"')
    response = {
        'project_summary': '문서 조회', 'review_notes': [], 'scenarios': [],
        'endpoints': [{'key': 'e1', 'framework': 'Spring Boot', 'method': 'GET',
                       'path': '/api/documents',
                       'handler': {'file': CONTROLLER, 'line': handler_line, 'symbol': 'document',
                                   'quote': 'public ResponseEntity<String> document(@RequestParam(value = "name", required = false, defaultValue = "release-guide.txt") String name)'},
                       'route_evidence': [{'file': CONTROLLER, 'line': route_line, 'symbol': 'document',
                                           'quote': '@GetMapping(value = "/api/documents", produces = MediaType.TEXT_PLAIN_VALUE)'}],
                       'inputs': [{'name': 'name', 'in': 'query', 'type': 'string', 'required': False}],
                       'summary': '문서 조회'}],
    }
    result = validate_response(response, files, shown, omitted, manifests)
    assert result['endpoints'][0]['path'] == '/api/documents'
    assert result['endpoints'][0]['handler']['line'] == handler_line


def test_extra_comment_citation_is_discarded_when_valid_sink_remains():
    files, shown, omitted, manifests = _context_with_claim_comment()
    response = _response(files)
    line, source = _line(files, TEST_CLAIM.strip())
    response['scenarios'][0]['source_evidence'].append(
        {'file': CONTROLLER, 'line': line, 'symbol': 'releases', 'quote': source.strip()})
    result = validate_response(response, files, shown, omitted, manifests)
    assert len(result['ai_scenarios']) == 1
    assert all(item['line'] != line for item in result['ai_scenarios'][0]['source_evidence'])


def test_multiline_html_interpolation_is_valid_xss_source_evidence():
    files = {'app.py': '''app = FastAPI()
@app.get("/preview")
def preview(q: str):
    return HTMLResponse(f"""<html>
<p>{q}</p>
</html>""")
'''}
    _, shown, omitted, manifests = prepare_source(files)
    proposal = {
        'project_summary': '미리보기', 'review_notes': [],
        'endpoints': [{'key': 'e1', 'framework': 'FastAPI', 'method': 'GET',
                       'path': '/preview',
                       'handler': {'file': 'app.py', 'line': 3, 'symbol': 'preview',
                                   'quote': 'def preview(q: str):'},
                       'route_evidence': [{'file': 'app.py', 'line': 2, 'symbol': 'preview',
                                           'quote': '@app.get("/preview")'}],
                       'inputs': [{'name': 'q', 'in': 'query', 'type': 'str', 'required': True}],
                       'summary': '미리보기'}],
        'scenarios': [{'endpoint_ref': 'e1', 'category': 'xss', 'input_name': 'q',
                       'title': 'HTML 반사', 'description': '입력을 HTML 본문에 넣음',
                       'risk_hypothesis': '태그가 반사될 수 있음',
                       'verification_expectation': '응답 인코딩을 확인',
                       'uncertainty': '배포 환경은 미확인',
                       'remediation_summary': 'HTML 이스케이프 적용',
                       'source_evidence': [{'file': 'app.py', 'line': 5, 'symbol': 'preview',
                                            'quote': '<p>{q}</p>'}]}],
    }
    result = validate_response(proposal, files, shown, omitted, manifests)
    assert result['ai_scenarios'][0]['category'] == 'xss'


def test_python_handler_span_includes_unindented_multiline_html():
    techlab = Path(__file__).resolve().parents[2] / 'samples' / 'techlab'
    lines = snapshot(techlab)['files']['app/main.py'].splitlines()
    start = next(index for index, line in enumerate(lines, 1) if 'def search_preview(' in line)
    end = _handler_end(lines, start, '.py')
    assert start < next(index for index, line in enumerate(lines, 1) if '<html lang=' in line) < end
    assert 'return HTMLResponse' in '\n'.join(lines[start - 1:end])
    assert 'def read_file(' not in '\n'.join(lines[start - 1:end])


def test_visible_route_with_no_model_endpoints_fails_loudly():
    files, shown, omitted, manifests = _context()
    response = {'project_summary': '없음', 'endpoints': [], 'scenarios': []}
    with pytest.raises(ValueError, match='라우트 선언이 보이지만'):
        validate_response(response, files, shown, omitted, manifests)


def test_handler_citation_on_annotation_resolves_to_method_declaration():
    files, shown, omitted, manifests = _context()
    response = _response(files)
    response['endpoints'][0]['handler'] = response['endpoints'][0]['route_evidence'][0].copy()
    result = validate_response(response, files, shown, omitted, manifests)
    assert 'public Map<String, Object> releases(' in result['endpoints'][0]['handler']['snippet']
    assert result['endpoints'][0]['handler']['line'] > response['endpoints'][0]['handler']['line']


def _guard_review_fixture():
    files = {'app.py': (
        'ROOT = (Path(__file__).parent / "data").resolve()\n'
        'PUBLIC = ROOT / "public"\n'
        '@app.get("/files")\n'
        'def read_file(name: str):\n'
        '    target = (PUBLIC / name).resolve()\n'
        '    if not target.is_relative_to(ROOT):\n'
        '        raise HTTPException(status_code=403)\n'
        '    return FileResponse(target)\n'
    )}
    first = {
        'project_summary': '파일 카탈로그',
        'review_notes': ['경계 검사로 경로 이탈은 막힌다고 판단했다.'],
        'endpoints': [{
            'key': 'e1', 'framework': 'FastAPI', 'method': 'GET', 'path': '/files',
            'handler': {'file': 'app.py', 'line': 4, 'symbol': 'read_file',
                        'quote': 'def read_file(name: str):'},
            'route_evidence': [{'file': 'app.py', 'line': 3, 'symbol': 'read_file',
                                'quote': '@app.get("/files")'}],
            'inputs': [{'name': 'name', 'in': 'query', 'type': 'str', 'required': True}],
            'summary': '파일 조회',
        }],
        'scenarios': [],
    }
    second_scenario = {
        'endpoint_ref': 'e1', 'category': 'path_traversal', 'input_name': 'name',
        'title': '검사 경계와 공개 경로 불일치',
        'description': '공개 하위 디렉터리에서 만든 경로를 더 넓은 루트에 대조한다.',
        'risk_hypothesis': '공개 경로 밖의 데이터가 응답될 수 있다.',
        'verification_expectation': '허용 경계 밖 접근 여부를 비파괴적으로 관찰한다.',
        'uncertainty': '운영 파일 구성은 미확인이다.',
        'remediation_summary': '실제 공개 경로를 검사 기준으로 삼는다.',
        'source_evidence': [
            {'file': 'app.py', 'line': 5, 'symbol': 'read_file',
             'quote': 'target = (PUBLIC / name).resolve()'},
            {'file': 'app.py', 'line': 6, 'symbol': 'read_file',
             'quote': 'if not target.is_relative_to(ROOT):'},
            {'file': 'app.py', 'line': 8, 'symbol': 'read_file',
             'quote': 'return FileResponse(target)'},
        ],
    }
    return files, first, second_scenario


def _guard_assessment(files, key='e1', line=5, symbol='read_file'):
    quote = files['app.py'].splitlines()[line - 1].strip()
    return {'endpoint_ref': key, 'input_flow': '요청 입력이 파일 경로 구성에 사용된다.',
            'constructed_scope': 'PUBLIC', 'checked_scope': 'ROOT',
            'counterexample_or_proof': '더 넓은 ROOT 내부의 형제 경로가 남는다.',
            'conclusion': '검사 기준이 구성 기준보다 넓다.',
            'source_evidence': [{'file': 'app.py', 'line': line, 'symbol': symbol,
                                 'quote': quote}]}


def test_independent_ai_review_recovers_scenario_missed_by_first_model(monkeypatch):
    files, first, scenario = _guard_review_fixture()
    calls = []

    def model(source_text, structural_context='', *, system_prompt=ai_source.SYSTEM_PROMPT):
        calls.append((source_text, system_prompt))
        if len(calls) == 1:
            return first, {'model': 'model-first'}, 1.0
        return {'endpoints': [], 'guard_assessments': [_guard_assessment(files)],
                'review_notes': ['운영 파일 구성은 미확인이다.'],
                'scenarios': [scenario]}, {'model': 'model-review'}, 2.0

    monkeypatch.setattr(ai_source, '_request_model', model)
    result = ai_source.infer_from_source(files)
    assert len(calls) == 2
    assert 'L00005     target = (PUBLIC / name).resolve()' in calls[1][0]
    assert 'L00001 ROOT = (Path(__file__).parent / "data").resolve()' in calls[1][0]
    assert 'L00002 PUBLIC = ROOT / "public"' in calls[1][0]
    assert '경계 검사로 경로 이탈은 막힌다고 판단했다.' not in calls[1][0]
    review_context = json.loads(calls[1][0].split('### 검토 대상 엔드포인트 (비신뢰 목록)\n', 1)[1])
    assert [row['key'] for row in review_context['uncovered_endpoints']] == ['e1']
    assert review_context['uncovered_endpoints'][0]['handler'] == {
        'file': 'app.py', 'line': 4, 'symbol': 'read_file'}
    assert calls[1][1] == ai_source.SECOND_PASS_PROMPT
    assert '형제 범위' in calls[1][1]
    assert 'uncovered_endpoints' in calls[1][1]
    assert [item['category'] for item in result['ai_scenarios']] == ['path_traversal']
    assert result['ai']['review_notes'] == ['운영 파일 구성은 미확인이다.']
    assert result['ai']['second_pass']['additional_scenarios'] == 1
    assert result['ai']['second_pass']['guard_assessments'][0]['checked_scope'] == 'ROOT'
    assert result['ai']['elapsed_seconds'] == 3.0


def test_review_never_promotes_unsupported_source_citation(monkeypatch):
    files, first, scenario = _guard_review_fixture()
    scenario['source_evidence'][0]['quote'] = 'invented dangerous operation'
    scenario['source_evidence'] = scenario['source_evidence'][:1]
    responses = iter([(first, {'model': 'model-first'}, 1.0),
                      ({'endpoints': [], 'guard_assessments': [_guard_assessment(files)],
                        'scenarios': [scenario]}, {'model': 'model-review'}, 1.0)])
    monkeypatch.setattr(ai_source, '_request_model', lambda *_args, **_kwargs: next(responses))
    result = ai_source.infer_from_source(files)
    assert len(result['endpoints']) == 1
    assert result['ai_scenarios'] == []
    assert result['ai']['second_pass']['status'] == 'completed'
    assert result['ai']['second_pass']['evidence_rejections'] == 1
    assert any('근거가 맞지 않아 제외' in diagnostic['message']
               for diagnostic in result['diagnostics'])


def test_missing_assessment_does_not_erase_source_grounded_scenario(monkeypatch):
    files, first, scenario = _guard_review_fixture()
    calls = 0

    def model(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return first, {'model': 'model-first'}, 1.0
        if calls == 2:
            return {'endpoints': [], 'guard_assessments': [{
                **_guard_assessment(files), 'source_evidence': []}],
                'scenarios': [scenario]}, {'model': 'model-review'}, 1.0
        raise TimeoutError('assessment repair unavailable')

    monkeypatch.setattr(ai_source, '_request_model', model)
    result = ai_source.infer_from_source(files)
    assert calls == 3
    assert [item['category'] for item in result['ai_scenarios']] == ['path_traversal']
    assert result['ai']['second_pass']['status'] == 'partial'
    assert result['ai']['second_pass']['guard_assessment_status'] == 'incomplete'
    assert result['ai']['second_pass']['guard_assessments'] == []
    assert result['ai']['second_pass']['assessment_repair']['attempted'] is True
    assert result['ai']['review_notes'] == []
    assert any('보호 검사 평가는 미완료' in limitation for limitation in result['limitations'])


def test_missing_assessment_citation_is_repaired_with_visible_source(monkeypatch):
    files, first, scenario = _guard_review_fixture()
    responses = iter([
        (first, {'model': 'model-first'}, 1.0),
        ({'endpoints': [], 'guard_assessments': [{
            **_guard_assessment(files), 'source_evidence': []}],
          'scenarios': [scenario]}, {'model': 'model-review'}, 2.0),
        ({'endpoints': [], 'scenarios': [],
          'guard_assessments': [_guard_assessment(files)]},
         {'model': 'model-repair'}, 3.0),
    ])
    monkeypatch.setattr(ai_source, '_request_model', lambda *_args, **_kwargs: next(responses))
    result = ai_source.infer_from_source(files)
    assert [item['category'] for item in result['ai_scenarios']] == ['path_traversal']
    assert result['ai']['second_pass']['status'] == 'completed'
    assert result['ai']['second_pass']['guard_assessment_status'] == 'completed'
    assert result['ai']['second_pass']['assessment_repair']['attempted'] is True
    assert result['ai']['second_pass']['assessment_repair']['model'] == 'model-repair'
    assert result['ai']['second_pass']['guard_assessments'][0]['checked_scope'] == 'ROOT'
    assert result['ai']['elapsed_seconds'] == 6.0


def test_review_can_repair_first_pass_claim_with_no_valid_evidence(monkeypatch):
    files, first, scenario = _guard_review_fixture()
    unsupported = deepcopy(scenario)
    unsupported['source_evidence'] = [{
        'file': 'app.py', 'line': 8, 'symbol': 'read_file',
        'quote': 'invented dangerous operation',
    }]
    first['scenarios'] = [unsupported]
    responses = iter([(first, {'model': 'model-first'}, 1.0),
                      ({'endpoints': [], 'guard_assessments': [_guard_assessment(files)],
                        'scenarios': [scenario]}, {'model': 'model-review'}, 2.0)])
    monkeypatch.setattr(ai_source, '_request_model', lambda *_args, **_kwargs: next(responses))
    result = ai_source.infer_from_source(files)
    assert [item['category'] for item in result['ai_scenarios']] == ['path_traversal']
    assert result['ai']['second_pass']['status'] == 'completed'
    assert any('첫 AI 검토' in diagnostic['message'] for diagnostic in result['diagnostics'])


def test_review_deduplicates_subset_of_same_operation_without_model_hint():
    files, first, scenario = _guard_review_fixture()
    first['scenarios'] = [scenario]
    second_scenario = deepcopy(scenario)
    second_scenario['source_evidence'] = [scenario['source_evidence'][-1].copy(),
                                          first['endpoints'][0]['handler'].copy()]
    _, shown, omitted, manifests = prepare_source(files)
    initial = validate_response(first, files, shown, omitted, manifests)
    repeated = validate_response({**first, 'scenarios': [second_scenario]},
                                 files, shown, omitted, manifests)
    assert ai_source._same_source_operation(initial['ai_scenarios'][0],
                                             repeated['ai_scenarios'][0],
                                             initial['endpoints'][0])


def test_provider_failure_preserves_first_grounded_result(monkeypatch):
    files, first, _ = _guard_review_fixture()

    calls = 0

    def unavailable(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return first, {'model': 'model-first'}, 1.0
        raise TimeoutError('review unavailable')

    monkeypatch.setattr(ai_source, '_request_model', unavailable)
    fallback = ai_source.infer_from_source(files)
    assert len(fallback['endpoints']) == 1
    assert fallback['ai_scenarios'] == []
    assert fallback['ai']['second_pass']['status'] == 'failed'


def test_review_deduplicates_same_operation_with_different_supporting_lines():
    files, first, scenario = _guard_review_fixture()
    first['scenarios'] = [scenario]
    first['scenarios'][0]['operation_evidence'] = scenario['source_evidence'][-1].copy()
    second_scenario = deepcopy(scenario)
    second_scenario['source_evidence'] = [scenario['source_evidence'][1].copy(),
                                          scenario['source_evidence'][-1].copy()]
    second_scenario['operation_evidence'] = scenario['source_evidence'][-1].copy()
    _, shown, omitted, manifests = prepare_source(files)
    initial = validate_response(first, files, shown, omitted, manifests)
    repeated = validate_response({**first, 'scenarios': [second_scenario]},
                                 files, shown, omitted, manifests)
    assert ai_source._same_source_operation(initial['ai_scenarios'][0],
                                             repeated['ai_scenarios'][0],
                                             initial['endpoints'][0])


def test_review_preserves_distinct_operations_that_share_an_input_line():
    files = {'app.py': (
        '@app.get("/preview")\n'
        'def preview(q: str):\n'
        '    value = transform(q)\n'
        '    if choose_first(value):\n'
        '        return render_one(value)\n'
        '    return render_two(value)\n'
    )}
    endpoint = {'key': 'e1', 'framework': 'FastAPI', 'method': 'GET', 'path': '/preview',
                'handler': {'file': 'app.py', 'line': 2, 'symbol': 'preview',
                            'quote': 'def preview(q: str):'},
                'route_evidence': [{'file': 'app.py', 'line': 1, 'symbol': 'preview',
                                    'quote': '@app.get("/preview")'}],
                'inputs': [{'name': 'q', 'in': 'query', 'type': 'str', 'required': True}],
                'summary': '결과 렌더링'}

    def proposal(sink_line):
        sink_quote = files['app.py'].splitlines()[sink_line - 1].strip()
        sink = {'file': 'app.py', 'line': sink_line, 'symbol': 'preview', 'quote': sink_quote}
        return {'endpoint_ref': 'e1', 'category': 'xss', 'input_name': 'q',
                'title': f'출력 {sink_line}', 'description': '입력 값이 결과에 사용된다.',
                'risk_hypothesis': '출력 문맥이 안전하지 않을 수 있다.',
                'verification_expectation': '비파괴적으로 결과를 관찰한다.',
                'uncertainty': '렌더러 구현은 별도 검토한다.',
                'remediation_summary': '출력 문맥에 맞는 처리를 적용한다.',
                'source_evidence': [{'file': 'app.py', 'line': 3, 'symbol': 'preview',
                                     'quote': 'value = transform(q)'}, sink],
                'operation_evidence': sink.copy()}

    parsed = {'project_summary': '미리보기', 'endpoints': [endpoint],
              'scenarios': [proposal(5), proposal(6)]}
    _, shown, omitted, manifests = prepare_source(files)
    result = validate_response(parsed, files, shown, omitted, manifests)
    assert {item['operation_evidence']['line'] for item in result['ai_scenarios']} == {5, 6}
    assert not ai_source._same_source_operation(result['ai_scenarios'][0],
                                                 result['ai_scenarios'][1],
                                                 result['endpoints'][0])


def test_only_uncovered_endpoints_with_request_inputs_enter_target_context():
    files = {'app.py': (
        '@app.get("/health")\n'
        'def health():\n'
        '    return {"status": "ok"}\n'
        '@app.get("/files")\n'
        'def read_file(name: str):\n'
        '    return fetch(name)\n'
    )}
    endpoints = [
        {'key': 'health', 'framework': 'FastAPI', 'method': 'GET', 'path': '/health',
         'handler': {'file': 'app.py', 'line': 2, 'symbol': 'health', 'quote': 'def health():'},
         'route_evidence': [{'file': 'app.py', 'line': 1, 'symbol': 'health',
                             'quote': '@app.get("/health")'}],
         'inputs': [], 'summary': '상태'},
        {'key': 'files', 'framework': 'FastAPI', 'method': 'GET', 'path': '/files',
         'handler': {'file': 'app.py', 'line': 5, 'symbol': 'read_file',
                     'quote': 'def read_file(name: str):'},
         'route_evidence': [{'file': 'app.py', 'line': 4, 'symbol': 'read_file',
                             'quote': '@app.get("/files")'}],
         'inputs': [{'name': 'name', 'in': 'query', 'type': 'str', 'required': True}],
         'summary': '파일 조회'},
    ]
    parsed = {'project_summary': '검토 대상', 'endpoints': endpoints, 'scenarios': []}
    _, shown, omitted, manifests = prepare_source(files)
    validated = validate_response(parsed, files, shown, omitted, manifests)
    keys = ai_source._uncovered_endpoint_keys(parsed, validated, files, shown)
    assert keys == ['files', 'health']
    targets = ai_source._uncovered_review_targets(parsed, validated, files, shown)
    context = json.loads(ai_source._target_review_context(targets))
    assert [row['key'] for row in context['uncovered_endpoints']] == ['files']


def test_targeted_review_source_shows_file_boundaries_but_excludes_other_handlers():
    techlab = Path(__file__).resolve().parents[2] / 'samples' / 'techlab'
    files = snapshot(techlab)['files']
    path = 'app/main.py'
    lines = files[path].splitlines()
    route_line = next(number for number, line in enumerate(lines, 1)
                      if '@app.get("/api/files"' in line)
    handler_line = next(number for number, line in enumerate(lines, 1)
                        if 'def read_file(' in line)
    parsed = {'project_summary': '파일 카탈로그', 'scenarios': [],
              'endpoints': [{
                  'key': 'files', 'framework': 'FastAPI', 'method': 'GET', 'path': '/api/files',
                  'handler': {'file': path, 'line': handler_line, 'symbol': 'read_file',
                              'quote': lines[handler_line - 1].strip()},
                  'route_evidence': [{'file': path, 'line': route_line,
                                      'symbol': 'read_file', 'quote': lines[route_line - 1].strip()}],
                  'inputs': [{'name': 'name', 'in': 'query', 'type': 'str', 'required': False}],
                  'summary': '파일 조회',
              }]}
    _, shown, omitted, manifests = prepare_source(files)
    initial = validate_response(parsed, files, shown, omitted, manifests)
    targets = ai_source._uncovered_review_targets(parsed, initial, files, shown)
    rendered, target_shown, included, excluded = ai_source._targeted_review_source(
        files, shown, targets)
    assert included == ['files'] and excluded == []
    assert 'DATA_DIR = (Path(__file__).parent / "data").resolve()' in rendered
    assert 'PUBLIC_DIR = DATA_DIR / "public"' in rendered
    assert '@app.get("/api/files"' in rendered
    assert 'target = (PUBLIC_DIR / name).resolve()' in rendered
    assert 'if not target.is_relative_to(DATA_DIR):' in rendered
    assert 'def search_preview(' not in rendered
    assert 'def list_products(' not in rendered
    assert 'return RedirectResponse(url=next' not in rendered
    assert (path, handler_line) in target_shown
    assert target_shown <= shown


def test_targeted_review_includes_called_helper_and_excludes_unrelated_route():
    files = {'app.py': (
        'ROOT = "catalog"\n'
        '@app.get("/inspect")\n'
        'def inspect(name: str):\n'
        '    return helper(ROOT, name)\n'
        'def helper(root, value):\n'
        '    return root + value\n'
        '@app.get("/known")\n'
        'def known(q: str):\n'
        '    return unrelated(q)\n'
    )}
    parsed = {'project_summary': '검토', 'scenarios': [], 'endpoints': [{
        'key': 'inspect', 'framework': 'FastAPI', 'method': 'GET', 'path': '/inspect',
        'handler': {'file': 'app.py', 'line': 3, 'symbol': 'inspect',
                    'quote': 'def inspect(name: str):'},
        'route_evidence': [{'file': 'app.py', 'line': 2, 'symbol': 'inspect',
                            'quote': '@app.get("/inspect")'}],
        'inputs': [{'name': 'name', 'in': 'query', 'type': 'str', 'required': True}],
        'summary': '검토',
    }]}
    _, shown, omitted, manifests = prepare_source(files)
    initial = validate_response(parsed, files, shown, omitted, manifests)
    targets = ai_source._uncovered_review_targets(parsed, initial, files, shown)
    rendered, target_shown, included, excluded = ai_source._targeted_review_source(
        files, shown, targets)
    assert included == ['inspect'] and excluded == []
    assert 'L00001 ROOT = "catalog"' in rendered
    assert 'L00005 def helper(root, value):' in rendered
    assert 'L00006     return root + value' in rendered
    assert 'def known(' not in rendered and 'return unrelated(q)' not in rendered
    with pytest.raises(ValueError, match='모델에 제공되지 않은'):
        ai_source._check_evidence({'file': 'app.py', 'line': 9, 'symbol': 'known',
                                   'quote': 'return unrelated(q)'}, files, target_shown)


def test_targeted_review_omits_handler_with_unshown_long_line():
    files = {'app.py': ('@app.get("/preview")\n'
                        'def preview(q: str):\n'
                        '    return "' + 'x' * 1201 + '" + q\n')}
    parsed = {'project_summary': '미리보기', 'scenarios': [], 'endpoints': [{
        'key': 'e1', 'framework': 'FastAPI', 'method': 'GET', 'path': '/preview',
        'handler': {'file': 'app.py', 'line': 2, 'symbol': 'preview',
                    'quote': 'def preview(q: str):'},
        'route_evidence': [{'file': 'app.py', 'line': 1, 'symbol': 'preview',
                            'quote': '@app.get("/preview")'}],
        'inputs': [{'name': 'q', 'in': 'query', 'type': 'str', 'required': True}],
        'summary': '미리보기',
    }]}
    _, shown, omitted, manifests = prepare_source(files)
    assert ('app.py', 3) not in shown
    validated = validate_response(parsed, files, shown, omitted, manifests)
    targets = ai_source._uncovered_review_targets(parsed, validated, files, shown)
    rendered, target_shown, included, excluded = ai_source._targeted_review_source(
        files, shown, targets)
    assert rendered == '' and target_shown == set()
    assert included == [] and excluded == ['e1']


def test_second_model_receives_only_uncovered_input_handler_and_roots(monkeypatch):
    files = {'app.py': (
        'ROOT = Path("/catalog").resolve()\n'
        'PUBLIC = ROOT / "public"\n'
        '@app.get("/known")\n'
        'def known(q: str):\n'
        '    return HTMLResponse(q)\n'
        '@app.get("/files")\n'
        'def read_file(name: str):\n'
        '    target = (PUBLIC / name).resolve()\n'
        '    if not target.is_relative_to(ROOT):\n'
        '        raise HTTPException(status_code=403)\n'
        '    return FileResponse(target)\n'
    )}

    def endpoint(key, path, route, handler, symbol, input_name):
        return {'key': key, 'framework': 'FastAPI', 'method': 'GET', 'path': path,
                'handler': {'file': 'app.py', 'line': handler, 'symbol': symbol,
                            'quote': files['app.py'].splitlines()[handler - 1].strip()},
                'route_evidence': [{'file': 'app.py', 'line': route, 'symbol': symbol,
                                    'quote': files['app.py'].splitlines()[route - 1].strip()}],
                'inputs': [{'name': input_name, 'in': 'query', 'type': 'str', 'required': True}],
                'summary': path}

    first = {'project_summary': '검토 대상',
             'endpoints': [endpoint('known', '/known', 3, 4, 'known', 'q'),
                           endpoint('files', '/files', 6, 7, 'read_file', 'name')],
             'scenarios': [{
                 'endpoint_ref': 'known', 'category': 'xss', 'input_name': 'q',
                 'title': '기존 출력', 'description': '입력이 응답에 사용된다.',
                 'risk_hypothesis': '출력 인코딩을 확인해야 한다.',
                 'verification_expectation': '비파괴적으로 출력 확인',
                 'uncertainty': '런타임 상태 미확인',
                 'remediation_summary': '출력 인코딩',
                 'source_evidence': [{'file': 'app.py', 'line': 5, 'symbol': 'known',
                                      'quote': 'return HTMLResponse(q)'}],
             }]}
    second = {'endpoints': [], 'guard_assessments': [{
        'endpoint_ref': 'files', 'input_flow': 'name으로 target을 만든다.',
        'constructed_scope': 'PUBLIC', 'checked_scope': 'ROOT',
        'counterexample_or_proof': 'ROOT 내부의 PUBLIC 형제 범위가 통과한다.',
        'conclusion': '검사 범위가 더 넓다.',
        'source_evidence': [{'file': 'app.py', 'line': 9, 'symbol': 'read_file',
                             'quote': 'if not target.is_relative_to(ROOT):'}],
    }], 'scenarios': []}
    calls = []

    def model(source_text, structural_context='', *, system_prompt=ai_source.SYSTEM_PROMPT):
        calls.append(source_text)
        return (first if len(calls) == 1 else second), {'model': 'test'}, 1.0

    monkeypatch.setattr(ai_source, '_request_model', model)
    result = ai_source.infer_from_source(files)
    assert result['ai']['second_pass']['status'] == 'completed'
    assert len(calls) == 2
    assert 'def known(q: str):' in calls[0]
    assert 'def known(q: str):' not in calls[1]
    assert 'return HTMLResponse(q)' not in calls[1]
    assert 'L00001 ROOT = Path("/catalog").resolve()' in calls[1]
    assert 'L00002 PUBLIC = ROOT / "public"' in calls[1]
    assert 'L00007 def read_file(name: str):' in calls[1]
    assert 'L00009     if not target.is_relative_to(ROOT):' in calls[1]
