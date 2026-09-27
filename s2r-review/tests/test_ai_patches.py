"""Model patch content is only a suggestion; snapshot checks create the diff."""

from copy import deepcopy
import json

import pytest

from review.ai_patches import prepare_patch_request, validate_patches
import patch_agent
from patch_agent import validate_input, validate_model_patch


REAL_REQUEST_REVIEW = patch_agent._request_review


SOURCE = 'def transform(raw):\n    return raw\n'
PATH = 'src/service.py'
IDENTIFIER = 'a' * 16
SCENARIO = {
    'id': IDENTIFIER, 'category': 'other_technical', 'title': '입력 처리 검토',
    'description': '입력이 그대로 사용됩니다.', 'risk_hypothesis': '입력 처리가 필요할 수 있습니다.',
    'verification_expectation': '안전한 입력을 관찰합니다.', 'uncertainty': '배포 상태 미확인',
    'remediation': {'summary': '입력 처리 로직을 수정합니다.'},
    'method': 'GET', 'path': '/process',
    'source_evidence': [{'file': PATH, 'line': 1}, {'file': PATH, 'line': 2}],
}


@pytest.fixture(autouse=True)
def independent_review_stub(monkeypatch):
    """Existing proposal tests exercise source gates without model network calls."""
    monkeypatch.setattr(patch_agent, '_request_review',
                        lambda *_args: {'verdict': 'accept', 'reason': '표시된 변경 범위를 검토했습니다.',
                                        'counterexample': ''})


def setup(status='fail'):
    files = {PATH: SOURCE}
    payload = prepare_patch_request([SCENARIO], {IDENTIFIER: {'status': status,
                                    'summary': '테스트 관찰'}}, files)
    assert validate_input(payload)[0][0]['id'] == IDENTIFIER
    return payload, files


def candidate():
    return {'file': PATH, 'reason': '함수의 반환값을 정규화하는 변경 제안입니다.',
            'edits': [{'start_line': 2, 'old_lines': ['    return raw'],
                       'new_lines': ['    return raw.strip()']}]}


def test_arbitrary_model_edit_becomes_exact_reviewable_diff_without_mutating_snapshot():
    payload, files = setup()
    validated = validate_model_patch(candidate(), payload['scenarios'][0], payload['sources'])
    patch = validate_patches({'patches': [validated]}, payload, files)[IDENTIFIER]
    assert patch['applicability'] == 'review_required'
    assert patch['file'] == PATH and patch['start_line'] == 2
    assert '-    return raw' in patch['diff']
    assert '+    return raw.strip()' in patch['diff']
    assert files[PATH] == SOURCE
    assert validated['validation']['syntax'] == 'passed'


def test_generation_uses_model_proposal_for_unrecognized_category(monkeypatch):
    payload, files = setup()
    calls = []

    def fake_model(scenario, sources, feedback=''):
        calls.append((scenario['id'], feedback))
        return candidate()

    monkeypatch.setattr(patch_agent, '_request_model', fake_model)
    generated = patch_agent.generate(payload)
    assert calls == [(IDENTIFIER, '')]
    result = validate_patches(generated, payload, files)[IDENTIFIER]
    assert result['applicability'] == 'review_required'


def test_generation_repairs_inexact_multiline_string_with_bounded_feedback(monkeypatch):
    payload, files = setup()
    invalid = {'file': PATH, 'reason': '한 줄을 바꿉니다.',
               'edits': [{'start_line': 1, 'old_lines': ['def transform(raw):\n   return raw'],
                          'new_lines': ['def transform(raw):\n    return raw.strip()']}]}
    feedbacks = []

    def fake_model(scenario, sources, feedback=''):
        feedbacks.append(feedback)
        return invalid if len(feedbacks) == 1 else candidate()

    monkeypatch.setattr(patch_agent, '_request_model', fake_model)
    generated = patch_agent.generate(payload)
    assert feedbacks == ['', 'AI 변경 전 코드와 원본이 다릅니다']
    assert validate_patches(generated, payload, files)[IDENTIFIER]['applicability'] == 'review_required'


def test_generation_reports_specific_failure_after_bounded_retries(monkeypatch):
    payload, _ = setup()
    invalid = {**candidate(), 'edits': [{'start_line': 2,
               'old_lines': ['    return a secret that is not in the source'],
               'new_lines': ['    return raw.strip()']}]}
    feedbacks = []

    def fake_model(scenario, sources, feedback=''):
        feedbacks.append(feedback)
        return invalid

    monkeypatch.setattr(patch_agent, '_request_model', fake_model)
    result = patch_agent.generate(payload)['patches'][0]
    assert len(feedbacks) == patch_agent.MAX_MODEL_ATTEMPTS
    assert result['file'] is None and result['edits'] == []
    assert 'AI 변경 전 코드와 원본이 다릅니다' in result['reason']
    assert 'a secret' not in result['reason']


def test_retry_instructions_are_system_message_not_untrusted_source_message(monkeypatch):
    payload, _ = setup()
    requests = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, limit):
            return json.dumps({'choices': [{'message': {'content': json.dumps(candidate())}}]}).encode()

    def fake_open(request, timeout, context):
        requests.append(json.loads(request.data))
        return Response()

    monkeypatch.setattr(patch_agent.urllib.request, 'urlopen', fake_open)
    patch_agent._request_model(payload['scenarios'][0], payload['sources'],
                               'AI 변경 전 코드와 원본이 다릅니다')
    messages = requests[0]['messages']
    assert [item['role'] for item in messages] == ['system', 'system', 'user']
    assert 'AI 변경 전 코드와 원본이 다릅니다' in messages[1]['content']
    assert 'AI 변경 전 코드와 원본이 다릅니다' not in messages[2]['content']


def test_review_receives_exact_edits_and_critique_stays_in_user_data(monkeypatch):
    payload, _ = setup()
    requests = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, limit):
            return json.dumps({'choices': [{'message': {'content': json.dumps({
                'verdict': 'revise', 'reason': '변경 후에도 같은 경로가 남습니다.',
                'counterexample': 'UNTRUSTED_CRITIQUE'
            })}}]}).encode()

    def fake_open(request, timeout, context):
        requests.append(json.loads(request.data))
        return Response()

    monkeypatch.setattr(patch_agent.urllib.request, 'urlopen', fake_open)
    monkeypatch.setattr(patch_agent, '_request_review', REAL_REQUEST_REVIEW)
    proposed = validate_model_patch(candidate(), payload['scenarios'][0], payload['sources'])
    review = patch_agent._request_review(payload['scenarios'][0], payload['sources'], proposed)
    assert review['verdict'] == 'revise'
    review_request = requests[-1]
    assert [item['role'] for item in review_request['messages']] == ['system', 'user']
    assert 'return raw.strip()' in review_request['messages'][1]['content']
    revision = {'previous_edits': proposed['edits'], 'review_reason': review['reason'],
                'counterexample': review['counterexample']}
    patch_agent._request_model(payload['scenarios'][0], payload['sources'], review_feedback=revision)
    revision_request = requests[-1]
    assert [item['role'] for item in revision_request['messages']] == ['system', 'system', 'user']
    assert 'UNTRUSTED_CRITIQUE' in revision_request['messages'][2]['content']
    assert all('UNTRUSTED_CRITIQUE' not in item['content']
               for item in revision_request['messages'][:2])


def test_worker_normalizes_multiline_json_string_only_after_exact_source_match():
    payload, files = setup()
    proposed = {'file': PATH, 'reason': '반환값을 변경합니다.',
                'edits': [{'start_line': 1,
                           'old_lines': ['def transform(raw):\n    return raw'],
                           'new_lines': ['def transform(raw):\n    return raw.strip()']}]}
    verified = validate_model_patch(proposed, payload['scenarios'][0], payload['sources'])
    assert verified['edits'] == [{'start_line': 1,
                                  'old_lines': ['def transform(raw):', '    return raw'],
                                  'new_lines': ['def transform(raw):', '    return raw.strip()']}]
    assert validate_patches({'patches': [verified]}, payload, files)[IDENTIFIER]['applicability'] == 'review_required'
    proposed['edits'][0]['old_lines'] = ['def transform(raw):\n   return raw']
    with pytest.raises(ValueError, match='원본이 다릅니다'):
        validate_model_patch(proposed, payload['scenarios'][0], payload['sources'])


def test_worker_aligns_unique_adjacent_exact_line_and_removes_visible_noops():
    source = 'def transform(raw):\n    return raw\n\n'
    files = {PATH: source}
    payload = prepare_patch_request([SCENARIO], {IDENTIFIER: {'status': 'fail'}}, files)
    proposed = {'file': PATH, 'reason': '함수 뒤에 설명을 추가합니다.', 'edits': [
        {'start_line': 2, 'old_lines': ['    return raw'], 'new_lines': ['    return raw']},
        {'start_line': 2, 'old_lines': [''], 'new_lines': ['# reviewed']},
    ]}
    verified = validate_model_patch(proposed, payload['scenarios'][0], payload['sources'])
    assert verified['edits'] == [{'start_line': 3, 'old_lines': [''], 'new_lines': ['# reviewed']}]
    assert validate_patches({'patches': [verified]}, payload, files)[IDENTIFIER]['applicability'] == 'review_required'


def test_worker_rejects_ambiguous_adjacent_alignment():
    source = '\ndef transform(raw):\n\n    return raw\n'
    files = {PATH: source}
    scenario = {**SCENARIO, 'source_evidence': [{'file': PATH, 'line': 2}, {'file': PATH, 'line': 4}]}
    payload = prepare_patch_request([scenario], {IDENTIFIER: {'status': 'fail'}}, files)
    proposed = {'file': PATH, 'reason': '빈 줄 변경을 시도합니다.',
                'edits': [{'start_line': 2, 'old_lines': [''], 'new_lines': ['# reviewed']}]}
    with pytest.raises(ValueError, match='원본이 다릅니다'):
        validate_model_patch(proposed, payload['scenarios'][0], payload['sources'])


@pytest.mark.parametrize('replacement', [
    ['    if raw not in ("north.local", "south.local"):',
     '        return ""', '    return raw'],
    ['    allowed = ("north.local", "south.local")',
     '    if raw not in allowed:', '        return ""', '    return raw'],
])
def test_worker_rejects_new_policy_values_copied_from_unrelated_scope(replacement):
    source = 'KNOWN = ("north.local", "south.local")\n\ndef transform(raw):\n    return raw\n'
    files = {PATH: source}
    scenario = {**SCENARIO, 'source_evidence': [{'file': PATH, 'line': 3},
                                                {'file': PATH, 'line': 4}]}
    payload = prepare_patch_request([scenario], {IDENTIFIER: {'status': 'fail'}}, files)
    proposed = {'file': PATH, 'reason': '새 허용 대상을 적용합니다.',
                'edits': [{'start_line': 4, 'old_lines': ['    return raw'],
                           'new_lines': replacement}]}
    with pytest.raises(ValueError, match='근거 없는 정책 조건값'):
        validate_model_patch(proposed, payload['scenarios'][0], payload['sources'])


def test_worker_accepts_policy_values_already_grounded_in_same_function():
    source = ('def transform(raw):\n'
              '    known = ("north.local", "south.local")\n'
              '    return raw\n')
    files = {PATH: source}
    scenario = {**SCENARIO, 'source_evidence': [{'file': PATH, 'line': 2},
                                                {'file': PATH, 'line': 3}]}
    payload = prepare_patch_request([scenario], {IDENTIFIER: {'status': 'fail'}}, files)
    proposed = {'file': PATH, 'reason': '함수 내부 근거 값을 사용합니다.',
                'edits': [{'start_line': 3, 'old_lines': ['    return raw'],
                           'new_lines': ['    if raw not in ("north.local", "south.local"):',
                                         '        return ""', '    return raw']}]}
    verified = validate_model_patch(proposed, payload['scenarios'][0], payload['sources'])
    assert validate_patches({'patches': [verified]}, payload, files)[IDENTIFIER]['applicability'] == 'review_required'


def test_generation_retries_after_unproven_policy_values(monkeypatch):
    source = 'def transform(raw):\n    return raw\n'
    files = {PATH: source}
    payload = prepare_patch_request([SCENARIO], {IDENTIFIER: {'status': 'fail'}}, files)
    invented = {'file': PATH, 'reason': '새 허용 대상을 가정합니다.',
                'edits': [{'start_line': 2, 'old_lines': ['    return raw'],
                           'new_lines': ['    if raw not in ("alpha", "beta"):',
                                         '        return ""', '    return raw']}]}
    feedbacks = []

    def fake_model(scenario, sources, feedback=''):
        feedbacks.append(feedback)
        return invented if len(feedbacks) == 1 else candidate()

    monkeypatch.setattr(patch_agent, '_request_model', fake_model)
    generated = patch_agent.generate(payload)
    assert feedbacks == ['', 'AI 변경안에 원본 함수의 근거 없는 정책 조건값이 추가되었습니다']
    assert validate_patches(generated, payload, files)[IDENTIFIER]['applicability'] == 'review_required'


def test_independent_review_revises_incomplete_fix_and_rechecks_without_static_pattern(monkeypatch):
    path = 'src/redirect.py'
    source = ('from urllib.parse import urlsplit\n'
              'from fastapi.responses import RedirectResponse\n\n'
              "def go(next='/'):\n"
              '    return RedirectResponse(next)\n')
    scenario = {**SCENARIO, 'category': 'open_redirect', 'path': '/go',
                'source_evidence': [{'file': path, 'line': 4}, {'file': path, 'line': 5}]}
    payload = prepare_patch_request([scenario], {IDENTIFIER: {'status': 'fail'}}, {path: source})
    weak = {'file': path, 'reason': '상대 경로만 허용합니다.', 'edits': [
        {'start_line': 5, 'old_lines': ['    return RedirectResponse(next)'],
         'new_lines': ["    if not next.startswith('/'):", "        next = '/'",
                       '    return RedirectResponse(next)']}]}
    revised = {'file': path, 'reason': 'URL 파서가 보는 외부 호스트도 배제합니다.', 'edits': [
        {'start_line': 5, 'old_lines': ['    return RedirectResponse(next)'],
         'new_lines': ['    target = urlsplit(next)',
                       "    if target.scheme or target.netloc or not next.startswith('/'):",
                       "        next = '/'", '    return RedirectResponse(next)']}]}
    calls, reviews = [], []

    def fake_propose(_scenario, _sources, feedback='', review_feedback=None):
        calls.append((feedback, review_feedback))
        return weak if len(calls) == 1 else revised

    def fake_review(_scenario, _sources, proposal):
        reviews.append(proposal['edits'])
        if len(reviews) == 1:
            return {'verdict': 'revise', 'reason': '접두 문자만으로 최종 URL 해석을 판정할 수 없습니다.',
                    'counterexample': '프로토콜 상대 URL은 슬래시로 시작해도 외부 호스트로 이동합니다.'}
        return {'verdict': 'accept', 'reason': '변경된 파서 판정 경로를 검토했습니다.',
                'counterexample': ''}

    monkeypatch.setattr(patch_agent, '_request_model', fake_propose)
    monkeypatch.setattr(patch_agent, '_request_review', fake_review)
    generated = patch_agent.generate(payload)
    assert len(calls) == len(reviews) == 2
    assert calls[1][1]['counterexample'].startswith('프로토콜 상대 URL')
    assert 'urlsplit(next)' in generated['patches'][0]['edits'][0]['new_lines'][0]
    result = validate_patches(generated, payload, {path: source})[IDENTIFIER]
    assert result['applicability'] == 'review_required'
    assert '+    target = urlsplit(next)' in result['diff']


def test_independent_review_rejection_remains_manual_after_one_revision(monkeypatch):
    payload, files = setup()
    proposed = []
    alternate = {'file': PATH, 'reason': '다른 정규화만 제안합니다.',
                 'edits': [{'start_line': 2, 'old_lines': ['    return raw'],
                            'new_lines': ['    return raw.lower()']}]}

    def fake_propose(*_args, **_kwargs):
        proposed.append(1)
        return candidate() if len(proposed) == 1 else alternate

    monkeypatch.setattr(patch_agent, '_request_model', fake_propose)
    monkeypatch.setattr(patch_agent, '_request_review',
                        lambda *_args: {'verdict': 'revise', 'reason': '같은 위험이 남아 있습니다.',
                                        'counterexample': '변경하지 않은 입력 경로가 남습니다.'})
    result = patch_agent.generate(payload)['patches'][0]
    assert len(proposed) == 2
    assert result['file'] is None and result['edits'] == []
    assert '변경하지 않은 입력 경로' in result['reason']
    assert validate_patches({'patches': [result]}, payload, files)[IDENTIFIER]['diff'] is None


def test_rejected_patch_cannot_be_repeated_as_a_revision(monkeypatch):
    payload, files = setup()
    reviews = []
    monkeypatch.setattr(patch_agent, '_request_model', lambda *_args, **_kwargs: candidate())

    def reject(*_args):
        reviews.append(1)
        return {'verdict': 'revise', 'reason': '기존 변경안의 효과가 부족합니다.',
                'counterexample': '같은 경로가 남습니다.'}

    monkeypatch.setattr(patch_agent, '_request_review', reject)
    result = patch_agent.generate(payload)['patches'][0]
    assert len(reviews) == 1
    assert result['file'] is None and '반복했습니다' in result['reason']
    assert validate_patches({'patches': [result]}, payload, files)[IDENTIFIER]['diff'] is None


@pytest.mark.parametrize('change', [
    {'file': 'private.py'},
    {'edits': [{'start_line': 2, 'old_lines': ['    return something_else'],
                'new_lines': ['    return raw.strip()']}]},
    {'edits': [{'start_line': 2, 'old_lines': ['    return raw'],
                'new_lines': ['    return (']}]},
    {'edits': [{'start_line': 100, 'old_lines': ['    return raw'],
                'new_lines': ['    return raw.strip()']}]},
])
def test_worker_rejects_out_of_scope_stale_or_invalid_proposal(change):
    payload, _ = setup()
    proposed = {**candidate(), **change}
    with pytest.raises(ValueError):
        validate_model_patch(proposed, payload['scenarios'][0], payload['sources'])


def test_host_rejects_model_attestation_or_stale_snapshot():
    payload, files = setup()
    proposed = validate_model_patch(candidate(), payload['scenarios'][0], payload['sources'])
    forged = deepcopy(proposed)
    forged['validation']['updated_sha256'] = '0' * 64
    assert validate_patches({'patches': [forged]}, payload, files)[IDENTIFIER]['diff'] is None
    stale = {PATH: SOURCE.replace('return raw', 'return raw + "x"')}
    assert validate_patches({'patches': [proposed]}, payload, stale)[IDENTIFIER]['diff'] is None


def test_host_rejects_overlapping_edits_even_with_valid_digest_shape():
    payload, files = setup()
    proposed = {'id': IDENTIFIER, 'file': PATH, 'reason': '근거 있는 변경',
                'edits': [candidate()['edits'][0], candidate()['edits'][0]],
                'validation': {'syntax': 'passed', 'source_sha256': payload['sources'][PATH]['sha256'],
                               'updated_sha256': '0' * 64}}
    result = validate_patches({'patches': [proposed]}, payload, files)[IDENTIFIER]
    assert result['applicability'] == 'manual_review'
    assert '겹칩니다' in result['reason']


def test_pass_result_and_missing_model_result_stay_manual():
    payload, files = setup('pass')
    candidate_result = validate_patches({'patches': []}, payload, files)[IDENTIFIER]
    assert candidate_result['applicability'] == 'manual_review'
    with pytest.raises(ValueError):
        validate_model_patch(candidate(), payload['scenarios'][0], payload['sources'])


def test_model_cannot_edit_source_lines_not_sent_in_excerpt():
    source = '\n'.join(['def handler(raw):'] + [f'    item_{index} = raw' for index in range(1400)]
                       + ['    return raw']) + '\n'
    files = {PATH: source}
    scenario = {**SCENARIO, 'source_evidence': [{'file': PATH, 'line': 1401}]}
    payload = prepare_patch_request([scenario], {IDENTIFIER: {'status': 'manual_review'}}, files)
    assert payload['scenarios'] and 500 not in payload['sources'][PATH]['visible_lines']
    bad = {'file': PATH, 'reason': '보지 못한 줄을 바꿉니다.',
           'edits': [{'start_line': 500, 'old_lines': ['    item_498 = raw'],
                      'new_lines': ['    item_498 = raw.strip()']}]}
    with pytest.raises(ValueError):
        validate_model_patch(bad, payload['scenarios'][0], payload['sources'])


@pytest.mark.parametrize('path,source,old,new', [
    ('src/app.js', 'function f(x) { return x; }\n',
     'function f(x) { return x; }', 'function f(x) { return x.trim(); }'),
    ('src/app.ts', 'function f(x: string): string { return x; }\n',
     'function f(x: string): string { return x; }',
     'function f(x: string): string { return x.trim(); }'),
    ('src/App.java', 'class App { String f(String x) { return x; } }\n',
     'class App { String f(String x) { return x; } }',
     'class App { String f(String x) { return x.trim(); } }'),
    ('src/app.php', '<?php function f($x) { return $x; }\n',
     '<?php function f($x) { return $x; }',
     '<?php function f($x) { return trim($x); }'),
])
def test_worker_parses_changed_multilanguage_source_when_grammars_available(path, source, old, new):
    pytest.importorskip('tree_sitter')
    scenario = {**SCENARIO, 'source_evidence': [{'file': path, 'line': 1}]}
    payload = prepare_patch_request([scenario], {IDENTIFIER: {'status': 'manual_review'}}, {path: source})
    proposed = {'file': path, 'reason': '함수 반환값을 수정합니다.',
                'edits': [{'start_line': 1, 'old_lines': [old], 'new_lines': [new]}]}
    verified = validate_model_patch(proposed, payload['scenarios'][0], payload['sources'])
    result = validate_patches({'patches': [verified]}, payload, {path: source})[IDENTIFIER]
    assert result['applicability'] == 'review_required'
    assert new in result['diff']
