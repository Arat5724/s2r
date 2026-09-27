"""The model reads source and AI mode fails closed on provider errors."""

import io
import hashlib
import json
import urllib.error

import pytest

import agent
import ai_source
import setup_worker


def test_worker_update_waits_for_operational_check(tmp_path):
    jobs = tmp_path / 'jobs'
    run = jobs / 'job' / 'runs' / 'run'
    run.mkdir(parents=True)
    (jobs / 'job' / 'status.json').write_text('{"state":"completed"}', encoding='utf-8')
    (run / 'status.json').write_text('{"state":"running"}', encoding='utf-8')
    with pytest.raises(RuntimeError, match='operational check'):
        setup_worker.ensure_no_active_work(jobs)
    (run / 'status.json').write_text('{"state":"completed"}', encoding='utf-8')
    setup_worker.ensure_no_active_work(jobs)


def response():
    payload = {'project_summary': '코드 기반 설명', 'endpoints': [], 'scenarios': [],
               'review_notes': ['실행 환경은 확인하지 않음']}
    return io.BytesIO(json.dumps({'choices': [{'message': {'content': json.dumps(payload)}}],
                                 'model': 'test-model'}).encode())


def test_model_request_contains_numbered_raw_source_not_a_route_inventory(monkeypatch):
    requests = []

    def request(req, **kwargs):
        requests.append(req)
        return response()

    monkeypatch.setattr(ai_source.urllib.request, 'urlopen', request)
    parsed, provider, _ = ai_source._request_model('### FILE app.py\nL00001 @app.get("/health")')
    assert parsed['project_summary'] == '코드 기반 설명'
    assert provider['model'] == 'test-model'
    assert len(requests) == 1
    assert requests[0].full_url == 'https://inference.local/v1/chat/completions'
    assert requests[0].method == 'POST'
    payload = json.loads(requests[0].data)
    assert 'L00001 @app.get("/health")' in payload['messages'][1]['content']
    assert '"id": "known"' not in payload['messages'][1]['content']


def test_fast_provider_unavailable_retries_once_without_changing_scope(monkeypatch):
    calls = []

    def request(req, **kwargs):
        calls.append((req.full_url, req.method, req.data))
        if len(calls) == 1:
            raise urllib.error.HTTPError(req.full_url, 503, 'Unavailable', {}, None)
        return response()

    monkeypatch.setattr(ai_source.urllib.request, 'urlopen', request)
    monkeypatch.setattr(ai_source.time, 'sleep', lambda _: None)
    parsed, _, _ = ai_source._request_model('### FILE app.py\nL00001 @app.get("/health")')
    assert parsed['endpoints'] == []
    assert len(calls) == 2
    assert calls[0] == calls[1]


def test_malformed_json_retries_once_with_identical_source(monkeypatch):
    calls = []

    def request(req, **kwargs):
        calls.append(req.data)
        if len(calls) == 1:
            return io.BytesIO(json.dumps({'choices': [{'message': {'content': '{invalid'}}]}).encode())
        return response()

    monkeypatch.setattr(ai_source.urllib.request, 'urlopen', request)
    monkeypatch.setattr(ai_source.time, 'sleep', lambda _: None)
    parsed, _, _ = ai_source._request_model('### FILE app.py\nL00001 @app.get("/health")')
    assert parsed['endpoints'] == []
    assert len(calls) == 2 and calls[0] == calls[1]


def test_transient_timeout_retries_once_with_identical_source(monkeypatch):
    calls = []

    def request(req, **kwargs):
        calls.append((req.full_url, req.data))
        if len(calls) == 1:
            raise TimeoutError('provider timed out')
        return response()

    monkeypatch.setattr(ai_source.urllib.request, 'urlopen', request)
    monkeypatch.setattr(ai_source.time, 'sleep', lambda _: None)
    parsed, _, _ = ai_source._request_model('### FILE app.py\nL00001 @app.get("/health")')
    assert parsed['endpoints'] == []
    assert len(calls) == 2 and calls[0] == calls[1]


def test_provider_failure_does_not_use_deterministic_fallback(monkeypatch, tmp_path):
    def failed_model(_files):
        raise urllib.error.HTTPError('https://inference.local/v1/chat/completions',
                                     401, 'Unauthorized', {}, None)

    monkeypatch.setattr(agent, 'infer_from_source', failed_model)
    content = '@app.get("/health")'
    (tmp_path / '0000').write_text(content, encoding='utf-8')
    identity = json.dumps({'app.py': content}, sort_keys=True, ensure_ascii=False,
                          separators=(',', ':')).encode()
    bundle = {'kind': 'mounted_source_manifest', 'files': ['app.py'],
              'source_hash': hashlib.sha256(identity).hexdigest()}
    with pytest.raises(RuntimeError, match='AI 소스 분석 실패'):
        agent.analyze_bundle(bundle, True, tmp_path)


def test_non_ai_request_is_rejected_without_invoking_source_analysis(monkeypatch):
    calls = []
    monkeypatch.setattr(agent, 'infer_from_source', lambda files: calls.append(files))
    with pytest.raises(RuntimeError, match='규칙 기반 소스 분석은 더 이상 실행하지 않습니다'):
        agent.analyze_bundle({'files': {'app.py': 'def health(): pass'}}, False)
    assert calls == []


def test_worker_image_and_checksums_exclude_retired_static_analyzers():
    dockerfile = (setup_worker.ROOT / 'worker' / 'Dockerfile').read_text(encoding='utf-8')
    copied = next(line for line in dockerfile.splitlines() if line.startswith('COPY '))
    assert set(setup_worker.RETIRED_CODE_FILES) == {
        'analyzer.py', 'framework_python.py', 'framework_javascript.py', 'framework_enterprise.py'}
    assert all(name not in setup_worker.CODE_FILES and name not in copied
               for name in setup_worker.RETIRED_CODE_FILES)
    assert all(not (setup_worker.ROOT / 'worker' / name).exists()
               for name in setup_worker.RETIRED_CODE_FILES)
