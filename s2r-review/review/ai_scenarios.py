"""Turn source-grounded model hypotheses into reviewable scenarios.

AI proposes the vulnerability, verification and repair.  The host validates
source citations and independently limits which selected requests may run.
"""

import hashlib
import json

from . import runtime


CATEGORIES = {
    'xss': 'XSS',
    'sqli': 'SQL 인젝션',
    'path_traversal': '경로 탐색',
    'open_redirect': '오픈 리다이렉트',
    'command_injection': '명령어 인젝션',
    'ssrf': '서버 측 요청 위조',
    'template_injection': '템플릿 인젝션',
    'insecure_deserialization': '안전하지 않은 역직렬화',
    'xxe': 'XML 외부 엔터티',
    'file_upload': '파일 업로드',
    'csrf': 'CSRF',
    'sensitive_data_exposure': '민감 정보 노출',
    'security_misconfiguration': '보안 설정 오류',
    'other_technical': '기타 기술 취약점',
}

MAX_SCENARIOS = 100


def _text(value, field, *, limit=800):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f'AI 시나리오의 {field} 값이 올바르지 않습니다.')
    return value.strip()


def _source_location(value, files):
    if not isinstance(value, dict):
        raise ValueError('AI 시나리오의 코드 근거 형식이 올바르지 않습니다.')
    name, line = value.get('file'), value.get('line')
    if not isinstance(name, str) or name not in files or type(line) is not int:
        raise ValueError('AI 시나리오의 코드 근거가 분석 범위 밖입니다.')
    lines = files[name].splitlines()
    if not 1 <= line <= len(lines) or not lines[line - 1].strip():
        raise ValueError('AI 시나리오의 코드 근거 줄이 원본과 일치하지 않습니다.')
    symbol = value.get('symbol')
    if not isinstance(symbol, str) or not symbol.strip() or len(symbol) > 160:
        symbol = lines[line - 1].strip()[:160]
    return {'file': name, 'line': line, 'symbol': symbol.strip()}


def _input_locations(endpoint):
    locations = {}
    for item in endpoint.get('inputs', []):
        if not isinstance(item, dict):
            continue
        for field in item.get('fields', [item]):
            if isinstance(field, dict) and isinstance(field.get('name'), str):
                location = field.get('in', item.get('in'))
                locations.setdefault(field['name'], set()).add(location)
    return locations


def normalize_ai_scenarios(result, files):
    """Validate model proposals; derive every operational permission locally."""
    if result.get('analysis_mode') != 'ai' or result.get('ai', {}).get('status') != 'completed':
        raise ValueError('AI가 완료한 소스 분석 결과가 아닙니다.')
    proposals = result.get('ai_scenarios')
    if not isinstance(proposals, list) or len(proposals) > MAX_SCENARIOS:
        raise ValueError('AI 시나리오 목록이 없거나 허용 개수를 초과했습니다.')
    endpoints = result.get('endpoints')
    if not isinstance(endpoints, list):
        raise ValueError('AI 엔드포인트 목록이 올바르지 않습니다.')
    by_id = {row.get('id'): row for row in endpoints if isinstance(row, dict)}
    if len(by_id) != len(endpoints):
        raise ValueError('AI 엔드포인트 ID가 중복되었습니다.')
    scenarios, ids = [], set()
    for proposal in proposals:
        if not isinstance(proposal, dict):
            raise ValueError('AI 시나리오 형식이 올바르지 않습니다.')
        endpoint = by_id.get(proposal.get('endpoint_id'))
        if endpoint is None:
            raise ValueError('AI 시나리오가 분석 결과에 없는 엔드포인트를 참조합니다.')
        category = proposal.get('category')
        if category not in CATEGORIES:
            raise ValueError('AI 시나리오의 취약점 카테고리가 지원 범위 밖입니다.')
        input_name = proposal.get('input_name')
        locations = _input_locations(endpoint)
        if input_name is not None and (not isinstance(input_name, str) or input_name not in locations):
            raise ValueError('AI 시나리오의 입력명이 엔드포인트 입력과 일치하지 않습니다.')
        input_location = None
        if input_name is not None and len(locations[input_name]) == 1:
            input_location = next(iter(locations[input_name]))
        raw_evidence = proposal.get('source_evidence')
        if not isinstance(raw_evidence, list) or not 1 <= len(raw_evidence) <= 8:
            raise ValueError('AI 시나리오에 검증 가능한 코드 근거가 없습니다.')
        evidence = []
        for value in raw_evidence:
            location = _source_location(value, files)
            if (location['file'], location['line']) not in {(e['file'], e['line']) for e in evidence}:
                evidence.append(location)
        handler = endpoint.get('handler') or {}
        handler_file, handler_line = handler.get('file'), handler.get('line')
        if (handler_file not in files or type(handler_line) is not int
                or not 1 <= handler_line <= len(files[handler_file].splitlines())):
            raise ValueError('AI 엔드포인트의 처리 함수 근거가 분석 소스와 일치하지 않습니다.')
        if not any(e['file'] == handler_file and e['line'] == handler_line for e in evidence):
            evidence.insert(0, {'file': handler_file, 'line': handler_line,
                                'symbol': str(handler.get('symbol') or '처리 함수')[:160]})
        title = _text(proposal.get('title'), '제목', limit=180)
        description = _text(proposal.get('description'), '설명', limit=2500)
        risk = _text(proposal.get('risk_hypothesis'), '위험 가설', limit=1800)
        expectation = _text(proposal.get('verification_expectation'), '검증 기준', limit=1200)
        uncertainty = _text(proposal.get('uncertainty'), '불확실성', limit=1200)
        fix = _text(proposal.get('remediation_summary'), '조치 제안', limit=1200)
        identity = json.dumps([endpoint['id'], category, input_name,
                               [(e['file'], e['line']) for e in evidence]], ensure_ascii=False)
        identifier = hashlib.sha256(identity.encode()).hexdigest()[:16]
        if identifier in ids:
            continue
        ids.add(identifier)
        position = ', '.join(f"{e['file']}:{e['line']}" for e in evidence[:4])
        manual_reason = 'AI가 제안한 코드 후보입니다. 이 경로의 비파괴성과 응답 판정을 독립적으로 확인하지 못해 자동 요청을 보내지 않습니다.'
        scenario = {
            'id': identifier,
            'endpoint_ids': [endpoint['id']],
            'source_evidence': evidence,
            'method': endpoint['method'], 'path': endpoint['path'],
            'category': category, 'title': title, 'description': description,
            'risk_hypothesis': risk, 'input_name': input_name,
            'input_location': input_location,
            'source_trigger': f"AI가 {endpoint['method']} {endpoint['path']}의 소스 위치 {position}에서 제안한 후보입니다.",
            'verification_expectation': expectation,
            'automation_rationale': manual_reason,
            'uncertainty': uncertainty,
            'review_steps': [f'표시된 소스 위치({position})에서 입력부터 사용 지점까지의 흐름을 확인합니다.',
                             expectation, '배포 설정과 정상·경계값 테스트로 실제 영향을 확인합니다.'],
            'execution_kind': 'manual', 'automatable': False,
            'disabled_reason': manual_reason,
            'checks': [], 'expected': expectation,
            'remediation': {'summary': fix,
                            'steps': [fix, '관련 입력 검증과 회귀 테스트를 추가하세요.']},
            'generation': 'ai',
        }
        if input_name and input_location in {'query', 'body'}:
            eligible, reason = runtime.ai_probe_eligibility(endpoint, scenario, files)
            if eligible:
                scenario.update(execution_kind='ai_request', automatable=True,
                                disabled_reason=None,
                                automation_rationale='선택한 경로와 입력이 원본 소스에 연결되고 직접 상태 변경은 확인되지 않았습니다. 간접 호출의 부작용은 별도 검토가 필요하며 요청 값은 실행 전에 다시 검증합니다.')
            else:
                scenario['disabled_reason'] = reason
                scenario['automation_rationale'] = f'자동 요청 보류: {reason}'
        elif input_name:
            scenario['disabled_reason'] = '단일 쿼리 또는 JSON 본문 입력 위치를 확인할 수 없습니다.'
            scenario['automation_rationale'] = '자동 요청 보류: 단일 쿼리 또는 JSON 본문 입력 위치를 확인할 수 없습니다.'
        scenarios.append(scenario)
    return scenarios
