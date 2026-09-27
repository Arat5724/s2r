"""Package source-specific AI plans into bounded Python check scripts."""

import json
import re
from urllib.parse import urlsplit

from .ai_scripts import validate_check, validate_plan
from .runtime import SAFE_PATH

HTTP_METHODS = frozenset({'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'})


def _target(origin):
    if not isinstance(origin, str) or any(ord(ch) < 33 or ord(ch) > 126 for ch in origin):
        raise ValueError('Expected an HTTP(S) origin without credentials or a path')
    try:
        url = urlsplit(origin)
        host, port = url.hostname, url.port
    except ValueError as exc:
        raise ValueError('Expected an HTTP(S) origin without credentials or a path') from exc
    if (url.scheme not in {'http', 'https'} or not host
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,249}', host)
            or url.username is not None or url.password is not None
            or url.path not in {'', '/'} or url.query or url.fragment):
        raise ValueError('Expected an HTTP(S) origin without credentials or a path')
    if port is None:
        port = 443 if url.scheme == 'https' else 80
    if not 1 <= port <= 65535:
        raise ValueError('Expected a valid HTTP(S) port')
    return {'scheme': url.scheme, 'host': host, 'port': port}


def _scenario_path(scenario):
    path = scenario.get('path')
    if (not isinstance(path, str) or not SAFE_PATH.fullmatch(path) or path.startswith('//')
            or any(part in {'.', '..'} for part in path.split('/'))):
        raise ValueError('Unapproved diagnostic path')
    return path


def _scenario_title(scenario):
    title = scenario.get('title', '')
    if not isinstance(title, str) or len(title) > 300:
        raise ValueError('Invalid scenario title')
    return title


def _scenario_method(scenario):
    method = scenario.get('method')
    if not isinstance(method, str) or method not in HTTP_METHODS:
        raise ValueError('Unapproved diagnostic method')
    return method


def render_script(origin, scenarios, ai_checks):
    """Render approved live scenarios; model code never owns network."""
    if not scenarios or not isinstance(ai_checks, dict):
        raise ValueError('AI 점검 계획이 없습니다.')
    if set(ai_checks) != {row['id'] for row in scenarios}:
        raise ValueError('AI 점검 계획과 선택 항목이 일치하지 않습니다.')
    configurations, definitions, mappings = [], [], []
    for scenario in scenarios:
        if not scenario.get('automatable'):
            raise ValueError('Only independently approved live scenarios may send requests')
        method = _scenario_method(scenario)
        path = _scenario_path(scenario)
        plan = validate_plan(ai_checks[scenario['id']], scenario)
        probe = plan['probe']
        requests = probe.get('requests') if 'requests' in probe else [probe]
        if not isinstance(requests, list) or len(requests) not in {1, 2}:
            raise ValueError('Only approved live requests may be downloaded')
        for request in requests:
            if request.get('input_location', 'query') not in {'query', 'body'}:
                raise ValueError('Unapproved diagnostic input location')
            if request.get('input_location') == 'body':
                body = json.dumps({request['query_key']: request['probe_value']},
                                  ensure_ascii=True, separators=(',', ':')).encode('utf-8')
                if len(body) > 512:
                    raise ValueError('Diagnostic JSON body exceeds 512 bytes')
        configurations.append({'id': scenario['id'], 'title': _scenario_title(scenario),
                               'method': method, 'path': path,
                               'requests': requests, 'reason': plan['reason']})
        definitions.append(validate_check(plan['source'], scenario, plan['probe']))
        mappings.append(f"{scenario['id']!r}: ai_evaluate_{scenario['id']}")
    encoded = repr(json.dumps({'target': _target(origin), 'scenarios': configurations},
                              ensure_ascii=True, separators=(',', ':')))
    source = '''#!/usr/bin/env python3
"""S2R Review source-specific AI checks. Python 3; authorized targets only.

The selected method and path are fixed in CONFIG. Each approved AI request sends
one URL-encoded query pair or one JSON body field (at most 512 bytes). Redirects
are not followed; no credentials or cookies are sent. The selected method may
change server state. Outside OpenShell the sandbox policy is not applied: review
the target and script before running it. A bounded observation is not proof of
universal safety.
"""

import http.client
import json
import sys
from urllib.parse import urlencode

CONFIG = json.loads(__S2R_CONFIG__)
MAX_BODY = 65536


def fetch(scenario, probe):
    target = CONFIG['target']
    connection_class = (http.client.HTTPSConnection if target['scheme'] == 'https'
                        else http.client.HTTPConnection)
    connection = None
    try:
        connection = connection_class(target['host'], target['port'], timeout=5)
        request_path = scenario['path']
        location = probe.get('input_location', 'query')
        if location == 'query' and probe['query_key'] is not None:
            request_path += '?' + urlencode({probe['query_key']: probe['probe_value']})
        if location == 'body':
            payload = json.dumps({probe['query_key']: probe['probe_value']},
                                 ensure_ascii=True, separators=(',', ':')).encode('utf-8')
            if len(payload) > 512:
                raise ValueError('Diagnostic JSON body exceeds 512 bytes')
            connection.request(scenario['method'], request_path, body=payload,
                               headers={'Content-Type': 'application/json'})
        else:
            connection.request(scenario['method'], request_path)
        response = connection.getresponse()
        body = response.read(MAX_BODY + 1)
        headers = {name.lower(): value[:1000] for name, value in response.getheaders()}
        return {'status': response.status, 'error': None,
                'body_text': body.decode('utf-8', errors='replace') if len(body) <= MAX_BODY else '',
                'body_within_limit': len(body) <= MAX_BODY, 'headers': headers}
    except (OSError, http.client.HTTPException):
        return {'status': None, 'error': 'connection_failed', 'body_text': '',
                'body_within_limit': False, 'headers': {}}
    finally:
        if connection is not None:
            connection.close()


__S2R_AI_FUNCTIONS__
AI_EVALUATORS = __S2R_AI_MAP__


def assess(scenario, observations):
    candidate = observations['candidate']
    baseline = observations.get('baseline')
    response = dict(candidate)
    if baseline is not None:
        response.update({'baseline_' + key: value for key, value in baseline.items()})
    if candidate['error'] is not None or baseline is not None and baseline['error'] is not None:
        verdict = ('unavailable', '대상 서버에 연결하지 못했습니다.')
    elif baseline is not None and (any(not isinstance(item['status'], int)
                                      or not 100 <= item['status'] <= 599
                                      for item in (baseline, candidate))):
        verdict = ('inconclusive', '기준 또는 후보 HTTP 상태 코드를 확인하지 못했습니다.')
    elif baseline is not None and (not baseline['body_within_limit']
                                  or not candidate['body_within_limit']):
        verdict = ('inconclusive', '기준 또는 후보 응답이 크기 제한을 넘었습니다.')
    elif baseline is None and candidate['status'] == 404:
        verdict = ('not_found', '선택한 경로가 404를 반환했습니다.')
    else:
        try:
            verdict = AI_EVALUATORS[scenario['id']](response)
        except (TypeError, ValueError, KeyError, IndexError, AttributeError, RecursionError):
            verdict = ('inconclusive', 'AI 판정 함수가 이 응답을 해석하지 못했습니다.')
    if (not isinstance(verdict, tuple) or len(verdict) != 2
            or verdict[0] not in {'pass', 'fail', 'inconclusive', 'not_found', 'unavailable'}
            or not isinstance(verdict[1], str) or not 1 <= len(verdict[1]) <= 200):
        verdict = ('inconclusive', 'AI 판정 함수의 결과 형식이 올바르지 않습니다.')
    return {'scenario_id': scenario['id'], 'title': scenario['title'],
            'method': scenario['method'], 'path': scenario['path'], 'status': verdict[0],
            'http_status': candidate['status'], 'detail': verdict[1],
            'baseline_http_status': baseline['status'] if baseline is not None else None}


def main():
    all_passed = True
    for scenario in CONFIG['scenarios']:
        observations = {}
        for request in scenario['requests']:
            observations[request.get('label', 'candidate')] = fetch(scenario, request)
        result = assess(scenario, observations)
        if result['status'] != 'pass':
            all_passed = False
        print(json.dumps(result, ensure_ascii=True, separators=(',', ':')))
    return 0 if all_passed else 1


if __name__ == '__main__':
    sys.exit(main())
'''
    return (source.replace('__S2R_CONFIG__', encoded)
            .replace('__S2R_AI_FUNCTIONS__', '\n\n'.join(definitions))
            .replace('__S2R_AI_MAP__', '{' + ','.join(mappings) + '}'))


def render_review_script(scenario, plan, *, source_context=None):
    """Offline model-authored evaluator for a scenario without safe live execution."""
    path = scenario.get('path')
    if (not isinstance(path, str) or not path.startswith('/') or len(path) > 240
            or any(ord(ch) < 32 for ch in path)):
        raise ValueError('Invalid scenario path for offline review')
    approved = validate_plan(plan, scenario, offline=True, source_context=source_context)
    payload = repr(json.dumps({'id': scenario['id'], 'title': _scenario_title(scenario),
                               'method': scenario.get('method'), 'path': path,
                               'reason': approved['reason']}, ensure_ascii=True))
    return '''#!/usr/bin/env python3
"""S2R Review offline-only AI check; this script makes NO network requests.

Supply a sanitized observation as JSON on standard input:
{"status": 200, "error": null, "body_text": "...",
 "body_within_limit": true, "headers": {"content-type": "text/html"}}
Only send observations from systems you are authorized to inspect.
"""

import json
import sys

SCENARIO = json.loads(__S2R_SCENARIO__)
MAX_BODY = 65536

__S2R_AI_FUNCTION__


def main():
    try:
        incoming = json.loads(sys.stdin.read(MAX_BODY + 8192))
        if not isinstance(incoming, dict):
            raise ValueError('observation must be a JSON object')
        status, error = incoming.get('status'), incoming.get('error')
        body_text, headers = incoming.get('body_text'), incoming.get('headers')
        if (status is not None and (type(status) is not int or not 100 <= status <= 599)
                or error is not None and (not isinstance(error, str) or len(error) > 120)
                or not isinstance(body_text, str) or len(body_text) > MAX_BODY
                or type(incoming.get('body_within_limit')) is not bool
                or not isinstance(headers, dict) or len(headers) > 64
                or any(not isinstance(k, str) or not isinstance(v, str)
                       or len(k) > 64 or len(v) > 1000 for k, v in headers.items())):
            raise ValueError('observation exceeds the accepted shape')
        observation = {'status': status, 'error': error, 'body_text': body_text,
                       'body_within_limit': incoming['body_within_limit'],
                       'headers': {key.lower(): value for key, value in headers.items()}}
        if error is not None:
            verdict = ('unavailable', '관찰된 연결 오류가 있습니다.')
        elif status == 404:
            verdict = ('not_found', '관찰된 경로가 404를 반환했습니다.')
        else:
            verdict = ai_evaluate___S2R_ID__(observation)
        if (not isinstance(verdict, tuple) or len(verdict) != 2
                or verdict[0] not in {'pass', 'fail', 'inconclusive', 'not_found', 'unavailable'}
                or not isinstance(verdict[1], str) or not 1 <= len(verdict[1]) <= 200):
            raise ValueError('AI evaluator returned an invalid result')
        print(json.dumps({'scenario_id': SCENARIO['id'], 'status': verdict[0],
                          'detail': verdict[1], 'http_status': status},
                         ensure_ascii=True, separators=(',', ':')))
    except (ValueError, TypeError, KeyError, IndexError):
        print(json.dumps({'scenario_id': SCENARIO['id'], 'status': 'inconclusive',
                          'detail': '입력 관찰값 또는 판정 결과를 확인하지 못했습니다.'},
                         ensure_ascii=True), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
'''.replace('__S2R_SCENARIO__', payload).replace(
        '__S2R_AI_FUNCTION__', validate_check(approved['source'], scenario,
                                              approved['probe'], offline=True)).replace(
        '__S2R_ID__', scenario['id'])
