"""Apply exact OpenShell method/path rules for bounded AI diagnostic requests."""
import copy
import ipaddress
import json
import re
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import bridge
from .ai_get_safety import prove_probe_safe

MAX_SCENARIOS = 10
MAX_ROUTES = 20
SAFE_PATH = re.compile(r'^/[A-Za-z0-9/_.~-]*$')
SAFE_QUERY_KEY = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$')
SAFE_PROBE_LABEL = {'baseline', 'candidate'}
HTTP_METHODS = {'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'}
INPUT_LOCATIONS = {'query', 'body'}
MAX_PROBE_VALUE = 160
MAX_JSON_BODY = 512
SAFE_TAG_VALUE = re.compile(
    r'<(strong|em|b|i)>(s2r_[A-Za-z0-9_-]{8,60})</\1>', re.I)
SAFE_REDIRECT_VALUE = re.compile(r'https://example\.invalid(?:/[A-Za-z0-9_./~-]*)?')
SCRIPT_SCHEME = re.compile(r'(?:javascript|data|vbscript)\s*:', re.I)


def _canonical_probe_path(path):
    return (isinstance(path, str) and bool(SAFE_PATH.fullmatch(path))
            and '//' not in path and all(part not in {'.', '..'} for part in path.split('/')))


def _input_location(row):
    return row.get('input_location', 'query')


def _approved_input(endpoint, name, location):
    inputs = endpoint.get('inputs') or []
    if (not isinstance(inputs, list) or not isinstance(name, str)
            or not SAFE_QUERY_KEY.fullmatch(name)
            or not isinstance(location, str) or location not in INPUT_LOCATIONS
            or any(not isinstance(item, dict) for item in inputs)):
        return False
    matches = [item for item in inputs if item.get('name') == name and item.get('in') == location]
    return (len(matches) == 1
            and not any(item.get('required') is True and item is not matches[0]
                        for item in inputs))


def ai_probe_eligibility(endpoint, scenario, files=None):
    """Require selected route, one declared input, and source-supported behavior."""
    path = endpoint.get('path')
    method = endpoint.get('method')
    if (not isinstance(method, str) or method not in HTTP_METHODS
            or scenario.get('method') != method
            or scenario.get('path') != path or scenario.get('endpoint_ids') != [endpoint.get('id')]
            or not _canonical_probe_path(path)):
        return False, '선택한 고정 HTTP 경로와 메서드를 확인할 수 없습니다.'
    name, location = scenario.get('input_name'), _input_location(scenario)
    if not _approved_input(endpoint, name, location):
        return False, '선택한 입력 위치와 이름 또는 다른 필수 입력을 확인할 수 없습니다.'
    if endpoint.get('conditions') or endpoint.get('guards') or endpoint.get('dependencies'):
        return False, '분기·권한·의존성 검토가 필요한 함수는 자동 요청하지 않습니다.'
    effects = endpoint.get('effects') or {}
    if effects.get('database_write_detected') or effects.get('session_change_detected'):
        return False, '상태 변경 가능성이 표시된 함수는 자동 요청하지 않습니다.'
    handler = endpoint.get('handler') or {}
    if not any(row.get('file') == handler.get('file') and
               handler.get('line', 0) <= row.get('line', -1) <= handler.get('end_line', 0)
               for row in scenario.get('source_evidence', [])):
        return False, '취약 동작 근거가 처리 함수 안에서 확인되지 않습니다.'
    return prove_probe_safe(files, endpoint, name, location)


def ai_get_eligibility(endpoint, scenario, files=None):
    """Compatibility entry point for existing callers."""
    return ai_probe_eligibility(endpoint, scenario, files)


def validate_target(value):
    url = urlsplit(value.strip())
    if url.scheme not in {'http', 'https'} or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in {'', '/'}:
        raise ValueError('http(s) 서버 주소만 입력하세요. 경로·계정·쿼리는 입력하지 않습니다.')
    try:
        port = url.port or (443 if url.scheme == 'https' else 80)
    except ValueError as exc:
        raise ValueError('올바른 서버 포트를 입력하세요.') from exc
    if not 1 <= port <= 65535 or len(value) > 250:
        raise ValueError('서버 주소 또는 포트가 허용 범위를 벗어났습니다.')
    hostname = url.hostname.lower()
    if hostname in {'localhost', '127.0.0.1'}:
        if port == 8020:
            raise ValueError('S2R Review 자체 서버는 점검 대상으로 선택할 수 없습니다.')
        # Docker Desktop forwards this name to host-bound localhost services.
        connection_host = 'host.docker.internal'
    else:
        if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,249}', hostname) or '..' in hostname:
            raise ValueError('올바른 DNS 호스트 이름을 입력하세요.')
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            if hostname in {'metadata.google.internal', 'host.docker.internal'} or hostname.endswith('.internal'):
                raise ValueError('이 호스트 이름은 점검 대상에 사용할 수 없습니다.')
        else:
            if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
                raise ValueError('메타데이터·예약 주소는 점검할 수 없습니다.')
        connection_host = hostname
    origin = f'{url.scheme}://{connection_host}:{port}'
    display = f'{url.scheme}://{hostname}:{port}'
    return {'display_origin': display, 'connection_origin': origin,
            'policy_host': connection_host, 'port': port, 'host_header': f'{hostname}:{port}'}


def _approved_probe_value(value):
    """The worker URL-encodes data; no model value can change the destination."""
    return (isinstance(value, str) and 1 <= len(value) <= MAX_PROBE_VALUE
            and all(32 <= ord(char) <= 126 for char in value)
            and not any(token in value for token in (';', '`', '$(', '&&', '||'))
            and not SCRIPT_SCHEME.search(value)
            and (not any(char in value for char in '<>')
                 or bool(SAFE_TAG_VALUE.fullmatch(value)))
            and (not ('://' in value or value.startswith('//'))
                 or bool(SAFE_REDIRECT_VALUE.fullmatch(value))))


def _bounded_json_body(key, value):
    return len(json.dumps({key: value}, ensure_ascii=False, separators=(',', ':')).encode('utf-8')) <= MAX_JSON_BODY


def _plan_requests(plan):
    probe = plan.get('probe') if isinstance(plan, dict) else None
    if not isinstance(probe, dict):
        raise ValueError('AI 점검 계획의 요청 목록을 확인할 수 없습니다.')
    if 'requests' in probe:
        requests = probe['requests']
        if (not isinstance(requests, list) or len(requests) != 2
                or any(not isinstance(item, dict) for item in requests)
                or {item.get('label') for item in requests} != SAFE_PROBE_LABEL):
            raise ValueError('비교 검증에는 기준값과 후보값 요청이 각각 하나씩 필요합니다.')
        return requests, True
    if set(probe) in ({'query_key', 'probe_value'},
                      {'query_key', 'probe_value', 'input_location'}):
        # Existing stored jobs use the single-candidate contract.
        return [probe], False
    raise ValueError('AI 점검 계획의 요청 목록을 확인할 수 없습니다.')


def validate_ai_routes(scenarios, endpoints, selection, plans, files=None):
    """Bind model data to selected, source-checked method and input location."""
    by_endpoint = {row['id']: row for row in endpoints}
    chosen_scenarios = set(selection['scenario_ids'])
    chosen_endpoints = set(selection['endpoint_ids'])
    routes = []
    for scenario in scenarios:
        identifier = scenario['id']
        if identifier not in chosen_scenarios or not scenario.get('automatable'):
            continue
        if not set(scenario['endpoint_ids']) <= chosen_endpoints:
            continue
        plan = plans.get(identifier)
        if plan is None:
            continue
        endpoint = by_endpoint.get(scenario['endpoint_ids'][0])
        if endpoint is None:
            raise ValueError('시나리오에 연결된 엔드포인트를 찾을 수 없습니다.')
        eligible, reason = ai_probe_eligibility(endpoint, scenario, files)
        if not eligible:
            raise ValueError(reason)
        requests, differential = _plan_requests(plan)
        location = _input_location(scenario)
        values = set()
        for request in requests:
            key, value = request.get('query_key'), request.get('probe_value')
            if (key != scenario.get('input_name')
                    or request.get('input_location', 'query') != location
                    or not _approved_probe_value(value)
                    or location == 'body' and not _bounded_json_body(key, value)):
                raise ValueError('AI가 제안한 입력이 선택한 함수의 입력 위치·범위를 벗어났습니다.')
            values.add(value)
            route = {'method': endpoint['method'], 'path': scenario['path'], 'endpoint_id': endpoint['id'],
                     'scenario_id': identifier, 'probe_kind': 'ai_generic',
                     'query_key': key, 'probe_value': value}
            if location == 'body':
                route['input_location'] = 'body'
            if differential:
                route['probe_label'] = request['label']
            routes.append(route)
        if differential and len(values) != 2:
            raise ValueError('기준값과 후보값은 달라야 합니다.')
    if len({route['scenario_id'] for route in routes}) > MAX_SCENARIOS:
        raise ValueError(f'한 번에 최대 {MAX_SCENARIOS}개 시나리오를 점검할 수 있습니다.')
    if len(routes) > MAX_ROUTES:
        raise ValueError(f'한 번에 최대 {MAX_ROUTES}개의 HTTP 진단만 실행할 수 있습니다.')
    return routes


def linux_copy(source, destination):
    subprocess.run(['wsl.exe', '-d', 'Ubuntu', '--', 'python3', '-c',
                    'from pathlib import Path; import sys; Path(sys.argv[2]).write_bytes(Path(sys.argv[1]).read_bytes())',
                    bridge.wsl_path(source), destination], check=True, timeout=20,
                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))


def set_policy(policy, folder, suffix, *, sandbox=None):
    local = folder / f'openshell-policy-{suffix}.json'
    local.write_text(json.dumps(policy, indent=2), encoding='utf-8')
    remote = f'/home/a/s2r-review-build/policy-{folder.name}-{suffix}.json'
    linux_copy(local, remote)
    sandbox = sandbox or bridge.sandbox_for_job(folder.parent.parent)
    bridge.command('policy', 'set', sandbox, '--policy', remote, '--wait', timeout=90)


def _write_recovery_state(job_dir: Path, state: str, reason: str = ''):
    path = job_dir / 'sandbox-recovery.json'
    temporary = job_dir / 'sandbox-recovery.tmp'
    temporary.write_text(json.dumps({'state': state, 'reason': reason[:500]}, ensure_ascii=False),
                         encoding='utf-8')
    for attempt in range(6):
        try:
            temporary.replace(path)
            return
        except PermissionError:
            if attempt == 5:
                raise
            time.sleep(0.02 * (attempt + 1))


def quarantine_orphan_job_sandbox(job_dir: Path):
    """Close a sandbox created before its durable job marker was written."""
    _write_recovery_state(job_dir, 'quarantining', '분석 샌드박스 표식이 없습니다.')
    try:
        isolated = bridge.quarantine_job_sandbox(job_dir)
    except Exception as exc:
        raise RuntimeError('표식 없는 분석 샌드박스를 격리하지 못했습니다. 앱 시작을 중단합니다.') from exc
    if not isolated:
        raise RuntimeError('표식 없는 분석 샌드박스를 격리하지 못했습니다. 앱 시작을 중단합니다.')
    _write_recovery_state(job_dir, 'quarantined', '표식 없는 분석 샌드박스를 격리했습니다.')
    return {'state': 'quarantined', 'reason': '표식 없는 분석 샌드박스를 격리했습니다.'}


def recover_job_sandbox(job_dir: Path):
    """Restore a stranded runtime grant before a saved job can run again.

    The launcher calls this before accepting requests. Never trust the sandbox
    name alone: the durable UUID, ownership label, policy, and bind sources
    must still match the job that created it.
    """
    marker = bridge._marker(job_dir)
    if marker is None:
        return {'state': 'legacy'}
    sandbox = marker['sandbox']
    try:
        baseline = json.loads((job_dir / 'openshell-policy.json').read_text(encoding='utf-8'))
        bridge._verify_policy(baseline, marker['files'])
        live = bridge._get_sandbox(sandbox)
        if (live['id'] != marker['sandbox_id']
                or live.get('labels', {}).get('s2r-review-job') != job_dir.name):
            raise RuntimeError('분석 샌드박스 UUID 또는 작업 표식이 저장된 값과 다릅니다.')
        info = bridge._inspect_container(sandbox, live)
        labels = (info.get('Config') or {}).get('Labels') or {}
        if (labels.get('openshell.ai/sandbox-id') != marker['sandbox_id']
                or labels.get('openshell.ai/sandbox-name') != sandbox):
            raise RuntimeError('분석 Docker 컨테이너 식별 정보가 저장된 값과 다릅니다.')
        bridge._verify_mount(info, Path(marker['source_root']), marker['files'])
        observed = live['policy']
        network = observed.get('network_policies', {})
        if 'runtime_target' in network:
            if set(network) != {'managed_inference', 'runtime_target'}:
                raise RuntimeError('중단된 운영 점검의 네트워크 허용 항목이 예상과 다릅니다.')
            without_target = copy.deepcopy(observed)
            del without_target['network_policies']['runtime_target']
            if without_target != baseline:
                raise RuntimeError('중단된 운영 점검의 기본 정책이 저장된 값과 다릅니다.')
            last_error = None
            for attempt in range(3):
                try:
                    set_policy(baseline, job_dir, 'startup-restored', sandbox=sandbox)
                    restored = bridge._get_sandbox(sandbox)['policy']
                    if restored != baseline:
                        raise RuntimeError('운영 점검의 임시 네트워크 정책이 제거되지 않았습니다.')
                    bridge.probe(sandbox=sandbox, job_dir=job_dir)
                    return {'state': 'restored'}
                except Exception as exc:
                    last_error = exc
                    if attempt < 2:
                        time.sleep(0.4 * (attempt + 1))
            raise RuntimeError('운영 점검의 임시 네트워크 정책을 복원하지 못했습니다.') from last_error
        if observed != baseline:
            raise RuntimeError('분석 샌드박스 정책이 저장된 기본 정책과 다릅니다.')
        bridge.probe(sandbox=sandbox, job_dir=job_dir)
        return {'state': 'verified'}
    except Exception as exc:
        # A failed policy restore must never leave a live container with its
        # source mounts and temporary network grant available for later use.
        _write_recovery_state(job_dir, 'quarantining', str(exc))
        try:
            isolated = bridge.quarantine_job_sandbox(job_dir)
        except Exception as isolation_error:
            raise RuntimeError('샌드박스 정책 복구와 격리가 모두 실패했습니다. 앱 시작을 중단합니다.') from isolation_error
        if not isolated:
            raise RuntimeError('샌드박스 정책 복구와 격리가 모두 실패했습니다. 앱 시작을 중단합니다.') from exc
        _write_recovery_state(job_dir, 'quarantined', str(exc))
        return {'state': 'quarantined', 'reason': str(exc)[:500]}


def _validate_transport_routes(routes):
    if not isinstance(routes, list) or len(routes) > MAX_ROUTES:
        raise ValueError('승인된 점검 요청 수가 허용 범위를 벗어났습니다.')
    by_scenario = {}
    for route in routes:
        if (not isinstance(route, dict) or not isinstance(route.get('method'), str)
                or route['method'] not in HTTP_METHODS
                or route.get('probe_kind') != 'ai_generic'
                or not _canonical_probe_path(route.get('path'))
                or not isinstance(_input_location(route), str)
                or _input_location(route) not in INPUT_LOCATIONS
                or not isinstance(route.get('query_key'), str)
                or not SAFE_QUERY_KEY.fullmatch(route['query_key'])
                or not _approved_probe_value(route.get('probe_value'))
                or _input_location(route) == 'body'
                   and not _bounded_json_body(route['query_key'], route['probe_value'])
                or not isinstance(route.get('scenario_id'), str)
                or not re.fullmatch(r'[a-f0-9]{16}', route['scenario_id'])):
            raise ValueError('승인되지 않은 점검 요청이 포함되었습니다.')
        by_scenario.setdefault(route['scenario_id'], []).append(route)
    if len(by_scenario) > MAX_SCENARIOS:
        raise ValueError('승인된 점검 시나리오 수가 허용 범위를 벗어났습니다.')
    for group in by_scenario.values():
        if len(group) == 1 and 'probe_label' not in group[0]:
            continue
        if (len(group) != 2 or {row.get('probe_label') for row in group} != SAFE_PROBE_LABEL
                or len({(row['method'], row['path'], row.get('endpoint_id'),
                         _input_location(row), row['query_key']) for row in group}) != 1
                or group[0]['probe_value'] == group[1]['probe_value']):
            raise ValueError('기준값과 후보값 요청이 일치하지 않습니다.')


def observe(folder: Path, target, routes, update):
    _validate_transport_routes(routes)
    if not routes:
        return [], {'policy_applied': False, 'reason': '선택한 시나리오에 자동 요청 없음',
                    'allowed_paths': [], 'allowed_routes': [], 'method': None,
                    'policy_restored': True}
    analysis_job = folder.parent.parent
    sandbox = bridge.sandbox_for_job(analysis_job)
    original = json.loads(bridge.command('sandbox', 'get', sandbox, '--output', 'json'))['policy']
    if set(original.get('network_policies', {})) != {'managed_inference'}:
        raise RuntimeError('운영 점검 시작 전 네트워크 정책이 예상과 다릅니다.')
    bridge.probe(sandbox=sandbox, job_dir=analysis_job)
    active = copy.deepcopy(original)
    allowed = sorted({(route['method'], route['path']) for route in routes})
    active['network_policies']['runtime_target'] = {
        'name': 'runtime_target',
        'endpoints': [{'host': target['policy_host'], 'port': target['port'], 'protocol': 'rest',
                       'enforcement': 'enforce',
                       'rules': [{'allow': {'method': method, 'path': path}}
                                 for method, path in allowed]}],
        'binaries': [{'path': '/usr/local/bin/python3'}, {'path': '/usr/local/bin/python3.11'}],
    }
    config = {'connection_origin': target['connection_origin'], 'host_header': target['host_header'], 'routes': routes}
    input_file = folder / 'runtime-input.json'
    input_file.write_text(json.dumps(config, ensure_ascii=False), encoding='utf-8')
    name = folder.name
    bridge.stage_input(input_file, name + '-verify', sandbox=sandbox)
    update('policy', 20, '선택한 HTTP 메서드와 경로만 OpenShell 네트워크 정책에 적용합니다.')
    policy_change_attempted = False
    scope = None
    try:
        policy_change_attempted = True
        set_policy(active, folder, 'active')
        live = json.loads(bridge.command('sandbox', 'get', sandbox, '--output', 'json'))['policy']
        observed_entry = live.get('network_policies', {}).get('runtime_target', {})
        observed_endpoints = observed_entry.get('endpoints', [])
        observed_endpoint = (observed_endpoints[0]
                             if isinstance(observed_endpoints, list)
                             and len(observed_endpoints) == 1
                             and isinstance(observed_endpoints[0], dict) else {})
        expected = set(allowed)
        observed_rules = observed_endpoint.get('rules', [])
        exact_rule_shape = (isinstance(observed_rules, list)
                            and all(isinstance(rule, dict) and set(rule) == {'allow'}
                                    and isinstance(rule['allow'], dict)
                                    and set(rule['allow']) == {'method', 'path'}
                                    for rule in observed_rules))
        actual = ({(rule['allow']['method'], rule['allow']['path'])
                   for rule in observed_rules} if exact_rule_shape else set())
        if (set(live.get('network_policies', {})) != {'managed_inference', 'runtime_target'}
                or not isinstance(observed_endpoints, list)
                or len(observed_endpoints) != 1 or len(observed_rules) != len(expected)
                or not exact_rule_shape or actual != expected
                or observed_endpoint.get('host') != target['policy_host']
                or observed_endpoint.get('port') != target['port']
                or observed_endpoint.get('protocol') != 'rest'
                or observed_endpoint.get('enforcement') != 'enforce'
                or observed_entry.get('binaries') != active['network_policies']['runtime_target']['binaries']):
            raise RuntimeError('OpenShell이 선택한 서버·경로 정책과 다르게 적용했습니다.')
        update('request', 45, f'허용된 메서드·경로 {len(allowed)}개에 진단 요청 {len(routes)}개를 보냅니다.')
        output = f'/output/{name}-verify.json'
        bridge.command('sandbox', 'exec', '--name', sandbox, '--no-tty', '--timeout', '150', '--',
                       '/usr/local/bin/python3', '-B', '/app/verify.py', '--input', f'/input/{name}-verify.json',
                       '--output', output, timeout=170)
        bridge.command('sandbox', 'download', sandbox, output, bridge.wsl_path(folder / 'observations.json'))
        observation_file = folder / 'observations.json'
        try:
            observations = json.loads(observation_file.read_text(encoding='utf-8'))['observations']
        finally:
            observation_file.unlink(missing_ok=True)
        scope = {'policy_applied': True, 'target_host': target['policy_host'], 'port': target['port'],
                 'method': allowed[0][0] if len({method for method, _ in allowed}) == 1 else 'MIXED',
                 'allowed_paths': sorted({route['path'] for route in routes}),
                 'allowed_routes': [{'method': method, 'path': path} for method, path in allowed],
                 'probes': [route['probe_kind'] for route in routes if route.get('probe_kind')],
                 'enforcement': 'enforce', 'observed_rules_match': True, 'policy_restored': False}
        return observations, scope
    finally:
        if policy_change_attempted:
            update('restore', 85, '임시 네트워크 허용 규칙을 제거합니다.')
            last_error = None
            for attempt in range(3):
                try:
                    set_policy(original, folder, 'restored')
                    restored = json.loads(bridge.command('sandbox', 'get', sandbox, '--output', 'json'))['policy']
                    if restored.get('network_policies') != original.get('network_policies'):
                        raise RuntimeError('운영 점검 뒤 OpenShell 네트워크 정책 복원이 확인되지 않았습니다.')
                    bridge.probe(sandbox=sandbox, job_dir=analysis_job)
                    last_error = None
                    break
                except Exception as exc:
                    last_error = exc
                    if attempt < 2:
                        time.sleep(0.4 * (attempt + 1))
            if last_error is not None:
                if sandbox != bridge.SANDBOX:
                    _write_recovery_state(analysis_job, 'quarantining', str(last_error))
                    try:
                        isolated = bridge.quarantine_job_sandbox(analysis_job)
                    except Exception as isolation_error:
                        raise RuntimeError('OpenShell 네트워크 정책 복원과 샌드박스 격리가 모두 실패했습니다.') from isolation_error
                    if not isolated:
                        raise RuntimeError('OpenShell 네트워크 정책 복원과 샌드박스 격리가 모두 실패했습니다.') from last_error
                    _write_recovery_state(analysis_job, 'quarantined', str(last_error))
                    raise RuntimeError('OpenShell 네트워크 정책 복원에 실패하여 작업 샌드박스를 격리했습니다.') from last_error
                raise RuntimeError('OpenShell 네트워크 정책 복원 실패. 샌드박스 상태를 점검해야 합니다.') from last_error
            if scope is not None:
                scope['policy_restored'] = True
            try:
                bridge.command('sandbox', 'exec', '--name', sandbox, '--no-tty', '--timeout', '20', '--',
                               '/usr/local/bin/python3', '-B', '-c',
                               'from pathlib import Path; Path("/output/' + name + '-verify.json").unlink(missing_ok=True)',
                               timeout=35)
            except Exception:
                # No response body is retained on the host. A later worker
                # cleanup can remove the bounded sandbox copy if needed.
                pass
