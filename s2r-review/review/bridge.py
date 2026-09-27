"""Host-owned transport for the OpenShell analysis workers.

Each new analysis gets a separate sandbox. Selected source files are mounted
read-only under /source; the duplicate /blocked mount verifies that Landlock
denies paths outside that directory. Docker and policy controls stay on host.
"""

import copy
import hashlib
import json
import re
import stat
import subprocess
import time
import uuid
from pathlib import Path, PurePosixPath

from .snapshot import read_scoped


SANDBOX = 's2r-review-ast-v1'  # Provisioned base worker for new analyses.
CLI = '/home/a/.local/bin/openshell'
IMAGE = 's2r-review-worker:local'
BASE_READ_ONLY = {'/usr', '/lib', '/etc', '/proc', '/dev/urandom', '/app', '/input', '/var/log'}
BASE_READ_WRITE = {'/output', '/tmp', '/dev/null'}
MAX_POLICY_PATHS = 256
MAX_SOURCE_FILES = 245
SOURCE_ROOT = '/source'
BLOCKED_TARGET = '/blocked/0000'
IMAGE_CODE_FILES = ('agent.py', 'source_mount.py', 'ai_source.py', 'ast_context.py', 'tree_context.py',
                    'script_agent.py', 'patch_agent.py', 'verify.py')


def wsl_path(path: Path):
    value = str(path.resolve())
    if len(value) < 3 or value[1] != ':':
        raise ValueError('Windows 로컬 드라이브 경로가 필요합니다.')
    return '/mnt/' + value[0].lower() + value[2:].replace('\\', '/')


def command(*args, timeout=130):
    # wsl.exe reparses Windows arguments before launching Linux. JSON driver
    # config loses its nested quotes when passed through that boundary. Send a
    # tiny Python launcher over stdin, then pass the original argv directly
    # from Linux to OpenShell without a shell or text interpolation.
    argv = [CLI, '--gateway', 'nemoclaw', *args]
    launcher = ('import json, subprocess, sys\n'
                f'argv = json.loads({json.dumps(json.dumps(argv, ensure_ascii=False), ensure_ascii=False)})\n'
                'raise SystemExit(subprocess.call(argv))\n')
    proc = subprocess.run(['wsl.exe', '-d', 'Ubuntu', '--', 'python3', '-'],
                          input=launcher.encode('utf-8'), capture_output=True, timeout=timeout,
                          creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    output = re.sub(r'\x1b\[[0-9;]*m', '', proc.stdout.decode('utf-8', errors='replace'))
    if proc.returncode:
        error = proc.stderr.decode('utf-8', errors='replace')[-2000:]
        error = re.sub(r'nvapi-[A-Za-z0-9_-]+', '[redacted]', error)
        raise RuntimeError(f'OpenShell 작업 실패 ({proc.returncode}): {error or output[-1500:]}')
    return output


def _docker(*args, timeout=30):
    proc = subprocess.run(['wsl.exe', '-d', 'Ubuntu', '--', 'docker', *args],
                          capture_output=True, timeout=timeout,
                          creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if proc.returncode:
        error = proc.stderr.decode('utf-8', errors='replace')[-1500:]
        raise RuntimeError(f'Docker 작업 실패 ({proc.returncode}): {error}')
    return proc.stdout.decode('utf-8', errors='replace')


def _job_name(job_dir: Path):
    try:
        identifier = uuid.UUID(job_dir.name)
    except (ValueError, AttributeError) as exc:
        raise ValueError('Invalid analysis job identifier') from exc
    if str(identifier) != job_dir.name:
        raise ValueError('Invalid analysis job identifier')
    # OpenShell 0.0.116 limits sandbox names to 19 characters. The full UUID
    # is still recorded as a label and the gateway UUID is pinned in the job.
    return 's2r-' + identifier.hex[:15]


def _legacy_job_name(job_dir: Path):
    """Recognize saved job markers created before the sandbox name changed."""
    identifier = uuid.UUID(job_dir.name)
    return 'ar-' + identifier.hex[:16]


def _relative_file(name: str):
    if not isinstance(name, str) or not name or '\\' in name or '\x00' in name:
        raise ValueError('선택한 소스 경로가 올바르지 않습니다.')
    value = PurePosixPath(name)
    if (value.is_absolute() or not value.parts or value.as_posix() != name
            or any(part in {'.', '..'} or ':' in part for part in value.parts)):
        raise ValueError('선택한 소스 경로가 프로젝트 밖을 가리킵니다.')
    return value


def _source_alias(index: int):
    if not 0 <= index < MAX_SOURCE_FILES:
        raise ValueError('OpenShell 소스 파일 번호가 범위 밖입니다.')
    return f'{SOURCE_ROOT}/{index:04d}'


def _file_bind_source(root: Path, name: str):
    relative = _relative_file(name)
    source = wsl_path(root.joinpath(*relative.parts))
    if len(source) > 4096:
        raise ValueError('OpenShell이 허용하는 마운트 원본 경로 길이를 초과했습니다.')
    return source


def _source_manifest(project_root: Path, bundle: dict):
    """Bind only paths from the trusted snapshot, and reject changed source."""
    root = project_root.resolve(strict=True)
    if not root.is_dir() or not isinstance(bundle, dict) or not isinstance(bundle.get('files'), dict):
        raise ValueError('분석 대상 프로젝트 또는 소스 목록이 올바르지 않습니다.')
    files = bundle['files']
    names = sorted(files)
    if not names or not isinstance(bundle.get('source_hash'), str):
        raise ValueError('분석 대상 소스의 해시가 없습니다.')
    if len(names) > MAX_SOURCE_FILES:
        raise ValueError(f'현재 분석은 최대 {MAX_SOURCE_FILES}개 소스 파일만 허용합니다.')
    for name in names:
        relative = _relative_file(name)
        path = root.joinpath(*relative.parts)
        _file_bind_source(root, name)
        # Reject links in any component, even when the resolved target stays in root.
        cursor = root
        for part in relative.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise ValueError('링크로 연결된 소스 파일은 마운트 분석에 사용할 수 없습니다.')
        actual = path.resolve(strict=True)
        if not actual.is_relative_to(root) or not actual.is_file():
            raise ValueError('선택한 소스가 프로젝트 범위 밖에 있습니다.')
        info = actual.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
            raise ValueError('일반 단일 링크 소스 파일만 마운트 분석에 사용할 수 있습니다.')
        try:
            content = read_scoped(actual, root).decode('utf-8-sig')
        except (UnicodeDecodeError, OSError) as exc:
            raise ValueError('선택한 소스를 안전하게 다시 읽지 못했습니다.') from exc
        if content != files[name]:
            raise ValueError('선택한 소스가 스냅샷 생성 후 변경되었습니다. 분석을 다시 시작하세요.')
    digest = hashlib.sha256(json.dumps(files, sort_keys=True, ensure_ascii=False,
                                       separators=(',', ':')).encode()).hexdigest()
    if not re.fullmatch(r'[a-f0-9]{64}', bundle['source_hash']) or digest != bundle['source_hash']:
        raise ValueError('선택한 소스의 스냅샷 해시가 일치하지 않습니다.')
    return root, names


def _marker(job_dir: Path):
    path = job_dir / 'sandbox.json'
    if not path.is_file():
        return None
    marker = json.loads(path.read_text(encoding='utf-8'))
    if (not isinstance(marker, dict)
            or marker.get('sandbox') not in {_job_name(job_dir), _legacy_job_name(job_dir)}
            or not isinstance(marker.get('source_root'), str)
            or not isinstance(marker.get('sandbox_id'), str)
            or not isinstance(marker.get('files'), list)
            or not marker['files'] or not all(isinstance(name, str) for name in marker['files'])
            or marker['files'] != sorted(set(marker['files']))
            or marker.get('mount_mode') != 'selected_file_binds_v1'
            or marker.get('source_deny') != BLOCKED_TARGET):
        raise RuntimeError('분석 샌드박스 식별 파일이 올바르지 않습니다.')
    try:
        uuid.UUID(marker['sandbox_id'])
        for name in marker['files']:
            _relative_file(name)
        if len(marker['files']) > MAX_SOURCE_FILES:
            raise ValueError('Too many mounted source files')
    except (ValueError, TypeError) as exc:
        raise RuntimeError('분석 샌드박스 식별 파일이 올바르지 않습니다.') from exc
    return marker


def sandbox_for_job(job_dir: Path):
    """Use a saved job sandbox when present, otherwise the provisioned worker."""
    marker = _marker(job_dir)
    if marker is not None:
        return marker['sandbox']
    # A missing marker must not silently send a new mounted-source job to the
    # base worker. Older saved jobs have neither of these records.
    if (job_dir / 'openshell-policy.json').exists() or (job_dir / 'source-manifest.json').exists():
        raise RuntimeError('작업별 분석 샌드박스 식별 파일이 없습니다. 공유 샌드박스로 전환하지 않습니다.')
    result_path = job_dir / 'result.json'
    if result_path.exists():
        result = json.loads(result_path.read_text(encoding='utf-8'))
        scope = result.get('scope', {}) if isinstance(result, dict) else {}
        if isinstance(scope, dict) and (scope.get('originals_mounted') is True
                                        or scope.get('source_mount_mode') == 'individual_files'):
            raise RuntimeError('작업별 분석 샌드박스 식별 파일이 없습니다. 공유 샌드박스로 전환하지 않습니다.')
    return SANDBOX


def _get_sandbox(sandbox: str):
    live = json.loads(command('sandbox', 'get', sandbox, '--output', 'json'))
    if live.get('name') != sandbox or live.get('phase') != 'Ready':
        raise RuntimeError('분석 샌드박스가 준비되지 않았거나 식별 정보가 일치하지 않습니다.')
    try:
        uuid.UUID(live['id'])
    except (KeyError, ValueError, TypeError) as exc:
        raise RuntimeError('분석 샌드박스 UUID가 올바르지 않습니다.') from exc
    return live


def _verify_policy(policy: dict, files: list[str] | None = None):
    filesystem = policy.get('filesystem_policy', {})
    expected_ro = BASE_READ_ONLY | ({SOURCE_ROOT} if files is not None else set())
    if (filesystem.get('include_workdir') is not False
            or len(filesystem.get('read_only', [])) != len(expected_ro)
            or set(filesystem.get('read_only', [])) != expected_ro
            or len(filesystem.get('read_write', [])) != len(BASE_READ_WRITE)
            or set(filesystem.get('read_write', [])) != BASE_READ_WRITE
            or policy.get('landlock', {}).get('compatibility') != 'hard_requirement'):
        raise RuntimeError('분석용 샌드박스 파일 정책이 예상과 다릅니다. 실행을 중단합니다.')
    if files is not None and (not 1 <= len(files) <= MAX_SOURCE_FILES
                              or len(expected_ro) + len(BASE_READ_WRITE) > MAX_POLICY_PATHS):
        raise RuntimeError('분석용 샌드박스 파일 정책이 OpenShell 범위 제한을 초과했습니다.')
    network = policy.get('network_policies', {})
    endpoints = [endpoint for entry in network.values() for endpoint in entry.get('endpoints', [])]
    if len(endpoints) != 1 or endpoints[0].get('host') != 'inference.local' or endpoints[0].get('enforcement') != 'enforce':
        raise RuntimeError('모델 추론 이외의 네트워크 정책이 발견되었습니다.')
    endpoint = endpoints[0]
    if (endpoint.get('port') != 443 or endpoint.get('protocol') != 'rest'
            or endpoint.get('rules') != [{'allow': {'method': 'POST', 'path': '/v1/chat/completions'}}]
            or endpoint.get('access') == 'full'):
        raise RuntimeError('모델 추론 네트워크 규칙이 예상과 다릅니다.')


def _inspect_container(sandbox: str, live: dict | None = None):
    live = live or _get_sandbox(sandbox)
    container = f"openshell-default--{sandbox}-{live['id']}"
    info = json.loads(_docker('inspect', '--format', '{{json .}}', container, timeout=20))
    if info.get('Name') != '/' + container or not info.get('State', {}).get('Running'):
        raise RuntimeError('분석 컨테이너 식별 정보가 일치하지 않습니다.')
    return info


def container_id(sandbox: str = SANDBOX):
    """Resolve the worker to its verified durable Docker identity."""
    return _inspect_container(sandbox)['Id']


def _verify_mount(info: dict, source_root: Path, files: list[str]):
    # OpenShell 0.0.116 places these in HostConfig.Binds, so compare Docker's
    # effective Mounts array rather than a specific HostConfig representation.
    expected = {_source_alias(index): _file_bind_source(source_root, name)
                for index, name in enumerate(files)}
    expected[BLOCKED_TARGET] = _file_bind_source(source_root, files[0])
    active = [item for item in info.get('Mounts', [])
              if any(item.get('Destination') == base
                     or item.get('Destination', '').startswith(base + '/')
                     for base in (SOURCE_ROOT, '/blocked'))]
    if (len(active) != len(expected)
            or {item.get('Destination') for item in active} != set(expected)):
        raise RuntimeError('선택된 소스 파일 마운트 목록이 예상과 다릅니다.')
    for item in active:
        if (item.get('Type') != 'bind' or item.get('RW') is not False
                or item.get('Source') != expected[item['Destination']]):
            raise RuntimeError('선택된 원본 파일의 읽기 전용 마운트를 확인하지 못했습니다.')


def probe(sandbox: str = SANDBOX, *, job_dir: Path | None = None):
    marker = _marker(job_dir) if job_dir is not None else None
    if marker is not None and sandbox != marker['sandbox']:
        raise RuntimeError('분석 작업과 샌드박스 이름이 일치하지 않습니다.')
    if sandbox != SANDBOX and marker is None:
        raise ValueError('작업별 샌드박스 검증에는 분석 작업 폴더가 필요합니다.')
    live = _get_sandbox(sandbox)
    if marker is not None and live['id'] != marker['sandbox_id']:
        raise RuntimeError('분석 샌드박스 UUID가 생성 시 값과 달라졌습니다.')
    _verify_policy(live['policy'], marker['files'] if marker is not None else None)
    if marker is not None:
        info = _inspect_container(sandbox, live)
        if info.get('Image') != _verify_worker_image():
            raise RuntimeError('작업별 샌드박스의 워커 이미지가 현재 소스 코드와 다릅니다. 새 분석을 시작하세요.')
        _verify_mount(info, Path(marker['source_root']), marker['files'])
    args = ['sandbox', 'exec', '--name', sandbox, '--no-tty', '--timeout', '20', '--',
            '/usr/local/bin/python3', '-B', '/app/agent.py', '--probe']
    if marker is not None:
        args.extend(('--source-allow', _source_alias(0), '--source-deny', BLOCKED_TARGET))
    output = command(*args, timeout=45)
    result = json.loads(output[output.index('{'):])
    if result.get('passed') is not True or (marker is not None and result.get('source_read_allowed') is not True):
        raise RuntimeError('읽기 전용 경계 검증 실패')
    if marker is not None:
        if (result.get('source_unselected_read_denied') is not True
                or result.get('source_write_denied') is not True):
            raise RuntimeError('선택 외 소스의 읽기 차단 검증 실패')
    return result


def _verify_worker_image():
    """The new sandbox must boot from the current worker source, not an old tag."""
    image = json.loads(_docker('image', 'inspect', IMAGE, '--format', '{{json .}}'))
    expected = {name: hashlib.sha256((Path(__file__).resolve().parents[1] / 'worker' / name).read_bytes()).hexdigest()
                for name in IMAGE_CODE_FILES}
    source = ('import hashlib,json; from pathlib import Path; '
              f'names={list(IMAGE_CODE_FILES)!r}; '
              'entries=lambda p: sorted(x.name for x in Path(p).iterdir()) if Path(p).is_dir() else []; '
              'print(json.dumps({"hashes":{n:hashlib.sha256((Path("/app")/n).read_bytes()).hexdigest() for n in names}, '
              '"source_entries":entries("/source"), "blocked_entries":entries("/blocked")}))')
    actual = json.loads(_docker('run', '--rm', '--entrypoint', '/usr/local/bin/python3', IMAGE,
                                '-B', '-c', source, timeout=45))
    if (actual.get('hashes') != expected or actual.get('source_entries') != []
            or actual.get('blocked_entries') != []):
        raise RuntimeError('s2r-review-worker:local 이미지 코드가 현재 워커 소스와 다릅니다. setup_worker.py로 이미지를 다시 빌드하세요.')
    return image['Id']


def _quarantine_container(sandbox: str, sandbox_id: str):
    """Find only the Docker container with this OpenShell name and durable ID."""
    container = f'openshell-default--{sandbox}-{sandbox_id}'
    try:
        info = json.loads(_docker('inspect', '--format', '{{json .}}', container, timeout=20))
    except RuntimeError as exc:
        if 'no such object' in str(exc).lower() or 'no such container' in str(exc).lower():
            return None
        raise
    labels = (info.get('Config') or {}).get('Labels') or {}
    if (not re.fullmatch(r'[a-f0-9]{64}', info.get('Id', ''))
            or info.get('Name') != '/' + container
            or labels.get('openshell.ai/sandbox-id') != sandbox_id
            or labels.get('openshell.ai/sandbox-name') != sandbox):
        raise RuntimeError('격리 대상 Docker 컨테이너 식별 정보가 일치하지 않습니다.')
    return info


def quarantine_job_sandbox(job_dir: Path) -> bool:
    """Remove this job's sandbox, or stop its exact container if removal fails.

    A job without a marker can only be an interrupted creation; in that case
    the gateway's full job label is required before acting on a container.
    """
    marker = _marker(job_dir)
    sandbox = marker['sandbox'] if marker is not None else _job_name(job_dir)
    gateway_missing = False
    try:
        live = json.loads(command('sandbox', 'get', sandbox, '--output', 'json'))
    except RuntimeError as exc:
        gateway_missing = 'not found' in str(exc).lower()
        if marker is None and not gateway_missing:
            raise RuntimeError('작업 표식이 없어 샌드박스 소유권을 확인할 수 없습니다.') from exc
        live = None
    if live is not None:
        sandbox_id = live.get('id')
        try:
            if (live.get('name') != sandbox
                    or live.get('labels', {}).get('s2r-review-job') != job_dir.name
                    or str(uuid.UUID(sandbox_id)) != sandbox_id
                    or (marker is not None and marker['sandbox_id'] != sandbox_id)):
                raise ValueError('Sandbox identity mismatch')
        except (TypeError, ValueError, AttributeError) as exc:
            raise RuntimeError('격리 대상 OpenShell 샌드박스의 작업 표식 또는 UUID가 일치하지 않습니다.') from exc
    elif marker is not None:
        sandbox_id = marker['sandbox_id']
    else:
        # Docker can outlive a failed gateway transaction. Without a durable
        # UUID or matching gateway label it would be unsafe to delete by name.
        prefix = f'openshell-default--{sandbox}-'
        names = _docker('ps', '-a', '--format', '{{.Names}}', timeout=20).splitlines()
        if any(name.startswith(prefix) for name in names):
            raise RuntimeError('작업 표식이 없는 OpenShell 컨테이너가 남아 있습니다. 자동 격리할 수 없습니다.')
        return True

    info = _quarantine_container(sandbox, sandbox_id)
    if live is not None:
        try:
            command('sandbox', 'delete', sandbox, timeout=120)
        except Exception:
            # Docker stop below is the fail-closed fallback for a gateway
            # transaction that refuses to delete the identified sandbox.
            if info is None:
                raise RuntimeError('OpenShell 삭제가 실패했고 컨테이너 상태를 확인할 수 없습니다.')
        else:
            info = _quarantine_container(sandbox, sandbox_id)
            if info is None:
                (job_dir / 'sandbox.json').unlink(missing_ok=True)
                return True
    elif info is None:
        if not gateway_missing:
            raise RuntimeError('OpenShell 상태를 확인할 수 없어 격리 완료를 증명할 수 없습니다.')
        (job_dir / 'sandbox.json').unlink(missing_ok=True)
        return True

    if info.get('State', {}).get('Running') is True:
        _docker('stop', info['Id'], timeout=60)
        info = _quarantine_container(sandbox, sandbox_id)
    if info is not None and info.get('State', {}).get('Running') is True:
        raise RuntimeError('원본 마운트가 있는 Docker 컨테이너가 계속 실행 중입니다.')
    return True


def _create_job_sandbox(job_dir: Path, project_root: Path, names: list[str]):
    sandbox = _job_name(job_dir)
    base = _get_sandbox(SANDBOX)['policy']
    _verify_policy(base)
    policy = copy.deepcopy(base)
    policy['filesystem_policy']['read_only'].append(SOURCE_ROOT)
    _verify_policy(policy, names)
    image_id = _verify_worker_image()
    policy_path = job_dir / 'openshell-policy.json'
    policy_path.write_text(json.dumps(policy, ensure_ascii=False, indent=2), encoding='utf-8')
    mounts = [{'type': 'bind', 'source': _file_bind_source(project_root, name),
               'target': _source_alias(index), 'read_only': True}
              for index, name in enumerate(names)]
    # The same first file is mounted outside the Landlock allowlist. A failed
    # read therefore proves policy enforcement rather than file nonexistence.
    mounts.append({'type': 'bind', 'source': _file_bind_source(project_root, names[0]),
                   'target': BLOCKED_TARGET, 'read_only': True})
    driver = {'docker': {'mounts': mounts}}
    try:
        command('sandbox', 'create', '--name', sandbox, '--from', IMAGE,
                '--label', f's2r-review-job={job_dir.name}',
                '--policy', wsl_path(policy_path), '--driver-config-json',
                json.dumps(driver, ensure_ascii=False, separators=(',', ':')),
                '--cpu', '1', '--memory', '1Gi', '--no-auto-providers',
                '--detach', '--', '/bin/sleep', 'infinity', timeout=600)
        deadline = time.monotonic() + 120
        while True:
            live = json.loads(command('sandbox', 'get', sandbox, '--output', 'json'))
            if live.get('phase') == 'Ready':
                break
            if live.get('phase') in {'Error', 'Stopped'} or time.monotonic() >= deadline:
                raise RuntimeError(f"분석 샌드박스 시작에 실패했습니다: {live.get('phase')}")
            time.sleep(2)
        if (live.get('name') != sandbox
                or live.get('labels', {}).get('s2r-review-job') != job_dir.name):
            raise RuntimeError('새 분석 샌드박스 이름과 작업 표식이 예상과 다릅니다.')
        _verify_policy(live['policy'], names)
        info = _inspect_container(sandbox, live)
        if info.get('Image') != image_id:
            raise RuntimeError('새 분석 샌드박스의 워커 이미지가 예상과 다릅니다.')
        _verify_mount(info, project_root, names)
        marker = {'sandbox': sandbox, 'sandbox_id': live['id'],
                  'source_root': str(project_root), 'files': names,
                  'source_deny': BLOCKED_TARGET,
                  'mount_mode': 'selected_file_binds_v1'}
        (job_dir / 'sandbox.json').write_text(json.dumps(marker, ensure_ascii=False, indent=2), encoding='utf-8')
    except Exception as creation_error:
        # The CLI can fail after the gateway has already created the sandbox.
        # Verify the job label and durable identity even when create failed.
        try:
            quarantine_job_sandbox(job_dir)
        except Exception as quarantine_error:
            raise RuntimeError(f'샌드박스 생성 실패: {creation_error}; '
                               f'격리 실패: {quarantine_error}') from quarantine_error
        raise
    return sandbox


def stage_input(source: Path, identifier: str, sandbox: str = SANDBOX):
    """Provision only a verified container; agent code never gets Docker access."""
    if not re.fullmatch(r'[a-zA-Z0-9-]+', identifier):
        raise ValueError('Invalid snapshot identifier')
    identity = container_id(sandbox)
    # Target the verified durable container ID, not an unverified reusable name.
    _docker('cp', wsl_path(source), f'{identity}:/input/{identifier}.json')


def run(job_dir: Path, update, project_root: Path):
    bundle = json.loads((job_dir / 'bundle.json').read_text(encoding='utf-8'))
    root, names = _source_manifest(project_root, bundle)
    update('boundary', 15, '선택한 소스 파일의 OpenShell 읽기 경계를 설정합니다.')
    sandbox = _create_job_sandbox(job_dir, root, names)
    try:
        boundary = probe(sandbox, job_dir=job_dir)
        update('snapshot_upload', 25, '선택한 소스 경로와 해시를 전달합니다.')
        name = job_dir.name
        manifest = {'kind': 'mounted_source_manifest', 'files': names,
                    'source_hash': bundle['source_hash']}
        input_file = job_dir / 'source-manifest.json'
        input_file.write_text(json.dumps(manifest, ensure_ascii=False), encoding='utf-8')
        stage_input(input_file, name, sandbox)
        update('analyzing', 50, 'Nemotron이 허용된 원본 소스에서 엔드포인트와 취약점 시나리오를 제안합니다.')
        command('sandbox', 'exec', '--name', sandbox, '--no-tty', '--timeout', '210', '--',
                '/usr/local/bin/python3', '-B', '/app/agent.py', '--input', f'/input/{name}.json',
                '--source-root', '/source', '--output', f'/output/{name}.json', '--ai', timeout=230)
        update('saving', 90, '분석 결과와 근거를 저장합니다.')
        command('sandbox', 'download', sandbox, f'/output/{name}.json', wsl_path(job_dir / 'worker-result.json'))
        result = json.loads((job_dir / 'worker-result.json').read_text(encoding='utf-8'))
        result['boundary'] = boundary
        result['sandbox'] = sandbox
        return result
    except Exception as analysis_error:
        try:
            quarantine_job_sandbox(job_dir)
        except Exception as quarantine_error:
            raise RuntimeError(f'분석 실패: {analysis_error}; '
                               f'샌드박스 격리 실패: {quarantine_error}') from quarantine_error
        raise


def _run_worker(run_dir: Path, label: str, payload: dict, worker: str, timeout: int):
    if not re.fullmatch(r'[a-f0-9-]{36}', run_dir.name):
        raise ValueError('Invalid run identifier')
    job_dir = run_dir.parent.parent
    sandbox = sandbox_for_job(job_dir)
    probe(sandbox, job_dir=job_dir if sandbox != SANDBOX else None)
    name = run_dir.name + '-' + label
    source = run_dir / f'{label}-input.json'
    source.write_text(json.dumps(payload, ensure_ascii=False), encoding='utf-8')
    stage_input(source, name, sandbox)
    command('sandbox', 'exec', '--name', sandbox, '--no-tty', '--timeout', str(timeout), '--',
            '/usr/local/bin/python3', '-B', f'/app/{worker}',
            '--input', f'/input/{name}.json', '--output', f'/output/{name}.json', timeout=timeout + 20)
    destination = run_dir / f'{label}-worker-result.json'
    command('sandbox', 'download', sandbox, f'/output/{name}.json', wsl_path(destination))
    return json.loads(destination.read_text(encoding='utf-8'))


def generate_ai_checks(run_dir: Path, selected: list[dict], *, label='scripts'):
    """Generate source-specific probe/evaluator plans in inference-only OpenShell."""
    if not 1 <= len(selected) <= 10:
        raise ValueError('AI 점검 계획은 1~10개의 선택된 시나리오만 처리합니다.')
    expected = {row['id'] for row in selected}
    if len(expected) != len(selected):
        raise ValueError('중복된 AI 점검 시나리오가 있습니다.')
    result = _run_worker(run_dir, label, {'scenarios': selected}, 'script_agent.py', 220 * len(selected))
    checks = result.get('checks')
    if not isinstance(checks, list) or len(checks) != len(selected):
        raise ValueError('AI 점검 계획의 항목 수가 일치하지 않습니다.')
    plans = {}
    for check in checks:
        if (not isinstance(check, dict) or set(check) != {'id', 'probe', 'source', 'reason'}
                or check['id'] not in expected or check['id'] in plans):
            raise ValueError('AI 점검 계획의 시나리오 ID 또는 형식이 올바르지 않습니다.')
        plans[check['id']] = {key: check[key] for key in ('probe', 'source', 'reason')}
    return plans


def generate_ai_patches(run_dir: Path, payload: dict, *, label='patches'):
    """Ask Nemotron for bounded exact line edits; never apply them to source."""
    if not payload.get('scenarios'):
        return {'patches': []}
    return _run_worker(run_dir, label, payload, 'patch_agent.py', 400 * len(payload['scenarios']))
