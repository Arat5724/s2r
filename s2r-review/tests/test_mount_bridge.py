"""Host OpenShell mount setup must grant named source files only."""

import copy
import hashlib
import json
import uuid

import pytest

from review import bridge


BASE_POLICY = {
    'version': 1,
    'filesystem_policy': {
        'include_workdir': False,
        'read_only': sorted(bridge.BASE_READ_ONLY),
        'read_write': sorted(bridge.BASE_READ_WRITE),
    },
    'landlock': {'compatibility': 'hard_requirement'},
    'network_policies': {'managed_inference': {
        'name': 'managed_inference',
        'binaries': [{'path': '/usr/local/bin/python3'}],
        'endpoints': [{'host': 'inference.local', 'port': 443,
                       'protocol': 'rest', 'enforcement': 'enforce',
                       'rules': [{'allow': {'method': 'POST', 'path': '/v1/chat/completions'}}]}],
    }},
}


def _bundle(files):
    identity = json.dumps(files, sort_keys=True, ensure_ascii=False,
                          separators=(',', ':')).encode('utf-8')
    return {'files': files, 'source_hash': hashlib.sha256(identity).hexdigest()}


def _job(tmp_path):
    job = tmp_path / str(uuid.uuid4())
    job.mkdir()
    return job


def test_mount_policy_grants_only_selected_leaf_and_read_only_bind(tmp_path, monkeypatch):
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'app.py').write_text('print("selected")\n', encoding='utf-8')
    (project / '.env').write_text('excluded=1\n', encoding='utf-8')
    job = _job(tmp_path)
    calls = []
    sandbox = bridge._job_name(job)
    sandbox_id = str(uuid.uuid4())
    live = {'name': sandbox, 'id': sandbox_id, 'phase': 'Ready',
            'labels': {'s2r-review-job': job.name}}

    monkeypatch.setattr(bridge, '_get_sandbox', lambda name: {'policy': copy.deepcopy(BASE_POLICY)})
    monkeypatch.setattr(bridge, '_verify_worker_image', lambda: 'sha256:image')
    monkeypatch.setattr(bridge, '_inspect_container', lambda *_: {'Image': 'sha256:image'})
    monkeypatch.setattr(bridge, '_verify_mount', lambda *_: None)

    def fake_command(*args, **_kwargs):
        calls.append(args)
        if args[:2] == ('sandbox', 'get'):
            return json.dumps({**live, 'policy': json.loads((job / 'openshell-policy.json').read_text())})
        return ''

    monkeypatch.setattr(bridge, 'command', fake_command)
    assert bridge._create_job_sandbox(job, project.resolve(), ['app.py']) == sandbox

    policy = json.loads((job / 'openshell-policy.json').read_text(encoding='utf-8'))
    assert set(policy['filesystem_policy']['read_only']) == bridge.BASE_READ_ONLY | {'/source'}
    assert '/source/app.py' not in policy['filesystem_policy']['read_only']
    assert set(policy['filesystem_policy']['read_write']) == bridge.BASE_READ_WRITE
    create = next(call for call in calls if call[:2] == ('sandbox', 'create'))
    driver = json.loads(create[create.index('--driver-config-json') + 1])
    assert driver == {'docker': {'mounts': [
        {'type': 'bind', 'source': bridge.wsl_path(project / 'app.py'),
         'target': '/source/0000', 'read_only': True},
        {'type': 'bind', 'source': bridge.wsl_path(project / 'app.py'),
         'target': '/blocked/0000', 'read_only': True}]}}
    marker = json.loads((job / 'sandbox.json').read_text(encoding='utf-8'))
    assert marker['source_deny'] == '/blocked/0000'
    assert marker['mount_mode'] == 'selected_file_binds_v1'
    assert marker['sandbox_id'] == sandbox_id


def test_analysis_stages_manifest_without_source_body(tmp_path, monkeypatch):
    project = tmp_path / 'project'
    project.mkdir()
    source = 'PRIVATE_SOURCE_CANARY = 123\n'
    (project / 'app.py').write_bytes(source.encode('utf-8'))
    job = _job(tmp_path)
    (job / 'bundle.json').write_text(json.dumps(_bundle({'app.py': source})), encoding='utf-8')
    sandbox = bridge._job_name(job)
    staged = []
    monkeypatch.setattr(bridge, '_create_job_sandbox', lambda *_: sandbox)
    monkeypatch.setattr(bridge, 'probe', lambda *_args, **_kwargs: {'passed': True})
    monkeypatch.setattr(bridge, 'stage_input', lambda path, name, target: staged.append(
        (json.loads(path.read_text(encoding='utf-8')), name, target)))

    def fake_command(*args, **_kwargs):
        if args[:2] == ('sandbox', 'download'):
            (job / 'worker-result.json').write_text('{}', encoding='utf-8')
        return ''

    monkeypatch.setattr(bridge, 'command', fake_command)
    result = bridge.run(job, lambda *_: None, project)
    assert staged == [({'kind': 'mounted_source_manifest', 'files': ['app.py'],
                        'source_hash': _bundle({'app.py': source})['source_hash']}, job.name, sandbox)]
    assert source not in (job / 'source-manifest.json').read_text(encoding='utf-8')
    assert result['sandbox'] == sandbox


def test_job_marker_legacy_fallback_and_probe_rejects_uuid_swap(tmp_path, monkeypatch):
    arbitrary = tmp_path / 'old-analysis'
    arbitrary.mkdir()
    assert bridge.sandbox_for_job(arbitrary) == bridge.SANDBOX

    job = _job(tmp_path)
    sandbox = bridge._job_name(job)
    marker = {'sandbox': sandbox, 'sandbox_id': str(uuid.uuid4()),
              'source_root': str(tmp_path), 'files': ['app.py'],
              'source_deny': '/blocked/0000', 'mount_mode': 'selected_file_binds_v1'}
    (job / 'sandbox.json').write_text(json.dumps(marker), encoding='utf-8')
    assert bridge.sandbox_for_job(job) == sandbox
    legacy = 'ar-' + uuid.UUID(job.name).hex[:16]
    (job / 'sandbox.json').write_text(json.dumps({**marker, 'sandbox': legacy}), encoding='utf-8')
    assert bridge.sandbox_for_job(job) == legacy
    (job / 'sandbox.json').write_text(json.dumps(marker), encoding='utf-8')
    monkeypatch.setattr(bridge, '_get_sandbox', lambda name: {
        'name': name, 'id': str(uuid.uuid4()), 'policy': BASE_POLICY})
    with pytest.raises(RuntimeError, match='UUID'):
        bridge.probe(sandbox, job_dir=job)


def test_mounted_job_without_marker_cannot_fall_back_to_shared_worker(tmp_path):
    job = _job(tmp_path)
    (job / 'result.json').write_text(json.dumps({'scope': {'originals_mounted': True}}), encoding='utf-8')
    with pytest.raises(RuntimeError, match='공유 샌드박스로 전환하지 않습니다'):
        bridge.sandbox_for_job(job)
    (job / 'result.json').unlink()
    (job / 'source-manifest.json').write_text('{}', encoding='utf-8')
    with pytest.raises(RuntimeError, match='공유 샌드박스로 전환하지 않습니다'):
        bridge.sandbox_for_job(job)


def test_policy_rejects_broad_source_grant():
    expected = copy.deepcopy(BASE_POLICY)
    expected['filesystem_policy']['read_only'].append('/source')
    bridge._verify_policy(expected, ['app.py'])
    expected['filesystem_policy']['read_only'].append('/blocked')
    with pytest.raises(RuntimeError, match='파일 정책'):
        bridge._verify_policy(expected, ['app.py'])


def test_mount_inspection_requires_exact_file_binds(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'app.py').write_bytes(b'print(1)\n')
    (project / 'requirements.txt').write_bytes(b'fastapi\n')
    first = bridge.wsl_path(project / 'app.py')
    second = bridge.wsl_path(project / 'requirements.txt')
    mounts = [
        {'Type': 'bind', 'Source': first, 'Destination': '/source/0000', 'RW': False},
        {'Type': 'bind', 'Source': second, 'Destination': '/source/0001', 'RW': False},
        {'Type': 'bind', 'Source': first, 'Destination': '/blocked/0000', 'RW': False},
    ]
    bridge._verify_mount({'Mounts': mounts}, project, ['app.py', 'requirements.txt'])
    with pytest.raises(RuntimeError, match='마운트 목록'):
        bridge._verify_mount({'Mounts': mounts + [
            {'Type': 'bind', 'Source': bridge.wsl_path(project),
             'Destination': '/source', 'RW': False}]},
            project, ['app.py', 'requirements.txt'])
    writable = copy.deepcopy(mounts)
    writable[0]['RW'] = True
    with pytest.raises(RuntimeError, match='읽기 전용'):
        bridge._verify_mount({'Mounts': writable}, project, ['app.py', 'requirements.txt'])


def test_job_probe_checks_flat_allowed_and_blocked_aliases(tmp_path, monkeypatch):
    job = _job(tmp_path)
    sandbox = bridge._job_name(job)
    sandbox_id = str(uuid.uuid4())
    marker = {'sandbox': sandbox, 'sandbox_id': sandbox_id,
              'source_root': str(tmp_path), 'files': ['app.py'],
              'source_deny': '/blocked/0000', 'mount_mode': 'selected_file_binds_v1'}
    (job / 'sandbox.json').write_text(json.dumps(marker), encoding='utf-8')
    policy = copy.deepcopy(BASE_POLICY)
    policy['filesystem_policy']['read_only'].append('/source')
    monkeypatch.setattr(bridge, '_get_sandbox', lambda name: {
        'name': name, 'id': sandbox_id, 'policy': policy})
    container = {'Mounts': [], 'Image': 'sha256:image'}
    monkeypatch.setattr(bridge, '_inspect_container', lambda *_: container)
    monkeypatch.setattr(bridge, '_verify_worker_image', lambda: 'sha256:image')
    monkeypatch.setattr(bridge, '_verify_mount', lambda *_: None)
    observed = []
    checks = {'passed': True, 'source_read_allowed': True,
              'source_write_denied': True, 'source_unselected_read_denied': True}

    def fake_command(*args, **_kwargs):
        observed.append(args)
        return json.dumps(checks)

    monkeypatch.setattr(bridge, 'command', fake_command)
    assert bridge.probe(sandbox, job_dir=job)['passed'] is True
    assert ('--source-allow', '/source/0000') == observed[0][-4:-2]
    assert ('--source-deny', '/blocked/0000') == observed[0][-2:]
    checks['source_unselected_read_denied'] = False
    with pytest.raises(RuntimeError, match='차단 검증 실패'):
        bridge.probe(sandbox, job_dir=job)
    checks['source_unselected_read_denied'] = True
    container['Image'] = 'sha256:outdated'
    with pytest.raises(RuntimeError, match='워커 이미지'):
        bridge.probe(sandbox, job_dir=job)


@pytest.mark.parametrize('own_label,should_delete', [(True, True), (False, False)])
def test_failed_creation_cleans_up_only_its_own_sandbox(tmp_path, monkeypatch, own_label, should_delete):
    project = tmp_path / 'project'
    project.mkdir()
    job = _job(tmp_path)
    sandbox = bridge._job_name(job)
    calls = []
    monkeypatch.setattr(bridge, '_get_sandbox', lambda name: {'policy': copy.deepcopy(BASE_POLICY)})
    monkeypatch.setattr(bridge, '_verify_worker_image', lambda: 'sha256:image')
    monkeypatch.setattr(bridge, '_quarantine_container', lambda *_: None)

    def fake_command(*args, **_kwargs):
        calls.append(args)
        if args[:2] == ('sandbox', 'get'):
            # The active policy is missing its selected source leaf.
            return json.dumps({'name': sandbox, 'id': str(uuid.uuid4()), 'phase': 'Ready',
                               'labels': {'s2r-review-job': job.name if own_label else 'another-job'},
                               'policy': BASE_POLICY})
        return ''

    monkeypatch.setattr(bridge, 'command', fake_command)
    with pytest.raises(RuntimeError) as error:
        bridge._create_job_sandbox(job, project, ['app.py'])
    assert any(call[:2] == ('sandbox', 'delete') for call in calls) is should_delete
    if not own_label:
        assert '격리 실패' in str(error.value)
    assert not (job / 'sandbox.json').exists()


def test_create_command_error_still_checks_for_labelled_orphan(tmp_path, monkeypatch):
    project = tmp_path / 'project'
    project.mkdir()
    job = _job(tmp_path)
    sandbox = bridge._job_name(job)
    calls = []
    sandbox_id = str(uuid.uuid4())
    monkeypatch.setattr(bridge, '_get_sandbox', lambda name: {'policy': copy.deepcopy(BASE_POLICY)})
    monkeypatch.setattr(bridge, '_verify_worker_image', lambda: 'sha256:image')
    monkeypatch.setattr(bridge, '_quarantine_container', lambda *_: None)

    def fake_command(*args, **_kwargs):
        calls.append(args)
        if args[:2] == ('sandbox', 'create'):
            raise RuntimeError('gateway returned an error after creation')
        if args[:2] == ('sandbox', 'get'):
            return json.dumps({'name': sandbox, 'id': sandbox_id,
                               'labels': {'s2r-review-job': job.name}})
        return ''

    monkeypatch.setattr(bridge, 'command', fake_command)
    with pytest.raises(RuntimeError, match='after creation'):
        bridge._create_job_sandbox(job, project, ['app.py'])
    assert any(call[:2] == ('sandbox', 'delete') for call in calls)


@pytest.mark.parametrize('stop_succeeds', [True, False])
def test_quarantine_stops_exact_container_when_gateway_delete_fails(tmp_path, monkeypatch, stop_succeeds):
    job = _job(tmp_path)
    sandbox = bridge._job_name(job)
    sandbox_id = str(uuid.uuid4())
    marker = {'sandbox': sandbox, 'sandbox_id': sandbox_id,
              'source_root': str(tmp_path), 'files': ['app.py'],
              'source_deny': '/blocked/0000', 'mount_mode': 'selected_file_binds_v1'}
    (job / 'sandbox.json').write_text(json.dumps(marker), encoding='utf-8')
    container_id = 'a' * 64
    container_name = f'openshell-default--{sandbox}-{sandbox_id}'
    running = True
    calls = []

    def fake_command(*args, **_kwargs):
        calls.append(args)
        if args[:2] == ('sandbox', 'get'):
            return json.dumps({'name': sandbox, 'id': sandbox_id,
                               'labels': {'s2r-review-job': job.name}})
        if args[:2] == ('sandbox', 'delete'):
            raise RuntimeError('delete failed')
        raise AssertionError(args)

    def fake_docker(*args, **_kwargs):
        nonlocal running
        calls.append(args)
        if args[0] == 'inspect':
            return json.dumps({'Id': container_id, 'Name': '/' + container_name,
                               'Config': {'Labels': {'openshell.ai/sandbox-id': sandbox_id,
                                                     'openshell.ai/sandbox-name': sandbox}},
                               'State': {'Running': running}})
        if args[0] == 'stop':
            assert args[1] == container_id
            if stop_succeeds:
                running = False
            return container_id
        raise AssertionError(args)

    monkeypatch.setattr(bridge, 'command', fake_command)
    monkeypatch.setattr(bridge, '_docker', fake_docker)
    if stop_succeeds:
        assert bridge.quarantine_job_sandbox(job) is True
        assert running is False
    else:
        with pytest.raises(RuntimeError, match='계속 실행'):
            bridge.quarantine_job_sandbox(job)
    assert any(call[:2] == ('sandbox', 'delete') for call in calls)
    assert (job / 'sandbox.json').exists()


def test_quarantine_rejects_wrong_job_label_without_docker_action(tmp_path, monkeypatch):
    job = _job(tmp_path)
    sandbox = bridge._job_name(job)
    marker = {'sandbox': sandbox, 'sandbox_id': str(uuid.uuid4()),
              'source_root': str(tmp_path), 'files': ['app.py'],
              'source_deny': '/blocked/0000', 'mount_mode': 'selected_file_binds_v1'}
    (job / 'sandbox.json').write_text(json.dumps(marker), encoding='utf-8')
    monkeypatch.setattr(bridge, 'command', lambda *_args, **_kwargs: json.dumps({
        'name': sandbox, 'id': marker['sandbox_id'], 'labels': {'s2r-review-job': 'another-job'}}))
    monkeypatch.setattr(bridge, '_docker', lambda *_args, **_kwargs: pytest.fail('Unexpected Docker action'))
    with pytest.raises(RuntimeError, match='작업 표식'):
        bridge.quarantine_job_sandbox(job)
