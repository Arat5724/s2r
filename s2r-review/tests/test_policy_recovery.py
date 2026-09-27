"""A crashed runtime check must not leave a temporary network grant usable."""

import copy
import json
import uuid

import pytest
from fastapi import HTTPException

from review import bridge, main, runtime


def _baseline():
    return {
        'version': 1,
        'filesystem_policy': {
            'include_workdir': False,
            'read_only': sorted(bridge.BASE_READ_ONLY | {'/source'}),
            'read_write': sorted(bridge.BASE_READ_WRITE),
        },
        'landlock': {'compatibility': 'hard_requirement'},
        'process': {'run_as_user': 'sandbox', 'run_as_group': 'sandbox'},
        'network_policies': {'managed_inference': {
            'name': 'managed_inference',
            'binaries': [{'path': '/usr/local/bin/python3'}],
            'endpoints': [{'host': 'inference.local', 'port': 443, 'protocol': 'rest',
                           'enforcement': 'enforce',
                           'rules': [{'allow': {'method': 'POST', 'path': '/v1/chat/completions'}}]}],
        }},
    }


def _job(tmp_path):
    job = tmp_path / 'jobs' / str(uuid.uuid4())
    job.mkdir(parents=True)
    sandbox = bridge._job_name(job)
    identity = str(uuid.uuid4())
    marker = {'sandbox': sandbox, 'sandbox_id': identity,
              'source_root': str(tmp_path), 'files': ['app.py'],
              'source_deny': bridge.BLOCKED_TARGET,
              'mount_mode': 'selected_file_binds_v1'}
    (job / 'sandbox.json').write_text(json.dumps(marker), encoding='utf-8')
    baseline = _baseline()
    (job / 'openshell-policy.json').write_text(json.dumps(baseline), encoding='utf-8')
    return job, sandbox, identity, baseline


def _stub_identity(monkeypatch, job, sandbox, identity, current):
    inspections = []

    def get(name):
        assert name == sandbox
        return {'name': sandbox, 'id': identity, 'phase': 'Ready',
                'labels': {'s2r-review-job': job.name},
                'policy': copy.deepcopy(current['policy'])}

    monkeypatch.setattr(bridge, '_get_sandbox', get)
    monkeypatch.setattr(bridge, '_inspect_container', lambda name, live: inspections.append((name, live['id'])) or {
        'Mounts': [], 'Config': {'Labels': {'openshell.ai/sandbox-id': identity,
                                           'openshell.ai/sandbox-name': sandbox}}})
    monkeypatch.setattr(bridge, '_verify_mount', lambda *args: inspections.append('mount'))
    monkeypatch.setattr(bridge, 'probe', lambda **kwargs: inspections.append(('probe', kwargs)) or {'passed': True})
    return inspections


def test_startup_removes_stranded_runtime_target_and_probes_boundary(tmp_path, monkeypatch):
    job, sandbox, identity, baseline = _job(tmp_path)
    current = {'policy': copy.deepcopy(baseline)}
    current['policy']['network_policies']['runtime_target'] = {'name': 'runtime_target'}
    inspections = _stub_identity(monkeypatch, job, sandbox, identity, current)
    applied = []

    def set_policy(policy, folder, suffix, *, sandbox=None):
        applied.append((policy, folder, suffix, sandbox))
        current['policy'] = copy.deepcopy(policy)

    monkeypatch.setattr(runtime, 'set_policy', set_policy)
    monkeypatch.setattr(bridge, 'quarantine_job_sandbox', lambda *_: pytest.fail('healthy recovery quarantined'))
    assert runtime.recover_job_sandbox(job) == {'state': 'restored'}
    assert applied == [(baseline, job, 'startup-restored', sandbox)]
    assert 'mount' in inspections
    assert ('probe', {'sandbox': sandbox, 'job_dir': job}) in inspections


def test_startup_verifies_healthy_sandbox_without_policy_change(tmp_path, monkeypatch):
    job, sandbox, identity, baseline = _job(tmp_path)
    inspections = _stub_identity(monkeypatch, job, sandbox, identity, {'policy': baseline})
    monkeypatch.setattr(runtime, 'set_policy', lambda *_args, **_kwargs: pytest.fail('healthy policy changed'))
    monkeypatch.setattr(bridge, 'quarantine_job_sandbox', lambda *_: pytest.fail('healthy sandbox quarantined'))
    assert runtime.recover_job_sandbox(job) == {'state': 'verified'}
    assert ('probe', {'sandbox': sandbox, 'job_dir': job}) in inspections


def test_startup_quarantines_when_restore_fails(tmp_path, monkeypatch):
    job, sandbox, identity, baseline = _job(tmp_path)
    current = {'policy': copy.deepcopy(baseline)}
    current['policy']['network_policies']['runtime_target'] = {'name': 'runtime_target'}
    _stub_identity(monkeypatch, job, sandbox, identity, current)
    calls = []

    def cannot_restore(*_args, **_kwargs):
        calls.append('restore')
        raise RuntimeError('restore failed')

    monkeypatch.setattr(runtime, 'set_policy', cannot_restore)
    monkeypatch.setattr(runtime.time, 'sleep', lambda *_: None)
    monkeypatch.setattr(bridge, 'quarantine_job_sandbox', lambda folder: calls.append(folder) or True)
    assert runtime.recover_job_sandbox(job)['state'] == 'quarantined'
    assert calls == ['restore', 'restore', 'restore', job]
    assert json.loads((job / 'sandbox-recovery.json').read_text(encoding='utf-8'))['state'] == 'quarantined'


def test_startup_rejects_swapped_uuid_before_policy_restore(tmp_path, monkeypatch):
    job, sandbox, identity, baseline = _job(tmp_path)
    current = {'policy': copy.deepcopy(baseline)}
    monkeypatch.setattr(bridge, '_get_sandbox', lambda _name: {
        'name': sandbox, 'id': str(uuid.uuid4()), 'phase': 'Ready',
        'labels': {'s2r-review-job': job.name}, 'policy': current['policy']})
    called = []

    def refuse_unknown_identity(folder):
        called.append(folder)
        raise RuntimeError('identity mismatch')

    monkeypatch.setattr(bridge, 'quarantine_job_sandbox', refuse_unknown_identity)
    monkeypatch.setattr(runtime, 'set_policy', lambda *_args, **_kwargs: pytest.fail('restored swapped UUID'))
    with pytest.raises(RuntimeError, match='앱 시작을 중단합니다'):
        runtime.recover_job_sandbox(job)
    assert called == [job]
    assert json.loads((job / 'sandbox-recovery.json').read_text(encoding='utf-8'))['state'] == 'quarantining'


def test_failed_runtime_restore_quarantines_own_job(tmp_path, monkeypatch):
    job, sandbox, _identity, baseline = _job(tmp_path)
    run = job / 'runs' / str(uuid.uuid4())
    run.mkdir(parents=True)
    current = {'policy': copy.deepcopy(baseline)}
    calls = []

    def command(*args, **_kwargs):
        if args[:2] == ('sandbox', 'get'):
            return json.dumps({'policy': current['policy']})
        if args[:2] == ('sandbox', 'exec'):
            raise RuntimeError('request failed')
        return ''

    def set_policy(policy, folder, suffix):
        calls.append(suffix)
        if suffix == 'restored':
            raise RuntimeError('restore failed')
        current['policy'] = copy.deepcopy(policy)

    monkeypatch.setattr(bridge, 'sandbox_for_job', lambda _folder: sandbox)
    monkeypatch.setattr(bridge, 'command', command)
    monkeypatch.setattr(bridge, 'stage_input', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(bridge, 'probe', lambda **_kwargs: {'passed': True})
    monkeypatch.setattr(bridge, 'quarantine_job_sandbox', lambda folder: calls.append(folder) or True)
    monkeypatch.setattr(runtime, 'set_policy', set_policy)
    monkeypatch.setattr(runtime.time, 'sleep', lambda *_: None)
    routes = [{'method': 'GET', 'path': '/', 'endpoint_id': 'one',
               'scenario_id': 'a' * 16, 'probe_kind': 'ai_generic',
               'query_key': 'q', 'probe_value': 's2r_probe_12345678'}]
    with pytest.raises(RuntimeError, match='격리했습니다'):
        runtime.observe(run, runtime.validate_target('http://127.0.0.1:8010'), routes, lambda *_: None)
    assert calls == ['active', 'restored', 'restored', 'restored', job]
    assert json.loads((job / 'sandbox-recovery.json').read_text(encoding='utf-8'))['state'] == 'quarantined'


def test_launcher_marks_stale_runs_and_blocks_quarantined_run(tmp_path, monkeypatch):
    job, _sandbox, _identity, _baseline_policy = _job(tmp_path)
    data = tmp_path
    run = job / 'runs' / str(uuid.uuid4())
    run.mkdir(parents=True)
    main.write_json(job / 'status.json', {'state': 'completed'})
    main.write_json(run / 'status.json', {'state': 'running'})
    monkeypatch.setattr(main, 'DATA', data)
    monkeypatch.setattr(runtime, 'recover_job_sandbox', lambda _job: {'state': 'quarantined'})
    main.recover_interrupted_jobs()
    assert main.read_json(run / 'status.json')['state'] == 'interrupted'
    assert main.read_json(job / 'sandbox-recovery.json')['state'] == 'quarantined'
    monkeypatch.setattr(main, 'completed_job', lambda *_: job)
    with pytest.raises(HTTPException) as error:
        main.create_run(job.name, main.RunRequest(selection_revision=1))
    assert error.value.status_code == 409


def test_startup_quarantines_unmarked_created_sandbox(tmp_path, monkeypatch):
    job = tmp_path / 'jobs' / str(uuid.uuid4())
    job.mkdir(parents=True)
    (job / 'openshell-policy.json').write_text('{}', encoding='utf-8')
    main.write_json(job / 'status.json', {'state': 'running'})
    main.write_json(job / 'sandbox-recovery.json', {'state': 'quarantining'})
    calls = []
    monkeypatch.setattr(main, 'DATA', tmp_path)
    monkeypatch.setattr(bridge, 'quarantine_job_sandbox', lambda folder: calls.append(folder) or True)
    main.recover_interrupted_jobs()
    assert calls == [job]
    assert main.read_json(job / 'sandbox-recovery.json')['state'] == 'quarantined'
    assert main.read_json(job / 'status.json')['state'] == 'interrupted'
