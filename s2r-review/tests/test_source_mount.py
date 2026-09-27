"""The AI worker reads only mounted originals named by an integrity manifest."""

import hashlib
import json
import os

import pytest

import agent
from source_mount import read_mounted_files


def manifest(files):
    identity = json.dumps(files, sort_keys=True, ensure_ascii=False,
                          separators=(',', ':')).encode('utf-8')
    return {'kind': 'mounted_source_manifest', 'files': sorted(files),
            'source_hash': hashlib.sha256(identity).hexdigest()}


def test_analysis_uses_mounted_utf8_sig_source_and_never_manifest_text(tmp_path, monkeypatch):
    (tmp_path / '0000').write_bytes(b'\xef\xbb\xbfprint("mounted")\n')
    files = {'pkg/app.py': 'print("mounted")\n'}
    observed = []

    def infer(mounted):
        observed.append(mounted)
        return {'endpoints': [], 'ai': {'status': 'ok'}}

    monkeypatch.setattr(agent, 'infer_from_source', infer)
    result = agent.analyze_bundle(manifest(files), True, tmp_path)
    assert observed == [files]
    assert result['analysis_mode'] == 'ai'


def test_source_change_or_forged_hash_fails_before_model_call(tmp_path, monkeypatch):
    path = tmp_path / '0000'
    path.write_text('original\n', encoding='utf-8')
    bundle = manifest({'app.py': 'original\n'})
    called = []
    monkeypatch.setattr(agent, 'infer_from_source', lambda files: called.append(files))
    path.write_text('changed\n', encoding='utf-8')
    with pytest.raises(ValueError, match='SHA-256 mismatch'):
        agent.analyze_bundle(bundle, True, tmp_path)
    path.write_text('original\n', encoding='utf-8')
    with pytest.raises(ValueError, match='SHA-256 mismatch'):
        agent.analyze_bundle({**bundle, 'source_hash': '0' * 64}, True, tmp_path)
    assert called == []


@pytest.mark.parametrize('name', [
    '../outside.py', '/absolute.py', 'dir/../../outside.py', 'dir//file.py',
    'dir/./file.py', 'C:/file.py', 'dir\\file.py', '.'])
def test_manifest_rejects_unsafe_paths_before_open(tmp_path, name):
    with pytest.raises(ValueError, match='Invalid source path'):
        read_mounted_files({'kind': 'mounted_source_manifest', 'files': [name],
                            'source_hash': '0' * 64}, tmp_path)


def test_manifest_requires_explicit_kind_hash_and_unique_names(tmp_path):
    (tmp_path / '0000').write_text('pass', encoding='utf-8')
    with pytest.raises(ValueError, match='manifest is required'):
        read_mounted_files({'files': {'app.py': 'pass'}}, tmp_path)
    with pytest.raises(ValueError, match='needs a SHA-256'):
        read_mounted_files({'kind': 'mounted_source_manifest', 'files': ['app.py']}, tmp_path)
    duplicate = manifest({'app.py': 'pass'})
    duplicate['files'] = ['app.py', 'app.py']
    with pytest.raises(ValueError, match='sorted and unique'):
        read_mounted_files(duplicate, tmp_path)
    unordered = manifest({'a.py': 'pass', 'b.py': 'pass'})
    unordered['files'] = ['b.py', 'a.py']
    with pytest.raises(ValueError, match='sorted and unique'):
        read_mounted_files(unordered, tmp_path)


def test_manifest_rejects_missing_invalid_utf8_and_hardlink(tmp_path):
    bundle = manifest({'app.py': 'pass'})
    with pytest.raises(FileNotFoundError):
        read_mounted_files(bundle, tmp_path)
    path = tmp_path / '0000'
    path.write_bytes(b'\xff')
    with pytest.raises(ValueError, match='UTF-8'):
        read_mounted_files(bundle, tmp_path)
    path.write_text('pass', encoding='utf-8')
    os.link(path, tmp_path / 'other')
    with pytest.raises(ValueError, match='single-link'):
        read_mounted_files(bundle, tmp_path)


def test_manifest_rejects_symlink_to_file_or_directory(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + '-outside.py')
    outside.write_text('pass', encoding='utf-8')
    try:
        (tmp_path / '0000').symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip('symlinks unavailable on this host')
    with pytest.raises((ValueError, OSError)):
        read_mounted_files(manifest({'app.py': 'pass'}), tmp_path)
    (tmp_path / '0000').unlink()
    target = tmp_path.parent / (tmp_path.name + '-target')
    target.mkdir()
    (target / '0000').write_text('pass', encoding='utf-8')
    (tmp_path / '0000').symlink_to(target / '0000')
    with pytest.raises((ValueError, OSError)):
        read_mounted_files(manifest({'nested/app.py': 'pass'}), tmp_path)


def test_manifest_uses_sorted_slots_to_reconstruct_original_names(tmp_path):
    (tmp_path / '0000').write_text('alpha', encoding='utf-8')
    (tmp_path / '0001').write_text('beta', encoding='utf-8')
    files = {'nested/a.py': 'alpha', 'nested/b.py': 'beta'}
    assert read_mounted_files(manifest(files), tmp_path) == files
    (tmp_path / '0000').write_text('beta', encoding='utf-8')
    (tmp_path / '0001').write_text('alpha', encoding='utf-8')
    with pytest.raises(ValueError, match='SHA-256 mismatch'):
        read_mounted_files(manifest(files), tmp_path)
