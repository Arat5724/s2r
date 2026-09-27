import os

import pytest

from review.snapshot import read_scoped, safe_project, snapshot


def project(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'requirements.txt').write_text('fastapi\n')
    (root / 'main.py').write_text('answer = 42\n')
    return root


def test_snapshot_excludes_runtime_and_sensitive_files(tmp_path):
    root = project(tmp_path)
    for folder in ['runtime', '.git', 'node_modules', '.venv', 'target']:
        (root / folder).mkdir()
        (root / folder / 'private.py').write_text('excluded')
    for name in ['.env', 'accounts.json', 'secrets.json', 'private-key.txt', 'db.sqlite']:
        (root / name).write_text('excluded')
    before = snapshot(root)
    assert set(before['files']) == {'requirements.txt', 'main.py'}
    (root / 'runtime' / 'private.py').write_text('new runtime state')
    assert before['source_hash'] == snapshot(root)['source_hash']
    (root / 'main.py').write_text('answer = 43\n')
    assert before['source_hash'] != snapshot(root)['source_hash']


def test_hardlinks_and_outside_opened_handles_are_rejected(tmp_path):
    root = project(tmp_path)
    outside = tmp_path / 'outside.py'
    outside.write_text('outside = True')
    os.link(outside, root / 'linked.py')
    assert 'linked.py' not in snapshot(root)['files']
    with pytest.raises(ValueError):
        read_scoped(outside, root)
    ordinary = tmp_path / 'ordinary.py'
    ordinary.write_text('outside = True')
    with pytest.raises(ValueError, match='허용 범위 밖'):
        read_scoped(ordinary, root)


def test_protected_folders_and_their_ancestors_are_rejected(tmp_path):
    root = project(tmp_path)
    protected = root / 'evaluation'
    protected.mkdir()
    with pytest.raises(ValueError):
        safe_project(str(root), [protected])
    with pytest.raises(ValueError):
        safe_project(str(protected), [protected])
    assert safe_project(str(root), []) == root


def test_non_utf8_and_oversized_files_are_skipped(tmp_path):
    root = project(tmp_path)
    (root / 'broken.py').write_bytes(b'\xff\xfe\xfa')
    (root / 'large.py').write_bytes(b'x' * 200_001)
    result = snapshot(root)
    assert {row['file'] for row in result['skipped']} == {'broken.py', 'large.py'}


@pytest.mark.parametrize(('manifest', 'source_file'), [
    ('package.json', 'src/server.ts'),
    ('pom.xml', 'src/main/java/Api.java'),
    ('build.gradle.kts', 'src/main/java/Api.java'),
    ('composer.json', 'routes/api.php'),
])
def test_non_python_projects_can_be_snapshotted(tmp_path, manifest, source_file):
    root = tmp_path / 'project'
    root.mkdir()
    (root / manifest).write_text('{}')
    source = root / source_file
    source.parent.mkdir(parents=True)
    source.write_text('source text')
    assert safe_project(str(root), []) == root
    assert source_file in snapshot(root)['files']
