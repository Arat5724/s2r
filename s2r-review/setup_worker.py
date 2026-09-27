"""Provision the dedicated OpenShell worker using the existing NemoClaw gateway."""
import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path

from review import bridge

ROOT = Path(__file__).resolve().parent
BUILD = '/home/a/s2r-review-build'
CODE_FILES = ['agent.py', 'source_mount.py', 'ai_source.py', 'ast_context.py', 'tree_context.py',
              'script_agent.py', 'patch_agent.py', 'verify.py']
# Existing worker containers may still have these files from older installs.
# Never stage them in a new image; remove them during a code-only upgrade.
RETIRED_CODE_FILES = ['analyzer.py', 'framework_python.py',
                      'framework_javascript.py', 'framework_enterprise.py']
PARSER_PACKAGES = {'tree-sitter': '0.25.2', 'tree-sitter-javascript': '0.25.0',
                   'tree-sitter-typescript': '0.23.2', 'tree-sitter-java': '0.23.5',
                   'tree-sitter-php': '0.24.1'}


def ensure_no_active_work(jobs: Path):
    for pattern in ('*/status.json', '*/runs/*/status.json'):
        for status in jobs.glob(pattern):
            if json.loads(status.read_text(encoding='utf-8')).get('state') in {'queued', 'running'}:
                raise RuntimeError('An analysis or operational check is running. Finish it before updating the worker.')


def wsl(*args, timeout=600):
    subprocess.run(['wsl.exe', '-d', 'Ubuntu', '--', *args], check=True, timeout=timeout)


def verify_parser_packages():
    names = list(PARSER_PACKAGES)
    source = ('import importlib.metadata as m,json; '
              f'print(json.dumps({{name:m.version(name) for name in {names!r}}}))')
    output = bridge.command('sandbox', 'exec', '--name', bridge.SANDBOX, '--no-tty',
                            '--timeout', '20', '--', '/usr/local/bin/python3', '-B', '-c', source)
    actual = json.loads(output[output.index('{'):])
    if actual != PARSER_PACKAGES:
        raise RuntimeError('Worker parser package versions differ from the image manifest; code-only update cannot replace native parser wheels.')
    return actual


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--update', action='store_true', help='Update only the dedicated analysis worker code')
    args = parser.parse_args()
    remaining = [name for name in RETIRED_CODE_FILES if (ROOT / 'worker' / name).exists()]
    if remaining:
        raise RuntimeError(f'Retired rule modules remain in worker source: {remaining}')
    bridge.command('gateway', 'info', '--output', 'json')
    try:
        current = json.loads(bridge.command('sandbox', 'get', bridge.SANDBOX, '--output', 'json'))
    except RuntimeError as exc:
        if 'not found' not in str(exc).lower():
            raise
        current = None
    if current and current.get('phase') != 'Ready':
        raise RuntimeError('Analysis worker is not Ready. Inspect it before proceeding; no sandbox was deleted.')
    if current:
        bridge.probe()
        verify_parser_packages()
        if not args.update:
            bridge._verify_worker_image()
            print('Existing worker boundary checks passed. Use --update after changing worker code.')
            return
        jobs = ROOT.parent / 's2r-review-data' / 'jobs'
        ensure_no_active_work(jobs)
    # Write plain bytes onto the Linux filesystem: Windows tar metadata is incompatible
    # with this OpenShell version's image builder.
    wsl('python3', '-c',
        'from pathlib import Path; import sys; src=Path(sys.argv[1]); dst=Path(sys.argv[2]); dst.mkdir(exist_ok=True); '
        f'[(dst/n).write_bytes((src/n).read_bytes()) for n in {(["Dockerfile", "policy.yaml", *CODE_FILES])!r}]',
        bridge.wsl_path(ROOT / 'worker'), BUILD)
    print('Building reproducible image from current worker sources...', flush=True)
    wsl('docker', 'build', '--tag', bridge.IMAGE, BUILD)
    if current:
        identity = bridge.container_id()
        for name in CODE_FILES:
            # Trusted administrator provisioning, never exposed as an agent tool.
            wsl('docker', 'cp', f'{BUILD}/{name}', f'{identity}:/app/{name}')
        # An update changes a running container rather than recreating it from
        # the new image. Remove old static modules from that existing layer.
        wsl('docker', 'exec', '--user', '0', identity, '/usr/local/bin/python3', '-B', '-c',
            f'from pathlib import Path; [(Path("/app")/n).unlink(missing_ok=True) for n in {RETIRED_CODE_FILES!r}]')
        print('Dedicated worker code updated; filesystem/network policy unchanged.', flush=True)
    else:
        print('Creating dedicated read-only analysis worker...', flush=True)
        print(bridge.command('sandbox', 'create', '--name', bridge.SANDBOX, '--from', BUILD,
              '--policy', BUILD + '/policy.yaml', '--cpu', '1', '--memory', '1Gi', '--no-auto-providers',
              '--detach', '--', '/bin/sleep', 'infinity', timeout=600))
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            phase = json.loads(bridge.command('sandbox', 'get', bridge.SANDBOX, '--output', 'json'))['phase']
            if phase == 'Ready':
                break
            if phase in {'Error', 'Stopped'}:
                raise RuntimeError(f'Worker phase: {phase}. Inspect OpenShell logs.')
            time.sleep(2)
    checks = bridge.probe()
    parsers = verify_parser_packages()
    remote_code = ('import hashlib,json; from pathlib import Path; '
                   f'code={CODE_FILES!r}; retired={RETIRED_CODE_FILES!r}; '
                   'print(json.dumps({"hashes":{n:hashlib.sha256(Path("/app",n).read_bytes()).hexdigest() for n in code}, '
                   '"retired_absent":all(not (Path("/app")/n).exists() for n in retired)}))')
    remote = bridge.command('sandbox', 'exec', '--name', bridge.SANDBOX, '--no-tty', '--timeout', '20', '--',
                            '/usr/local/bin/python3', '-B', '-c', remote_code)
    remote_result = json.loads(remote[remote.index('{'):])
    actual = remote_result['hashes']
    expected = {n: hashlib.sha256((ROOT / 'worker' / n).read_bytes()).hexdigest() for n in CODE_FILES}
    if actual != expected or remote_result['retired_absent'] is not True:
        raise RuntimeError('Worker code checksum mismatch')
    print(json.dumps({'sandbox': bridge.SANDBOX, 'boundary': checks,
                      'parser_packages': parsers, 'code_matches': True}))


if __name__ == '__main__':
    main()
