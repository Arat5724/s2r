"""Read-only, AI-only OpenShell worker entry point.

Nemotron receives numbered source and syntax hints; target modules are never
imported or executed.  Older deterministic results remain host-side history.
"""

import argparse
import errno
import json
import os
import sys
from pathlib import Path

from ai_source import infer_from_source
from source_mount import read_mounted_files, read_source_bytes


def verify_boundary(source_allow=None, source_deny=None):
    if (source_allow, source_deny) not in ((None, None), ('/source/0000', '/blocked/0000')):
        raise ValueError('Source probe paths must be /source/0000 and /blocked/0000')
    checks = {}
    try:
        with open('/input/canary.txt', 'a') as stream:
            stream.write('unexpected-write')
        checks['input_write_denied'] = False
    except PermissionError:
        checks['input_write_denied'] = True
    try:
        Path('/protected/canary.txt').read_text()
        checks['outside_read_denied'] = False
    except PermissionError:
        checks['outside_read_denied'] = True
    path = Path('/output/.write-probe')
    path.write_text('output-check')
    checks['output_write_allowed'] = path.read_text() == 'output-check'
    path.unlink()
    checks['input_read_allowed'] = Path('/input/canary.txt').read_text().startswith('READ_ONLY_TEST')
    if source_allow is not None:
        read_source_bytes(Path('/source'), '0000')
        checks['source_read_allowed'] = True
        try:
            descriptor = os.open(source_allow, os.O_WRONLY | os.O_APPEND)
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EPERM, errno.EROFS):
                raise
            checks['source_write_denied'] = True
        else:
            os.close(descriptor)
            checks['source_write_denied'] = False
        try:
            read_source_bytes(Path('/blocked'), '0000')
            checks['source_unselected_read_denied'] = False
        except PermissionError:
            checks['source_unselected_read_denied'] = True
    checks['passed'] = all(checks.values())
    if source_allow is not None:
        checks['source_scope_probe'] = 'unselected_file'
    if not checks['passed']:
        raise RuntimeError('Filesystem boundary verification failed: ' + json.dumps(checks))
    return checks


def analyze_bundle(bundle, use_ai, source_root=Path('/source')):
    if use_ai is not True:
        raise RuntimeError('규칙 기반 소스 분석은 더 이상 실행하지 않습니다. --ai로 새 분석을 시작하세요.')
    files = read_mounted_files(bundle, source_root)
    # A provider/schema failure cannot masquerade as a successful scan.
    try:
        result = infer_from_source(files)
    except Exception as exc:
        raise RuntimeError('AI 소스 분석 실패: 모델 응답이나 근거를 확인할 수 없습니다. 다시 분석하세요. '
                           f'({type(exc).__name__})') from None
    result['analysis_mode'] = 'ai'
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input')
    parser.add_argument('--output')
    parser.add_argument('--ai', action='store_true')
    parser.add_argument('--probe', action='store_true')
    parser.add_argument('--source-root', choices=['/source'], default='/source')
    parser.add_argument('--source-allow')
    parser.add_argument('--source-deny')
    args = parser.parse_args()
    boundary = verify_boundary(args.source_allow, args.source_deny)
    if args.probe:
        print(json.dumps(boundary))
        return
    source = Path(args.input).resolve()
    target = Path(args.output).resolve()
    if not source.is_relative_to('/input') or not target.is_relative_to('/output'):
        raise ValueError('Input/output are outside approved paths')
    bundle = json.loads(source.read_text())
    result = analyze_bundle(bundle, args.ai, Path(args.source_root))
    result['boundary'] = boundary
    target.write_text(json.dumps(result, ensure_ascii=False, indent=2))
    print(json.dumps({'status': 'completed', 'output': str(target),
                      'endpoints': len(result['endpoints']), 'ai': result['ai']['status']}))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from None
