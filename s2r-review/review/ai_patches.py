"""Validate source-grounded, model-written patch proposals without applying them.

The model supplies only replacement lines. This trusted host checks those lines
against the immutable analysis snapshot, then constructs the unified diff.
"""

import ast
import difflib
import hashlib
import re
from pathlib import PurePosixPath


SOURCE_SUFFIXES = {'.py', '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.java', '.php'}
MAX_SCENARIOS = 12
MAX_SOURCE_CHARS = 80_000
MAX_EXCERPT_CHARS = 17_000
MAX_EDITS = 8
MAX_CHANGED_LINES = 180
ID_PATTERN = re.compile(r'[a-f0-9]{16}\Z')


def manual_patch(reason):
    return {'file': None, 'start_line': None, 'diff': None,
            'applicability': 'manual_review', 'reason': reason}


def _sha(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _bounded(value, limit):
    return value[:limit] if isinstance(value, str) else ''


def _outcome_summary(outcome):
    evidence = outcome.get('evidence') if isinstance(outcome, dict) else None
    evidence = evidence if isinstance(evidence, dict) else {}
    status = outcome.get('status') if isinstance(outcome, dict) else None
    summary = outcome.get('summary') if isinstance(outcome, dict) else None
    observed = {'status': status if status in {
        'pass', 'fail', 'manual_review', 'inconclusive', 'not_found', 'unavailable', 'blocked'}
        else 'inconclusive', 'summary': _bounded(summary, 600)}
    http_status = evidence.get('status_code')
    if type(http_status) is int and 100 <= http_status <= 599:
        observed['http_status'] = http_status
    probe = evidence.get('probe')
    if isinstance(probe, dict):
        observed['probe'] = {str(key)[:70]: value for key, value in list(probe.items())[:15]
                             if isinstance(key, str) and type(value) is bool}
    headers = evidence.get('headers')
    if isinstance(headers, dict):
        allowed = {'content-security-policy', 'referrer-policy',
                   'x-content-type-options', 'location', 'content-type'}
        observed['headers'] = {key: _bounded(value, 240) for key, value in headers.items()
                               if isinstance(key, str) and key.lower() in allowed}
    return observed


def _excerpt(source, evidence_lines):
    """Keep the evidence's surrounding function/code in a numbered view."""
    lines = source.splitlines()
    if len(source) <= MAX_EXCERPT_CHARS:
        selected = set(range(len(lines)))
    else:
        selected = set(range(min(24, len(lines))))
        for number in evidence_lines:
            selected.update(range(max(0, number - 61), min(len(lines), number + 60)))
        # For Python, prefer the complete enclosing function when it fits the
        # source budget. This is navigation context, not a vulnerability rule.
        try:
            tree = ast.parse(source)
        except SyntaxError:
            tree = None
        if tree is not None:
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if any(node.lineno <= number <= node.end_lineno for number in evidence_lines):
                    start = min([node.lineno] + [dec.lineno for dec in node.decorator_list])
                    if node.end_lineno - start <= 140:
                        selected.update(range(start - 1, node.end_lineno))
    # Always reserve the evidence lines before adding broader context. Whole
    # lines longer than 1200 chars are never shown or eligible for replacement.
    priority = sorted(selected, key=lambda index: (
        0 if index + 1 in evidence_lines else
        1 if min((abs(index + 1 - line) for line in evidence_lines), default=1000) <= 8 else
        2 if index < 24 else 3,
        min((abs(index + 1 - line) for line in evidence_lines), default=1000), index))
    chosen, used = set(), 0
    for index in priority:
        if not 0 <= index < len(lines):
            continue
        line = lines[index]
        if len(line) > 1200:
            continue
        cost = len(line) + 10
        if used + cost > MAX_EXCERPT_CHARS:
            continue
        chosen.add(index)
        used += cost
    rendered = '\n'.join(f'L{index + 1:05d} {lines[index]}' for index in sorted(chosen))
    return rendered, sorted(index + 1 for index in chosen)


def prepare_patch_request(scenarios, outcomes_by_id, files):
    """Build bounded model input from selected AI scenarios and snapshot files.

    At most twelve scenarios are included; callers should mark absent scenarios
    manual, rather than infer that no patch is needed.
    """
    if not isinstance(scenarios, list) or not isinstance(outcomes_by_id, dict) or not isinstance(files, dict):
        raise ValueError('AI 변경 제안 입력 형식이 올바르지 않습니다.')
    chosen, sources, all_evidence = [], {}, {}
    seen = set()
    for scenario in scenarios[:MAX_SCENARIOS]:
        if not isinstance(scenario, dict):
            continue
        identifier = scenario.get('id')
        if not isinstance(identifier, str) or not ID_PATTERN.fullmatch(identifier) or identifier in seen:
            continue
        seen.add(identifier)
        evidence = scenario.get('source_evidence')
        if not isinstance(evidence, list):
            continue
        by_file = {}
        for location in evidence[:10]:
            if not isinstance(location, dict):
                continue
            path, number = location.get('file'), location.get('line')
            if (not isinstance(path, str) or path not in files or '\\' in path
                    or PurePosixPath(path).is_absolute() or '..' in PurePosixPath(path).parts
                    or PurePosixPath(path).suffix.lower() not in SOURCE_SUFFIXES
                    or type(number) is not int):
                continue
            content = files[path]
            if (not isinstance(content, str) or len(content) > MAX_SOURCE_CHARS
                    or not 1 <= number <= len(content.splitlines())):
                continue
            by_file.setdefault(path, set()).add(number)
        # A single fix must be source-grounded in one of the scenario's cited
        # files. More than two files makes this patch request ambiguous.
        evidence_paths = list(by_file)
        source_paths = (evidence_paths if len(evidence_paths) <= 2
                        else [evidence_paths[0], evidence_paths[-1]])
        if not source_paths:
            continue
        for path in source_paths:
            all_evidence.setdefault(path, set()).update(by_file[path])
        outcome = outcomes_by_id.get(identifier)
        chosen.append({
            'id': identifier, 'category': _bounded(scenario.get('category'), 60),
            'title': _bounded(scenario.get('title'), 180),
            'description': _bounded(scenario.get('description'), 1800),
            'risk_hypothesis': _bounded(scenario.get('risk_hypothesis'), 1000),
            'verification_expectation': _bounded(scenario.get('verification_expectation'), 800),
            'uncertainty': _bounded(scenario.get('uncertainty'), 800),
            'remediation_summary': _bounded((scenario.get('remediation') or {}).get('summary'), 800),
            'method': _bounded(scenario.get('method'), 16),
            'path': _bounded(scenario.get('path'), 300),
            'source_evidence': [{'file': path, 'line': number} for path in source_paths
                                for number in sorted(by_file[path])],
            'source_paths': source_paths,
            'outcome': _outcome_summary(outcome),
        })
    for path, evidence_lines in all_evidence.items():
        content = files[path]
        excerpt, visible = _excerpt(content, evidence_lines)
        if visible:
            sources[path] = {'sha256': _sha(content), 'content': content,
                             'excerpt': excerpt, 'visible_lines': visible}
    chosen = [row for row in chosen if any(path in sources for path in row['source_paths'])]
    for row in chosen:
        row['source_paths'] = [path for path in row['source_paths'] if path in sources]
        row['source_evidence'] = [entry for entry in row['source_evidence']
                                  if entry['file'] in row['source_paths']]
    return {'scenarios': chosen, 'sources': sources}


def _rebuild(source, lines):
    if '\r' in source.replace('\r\n', ''):
        raise ValueError('지원하지 않는 줄바꿈 형식입니다.')
    newline = '\r\n' if '\r\n' in source else '\n'
    if '\r\n' in source and '\n' in source.replace('\r\n', ''):
        raise ValueError('혼합 줄바꿈 파일입니다.')
    return newline.join(lines) + (newline if source.endswith(('\n', '\r\n')) else '')


def _validate_one(item, scenario, sources, files):
    identifier = scenario['id']
    if not isinstance(item, dict) or item.get('id') != identifier:
        return manual_patch('AI 변경 제안의 시나리오 ID가 일치하지 않습니다.')
    reason = item.get('reason')
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 1000:
        return manual_patch('AI 변경 제안의 근거가 없거나 길이 제한을 초과했습니다.')
    reason = reason.strip()
    if item.get('file') is None:
        if set(item) != {'id', 'file', 'reason', 'edits'} or item.get('edits') != []:
            return manual_patch('AI 수동 검토 제안 형식이 올바르지 않습니다.')
        return manual_patch(reason)
    if set(item) != {'id', 'file', 'reason', 'edits', 'validation'}:
        return manual_patch('AI 변경 제안 형식이 올바르지 않습니다.')
    if scenario['outcome']['status'] in {'pass', 'blocked'}:
        return manual_patch('운영 결과가 통과 또는 선택 제외 상태여서 코드 변경안을 제시하지 않습니다.')
    path = item.get('file')
    if not isinstance(path, str) or path not in scenario['source_paths'] or path not in sources or path not in files:
        return manual_patch('AI 변경 대상이 시나리오의 코드 근거 파일과 일치하지 않습니다.')
    source = files[path]
    source_meta = sources[path]
    if (not isinstance(source, str) or _sha(source) != source_meta.get('sha256')
            or source_meta.get('content') != source):
        return manual_patch('분석 당시 소스 복사본과 변경 대상이 일치하지 않습니다.')
    edits = item.get('edits')
    if not isinstance(edits, list) or not 1 <= len(edits) <= MAX_EDITS:
        return manual_patch('AI 변경 줄 수가 허용 범위를 벗어났습니다.')
    lines = source.splitlines()
    visible = set(source_meta.get('visible_lines', []))
    cited = {entry['line'] for entry in scenario['source_evidence'] if entry['file'] == path}
    normalized, touched, changed_lines = [], set(), 0
    for edit in edits:
        if not isinstance(edit, dict) or set(edit) != {'start_line', 'old_lines', 'new_lines'}:
            return manual_patch('AI 변경 항목 형식이 올바르지 않습니다.')
        start, old, new = edit['start_line'], edit['old_lines'], edit['new_lines']
        if (type(start) is not int or not isinstance(old, list) or not isinstance(new, list)
                or not 0 <= len(old) <= 60 or not 0 <= len(new) <= 60
                or not old and not new):
            return manual_patch('AI 변경 범위가 올바르지 않습니다.')
        if any(not isinstance(line, str) or len(line) > 1200 or '\n' in line or '\r' in line
               for line in old + new):
            return manual_patch('AI 변경 줄에 허용되지 않은 내용이 있습니다.')
        if not 1 <= start <= len(lines) + (0 if old else 1):
            return manual_patch('AI 변경 줄 번호가 소스 범위 밖입니다.')
        if lines[start - 1:start - 1 + len(old)] != old:
            return manual_patch('AI 변경 전 코드가 분석 당시 원본과 다릅니다.')
        span = set(range(start, start + len(old))) if old else {start}
        if not old and start == len(lines) + 1:
            span = {len(lines)}
        if not span <= visible:
            return manual_patch('AI가 보지 못한 소스 줄을 변경하려 했습니다.')
        if touched & span:
            return manual_patch('AI 변경 범위가 서로 겹칩니다.')
        if not any(abs(start - number) <= 100 for number in cited) and start > 40:
            return manual_patch('AI 변경 위치가 시나리오의 코드 근거에서 너무 멉니다.')
        touched.update(span)
        changed_lines += len(old) + len(new)
        normalized.append((start, old, new))
    if changed_lines > MAX_CHANGED_LINES:
        return manual_patch('AI 변경량이 검토 가능한 범위를 초과했습니다.')
    if not any(abs(start - number) <= 100 for start, _, _ in normalized for number in cited):
        return manual_patch('AI 변경안이 시나리오의 코드 근거를 수정하지 않습니다.')
    updated_lines = lines.copy()
    for start, old, new in sorted(normalized, reverse=True):
        updated_lines[start - 1:start - 1 + len(old)] = new
    try:
        updated = _rebuild(source, updated_lines)
    except ValueError as exc:
        return manual_patch(str(exc))
    if updated == source:
        return manual_patch('AI 변경 제안이 원본과 같습니다.')
    validation = item.get('validation')
    if (not isinstance(validation, dict) or validation.get('syntax') != 'passed'
            or validation.get('source_sha256') != _sha(source)
            or validation.get('updated_sha256') != _sha(updated)):
        return manual_patch('AI 변경안의 구문 검증 결과가 소스와 일치하지 않습니다.')
    if PurePosixPath(path).suffix.lower() == '.py':
        try:
            ast.parse(updated)
        except SyntaxError:
            return manual_patch('AI 변경안이 Python 문법 검증에 실패했습니다.')
    diff = '\n'.join(difflib.unified_diff(
        lines, updated_lines, fromfile=f'a/{path}', tofile=f'b/{path}', lineterm='', n=3)) + '\n'
    if not diff.startswith(f'--- a/{path}\n+++ b/{path}\n@@ '):
        return manual_patch('AI 변경안에서 정확한 diff를 생성하지 못했습니다.')
    if scenario['outcome']['status'] != 'fail':
        reason += ' 운영 재현은 확인되지 않았으며 분석 시점 소스의 위험 가설에 대한 제안입니다.'
    return {'file': path, 'start_line': min(start for start, _, _ in normalized),
            'diff': diff, 'applicability': 'review_required',
            'source_sha256': _sha(source), 'reason': reason}


def validate_patches(response, payload, files):
    """Return one patch or explicit manual result for each requested scenario."""
    scenarios = payload.get('scenarios') if isinstance(payload, dict) else None
    sources = payload.get('sources') if isinstance(payload, dict) else None
    if not isinstance(scenarios, list) or not isinstance(sources, dict) or not isinstance(files, dict):
        raise ValueError('AI 변경 제안 검증 입력이 올바르지 않습니다.')
    raw = response.get('patches') if isinstance(response, dict) else None
    if not isinstance(raw, list) or len(raw) > len(scenarios):
        raise ValueError('AI 변경 제안 응답 형식이 올바르지 않습니다.')
    by_id = {}
    expected = {scenario['id'] for scenario in scenarios}
    for item in raw:
        if not isinstance(item, dict) or item.get('id') not in expected or item['id'] in by_id:
            raise ValueError('AI 변경 제안 응답에 중복 또는 예상 밖 시나리오가 있습니다.')
        by_id[item['id']] = item
    return {scenario['id']: _validate_one(by_id.get(scenario['id']), scenario, sources, files)
            for scenario in scenarios}
