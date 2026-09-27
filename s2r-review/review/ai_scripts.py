"""Validate model-authored probe plans and bounded Python response evaluators.

The model can choose one bounded input value and a pure decision function. The host owns
the target, selected route, HTTP method, transport, response limits, and policy.
This validator is intentionally independent of vulnerability categories.
"""

import ast
import json
import re


STATUSES = {'pass', 'fail', 'inconclusive', 'not_found', 'unavailable'}
LOCAL_FIELDS = ('status', 'error', 'body_text', 'body_within_limit', 'headers')
BASELINE_FIELDS = ('baseline_status', 'baseline_error', 'baseline_body_text',
                   'baseline_body_within_limit', 'baseline_headers')
RESPONSE_FIELDS = set(LOCAL_FIELDS)
QUERY_KEY = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}\Z')
HEADER_KEY = re.compile(r'[a-z0-9][a-z0-9-]{0,63}\Z')
LOCAL_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}\Z')
ID = re.compile(r'[a-f0-9]{16}\Z')
PLAIN_MARKER = re.compile(r's2r_[A-Za-z0-9_-]{8,60}\Z', re.I)
TAGGED_MARKER = re.compile(r'<(strong|em|b|i)>(s2r_[A-Za-z0-9_-]{8,60})</\1>\Z', re.I)
MAX_SOURCE = 4000
ALLOWED_METHODS = {'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'}


def validate_probe(probe):
    """Two source-specific differential requests or a legacy/offline plan."""
    if isinstance(probe, dict) and set(probe) == {'requests'}:
        requests = probe['requests']
        if not isinstance(requests, list) or len(requests) not in {0, 2}:
            raise ValueError('AI 차등 진단은 기준/후보 두 요청이 필요합니다.')
        checked = []
        for label, item in zip(('baseline', 'candidate'), requests):
            if (not isinstance(item, dict)
                    or set(item) not in ({'label', 'query_key', 'probe_value'},
                                         {'label', 'query_key', 'probe_value', 'input_location'})
                    or item['label'] != label
                    or item.get('input_location', 'query') not in {'query', 'body'}
                    or not isinstance(item['query_key'], str)
                    or not QUERY_KEY.fullmatch(item['query_key'])
                    or not isinstance(item['probe_value'], str)
                    or not 1 <= len(item['probe_value']) <= 160
                    or any(ord(char) < 32 or ord(char) > 126
                           for char in item['probe_value'])
                    or any(fragment in item['probe_value']
                           for fragment in (';', '`', '$(', '&&', '||'))
                    or (any(char in item['probe_value'] for char in '<>')
                        and not TAGGED_MARKER.fullmatch(item['probe_value']))
                    or (('://' in item['probe_value'] or item['probe_value'].startswith('//'))
                        and not re.fullmatch(
                            r'https://example\.invalid(?:/[A-Za-z0-9_./~-]*)?',
                            item['probe_value']))
                    or re.search(r'(?i)(?:javascript|data|vbscript)\s*:',
                                 item['probe_value'])):
                raise ValueError('AI 차등 진단 입력 형식 또는 문자 범위 오류')
            checked.append(dict(item))
        if checked and (checked[0]['query_key'] != checked[1]['query_key']
                        or checked[0].get('input_location', 'query')
                        != checked[1].get('input_location', 'query')
                        or checked[0]['probe_value'] == checked[1]['probe_value']):
            raise ValueError('AI 차등 진단은 같은 입력의 서로 다른 두 값이어야 합니다.')
        return {'requests': checked}
    if (not isinstance(probe, dict)
            or set(probe) not in ({'query_key', 'probe_value'},
                                  {'query_key', 'probe_value', 'input_location'})
            or probe.get('input_location', 'query') not in {'query', 'body'}):
        raise ValueError('AI 진단 입력은 query_key/probe_value 한 쌍이어야 합니다.')
    key, value = probe['query_key'], probe['probe_value']
    if key is None and value is None:
        if probe.get('input_location', 'query') != 'query':
            raise ValueError('오프라인 진단에는 요청 본문 위치를 지정할 수 없습니다.')
        return {'query_key': None, 'probe_value': None}
    if not isinstance(key, str) or not QUERY_KEY.fullmatch(key):
        raise ValueError('AI 진단 입력의 질의 이름이 허용되지 않습니다.')
    if (not isinstance(value, str) or len(value) > 120
            or not (PLAIN_MARKER.fullmatch(value) or TAGGED_MARKER.fullmatch(value))):
        raise ValueError('AI 진단 입력의 질의 값이 허용되지 않습니다.')
    return {**probe}


def _literal(node):
    if not isinstance(node, ast.Constant):
        return False
    value = node.value
    return (type(value) in {str, int, bool, type(None)}
            and (not isinstance(value, str) or len(value) <= 240)
            and (type(value) is not int or abs(value) <= 100_000))


def _json_kind(node, aliases, seen=None):
    """Trace only JSON data parsed from the two bounded response bodies."""
    seen = set() if seen is None else seen
    if isinstance(node, ast.Name):
        if node.id in {'body_text', 'baseline_body_text'}:
            return ('text', 'baseline' if node.id.startswith('baseline_') else 'candidate', None)
        if node.id in aliases and node.id not in seen:
            return _json_kind(aliases[node.id], aliases, seen | {node.id})
        return None
    if not isinstance(node, ast.Call) or node.keywords:
        return None
    if (isinstance(node.func, ast.Attribute) and node.func.attr == 'loads'
            and isinstance(node.func.value, ast.Name) and node.func.value.id == 'json'
            and len(node.args) == 1):
        source = _json_kind(node.args[0], aliases, seen)
        return ('document', source[1], None) if source and source[0] == 'text' else None
    if (isinstance(node.func, ast.Attribute) and node.func.attr == 'get'
            and len(node.args) == 2
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and 1 <= len(node.args[0].value) <= 64
            and '__' not in node.args[0].value
            and not any(ord(ch) < 32 for ch in node.args[0].value)
            and isinstance(node.args[1], ast.List) and not node.args[1].elts):
        owner = _json_kind(node.func.value, aliases, seen)
        return ('field', owner[1], node.args[0].value) if owner and owner[0] == 'document' else None
    if isinstance(node.func, ast.Name) and node.func.id == 'len' and len(node.args) == 1:
        field = _json_kind(node.args[0], aliases, seen)
        return ('length', field[1], field[2]) if field and field[0] == 'field' else None
    return None


def _expression(node, assigned, aliases=None, depth=0):
    aliases = {} if aliases is None else aliases
    if depth > 12:
        raise ValueError('AI 판정 조건이 너무 깊습니다.')
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
        if node.id not in assigned:
            raise ValueError('AI 판정 코드의 변수 참조가 허용되지 않습니다.')
        return
    if _literal(node):
        return
    if isinstance(node, (ast.Tuple, ast.List)) and len(node.elts) <= 8:
        for item in node.elts:
            _expression(item, assigned, aliases, depth + 1)
        return
    if isinstance(node, ast.Call):
        kind = _json_kind(node, aliases)
        if kind and (kind[1] != 'baseline' or 'baseline_body_text' in assigned):
            return
        if (not isinstance(node.func, ast.Attribute) or node.func.attr != 'get'
                or not isinstance(node.func.value, ast.Name)
                or node.func.value.id not in {'headers', 'baseline_headers'}
                or node.func.value.id not in assigned
                or not 1 <= len(node.args) <= 2
                or node.keywords or not isinstance(node.args[0], ast.Constant)
                or not isinstance(node.args[0].value, str)
                or not HEADER_KEY.fullmatch(node.args[0].value)
                or (len(node.args) == 2 and
                    (not isinstance(node.args[1], ast.Constant)
                     or node.args[1].value != ''))):
            raise ValueError('AI 판정 코드에는 헤더 조회만 허용됩니다.')
        return
    if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
        if len(node.values) > 6:
            raise ValueError('AI 판정 조건이 너무 깁니다.')
        for item in node.values:
            _expression(item, assigned, aliases, depth + 1)
        return
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        _expression(node.operand, assigned, aliases, depth + 1)
        return
    if isinstance(node, ast.Compare) and len(node.ops) <= 3:
        if not all(isinstance(op, (ast.Eq, ast.NotEq, ast.Is, ast.IsNot,
                                   ast.In, ast.NotIn, ast.Gt, ast.GtE,
                                   ast.Lt, ast.LtE)) for op in node.ops):
            raise ValueError('AI 판정 비교 연산이 허용되지 않습니다.')
        _expression(node.left, assigned, aliases, depth + 1)
        for item in node.comparators:
            _expression(item, assigned, aliases, depth + 1)
        return
    raise ValueError('AI 판정 조건에 실행이 허용되지 않는 표현식이 있습니다.')


def _statements(body, assigned, aliases=None, depth=0):
    aliases = {} if aliases is None else aliases
    if depth > 5 or len(body) > 20:
        raise ValueError('AI 판정 코드가 너무 복잡합니다.')
    verdicts = set()
    for statement in body:
        if isinstance(statement, ast.If):
            _expression(statement.test, assigned, aliases)
            verdicts |= _statements(statement.body, assigned, aliases, depth + 1)
            verdicts |= _statements(statement.orelse, assigned, aliases, depth + 1)
        elif isinstance(statement, ast.Return):
            value = statement.value
            if (not isinstance(value, ast.Tuple) or len(value.elts) != 2
                    or not all(isinstance(part, ast.Constant) and isinstance(part.value, str)
                               for part in value.elts)):
                raise ValueError('AI 판정은 문자열 두 개를 반환해야 합니다.')
            verdict, detail = (part.value for part in value.elts)
            if (verdict not in STATUSES or not 1 <= len(detail) <= 200
                    or any(ord(ch) < 32 for ch in detail)):
                raise ValueError('AI 판정 상태 또는 설명이 허용되지 않습니다.')
            verdicts.add(verdict)
        else:
            raise ValueError('AI 판정 코드에는 조건문과 반환문만 허용됩니다.')
    return verdicts


def _normalize_model_source(source):
    """Normalize only a JSON import and proven array-count detail strings."""
    tree = ast.parse(source)
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
        return source
    function = tree.body[0]
    containers = [function.body]
    containers.extend(item.body for item in function.body if isinstance(item, ast.Try))
    imports = [item for item in ast.walk(function)
               if isinstance(item, (ast.Import, ast.ImportFrom))]
    changed = False
    if imports:
        item = imports[0]
        if (len(imports) != 1 or not isinstance(item, ast.Import)
                or len(item.names) != 1 or item.names[0].name != 'json'
                or item.names[0].asname is not None
                or not any(item in body for body in containers)):
            raise ValueError('AI 판정 import는 json 하나만 허용됩니다.')
        next(body for body in containers if item in body).remove(item)
        changed = True
    assignments = []
    for item in function.body:
        assignments.extend(item.body if isinstance(item, ast.Try) else [item])
    aliases = {item.targets[0].id: item.value for item in assignments
               if isinstance(item, ast.Assign) and len(item.targets) == 1
               and isinstance(item.targets[0], ast.Name)}
    for item in ast.walk(function):
        if not isinstance(item, ast.Return) or not isinstance(item.value, ast.Tuple):
            continue
        parts = item.value.elts
        if len(parts) != 2 or not isinstance(parts[1], ast.JoinedStr):
            continue
        if (not isinstance(parts[0], ast.Constant) or parts[0].value != 'fail'
                or len(parts[1].values) > 12):
            raise ValueError('동적 판정 설명은 JSON 배열 길이 차이에만 허용됩니다.')
        origins = set()
        for part in parts[1].values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                if len(part.value) > 200 or any(ord(ch) < 32 for ch in part.value):
                    raise ValueError('동적 판정 설명 길이 오류')
            elif (isinstance(part, ast.FormattedValue)
                  and isinstance(part.value, ast.Name)
                  and part.conversion == -1 and part.format_spec is None):
                kind = _json_kind(part.value, aliases)
                if not kind or kind[0] != 'length':
                    raise ValueError('동적 판정 설명은 JSON 배열 길이만 참조할 수 있습니다.')
                origins.add(kind[1])
            else:
                raise ValueError('동적 판정 설명 표현식 오류')
        if origins != {'baseline', 'candidate'}:
            raise ValueError('동적 판정 설명에는 두 JSON 배열 길이가 필요합니다.')
        parts[1] = ast.Constant('기준과 후보 JSON 배열 길이 차이를 관찰했습니다.')
        changed = True
    return ast.unparse(tree).strip() + '\n' if changed else source


def validate_check(source, scenario, probe=None, *, offline=False):
    """Return renamed, category-neutral pure evaluator source."""
    identifier = scenario.get('id', '')
    if not isinstance(identifier, str) or not ID.fullmatch(identifier):
        raise ValueError('AI 판정 시나리오 ID 오류')
    if not offline and scenario.get('method') not in ALLOWED_METHODS:
        raise ValueError('AI 판정의 HTTP 메서드를 확인할 수 없습니다.')
    if probe is not None:
        probe = validate_probe(probe)
    differential = bool(isinstance(probe, dict) and 'requests' in probe
                        and probe['requests'])
    if (not isinstance(source, str) or not 1 <= len(source) <= MAX_SOURCE
            or '\x00' in source):
        raise ValueError('AI 판정 코드 길이 오류')
    try:
        source = _normalize_model_source(source)
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise ValueError('AI 판정 코드 Python 문법 오류') from exc
    if len(list(ast.walk(tree))) > (320 if differential else 190) or len(tree.body) != 1:
        raise ValueError('AI 판정 코드는 단일 함수여야 합니다.')
    function = tree.body[0]
    if (not isinstance(function, ast.FunctionDef) or function.name != 'evaluate'
            or function.decorator_list or function.returns is not None
            or function.type_comment or function.args.posonlyargs
            or function.args.kwonlyargs or function.args.vararg or function.args.kwarg
            or function.args.defaults or function.args.kw_defaults
            or len(function.args.args) != 1 or function.args.args[0].arg != 'response'
            or function.args.args[0].annotation is not None):
        raise ValueError('AI 판정은 evaluate(response)만 정의해야 합니다.')
    fields = LOCAL_FIELDS + BASELINE_FIELDS if differential else LOCAL_FIELDS
    if len(function.body) < len(fields) + 1:
        raise ValueError('AI 판정의 응답 필드 초기화가 누락되었습니다.')
    for expected, statement in zip(fields, function.body):
        if (not isinstance(statement, ast.Assign) or len(statement.targets) != 1
                or not isinstance(statement.targets[0], ast.Name)
                or statement.targets[0].id != expected):
            raise ValueError('AI 판정의 응답 필드 초기화 형식 오류')
        value = statement.value
        if (not isinstance(value, ast.Call) or not isinstance(value.func, ast.Attribute)
                or value.func.attr != 'get' or not isinstance(value.func.value, ast.Name)
                or value.func.value.id != 'response' or len(value.args) != 1
                or not isinstance(value.args[0], ast.Constant)
                or value.args[0].value != expected or value.keywords):
            raise ValueError('AI 판정의 응답 필드 초기화 형식 오류')
    remaining = function.body[len(fields):]
    assigned = set(fields)
    aliases = {}
    extra = 0

    def consume(statement):
        nonlocal extra
        if (extra >= 8 or len(statement.targets) != 1
                or not isinstance(statement.targets[0], ast.Name)):
            raise ValueError('AI 판정의 로컬 변수 할당 범위 오류')
        name = statement.targets[0].id
        if (not LOCAL_NAME.fullmatch(name) or '__' in name
                or name == 'response' or name in assigned):
            raise ValueError('AI 판정의 로컬 변수명이 허용되지 않습니다.')
        _expression(statement.value, assigned, aliases)
        assigned.add(name)
        aliases[name] = statement.value
        extra += 1

    def consume_try(statement):
        if (statement.orelse or statement.finalbody
                or len(statement.handlers) != 1 or not statement.body
                or not all(isinstance(item, ast.Assign) for item in statement.body)):
            raise ValueError('JSON 처리 try 범위 오류')
        handler = statement.handlers[0]
        if (not isinstance(handler.type, ast.Name) or handler.type.id != 'Exception'
                or handler.name is not None or len(handler.body) != 1
                or _statements(handler.body, assigned, aliases) != {'inconclusive'}):
            raise ValueError('JSON 처리 오류는 판단 보류만 허용됩니다.')
        for item in statement.body:
            consume(item)
    verdicts = set()
    used_try = False
    for statement in remaining:
        if isinstance(statement, ast.Assign):
            consume(statement)
        elif isinstance(statement, ast.Try):
            if used_try:
                raise ValueError('JSON 처리 try는 한 번만 허용됩니다.')
            consume_try(statement)
            used_try = True
        else:
            verdicts |= _statements([statement], assigned, aliases)
    if not isinstance(function.body[-1], ast.Return) or 'inconclusive' not in verdicts:
        raise ValueError('AI 판정에는 마지막 판단 보류 반환이 필요합니다.')
    function.name = f'ai_evaluate_{identifier}'
    return ast.unparse(tree).strip() + '\n'


def load_evaluator(source, scenario, probe=None, *, offline=False):
    """Compile only source accepted by the strict AST validator."""
    renamed = validate_check(source, scenario, probe, offline=offline)
    namespace = {}
    exec(compile(renamed, '<s2r-ai-evaluator>', 'exec'),
         {'__builtins__': {}, 'json': json, 'len': len, 'Exception': Exception}, namespace)
    return namespace[f"ai_evaluate_{scenario['id']}"]


def _source_code_literals(source_context):
    """Read quoted literals from numbered code lines, excluding source comments."""
    literals = set()
    if not isinstance(source_context, str):
        return literals
    in_comment = None
    for line in source_context.splitlines():
        match = re.match(r'^L\d{5}\s(.*)$', line)
        if not match:
            continue
        code, index = match.group(1), 0
        while index < len(code):
            if in_comment:
                end = code.find(in_comment, index)
                if end < 0:
                    break
                index, in_comment = end + len(in_comment), None
                continue
            if code.startswith('/*', index):
                in_comment, index = '*/', index + 2
                continue
            if code.startswith('<!--', index):
                in_comment, index = '-->', index + 4
                continue
            if code.startswith('//', index) or code[index] == '#':
                break
            quote = code[index]
            if quote not in {'\'', '"', '`'}:
                index += 1
                continue
            index += 1
            value = []
            while index < len(code):
                char = code[index]
                if char == '\\' and index + 1 < len(code):
                    value.append(code[index + 1])
                    index += 2
                elif char == quote:
                    literals.add(''.join(value))
                    index += 1
                    break
                else:
                    value.append(char)
                    index += 1
    return literals


def _offline_body_needles(function):
    """Resolve simple local aliases used in body_text comparisons."""
    assignments = []
    for item in function.body:
        assignments.extend(item.body if isinstance(item, ast.Try) else [item])
    aliases = {item.targets[0].id: item.value for item in assignments
               if isinstance(item, ast.Assign) and len(item.targets) == 1
               and isinstance(item.targets[0], ast.Name)}

    def follow(node, seen=None):
        seen = set() if seen is None else seen
        if isinstance(node, ast.Name) and node.id != 'body_text' and node.id not in seen:
            value = aliases.get(node.id)
            if value is not None:
                return follow(value, seen | {node.id})
        return node

    def references_body(node):
        node = follow(node)
        return (isinstance(node, ast.Name) and node.id == 'body_text'
                or any(references_body(child) for child in ast.iter_child_nodes(node)))

    needles = set()
    for comparison in ast.walk(function):
        if not isinstance(comparison, ast.Compare):
            continue
        parts = [comparison.left, *comparison.comparators]
        if any(references_body(part) for part in parts):
            for part in parts:
                if not references_body(part):
                    needles.update(node.value for node in ast.walk(follow(part))
                                   if isinstance(node, ast.Constant)
                                   and isinstance(node.value, str) and node.value)
    return needles


def _validate_offline_signal(source, source_context):
    """Do not certify an offline failure from an unsent marker or generic token."""
    tree = ast.parse(source)

    def is_fail(statement):
        return (isinstance(statement, ast.Return)
                and isinstance(statement.value, ast.Tuple)
                and len(statement.value.elts) == 2
                and isinstance(statement.value.elts[0], ast.Constant)
                and statement.value.elts[0].value == 'fail')

    def contains_fail(statements):
        return any(is_fail(item) or isinstance(item, ast.If) and (
            contains_fail(item.body) or contains_fail(item.orelse))
                   for item in statements)

    if not contains_fail(tree.body[0].body):
        return
    if any(is_fail(item) for item in tree.body[0].body):
        raise ValueError('오프라인 판정의 fail에는 구체적인 응답 조건이 필요합니다.')
    for node in ast.walk(tree):
        if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and re.search(r's2r_[A-Za-z0-9_-]{8,60}', node.value, re.I)):
            raise ValueError('오프라인 판정은 보내지 않은 진단 마커 반사로 취약점을 확정할 수 없습니다.')

    def inspect_fail_branches(statements):
        for item in statements:
            if not isinstance(item, ast.If):
                continue
            if contains_fail(item.body) or contains_fail(item.orelse):
                for node in ast.walk(item.test):
                    if isinstance(node, ast.Compare) and any(
                            isinstance(op, (ast.In, ast.NotIn)) for op in node.ops):
                        for part in [node.left, *node.comparators]:
                            if (isinstance(part, ast.Constant) and isinstance(part.value, str)
                                    and 0 < len(part.value) < 8):
                                raise ValueError('오프라인 판정의 짧은 일반 문자열은 취약점 근거가 아닙니다.')
                inspect_fail_branches(item.body)
                inspect_fail_branches(item.orelse)

    inspect_fail_branches(tree.body[0].body)
    source_literals = _source_code_literals(source_context)
    if any(not any(needle in literal for literal in source_literals)
           for needle in _offline_body_needles(tree.body[0])):
        raise ValueError('오프라인 본문 fail 신호가 제공된 함수 코드의 문자열 리터럴에 없습니다.')


def _validate_active_html_signal(source, marker):
    """Every active fail path must require HTML and the exact inert tag."""
    function = ast.parse(source).body[0]
    aliases = {item.targets[0].id: item.value
               for item in function.body if isinstance(item, ast.Assign)
               and len(item.targets) == 1 and isinstance(item.targets[0], ast.Name)}

    def follow(node, seen=None):
        seen = set() if seen is None else seen
        if isinstance(node, ast.Name) and node.id not in {'body_text', 'headers'}:
            if node.id in seen:
                return node
            value = aliases.get(node.id)
            if value is not None:
                return follow(value, seen | {node.id})
        return node

    def literal(node):
        node = follow(node)
        return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

    def html_header(node):
        node = follow(node)
        return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == 'get'
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == 'headers'
                and len(node.args) in {1, 2}
                and literal(node.args[0]) == 'content-type')

    def facts(node):
        node = follow(node)
        if isinstance(node, ast.BoolOp):
            parts = [facts(value) for value in node.values]
            return (set().union(*parts) if isinstance(node.op, ast.And)
                    else set.intersection(*parts) if parts else set())
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.In):
            needle = literal(node.left)
            haystack = follow(node.comparators[0])
            if needle == 'text/html' and html_header(haystack):
                return {'html'}
            if needle == marker and isinstance(haystack, ast.Name) and haystack.id == 'body_text':
                return {'tag'}
        return set()

    def facts_false(node):
        node = follow(node)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return facts(node.operand)
        if isinstance(node, ast.BoolOp):
            parts = [facts_false(value) for value in node.values]
            return (set().union(*parts) if isinstance(node.op, ast.Or)
                    else set.intersection(*parts) if parts else set())
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.NotIn):
            needle = literal(node.left)
            haystack = follow(node.comparators[0])
            if needle == 'text/html' and html_header(haystack):
                return {'html'}
            if needle == marker and isinstance(haystack, ast.Name) and haystack.id == 'body_text':
                return {'tag'}
        return set()

    def always_returns(statements):
        if not statements:
            return False
        last = statements[-1]
        return (isinstance(last, ast.Return)
                or isinstance(last, ast.If) and bool(last.orelse)
                and always_returns(last.body) and always_returns(last.orelse))

    def walk(statements, required):
        current = set(required)
        for item in statements:
            if isinstance(item, ast.If):
                walk(item.body, current | facts(item.test))
                walk(item.orelse, current | facts_false(item.test))
                true_done, false_done = always_returns(item.body), always_returns(item.orelse)
                if true_done and false_done:
                    return
                if true_done:
                    current |= facts_false(item.test)
                elif false_done:
                    current |= facts(item.test)
            elif (isinstance(item, ast.Return)
                  and isinstance(item.value, ast.Tuple)
                  and isinstance(item.value.elts[0], ast.Constant)
                  and item.value.elts[0].value == 'fail'
                  and not {'html', 'tag'} <= current):
                raise ValueError('자동 fail 판정에는 HTML 유형과 정확한 태그 반사 조건이 모두 필요합니다.')

    walk(function.body, set())


def _validate_pair_signal(source, probe, source_context, fixture_hints=()):
    """Reject a model's single-response success claim for a two-response plan."""
    if (not isinstance(fixture_hints, (list, tuple))
            or any(not isinstance(hint, dict) or
                   not {'path', 'purpose', 'marker'} <= set(hint)
                   for hint in fixture_hints)):
        raise ValueError('샘플 파일 힌트 형식 오류')
    function = ast.parse(source).body[0]
    assignments = []
    for item in function.body:
        assignments.extend(item.body if isinstance(item, ast.Try) else [item])
    aliases = {item.targets[0].id: item.value for item in assignments
               if isinstance(item, ast.Assign) and len(item.targets) == 1
               and isinstance(item.targets[0], ast.Name)}
    key = probe['requests'][0]['query_key']
    candidate_value = probe['requests'][1]['probe_value']
    canary_markers = {
        hint['marker'] for hint in fixture_hints
        if (hint.get('purpose') == 'synthetic_canary' and hint.get('marker')
            and hint['path'].split('/')[-1] in candidate_value)
    }
    numbered = '\n'.join(line.split(' ', 1)[1] for line in (source_context or '').splitlines()
                         if re.match(r'^L\d{5} ', line))
    if not re.search(r'(?<![A-Za-z0-9_])' + re.escape(key) + r'(?![A-Za-z0-9_])', numbered):
        raise ValueError('AI 진단 입력명이 제공된 함수 코드에서 확인되지 않습니다.')

    def resolve(node, seen=None):
        seen = set() if seen is None else seen
        if isinstance(node, ast.Name) and node.id in aliases and node.id not in seen:
            return resolve(aliases[node.id], seen | {node.id})
        return node

    def field(node):
        json_kind = _json_kind(node, aliases)
        if json_kind and json_kind[0] == 'length':
            return (json_kind[1], 'json:' + json_kind[2] + ':length')
        if isinstance(node, ast.Name):
            if node.id in RESPONSE_FIELDS:
                return ('candidate', node.id)
            if node.id in BASELINE_FIELDS:
                return ('baseline', node.id.removeprefix('baseline_'))
        node = resolve(node)
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == 'get' and isinstance(node.func.value, ast.Name)
                and node.args and isinstance(node.args[0], ast.Constant)):
            owner = field(node.func.value)
            if owner and owner[1] == 'headers':
                return (owner[0], 'headers:' + str(node.args[0].value))
        return None

    def atom(test):
        if not isinstance(test, ast.Compare) or len(test.ops) != 1:
            return set()
        left, right = test.left, test.comparators[0]
        left_field, right_field = field(left), field(right)
        op = type(test.ops[0]).__name__
        if left_field and isinstance(resolve(right), ast.Constant):
            return {(left_field[0], left_field[1], op, resolve(right).value)}
        if right_field and isinstance(resolve(left), ast.Constant):
            return {(right_field[0], right_field[1], op, resolve(left).value)}
        if left_field and right_field and left_field[0] != right_field[0]:
            return {('cross', left_field[1], op, right_field[1])}
        return set()

    def facts(test):
        test = resolve(test)
        if isinstance(test, ast.BoolOp):
            groups = [facts(part) for part in test.values]
            return (set().union(*groups) if isinstance(test.op, ast.And)
                    else set.intersection(*groups) if groups else set())
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            opposite = {'In': 'NotIn', 'NotIn': 'In', 'Eq': 'NotEq',
                        'NotEq': 'Eq', 'Is': 'IsNot', 'IsNot': 'Is'}
            return {(origin, name, opposite[op], value)
                    for origin, name, op, value in facts(test.operand)
                    if op in opposite}
        return atom(test)

    def distinguished(known):
        baseline = [fact for fact in known if fact[0] == 'baseline']
        candidate = [fact for fact in known if fact[0] == 'candidate']
        if canary_markers:
            return any(('baseline', 'body_text', 'NotIn', marker) in known
                       and ('candidate', 'body_text', 'In', marker) in known
                       for marker in canary_markers)
        if any(fact[0] == 'cross' and fact[1] == fact[3]
               and fact[1].startswith('json:') and fact[1].endswith(':length')
               and fact[2] in {'Gt', 'Lt', 'NotEq'} for fact in known):
            return True
        return any(prior[1] == current[1] and
                   (prior[3] != current[3] or prior[2] != current[2])
                   for prior in baseline for current in candidate)

    def visit(statements, known):
        for statement in statements:
            if isinstance(statement, ast.If):
                visit(statement.body, known | facts(statement.test))
                visit(statement.orelse, known)
            elif (isinstance(statement, ast.Return)
                  and isinstance(statement.value, ast.Tuple)
                  and isinstance(statement.value.elts[0], ast.Constant)
                  and statement.value.elts[0].value == 'fail'
                  and not distinguished(known)):
                raise ValueError('자동 fail 판정에는 기준/후보의 구별되는 응답 조건이 필요합니다.')

    visit(function.body, set())


def validate_plan(plan, scenario, *, offline=False, source_context=None):
    if not isinstance(plan, dict) or set(plan) != {'probe', 'source', 'reason'}:
        raise ValueError('AI 점검 계획 형식 오류')
    probe = validate_probe(plan['probe'])
    if isinstance(probe, dict) and probe.get('requests'):
        expected_name = scenario.get('input_name')
        expected_location = scenario.get('input_location')
        for request in probe['requests']:
            if expected_name is not None and request['query_key'] != expected_name:
                raise ValueError('AI 진단 입력명이 선택한 소스 입력과 일치하지 않습니다.')
            if (expected_location is not None
                    and request.get('input_location', 'query') != expected_location):
                raise ValueError('AI 진단 입력 위치가 선택한 소스 입력과 일치하지 않습니다.')
    elif isinstance(probe, dict) and probe.get('query_key') is not None:
        if (scenario.get('input_name') is not None
                and probe['query_key'] != scenario['input_name']):
            raise ValueError('AI 진단 입력명이 선택한 소스 입력과 일치하지 않습니다.')
        if (scenario.get('input_location') is not None
                and probe.get('input_location', 'query') != scenario['input_location']):
            raise ValueError('AI 진단 입력 위치가 선택한 소스 입력과 일치하지 않습니다.')
    source = _normalize_model_source(plan['source']) if isinstance(plan['source'], str) else plan['source']
    if isinstance(probe, dict) and 'requests' in probe:
        if offline and probe['requests']:
            raise ValueError('오프라인 점검 계획은 네트워크 진단 입력을 가질 수 없습니다.')
        validate_check(source, scenario, probe, offline=offline)
        if source_context is None:
            source_context = scenario.get('source_context')
        if probe['requests']:
            _validate_pair_signal(source, probe, source_context,
                                  scenario.get('fixture_hints', ()))
            tag = probe['requests'][1]['probe_value']
            if TAGGED_MARKER.fullmatch(tag):
                _validate_active_html_signal(source, tag)
        else:
            _validate_offline_signal(source, source_context)
        reason = plan['reason']
        if not isinstance(reason, str) or not 1 <= len(reason) <= 600:
            raise ValueError('AI 점검 계획 설명 범위 오류')
        return {'probe': probe, 'source': source.rstrip() + '\n',
                'reason': reason.strip()}
    if offline and probe['query_key'] is not None:
        raise ValueError('오프라인 점검 계획은 네트워크 진단 입력을 가질 수 없습니다.')
    if not offline and probe['query_key'] is not None and PLAIN_MARKER.fullmatch(probe['probe_value']):
        raise ValueError('평문 마커 반사는 자동 취약점 판정 근거가 될 수 없습니다.')
    validate_check(source, scenario, probe, offline=offline)
    if source_context is None:
        source_context = scenario.get('source_context')
    if offline or probe['query_key'] is None:
        _validate_offline_signal(source, source_context)
    else:
        _validate_active_html_signal(source, probe['probe_value'])
    reason = plan['reason']
    if not isinstance(reason, str) or not 1 <= len(reason) <= 600:
        raise ValueError('AI 점검 계획 설명 범위 오류')
    # Keep the original evaluate(response) form so this plan can be validated
    # again at the live-result and download boundaries.
    return {'probe': probe, 'source': source.rstrip() + '\n',
            'reason': reason.strip()}


def evaluate_observation(plan, scenario, observation, *, offline=False, source_context=None):
    """Apply the same validated evaluator used by the downloadable script."""
    approved = validate_plan(plan, scenario, offline=offline, source_context=source_context)
    if 'requests' in approved['probe'] and approved['probe']['requests']:
        if (not isinstance(observation, dict)
                or not isinstance(observation.get('baseline'), dict)
                or not isinstance(observation.get('candidate'), dict)):
            return 'inconclusive', '기준/후보 응답을 모두 확인하지 못했습니다.'

        def normalize(item):
            status = item.get('status_code', item.get('status'))
            raw_headers = item.get('headers') or {}
            headers = ({str(k).lower(): str(v)[:1000] for k, v in raw_headers.items()}
                       if isinstance(raw_headers, dict) else {})
            body = item.get('body_text')
            within = item.get('body_within_limit') is True
            if not isinstance(body, str):
                body, within = '', False
            return {'status': status, 'error': item.get('error'),
                    'body_text': body[:65536], 'body_within_limit': within,
                    'headers': headers}

        baseline = normalize(observation['baseline'])
        candidate = normalize(observation['candidate'])
        if baseline['error'] is not None or candidate['error'] is not None:
            return 'unavailable', '기준 또는 후보 요청에서 연결 오류가 발생했습니다.'
        if (any(not isinstance(item['status'], int) or not 100 <= item['status'] <= 599
                for item in (baseline, candidate))):
            return 'inconclusive', '기준 또는 후보 HTTP 상태 코드를 확인하지 못했습니다.'
        if not baseline['body_within_limit'] or not candidate['body_within_limit']:
            return 'inconclusive', '기준 또는 후보 응답이 크기 제한을 넘었습니다.'
        response = {**candidate,
                    **{'baseline_' + key: value for key, value in baseline.items()}}
        try:
            verdict = load_evaluator(approved['source'], scenario, approved['probe'])(response)
        except (TypeError, ValueError, KeyError, IndexError, AttributeError, RecursionError):
            return 'inconclusive', 'AI 판정 함수가 이 응답을 해석하지 못했습니다.'
        if (not isinstance(verdict, tuple) or len(verdict) != 2
                or verdict[0] not in STATUSES or not isinstance(verdict[1], str)
                or not 1 <= len(verdict[1]) <= 200):
            return 'inconclusive', 'AI 판정 함수의 결과 형식이 올바르지 않습니다.'
        return verdict
    if not isinstance(observation, dict):
        return 'inconclusive', '서버 응답을 확인하지 못했습니다.'
    if observation.get('error') is not None:
        return 'unavailable', '대상 서버에 연결하지 못했습니다.'
    status = observation.get('status_code', observation.get('status'))
    if status == 404:
        return 'not_found', '선택한 경로가 404를 반환했습니다.'
    if not isinstance(status, int) or not 100 <= status <= 599:
        return 'inconclusive', 'HTTP 상태 코드를 확인하지 못했습니다.'
    raw_headers = observation.get('headers') or {}
    headers = ({str(k).lower(): str(v)[:1000] for k, v in raw_headers.items()}
               if isinstance(raw_headers, dict) else {})
    body_text = observation.get('body_text')
    within_limit = observation.get('body_within_limit')
    if not isinstance(body_text, str):
        body_text = ''
        within_limit = False
    body_text = body_text[:65536]
    if within_limit is not True:
        within_limit = False
    response = {'status': status, 'error': None, 'body_text': body_text,
                'body_within_limit': within_limit, 'headers': headers}
    try:
        verdict = load_evaluator(approved['source'], scenario, approved['probe'],
                                 offline=offline)(response)
    except (TypeError, ValueError, KeyError, IndexError, AttributeError, RecursionError):
        return 'inconclusive', 'AI 판정 함수가 이 응답을 해석하지 못했습니다.'
    if (not isinstance(verdict, tuple) or len(verdict) != 2
            or verdict[0] not in STATUSES or not isinstance(verdict[1], str)
            or not 1 <= len(verdict[1]) <= 200):
        return 'inconclusive', 'AI 판정 함수의 결과 형식이 올바르지 않습니다.'
    return verdict
