"""Conservative source binding for a selected diagnostic route.

This is an execution boundary, not a vulnerability recognizer. It checks the
original snapshot rather than trusting a model-provided handler snippet. An
unrecognized framework, binding, decorator, statement or expression stays
offline.
"""

import ast
import re
from pathlib import PurePosixPath


LITERAL_PATH = re.compile(r'/[A-Za-z0-9/_.~-]*\Z')
RESPONSE_CLASSES = frozenset({
    'Response', 'HTMLResponse', 'PlainTextResponse', 'JSONResponse',
    'RedirectResponse',
})
_CRITICAL = frozenset({'FastAPI', 'Query', 'Body', 'str', 'app', *RESPONSE_CLASSES})
EFFECTFUL_CALL = re.compile(
    r'(?i:save|write|update|delete|remove|create|insert|commit|flush|publish|'
    r'enqueue|dispatch|upload|unlink|mkdir|rmdir|truncate|execute|open|run)'
    r'(?:_|[A-Z]|$)')


def _fail(reason):
    return False, reason


def _direct_imports(tree):
    """Map direct import bindings and reject ambiguous imports later."""
    imports = {}
    for statement in tree.body:
        if isinstance(statement, ast.ImportFrom) and statement.level == 0:
            for alias in statement.names:
                if alias.name == '*':
                    return None
                bound = alias.asname or alias.name
                imports.setdefault(bound, []).append((statement.module, alias.name,
                                                       statement.lineno))
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                bound = alias.asname or alias.name.split('.', 1)[0]
                imports.setdefault(bound, []).append((alias.name, None,
                                                       statement.lineno))
    return imports


def _find_handler(scope, line, ancestors=()):
    """Accept a route declared directly in a module or function body."""
    for statement in scope.body:
        if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if statement.lineno == line:
            return statement, scope, ancestors
        if statement.lineno < line <= (statement.end_lineno or statement.lineno):
            found = _find_handler(statement, line, (*ancestors, statement))
            if found is not None:
                return found
    return None


def _app_assignment(scope, before_line):
    found = []
    for statement in scope.body:
        if isinstance(statement, ast.Assign):
            if len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name):
                if statement.targets[0].id == 'app':
                    found.append(statement)
        elif isinstance(statement, ast.AnnAssign):
            if isinstance(statement.target, ast.Name) and statement.target.id == 'app':
                found.append(statement)
    if len(found) != 1 or found[0].lineno >= before_line:
        return None
    assignment = found[0]
    value = assignment.value
    if (not isinstance(value, ast.Call) or not isinstance(value.func, ast.Name)
            or value.func.id != 'FastAPI' or value.args or any(keyword.arg is None
                                                for keyword in value.keywords)):
        return None
    allowed = {'title', 'version', 'description', 'docs_url', 'redoc_url',
               'openapi_url', 'debug', 'lifespan'}
    keys = [keyword.arg for keyword in value.keywords]
    if len(keys) != len(set(keys)) or not set(keys) <= allowed:
        return None
    for keyword in value.keywords:
        item = keyword.value
        if keyword.arg == 'lifespan':
            if not isinstance(item, ast.Name) or not item.id.isidentifier():
                return None
        elif keyword.arg == 'debug':
            if not isinstance(item, ast.Constant) or type(item.value) is not bool:
                return None
        elif (not isinstance(item, ast.Constant)
              or item.value is not None and not isinstance(item.value, str)):
            return None
    return assignment


def _unshadowed(tree, imports, names, app_binding):
    """Reject any rebinding that could change the resolved FastAPI symbols."""
    if imports.get('app') or imports.get('str'):
        return False
    for name, module, original in names:
        bindings = imports.get(name, [])
        if len(bindings) != 1 or bindings[0][:2] != (module, original):
            return False
    protected = {name for name, _, _ in names} | {'app', 'str'}
    allowed_app_store = (app_binding.targets[0] if isinstance(app_binding, ast.Assign)
                         else app_binding.target)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(alias.name == '*' for alias in node.names):
            return False
        if isinstance(node, (ast.Import, ast.ImportFrom)) and node not in tree.body:
            # A nested import can replace a binding in the route's lexical scope.
            bound = [(alias.asname or alias.name.split('.', 1)[0])
                     for alias in node.names]
            if protected.intersection(bound):
                return False
        if isinstance(node, ast.Name) and node.id in protected and isinstance(node.ctx, (ast.Store, ast.Del)):
            if node is not allowed_app_store:
                return False
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            if isinstance(node.value, ast.Name) and (
                    node.value.id in protected - {'app'}
                    or node.value.id == 'app' and node.attr in {'get', 'route', 'router'}):
                return False
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in {'exec', 'eval', 'globals', 'locals', 'setattr', 'delattr'}):
            # These can replace imports or app methods without an AST Store.
            return False
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in protected:
            return False
        # A distinct nested function may have its own app parameter (TechLab's
        # lifespan hook does). Only names shared with the imported constructors
        # can shadow the response call in the handler.
        if isinstance(node, ast.arg) and node.arg in protected - {'app'}:
            return False
        if isinstance(node, (ast.Global, ast.Nonlocal)) and protected.intersection(node.names):
            return False
        if isinstance(node, ast.ExceptHandler) and node.name in protected:
            return False
        if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name in protected:
            return False
        if isinstance(node, ast.MatchMapping) and node.rest in protected:
            return False
    return True


def _route_decorator(function, path, imports, method='GET'):
    if len(function.decorator_list) != 1:
        return False
    decorator = function.decorator_list[0]
    if (not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute)
            or decorator.func.attr != method.lower()
            or not isinstance(decorator.func.value, ast.Name)
            or decorator.func.value.id != 'app'
            or len(decorator.args) != 1 or not isinstance(decorator.args[0], ast.Constant)
            or decorator.args[0].value != path):
        return False
    seen = set()
    for keyword in decorator.keywords:
        key, value = keyword.arg, keyword.value
        if key in seen:
            return False
        seen.add(key)
        if key == 'response_class':
            if (not isinstance(value, ast.Name) or value.id not in RESPONSE_CLASSES
                    or len(imports.get(value.id, [])) != 1
                    or imports[value.id][0][:2] != ('fastapi.responses', value.id)):
                return False
        elif key == 'tags':
            if (not isinstance(value, (ast.List, ast.Tuple)) or len(value.elts) > 10
                    or any(not isinstance(item, ast.Constant) or not isinstance(item.value, str)
                           or len(item.value) > 80 for item in value.elts)):
                return False
        elif key == 'include_in_schema':
            if not isinstance(value, ast.Constant) or type(value.value) is not bool:
                return False
        else:
            # dependencies, callbacks and dynamic metadata can execute or alter
            # the request path, so this proof does not attempt to reason about them.
            return False
    return True


def _query_default(default, imports):
    if isinstance(default, ast.Constant) and isinstance(default.value, str):
        return True, False
    if (not isinstance(default, ast.Call) or not isinstance(default.func, ast.Name)
            or default.func.id != 'Query' or default.args
            or any(keyword.arg is None for keyword in default.keywords)):
        return False, False
    if len(imports.get('Query', [])) != 1 or imports['Query'][0][:2] != ('fastapi', 'Query'):
        return False, False
    keys = {keyword.arg for keyword in default.keywords}
    if (len(keys) != len(default.keywords) or 'default' not in keys
            or not keys <= {'default', 'max_length', 'min_length'}):
        return False, False
    for keyword in default.keywords:
        value = keyword.value
        if keyword.arg == 'default':
            if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                return False, False
        elif (not isinstance(value, ast.Constant) or type(value.value) is not int
              or not 0 <= value.value <= 10_000):
            return False, False
    return True, True


def _body_default(default, imports):
    """Accept only a primitive JSON string embedded under its field name."""
    if (not isinstance(default, ast.Call) or not isinstance(default.func, ast.Name)
            or default.func.id != 'Body' or len(default.args) > 1
            or any(keyword.arg is None for keyword in default.keywords)
            or len(imports.get('Body', [])) != 1
            or imports['Body'][0][:2] != ('fastapi', 'Body')):
        return False
    keys = [keyword.arg for keyword in default.keywords]
    if (len(keys) != len(set(keys)) or not set(keys) <=
            {'default', 'embed', 'max_length', 'min_length'}
            or bool(default.args) and 'default' in keys):
        return False
    options = {keyword.arg: keyword.value for keyword in default.keywords}
    embedded = options.get('embed')
    if not isinstance(embedded, ast.Constant) or embedded.value is not True:
        return False
    values = [*default.args]
    if 'default' in options:
        values.append(options['default'])
    if any(not isinstance(value, ast.Constant)
           or not (isinstance(value.value, str) or value.value is Ellipsis)
           for value in values):
        return False
    for key in ('max_length', 'min_length'):
        value = options.get(key)
        if value is not None and (not isinstance(value, ast.Constant)
                                  or type(value.value) is not int
                                  or not 0 <= value.value <= 10_000):
            return False
    return True


def _signature(function, input_name, imports):
    args = function.args
    if (len(args.args) != 1 or args.args[0].arg != input_name
            or args.posonlyargs or args.kwonlyargs or args.vararg or args.kwarg
            or args.kw_defaults or len(args.defaults) != 1):
        return False, False
    annotation = args.args[0].annotation
    if not isinstance(annotation, ast.Name) or annotation.id != 'str':
        return False, False
    return _query_default(args.defaults[0], imports)


def _body_signature(function, input_name, imports):
    args = function.args
    if (len(args.args) != 1 or args.args[0].arg != input_name
            or args.posonlyargs or args.kwonlyargs or args.vararg or args.kwarg
            or args.kw_defaults or len(args.defaults) != 1):
        return False
    annotation = args.args[0].annotation
    return (isinstance(annotation, ast.Name) and annotation.id == 'str'
            and _body_default(args.defaults[0], imports))


def _literal_or_input(expression, input_name):
    """Return whether an expression is pure and whether it reads the query."""
    if isinstance(expression, ast.Constant) and type(expression.value) in {str, int, float}:
        return True, False
    if isinstance(expression, ast.Name) and expression.id == input_name:
        return True, True
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Add):
        left, left_input = _literal_or_input(expression.left, input_name)
        right, right_input = _literal_or_input(expression.right, input_name)
        return left and right, left_input or right_input
    if isinstance(expression, ast.JoinedStr):
        checked = [_literal_or_input(value, input_name) for value in expression.values]
        return all(pure for pure, _ in checked), any(used for _, used in checked)
    if (isinstance(expression, ast.FormattedValue) and expression.conversion == -1
            and expression.format_spec is None
            and isinstance(expression.value, ast.Name)
            and expression.value.id == input_name):
        return True, True
    return False, False


def _direct_response(function, input_name, imports):
    if len(function.body) != 1 or not isinstance(function.body[0], ast.Return):
        return False, None
    result = function.body[0].value
    if (not isinstance(result, ast.Call) or not isinstance(result.func, ast.Name)
            or result.func.id not in RESPONSE_CLASSES or len(result.args) > 1
            or any(keyword.arg is None for keyword in result.keywords)):
        return False, None
    constructor = result.func.id
    bindings = imports.get(constructor, [])
    if len(bindings) != 1 or bindings[0][:2] != ('fastapi.responses', constructor):
        return False, None
    content_key = 'url' if constructor == 'RedirectResponse' else 'content'
    keyword_names = [keyword.arg for keyword in result.keywords]
    if (len(set(keyword_names)) != len(keyword_names)
            or not set(keyword_names) <= {content_key, 'status_code', 'media_type'}
            or constructor == 'RedirectResponse' and 'media_type' in keyword_names
            or result.args and content_key in keyword_names
            or not result.args and content_key not in keyword_names):
        return False, None
    values = [*result.args]
    for keyword in result.keywords:
        value = keyword.value
        if keyword.arg == 'status_code':
            if (not isinstance(value, ast.Constant) or type(value.value) is not int
                    or not 100 <= value.value <= 599):
                return False, None
        elif keyword.arg == 'media_type':
            if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                return False, None
        else:
            values.append(value)
    checked = [_literal_or_input(value, input_name) for value in values]
    return (all(pure for pure, _ in checked) and any(used for _, used in checked)), constructor


def prove_direct_probe(files, endpoint, input_name, input_location='query'):
    """Return whether the source proves a direct FastAPI scalar response.

    This deliberately excludes Flask/Django/JavaScript/Java/PHP and complex
    FastAPI handlers. It verifies only the handler's direct response; app-wide
    middleware and deployment configuration still require separate review.
    """
    if not isinstance(files, dict) or not isinstance(endpoint, dict):
        return _fail('원본 소스 또는 엔드포인트 형식이 올바르지 않습니다.')
    handler = endpoint.get('handler')
    if not isinstance(handler, dict):
        return _fail('처리 함수의 원본 위치를 확인할 수 없습니다.')
    path, source_path, line = endpoint.get('path'), handler.get('file'), handler.get('line')
    method = endpoint.get('method')
    if (endpoint.get('framework') != 'FastAPI'
            or not isinstance(method, str) or not re.fullmatch(r'[A-Z]{3,7}', method)
            or input_location not in {'query', 'body'}
            or not isinstance(path, str) or not LITERAL_PATH.fullmatch(path)
            or path.startswith('//') or any(part in {'.', '..'} for part in path.split('/'))
            or not isinstance(source_path, str) or PurePosixPath(source_path).suffix != '.py'
            or source_path not in files or type(line) is not int or line < 1
            or not isinstance(input_name, str) or not input_name.isidentifier()):
        return _fail('지원되는 FastAPI 함수와 고정 경로를 확인할 수 없습니다.')
    source = files[source_path]
    if not isinstance(source, str) or len(source) > 1_000_000:
        return _fail('원본 Python 파일의 크기 또는 형식을 확인할 수 없습니다.')
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return _fail('원본 Python 파일을 구문 분석하지 못했습니다.')
    located = _find_handler(tree, line)
    if located is None:
        return _fail('모델이 지정한 함수 줄과 원본 AST가 일치하지 않습니다.')
    function, scope, ancestors = located
    if (len(ancestors) > 1 or any(ancestor.decorator_list for ancestor in ancestors)
            or handler.get('symbol', '').split('.')[-1] != function.name
            or type(handler.get('end_line')) is not int
            or handler['end_line'] < (function.end_lineno or function.lineno)):
        return _fail('함수 범위 또는 바깥쪽 데코레이터를 확인할 수 없습니다.')
    imports = _direct_imports(tree)
    if imports is None or len(imports.get('FastAPI', [])) != 1 or imports['FastAPI'][0][:2] != ('fastapi', 'FastAPI'):
        return _fail('FastAPI 생성자의 직접 import 바인딩을 확인할 수 없습니다.')
    app_binding = _app_assignment(scope, function.lineno)
    if app_binding is None:
        return _fail('라우터 app이 실제 FastAPI 인스턴스와 연결되지 않았습니다.')
    if not _route_decorator(function, path, imports, method):
        return _fail('단일 FastAPI 경로 데코레이터 또는 안전한 메타데이터를 확인할 수 없습니다.')
    if input_location == 'query':
        signature_ok, uses_query = _signature(function, input_name, imports)
    else:
        signature_ok, uses_query = _body_signature(function, input_name, imports), False
    if not signature_ok:
        return _fail('선택적 문자열 쿼리 하나로 된 함수 시그니처가 아닙니다.')
    direct, response_name = _direct_response(function, input_name, imports)
    if not direct:
        return _fail('함수에서 선택 쿼리만 사용하는 직접 응답을 확인할 수 없습니다.')
    required = [('FastAPI', 'fastapi', 'FastAPI'),
                (response_name, 'fastapi.responses', response_name)]
    for keyword in function.decorator_list[0].keywords:
        if keyword.arg == 'response_class':
            class_name = keyword.value.id
            if class_name != response_name:
                required.append((class_name, 'fastapi.responses', class_name))
    if uses_query:
        required.append(('Query', 'fastapi', 'Query'))
    if input_location == 'body':
        required.append(('Body', 'fastapi', 'Body'))
    if not _unshadowed(tree, imports, required, app_binding):
        return _fail('FastAPI, 응답 생성자 또는 쿼리 바인딩이 재정의될 수 있습니다.')
    if imports['FastAPI'][0][2] >= app_binding.lineno or imports[response_name][0][2] >= function.lineno:
        return _fail('FastAPI 또는 응답 생성자 import의 실행 순서를 확인할 수 없습니다.')
    return True, ''


def prove_direct_get(files, endpoint, input_name):
    """Compatibility proof for the original GET/query direct-response path."""
    if endpoint.get('method') != 'GET':
        return _fail('GET 경로가 아닙니다.')
    return prove_direct_probe(files, endpoint, input_name, 'query')


def prove_probe_safe(files, endpoint, input_name, input_location='query'):
    """Check route and selected input against the original source snapshot.

    The check is independent of the HTTP method. It accepts only literal paths,
    source-backed route registration, and a supported scalar query or JSON body
    binding. The transport fixes the method and destination separately.
    """
    if not isinstance(files, dict) or not isinstance(endpoint, dict):
        return _fail('원본 소스 또는 엔드포인트 형식이 올바르지 않습니다.')
    path, handler, method = (endpoint.get('path'), endpoint.get('handler'),
                             endpoint.get('method'))
    if (not isinstance(method, str) or not re.fullmatch(r'[A-Z]{3,7}', method)
            or not isinstance(path, str)
            or not LITERAL_PATH.fullmatch(path) or path.startswith('//')
            or any(part in {'.', '..'} for part in path.split('/'))):
        return _fail('선택한 고정 경로와 메서드를 확인할 수 없습니다.')
    if input_location not in {'query', 'body'}:
        return _fail('지원되는 입력 위치를 확인할 수 없습니다.')
    if (not isinstance(input_name, str) or not input_name.isidentifier()
            or not any(isinstance(item, dict) and item.get('name') == input_name
                       and item.get('in') == input_location
                       for item in endpoint.get('inputs', []))):
        return _fail('선택한 입력의 이름과 위치를 소스에 연결할 수 없습니다.')
    if not isinstance(handler, dict):
        return _fail('처리 함수의 원본 위치를 확인할 수 없습니다.')
    source_path, line, end = handler.get('file'), handler.get('line'), handler.get('end_line')
    if (not isinstance(source_path, str) or source_path not in files
            or type(line) is not int or type(end) is not int or line < 1 or end < line
            or not isinstance(files[source_path], str)):
        return _fail('처리 함수의 원본 범위를 확인할 수 없습니다.')
    source_lines = files[source_path].splitlines()
    if end > len(source_lines) or not source_lines[line - 1].strip():
        return _fail('처리 함수의 원본 줄이 분석 당시 소스와 일치하지 않습니다.')
    if (endpoint.get('framework') == 'FastAPI'
            and PurePosixPath(source_path).suffix == '.py'):
        direct, _ = prove_direct_probe(files, endpoint, input_name, input_location)
        if direct:
            return True, ''
    registration = [row for row in endpoint.get('call_chain', [])
                    if isinstance(row, dict) and row.get('reason') == 'route registration']
    if not registration or any(
            row.get('file') not in files or type(row.get('line')) is not int
            or not 1 <= row['line'] <= len(files[row['file']].splitlines())
            or not files[row['file']].splitlines()[row['line'] - 1].strip()
            for row in registration):
        return _fail('원본 코드의 라우트 등록 근거를 확인할 수 없습니다.')
    route_declarations = '\n'.join(
        files[row['file']].splitlines()[row['line'] - 1] for row in registration)
    if method.lower() not in route_declarations.lower():
        return _fail('원본 라우트 선언에서 선택한 메서드를 확인할 수 없습니다.')

    if endpoint.get('framework') != 'FastAPI' or PurePosixPath(source_path).suffix != '.py':
        # The route citation was checked against the snapshot during analysis.
        # Also require the selected field in the original handler text, rather
        # than trusting an endpoint input row by itself.
        code = '\n'.join(source_lines[line - 1:end])
        if not re.search(r'(?<![\w$])' + re.escape(input_name) + r'(?![\w$])', code):
            return _fail('선택한 입력을 원본 처리 함수에서 찾을 수 없습니다.')
        for source_line in code.splitlines():
            if re.match(r'\s*(?:async\s+def|def|(?:export\s+)?(?:async\s+)?function)\b',
                        source_line):
                continue
            for match in re.finditer(r'\b([A-Za-z_$][\w$]*)\s*\(', source_line):
                if EFFECTFUL_CALL.match(match.group(1)) or match.group(1) in {
                        'exec', 'eval', 'spawn', 'system', 'fetch'}:
                    return _fail('처리 함수에 직접 상태 변경이나 외부 호출이 보입니다.')
        if re.search(r'\b(?:session|db|database|repository|store)\s*(?:\.|\[)[^\n=]*=', code):
            return _fail('처리 함수에 외부 상태 대입이 보입니다.')
        return True, ''

    try:
        tree = ast.parse(files[source_path])
    except (SyntaxError, ValueError, RecursionError):
        return _fail('원본 Python 파일을 구문 분석하지 못했습니다.')
    located = _find_handler(tree, line)
    if located is None:
        return _fail('처리 함수와 원본 AST가 일치하지 않습니다.')
    function, scope, ancestors = located
    if (len(ancestors) > 1 or any(item.decorator_list for item in ancestors)
            or function.name != str(handler.get('symbol', '')).split('.')[-1]
            or end < (function.end_lineno or function.lineno)):
        return _fail('처리 함수 범위와 실제 선언이 일치하지 않습니다.')
    imports = _direct_imports(tree)
    if (imports is None or len(imports.get('FastAPI', [])) != 1
            or imports['FastAPI'][0][:2] != ('fastapi', 'FastAPI')):
        return _fail('FastAPI 라우트의 import 바인딩을 확인할 수 없습니다.')
    app_binding = _app_assignment(scope, function.lineno)
    if app_binding is None or not _route_decorator(function, path, imports, method):
        return _fail('원본 소스의 FastAPI 경로 등록을 확인할 수 없습니다.')
    if not _unshadowed(tree, imports, [('FastAPI', 'fastapi', 'FastAPI')], app_binding):
        return _fail('FastAPI 라우트 바인딩이 재정의될 수 있습니다.')
    parameters = function.args.args
    if (function.args.posonlyargs or function.args.vararg or function.args.kwarg
            or function.args.kwonlyargs or len(function.args.defaults) > len(parameters)):
        return _fail('처리 함수의 입력 바인딩을 확인할 수 없습니다.')
    defaults = {argument.arg: default for argument, default in
                zip(parameters[-len(function.args.defaults):], function.args.defaults)}
    if input_name not in defaults:
        return _fail('선택한 입력이 원본 함수에 바인딩되지 않았습니다.')
    selected = next((argument for argument in parameters if argument.arg == input_name), None)
    if (selected is None or not isinstance(selected.annotation, ast.Name)
            or selected.annotation.id != 'str'):
        return _fail('선택한 입력은 단순 문자열이어야 합니다.')
    if input_location == 'query':
        bound = _query_default(defaults[input_name], imports)[0]
    else:
        bound = _body_default(defaults[input_name], imports)
    if not bound:
        return _fail('선택한 입력의 원본 쿼리 또는 JSON 본문 바인딩이 일치하지 않습니다.')
    if not any(isinstance(node, ast.Name) and node.id == input_name
               and isinstance(node.ctx, ast.Load) for node in ast.walk(function)):
        return _fail('선택한 입력을 처리 함수가 사용하지 않습니다.')
    if input_location == 'body' and not _unshadowed(
            tree, imports, [('FastAPI', 'fastapi', 'FastAPI'),
                            ('Body', 'fastapi', 'Body')], app_binding):
        return _fail('JSON 본문 또는 FastAPI 바인딩이 재정의될 수 있습니다.')
    for node in ast.walk(function):
        if isinstance(node, (ast.AugAssign, ast.Delete, ast.NamedExpr, ast.For,
                             ast.AsyncFor, ast.While, ast.With, ast.AsyncWith,
                             ast.Try, ast.Yield, ast.YieldFrom, ast.Await,
                             ast.Global, ast.Nonlocal)):
            return _fail('상태 변경 또는 복잡한 실행 경로가 있어 자동 요청을 보류합니다.')
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(part, (ast.Attribute, ast.Subscript))
                   for target in targets for part in ast.walk(target)):
                return _fail('처리 함수가 외부 상태에 대입할 수 있습니다.')
        if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)):
            return _fail('처리 함수에 응답과 분리된 호출이 있습니다.')
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in {'exec', 'eval', 'setattr', 'delattr'}):
            return _fail('처리 함수에 동적 상태 변경 호출이 있습니다.')
        if isinstance(node, ast.Call):
            callee = (node.func.id if isinstance(node.func, ast.Name) else
                      node.func.attr if isinstance(node.func, ast.Attribute) else '')
            if EFFECTFUL_CALL.match(callee):
                return _fail('처리 함수에 상태 변경을 수행할 수 있는 호출이 있습니다.')
    return True, ''


def prove_read_only_get(files, endpoint, input_name):
    """Compatibility entrypoint for previously saved GET/query diagnostics."""
    return prove_probe_safe(files, endpoint, input_name, 'query')
