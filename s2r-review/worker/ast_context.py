"""Bounded, evidence-linked Python AST hints for the AI source reader.

These are syntactic facts, not a route inventory or vulnerability findings.  The
model must still examine the numbered source, identify endpoints and form its
own hypotheses.  No target module is imported or executed.
"""

import ast
import json
from pathlib import PurePosixPath


MAX_FILE_CHARS = 200_000
MAX_TOTAL_PARSE_CHARS = 500_000
MAX_FILES = 40
MAX_CONTEXT_CHARS = 24_000
MAX_FUNCTIONS = 90
MAX_BODY_FACTS = 18
MAX_NAME_CHARS = 120
REGISTRATION_CALLS = {
    'path', 're_path', 'include', 'register_blueprint', 'include_router',
    'add_url_rule', 'add_api_route', 'add_route', 'route',
}


def _name(node):
    """Render only a dotted Python identifier, never arbitrary source text."""
    if isinstance(node, ast.Name):
        value = node.id
    elif isinstance(node, ast.Attribute):
        parent = _name(node.value)
        value = f'{parent}.{node.attr}' if parent else ''
    else:
        value = ''
    return value[:MAX_NAME_CHARS]


def _literal(node):
    if isinstance(node, ast.Constant):
        value = node.value
        if isinstance(value, str):
            return value[:100] if value.isprintable() else None
        if isinstance(value, (int, bool)):
            return value
    if isinstance(node, (ast.List, ast.Tuple)) and len(node.elts) <= 6:
        values = [_literal(part) for part in node.elts]
        if all(value is not None for value in values):
            return values
    return None


def _refs(node, *, limit=12):
    result = []
    if node is None:
        return result
    for part in ast.walk(node):
        if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Load):
            name = part.id[:MAX_NAME_CHARS]
            if name not in result:
                result.append(name)
                if len(result) >= limit:
                    break
    return result


def _visible(path, node, shown):
    return isinstance(getattr(node, 'lineno', None), int) and (path, node.lineno) in shown


def _visible_span(path, node, shown):
    start = getattr(node, 'lineno', None)
    end = getattr(node, 'end_lineno', start)
    return (isinstance(start, int) and isinstance(end, int) and end >= start
            and all((path, line) in shown for line in range(start, end + 1)))


def _call(node):
    refs = []
    for expression in [*node.args, *(part.value for part in node.keywords)]:
        for name in _refs(expression):
            if name not in refs:
                refs.append(name)
    result = {'callee': _name(node.func), 'refs': refs[:12]}
    literals = [_literal(arg) for arg in node.args[:3]]
    if any(value is not None for value in literals):
        result['literal_args'] = literals
    keywords = {part.arg: _literal(part.value) for part in node.keywords[:8]
                if part.arg and _literal(part.value) is not None}
    if keywords:
        result['literal_keywords'] = keywords
    return result


def _target_names(node):
    return list(dict.fromkeys(part.id[:MAX_NAME_CHARS] for part in ast.walk(node)
                              if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Store)))[:8]


def _body_nodes(function):
    """Walk the body without assigning a nested function's uses to its parent."""
    pending = list(reversed(function.body))
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield node
        pending.extend(reversed(list(ast.iter_child_nodes(node))))


def _functions(tree):
    """Include nested app factories and class methods, retaining their scope."""
    pending = [(node, ()) for node in reversed(tree.body)]
    while pending:
        node, scope = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            current = (*scope, (node.name, node.lineno))
            yield node, current
            pending.extend((child, current) for child in reversed(node.body))
        elif isinstance(node, ast.ClassDef):
            current = (*scope, (node.name, node.lineno))
            pending.extend((child, current) for child in reversed(node.body))
        elif isinstance(node, ast.If):
            pending.extend((child, scope) for child in reversed(node.body + node.orelse))
        elif isinstance(node, (ast.Try, ast.TryStar)):
            children = node.body + node.orelse + node.finalbody
            for handler in node.handlers:
                children += handler.body
            pending.extend((child, scope) for child in reversed(children))


def _function_fact(path, node, scope, shown):
    if not _visible(path, node, shown):
        return None
    symbol = '.'.join(name for name, line in scope if (path, line) in shown)
    fact = {'kind': 'function', 'file': path, 'line': node.lineno,
            'symbol': symbol[:MAX_NAME_CHARS],
            'parameters': [arg.arg[:MAX_NAME_CHARS] for arg in
                           node.args.posonlyargs + node.args.args + node.args.kwonlyargs
                           if _visible(path, arg, shown)][:25]}
    decorators = []
    for decorator in node.decorator_list[:8]:
        if not _visible_span(path, decorator, shown):
            continue
        row = {'line': decorator.lineno}
        row.update(_call(decorator) if isinstance(decorator, ast.Call)
                   else {'callee': _name(decorator)})
        decorators.append(row)
    if decorators:
        fact['decorators'] = decorators
    calls, assignments, returns, subscripts = [], [], [], []
    for item in _body_nodes(node):
        if not _visible_span(path, item, shown):
            continue
        if isinstance(item, ast.Call) and len(calls) < MAX_BODY_FACTS:
            calls.append({'line': item.lineno, **_call(item)})
        elif isinstance(item, (ast.Assign, ast.AnnAssign)) and len(assignments) < MAX_BODY_FACTS:
            targets = item.targets if isinstance(item, ast.Assign) else [item.target]
            row = {'line': item.lineno, 'targets': [name for target in targets
                                                   for name in _target_names(target)][:8],
                   'refs': _refs(item.value)}
            if isinstance(item.value, ast.Call):
                row['from_call'] = _name(item.value.func)
            assignments.append(row)
        elif isinstance(item, ast.Return) and len(returns) < MAX_BODY_FACTS:
            row = {'line': item.lineno, 'refs': _refs(item.value)}
            if isinstance(item.value, ast.Call):
                row['call'] = _name(item.value.func)
            returns.append(row)
        elif isinstance(item, ast.Subscript) and len(subscripts) < MAX_BODY_FACTS:
            owner = _name(item.value)
            key = _literal(item.slice)
            if owner and key is not None:
                subscripts.append({'line': item.lineno, 'owner': owner, 'key': key})
    for label, rows in [('calls', calls), ('assignments', assignments),
                        ('returns', returns), ('subscripts', subscripts)]:
        if rows:
            fact[label] = rows
    return fact


def _registrations(path, tree, shown):
    """Surface registration syntax without resolving or claiming final routes."""
    facts = []
    pending = list(reversed(tree.body))
    while pending and len(facts) < MAX_FUNCTIONS:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Call) and _visible_span(path, node, shown):
            callee = _name(node.func)
            if callee.rsplit('.', 1)[-1] in REGISTRATION_CALLS:
                facts.append({'kind': 'registration_call', 'file': path,
                              'line': node.lineno, **_call(node)})
        pending.extend(reversed(list(ast.iter_child_nodes(node))))
    return facts


def _module(path):
    stem = path[:-3].replace('\\', '/').replace('/', '.')
    return stem[:-9] if stem.endswith('.__init__') else stem


def _visible_imports(path, tree, shown):
    """Only use imports whose complete statement was displayed to the model."""
    aliases = {}
    package = (_module(path) if PurePosixPath(path.replace('\\', '/')).name == '__init__.py'
               else _module(path).rpartition('.')[0])
    for node in tree.body:
        if not _visible_span(path, node, shown):
            continue
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split('.')[0]] = (
                    alias.name if alias.asname else alias.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                components = package.split('.') if package else []
                components = components[:max(0, len(components) - node.level + 1)]
                base = '.'.join([*components, *(node.module or '').split('.')]).strip('.')
            else:
                base = node.module or ''
            for alias in node.names:
                if alias.name != '*':
                    aliases[alias.asname or alias.name] = '.'.join(
                        part for part in (base, alias.name) if part)
    return aliases


def _link_visible_definitions(facts, trees, shown):
    """Add candidate links, not a claim of runtime call resolution."""
    definitions = {}
    same_file = {}
    for fact in facts:
        if fact['kind'] != 'function':
            continue
        path, symbol = fact['file'], fact['symbol']
        if not symbol:
            continue
        definitions[_module(path) + '.' + symbol] = fact
        same_file.setdefault((path, symbol.rsplit('.', 1)[-1]), []).append(fact)
    imports = {path: _visible_imports(path, tree, shown) for path, tree in trees.items()}
    for fact in facts:
        if fact['kind'] != 'function':
            continue
        path = fact['file']
        for call in fact.get('calls', []):
            callee = call['callee']
            first, *rest = callee.split('.')
            imported = imports[path].get(first)
            target = None
            if imported:
                qualified = '.'.join([imported, *rest])
                target = definitions.get(qualified)
            if target is None and '.' not in callee:
                candidates = same_file.get((path, callee), [])
                if len(candidates) == 1:
                    target = candidates[0]
            if target is not None and target is not fact:
                call['candidate_definition'] = {
                    'file': target['file'], 'line': target['line'], 'symbol': target['symbol']}


def extract_ast_context(files, shown):
    """Return ``(JSON context, metadata)`` from visible Python source lines only.

    The context is a hint for the model. Every reported line is in ``shown``;
    AST data from omitted lines and files is never exposed. Parse failures are
    skipped and reported in counts. Size and traversal limits are independent
    from the raw-source budget used by the caller.
    """
    if not isinstance(files, dict) or not isinstance(shown, set):
        raise TypeError('files and shown must be a dict and a set')
    visible_paths = {path for path, _ in shown}
    selected = [(path, source) for path, source in sorted(files.items())
                if isinstance(path, str) and isinstance(source, str)
                and path.endswith('.py') and len(path) <= 240
                and path in visible_paths]
    parsed, failed, skipped, total_chars, facts, limited = 0, 0, 0, 0, [], 0
    trees = {}
    diagnostics = []
    for path, source in selected[:MAX_FILES]:
        if len(source) > MAX_FILE_CHARS or total_chars + len(source) > MAX_TOTAL_PARSE_CHARS:
            skipped += 1
            if len(diagnostics) < 12:
                diagnostics.append({'file': path, 'reason': 'size_limit'})
            continue
        total_chars += len(source)
        try:
            tree = ast.parse(source, filename=path)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            failed += 1
            if len(diagnostics) < 12:
                diagnostics.append({'file': path, 'reason': 'parse_failed'})
            continue
        parsed += 1
        trees[path] = tree
        path_facts = _registrations(path, tree, shown)
        functions = [_function_fact(path, node, scope, shown)
                     for node, scope in _functions(tree)]
        functions = [fact for fact in functions if fact is not None]
        functions.sort(key=lambda fact: (not bool(fact.get('decorators')), fact['line']))
        limited += max(0, len(functions) - MAX_FUNCTIONS)
        facts.extend(path_facts + functions[:MAX_FUNCTIONS])
    skipped += max(0, len(selected) - MAX_FILES)
    for path, _ in selected[MAX_FILES:MAX_FILES + max(0, 12 - len(diagnostics))]:
        diagnostics.append({'file': path, 'reason': 'file_count_limit'})
    _link_visible_definitions(facts, trees, shown)
    # Retain whole facts and preserve a valid JSON object at every size.
    context = {'version': 1, 'note': 'AST 구문 단서만 제시합니다. 원본 줄을 직접 검토하고 근거를 인용하세요. 라우트·취약점 확정 아님.',
               'facts': []}
    kept = 0
    for fact in facts:
        context['facts'].append(fact)
        encoded = json.dumps(context, ensure_ascii=False, separators=(',', ':'))
        if len(encoded) > MAX_CONTEXT_CHARS:
            context['facts'].pop()
            break
        kept += 1
    metadata = {'status': 'completed' if kept else 'no_visible_python_facts',
                'files_parsed': parsed, 'files_failed': failed, 'files_skipped': skipped,
                'facts_included': kept, 'facts_omitted': len(facts) - kept + limited,
                'chars': len(json.dumps(context, ensure_ascii=False, separators=(',', ':'))),
                'diagnostics': diagnostics}
    return json.dumps(context, ensure_ascii=False, separators=(',', ':')), metadata
