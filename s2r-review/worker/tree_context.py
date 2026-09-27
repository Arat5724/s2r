"""Bounded Tree-sitter syntax hints for source shown to the AI reader.

Facts here are *syntax*, not resolved routes, data flow, or vulnerability
findings.  The parser never imports or runs a scanned project.  Only names and
literal arguments whose complete source lines were shown to the model can be
reported.  Missing grammar wheels and recovered parse errors are visible in
metadata instead of being treated as successful analysis.
"""

import importlib
import json
import re
from importlib import metadata as package_metadata
from pathlib import PurePosixPath


MAX_FILES = 40
MAX_FILE_CHARS = 180_000
MAX_TOTAL_PARSE_CHARS = 500_000
MAX_NODES_PER_FILE = 35_000
MAX_FACTS_PER_FILE = 100
MAX_CONTEXT_CHARS = 24_000
MAX_NAME_CHARS = 120
MAX_LITERAL_CHARS = 100
MAX_SPAN_LINES = 18
MAX_DIAGNOSTICS = 12

GRAMMARS = {
    '.js': ('tree_sitter_javascript', 'language'),
    '.jsx': ('tree_sitter_javascript', 'language'),
    '.mjs': ('tree_sitter_javascript', 'language'),
    '.cjs': ('tree_sitter_javascript', 'language'),
    '.ts': ('tree_sitter_typescript', 'language_typescript'),
    '.tsx': ('tree_sitter_typescript', 'language_tsx'),
    '.java': ('tree_sitter_java', 'language'),
    '.php': ('tree_sitter_php', 'language_php'),
}
PACKAGES = {'tree-sitter', 'tree-sitter-javascript',
            'tree-sitter-typescript', 'tree-sitter-java', 'tree-sitter-php'}
DECLARATIONS = {
    'class_declaration', 'interface_declaration', 'function_declaration',
    'generator_function_declaration', 'function_definition',
    'method_definition', 'method_declaration', 'constructor_declaration',
}
ANNOTATIONS = {'decorator', 'annotation', 'marker_annotation'}
CALLS = {'call_expression', 'method_invocation', 'function_call_expression',
         'member_call_expression', 'scoped_call_expression'}
ASSIGNMENTS = {'variable_declarator', 'assignment_expression'}
IDENTIFIERS = {'identifier', 'property_identifier', 'type_identifier',
               'name', 'variable_name'}
SIMPLE_NAME = re.compile(r'\$?[A-Za-z_][A-Za-z_0-9$]*\Z')


def _parser_for(suffix):
    """Load only official language wheels; callers report ImportError cleanly."""
    from tree_sitter import Language, Parser

    module_name, language_function = GRAMMARS[suffix]
    module = importlib.import_module(module_name)
    return Parser(Language(getattr(module, language_function)()))


def source_spans(path, text):
    """Return complete declaration/statement line spans for a large source view.

    The spans describe syntax only.  This is deliberately independent from
    framework routes, vulnerability categories, and sink names.  Parse errors
    or unavailable grammars leave source selection to its bounded fallback.
    """
    suffix = PurePosixPath(path).suffix.lower()
    if suffix not in GRAMMARS or len(text) > MAX_FILE_CHARS:
        return []
    try:
        root = _parser_for(suffix).parse(text.encode('utf-8')).root_node
    except (ImportError, AttributeError, TypeError, ValueError, UnicodeError,
            RuntimeError, RecursionError, MemoryError):
        return []
    if root.has_error:
        return []
    spans = []
    visited = 0
    for node in root.named_children:
        start, end = _lines(node)
        if node.type in {'class_declaration', 'interface_declaration'}:
            body = node.child_by_field_name('body')
            if body is not None:
                spans.append((start, max(start, body.start_point.row + 1)))
            else:
                spans.append((start, end))
        else:
            spans.append((start, end))
    pending = list(reversed(root.named_children))
    while pending and visited < MAX_NODES_PER_FILE:
        node = pending.pop()
        visited += 1
        if (node.type in DECLARATIONS and node.type not in {'class_declaration', 'interface_declaration'}
                or node.type in {'arrow_function', 'function_expression', 'anonymous_function',
                                 'lambda_expression'}):
            spans.append(_lines(node))
        elif node.type == 'variable_declarator':
            value = node.child_by_field_name('value')
            if value is not None and value.type == 'arrow_function':
                spans.append(_lines(node))
        pending.extend(reversed(node.named_children))
    return sorted(set((start, end) for start, end in spans if start > 0 and end >= start))


def _lines(node):
    start = node.start_point.row + 1
    # Tree-sitter end positions are exclusive.  A closing newline belongs to
    # the preceding line, which avoids citing a line that was not displayed.
    end = node.end_point.row + (0 if node.end_point.column == 0 else 1)
    return start, max(start, end)


def _visible(path, node, shown, *, max_lines=MAX_SPAN_LINES):
    start, end = _lines(node)
    return (end - start + 1 <= max_lines
            and all((path, line) in shown for line in range(start, end + 1)))


def _text(node, source):
    return source[node.start_byte:node.end_byte].decode('utf-8', 'replace')


def _identifier(node, source, path, shown):
    if node is None or node.type not in IDENTIFIERS or not _visible(path, node, shown):
        return ''
    value = _text(node, source)
    return value[:MAX_NAME_CHARS] if len(value) <= MAX_NAME_CHARS and SIMPLE_NAME.fullmatch(value) else ''


def _expr_name(node, source, path, shown, *, depth=0):
    """Render only identifiers and direct member syntax, never arbitrary code."""
    if node is None or depth > 5 or not _visible(path, node, shown):
        return ''
    simple = _identifier(node, source, path, shown)
    if simple:
        return simple
    if node.type in {'this', 'super'}:
        return node.type
    if node.type in {'member_expression', 'field_access', 'member_access_expression',
                     'scoped_property_access_expression', 'scoped_identifier'}:
        left = (node.child_by_field_name('object') or node.child_by_field_name('scope'))
        right = (node.child_by_field_name('property') or node.child_by_field_name('name'))
        if left is None or right is None:
            named = node.named_children
            if len(named) != 2:
                return ''
            left, right = named
        prefix = _expr_name(left, source, path, shown, depth=depth + 1)
        name = _identifier(right, source, path, shown)
        if prefix and name:
            separator = '::' if node.type.startswith('scoped_') else (
                '->' if node.type == 'member_access_expression' else '.')
            result = prefix + separator + name
            return result if len(result) <= MAX_NAME_CHARS else ''
    return ''


def _literal(node, source, path, shown):
    if node is None or not _visible(path, node, shown, max_lines=3):
        return None
    if node.type == 'argument' and len(node.named_children) == 1:
        return _literal(node.named_children[0], source, path, shown)
    if node.type == 'element_value_array_initializer' and len(node.named_children) <= 6:
        values = [_literal(child, source, path, shown) for child in node.named_children]
        return values if values and all(value is not None for value in values) else None
    if node.type not in {'string', 'string_literal'}:
        return None
    raw = _text(node, source)
    if (len(raw) < 2 or raw[0] not in {'"', "'"} or raw[-1] != raw[0]
            or len(raw) - 2 > MAX_LITERAL_CHARS):
        return None
    value = raw[1:-1]
    return value if value.isprintable() else None


def _refs(node, source, path, shown, *, limit=10):
    if node is None or not _visible(path, node, shown):
        return []
    found, pending = [], [node]
    while pending and len(found) < limit:
        part = pending.pop()
        if part.type in {'comment', 'string', 'string_literal'}:
            continue
        value = _identifier(part, source, path, shown)
        if value and value not in found:
            found.append(value)
        if value:
            continue
        pending.extend(reversed(part.named_children))
    return found


def _argument_facts(node, source, path, shown):
    arguments = node.child_by_field_name('arguments')
    if arguments is None or not _visible(path, arguments, shown):
        return [], []
    literals = [_literal(child, source, path, shown) for child in arguments.named_children[:5]]
    refs = []
    for child in arguments.named_children[:8]:
        for ref in _refs(child, source, path, shown):
            if ref not in refs:
                refs.append(ref)
    return literals, refs[:10]


def _location(kind, path, node):
    line, end_line = _lines(node)
    return {'kind': kind, 'file': path, 'line': line, 'end_line': end_line}


def _declaration(node, source, path, shown, scope):
    name_node = node.child_by_field_name('name')
    name = _identifier(name_node, source, path, shown)
    if not name:
        return None, scope
    fact = _location('declaration', path, name_node)
    fact.update({'syntax': node.type, 'name': name})
    if scope:
        fact['scope'] = '.'.join(scope)[:MAX_NAME_CHARS]
    parameters = node.child_by_field_name('parameters')
    if parameters is not None and _visible(path, parameters, shown):
        names = []
        for parameter in parameters.named_children[:25]:
            candidate = (parameter if parameter.type in IDENTIFIERS else
                         parameter.child_by_field_name('name') or
                         parameter.child_by_field_name('pattern'))
            value = _identifier(candidate, source, path, shown)
            if not value:
                # Some grammar parameter nodes have no stable name field.  The
                # last direct identifier is the parameter, after its type.
                for child in reversed(parameter.named_children):
                    value = _identifier(child, source, path, shown)
                    if value:
                        break
            if value and value not in names:
                names.append(value)
        if names:
            fact['parameters'] = names[:20]
    return fact, (*scope, name)


def _arrow_declaration(node, source, path, shown, scope):
    value = node.child_by_field_name('value')
    if value is None or value.type != 'arrow_function':
        return None
    name_node = node.child_by_field_name('name')
    name = _identifier(name_node, source, path, shown)
    if not name:
        return None
    fact = _location('declaration', path, name_node)
    fact.update({'syntax': 'arrow_function', 'name': name})
    if scope:
        fact['scope'] = '.'.join(scope)[:MAX_NAME_CHARS]
    parameters = value.child_by_field_name('parameters')
    if parameters is not None and _visible(path, parameters, shown):
        fact['parameters'] = _refs(parameters, source, path, shown, limit=20)
    return fact


def _annotation(node, source, path, shown, scope):
    if not _visible(path, node, shown):
        return None
    expression = next((child for child in node.named_children
                       if child.type in CALLS), None)
    if expression is not None:
        callee_node = (expression.child_by_field_name('function') or
                       expression.child_by_field_name('name'))
        name = _expr_name(callee_node, source, path, shown)
        literals, _ = _argument_facts(expression, source, path, shown)
    else:
        name = _identifier(node.child_by_field_name('name'), source, path, shown)
        if not name and node.named_children:
            name = _expr_name(node.named_children[0], source, path, shown)
        literals, _ = _argument_facts(node, source, path, shown)
    if not name:
        return None
    fact = _location('annotation', path, node)
    fact.update({'syntax': node.type, 'name': name})
    if scope:
        fact['scope'] = '.'.join(scope)[:MAX_NAME_CHARS]
    if any(item is not None for item in literals):
        fact['literal_args'] = literals
    arguments = node.child_by_field_name('arguments')
    if arguments is not None and _visible(path, arguments, shown):
        keywords = {}
        for child in arguments.named_children[:8]:
            if child.type != 'element_value_pair':
                continue
            key = _identifier(child.child_by_field_name('key'), source, path, shown)
            value = _literal(child.child_by_field_name('value'), source, path, shown)
            if key and value is not None:
                keywords[key] = value
        if keywords:
            fact['literal_keywords'] = keywords
    return fact


def _call(node, source, path, shown, scope):
    if not _visible(path, node, shown):
        return None
    if node.type == 'method_invocation':
        object_node = node.child_by_field_name('object')
        name_node = node.child_by_field_name('name')
        prefix = _expr_name(object_node, source, path, shown)
        name = _identifier(name_node, source, path, shown)
        callee = (prefix + '.' if prefix else '') + name
    elif node.type in {'member_call_expression', 'scoped_call_expression'}:
        object_node = (node.child_by_field_name('object') or
                       node.child_by_field_name('scope'))
        name_node = node.child_by_field_name('name')
        prefix = _expr_name(object_node, source, path, shown)
        name = _identifier(name_node, source, path, shown)
        separator = '::' if node.type == 'scoped_call_expression' else '->'
        callee = prefix + separator + name if prefix and name else ''
    else:
        function = node.child_by_field_name('function')
        callee = _expr_name(function, source, path, shown)
    if not callee or len(callee) > MAX_NAME_CHARS:
        return None
    fact = _location('call', path, node)
    fact['callee'] = callee
    if scope:
        fact['scope'] = '.'.join(scope)[:MAX_NAME_CHARS]
    literals, refs = _argument_facts(node, source, path, shown)
    if any(item is not None for item in literals):
        fact['literal_args'] = literals
    if refs:
        fact['argument_identifiers'] = refs
    return fact


def _assignment(node, source, path, shown, scope):
    if not _visible(path, node, shown):
        return None
    target = (node.child_by_field_name('name') or node.child_by_field_name('left'))
    value = (node.child_by_field_name('value') or node.child_by_field_name('right'))
    target_name = _expr_name(target, source, path, shown)
    if not target_name or value is None:
        return None
    fact = _location('assignment', path, node)
    fact['target'] = target_name
    if scope:
        fact['scope'] = '.'.join(scope)[:MAX_NAME_CHARS]
    refs = _refs(value, source, path, shown)
    if refs:
        fact['refs'] = refs
    if value.type in CALLS:
        call = _call(value, source, path, shown, scope)
        if call:
            fact['from_call'] = call['callee']
    return fact


def _return(node, source, path, shown, scope):
    if not _visible(path, node, shown):
        return None
    expression = next((child for child in node.named_children
                       if child.type != 'comment'), None)
    if expression is None:
        return None
    fact = _location('return', path, node)
    if scope:
        fact['scope'] = '.'.join(scope)[:MAX_NAME_CHARS]
    refs = _refs(expression, source, path, shown)
    if refs:
        fact['refs'] = refs
    if expression.type in CALLS:
        call = _call(expression, source, path, shown, scope)
        if call:
            fact['call'] = call['callee']
    return fact if 'refs' in fact or 'call' in fact else None


def _facts(path, source, root, shown):
    facts, visited, pending = [], 0, [(root, (), False)]
    while pending and visited < MAX_NODES_PER_FILE and len(facts) < MAX_FACTS_PER_FILE:
        node, scope, in_annotation = pending.pop()
        visited += 1
        if node.type in {'comment', 'string', 'string_literal'}:
            continue
        next_scope = scope
        fact = None
        if node.type in DECLARATIONS:
            fact, next_scope = _declaration(node, source, path, shown, scope)
        elif node.type == 'variable_declarator':
            fact = _arrow_declaration(node, source, path, shown, scope)
            if fact is not None:
                next_scope = (*scope, fact['name'])
            else:
                fact = _assignment(node, source, path, shown, scope)
        elif node.type in ANNOTATIONS:
            fact = _annotation(node, source, path, shown, scope)
            in_annotation = True
        elif node.type in CALLS and not in_annotation:
            fact = _call(node, source, path, shown, scope)
        elif node.type in ASSIGNMENTS:
            fact = _assignment(node, source, path, shown, scope)
        elif node.type == 'return_statement':
            fact = _return(node, source, path, shown, scope)
        if fact:
            facts.append(fact)
        pending.extend((child, next_scope, in_annotation)
                       for child in reversed(node.named_children))
    return facts, bool(pending)


def extract_tree_context(files, shown):
    """Return ``(JSON context, metadata)`` for visible JS/TS/Java/PHP syntax."""
    if not isinstance(files, dict) or not isinstance(shown, set):
        raise TypeError('files and shown must be a dict and a set')
    visible_paths = {path for path, _ in shown}
    selected = [(path, source) for path, source in sorted(files.items())
                if isinstance(path, str) and isinstance(source, str)
                and PurePosixPath(path).suffix.lower() in GRAMMARS
                and len(path) <= 240 and path in visible_paths]
    parsed = failed = skipped = unavailable = total_chars = limited = 0
    facts, diagnostics = [], []
    for path, text in selected[:MAX_FILES]:
        if len(text) > MAX_FILE_CHARS or total_chars + len(text) > MAX_TOTAL_PARSE_CHARS:
            skipped += 1
            if len(diagnostics) < MAX_DIAGNOSTICS:
                diagnostics.append({'file': path, 'reason': 'size_limit'})
            continue
        total_chars += len(text)
        suffix = PurePosixPath(path).suffix.lower()
        try:
            parser = _parser_for(suffix)
        except (ImportError, AttributeError, TypeError, ValueError):
            skipped += 1
            unavailable += 1
            if len(diagnostics) < MAX_DIAGNOSTICS:
                diagnostics.append({'file': path, 'reason': 'parser_unavailable',
                                    'grammar': suffix})
            continue
        try:
            encoded = text.encode('utf-8')
            root = parser.parse(encoded).root_node
        except (UnicodeError, ValueError, RuntimeError, RecursionError, MemoryError):
            failed += 1
            if len(diagnostics) < MAX_DIAGNOSTICS:
                diagnostics.append({'file': path, 'reason': 'parse_failed'})
            continue
        if root.has_error:
            failed += 1
            if len(diagnostics) < MAX_DIAGNOSTICS:
                diagnostics.append({'file': path, 'reason': 'syntax_error'})
            continue
        parsed += 1
        path_facts, truncated = _facts(path, encoded, root, shown)
        facts.extend(path_facts)
        if truncated:
            limited += 1
            if len(diagnostics) < MAX_DIAGNOSTICS:
                diagnostics.append({'file': path, 'reason': 'node_or_fact_limit'})
    skipped += max(0, len(selected) - MAX_FILES)
    for path, _ in selected[MAX_FILES:MAX_FILES + max(0, MAX_DIAGNOSTICS - len(diagnostics))]:
        diagnostics.append({'file': path, 'reason': 'file_count_limit'})
    context = {'version': 1,
               'note': 'Tree-sitter 구문 단서입니다. 원본 줄을 직접 확인하세요. 라우트·취약점·실제 데이터 흐름 확정 아님.',
               'facts': []}
    for fact in facts:
        context['facts'].append(fact)
        if len(json.dumps(context, ensure_ascii=False, separators=(',', ':'))) > MAX_CONTEXT_CHARS:
            context['facts'].pop()
            break
    result = json.dumps(context, ensure_ascii=False, separators=(',', ':'))
    kept = len(context['facts'])
    if selected and unavailable == len(selected):
        status = 'parser_unavailable'
    elif not selected:
        status = 'no_supported_files'
    elif failed or unavailable or skipped or limited:
        status = 'partial'
    else:
        status = 'completed' if kept else 'no_visible_facts'
    versions = {}
    for package in sorted(PACKAGES):
        try:
            versions[package] = package_metadata.version(package)
        except package_metadata.PackageNotFoundError:
            pass
    metadata = {'status': status, 'files_parsed': parsed, 'files_failed': failed,
                'files_skipped': skipped, 'facts_included': kept,
                'facts_omitted': len(facts) - kept, 'files_limited': limited,
                'chars': len(result), 'diagnostics': diagnostics,
                'parser_packages': versions}
    return result, metadata
