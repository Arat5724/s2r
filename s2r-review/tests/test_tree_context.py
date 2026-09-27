"""Cross-language syntax hints are bounded and tied to displayed source."""

import json

import pytest

import tree_context


@pytest.fixture
def parsers():
    for module in ('tree_sitter', 'tree_sitter_javascript',
                   'tree_sitter_typescript', 'tree_sitter_java', 'tree_sitter_php'):
        pytest.importorskip(module)


def _extract(files, shown=None):
    if shown is None:
        shown = {(path, line) for path, source in files.items()
                 for line, _ in enumerate(source.splitlines(), 1)}
    text, metadata = tree_context.extract_tree_context(files, shown)
    return json.loads(text)['facts'], metadata, text


def test_js_jsx_and_ts_tsx_use_syntax_nodes_and_skip_comment_string_decoys(parsers):
    files = {
        'server.js': '''// app.get('/comment', fake)
const decoy = "app.get('/string', fake)";
app.get('/real', handler);
function handler(req, res) {
  const q = req.query.q;
  return res.send(q);
}
''',
        'view.jsx': '''export function Search() {
  return <p>{window.location.search}</p>;
}
''',
        'controller.ts': '''@Controller('/api')
class C {
  @Get('items')
  find(@Query('q') q: string) { return this.service.lookup(q); }
}
''',
        'route.tsx': '''export async function GET(request: Request) {
  const url = new URL(request.url);
  return <span>{url.pathname}</span>;
}
''',
    }
    facts, metadata, text = _extract(files)
    assert metadata['status'] == 'completed'
    assert metadata['files_parsed'] == 4
    assert '/comment' not in text and '/string' not in text
    assert any(row['kind'] == 'call' and row['callee'] == 'app.get'
               and row['literal_args'][0] == '/real' for row in facts)
    assert any(row['kind'] == 'assignment' and row['target'] == 'q'
               and 'req' in row['refs'] for row in facts)
    assert any(row['kind'] == 'annotation' and row['name'] == 'Get'
               and row['literal_args'] == ['items'] for row in facts)
    assert any(row['kind'] == 'declaration' and row['name'] == 'GET'
               and row['file'] == 'route.tsx' for row in facts)
    assert all(row['kind'] not in {'endpoint', 'vulnerability', 'scenario'} for row in facts)


def test_spring_and_laravel_ground_annotations_calls_and_methods(parsers):
    files = {
        'src/C.java': '''@RestController
@RequestMapping("/api")
class C {
  @GetMapping("/items/{id}")
  String show(String id) { return repo.find(id); }
  @PostMapping(path="/items")
  String save(String body) { return repo.save(body); }
}
''',
        'routes/web.php': '''<?php
// Route::get('/comment', [C::class, 'show']);
Route::get('/items', [C::class, 'show']);
class C {
  public function show($q) { return DB::select($q); }
}
''',
    }
    facts, metadata, text = _extract(files)
    assert metadata['files_parsed'] == 2
    assert '/comment' not in text
    assert any(row['kind'] == 'annotation' and row['name'] == 'GetMapping'
               and row['literal_args'] == ['/items/{id}'] for row in facts)
    assert any(row['kind'] == 'annotation' and row['name'] == 'PostMapping'
               and row['literal_keywords'] == {'path': '/items'} for row in facts)
    assert any(row['kind'] == 'call' and row['callee'] == 'repo.find'
               and row['scope'] == 'C.show' for row in facts)
    assert any(row['kind'] == 'call' and row['callee'] == 'Route::get'
               and row['literal_args'][0] == '/items' for row in facts)
    assert any(row['kind'] == 'call' and row['callee'] == 'DB::select'
               and '$q' in row['argument_identifiers'] for row in facts)


def test_hidden_source_and_partial_multiline_call_cannot_leak(parsers):
    source = '''app.get('/visible', handler);
app.get(
  '/hidden',
  secretHandler
);
function handler(req) { return req.query.q; }
function secretHandler(req) { return exec(req.query.token); }
'''
    shown = {('server.js', 1), ('server.js', 2), ('server.js', 5),
             ('server.js', 6)}
    facts, metadata, text = _extract({'server.js': source}, shown)
    assert metadata['files_parsed'] == 1
    assert '/visible' in text
    assert '/hidden' not in text and 'secretHandler' not in text
    assert 'exec' not in text and 'token' not in text
    assert all(all(('server.js', line) in shown
                   for line in range(row['line'], row['end_line'] + 1))
               for row in facts)


def test_recovered_parse_error_is_reported_and_no_facts_are_claimed(parsers):
    facts, metadata, _ = _extract({'bad.js': 'function {\napp.get("/x", h);\n'})
    assert facts == []
    assert metadata['files_failed'] == 1
    assert metadata['diagnostics'][0]['reason'] == 'syntax_error'


def test_missing_optional_wheel_is_truthful_without_crashing(monkeypatch):
    def unavailable(_):
        raise ImportError('test missing wheel')
    monkeypatch.setattr(tree_context, '_parser_for', unavailable)
    facts, metadata, _ = _extract({'server.js': "app.get('/x', h);"})
    assert facts == []
    assert metadata['status'] == 'parser_unavailable'
    assert metadata['files_parsed'] == 0
    assert metadata['files_skipped'] == 1
    assert metadata['diagnostics'][0]['reason'] == 'parser_unavailable'


def test_size_and_output_budgets_are_valid_json_and_report_truncation(parsers, monkeypatch):
    monkeypatch.setattr(tree_context, 'MAX_FILE_CHARS', 16)
    facts, metadata, _ = _extract({'server.js': "app.get('/this-is-too-long', h);"})
    assert facts == [] and metadata['files_skipped'] == 1
    assert metadata['diagnostics'][0]['reason'] == 'size_limit'

    monkeypatch.setattr(tree_context, 'MAX_FILE_CHARS', 180_000)
    monkeypatch.setattr(tree_context, 'MAX_CONTEXT_CHARS', 260)
    source = "\n".join(f"app.get('/{i}', h);" for i in range(20))
    facts, metadata, text = _extract({'server.js': source})
    assert len(text) <= 260
    assert len(facts) > 0
    assert metadata['facts_omitted'] > 0


def test_package_version_metadata_only_reports_installed_distributions(parsers):
    _, metadata, _ = _extract({'server.js': "app.get('/x', h);"})
    assert metadata['parser_packages']['tree-sitter']
    assert metadata['parser_packages']['tree-sitter-javascript']
