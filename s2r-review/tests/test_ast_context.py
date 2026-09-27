"""The AST helper supplies visible structure without making security claims."""

import json
from pathlib import Path

from ast_context import MAX_CONTEXT_CHARS, extract_ast_context
from ai_source import prepare_source
from review.snapshot import snapshot


def _extract(files, visible=None):
    shown = visible if visible is not None else {
        (path, line) for path, source in files.items()
        for line, _ in enumerate(source.splitlines(), 1)
    }
    text, metadata = extract_ast_context(files, shown)
    return json.loads(text)['facts'], metadata, text


def test_fastapi_nested_handler_calls_and_parameter_refs_are_structural_facts():
    source = '''from fastapi import FastAPI
from fastapi.responses import HTMLResponse
def create_app():
    app = FastAPI()
    @app.get("/preview")
    def preview(q: str):
        return HTMLResponse(f"<p>{q}</p>")
    return app
'''
    facts, metadata, _ = _extract({'app.py': source})
    handler = next(row for row in facts if row.get('symbol') == 'create_app.preview')
    assert handler['line'] == 6
    assert handler['parameters'] == ['q']
    assert handler['decorators'][0]['literal_args'] == ['/preview']
    assert {'line': 7, 'callee': 'HTMLResponse', 'refs': ['q']} in handler['calls']
    assert handler['returns'][0]['refs'] == ['HTMLResponse', 'q']
    assert metadata['status'] == 'completed'
    assert all('category' not in row and 'vulnerability' not in row for row in facts)


def test_flask_request_lookup_and_response_call_preserve_source_locations():
    source = '''from flask import Blueprint, request, render_template_string
bp = Blueprint("catalog", __name__)
@bp.route("/search", methods=["GET"])
def search():
    q = request.args.get("q", "")
    return render_template_string("<p>{{ q }}</p>", q=q)
'''
    facts, _, _ = _extract({'routes.py': source})
    handler = next(row for row in facts if row.get('symbol') == 'search')
    assert handler['decorators'][0]['literal_args'] == ['/search']
    assert handler['decorators'][0]['literal_keywords'] == {'methods': ['GET']}
    assert handler['assignments'][0]['targets'] == ['q']
    assert any(call['callee'] == 'request.args.get' and call['line'] == 5
               and call['literal_args'][0] == 'q' for call in handler['calls'])
    assert any(call['callee'] == 'render_template_string' and call['line'] == 6
               and 'q' in call['refs'] for call in handler['calls'])


def test_django_urlconf_is_a_registration_hint_and_not_an_endpoint():
    files = {
        'app/urls.py': 'from django.urls import path\nfrom . import views\nurlpatterns = [path("items/", views.items)]\n',
        'app/views.py': 'def items(request):\n    q = request.GET.get("q")\n    return fetch_items(q)\n',
    }
    facts, _, _ = _extract(files)
    registration = next(row for row in facts if row['kind'] == 'registration_call')
    assert registration['file'] == 'app/urls.py'
    assert registration['line'] == 3
    assert registration['literal_args'][0] == 'items/'
    assert registration['callee'] == 'path'
    assert all(row['kind'] != 'endpoint' for row in facts)
    handler = next(row for row in facts if row.get('symbol') == 'items')
    assert any(call['callee'] == 'request.GET.get' for call in handler['calls'])


def test_visible_import_can_link_a_call_to_visible_helper_definition():
    files = {
        'app/main.py': 'from . import helpers\n@app.get("/items")\ndef items(q):\n    return helpers.lookup(q)\n',
        'app/helpers.py': 'def lookup(q):\n    return q.strip()\n',
    }
    facts, _, _ = _extract(files)
    handler = next(row for row in facts if row.get('symbol') == 'items')
    call = next(row for row in handler['calls'] if row['callee'] == 'helpers.lookup')
    assert call['candidate_definition'] == {
        'file': 'app/helpers.py', 'line': 1, 'symbol': 'lookup'}
    # A hidden import cannot establish a cross-file candidate link.
    shown = {(path, line) for path, source in files.items()
             for line, _ in enumerate(source.splitlines(), 1)} - {('app/main.py', 1)}
    hidden_facts, _, _ = _extract(files, shown)
    hidden_handler = next(row for row in hidden_facts if row.get('symbol') == 'items')
    assert 'candidate_definition' not in next(row for row in hidden_handler['calls']
                                               if row['callee'] == 'helpers.lookup')


def test_omitted_source_lines_are_never_exposed_as_ast_evidence():
    source = '''@app.get("/public")
def public(q):
    return q
@app.get("/secret")
def secret(token):
    return dangerous(token)
'''
    facts, _, text = _extract({'app.py': source}, {('app.py', 1), ('app.py', 2), ('app.py', 3)})
    assert len(facts) == 1
    assert facts[0]['symbol'] == 'public'
    assert 'secret' not in text and 'dangerous' not in text
    assert all(row['line'] <= 3 for row in facts)


def test_visible_start_of_multiline_call_does_not_expose_hidden_argument():
    source = '''@app.get(
    "/hidden-route"
)
def handler(q,
            hidden_token):
    return render(
        "secret payload", q)
'''
    shown = {('app.py', line) for line in (1, 4, 6)}
    facts, _, text = _extract({'app.py': source}, shown)
    handler = next(row for row in facts if row['kind'] == 'function')
    assert handler['symbol'] == 'handler'
    assert handler['parameters'] == ['q']
    assert not handler.get('decorators')
    assert not handler.get('calls')
    assert '/hidden-route' not in text
    assert 'hidden_token' not in text
    assert 'secret payload' not in text


def test_comment_like_route_text_and_target_code_are_never_executed():
    source = '''# @app.get("/comment-only")
raise RuntimeError("target must not run")
def helper():
    return 1
'''
    facts, _, text = _extract({'app.py': source})
    assert len(facts) == 1 and facts[0]['symbol'] == 'helper'
    assert '/comment-only' not in text


def test_parse_error_and_context_budget_fail_closed_without_source_text():
    malformed = {'broken.py': 'def nope(:\n  pass\n'}
    facts, metadata, _ = _extract(malformed)
    assert not facts and metadata['files_failed'] == 1
    assert metadata['diagnostics'] == [{'file': 'broken.py', 'reason': 'parse_failed'}]
    many = {'app.py': '\n'.join(f'def f{i}(q):\n    return response.render(q)' for i in range(160))}
    facts, metadata, context = _extract(many)
    assert len(context) <= MAX_CONTEXT_CHARS
    assert metadata['facts_omitted'] > 0
    assert all(row['file'] == 'app.py' for row in facts)


def test_real_techlab_ast_hints_track_the_numbered_source_boundary():
    project = Path(__file__).resolve().parents[2] / 'samples' / 'techlab'
    files = snapshot(project)['files']
    _, shown, _, _ = prepare_source(files)
    facts, metadata, _ = _extract(files, shown)
    preview = next(row for row in facts if row.get('symbol') == 'create_app.search_preview')
    assert any(item.get('literal_args', [None])[0] == '/search/preview'
               for item in preview.get('decorators', []))
    assert any(item['callee'] == 'HTMLResponse' and 'q' in item['refs']
               for item in preview.get('calls', []))
    listing = next(row for row in facts if row.get('symbol') == 'create_app.list_products')
    repository_call = next(item for item in listing.get('calls', [])
                           if item['callee'] == 'repositories.find_products')
    assert repository_call['candidate_definition']['file'] == 'app/repositories.py'
    assert metadata['files_parsed'] > 0 and metadata['files_failed'] == 0
    assert all((row['file'], row['line']) in shown for row in facts)
