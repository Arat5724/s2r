"""Automatic GET permission must come from original FastAPI source bindings."""

import ast
from pathlib import Path

import pytest

from review.ai_get_safety import prove_direct_get, prove_read_only_get
from review.snapshot import snapshot


def _endpoint(source, *, function='echo', path='/echo', framework='FastAPI',
              source_file='app.py', input_name='q'):
    node = next(node for node in ast.walk(ast.parse(source))
                if isinstance(node, ast.FunctionDef) and node.name == function)
    return {
        'id': 'test-endpoint', 'framework': framework, 'method': 'GET', 'path': path,
        'handler': {'file': source_file, 'line': node.lineno, 'end_line': node.end_lineno,
                    'symbol': function, 'snippet': ast.get_source_segment(source, node)},
        'inputs': [{'in': 'query', 'name': input_name, 'required': False}],
    }


def test_real_techlab_preview_and_redirect_have_direct_get_proof():
    project = Path(__file__).resolve().parents[2] / 'samples' / 'techlab'
    files = snapshot(project)['files']
    source = files['app/main.py']
    for path, function, input_name in [('/search/preview', 'search_preview', 'q'),
                                       ('/go', 'go', 'next')]:
        endpoint = _endpoint(source, function=function, path=path,
                             source_file='app/main.py', input_name=input_name)
        approved, reason = prove_direct_get(files, endpoint, input_name)
        assert approved, (path, reason)


BASE = '''from fastapi import FastAPI
from fastapi.responses import HTMLResponse
app = FastAPI()
@app.get('/echo')
def echo(q: str = ''):
    return HTMLResponse(f'<p>{q}</p>')
'''


def test_simple_fastapi_function_uses_actual_import_and_query():
    assert prove_direct_get({'app.py': BASE}, _endpoint(BASE), 'q') == (True, '')


@pytest.mark.parametrize('source', [
    BASE.replace('app = FastAPI()',
                 'def HTMLResponse(content):\n    write_state()\n    return content\napp = FastAPI()'),
    BASE.replace('app = FastAPI()',
                 'app = FastAPI()\nHTMLResponse = untrusted_response'),
    BASE.replace('app = FastAPI()',
                 'def FastAPI():\n    return untrusted_router\napp = FastAPI()'),
    BASE.replace('app = FastAPI()', 'app = untrusted_router()'),
    BASE.replace('app = FastAPI()', 'app = FastAPI(dependencies=[Depends(write_state)])'),
    BASE.replace('app = FastAPI()', 'app = FastAPI(route_class=untrusted_route)'),
    BASE.replace('app = FastAPI()', 'app = FastAPI(middleware=[untrusted_middleware])'),
    BASE.replace('app = FastAPI()', 'app = FastAPI()\napp.get = untrusted_router'),
    BASE.replace('app = FastAPI()', 'app = FastAPI()\napp.router = untrusted_router'),
    BASE.replace('app = FastAPI()', 'app = FastAPI()\nHTMLResponse.__init__ = untrusted_init'),
    BASE.replace('app = FastAPI()', 'app = FastAPI()\nfrom untrusted import router as app'),
    BASE.replace('app = FastAPI()', 'app = FastAPI()\nfrom untrusted import Text as str'),
])
def test_shadowed_response_fastapi_or_app_binding_is_never_auto_requested(source):
    assert prove_direct_get({'app.py': source}, _endpoint(source), 'q')[0] is False


@pytest.mark.parametrize('source', [
    BASE.replace("@app.get('/echo')", "@untrusted_wrapper\n@app.get('/echo')"),
    BASE.replace("@app.get('/echo')", "@app.get('/echo', dependencies=[Depends(write_state)])"),
    BASE.replace("@app.get('/echo')", "@app.post('/other')\n@app.get('/echo')"),
])
def test_additional_or_effectful_decorators_are_not_proven(source):
    assert prove_direct_get({'app.py': source}, _endpoint(source), 'q')[0] is False


@pytest.mark.parametrize('source', [
    BASE.replace('    return HTMLResponse(f\'<p>{q}</p>\')',
                 '    return HTMLResponse(SECRET)'),
    BASE.replace('    return HTMLResponse(f\'<p>{q}</p>\')',
                 '    return HTMLResponse(rewrite(q))'),
    BASE.replace('    return HTMLResponse(f\'<p>{q}</p>\')',
                 '    write_state()\n    return HTMLResponse(q)'),
    BASE.replace("def echo(q: str = ''):", 'def echo(q: str):'),
])
def test_global_data_helper_calls_write_and_required_query_are_not_proven(source):
    assert prove_direct_get({'app.py': source}, _endpoint(source), 'q')[0] is False


def test_model_snippet_cannot_override_original_function():
    endpoint = _endpoint(BASE)
    endpoint['handler']['snippet'] = "def echo(q: str = ''): return HTMLResponse(q)"
    assert prove_direct_get({'app.py': BASE}, endpoint, 'q') == (True, '')
    endpoint['handler']['line'] += 1
    assert prove_direct_get({'app.py': BASE}, endpoint, 'q')[0] is False


def test_unrecognized_framework_stays_offline():
    endpoint = _endpoint(BASE, framework='Spring Boot')
    assert prove_direct_get({'app.py': BASE}, endpoint, 'q')[0] is False


def test_selected_techlab_gets_can_use_bounded_live_diagnostics():
    project = Path(__file__).resolve().parents[2] / 'samples' / 'techlab'
    files = snapshot(project)['files']
    source = files['app/main.py']
    for path, function, input_name in [('/api/products', 'list_products', 'q'),
                                       ('/api/files', 'read_file', 'name'),
                                       ('/go', 'go', 'next'),
                                       ('/search/preview', 'search_preview', 'q')]:
        endpoint = _endpoint(source, function=function, path=path,
                             source_file='app/main.py', input_name=input_name)
        route_line = next(number for number, value in enumerate(source.splitlines(), 1)
                          if value.strip().startswith('@app.get(')
                          and repr(path)[1:-1] in value)
        endpoint['call_chain'] = [{'file': 'app/main.py', 'line': route_line,
                                   'reason': 'route registration'}]
        approved, reason = prove_read_only_get(files, endpoint, input_name)
        assert approved, (path, reason)


def test_selected_get_still_rejects_obvious_out_of_band_calls():
    source = BASE.replace("    return HTMLResponse(f'<p>{q}</p>')",
                          "    write_state()\n    return HTMLResponse(f'<p>{q}</p>')")
    endpoint = _endpoint(source)
    endpoint['call_chain'] = [{'file': 'app.py', 'line': 4,
                               'reason': 'route registration'}]
    assert prove_read_only_get({'app.py': source}, endpoint, 'q')[0] is False
