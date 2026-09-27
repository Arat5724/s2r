"""Bounded execution of model-generated, host-approved HTTP observations."""

import argparse
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


SAFE_PATH = re.compile(r'^/[A-Za-z0-9/_.~-]*$')
SAFE_QUERY_KEY = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$')
SAFE_SCENARIO_ID = re.compile(r'[a-f0-9]{16}')
SAFE_TAG_VALUE = re.compile(
    r'<(strong|em|b|i)>(s2r_[A-Za-z0-9_-]{8,60})</\1>', re.I)
SAFE_REDIRECT_VALUE = re.compile(r'https://example\.invalid(?:/[A-Za-z0-9_./~-]*)?')
SCRIPT_SCHEME = re.compile(r'(?:javascript|data|vbscript)\s*:', re.I)
MAX_BODY = 65_536
MAX_SCENARIOS = 10
MAX_ROUTES = 20
MAX_PROBE_VALUE = 160
MAX_JSON_BODY = 512
PROBE_LABELS = {'baseline', 'candidate'}
HTTP_METHODS = {'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'}
INPUT_LOCATIONS = {'query', 'body'}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _validate_route(route):
    if not isinstance(route, dict) or route.get('probe_kind') != 'ai_generic':
        raise ValueError('Only AI-generated diagnostic routes are supported')
    path = route.get('path')
    method, location = route.get('method'), route.get('input_location', 'query')
    if (not isinstance(method, str) or method not in HTTP_METHODS
            or not isinstance(location, str) or location not in INPUT_LOCATIONS
            or not isinstance(path, str)
            or not SAFE_PATH.fullmatch(path) or '//' in path
            or any(part in {'.', '..'} for part in path.split('/'))):
        raise ValueError('Nonliteral or unapproved route')
    query_key, value, identifier = (route.get('query_key'), route.get('probe_value'),
                                    route.get('scenario_id'))
    if (not isinstance(query_key, str) or not SAFE_QUERY_KEY.fullmatch(query_key)
            or not isinstance(value, str) or not 1 <= len(value) <= MAX_PROBE_VALUE
            or any(not 32 <= ord(char) <= 126 for char in value)
            or any(token in value for token in (';', '`', '$(', '&&', '||'))
            or SCRIPT_SCHEME.search(value)
            or any(char in value for char in '<>') and not SAFE_TAG_VALUE.fullmatch(value)
            or ('://' in value or value.startswith('//'))
               and not SAFE_REDIRECT_VALUE.fullmatch(value)
            or not isinstance(identifier, str)
            or not SAFE_SCENARIO_ID.fullmatch(identifier)):
        raise ValueError('Unapproved AI diagnostic probe')
    if location == 'body' and len(json.dumps(
            {query_key: value}, ensure_ascii=False, separators=(',', ':')).encode('utf-8')) > MAX_JSON_BODY:
        raise ValueError('AI diagnostic body too large')
    if 'probe_label' in route and route['probe_label'] not in PROBE_LABELS:
        raise ValueError('Unapproved AI diagnostic probe label')


def _request(opener, config, route):
    location = route.get('input_location', 'query')
    url = config['connection_origin'] + route['path']
    headers = {'Host': config['host_header'],
               'Accept': 'application/json, text/html',
               'User-Agent': 'S2R-Review/1.0',
               'Cache-Control': 'no-store'}
    body = None
    if location == 'query':
        url += '?' + urllib.parse.urlencode({route['query_key']: route['probe_value']})
    else:
        body = json.dumps({route['query_key']: route['probe_value']},
                          ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    request = urllib.request.Request(
        url, data=body, headers=headers, method=route['method'])
    started = time.monotonic()
    try:
        with opener.open(request, timeout=5) as response:
            status, headers = response.status, response.headers
            body = response.read(MAX_BODY + 1)
        error = None
    except urllib.error.HTTPError as exc:
        status, headers, error = exc.code, exc.headers, None
        body = exc.read(MAX_BODY + 1)
        exc.close()
    except (OSError, TimeoutError) as exc:
        cause = getattr(exc, 'reason', exc)
        status, headers, body = None, {}, b''
        error = f'{type(exc).__name__}: {type(cause).__name__}: {str(cause)[:180]}'
    selected = {name: str(headers.get(name, ''))[:500] for name in (
        'Content-Security-Policy', 'Referrer-Policy', 'X-Content-Type-Options',
        'Content-Type', 'Location')}
    within_limit = len(body) <= MAX_BODY
    return {
        'status_code': status, 'headers': selected, 'error': error,
        'duration_ms': round((time.monotonic() - started) * 1000, 1),
        'body_within_limit': within_limit,
        'body_text': body.decode('utf-8', errors='replace') if within_limit else '',
    }


def check(config):
    if not isinstance(config, dict):
        raise ValueError('Runtime scope exceeded')
    origin, host_header = config.get('connection_origin'), config.get('host_header')
    if (not isinstance(origin, str) or len(origin) > 250
            or not isinstance(host_header, str) or not 1 <= len(host_header) <= 250
            or any(not 33 <= ord(char) <= 126 for char in host_header)):
        raise ValueError('Runtime target invalid')
    parts = urllib.parse.urlsplit(origin)
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError('Runtime target invalid') from exc
    if (parts.scheme not in {'http', 'https'} or not parts.hostname or port is None
            or parts.username or parts.password or parts.path or parts.query or parts.fragment
            or not 1 <= port <= 65535):
        raise ValueError('Runtime target invalid')
    routes = config.get('routes')
    if not isinstance(routes, list) or len(routes) > MAX_ROUTES:
        raise ValueError('Runtime scope exceeded')
    for route in routes:
        _validate_route(route)
    if len({route['scenario_id'] for route in routes}) > MAX_SCENARIOS:
        raise ValueError('Runtime scope exceeded')
    grouped = {}
    for route in routes:
        grouped.setdefault(route['scenario_id'], []).append(route)
    if any(len(group) > 2 for group in grouped.values()):
        raise ValueError('Runtime scope exceeded')
    if len({(route['scenario_id'], route.get('probe_label'), route['method'],
             route['path'], route.get('input_location', 'query'), route['query_key'],
             route['probe_value']) for route in routes}) != len(routes):
        raise ValueError('Duplicate AI diagnostic route')
    for group in grouped.values():
        if len(group) == 1 and 'probe_label' not in group[0]:
            continue  # An existing approved single-candidate job.
        if (len(group) != 2 or {row.get('probe_label') for row in group} != PROBE_LABELS
                or len({(row['method'], row['path'], row.get('endpoint_id'),
                         row.get('input_location', 'query'), row['query_key'])
                        for row in group}) != 1
                or group[0]['probe_value'] == group[1]['probe_value']):
            raise ValueError('Incomplete or inconsistent comparison requests')
    # Preserve OpenShell's injected HTTP(S)_PROXY so its L7 allowlist sees each request.
    opener = urllib.request.build_opener(
        NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    return [
        {'method': route['method'], 'path': route['path'], 'probe_kind': 'ai_generic',
         'input_location': route.get('input_location', 'query'),
         'query_key': route['query_key'], 'scenario_id': route['scenario_id'],
         **({'probe_label': route['probe_label']} if 'probe_label' in route else {}),
         **_request(opener, config, route)}
        for route in routes
    ]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    source, target = Path(args.input).resolve(), Path(args.output).resolve()
    if not source.is_relative_to('/input') or not target.is_relative_to('/output'):
        raise ValueError('Outside approved file paths')
    config = json.loads(source.read_text())
    if (not isinstance(config, dict) or not isinstance(config.get('routes'), list)
            or len(config['routes']) > MAX_ROUTES
            or not isinstance(config.get('connection_origin'), str)
            or config['connection_origin'].count('/') != 2):
        raise ValueError('Runtime scope exceeded')
    result = {'observations': check(config)}
    target.write_text(json.dumps(result, ensure_ascii=False))
    print(json.dumps({'status': 'completed', 'requests': len(config['routes'])}))


if __name__ == '__main__':
    main()
