"""Look up exact public-registry pins in OSV; never infer exploitability."""
import json
import re
import ssl
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

PIN = re.compile(r'^([A-Za-z0-9][A-Za-z0-9_.-]{0,99})==([0-9][A-Za-z0-9_.!+-]{0,79})$')
ID = re.compile(r'^[A-Za-z0-9_.-]{1,100}$')
NPM_NAME = re.compile(r'^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$')
COMPOSER_NAME = re.compile(r'^[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*$')
MAVEN_PART = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$')
# A bare version is required. Ranges, tags, aliases, workspace/file/git/HTTP
# references, properties, and snapshots cannot establish an installed version.
SEMVER_PIN = re.compile(r'^v?[0-9]+(?:\.[0-9]+){2,3}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$')
MAVEN_PIN = re.compile(r'^[0-9][A-Za-z0-9_.+-]{0,79}$')
GRADLE_CONFIG = r'(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|annotationProcessor|kapt)'
GRADLE_START = re.compile(r'^\s*' + GRADLE_CONFIG + r'(?=\s|\()')
GRADLE_LITERAL = re.compile(r'^\s*' + GRADLE_CONFIG +
                            r'\s*(?:\(\s*)?(?P<quote>[\'\"])(?P<coordinate>[^\'\"]+)(?P=quote)\s*\)?\s*;?\s*(?://.*)?$')


def fetch_osv(payload):
    request = urllib.request.Request('https://api.osv.dev/v1/querybatch',
              data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(request, timeout=15, context=ssl.create_default_context()) as response:
        data = response.read(2_000_001)
    if len(data) > 2_000_000:
        raise ValueError('OSV response size limit exceeded')
    return json.loads(data)


def _line_of(content, text):
    return next((number for number, line in enumerate(content.splitlines(), 1) if text in line), None)


def _unresolved(unresolved, file, reason, line=None):
    unresolved.append({'file': file, 'line': line, 'reason': reason})


def _add(pinned, ecosystem, name, version, file):
    key = (ecosystem, name, version)
    row = pinned.setdefault(key, {'ecosystem': ecosystem, 'name': name,
                                  'version': version, 'source_files': []})
    if file not in row['source_files']:
        row['source_files'].append(file)


def _requirements(file, content, pinned, unresolved):
    lines = content.splitlines()
    # An option or included file can redirect resolution to a private index.
    if any(line.strip().startswith(('-', 'git+', 'http:', 'https:')) for line in lines):
        _unresolved(unresolved, file, '사용자 지정 인덱스·옵션·URL이 있어 외부 조회 제외')
        return
    for line_no, line in enumerate(lines, 1):
        value = line.partition('#')[0].strip()
        if not value:
            continue
        match = PIN.fullmatch(value)
        if not match:
            _unresolved(unresolved, file, '정확한 PyPI 고정 버전이 아님', line_no)
            continue
        name, version = match.groups()
        _add(pinned, 'PyPI', re.sub(r'[-_.]+', '-', name).lower(), version, file)


def _json_manifest(file, content, unresolved):
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        _unresolved(unresolved, file, 'JSON 매니페스트를 해석할 수 없음')
        return None
    if not isinstance(data, dict):
        _unresolved(unresolved, file, 'JSON 매니페스트 형식이 아님')
        return None
    return data


def _npm(file, content, pinned, unresolved):
    data = _json_manifest(file, content, unresolved)
    if data is None:
        return
    # package.json itself can override the public registry. npmrc is omitted
    # from source snapshots, so a scoped registry is never assumed from a URL.
    if (data.get('registry') or data.get('registries') or
            any(isinstance(data.get(key), dict) and data[key].get('registry')
                for key in ('config', 'publishConfig'))):
        _unresolved(unresolved, file, '사용자 지정 npm 레지스트리 설정이 있어 외부 조회 제외')
        return
    for section in ('dependencies', 'devDependencies', 'optionalDependencies'):
        entries = data.get(section, {})
        if not isinstance(entries, dict):
            _unresolved(unresolved, file, f'{section} 형식을 해석할 수 없음')
            continue
        for name, version in entries.items():
            line = _line_of(content, json.dumps(name, ensure_ascii=False)) if isinstance(name, str) else None
            if not isinstance(name, str) or not NPM_NAME.fullmatch(name) or len(name) > 214:
                _unresolved(unresolved, file, '공개 npm 패키지 이름 형식이 아님', line)
            elif not isinstance(version, str) or not SEMVER_PIN.fullmatch(version):
                _unresolved(unresolved, file, '정확한 npm 고정 버전이 아님', line)
            else:
                _add(pinned, 'npm', name, version, file)


def _local(tag):
    return tag.rsplit('}', 1)[-1]


def _child(element, name):
    return next((item for item in element if _local(item.tag) == name), None)


def _text(element, name):
    child = _child(element, name)
    return (child.text or '').strip() if child is not None else ''


def _maven(file, content, pinned, unresolved):
    if '<!DOCTYPE' in content.upper() or '<!ENTITY' in content.upper():
        _unresolved(unresolved, file, 'XML DTD·엔터티가 있어 외부 조회 제외')
        return
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        _unresolved(unresolved, file, 'pom.xml을 해석할 수 없음')
        return
    if _local(root.tag) != 'project':
        _unresolved(unresolved, file, 'Maven project 형식이 아님')
        return
    if any(_local(element.tag) in ('repository', 'pluginRepository') for element in root.iter()):
        _unresolved(unresolved, file, '사용자 지정 Maven 저장소가 있어 외부 조회 제외')
        return
    dependencies = _child(root, 'dependencies')
    if dependencies is None:
        return
    for dependency in dependencies:
        if _local(dependency.tag) != 'dependency':
            continue
        group, artifact = _text(dependency, 'groupId'), _text(dependency, 'artifactId')
        version = _text(dependency, 'version')
        line = _line_of(content, f'<artifactId>{artifact}</artifactId>') if artifact else None
        if not MAVEN_PART.fullmatch(group) or not MAVEN_PART.fullmatch(artifact):
            _unresolved(unresolved, file, 'Maven 좌표가 구체적인 공개 패키지 형식이 아님', line)
        elif (not MAVEN_PIN.fullmatch(version) or version.upper() in ('LATEST', 'RELEASE')
              or version.upper().endswith('-SNAPSHOT')):
            _unresolved(unresolved, file, '정확한 Maven 고정 버전이 아님', line)
        elif _text(dependency, 'scope') == 'import' or _text(dependency, 'type') == 'pom':
            _unresolved(unresolved, file, 'Maven BOM·POM은 설치 라이브러리로 확인되지 않음', line)
        else:
            _add(pinned, 'Maven', f'{group}:{artifact}', version, file)


def _gradle(file, content, pinned, unresolved):
    # Only the standard public repositories are assumed. A repository declared
    # through Gradle DSL may serve private coordinates under a public-looking ID.
    if (re.search(r'\b(?:mavenLocal|flatDir|ivy|exclusiveContent)\s*(?:\(|\{)', content) or
            re.search(r'\bmaven\s*(?:\(|\{)', content) or
            ('repositories' in content and re.search(r'\burl\s*(?:=|\(|[\s]+[\'\"])', content))):
        _unresolved(unresolved, file, '사용자 지정 Gradle 저장소가 있어 외부 조회 제외')
        return
    for line_no, line in enumerate(content.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith(('//', '/*', '*')) or not GRADLE_START.match(line):
            continue
        match = GRADLE_LITERAL.fullmatch(line)
        if not match:
            _unresolved(unresolved, file, '정확한 Gradle literal 좌표가 아님', line_no)
            continue
        parts = match.group('coordinate').split(':')
        if len(parts) != 3 or not MAVEN_PART.fullmatch(parts[0]) or not MAVEN_PART.fullmatch(parts[1]):
            _unresolved(unresolved, file, 'Maven 좌표가 구체적인 공개 패키지 형식이 아님', line_no)
            continue
        group, artifact, version = parts
        if not MAVEN_PIN.fullmatch(version) or version.upper().endswith('-SNAPSHOT'):
            _unresolved(unresolved, file, '정확한 Maven 고정 버전이 아님', line_no)
            continue
        _add(pinned, 'Maven', f'{group}:{artifact}', version, file)


def _composer(file, content, pinned, unresolved):
    data = _json_manifest(file, content, unresolved)
    if data is None:
        return
    if data.get('repositories'):
        _unresolved(unresolved, file, '사용자 지정 Composer 저장소가 있어 외부 조회 제외')
        return
    for section in ('require', 'require-dev'):
        entries = data.get(section, {})
        if not isinstance(entries, dict):
            _unresolved(unresolved, file, f'{section} 형식을 해석할 수 없음')
            continue
        for name, version in entries.items():
            line = _line_of(content, json.dumps(name, ensure_ascii=False)) if isinstance(name, str) else None
            if not isinstance(name, str) or not COMPOSER_NAME.fullmatch(name):
                _unresolved(unresolved, file, 'Packagist 패키지 이름 형식이 아님', line)
            elif not isinstance(version, str) or not SEMVER_PIN.fullmatch(version):
                _unresolved(unresolved, file, '정확한 Packagist 고정 버전이 아님', line)
            else:
                _add(pinned, 'Packagist', name, version, file)


def audit_dependencies(files, fetcher=None):
    pinned, unresolved = {}, []
    for file, content in files.items():
        name = file.rsplit('/', 1)[-1]
        if name.startswith('requirements') and name.endswith(('.txt', '.in')):
            _requirements(file, content, pinned, unresolved)
        elif name == 'package.json':
            _npm(file, content, pinned, unresolved)
        elif name == 'pom.xml':
            _maven(file, content, pinned, unresolved)
        elif name in ('build.gradle', 'build.gradle.kts'):
            _gradle(file, content, pinned, unresolved)
        elif name == 'composer.json':
            _composer(file, content, pinned, unresolved)
    packages = list(pinned.values())
    if len(packages) > 50:
        _unresolved(unresolved, '*', '최대 50개 버전 조회 제한')
        packages = packages[:50]
    now = datetime.now(timezone.utc).isoformat()
    base = {'provider': 'OSV', 'checked_at': now, 'packages': packages, 'unresolved': unresolved,
            'message': '공개 레지스트리의 정확한 고정 버전만 조회했습니다. 일치 기록이 없어도 안전을 보증하지 않습니다.'}
    if not packages:
        return {**base, 'status': 'partial', 'message': '조회 가능한 고정 버전이 없습니다.'}
    payload = {'queries': [{'package': {'name': row['name'], 'ecosystem': row['ecosystem']},
                           'version': row['version']} for row in packages]}
    try:
        data = (fetcher or fetch_osv)(payload)
        results = data['results']
        if not isinstance(results, list) or len(results) != len(packages):
            raise ValueError('OSV response count mismatch')
        for row, found in zip(packages, results):
            if found.get('next_page_token'):
                row.update(status='unresolved', advisories=[])
                _unresolved(unresolved, ', '.join(row['source_files']), 'OSV 결과 페이지가 더 있어 이 버전은 미완료')
                continue
            advisory_ids = [item['id'] for item in found.get('vulns', [])
                            if isinstance(item, dict) and ID.fullmatch(str(item.get('id', '')))]
            row.update(status='advisories_found' if advisory_ids else 'no_known_advisories',
                       advisories=[{'id': identifier, 'url': 'https://osv.dev/vulnerability/' + identifier}
                                   for identifier in dict.fromkeys(advisory_ids[:100])])
        return {**base, 'status': 'partial' if unresolved else 'completed'}
    except Exception as exc:
        for row in packages:
            row.update(status='unresolved', advisories=[])
        return {**base, 'status': 'failed', 'message': f'OSV 조회 실패 ({type(exc).__name__}). 안전 여부를 판단하지 않았습니다.'}
