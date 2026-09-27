"""Build offline review entries from independently fetched OSV advisories.

This module maps an advisory back to an exact manifest pin. It does not infer
code vulnerabilities or authorize operational HTTP requests.
"""

import hashlib
import re

from .dependencies import PIN


def _dependency_pin_line(file, source, package):
    ecosystem = package.get('ecosystem', 'PyPI')
    name, version = package['name'], package['version']
    if ecosystem == 'PyPI':
        for line_number, line in enumerate(source.splitlines(), 1):
            match = PIN.fullmatch(line.partition('#')[0].strip())
            if match and re.sub(r'[-_.]+', '-', match.group(1)).lower() == name and match.group(2) == version:
                return line_number
        return None
    if ecosystem in {'npm', 'Packagist'} and file.endswith('.json'):
        quoted = '"' + name + '"'
        if quoted in source and '"' + version + '"' in source:
            return next((number for number, line in enumerate(source.splitlines(), 1)
                         if quoted in line), None)
    if ecosystem == 'Maven':
        if file.endswith(('.gradle', '.kts')):
            coordinate = name + ':' + version
            return next((number for number, line in enumerate(source.splitlines(), 1)
                         if coordinate in line), None)
        if file.endswith('.xml'):
            artifact = name.rsplit(':', 1)[-1]
            if (f'<groupId>{name.rsplit(":", 1)[0]}</groupId>' in source and
                    f'<version>{version}</version>' in source):
                return next((number for number, line in enumerate(source.splitlines(), 1)
                             if f'<artifactId>{artifact}</artifactId>' in line), None)
    return None


def build_dependency_scenarios(audit, files):
    scenarios = []
    for package in audit.get('packages', []):
        advisories = package.get('advisories', [])
        if not advisories:
            continue
        locations = []
        for file in package.get('source_files', []):
            line_number = _dependency_pin_line(file, files.get(file, ''), package)
            if line_number is not None:
                locations.append({'file': file, 'line': line_number, 'symbol': 'package pin'})
        if not locations:
            continue
        name, version = package['name'], package['version']
        ecosystem = package.get('ecosystem', 'PyPI')
        display = f'{name}=={version}' if ecosystem == 'PyPI' else f'{name}@{version}'
        identifiers = [row['id'] for row in advisories]
        package_locations = ', '.join(f"{item['file']}:{item['line']}" for item in locations[:3])
        title = f'{display} · 보안 공지 영향 검토'
        scenarios.append({'id': hashlib.sha256(f'package:{ecosystem}:{name}:{version}'.encode()).hexdigest()[:16],
                          'endpoint_ids': [], 'source_evidence': locations, 'method': 'PACKAGE',
                          'path': display, 'category': 'dependency_advisory', 'title': title,
                          'description': f"OSV 공지 {', '.join(identifiers[:5])}와 실제 배포·코드 사용 경로의 관련성을 확인합니다.",
                          'risk_hypothesis': f'{ecosystem} {display}에 적용되는 보안 공지가 있지만, 실제 배포와 사용 경로가 공지 조건에 해당할 때만 영향 가능성이 있습니다.',
                          'source_trigger': (f"{package_locations}에서 "
                                             f"{ecosystem} {display} 고정 버전을 발견했고 OSV 공지 {', '.join(identifiers[:5])}를 조회했습니다."),
                          'verification_expectation': '실제 설치 버전과 공지의 영향 조건·수정 버전·코드 호출 경로를 대조합니다.',
                          'automation_rationale': '버전 조회만으로 해당 취약 코드의 사용 여부나 악용 가능성을 판단할 수 없어 운영 요청을 보내지 않습니다.',
                          'uncertainty': 'OSV 공지는 취약점 후보 근거이며 이 프로젝트의 실제 취약 여부 또는 악용 가능성의 증명이 아닙니다.',
                          'review_steps': ['해당 패키지가 운영 이미지에 포함되는지 확인합니다.',
                                           '공지의 영향 버전·설정과 실제 사용 기능을 비교합니다.',
                                           '영향이 확인되면 수정 버전과 호환성을 확인합니다.'],
                          'execution_kind': 'manual', 'automatable': False,
                          'disabled_reason': '공지 영향 조건과 사용 경로 확인 필요 — 자동 요청 제외',
                          'checks': [], 'expected': '배포 포함 여부, 영향 버전·설정, 호출 경로 확인',
                          'remediation': {'summary': f'{name}의 공지 영향 조건과 수정 버전을 확인하세요.',
                                          'steps': ['고정된 버전이 실제 운영 환경에도 설치되는지 확인하세요.',
                                                    '공지의 영향 버전·설정·사용 경로와 소스 호출 위치를 비교하세요.',
                                                    '영향이 확인되면 호환 가능한 수정 버전으로 갱신하고 회귀 테스트를 실행하세요.']}})
    return scenarios[:50]
