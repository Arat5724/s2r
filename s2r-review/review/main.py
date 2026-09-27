import ast
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import bridge, runtime
from .ai_scenarios import normalize_ai_scenarios
from .ai_scripts import evaluate_observation, validate_plan
from .ai_patches import manual_patch, prepare_patch_request, validate_patches
from .dependencies import audit_dependencies
from .dependency_scenarios import build_dependency_scenarios
from .scripts import render_review_script, render_script
from .snapshot import safe_project, snapshot

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(os.getenv('S2R_REVIEW_DATA', str(ROOT.parent / 's2r-review-data'))).resolve()
SAMPLE = ROOT.parent / 'samples' / 'teamshelf'
TECHLAB = ROOT.parent / 'samples' / 'techlab'
SPRING_SAMPLE = ROOT.parent / 'samples' / 'spring-releasehub'
PROTECTED = [ROOT, DATA, ROOT.parent / 'samples' / 'teamshelf-evaluation', ROOT.parent / 'samples' / 'teamshelf-runtime',
             ROOT.parent / 'samples' / 'techlab-runtime', ROOT.parent / 'samples' / 'spring-releasehub-runtime']
DATA.mkdir(exist_ok=True)
(DATA / 'jobs').mkdir(exist_ok=True)
TOKEN = secrets.token_urlsafe(32)
POOL = ThreadPoolExecutor(max_workers=1)
RUNNING = threading.Lock()
STORE_LOCK = threading.Lock()
JSON_LOCK = threading.RLock()

def stamp():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    # Windows cannot replace a file while another request has it open for reading.
    with JSON_LOCK:
        tmp = path.with_suffix('.tmp')
        tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
        for attempt in range(6):
            try:
                tmp.replace(path)
                return
            except PermissionError:
                if attempt == 5:
                    raise
                time.sleep(0.02 * (attempt + 1))


def read_json(path):
    with JSON_LOCK:
        return json.loads(path.read_text(encoding='utf-8'))


def projects():
    path = DATA / 'projects.json'
    defaults = [
        {'id': 'techlab', 'name': 'TechLab', 'path': str(TECHLAB)},
        {'id': 'spring-releasehub', 'name': 'ReleaseHub (Spring Boot)', 'path': str(SPRING_SAMPLE)},
    ]
    # Replace only the original built-in TeamShelf entry. User-added projects
    # and job histories remain available, including a separately added TeamShelf.
    with JSON_LOCK:
        previous = read_json(path) if path.exists() else []
        result = defaults.copy()
        for row in previous:
            builtin = next((item for item in defaults if row.get('id') == item['id']), None)
            if row == builtin:
                continue
            if (row.get('id') == 'teamshelf' and row.get('name') == 'TeamShelf'
                    and Path(row.get('path', '')).resolve() == SAMPLE.resolve()):
                continue
            if builtin is not None:
                # Keep an older user entry with this ID selectable as well.
                row = {**row, 'id': uuid.uuid5(uuid.NAMESPACE_URL, 's2r-review:' + row['path']).hex}
            result.append(row)
        if result != previous:
            write_json(path, result)
        return result


def job_path(identifier):
    try:
        parsed = uuid.UUID(identifier)
    except ValueError:
        raise HTTPException(404, '분석 작업을 찾을 수 없습니다.')
    if str(parsed) != identifier:
        raise HTTPException(404, '분석 작업을 찾을 수 없습니다.')
    path = DATA / 'jobs' / identifier
    if not path.is_dir():
        raise HTTPException(404, '분석 작업을 찾을 수 없습니다.')
    return path


def read_status(path):
    return read_json(path / 'status.json')


def recover_interrupted_jobs():
    """Only the server launcher may recover sandboxes and mark stale work."""
    for job in sorted((DATA / 'jobs').iterdir()):
        if not job.is_dir():
            continue
        recovery_file = job / 'sandbox-recovery.json'
        pending = (recovery_file.is_file()
                   and read_json(recovery_file).get('state') == 'quarantining')
        if (job / 'sandbox.json').is_file():
            recovered = runtime.recover_job_sandbox(job)
        elif (job / 'openshell-policy.json').is_file() or (job / 'source-manifest.json').is_file() or pending:
            recovered = runtime.quarantine_orphan_job_sandbox(job)
        else:
            continue
        write_json(job / 'sandbox-recovery.json', recovered)
    for stale in (DATA / 'jobs').glob('*/status.json'):
        value = json.loads(stale.read_text(encoding='utf-8'))
        if value.get('state') in {'queued', 'running'}:
            value.update(state='interrupted', message='앱이 재시작되어 이전 작업이 중단되었습니다. 새 분석을 시작하세요.')
            write_json(stale, value)
    for stale in (DATA / 'jobs').glob('*/runs/*/status.json'):
        value = json.loads(stale.read_text(encoding='utf-8'))
        if value.get('state') in {'queued', 'running'}:
            value.update(state='interrupted', stage='interrupted', finished_at=stamp(),
                         message='앱이 재시작되어 운영 점검이 중단되었습니다. 정책 복구 상태를 확인하고 다시 시작하세요.')
            write_json(stale, value)

app = FastAPI(title='S2R Review', docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=['127.0.0.1', 'localhost', 'testserver'])


@app.middleware('http')
async def local_boundary(request: Request, call_next):
    if request.method not in {'GET', 'HEAD', 'OPTIONS'}:
        origin = request.headers.get('origin')
        allowed_origin = f'{request.url.scheme}://{request.headers.get("host", "")}'
        if origin is not None and origin != allowed_origin:
            return JSONResponse({'detail': '다른 사이트에서의 요청은 허용하지 않습니다.'}, status_code=403)
        if not hmac.compare_digest(request.headers.get('x-s2r-token', ''), TOKEN):
            return JSONResponse({'detail': '로컬 화면을 새로고침한 뒤 다시 시도하세요.'}, status_code=403)
    response = await call_next(request)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    return response


@app.get('/')
def home():
    return FileResponse(ROOT / 'static' / 'index.html')


@app.get('/api/config')
def config():
    return {'projects': projects(), 'token': TOKEN, 'sandbox': '작업별 OpenShell 샌드박스', 'output_dir': str(DATA / 'jobs'),
            'framework': 'FastAPI · Flask · Django · Express · Next.js · NestJS · Spring Boot · Laravel',
            'model_route': '기존 NemoClaw Nemotron 경로',
            'scope': {'originals_mounted': True, 'source_mount_mode': 'individual_files',
                      'source': '/source (선택 원본 파일만 읽기 허용)',
                      'inputs': '/input (메타데이터만 읽기 허용)', 'outputs': '/output (쓰기 허용)'}}


@app.post('/api/projects/select')
def choose_project():
    try:
        proc = subprocess.run([sys.executable, '-B', str(ROOT / 'review' / 'picker.py')], capture_output=True,
                              timeout=120, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if proc.returncode:
            raise ValueError('폴더 선택 창을 열지 못했습니다.')
        chosen = proc.stdout.decode('utf-8').strip()
        if not chosen:
            return {'cancelled': True}
        root = safe_project(chosen, PROTECTED)
        with STORE_LOCK:
            items = projects()
            old = next((row for row in items if Path(row['path']) == root), None)
            if old:
                return {'project': old}
            item = {'id': uuid.uuid4().hex, 'name': root.name, 'path': str(root)}
            items.append(item)
            write_json(DATA / 'projects.json', items)
        return {'project': item}
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        raise HTTPException(400, str(exc))


class AnalysisRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    project_id: str
    ai: bool = True


@app.post('/api/jobs', status_code=202)
def create_job(payload: AnalysisRequest):
    if not payload.ai:
        raise HTTPException(400, '새 분석은 AI 기반 소스·시나리오 생성만 지원합니다.')
    project = next((row for row in projects() if row['id'] == payload.project_id), None)
    if project is None:
        raise HTTPException(404, '연결된 프로젝트를 선택하세요.')
    try:
        root = safe_project(project['path'], PROTECTED)
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc))
    if not RUNNING.acquire(blocking=False):
        raise HTTPException(409, '다른 분석이 진행 중입니다. 완료 후 다시 시작하세요.')
    try:
        identifier = str(uuid.uuid4())
        folder = DATA / 'jobs' / identifier
        folder.mkdir()
        status = {'id': identifier, 'project': project, 'created_at': stamp(), 'state': 'queued',
                  'progress': 0, 'stage': 'queued', 'message': '분석을 준비합니다.', 'ai_requested': payload.ai}
        write_json(folder / 'status.json', status)
        POOL.submit(analyze, folder, root, status)
        return status
    except Exception:
        RUNNING.release()
        raise


def analyze(folder, root, status):
    def update(stage, progress, message):
        status.update(stage=stage, state='running', progress=progress, message=message, updated_at=stamp())
        write_json(folder / 'status.json', status)
        with (folder / 'events.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps({'time': stamp(), 'stage': stage, 'message': message}, ensure_ascii=False) + '\n')
    try:
        update('snapshot', 5, '마운트할 소스 파일 목록과 분석 버전을 기록합니다.')
        bundle = snapshot(root)
        write_json(folder / 'bundle.json', bundle)
        result = bridge.run(folder, update, root)
        after = snapshot(root)
        result.update(schema_version=1, id=status['id'], project=status['project'], created_at=status['created_at'],
                      source_hash=bundle['source_hash'], source_hash_scope=bundle['hash_scope'],
                      source_unchanged=bundle['source_hash'] == after['source_hash'], skipped_files=bundle['skipped'],
                      scope={'originals_mounted': True, 'source_mount_mode': 'individual_files',
                             'read_only_source': '/source (선택 원본 파일만)',
                             'read_only_input': '/input (소스 목록과 해시만)', 'write_output': '/output'})
        if not result['source_unchanged']:
            result['diagnostics'].append({'message': '분석 중 원본 내용이 변경되었습니다. 마운트에서 읽은 파일은 시작 시점 해시와 일치하는지 별도로 확인했습니다.'})
        if result.get('analysis_mode') != 'ai':
            raise ValueError('AI가 엔드포인트와 시나리오를 생성한 결과가 아닙니다.')
        scenarios = normalize_ai_scenarios(result, bundle['files'])
        write_json(folder / 'scenarios.json', {'version': 8, 'generator': 'ai', 'scenarios': scenarios})
        write_json(folder / 'result.json', result)
        (folder / 'report.md').write_text(markdown_report(result, scenarios), encoding='utf-8')
        status.update(state='completed', progress=100, stage='completed', finished_at=stamp(),
                      message='AI가 엔드포인트와 취약점 시나리오를 생성했습니다.',
                      counts=result['counts'], ai_status=result['ai']['status'])
        write_json(folder / 'status.json', status)
    except Exception as exc:
        status.update(state='failed', stage='failed', message=str(exc)[:2000], finished_at=stamp())
        write_json(folder / 'status.json', status)
    finally:
        RUNNING.release()


def markdown_report(result, scenarios=None):
    lines = ['# S2R Review 소스 분석 보고서', '', f"프로젝트: {result['project']['name']}",
             f"확인된 프레임워크: {result['framework']}",
             f"분석 시각: {result['created_at']}", f"소스 SHA-256: {result['source_hash']}", '',
             '## 분석 범위', '', '선별된 원본 소스 파일을 각각 읽기 전용으로 마운트하고 OpenShell 파일 정책 안에서 정적 분석했습니다. 웹사이트 요청과 CVE 조회는 수행하지 않았습니다.',
             f"파일 경계 확인: {result['boundary'].get('passed')}", f"원본 내용 동일: {result['source_unchanged']}", '',
             '## 분석 방식', '', f"방식: {result.get('analysis_mode', 'ai')}",
             f"AI 상태: {result['ai']['status']}", result['ai'].get('project_summary', 'AI 설명 없음'),
             'AI가 찾은 엔드포인트와 취약점 후보는 소스 근거와 함께 검토하세요.', '',
             '## 엔드포인트', '', '| 메서드 | 경로 | 처리 함수 | 등록 조건 |', '|---|---|---|---|']
    assist = result['ai'].get('syntax_assist') or {}
    if assist:
        syntax_lines = ['## AST·구문 트리 보조 분석', '',
                        '구문 구조는 Nemotron의 소스 탐색을 돕는 단서입니다. 엔드포인트와 취약점 가설은 모델이 제안하고 원본 코드 줄로 검증합니다. 동적 호출과 누락된 파일은 확정하지 않습니다.', '']
        for key, label in [('python_ast', 'Python AST'), ('tree_sitter', 'Tree-sitter')]:
            item = assist.get(key) or {}
            syntax_lines.append(
                f"- {label}: 상태 {item.get('status', '미확인')}, 파싱 {item.get('files_parsed', 0)}개 파일, "
                f"실패 {item.get('files_failed', 0)}개, 제외 {item.get('files_skipped', 0)}개, "
                f"처리 한도 도달 {item.get('files_limited', 0)}개, "
                f"전달한 구조 단서 {item.get('facts_included', 0)}개, 생략 {item.get('facts_omitted', 0)}개")
        syntax_lines.append('')
        at = lines.index('## 엔드포인트')
        lines[at:at] = syntax_lines
    for e in result['endpoints']:
        values = [e['method'], e['path'], f"{e['handler']['file']}:{e['handler']['line']} {e['handler']['symbol']}", ' / '.join(e['conditions']) or '조건 없음']
        lines.append('| ' + ' | '.join(value.replace('|', '\\|').replace('\n', ' ') for value in values) + ' |')
    lines += ['', '## 엔드포인트별 근거', '']
    summaries = {row['id']: row['summary'] for row in result['ai'].get('endpoints', [])}
    for e in result['endpoints']:
        lines += [f"### {e['method']} {e['path']}", '', summaries.get(e['id'], 'AI 설명 없음'), '',
                  f"인증·권한 패턴: {e['auth']} (안전성 증명 아님)", '실행 환경: 미확인', '',
                  '입력값:', '']
        for item in e['inputs']:
            for field in item.get('fields', [item]):
                constraints = ', '.join(f'{key}={value}' for key, value in field.get('constraints', {}).items())
                lines.append(f"- {item['in']} / {field['name']}: {field['type']} / {'필수' if field['required'] else '선택'} / {constraints}")
        if not e['inputs']:
            lines.append('- 추출된 요청 파라미터 없음. 인증 헤더는 의존성 근거를 확인하세요.')
        lines += ['', '관련 함수:', '']
        lines += [f"- {c['symbol']} — {c['file']}:{c['line']} ({c['reason']})" for c in e['call_chain']]
        lines.append('')
    if scenarios is not None:
        lines += ['', '## AI 취약점 시나리오', '']
        for row in scenarios:
            evidence = ', '.join(f"{e['file']}:{e['line']}" for e in row['source_evidence'])
            lines += [f"### {row['title']}", '', f"카테고리: {row['category']}",
                      f"경로: {row['method']} {row['path']}", f"코드 근거: {evidence}",
                      row['description'], f"위험 가설: {row['risk_hypothesis']}",
                      f"검증 기준: {row['verification_expectation']}",
                      f"자동 운영 검증: {'가능' if row['automatable'] else '보류'}", '']
        if not scenarios:
            lines += ['모델이 근거 있는 기술 취약점 후보를 제안하지 않았습니다.', '']
    lines += ['', '## 해석 한계', ''] + ['- ' + value for value in result['limitations']]
    return '\n'.join(lines) + '\n'


def completed_job(identifier):
    folder = job_path(identifier)
    if read_status(folder)['state'] != 'completed' or not (folder / 'result.json').exists():
        raise HTTPException(409, '소스 분석을 완료한 후 선택하세요.')
    return folder


def catalog(folder):
    path = folder / 'scenarios.json'
    files = read_json(folder / 'bundle.json')['files']
    if path.exists():
        cached = read_json(path)
        if isinstance(cached, dict) and cached.get('version') in {7, 8}:
            base = cached['scenarios']
        else:
            cached = None
    else:
        cached = None
    if cached is None:
        result = read_json(folder / 'result.json')
        if result.get('analysis_mode') == 'ai':
            base = normalize_ai_scenarios(result, files)
            write_json(path, {'version': 8, 'generator': 'ai', 'scenarios': base})
        else:
            # Historical rule-based jobs remain readable only when their
            # original catalog exists; never reconstruct retired findings.
            base = []
    if cached is not None and cached.get('version') == 8 and cached.get('generator') == 'ai':
        # Re-evaluate transport eligibility against the immutable source
        # snapshot. Older analyses keep their findings and IDs, while a new
        # safety gate can be used for a newly selected operational run.
        by_id = {row['id']: row for row in read_json(folder / 'result.json')['endpoints']}
        for row in base:
            endpoint = by_id.get((row.get('endpoint_ids') or [None])[0])
            if endpoint is None or row.get('generation') != 'ai':
                continue
            eligible, reason = runtime.ai_get_eligibility(endpoint, row, files)
            row['automatable'] = eligible
            row['execution_kind'] = 'ai_request' if eligible else 'manual'
            row['disabled_reason'] = None if eligible else reason
            row['automation_rationale'] = (
                f"선택한 {row['method']} 경로에서 제한된 AI 진단 입력을 비교 검증합니다." if eligible
                else f'자동 요청 보류: {reason}')
    audit_path = folder / 'dependency-audit.json'
    if not audit_path.exists():
        return base
    return base + build_dependency_scenarios(read_json(audit_path), files)


def selection(folder):
    path = folder / 'selection.json'
    if path.exists():
        return read_json(path)
    project_id = read_status(folder).get('project', {}).get('id')
    target_port = 8030 if project_id == 'spring-releasehub' else 8010
    return {'revision': 0, 'scenario_ids': [], 'endpoint_ids': [],
            'target_base_url': f'http://127.0.0.1:{target_port}'}


@app.get('/api/jobs/{identifier}/workflow')
def workflow(identifier: str):
    folder = completed_job(identifier)
    result_data = read_json(folder / 'result.json')
    scenarios = catalog(folder)
    options = []
    for endpoint in result_data['endpoints']:
        linked = [s for s in scenarios if endpoint['id'] in s['endpoint_ids']]
        can_request = any(s['automatable'] for s in linked)
        options.append({'id': endpoint['id'], 'method': endpoint['method'], 'path': endpoint['path'],
                        'automatable': can_request,
                        'disabled_reason': None if can_request else next((s['disabled_reason'] for s in linked if not s['automatable']), None),
                        'scenario_ids': [s['id'] for s in linked]})
    runs = [read_json(path) for path in (folder / 'runs').glob('*/status.json')] if (folder / 'runs').exists() else []
    audit_path = folder / 'dependency-audit.json'
    return {'scenarios': scenarios, 'endpoint_options': options, 'selection': selection(folder),
            'runs': sorted(runs, key=lambda row: row['created_at'], reverse=True),
            'dependency_audit': read_json(audit_path) if audit_path.exists() else None}


class SelectionRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    revision: int = Field(ge=0)
    scenario_ids: list[str] = Field(max_length=100)
    endpoint_ids: list[str] = Field(max_length=100)
    target_base_url: str = Field(max_length=250)


@app.put('/api/jobs/{identifier}/selection')
def save_selection(identifier: str, payload: SelectionRequest):
    folder = completed_job(identifier)
    all_scenarios = {row['id'] for row in catalog(folder)}
    all_endpoints = {row['id'] for row in read_json(folder / 'result.json')['endpoints']}
    if set(payload.scenario_ids) - all_scenarios or set(payload.endpoint_ids) - all_endpoints:
        raise HTTPException(400, '분석 결과에 없는 시나리오 또는 엔드포인트입니다.')
    try:
        runtime.validate_target(payload.target_base_url)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    with STORE_LOCK:
        old = selection(folder)
        if old['revision'] != payload.revision:
            raise HTTPException(409, '다른 화면에서 선택이 변경되었습니다. 새로고침한 뒤 다시 선택하세요.')
        value = {'revision': old['revision'] + 1,
                 'scenario_ids': sorted(set(payload.scenario_ids)),
                 'endpoint_ids': sorted(set(payload.endpoint_ids)),
                 'target_base_url': payload.target_base_url.strip()}
        write_json(folder / 'selection.json', value)
    return value


@app.post('/api/jobs/{identifier}/dependency-audit')
def run_dependency_audit(identifier: str):
    folder = completed_job(identifier)
    files = read_json(folder / 'bundle.json')['files']
    audit = audit_dependencies(files)
    write_json(folder / 'dependency-audit.json', audit)
    # The package lookup can run after an operational check; keep its downloadable
    # integrated report in sync with the audit displayed in the UI.
    for result_path in (folder / 'runs').glob('*/result.json') if (folder / 'runs').exists() else []:
        run = read_json(result_path)
        run['dependency_audit'] = audit
        write_json(result_path, run)
        (result_path.parent / 'report.md').write_text(runtime_report(run), encoding='utf-8')
    return audit


class RunRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    selection_revision: int = Field(ge=1)


def run_path(identifier, run_id):
    folder = completed_job(identifier)
    try:
        if str(uuid.UUID(run_id)) != run_id:
            raise ValueError()
    except ValueError:
        raise HTTPException(404, '운영 점검 이력을 찾을 수 없습니다.')
    path = folder / 'runs' / run_id
    if not path.is_dir():
        raise HTTPException(404, '운영 점검 이력을 찾을 수 없습니다.')
    return path


@app.post('/api/jobs/{identifier}/runs', status_code=202)
def create_run(identifier: str, payload: RunRequest):
    folder = completed_job(identifier)
    recovery_file = folder / 'sandbox-recovery.json'
    if recovery_file.exists() and read_json(recovery_file).get('state') in {'quarantining', 'quarantined'}:
        raise HTTPException(409, '분석 샌드박스가 격리되었습니다. 새 분석을 시작하세요.')
    saved = selection(folder)
    if saved['revision'] != payload.selection_revision:
        raise HTTPException(409, '저장된 선택 버전이 바뀌었습니다.')
    if not saved['scenario_ids']:
        raise HTTPException(400, '점검할 시나리오를 선택하세요.')
    try:
        target = runtime.validate_target(saved['target_base_url'])
        scenarios = catalog(folder)
        endpoints = read_json(folder / 'result.json')['endpoints']
        ai_mode = read_json(folder / 'result.json').get('analysis_mode') == 'ai'
        if not ai_mode:
            raise ValueError('이전 규칙 기반 기록은 열람만 가능합니다. 새 AI 분석을 시작하세요.')
        routes = []
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if not RUNNING.acquire(blocking=False):
        raise HTTPException(409, '다른 분석·운영 점검이 진행 중입니다.')
    try:
        run_id = str(uuid.uuid4())
        run_folder = folder / 'runs' / run_id
        run_folder.mkdir(parents=True)
        status = {'id': run_id, 'analysis_id': identifier, 'state': 'queued', 'stage': 'queued',
                  'created_at': stamp(), 'progress': 0, 'message': '선택한 범위를 확인합니다.',
                  'selection_revision': saved['revision']}
        write_json(run_folder / 'status.json', status)
        POOL.submit(execute_ai_run, run_folder, saved.copy(), scenarios, endpoints, target, routes, status)
        return status
    except Exception:
        RUNNING.release()
        raise


def runtime_report(value):
    ai_mode = value.get('source', {}).get('analysis_mode') == 'ai'
    scope = value.get('scope') or {}
    allowed_routes = scope.get('allowed_routes')
    if allowed_routes is None:
        allowed_routes = [{'method': scope.get('method', 'GET'), 'path': path}
                          for path in scope.get('allowed_paths', [])]
    allowed_text = ', '.join(f"{row['method']} {row['path']}" for row in allowed_routes) or '(요청 없음)'
    lines = ['# S2R Review 운영 점검 보고서', '', f"분석 ID: {value['analysis_id']}",
             f"점검 ID: {value['id']}", f"대상 서버: {value['target_base_url']}",
             f"선택 버전: {value['selection']['revision']}",
             f"요청 허용 범위: {allowed_text}", '',
             ('AI가 코드 근거로 기준값·후보값 요청과 응답 판정 코드를 생성했습니다. 선택한 메서드·경로마다 최대 두 요청을 제한된 범위에서 보냈으며, 실행하지 못한 항목은 그 이유를 별도로 기록했습니다.'
              if ai_mode else
              '이전 규칙 기반 분석 기록입니다.'), '']
    if value['scope'].get('policy_applied'):
        lines += [f"임시 정책 복원: {'확인' if value['scope'].get('policy_restored') else '결과에 기록되지 않음'}", '']
    generation = value.get('script_generation') or {}
    if value.get('source', {}).get('analysis_mode') == 'ai':
        lines += ['## Python 재검증 스크립트', '']
        if generation.get('status') == 'completed':
            lines += ['Nemotron이 함수 코드에서 진단 입력과 Python 응답 판정 함수를 생성했습니다. 호스트가 형식과 요청 범위를 검증했습니다.',
                      '자동 요청 스크립트를 별도로 실행하면 OpenShell 네트워크 정책은 적용되지 않습니다. 오프라인 스크립트는 네트워크 요청을 보내지 않습니다.', '']
        elif generation.get('status') == 'failed':
            lines += [f"생성 실패: {generation.get('message', 'AI 판정 코드를 제공할 수 없습니다.')}", '']
    lines += ['## 결과 집계', '']
    lines += [f'- {kind}: {count}' for kind, count in value['counts'].items() if count]
    lines.append('')
    source = value.get('source') or {}
    if source:
        lines += ['## 소스 분석', '', f"프로젝트: {source['project_name']}",
                  f"프레임워크: {source['framework']}",
                  f"소스 해시: {source.get('source_hash', '기록 없음')}",
                  f"분석한 엔드포인트: {len(source['endpoints'])}개", '']
        if source.get('project_summary'):
            lines += [f"모델 생성 서비스 설명: {source['project_summary']}", '']
        lines += ['### 엔드포인트 목록', '', '| 메서드 | 경로 | 선택 |', '|---|---|---|']
        selected = set(value['selection']['endpoint_ids'])
        for endpoint in source['endpoints']:
            lines.append(f"| {endpoint['method']} | `{endpoint['path']}` | {'예' if endpoint['id'] in selected else '아니오'} |")
        lines.append('')
    for item in value['results']:
        scenario = item['scenario']
        evidence_locations = ', '.join(f"{e['file']}:{e['line']}" for e in scenario['source_evidence'])
        lines += [f"## {scenario['title']}", '',
                  f"결과: {item['status']}", item['summary'],
                  f"코드 근거: {evidence_locations}", '']
        for field, title in [('risk_hypothesis', '위험 가설'), ('source_trigger', '시나리오 근거'),
                             ('verification_expectation', '판단 기준'),
                             ('automation_rationale', '실행 방식'), ('uncertainty', '판단 한계')]:
            if scenario.get(field):
                lines.append(f"{title}: {scenario[field]}")
        if scenario.get('review_steps'):
            lines += ['', '검토 단계:'] + [f'- {step}' for step in scenario['review_steps']]
        if item['status'] not in {'pass', 'blocked'}:
            lines.append(f"{'추가 검토' if item['status'] == 'manual_review' else '조치 제안'}: {scenario['remediation']['summary']}")
            for step in scenario['remediation']['steps']:
                lines.append('- ' + step)
        if item.get('http_status') is not None:
            lines.append(f"- HTTP 상태: {item['http_status']}")
        request = item.get('request')
        if request:
            location = 'JSON 본문' if request.get('input_location') == 'body' else '쿼리'
            lines.append(f"- 실제 요청: {request['method']} {request['path']} · "
                         f"{location} {request.get('input_name', '')} · {request.get('count', 1)}회")
        observed_pair = item.get('evidence') or {}
        if isinstance(observed_pair, dict) and {'baseline', 'candidate'} <= set(observed_pair):
            lines.append(f"- 실제 요청: 기준값 HTTP {observed_pair['baseline'].get('status_code')}, "
                         f"후보값 HTTP {observed_pair['candidate'].get('status_code')}")
        if item.get('script_available'):
            mode = '오프라인 응답 검토' if item.get('script_mode') == 'offline' else '승인된 요청 재검증'
            lines.append(f"- Python 점검 스크립트: scripts/{item['scenario_id']}.py ({mode})")
        patch = item.get('patch') or {}
        if patch.get('diff'):
            lines += ['', f"변경 제안: {patch['file']}:{patch['start_line']}", patch['reason'],
                      '```diff', patch['diff'].rstrip(), '```']
        elif patch.get('reason') and item['status'] in {'fail', 'manual_review', 'inconclusive', 'not_found'}:
            lines.append(f"정확한 diff 미제공: {patch['reason']}")
        lines.append('')
    audit = value.get('dependency_audit')
    if audit:
        lines += ['## 패키지 공지 조회', '', f"OSV 상태: {audit['status']}", '']
        for package in audit['packages']:
            ids = ', '.join(row['id'] for row in package.get('advisories', []))
            lines.append(f"- {package['name']}=={package['version']}: {package['status']} {ids}")
        lines.append('')
    return '\n'.join(lines) + '\n'


def _ai_source_context(scenario, endpoints, files):
    """Show the model the cited handler and nearby source, with original lines."""
    endpoint = next((row for row in endpoints if row['id'] in scenario.get('endpoint_ids', [])), None)
    handler = (endpoint or {}).get('handler') or {}
    selected = {}
    if handler.get('file') in files and type(handler.get('line')) is int:
        start = max(1, handler['line'] - 2)
        end = min(len(files[handler['file']].splitlines()), handler.get('end_line', start) + 2)
        if end - start <= 140:
            selected.setdefault(handler['file'], set()).update(range(start, end + 1))
        if handler['file'].endswith('.py'):
            try:
                tree = ast.parse(files[handler['file']])
                function = next((node for node in ast.walk(tree)
                                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                                 and node.lineno == handler['line']), None)
                names = ({node.id for node in ast.walk(function)
                          if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
                         if function is not None else set())
                for _ in range(2):
                    added = False
                    for node in tree.body:
                        if isinstance(node, ast.Assign):
                            targets = {part.id for target in node.targets for part in ast.walk(target)
                                       if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Store)}
                        elif isinstance(node, ast.AnnAssign):
                            targets = {part.id for part in ast.walk(node.target)
                                       if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Store)}
                        else:
                            continue
                        if targets & names and (node.end_lineno or node.lineno) - node.lineno <= 12:
                            selected.setdefault(handler['file'], set()).update(
                                range(node.lineno, (node.end_lineno or node.lineno) + 1))
                            before = len(names)
                            names.update(part.id for part in ast.walk(node.value)
                                         if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Load))
                            added |= len(names) > before
                    if not added:
                        break
            except (SyntaxError, ValueError, RecursionError):
                pass
    for evidence in scenario.get('source_evidence', []):
        path, line = evidence.get('file'), evidence.get('line')
        if path in files and type(line) is int:
            selected.setdefault(path, set()).update(range(max(1, line - 8), line + 9))
    chunks = []
    for path, numbers in selected.items():
        lines = files[path].splitlines()
        excerpt = '\n'.join(f'L{number:05d} {lines[number - 1]}' for number in sorted(numbers)
                            if 1 <= number <= len(lines))
        if excerpt:
            chunks.append(f'FILE {path}\n{excerpt}')
    return ('\n\n'.join(chunks) or '분석 당시 코드 근거를 재구성할 수 없습니다.')[:13500]


def _fixture_hints(files):
    """Expose owner-declared synthetic fixture names, never arbitrary file data."""
    manifest = files.get('s2r-review-fixtures.json')
    if not isinstance(manifest, str) or len(manifest) > 4000:
        return []
    try:
        data = json.loads(manifest)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict) or data.get('version') != 1:
        return []
    declared = data.get('probe_files')
    if not isinstance(declared, list) or len(declared) > 8:
        return []
    hints = []
    for item in declared:
        if not isinstance(item, dict) or set(item) - {'path', 'purpose', 'marker'}:
            return []
        path, purpose, marker = item.get('path'), item.get('purpose'), item.get('marker')
        if (not isinstance(path, str) or len(path) > 240 or '\\' in path
                or path.startswith('/') or any(part in {'', '.', '..'} for part in path.split('/'))
                or not path.endswith('.txt') or path not in files
                or purpose not in {'public_control', 'synthetic_canary'}):
            return []
        if purpose == 'synthetic_canary':
            if (not isinstance(marker, str) or not re.fullmatch(r'[A-Za-z0-9_-]{4,64}', marker)
                    or files[path].strip() != marker):
                return []
        elif marker is not None:
            return []
        hints.append({'path': path, 'purpose': purpose, 'marker': marker})
    return hints


def _script_request(scenario, endpoints, files):
    endpoint = next((row for row in endpoints
                     if row.get('id') in scenario.get('endpoint_ids', [])), None)
    matching_inputs = [row for row in (endpoint or {}).get('inputs', [])
                       if isinstance(row, dict) and row.get('name') == scenario.get('input_name')
                       and row.get('in') in {'query', 'body'}]
    locations = {row['in'] for row in matching_inputs}
    input_location = next(iter(locations)) if len(locations) == 1 else None
    return {'id': scenario['id'], 'category': scenario['category'],
            'method': scenario['method'], 'path': scenario['path'],
            'input_name': scenario.get('input_name'), 'input_location': input_location,
            'title': scenario['title'], 'risk_hypothesis': scenario['risk_hypothesis'],
            'verification_expectation': scenario['verification_expectation'],
            'source_context': _ai_source_context(scenario, endpoints, files),
            'source_evidence': [{'file': row['file'], 'line': row['line']}
                                for row in scenario.get('source_evidence', [])[:12]],
            'automatable': bool(scenario.get('automatable')),
            'fixture_hints': _fixture_hints(files)}


def _cached_ai_plan(job, identifier):
    """Reuse a model-authored plan from this immutable analysis snapshot."""
    prior = (job / 'runs').glob(f'*/scripts-{identifier}-worker-result.json')
    for path in sorted(prior, key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            checks = read_json(path).get('checks')
            if (isinstance(checks, list) and len(checks) == 1
                    and isinstance(checks[0], dict) and checks[0].get('id') == identifier
                    and set(checks[0]) == {'id', 'probe', 'source', 'reason'}
                    and isinstance(checks[0].get('probe'), dict)
                    and len(checks[0]['probe'].get('requests', [])) == 2):
                return {key: checks[0][key] for key in ('probe', 'source', 'reason')}
        except (OSError, ValueError, AttributeError):
            continue
    return None


def _has_live_probe(plan):
    probe = plan.get('probe') if isinstance(plan, dict) else None
    if not isinstance(probe, dict):
        return False
    if 'requests' in probe:
        return bool(probe['requests'])
    return probe.get('query_key') is not None


def _public_observation(row):
    return {key: value for key, value in row.items() if key != 'body_text'}


def execute_ai_run(folder, saved, scenarios, endpoints, target, _routes, status):
    """AI plans all selected checks and patches; trusted code owns execution."""
    def update(stage, progress, message):
        status.update(state='running', stage=stage, progress=progress, message=message, updated_at=stamp())
        write_json(folder / 'status.json', status)
        with (folder / 'events.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps({'time': stamp(), 'stage': stage, 'message': message}, ensure_ascii=False) + '\n')

    try:
        parent = folder.parent.parent
        files = read_json(parent / 'bundle.json')['files']
        source_result = read_json(parent / 'result.json')
        chosen_ids, endpoint_ids = set(saved['scenario_ids']), set(saved['endpoint_ids'])
        selected = [item for item in scenarios if item['id'] in chosen_ids]
        effective = [item for item in selected if set(item['endpoint_ids']) <= endpoint_ids]
        plans, plan_errors, source_contexts, request_meta = {}, {}, {}, {}
        for index, scenario in enumerate(effective, 1):
            update('generating_script', 5 + int(25 * index / max(1, len(effective))),
                   f'AI가 만든 함수별 점검 계획을 확인합니다 ({index}/{len(effective)}).')
            try:
                request = _script_request(scenario, endpoints, files)
                source_contexts[scenario['id']] = request['source_context']
                request_meta[scenario['id']] = request
                checked_scenario = {**scenario, 'fixture_hints': request['fixture_hints'],
                                    'input_location': request['input_location']}
                candidate = _cached_ai_plan(parent, scenario['id'])
                approved = None
                if candidate is not None:
                    try:
                        approved = validate_plan(
                            candidate, checked_scenario,
                            offline=not scenario.get('automatable') or not _has_live_probe(candidate),
                            source_context=request['source_context'])
                    except (TypeError, ValueError, KeyError):
                        candidate = None
                if candidate is None:
                    candidate = bridge.generate_ai_checks(
                        folder, [request], label=f"scripts-{scenario['id']}")[scenario['id']]
                    approved = validate_plan(
                        candidate, checked_scenario,
                        offline=not scenario.get('automatable') or not _has_live_probe(candidate),
                        source_context=request['source_context'])
                offline = not scenario.get('automatable') or not _has_live_probe(approved)
                if not offline:
                    requests = (approved['probe']['requests'] if 'requests' in approved['probe']
                                else [approved['probe']])
                    if any(item['query_key'] != scenario.get('input_name')
                           or item.get('input_location', 'query') != request['input_location']
                           for item in requests):
                        raise ValueError('AI 진단 입력이 소스의 선택된 파라미터·위치와 일치하지 않습니다.')
                plans[scenario['id']] = approved
            except Exception as exc:
                plan_errors[scenario['id']] = str(exc)[:300]
        active_plans = {identifier: plan for identifier, plan in plans.items()
                        if _has_live_probe(plan)}
        routes = runtime.validate_ai_routes(effective, endpoints, saved, active_plans, files)
        update('runtime', 35, f'검증된 요청 {len(routes)}개를 선택한 서버에 적용합니다.')
        observations, scope = runtime.observe(folder, target, routes, update)
        if (not isinstance(observations, list) or len(observations) != len(routes)
                or any(not isinstance(row, dict) for row in observations)):
            raise ValueError('운영 관찰 결과가 승인된 요청 목록과 일치하지 않습니다.')
        route_key = lambda row: (row.get('scenario_id'), row.get('probe_label'))
        approved_routes = {route_key(route): route for route in routes}
        if (len(approved_routes) != len(routes)
                or {route_key(row) for row in observations} != set(approved_routes)):
            raise ValueError('운영 관찰의 시나리오·기준/후보 요청이 승인 목록과 다릅니다.')
        for observation in observations:
            route = approved_routes[route_key(observation)]
            if (observation.get('method', 'GET') != route['method']
                    or observation.get('path') != route['path']
                    or observation.get('query_key') != route['query_key']
                    or observation.get('input_location', 'query')
                    != route.get('input_location', 'query')
                    or observation.get('probe_kind') != route['probe_kind']):
                raise ValueError('운영 관찰 결과가 선택한 메서드·경로·입력에 일치하지 않습니다.')
        observed = {}
        for row in observations:
            observed.setdefault(row['scenario_id'], {})[row.get('probe_label') or 'candidate'] = row
        scripts_folder = folder / 'scripts'
        scripts_folder.mkdir(exist_ok=True)
        rows, active_for_combined = [], []
        for scenario in selected:
            identifier = scenario['id']
            plan = plans.get(identifier)
            checked_scenario = {**scenario,
                                'fixture_hints': request_meta.get(identifier, {}).get('fixture_hints', []),
                                'source_context': source_contexts.get(identifier),
                                'input_location': request_meta.get(identifier, {}).get('input_location')}
            captured = observed.get(identifier) or {}
            paired = 'requests' in (plan or {}).get('probe', {}) and _has_live_probe(plan)
            observation = ({'baseline': captured['baseline'], 'candidate': captured['candidate']}
                           if paired and set(captured) == {'baseline', 'candidate'}
                           else captured.get('candidate') if not paired else None)
            if not set(scenario['endpoint_ids']) <= endpoint_ids:
                state, message = 'blocked', '연결된 엔드포인트가 선택에서 제외되었습니다.'
            elif plan is None:
                state, message = 'manual_review', 'AI 점검 계획을 검증하지 못했습니다: ' + plan_errors.get(identifier, '모델 응답 없음')
            elif observation is None:
                state, message = 'manual_review', '자동 요청을 보내지 않았습니다. 생성된 오프라인 점검 코드로 응답을 직접 검토하세요.'
            else:
                state, message = evaluate_observation(plan, checked_scenario, observation)
            script_available = False
            if plan is not None and state != 'blocked':
                try:
                    if observation is not None:
                        script = render_script(target['display_origin'], [checked_scenario], {identifier: plan})
                        active_for_combined.append(checked_scenario)
                    else:
                        script = render_review_script(
                            checked_scenario, plan, source_context=source_contexts[identifier])
                    (scripts_folder / f'{identifier}.py').write_text(script, encoding='utf-8')
                    script_available = True
                except Exception as exc:
                    plan_errors[identifier] = str(exc)[:300]
            candidate_observation = (observation.get('candidate') if paired and observation else observation)
            public_evidence = ({label: _public_observation(value)
                                for label, value in observation.items()}
                               if paired and observation else
                               _public_observation(observation) if observation else None)
            request_probe = ((plan['probe']['requests'][0] if paired else plan['probe'])
                             if observation and plan else None)
            row = {'scenario_id': identifier, 'status': state, 'summary': message,
                   'http_status': candidate_observation.get('status_code') if candidate_observation else None,
                   'request': {'method': scenario['method'], 'path': scenario['path'],
                               'url': target['display_origin'] + scenario['path'],
                               'count': 2 if paired else 1,
                               'input_name': request_probe['query_key'],
                               'input_location': request_probe.get('input_location', 'query')}
                              if observation else None,
                   'evidence': public_evidence,
                   'remediation': scenario['remediation'], 'scenario': scenario,
                   'script_available': script_available,
                   'script_mode': (('live_get' if scenario['method'] == 'GET' else 'live_request')
                                   if observation is not None else 'offline') if script_available else None,
                   'patch': manual_patch('AI 변경안 생성 전입니다.')}
            rows.append(row)
        if active_for_combined:
            combined = render_script(target['display_origin'], active_for_combined,
                                     {scenario['id']: plans[scenario['id']] for scenario in active_for_combined})
        else:
            combined = '# 자동 요청이 허용된 시나리오가 없습니다. 개별 오프라인 점검 스크립트를 사용하세요.\n'
        (folder / 'check.py').write_text(combined, encoding='utf-8')
        available = sum(row['script_available'] for row in rows)
        generation = {'status': 'completed' if available else 'failed', 'model': 'Nemotron',
                      'message': f'AI 점검 스크립트 {available}개 생성, {len(plan_errors)}개 검증 보류.',
                      'errors': plan_errors}
        for index, row in enumerate(rows, 1):
            scenario = row['scenario']
            if row['status'] in {'pass', 'blocked'}:
                row['patch'] = manual_patch('통과 또는 선택 제외 항목에는 코드 변경안을 제시하지 않습니다.')
                continue
            update('generating_patch', 86 + int(10 * index / max(1, len(rows))),
                   f'AI가 원본 소스 기반 조치 diff를 제안합니다 ({index}/{len(rows)}).')
            try:
                payload = prepare_patch_request([scenario], {scenario['id']: row}, files)
                if not payload['scenarios']:
                    row['patch'] = manual_patch('검증 가능한 코드 근거가 없어 정확한 diff를 만들 수 없습니다.')
                    continue
                response = bridge.generate_ai_patches(folder, payload, label=f"patches-{scenario['id']}")
                row['patch'] = validate_patches(response, payload, files).get(
                    scenario['id'], manual_patch('AI 변경안이 누락되었습니다.'))
            except Exception as exc:
                row['patch'] = manual_patch(f'AI 변경안 검증 실패: {str(exc)[:250]}')
        counts = {key: sum(row['status'] == key for row in rows)
                  for key in ['pass', 'fail', 'not_found', 'unavailable', 'inconclusive', 'blocked', 'manual_review']}
        source = {'project_name': source_result['project']['name'], 'framework': source_result['framework'],
                  'analysis_mode': 'ai', 'source_hash': source_result.get('source_hash'),
                  'project_summary': source_result.get('ai', {}).get('project_summary', ''),
                  'endpoints': [{'id': e['id'], 'method': e['method'], 'path': e['path']} for e in endpoints]}
        audit_file = parent / 'dependency-audit.json'
        value = {'id': status['id'], 'analysis_id': status['analysis_id'], 'created_at': status['created_at'],
                 'finished_at': stamp(), 'target_base_url': target['display_origin'], 'selection': saved,
                 'scope': scope, 'results': rows, 'counts': counts, 'source': source,
                 'script_generation': generation,
                 'dependency_audit': read_json(audit_file) if audit_file.exists() else None,
                 'limitations': ['AI가 생성한 시나리오·점검 함수·수정안은 코드 및 제한된 응답의 근거에만 적용됩니다.',
                                 '자동 실행은 소스에 연결된 사용자 선택 메서드·경로에서 기준·후보 응답을 비교합니다. 처리 함수 밖의 간접 부작용까지 증명하지는 못합니다.',
                                 '오프라인 점검 스크립트는 네트워크 요청을 보내지 않으며, 조치 diff는 원본 파일에 적용되지 않습니다.']}
        write_json(folder / 'result.json', value)
        (folder / 'report.md').write_text(runtime_report(value), encoding='utf-8')
        write_json(folder / 'policy.json', scope)
        status.update(state='completed', stage='completed', progress=100, message='AI 운영 점검과 조치 제안을 완료했습니다.',
                      finished_at=stamp(), counts=counts)
        write_json(folder / 'status.json', status)
    except Exception as exc:
        status.update(state='failed', stage='failed', message=str(exc)[:2000], finished_at=stamp())
        write_json(folder / 'status.json', status)
    finally:
        RUNNING.release()


@app.get('/api/jobs/{identifier}/runs/{run_id}')
def run_status(identifier: str, run_id: str):
    folder = run_path(identifier, run_id)
    status = read_status(folder)
    result_path = folder / 'result.json'
    return {**status, **read_json(result_path)} if result_path.exists() else status


@app.get('/api/jobs/{identifier}/runs/{run_id}/download/{kind}')
def run_download(identifier: str, run_id: str, kind: str, scenario_id: str | None = None):
    folder = run_path(identifier, run_id)
    if scenario_id is not None:
        if kind != 'script' or not re.fullmatch(r'[a-f0-9]{16}', scenario_id):
            raise HTTPException(404, '점검 스크립트를 찾을 수 없습니다.')
        result_path = folder / 'result.json'
        if not result_path.exists():
            raise HTTPException(409, '점검 결과가 아직 없습니다.')
        result = read_json(result_path)
        ai_mode = result.get('source', {}).get('analysis_mode') == 'ai'
        selected = next((row for row in result['results']
                         if row['scenario_id'] == scenario_id and row.get('script_available')), None)
        if selected is None:
            raise HTTPException(404, '선택한 시나리오에는 실행 스크립트가 없습니다.')
        filename = f's2r-scenario-{scenario_id}.py'
        path = folder / 'scripts' / f'{scenario_id}.py'
        if path.is_file():
            return FileResponse(path, filename=filename, media_type='text/x-python')
        if ai_mode:
            raise HTTPException(409, 'AI 생성 스크립트 파일이 누락되었습니다.')
        raise HTTPException(404, '과거 점검 기록의 Python 스크립트 파일이 남아 있지 않습니다.')
    names = {'json': ('result.json', 'application/json'), 'report': ('report.md', 'text/markdown'),
             'script': ('check.py', 'text/x-python'), 'policy': ('policy.json', 'application/json')}
    if kind not in names:
        raise HTTPException(404)
    filename, media = names[kind]
    path = folder / filename
    if kind == 'script' and not path.is_file() and (folder / 'result.json').is_file():
        result = read_json(folder / 'result.json')
        if result.get('source', {}).get('analysis_mode') == 'ai':
            raise HTTPException(409, 'AI 생성 스크립트 파일이 누락되었습니다.')
        raise HTTPException(404, '과거 점검 기록의 Python 스크립트 파일이 남아 있지 않습니다.')
    if not path.exists():
        raise HTTPException(409, '점검 결과가 아직 없습니다.')
    if kind == 'script' and (folder / 'result.json').is_file():
        result = read_json(folder / 'result.json')
        if (result.get('source', {}).get('analysis_mode') == 'ai'
                and result.get('script_generation', {}).get('status') != 'completed'):
            raise HTTPException(404, '선택한 시나리오에는 실행 스크립트가 없습니다.')
    return FileResponse(path, filename=f's2r-run-{run_id[:8]}-{filename}', media_type=media)


@app.get('/api/jobs')
def history():
    items = [read_status(path) for path in (DATA / 'jobs').iterdir() if path.is_dir() and (path / 'status.json').exists()]
    return {'items': sorted(items, key=lambda row: row['created_at'], reverse=True)[:100]}


@app.get('/api/jobs/{identifier}')
def job_status(identifier: str):
    return read_status(job_path(identifier))


@app.get('/api/jobs/{identifier}/result')
def result(identifier: str):
    path = job_path(identifier) / 'result.json'
    if not path.exists():
        raise HTTPException(409, '아직 분석 결과가 없습니다.')
    return json.loads(path.read_text(encoding='utf-8'))


@app.get('/api/jobs/{identifier}/source')
def source(identifier: str, file: str):
    folder = job_path(identifier)
    if not (folder / 'bundle.json').exists():
        raise HTTPException(409, '아직 소스 복사본이 없습니다.')
    bundle = json.loads((folder / 'bundle.json').read_text(encoding='utf-8'))
    if file not in bundle['files']:
        raise HTTPException(404, '분석 범위에 포함되지 않은 파일입니다.')
    return {'file': file, 'content': bundle['files'][file], 'source_hash': bundle['source_hash']}


@app.get('/api/jobs/{identifier}/download/{kind}')
def download(identifier: str, kind: str):
    names = {'json': ('result.json', 'application/json'), 'report': ('report.md', 'text/markdown')}
    if kind not in names:
        raise HTTPException(404)
    name, media = names[kind]
    path = job_path(identifier) / name
    if not path.exists():
        raise HTTPException(409, '아직 분석 결과가 없습니다.')
    return FileResponse(path, filename=f's2r-{identifier[:8]}-{name}', media_type=media)


app.mount('/static', StaticFiles(directory=ROOT / 'static'), name='static')
