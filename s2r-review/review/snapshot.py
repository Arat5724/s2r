import hashlib
import json
import os
import stat
from pathlib import Path

IGNORED_DIRS = {'.git', '.svn', '.venv', 'venv', 'node_modules', '__pycache__', '.pytest_cache',
                '.next', 'dist', 'build', 'target', 'coverage', 'runtime', 'logs', '.ssh', '.aws', '.codex'}
EXTENSIONS = {'.py', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.java', '.php', '.xml', '.gradle', '.kts',
              '.json', '.toml', '.yaml', '.yml', '.md', '.txt', '.html', '.css'}
SOURCE_EXTENSIONS = {'.py', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.java', '.php'}
MANIFEST_NAMES = {'requirements.txt', 'requirements.in', 'pyproject.toml', 'package.json',
                  'pom.xml', 'build.gradle', 'build.gradle.kts', 'composer.json'}
SENSITIVE_NAMES = {'accounts.json', 'credentials.json', 'secrets.json', 'settings.xml',
                   'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock', 'composer.lock'}
# Each selected source becomes a separate read-only bind mount. Bound the
# number of mounts so sandbox creation and teardown stay predictable.
MAX_FILES, MAX_FILE_SIZE, MAX_TOTAL = 245, 200_000, 3_000_000


def safe_project(path: str, forbidden: list[Path]) -> Path:
    root = Path(path).resolve(strict=True)
    if not root.is_dir() or root == Path(root.anchor) or root == Path.home():
        raise ValueError('프로젝트 폴더를 선택하세요. 드라이브 전체나 홈 폴더는 허용하지 않습니다.')
    for protected in forbidden:
        protected = protected.resolve()
        if root == protected or root.is_relative_to(protected) or protected.is_relative_to(root):
            raise ValueError('선택한 폴더에 분석 결과·평가 정답·실행 계정 영역이 포함됩니다. 소스 프로젝트만 선택하세요.')
    if not any((root / name).is_file() for name in MANIFEST_NAMES):
        raise ValueError('프로젝트 루트에 지원하는 의존성 파일(requirements, pyproject, package.json, pom.xml, build.gradle, composer.json)이 필요합니다.')
    return root


def is_link(path: Path) -> bool:
    info = path.lstat()
    return path.is_symlink() or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


def read_scoped(path: Path, root: Path) -> bytes:
    """Check the opened file handle, not only a path that could change before open."""
    with path.open('rb') as source:
        if os.fstat(source.fileno()).st_nlink > 1:
            raise ValueError('하드 링크 파일은 제외합니다.')
        if os.name == 'nt':
            import ctypes
            import msvcrt
            from ctypes import wintypes
            get_name = ctypes.windll.kernel32.GetFinalPathNameByHandleW
            get_name.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
            get_name.restype = wintypes.DWORD
            buffer = ctypes.create_unicode_buffer(32768)
            length = get_name(msvcrt.get_osfhandle(source.fileno()), buffer, len(buffer), 0)
            if not 0 < length < len(buffer):
                raise ValueError('열린 파일의 실제 경로를 확인할 수 없습니다.')
            name = buffer.value
            if name.startswith('\\\\?\\UNC\\'):
                name = '\\\\' + name[8:]
            elif name.startswith('\\\\?\\'):
                name = name[4:]
            actual = Path(name).resolve()
        else:
            actual = Path(f'/proc/self/fd/{source.fileno()}').resolve()
        if not actual.is_relative_to(root):
            raise ValueError('파일의 실제 위치가 허용 범위 밖입니다.')
        return source.read(MAX_FILE_SIZE + 1)


def snapshot(root: Path):
    files, skipped, total = {}, [], 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        base = Path(directory)
        dirs[:] = sorted(name for name in dirs if name not in IGNORED_DIRS and not name.startswith('.')
                         and not is_link(base / name))
        for name in sorted(names):
            path = base / name
            relative = path.relative_to(root).as_posix()
            if name.startswith('.') or name.lower() in SENSITIVE_NAMES or path.suffix.lower() not in EXTENSIONS:
                continue
            if any(token in name.lower() for token in ['credential', 'secret', 'private-key', 'access-token']):
                skipped.append({'file': relative, 'reason': '민감 파일명 제외'})
                continue
            if is_link(path) or not path.resolve().is_relative_to(root):
                skipped.append({'file': relative, 'reason': '링크 또는 범위 밖 경로'})
                continue
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
                skipped.append({'file': relative, 'reason': '일반 단일 링크 파일만 허용'})
                continue
            if info.st_size > MAX_FILE_SIZE:
                skipped.append({'file': relative, 'reason': '파일 크기 제한 초과'})
                continue
            # No target module import or shell command; open only in binary read mode.
            try:
                data = read_scoped(path, root)
            except (ValueError, OSError):
                skipped.append({'file': relative, 'reason': '열린 파일의 경계 확인 실패'})
                continue
            if len(data) > MAX_FILE_SIZE:
                skipped.append({'file': relative, 'reason': '파일 크기 변경'})
                continue
            try:
                content = data.decode('utf-8-sig')
            except UnicodeDecodeError:
                skipped.append({'file': relative, 'reason': 'UTF-8 텍스트가 아님'})
                continue
            if '\x00' in content:
                continue
            total += len(data)
            if len(files) >= MAX_FILES or total > MAX_TOTAL:
                raise ValueError(f'첫 버전은 {MAX_FILES}개 파일, 총 3 MB까지 지원합니다. 더 작은 프로젝트를 선택하세요.')
            files[relative] = content
    if not any(Path(name).suffix.lower() in SOURCE_EXTENSIONS for name in files):
        raise ValueError('지원하는 소스 파일(.py, .js, .mjs, .cjs, .ts, .tsx, .jsx, .java, .php)을 찾지 못했습니다.')
    identity = json.dumps(files, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
    return {'files': files, 'source_hash': hashlib.sha256(identity).hexdigest(), 'bytes': total, 'skipped': skipped,
            'hash_scope': '선별된 UTF-8 소스 파일의 경로와 내용'}
