"""Read original files through individually mounted OpenShell /source slots.

The JSON manifest pairs sorted project-relative names with flat mount slots.
The model receives content read from those slots under the original names.
On Linux each path is opened relative to a descriptor with O_NOFOLLOW.
"""

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from pathlib import PurePosixPath


MAX_FILES = 245
MAX_FILE_SIZE = 200_000
MAX_TOTAL = 3_000_000


def relative_source_path(value):
    """Accept only the canonical relative POSIX paths produced by snapshot()."""
    if (not isinstance(value, str) or not value or '\\' in value or '\x00' in value
            or ':' in value or value.startswith('/') or value.endswith('/')):
        raise ValueError('Invalid source path')
    parts = value.split('/')
    if any(part in ('', '.', '..') for part in parts) or PurePosixPath(value).as_posix() != value:
        raise ValueError('Invalid source path')
    return parts


def _read_posix(root: Path, parts: list[str]) -> bytes:
    # O_PATH traverses approved leaves without requesting READ_DIR on parents.
    directory_flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    handles = []
    try:
        handles.append(os.open(root, directory_flags))
        for part in parts[:-1]:
            handles.append(os.open(part, directory_flags, dir_fd=handles[-1]))
        file_fd = os.open(parts[-1], file_flags, dir_fd=handles[-1])
        handles.append(file_fd)
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError('Source must be a regular single-link file')
        if before.st_size > MAX_FILE_SIZE:
            raise ValueError('Source file is too large')
        with os.fdopen(os.dup(file_fd), 'rb') as stream:
            data = stream.read(MAX_FILE_SIZE + 1)
        after = os.fstat(file_fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                         after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('Source changed while being read')
        if len(data) > MAX_FILE_SIZE or len(data) != after.st_size:
            raise ValueError('Source file size changed')
        return data
    finally:
        for handle in reversed(handles):
            os.close(handle)


def _read_windows(root: Path, parts: list[str]) -> bytes:
    """Local-test equivalent; the deployed worker always uses _read_posix."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    base = root.resolve(strict=True)
    current = base
    for part in parts:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('Source link is not allowed')
    fd = os.open(current, os.O_RDONLY | os.O_BINARY)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError('Source must be a regular single-link file')
        if before.st_size > MAX_FILE_SIZE:
            raise ValueError('Source file is too large')
        get_name = ctypes.windll.kernel32.GetFinalPathNameByHandleW
        get_name.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
        get_name.restype = wintypes.DWORD
        buffer = ctypes.create_unicode_buffer(32768)
        length = get_name(msvcrt.get_osfhandle(fd), buffer, len(buffer), 0)
        if not 0 < length < len(buffer):
            raise ValueError('Cannot verify opened source path')
        actual = buffer.value
        if actual.startswith('\\\\?\\UNC\\'):
            actual = '\\\\' + actual[8:]
        elif actual.startswith('\\\\?\\'):
            actual = actual[4:]
        if not Path(actual).resolve().is_relative_to(base):
            raise ValueError('Opened source is outside mount')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            data = stream.read(MAX_FILE_SIZE + 1)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                         after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('Source changed while being read')
        if len(data) > MAX_FILE_SIZE or len(data) != after.st_size:
            raise ValueError('Source file size changed')
        return data
    finally:
        os.close(fd)


def read_source_bytes(root: Path, path: str) -> bytes:
    parts = relative_source_path(path)
    if os.name == 'nt':
        return _read_windows(root, parts)
    return _read_posix(root, parts)


def read_mounted_files(bundle: dict, source_root: Path = Path('/source')) -> dict[str, str]:
    if (not isinstance(bundle, dict) or bundle.get('kind') != 'mounted_source_manifest'
            or not isinstance(bundle.get('files'), list)):
        raise ValueError('Mounted source manifest is required')
    names = bundle['files']
    source_hash = bundle.get('source_hash')
    if not isinstance(source_hash, str) or not re.fullmatch(r'[a-f0-9]{64}', source_hash):
        raise ValueError('Mounted source manifest needs a SHA-256 hash')
    if not 1 <= len(names) <= MAX_FILES:
        raise ValueError('Source file count is outside limit')
    for path in names:
        relative_source_path(path)
    if names != sorted(set(names)):
        raise ValueError('Source paths must be sorted and unique')
    mounted = {}
    total = 0
    for index, path in enumerate(names):
        data = read_source_bytes(source_root, f'{index:04d}')
        total += len(data)
        if total > MAX_TOTAL:
            raise ValueError('Source total size is outside limit')
        try:
            content = data.decode('utf-8-sig')
        except UnicodeDecodeError as exc:
            raise ValueError('Mounted source is not UTF-8 text') from exc
        if '\x00' in content:
            raise ValueError('Mounted source contains NUL')
        mounted[path] = content
    identity = json.dumps(mounted, sort_keys=True, ensure_ascii=False,
                          separators=(',', ':')).encode('utf-8')
    if source_hash != hashlib.sha256(identity).hexdigest():
        raise ValueError('Source bundle SHA-256 mismatch')
    return mounted
