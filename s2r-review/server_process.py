"""Windows process management shared with the WSL/Git Bash launchers.

The application host uses wsl.exe and Windows drive paths, so this helper must
run under Windows Python even when the calling shell is Bash in WSL.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parent
DATA = ROOT.parent / 's2r-review-data'
RECORD = DATA / 'server-process.json'
SCRIPT = ROOT / 'run.py'
PORT = 8020
WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


class FILETIME(ctypes.Structure):
    _fields_ = [('low', wintypes.DWORD), ('high', wintypes.DWORD)]


def _kernel32():
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(FILETIME)] * 4
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetExitCodeProcess.restype = wintypes.BOOL
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                  ctypes.POINTER(wintypes.DWORD)]
    kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.TerminateProcess.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    return kernel


def _open_process(pid: int, *, terminate: bool = False):
    kernel = _kernel32()
    # SYNCHRONIZE permits waiting for a terminated process before returning.
    access = 0x1000 | (0x0001 | 0x00100000 if terminate else 0)
    handle = kernel.OpenProcess(access, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        if error == 87:  # ERROR_INVALID_PARAMETER: no such PID
            return kernel, None
        raise OSError(error, f'Cannot inspect process {pid}; no process was stopped.')
    exit_code = wintypes.DWORD()
    if not kernel.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
        error = ctypes.get_last_error()
        kernel.CloseHandle(handle)
        raise OSError(error, f'Cannot inspect process {pid}; no process was stopped.')
    if exit_code.value != 259:  # STILL_ACTIVE
        kernel.CloseHandle(handle)
        return kernel, None
    return kernel, handle


def _identity(kernel, handle) -> tuple[int, str]:
    times = [FILETIME() for _ in range(4)]
    if not kernel.GetProcessTimes(handle, *(ctypes.byref(item) for item in times)):
        raise ctypes.WinError(ctypes.get_last_error())
    created = (times[0].high << 32) | times[0].low
    path = ctypes.create_unicode_buffer(32768)
    length = wintypes.DWORD(len(path))
    if not kernel.QueryFullProcessImageNameW(handle, 0, path, ctypes.byref(length)):
        raise ctypes.WinError(ctypes.get_last_error())
    return created, path.value


def _inspect(pid: int) -> tuple[int, str] | None:
    kernel, handle = _open_process(pid)
    if handle is None:
        return None
    try:
        return _identity(kernel, handle)
    finally:
        kernel.CloseHandle(handle)


def _time_iso(filetime: int) -> str:
    # CIM/Win32_Process CreationDate is microsecond precision; retain its
    # seven-digit .NET representation for compatibility with stop.ps1.
    stamp = WINDOWS_EPOCH + timedelta(microseconds=filetime // 10)
    return stamp.strftime('%Y-%m-%dT%H:%M:%S.%f0Z')


def _time_micros(value: str) -> int:
    stamp = datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc)
    delta = stamp - WINDOWS_EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.normpath(left)) == os.path.normcase(os.path.normpath(right))


def _command_executable(command: str) -> str:
    command = command.lstrip()
    if command.startswith('"'):
        return command.split('"', 2)[1]
    return command.split(maxsplit=1)[0]


def _record_matches(record: dict, identity: tuple[int, str]) -> bool:
    try:
        created, executable = identity
        command = record['command_line']
        if not _same_path(record['script'], str(SCRIPT)) or str(SCRIPT).lower() not in command.lower():
            return False
        if not _same_path(_command_executable(command), executable):
            return False
        if 'executable' in record and not _same_path(record['executable'], executable):
            return False
        if 'created_filetime' in record and int(record['created_filetime']) != created:
            return False
        return _time_micros(record['created_at']) == created // 10
    except (KeyError, TypeError, ValueError, IndexError):
        return False


def _listener_pid(port: int, *, exact_loopback: bool = False) -> int | None:
    output = subprocess.run(['netstat', '-ano', '-p', 'tcp'], check=True, capture_output=True,
                            text=True, errors='replace').stdout
    addresses = {f'127.0.0.1:{port}'} if exact_loopback else {f'127.0.0.1:{port}', f'0.0.0.0:{port}'}
    for line in output.splitlines():
        columns = line.split()
        if (len(columns) >= 5 and columns[0].upper() == 'TCP' and columns[1] in addresses
                and columns[3].upper() == 'LISTENING' and columns[4].isdecimal()):
            return int(columns[4])
    return None


def start(python_path: Path) -> None:
    python_path = python_path.resolve(strict=True)
    if _listener_pid(PORT) is not None:
        raise RuntimeError('Port 8020 is already in use. Open http://127.0.0.1:8020 or inspect the existing process.')
    DATA.mkdir(parents=True, exist_ok=True)
    args = [str(python_path), '-B', str(SCRIPT)]
    with (DATA / 'server.out.log').open('wb') as stdout, (DATA / 'server.err.log').open('wb') as stderr:
        process = subprocess.Popen(args, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                   creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
    try:
        for _ in range(40):
            time.sleep(0.25)
            owner = _listener_pid(PORT, exact_loopback=True)
            if owner == process.pid and process.poll() is None:
                break
            if owner is not None or process.poll() is not None:
                raise RuntimeError('Startup failed. Inspect s2r-review-data/server.err.log.')
        else:
            raise RuntimeError('Startup failed. Inspect s2r-review-data/server.err.log.')
        identity = _inspect(process.pid)
        if identity is None:
            raise RuntimeError('Started process exited before its identity could be recorded.')
        created, executable = identity
        record = {
            'pid': process.pid,
            'created_at': _time_iso(created),
            'created_filetime': created,
            'command_line': subprocess.list2cmdline(args),
            'script': str(SCRIPT),
            'executable': executable,
        }
        temporary = RECORD.with_suffix('.json.tmp')
        temporary.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding='utf-8')
        os.replace(temporary, RECORD)
    except BaseException:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        raise
    print('S2R Review is ready: http://127.0.0.1:8020')


def stop(*, verify_only: bool = False) -> None:
    if not RECORD.exists():
        raise RuntimeError('No process record exists. No process was stopped.')
    record = json.loads(RECORD.read_text(encoding='utf-8-sig'))
    pid = int(record['pid'])
    kernel, handle = _open_process(pid, terminate=not verify_only)
    if handle is None:
        print('S2R Review is already stopped.')
        return
    try:
        if not _record_matches(record, _identity(kernel, handle)):
            raise RuntimeError('Process identity does not match the saved record. No process was stopped.')
        if verify_only:
            print('Saved S2R Review process identity matches the running process.')
            return
        if not kernel.TerminateProcess(handle, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        if kernel.WaitForSingleObject(handle, 5000) != 0:  # WAIT_OBJECT_0
            raise RuntimeError('Process termination did not complete within five seconds.')
    finally:
        kernel.CloseHandle(handle)
    print('S2R Review stopped. Saved analyses and the OpenShell worker are preserved.')


def main() -> None:
    parser = argparse.ArgumentParser(description='Windows host process helper for Bash launchers')
    actions = parser.add_subparsers(dest='action', required=True)
    actions.add_parser('start').add_argument('--python', required=True, type=Path)
    actions.add_parser('stop')
    actions.add_parser('verify', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('S2R Review host requires Windows Python; invoke start.sh/stop.sh from WSL or Git Bash.')
    try:
        if args.action == 'start':
            start(args.python)
        else:
            stop(verify_only=args.action == 'verify')
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        parser.exit(1, f'{exc}\n')


if __name__ == '__main__':
    main()
