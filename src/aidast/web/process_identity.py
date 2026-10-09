"""Read the process identity used before signaling isolated web workers."""

from __future__ import annotations

import ctypes
import errno
import importlib
import os
import sys
import time
from pathlib import Path


def _windows_host() -> bool:
    return os.name == "nt"


def _psutil():
    return importlib.import_module("psutil")


def process_stat(pid: int) -> tuple[str, str]:
    """Return a zombie indicator and a PID-reuse-resistant start identifier."""
    if _windows_host():
        psutil = _psutil()
        try:
            process = psutil.Process(pid)
            started = repr(process.create_time())
            running = process.is_running()
        except psutil.Error as exc:
            raise OSError("cannot read process status") from exc
        return ("R" if running else "Z", started)
    if sys.platform == "darwin":
        info = _darwin_bsd_info(pid)
        return ("Z" if info.status == 5 else "R", f"{info.start_sec}:{info.start_usec}")
    fields = Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()
    return fields[0], fields[19]


def process_cwd(pid: int) -> Path:
    if _windows_host():
        psutil = _psutil()
        try:
            directory = psutil.Process(pid).cwd()
        except psutil.Error as exc:
            raise OSError("cannot read process cwd") from exc
        if not directory:
            raise OSError("process cwd is unavailable")
        return Path(directory).resolve()
    if sys.platform == "darwin":
        libproc = _libproc()
        info = _VnodePathInfo()
        size = ctypes.sizeof(info)
        if libproc.proc_pidinfo(pid, 9, 0, ctypes.byref(info), size) != size:
            raise OSError(ctypes.get_errno(), "cannot read process cwd")
        path = bytes(info.cwd.path).split(b"\0", 1)[0]
        if not path:
            raise OSError("process cwd is unavailable")
        return Path(os.fsdecode(path)).resolve()
    return Path(os.readlink(f"/proc/{pid}/cwd")).resolve()


def process_args(pid: int) -> list[str]:
    if _windows_host():
        psutil = _psutil()
        try:
            return psutil.Process(pid).cmdline()
        except psutil.Error as exc:
            raise OSError("cannot read process arguments") from exc
    if sys.platform == "darwin":
        for attempt in range(3):
            try:
                return _darwin_args(pid)
            except OSError as exc:
                if exc.errno not in {errno.EIO, errno.ENOMEM} or attempt == 2:
                    raise
                time.sleep(0.002)
    return [
        os.fsdecode(value)
        for value in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        if value
    ]


def _darwin_args(pid: int) -> list[str]:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.sysctl.argtypes = [
        ctypes.POINTER(ctypes.c_int), ctypes.c_uint, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t,
    ]
    libc.sysctl.restype = ctypes.c_int
    mib = (ctypes.c_int * 3)(1, 49, pid)  # CTL_KERN, KERN_PROCARGS2, pid
    size = ctypes.c_size_t()
    if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0:
        raise OSError(ctypes.get_errno(), "cannot size process arguments")
    data = ctypes.create_string_buffer(size.value)
    if libc.sysctl(mib, 3, data, ctypes.byref(size), None, 0) != 0:
        raise OSError(ctypes.get_errno(), "cannot read process arguments")
    raw = data.raw[:size.value]
    if len(raw) < 4:
        raise OSError("process arguments are incomplete")
    argc = int.from_bytes(raw[:4], sys.byteorder, signed=True)
    if argc < 1:
        raise OSError("process arguments are empty")
    cursor = raw.find(b"\0", 4)
    if cursor < 0:
        raise OSError("process executable path is incomplete")
    while cursor < len(raw) and raw[cursor] == 0:
        cursor += 1
    args: list[str] = []
    for _ in range(argc):
        end = raw.find(b"\0", cursor)
        if end < 0:
            raise OSError("process arguments are incomplete")
        args.append(os.fsdecode(raw[cursor:end]))
        cursor = end + 1
    return args


class _BsdInfo(ctypes.Structure):
    # Darwin's proc_bsdinfo from <sys/proc_info.h> (MAXCOMLEN = 16).
    _fields_ = [
        ("flags", ctypes.c_uint32), ("status", ctypes.c_uint32),
        ("xstatus", ctypes.c_uint32), ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32), ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32), ("ruid", ctypes.c_uint32),
        ("rgid", ctypes.c_uint32), ("svuid", ctypes.c_uint32),
        ("svgid", ctypes.c_uint32), ("reserved", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32),
        ("nfiles", ctypes.c_uint32), ("pgid", ctypes.c_uint32),
        ("pjobc", ctypes.c_uint32), ("tdev", ctypes.c_uint32),
        ("tpgid", ctypes.c_uint32), ("nice", ctypes.c_int32),
        ("start_sec", ctypes.c_uint64), ("start_usec", ctypes.c_uint64),
    ]


class _VnodeInfoPath(ctypes.Structure):
    # The vnode_info metadata precedes MAXPATHLEN (1024) bytes of path.
    _fields_ = [("metadata", ctypes.c_byte * 152), ("path", ctypes.c_char * 1024)]


class _VnodePathInfo(ctypes.Structure):
    _fields_ = [("cwd", _VnodeInfoPath), ("root", _VnodeInfoPath)]


def _libproc() -> ctypes.CDLL:
    libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    libproc.proc_pidinfo.argtypes = [
        ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p,
        ctypes.c_int,
    ]
    libproc.proc_pidinfo.restype = ctypes.c_int
    return libproc


def _darwin_bsd_info(pid: int) -> _BsdInfo:
    info = _BsdInfo()
    size = ctypes.sizeof(info)
    if _libproc().proc_pidinfo(pid, 3, 0, ctypes.byref(info), size) != size:
        raise OSError(ctypes.get_errno(), "cannot read process status")
    if info.pid != pid:
        raise OSError("process identifier changed")
    return info
