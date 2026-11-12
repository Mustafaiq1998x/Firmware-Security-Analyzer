"""Run dashboard analysis in a disposable child process."""
import asyncio
import ctypes
import json
import multiprocessing
import os
from pathlib import Path
import sys
import time

from .analyzer import scan_file
from .extraction import safe_extract_archive
from .unpack import unpack_image
from .hikvision import FORMAT as SWKH_FORMAT

MEMORY_BYTES = 768 * 1024 * 1024
MAX_SECONDS = 120


def _limit_windows_memory():
    from ctypes import wintypes as w

    class Basic(ctypes.Structure):
        _fields_ = [
            ("ProcessTime", ctypes.c_int64), ("JobTime", ctypes.c_int64),
            ("LimitFlags", w.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", w.DWORD),
            ("Affinity", ctypes.c_size_t), ("PriorityClass", w.DWORD),
            ("SchedulingClass", w.DWORD),
        ]

    class Extended(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", Basic), ("IoInfo", ctypes.c_uint64 * 6),
            ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [w.LPVOID, w.LPCWSTR]
    kernel.CreateJobObjectW.restype = w.HANDLE
    kernel.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD]
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    limits = Extended()
    limits.BasicLimitInformation.LimitFlags = 0x100  # JOB_OBJECT_LIMIT_PROCESS_MEMORY
    limits.ProcessMemoryLimit = MEMORY_BYTES
    if not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not kernel.AssignProcessToJobObject(job, kernel.GetCurrentProcess()):
        raise ctypes.WinError(ctypes.get_last_error())
    # The child retains the job handle until it exits.


def _analyze(source, workspace, max_bytes, inspect_archive, feed=None, desktop=False):
    output = Path(workspace) / "result.json"
    try:
        if os.name == "nt":
            _limit_windows_memory()
        elif sys.platform.startswith("linux"):
            import resource
            _, hard = resource.getrlimit(resource.RLIMIT_AS)
            cap = MEMORY_BYTES if hard == resource.RLIM_INFINITY else min(hard, MEMORY_BYTES)
            resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
        elif inspect_archive or desktop:
            raise ValueError("Archive inspection with a memory limit requires Linux or Windows")
        report = scan_file(source, cve_feed=feed, max_file_size=max_bytes)
        profile = report["analysis"]["firmware_profile"]
        supported = profile["outer_format"] in {"ZIP", "ZIP header marker", "TAR"} or profile["components"]
        if inspect_archive or (desktop and supported):
            try:
                unpacked = Path(workspace) / "files"
                if desktop:
                    report["archive_inspection"] = unpack_image(source, unpacked, report)
                else:
                    report["archive_inspection"] = safe_extract_archive(source, unpacked)
                manifest = report["archive_inspection"]
                members = [e for e in manifest.get("entries", []) if e["status"] == "extracted"]
                if (manifest["format"] == "zip" and len(members) == 1 and
                        Path(members[0]["path"]).suffix.lower() == ".dav"):
                    member = members[0]
                    inner = scan_file(unpacked / member["path"], cve_feed=feed, max_file_size=max_bytes)
                    if inner["analysis"]["firmware_profile"]["outer_format"] == SWKH_FORMAT:
                        report["packaged_firmware"] = {
                            "path": member["path"], "sha256": inner["input"]["sha256"],
                            "firmware_profile": inner["analysis"]["firmware_profile"],
                            "kernel_versions": inner["analysis"]["kernel_versions"],
                            "cve_assessment": inner["analysis"]["cve_assessment"],
                            "cve_matches": inner["analysis"]["cve_matches"],
                        }
            except (ValueError, OSError) as exc:
                report["archive_inspection"] = {"status": "rejected", "reason": str(exc)}
        output.write_text(json.dumps(report), encoding="utf-8")
    except (OSError, ValueError, MemoryError) as exc:
        (Path(workspace) / "error.txt").write_text(str(exc) or "Worker memory limit reached", encoding="utf-8")


async def inspect_upload(source, workspace, max_bytes, inspect_archive, disconnected):
    process = multiprocessing.get_context("spawn").Process(
        target=_analyze, args=(source, workspace, max_bytes, inspect_archive)
    )
    deadline = time.monotonic() + MAX_SECONDS
    process.start()
    try:
        while process.is_alive():
            if time.monotonic() >= deadline:
                raise TimeoutError("The analysis exceeded its time limit")
            if await disconnected():
                raise ValueError("Analysis cancelled")
            await asyncio.sleep(0.1)
        error = workspace / "error.txt"
        if error.exists():
            raise ValueError(error.read_text(encoding="utf-8"))
        if process.exitcode:
            raise ValueError("Analysis worker terminated")
        return json.loads((workspace / "result.json").read_text(encoding="utf-8"))
    finally:
        if process.is_alive():
            process.kill()
        process.join()
        process.close()
