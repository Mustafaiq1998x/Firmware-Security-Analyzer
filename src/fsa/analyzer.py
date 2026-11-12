"""Read-only, memory-mapped firmware image analyzer."""
from __future__ import annotations

import hashlib
import mmap
import os
import tarfile
from pathlib import Path

from .cve import load_feed, match_kernel_cves
from .entropy import sample_entropy
from .heuristics import extract_strings, find_kernel_versions, inspect_strings
from .signatures import identify_signatures

DEFAULT_MAX_FILE_SIZE = 512 * 1024 * 1024


def _analyze_buffer(data, *, name: str, size: int, max_strings: int,
                    cve_feed: str | None) -> dict:
    """Analyze a bytes-like object; callers keep its backing store read-only."""
    strings = extract_strings(data, limit=max_strings)
    versions = find_kernel_versions(strings)
    report = {
        "tool": "Firmware Security Analyzer",
        "version": "0.1.2",
        "input": {
            "name": name,
            "size_bytes": size,
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "analysis": {
            "signatures": identify_signatures(data),
            "entropy_samples": sample_entropy(data),
            "printable_strings_count": len(strings),
            "kernel_versions": versions,
            "heuristic_findings": inspect_strings(strings),
            "cve_matches": [],
        },
        "limitations": [
            "Static triage only; findings require manual validation.",
            "A version string does not prove a CVE is applicable.",
            "No firmware execution or automatic filesystem extraction is performed.",
            "Signature matches are byte-pattern indicators, not validated filesystem or container parses.",
        ],
    }
    # GNU and POSIX TAR store their magic inside the first 512-byte header.
    if size >= 512 and data[257:262] == b"ustar":
        try:
            tarfile.TarInfo.frombuf(data[:512], "utf-8", "surrogateescape")
        except tarfile.HeaderError:
            pass
        else:
            report["analysis"]["container_header"] = {
                "format": "TAR", "offset": 0, "validated": "first header checksum"
            }
    if cve_feed:
        report["analysis"]["cve_matches"] = match_kernel_cves(versions, load_feed(cve_feed))
    return report


def scan_file(
    path: str | Path,
    max_strings: int = 20000,
    cve_feed: str | None = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> dict:
    """Scan a firmware image read-only using mmap to avoid a full RAM copy.

    String extraction is separately bounded by count and per-string length.
    Empty files are handled without attempting to create a zero-length mapping.
    """
    if max_file_size <= 0:
        raise ValueError("max_file_size must be positive")
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(source)

    with source.open("rb") as handle:
        size = os.fstat(handle.fileno()).st_size
        if size > max_file_size:
            raise ValueError(f"Input exceeds configured size limit ({max_file_size} bytes)")
        if size == 0:
            return _analyze_buffer(b"", name=source.name, size=0,
                                   max_strings=max_strings, cve_feed=cve_feed)
        # mmap is read-only: analysis functions can scan the buffer without
        # copying the entire firmware image into Python-managed memory.
        with mmap.mmap(handle.fileno(), length=0, access=mmap.ACCESS_READ) as data:
            mapped_size = len(data)
            if mapped_size > max_file_size:
                raise ValueError(f"Input exceeds configured size limit ({max_file_size} bytes)")
            return _analyze_buffer(data, name=source.name, size=mapped_size,
                                   max_strings=max_strings, cve_feed=cve_feed)
