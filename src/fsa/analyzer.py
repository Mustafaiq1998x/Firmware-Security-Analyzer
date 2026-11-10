"""Read-only firmware image analyzer."""
from __future__ import annotations

import hashlib
from pathlib import Path

from .cve import load_feed, match_kernel_cves
from .entropy import sample_entropy
from .heuristics import extract_strings, find_kernel_versions, inspect_strings
from .signatures import identify_signatures

DEFAULT_MAX_FILE_SIZE = 512 * 1024 * 1024


def scan_file(
    path: str | Path,
    max_strings: int = 20000,
    cve_feed: str | None = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> dict:
    if max_file_size <= 0:
        raise ValueError("max_file_size must be positive")
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(source)
    size = source.stat().st_size
    if size > max_file_size:
        raise ValueError(f"Input exceeds configured size limit ({max_file_size} bytes)")
    # Read at most limit + 1 to handle a file growing after stat().
    with source.open("rb") as handle:
        data = handle.read(max_file_size + 1)
    if len(data) > max_file_size:
        raise ValueError(f"Input exceeds configured size limit ({max_file_size} bytes)")

    strings = extract_strings(data, limit=max_strings)
    versions = find_kernel_versions(strings)
    report = {
        "tool": "Firmware Security Analyzer",
        "version": "0.1.0",
        "input": {
            "name": source.name,
            "size_bytes": len(data),
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
        ],
    }
    if cve_feed:
        report["analysis"]["cve_matches"] = match_kernel_cves(versions, load_feed(cve_feed))
    return report
