# Firmware Security Analyzer (FSA)

A defensive, cross-platform static-analysis toolkit for firmware images and
firmware filesystems. FSA performs **offline, non-exploitative triage** and
produces JSON/HTML reports. It is intended for firmware you own or are
explicitly authorized to assess.

> **Important:** Findings are indicators for human review, not proof of
> exploitability. A kernel version string alone does not establish that a CVE
> affects a device. FSA does not execute firmware, attempt logins, exploit
> vulnerabilities, or modify input files.

## Features in v0.1.2

- SHA-256 and file metadata.
- Identification of common embedded signatures (SquashFS, CramFS, JFFS2,
  U-Boot uImage, ELF, gzip, XZ, ZIP, and device-tree blobs).
- Printable-string extraction and conservative indicators for possible
  hard-coded credentials, private-key material, debug services, and weak
  cryptographic references.
- Entropy sampling to help locate compressed/encrypted regions.
- Heuristic Linux kernel version extraction.
- Offline CVE-feed matching against an explicitly supplied JSON file.
- JSON and self-contained HTML reports.
- CLI on Windows, Linux, and macOS; optional FastAPI browser dashboard/API.
- Responsive bilingual Arabic/English browser dashboard with RTL/LTR switching, drag-and-drop upload, scan summary, entropy chart, signature offsets, heuristic evidence, kernel versions, CVE-feed matches, and JSON export.

## Safety and scope

Only analyze firmware images you own or have permission to inspect. Treat
firmware and extracted strings as untrusted data. FSA reads the input as bytes
and does not execute it. Do not treat a heuristic alert as a confirmed
vulnerability. Validate findings against vendor advisories, affected
configuration, backported patches, and the exact device build.

## Quick start

Python 3.10+ is required.

### Linux / macOS
```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev,web]"
pytest
fsa scan samples/demo_firmware.bin --out reports/demo.json --html reports/demo.html
```

### Windows PowerShell
```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,web]"
pytest
fsa scan samples/demo_firmware.bin --out reports/demo.json --html reports/demo.html
```

A small synthetic sample is provided for testing. It is **not** real vendor
firmware and contains no real credentials.

## CLI

```text
fsa scan IMAGE [--out report.json] [--html report.html] [--max-strings 20000] [--max-file-size-mib 512]
fsa info IMAGE
fsa serve [--host 127.0.0.1] [--port 8000]
```

The optional web service exposes:
- `GET /` responsive Arabic/English dashboard for local browser-based scanning (English LTR by default, Arabic RTL via the language switch).
- `GET /health` service health and version.
- `POST /scan` multipart firmware upload; returns a JSON report.
- `GET /docs` interactive API documentation.

Start the dashboard with `fsa serve` and open `http://127.0.0.1:8000`. The web extra includes `python-multipart`, required for secure multipart upload handling. The dashboard runs locally and does not require a third-party frontend service.

Keep the service bound to `127.0.0.1` unless you have a deliberate, secured
deployment plan. The API has no authentication in this initial release. API uploads are limited to 128 MiB; CLI scans default to a 512 MiB limit, configurable with `--max-file-size-mib`. Reports cannot overwrite the input image through the CLI.

## Offline CVE feed format

FSA does not silently query external services. Supply a locally downloaded,
reviewed JSON file with this shape:

```json
{
  "items": [
    {
      "cve": "CVE-2024-0001",
      "component": "linux",
      "version_start": "4.0",
      "version_end": "4.9.999",
      "summary": "Example record; replace with verified advisory data"
    }
  ]
}
```

The simple range matcher is lexical/numeric best-effort and is not a substitute
for vendor-specific version comparison. Real NVD feeds use a more complex
schema; normalize and verify records before importing them. A match is labelled
`needs_manual_validation`.

## Architecture

```text
src/fsa/
  analyzer.py     scan orchestration
  signatures.py   magic-byte identification
  heuristics.py   conservative text indicators
  entropy.py      entropy sampling
  cve.py          offline advisory matching
  reporting.py    JSON and HTML output
  cli.py          command-line interface
  webapp.py       optional local API
tests/            automated tests
docs/             methodology, validation, roadmap
```

## Current limitations

- No full filesystem extraction in v0.1. Extraction of untrusted archives can
  create path traversal, resource exhaustion, and parser risks. This version
  deliberately avoids automatic extraction.
- No full ELF dependency analysis or architecture-specific disassembly yet.
- Secret detection is heuristic and may produce false positives.
- CVE matching requires a curated local feed and manual confirmation.
- No claim of complete firmware coverage.

## Development

See [CHANGELOG.md](CHANGELOG.md) for release history, [docs/GUI.md](docs/GUI.md) for dashboard usage, and [docs/PHASE1_AUDIT.md](docs/PHASE1_AUDIT.md) for the v0.1.0 stabilization audit.

```bash
python -m pip install -e ".[dev,web]"
pytest -q
```

Please submit reproducible bug reports with a synthetic sample whenever
possible. Never publish real secrets, private firmware, or unredacted sensitive
device data.
