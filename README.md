# Firmware Security Analyzer (FSA)

A defensive, cross-platform static-analysis toolkit for firmware images and
firmware archives. FSA performs **offline, non-exploitative triage** and
produces JSON/HTML reports. It is intended for firmware you own or are
explicitly authorized to assess.

> **Important:** Findings are indicators for human review, not proof of
> exploitability. A kernel version string alone does not establish that a CVE
> affects a device. FSA does not execute firmware, attempt logins, exploit
> vulnerabilities, or modify input files.

## Current features

- SHA-256 and file metadata; read-only memory-mapped scanning avoids a full in-memory copy of the input image.
- Identification of common embedded signatures (SquashFS, CramFS, JFFS2,
  U-Boot uImage, ELF, gzip, XZ, ZIP, UBI/UBIFS, Android boot/sparse, Zstandard,
  LZ4, bzip2, CPIO, OpenWrt TRX, and device-tree/FIT markers).
- Printable-string extraction and conservative indicators for possible
  hard-coded credentials, private-key material, debug services, and weak
  cryptographic references.
- Entropy sampling distributed across the complete image to help locate compressed/encrypted regions.
- Heuristic Linux kernel version extraction.
- Offline CVE-feed matching against an explicitly supplied JSON file.
- **Bounded ZIP and TAR extraction** with preflight limits on ZIP central-directory
  metadata, component-level path collision detection, link/special-file rejection,
  byte/file/depth/time limits, per-file SHA-256, and cleanup after failed extraction.
- JSON and self-contained HTML reports.
- CLI on Windows, Linux, and macOS; optional FastAPI browser dashboard/API.
- Responsive bilingual Arabic/English browser dashboard with RTL/LTR switching,
  drag-and-drop upload, scan summary, entropy chart, signature offsets,
  heuristic evidence, kernel versions, CVE-feed matches, and JSON export.

## Safety and scope

Only analyze firmware images you own or have permission to inspect. Treat
firmware, archive metadata, and extracted strings as untrusted data. FSA does
not execute extracted files. Archive extraction is limited to ZIP and TAR;
firmware filesystem formats such as SquashFS, CramFS, JFFS2, and UBIFS require
separate dedicated parsers and are not extracted by this feature. Do not treat
a heuristic alert as a confirmed vulnerability. Validate findings against
vendor advisories, affected configuration, backported patches, and the exact
device build.

## Quick start

Python 3.10+ is required.

### Linux / macOS
```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev,web]"
pytest
fsa scan samples/demo_firmware.bin --out reports/demo.json --html reports/demo.html
fsa extract firmware-rootfs.tar.gz --outdir ./extracted --report ./extraction.json
```

### Windows PowerShell
```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,web]"
pytest
fsa scan samples/demo_firmware.bin --out reports/demo.json --html reports/demo.html
fsa extract firmware-rootfs.tar.gz --outdir .\extracted --report .\extraction.json
```

A small synthetic sample is provided for testing. It is **not** real vendor
firmware and contains no real credentials.

### Android / Termux

The core CLI and tests do not require the optional web or lint dependencies.
On Termux, use `python -m pip install -e ".[dev]"` and run
`python -m pytest -q --ignore=tests/test_webapp.py`. Do not install `web` or
`lint` extras in Termux unless their native dependencies are available for
your Python/Android build. Full web and lint checks run in the Linux/Windows CI matrix.

## CLI

```text
fsa scan IMAGE [--out report.json] [--html report.html] [--max-strings 20000] [--max-file-size-mib 512]
fsa extract ARCHIVE --outdir DIRECTORY [--report report.json] [--max-archive-mib 64] [--max-central-directory-mib 16] [--max-total-mib 512] [--max-file-mib 128] [--max-files 20000] [--max-directories 10000] [--max-depth 64] [--max-ratio 200] [--max-seconds 120]
fsa info IMAGE
fsa serve [--host 127.0.0.1] [--port 8000]
```

The extraction destination must be a new or empty directory. The extractor preflights ZIP central-directory size and entry count before
loading entry metadata. It rejects absolute/traversal paths, Windows drive and
UNC paths, reserved or ambiguous Windows names, component-level case
collisions, links, special files, and sparse TAR entries. Limits are enforced
while actual bytes are copied.
Nested archives are not recursively extracted. See [docs/EXTRACTION.md](docs/EXTRACTION.md)
for the threat model and detailed limits.

The optional web service exposes:
- `GET /` responsive Arabic/English dashboard for local browser-based scanning.
- `GET /health` service health and version.
- `POST /scan` multipart firmware upload; returns a JSON report.
- `GET /docs` interactive API documentation.

Start the dashboard with `fsa serve` and open `http://127.0.0.1:8000`. The web
extra includes `python-multipart`, required for multipart upload handling. The
`lint` extra installs Ruff separately; on Android/Termux, install the core and
`dev` extras without `web` or `lint` because native wheels for some optional
dependencies may not be available. The
web upload endpoint performs static scanning only; it does not extract
archives. Keep the service bound to `127.0.0.1` unless you have a deliberate,
secured deployment plan. The API has no authentication in this release. API
uploads are limited to 128 MiB; CLI scans default to a 512 MiB limit.

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
  extraction.py   bounded ZIP/TAR extraction
  signatures.py   magic-byte identification
  heuristics.py   conservative text indicators
  entropy.py      entropy sampling
  cve.py          offline advisory matching
  reporting.py    JSON/HTML output
  cli.py          command-line interface
  webapp.py       optional local API
```

## Current limitations

- ZIP/TAR extraction is not a general firmware-filesystem unpacker.
- No full ELF dependency analysis or architecture-specific disassembly yet.
- Secret detection is heuristic and may produce false positives.
- CVE matching requires a curated local feed and manual confirmation.
- No claim of complete firmware coverage.

## Development

See [CHANGELOG.md](CHANGELOG.md), [docs/GUI.md](docs/GUI.md),
[docs/EXTRACTION.md](docs/EXTRACTION.md), [docs/REFERENCE_TOOLS.md](docs/REFERENCE_TOOLS.md),
and [docs/PHASE1_AUDIT.md](docs/PHASE1_AUDIT.md).

```bash
python -m pip install -e ".[dev,web]"
pytest -q
```

Please submit reproducible bug reports with a synthetic sample whenever
possible. Never publish real secrets, private firmware, or unredacted sensitive
device data.
