# Command-line and API reference

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
dependencies may not be available. The web upload endpoint can inspect ZIP and TAR archives on request. Keep the service bound to `127.0.0.1` unless you have a deliberate,
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

### Android / Termux

The core CLI and tests do not require the optional web or lint dependencies.
On Termux, use `python -m pip install -e ".[dev]"` and run
`python -m pytest -q --ignore=tests/test_webapp.py`. Do not install `web` or
`lint` extras in Termux unless their native dependencies are available for
your Python/Android build. Web tests run in the Linux/Windows CI matrix.
