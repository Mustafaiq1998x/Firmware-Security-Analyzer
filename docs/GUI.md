# Browser dashboard

FSA 0.1.2 includes a local bilingual Arabic/English browser dashboard. English LTR is the default; use the language switch in the header to switch to Arabic RTL. Install the web extra and start it with:

```bash
python -m pip install -e ".[web]"
fsa serve
```

Open `http://127.0.0.1:8000`. Select or drag a firmware image into the upload area and start the scan. The UI presents file metadata and SHA-256, signature offsets, sampled entropy, extracted Linux kernel versions, heuristic indicators with evidence, and offline CVE-feed matches when a feed is supplied through the CLI. The dashboard exports the current result as JSON. Firmware-derived strings, signatures, hashes, and evidence are kept unchanged when switching languages; only interface labels are translated.

The browser upload endpoint is limited to 128 MiB and streams the request into a temporary file in 1 MiB chunks. The temporary file is removed after the scan. The analyzer then reads the accepted image into memory; this is not a streaming parser. Responses are marked `Cache-Control: no-store`.

The web service has no authentication. Keep it bound to `127.0.0.1`; do not expose it to a LAN or the public internet without adding authentication, TLS, request controls, and a deliberate deployment review. The dashboard does not execute firmware, extract filesystems, or prove that a heuristic indicator is exploitable.
