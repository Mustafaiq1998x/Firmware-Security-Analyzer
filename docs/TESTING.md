# Testing and quality gates

Run `python -m pip install -e ".[dev,web]"` then `pytest -q`.

The CI workflow installs both development and web extras and runs on Windows and Ubuntu with Python 3.10–3.13.

Recommended release checks:
- Run tests on the latest supported Windows and Ubuntu Python versions.
- Run Ruff: `ruff check src tests`.
- Add synthetic fixtures for every new signature or heuristic.
- Verify stable JSON output and HTML escaping.
- Test large files and malformed inputs under a memory limit.
- Do not add real device credentials, customer firmware, or private keys to
  test fixtures or Git history.

The API upload path streams request data to a temporary file in 1 MiB chunks and enforces its configured byte limit while receiving the request. The analyzer itself currently loads the accepted image into memory; test under constrained memory before raising the 512 MiB CLI limit.
