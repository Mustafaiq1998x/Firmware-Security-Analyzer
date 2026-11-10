# FSA v0.1.0 — Phase 1 Audit and Stabilization

Date: 2026-11-10

## Scope and method

Inspected the supplied ZIP archive, extracted it with path validation, reviewed all 23 project source/configuration/test/documentation files, ran the existing tests, exercised the CLI and report writers, and called the FastAPI endpoints using TestClient. The supplied archive contains 51 ZIP entries because it also includes `.pytest_cache`, `__pycache__`, and 11 `.pyc` files. The ZIP integrity check passed. The pytest cache metadata was read and all 11 bundled Python bytecode files were disassembled; they correspond to generated copies of the listed source/tests, not additional project modules. No real vendor firmware is included; the 102-byte sample is synthetic.

Runtime environment: Python 3.13.5 on Linux. A fully isolated dependency installation could not be completed because PyPI DNS/network access was unavailable. The project itself was installed editable in a venv without resolving/downloading dependencies; tests and API checks used preinstalled test/runtime packages. Windows and Python 3.10–3.12 were not executable in this environment.

## Confirmed baseline results

- Original test suite: 10/10 passed.
- CLI help and `info`: passed.
- CLI `scan`: passed; produced JSON and HTML reports.
- Synthetic sample: expected ELF/XZ markers, Linux 4.9.138 string, and one heuristic password indicator found.
- JSON parsing and HTML escaping: passed.
- FastAPI `/health` and `/scan`: passed.
- Documented `GET /` route: initially returned 404; fixed in stabilization.

## Confirmed defects fixed

1. `extract_strings(..., limit=0)` returned one string instead of none; negative limits also behaved incorrectly.
2. `inspect_strings(..., max_evidence_per_rule=0)` still returned evidence; negative limits behaved incorrectly.
3. Negative signature hit limits were not rejected.
4. The analyzer and CLI `info` loaded whole files without an explicit resource ceiling. Added a configurable 512 MiB CLI/analyzer ceiling and chunked hashing for `info`; API remains limited to 128 MiB.
5. CVE feed loader accepted non-object top-level JSON and weakly validated records. Added feed-size, item-count, record, CVE-ID, and version-bound validation.
6. README documented `GET /`, but the FastAPI app did not implement it; added a minimal landing page.
7. API scanned a `NamedTemporaryFile` while it remained open. This pattern can fail on Windows due to file-sharing semantics; it now closes the temporary file before scanning and deletes it in `finally`.
8. CLI report destinations could overwrite the source image or each other; added path checks.
9. The ZIP included interpreter bytecode and pytest cache artifacts; release packaging should exclude these.

## Confirmed limitations retained and documented

- Magic-byte hits are candidate offsets, not structural validation of a complete filesystem, executable, or archive.
- Kernel version parsing and numeric CVE range comparison are approximate. Vendor backports, custom kernels, configuration, and exact build identity are not resolved.
- Heuristic strings can be false positives and may not indicate active services or credentials.
- No full filesystem extraction, ELF parsing, YARA engine integration, SBOM, or NVD schema ingestion is implemented in v0.1.0.
- The web API has no authentication. It should remain bound to loopback unless deployed behind suitable access controls.

## Potential improvements / not established as defects

- Add a streaming analysis pipeline to support images larger than the configured cap without retaining the full file in memory.
- Add structural validation for SquashFS, CramFS, JFFS2, ELF, DTB, gzip, XZ, and ZIP hits.
- Add a real vendor-firmware regression corpus with provenance and authorization records.
- Add more precise CVE applicability using CPE, vendor advisories, kernel stable patch history, and explicit backport evidence.
- Add report schema/versioning and deterministic output tests.
- Evaluate archive extraction only in Phase 2 with strict path, count, expanded-size, nesting, timeout, and parser isolation limits.

## Post-fix verification

- Regression suite after first stabilization: 24/24 passed on Python 3.13.5/Linux. After follow-up hardening: 26/26 passed on Python 3.13.5/Linux.
- `compileall` for source and tests: passed.
- Installed `fsa` entry point: help, `info`, and `scan` passed.
- JSON and HTML output after stabilization: passed.
- Oversized-input argument guard: rejected zero MiB as expected.
- FastAPI `GET /`, `GET /health`, and `POST /scan`: all returned 200 in TestClient checks.
- Windows and Python 3.10–3.12 were not run locally. CI has been expanded to cover those environments, but its result is pending a GitHub Actions run.

The local venv used the preinstalled system test/runtime packages because the environment could not reach PyPI. This validates execution in the available environment but is not evidence of a clean dependency installation from the package index.

## Phase 1 exit decision

The original v0.1.0 baseline was functional but not sufficiently hardened for untrusted or unusually large inputs. Stabilization changes have been applied locally. Phase 1 is not considered fully closed until the final regression suite passes and CI confirms Windows/Linux across the declared Python versions. Phase 2 must remain blocked until those checks are complete.

### Follow-up hardening pass

A second review found two additional edge cases in the stabilized archive: the entropy sampler silently treated a negative `max_blocks` as an empty result, and the API held the full accepted upload in memory before the analyzer read it again. The sampler now rejects negative limits, and API uploads are copied to a temporary file in 1 MiB chunks with a running 128 MiB cap. Regression tests cover both cases. The updated regression suite passes 26/26 on Python 3.13.5/Linux. CLI `--help`, `info`, and `scan` were exercised directly from the extracted source tree; JSON parsed successfully and HTML was created. FastAPI upload-size rejection is covered by a test. This reduces duplicate upload buffering but does not make the analyzer streaming: the analyzer still reads an accepted image into memory, subject to its configured cap.


## Final Phase 1 status (local environment)

- Updated project ZIP contains only the 27 intended project files; no `.pyc`, `__pycache__`, or pytest cache artifacts.
- `python -m pytest -q`: 26 passed on Python 3.13.5/Linux.
- `python -m compileall -q src tests`: passed.
- CLI `--help`, `info`, and `scan`: passed when invoked from the extracted source tree; generated JSON parsed and HTML output existed.
- FastAPI route tests and upload-limit rejection: passed in the regression suite.
- A fresh editable installation attempt in a new venv could not complete: pip attempted to fetch the build requirement `setuptools>=68`, but network/DNS access to PyPI was unavailable. This is not a project test failure; clean package installation remains unverified.
- Windows and Python 3.10–3.12 remain unverified locally; the GitHub Actions matrix must run before declaring cross-platform compatibility.
- No real DVR firmware was attached in this turn, so no real-world regression scan was performed.

**Exit decision:** Phase 1 is locally stabilized but not fully closed. Do not start Phase 2 until GitHub Actions confirms the matrix and a clean dependency installation is demonstrated.

## v0.1.1 CI finding and remediation

The first GitHub Actions run for commit `79619bdf2b506023d69359a02b8583c05f19d332` installed the project successfully on Ubuntu/Python 3.12 but failed test collection because FastAPI's multipart route requires `python-multipart`, which was absent from the `web` optional dependencies. The other matrix jobs were cancelled by the default fail-fast behavior; they did not pass or fail independently. Version 0.1.1 adds `python-multipart` to the web extra, packages the browser dashboard asset, adds web UI assertions, and disables matrix fail-fast so all environments report their own results. Local verification on Python 3.13/Linux: 26 tests passed, compileall passed, and a wheel built successfully with the dashboard HTML included. The GitHub matrix still must be rerun before Phase 1 can be declared closed.


## v0.1.2 bilingual dashboard update

The browser dashboard now supports English (default LTR) and Arabic (RTL) through a header language switch. Interface labels and result summaries are translated while firmware-derived evidence and identifiers remain unchanged. Local regression coverage remains 26 tests; CI matrix verification is still required before closing Phase 1.
