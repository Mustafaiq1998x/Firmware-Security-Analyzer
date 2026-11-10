# Changelog

## 0.1.0 — Phase 1 stabilization (2026-11-10)

- Preserved the original CLI, static analysis pipeline, JSON/HTML reports, and optional FastAPI interface.
- Added bounded CLI analysis reads and streaming SHA-256 calculation for `info`.
- Added validation for zero and negative string, evidence, and signature limits.
- Added CVE feed structure, identifier, version-bound, and size validation; numeric range matches remain approximate and require manual review.
- Added the documented `GET /` API landing page.
- Changed API temporary-file handling to close the file before analysis for Windows compatibility and sanitize the temporary suffix.
- Added CLI protection against report paths that overwrite the input image or each other.
- Expanded regression tests and CI to Windows/Linux and Python 3.10–3.13.
- Added regression coverage for report HTML escaping and API routes.

This release remains static triage software. It does not prove vulnerability applicability and does not perform firmware extraction.

### Additional Phase 1 hardening (2026-11-10)

- Stream FastAPI uploads to a temporary file in bounded chunks instead of retaining the complete upload in memory before scanning.
- Reject negative entropy sampling block limits explicitly.
- Add regression tests for upload-size enforcement and invalid entropy limits.
