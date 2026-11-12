# Changelog

## Unreleased — Phase 2 bounded archive extraction

- Added non-recursive ZIP and TAR extraction without shell commands or external unpackers.
- Enforced archive, per-file, aggregate byte, file-count, directory-count, path-depth, compression-ratio, and time limits.
- Rejected traversal/absolute/UNC/drive paths, ambiguous Windows names, duplicate and case-colliding paths, links, special entries, and sparse TAR files.
- Added streamed byte accounting, per-file SHA-256 hashes, extraction reports, and cleanup on failure.
- Added the `fsa extract` CLI command and documented the extraction threat model and format limitations.
- Added adversarial extraction regression tests.
- Preflight ZIP entry count and central-directory size before loading `ZipInfo` records.
- Track normalized path components to reject collisions in implicit parent directories.
- Validate ZIP Unix/DOS directory metadata and reject contradictory directory records.
- Clean up only paths created by the extraction operation, including on keyboard interruption.
- Split Ruff into an optional `lint` extra so Android/Termux core testing does not require Rust-based Ruff builds.
- Use read-only memory mapping for firmware scans and cap each extracted printable string at 1 KiB.
- Distribute entropy samples across the full firmware image instead of sampling only its first MiB.
- Expand conservative marker coverage for UBI/UBIFS, Android boot/sparse, Zstandard, LZ4, bzip2, CPIO, and TRX.
- This work remains pending cross-platform CI and review; no release version has been assigned.

## 0.1.2 — Bilingual dashboard (2026-11-10)

- Added an in-dashboard Arabic/English language switch with correct RTL/LTR layout and translated interface labels, scan states, and result summaries.
- Kept firmware-derived names, hashes, signatures, and evidence unchanged across language switches.
- Expanded dashboard regression checks for the language selector and English resources.
- Bumped the package version to 0.1.2.

## 0.1.1 — Browser dashboard and web dependency fix (2026-11-10)

- Added the missing `python-multipart` dependency to the `web` extra; FastAPI multipart routes now have their required runtime dependency.
- Replaced the placeholder landing page with a responsive bilingual Arabic/English browser dashboard (English LTR by default, Arabic RTL toggle).
- Added drag-and-drop and file-picker uploads, a 128 MiB client-side guard, scan status and error messaging.
- Added summary metrics, entropy visualization, signature locations, heuristic evidence, kernel-version and CVE-feed panels, file metadata, and JSON report download.
- Packaged the dashboard HTML as package data so installed distributions include the UI asset.
- Improved API error responses for malformed/unreadable uploads while retaining temporary-file cleanup and bounded upload streaming.
- Expanded web UI regression assertions, including language-switch presence and English translation resources.

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
