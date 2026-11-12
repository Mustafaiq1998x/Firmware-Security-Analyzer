# Reference tools and implementation policy

Review date: 2026-11-11

FSA uses established firmware-analysis tools as architectural references. It does
not claim feature parity with them, and this release does not vendor their code.

## Binwalk

- Upstream: https://github.com/ReFirmLabs/binwalk
- License: MIT (verify the license file for the exact upstream revision before
  copying or modifying any source file).
- Useful design references: content-based signature identification, byte-offset
  reporting, entropy analysis, extraction workflows, and machine-readable output.
- FSA decision: keep its current core independent and portable. A future optional
  Binwalk integration must record the executable version, arguments, exit code,
  and raw output, and must run in a constrained local process. It must never be
  silently treated as a validated parse.

## unblob

- Upstream: https://github.com/onekey-sec/unblob
- License: MIT (check individual bundled components and the exact revision).
- Useful design references: handler/extractor separation, chunk boundaries,
  metadata reporting, recursive inspection, and explicit reporting of unknown
  regions.
- FSA decision: adopt the handler-oriented architecture in a future phase. Do
  not copy individual handlers until their dependencies, tests, and attribution
  requirements have been reviewed. Recursive processing must have global depth,
  byte, entry, CPU-time, and disk quotas.

## FACT — Firmware Analysis and Comparison Tool

- Upstream: https://github.com/fkie-cad/fact_core
- License: GPL-3.0-or-later; some plugins may have separate licenses.
- Useful design references: modular analysis plugins, searchable findings,
  firmware comparison, and a unified review workflow.
- FSA decision: use the product concepts as design inspiration only. Do not copy
  FACT source files into this MIT-licensed project unless the project licensing
  strategy is deliberately changed and all obligations are reviewed.

## FSA implementation priorities

1. Keep the default scan local, read-only, and non-executing.
2. Prefer standard-library parsing for the core and optional integrations for
   platform-specific extractors.
3. Treat every signature hit as a low-confidence lead until format-specific
   structural validation succeeds.
4. Preserve offsets, hashes, tool versions, extraction logs, and parser errors
   as report evidence.
5. Make recursive extraction opt-in and enforce cumulative resource limits.
6. Keep firmware samples local unless the owner explicitly chooses to share them.

The current scanner is still an initial triage engine. It does not yet parse
SquashFS/JFFS2/UBIFS filesystems, inspect ELF dependencies, build an SBOM, or
prove CVE applicability. Those require separate, testable phases.
