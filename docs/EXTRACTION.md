# Safe archive extraction (Phase 2)

FSA currently extracts only ZIP and TAR archives. This is a bounded archive
handling feature, not a general firmware-filesystem unpacker. SquashFS,
CramFS, JFFS2, UBIFS, vendor containers, and other filesystem images are not
extracted by this module.

## CLI

```bash
fsa extract firmware-rootfs.tar.gz --outdir ./extracted --report ./extraction.json
```

The destination must be a new or empty directory. The default limits are:

- Archive input: 64 MiB
- ZIP central directory: 16 MiB, checked before entry metadata is materialized
- TAR extended-header payloads combined: 1 MiB (`--max-tar-metadata-mib`)
- Total extracted bytes: 512 MiB
- One extracted file: 128 MiB
- Files: 20,000
- Directories (including implicit parents): 10,000
- Path depth: 64 components
- ZIP per-entry compression ratio: 200:1
- TAR output: bounded by total extracted bytes and time (no per-member compressed size exists)
- Wall-clock copy/iteration budget: 120 seconds

All limits are configurable with `fsa extract --help`, including the ZIP
central-directory budget. Keep conservative limits when inspecting untrusted
firmware. Increasing limits increases the
impact of malformed or hostile inputs.

## Security behavior

- ZIP and TAR are handled with Python's standard library; no shell commands or
  external unpackers are invoked.
- Absolute paths, drive paths, UNC paths, traversal components, ambiguous
  Windows names, duplicate paths, case-colliding path components (including
  implicit parent directories), and file/directory collisions are rejected.
- Symbolic links, hard links, devices, FIFOs, encrypted ZIP entries, and other
  special archive entries are rejected.
- Actual bytes copied are counted while streaming. Declared sizes are checked
  against actual output, with per-file and aggregate limits. ZIP entries are
  checked against a compression-ratio threshold; TAR streams use total-byte and
  time budgets.
- A failed extraction removes only filesystem objects created by that invocation. It does not recursively delete untracked content from a pre-existing empty destination.
- Nested archives are not recursively extracted or executed.
- Each regular file receives a SHA-256 digest in the extraction report.

Fixed-size ZIP64 end records are supported. ZIP64 extensible end records and prefixed ZIP64 archives are rejected.

## Limitations and threat model

The archive and its metadata are untrusted. ZIP central-directory size and
entry-count checks run before `ZipFile.infolist()` is allowed to materialize
entry objects. The extractor is designed to resist common archive path
traversal and decompression/resource exhaustion patterns,
but it is not a sandbox against a compromised Python runtime, malicious local
processes racing filesystem paths, or vulnerabilities in Python's archive
parsers. The central-directory preflight bounds metadata allocation; it does
not make Python's ZIP/TAR parsers formally memory-safe. Deadlines are checked between parser and copy operations. The direct extraction API and CLI use cooperative limits. The dashboard runs optional archive inspection in a separate worker under a 120-second watchdog. On Linux it caps address space and on Windows it caps process memory at 768 MiB. Run analysis as an
unprivileged user in a disposable workspace. Do not expose extraction as a
public unauthenticated service. Dashboard archive inspection is opt-in and returns a file manifest. It removes the private extraction workspace after the request.

A successful extraction means only that the archive passed these checks and
was copied within configured limits. It does not establish that extracted
firmware is safe.
