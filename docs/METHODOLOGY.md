# Methodology

FSA v0.1 is a triage tool, not a vulnerability scanner that can prove impact.

1. Read the image as opaque bytes; never execute it.
2. Compute SHA-256 to identify the exact analyzed artifact.
3. Search a small, documented set of magic-byte signatures.
4. Sample Shannon entropy in fixed-size blocks. High entropy can indicate
   compression or encryption, but is not proof of either.
5. Extract printable ASCII strings and apply conservative regex indicators.
6. Extract Linux kernel version strings where present.
7. Optionally compare those versions with a user-supplied normalized offline
   advisory feed. Every match is explicitly marked for manual validation.

## Validation workflow

For each finding, record:
- firmware vendor, model, hardware revision, and exact firmware version;
- source and acquisition date of the image;
- image SHA-256;
- file offset and containing component;
- vendor advisory and upstream references;
- whether the vendor backported a fix;
- reproducible, non-destructive validation evidence;
- remediation recommendation and disclosure status.

Never report a CVE as confirmed based only on a string or version range match.
