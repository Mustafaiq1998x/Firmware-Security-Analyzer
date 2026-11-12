# Read a firmware inspection report

This walkthrough uses the 102-byte [synthetic firmware fixture](../samples/demo_firmware.bin) shipped with FSA. The dashboard's **View sample report** control opens [the same scan data](../src/fsa/assets/example-report.json). No firmware download is required.

| Evidence | Recorded value | Interpretation |
|---|---|---|
| SHA-256 | `bc1fff1765c26efc2bbd546619dd012952d305e05b099ad2dcc10d828e2a3830` | Identifies the exact input bytes. |
| ELF marker | Offset 29 (`0x1d`), bytes `7f454c46` | An ELF signature occurs here. The fixture contains a marker rather than a complete ELF file. |
| XZ marker | Offset 96 (`0x60`), bytes `fd377a585a00` | A second format marker in the same input. |
| Kernel version string | `4.9.138` | Text embedded in the fixture. No CVE feed was supplied. |
| Possible hardcoded password | `password=not-a-real-secret` | One deliberately synthetic, low-confidence match. |
| Entropy sample | 5.0004 bits per byte | The sample covers all 102 bytes. |

## Reproduce it

```sh
fsa scan samples/demo_firmware.bin --out demo.json --html demo.html
```

Open `demo.html` locally to review evidence and offsets. The complete JSON is available inside the exported document. [See validation on three real OpenWrt images](FIRMWARE_VALIDATION.md).
