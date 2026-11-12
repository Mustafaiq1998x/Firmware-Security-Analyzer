# Native desktop inspector

On Kali Linux install Tk with `sudo apt install python3-tk` if your Python installation lacks it. On Windows select Tcl/Tk support in the Python installer. From the checkout install with `python -m pip install .` and start `fsa-gui`. The desktop worker supports Linux and Windows. The optional browser dashboard is available with the web extra and `fsa-web`.

Choose **Open firmware…** to inspect a local file. BIN and DAV are filename extensions. Format detection uses the actual bytes. The overview displays image identity, identifiers declared by the firmware, evidence offsets, compression and encryption evidence. Unknown formats remain available for static marker, string and entropy analysis. ELF markers and Linux text alone do not identify a device.

| Detected structure | Evidence and output |
|---|---|
| OpenWrt metadata trailer | Size, version and CRC checked. Displays board, compatible device IDs, target and declared release. This does not authenticate the manufacturer. |
| Legacy U-Boot image | Checks both CRCs and payload bounds. Exports the payload and reports the declared compression. |
| SquashFS v4 | Checks superblock and table bounds. Exports the filesystem image. The inode count includes directories and other inode types. Internal files are not enumerated. |
| ZIP / TAR | A bounded extraction produces regular files and a manifest in a private workspace. Desktop automatic unpacking recognizes ZIP and checked GNU/POSIX TAR headers. ZIP flags report encryption at the archive-member layer. |
| LUKS1 | Reads the declared cipher, mode and payload offset. The inspector does not decrypt containers. Other schemes may be unrecognized. |
| Proprietary DAV | Inspects recognizable structures inside the input. Unknown vendor-specific containers need a dedicated decoder. |

**Files** shows the current manifest. **Save extracted files…** copies those outputs to a new directory under the selected parent. Closing the window or opening another image removes temporary outputs. Save the JSON or HTML report before moving on. Extraction and input limits apply; a rejected archive may still have a static scan report.

**CVE feed…** selects a normalized local JSON advisory feed for subsequent scans. Kernel version ranges give review candidates. A `device-firmware` feed record must provide `cve`, `board`, `distribution`, `release` and an HTTPS `advisory_url`. Matches require an exact compatible device identifier, distribution and release. Verify the applicability and source of each advisory. See the [CLI feed reference](CLI.md).
