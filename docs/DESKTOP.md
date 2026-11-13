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

### Hikvision SWKH update directories

FSA recognizes this container variant by its encoded directory, independent of the filename. It checks the directory checksum, entry count, ordered byte ranges and each stored-byte checksum before reporting a match. The component view includes directory names and sizes. Saved components retain their stored bytes and use a data-file suffix. A valid embedded legacy U-Boot header can supply OS, architecture and kernel version evidence. Board IDs, device compatibility, package release and payload encryption remain unknown without independent evidence. These checksums do not authenticate the update.

When inspecting a ZIP containing one DAV update, the desktop shows both container layers. Saving files from the outer ZIP saves the DAV; opening that DAV lets you save its indexed entries. Offsets in its component table are relative to the DAV.

### Router update ZIPs

Open the vendor ZIP directly. If it contains one candidate BIN, IMG or DAV and the inner image has a supported firmware structure, the overview shows the ZIP and the identified image. PDFs and other accompanying documents remain visible in Files. Component and signature offsets refer to the inner image. Save extracted files to export the ZIP members, then open the inner image to export its partitions. A ZIP with several candidate firmware images remains an archive inventory so you can select the desired image.
