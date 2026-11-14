# Device firmware coverage

Supported layouts are identified using file contents. A published sample can also be identified by SHA-256. The report records the publisher and source for that identity, independently of partition recognition.

| Category | Input checked | Result |
|---|---|---|
| Satellite receivers | MediaStar MS-15000 Forever BlackMenu 3.58 | Exact build identity; three bounded SquashFS 4.0 filesystems (gzip, gzip, LZMA). The outer format remains unrecognized. |
| IP cameras | OpenIPC SSC335 NOR Lite | U-Boot image, Linux 4.9.84, two exportable components. The build targets a chip platform shared by cameras. |
| Surveillance recorders | Supplied Hikvision SWKH DAV | Ten indexed entries and Linux 4.9.138. The sample does not establish a particular DVR/NVR model. |
| System firmware | Debian EDK II OVMF_CODE.fd | Two checksum-checked firmware volumes on a virtual UEFI platform. Retail motherboard BIOS wrappers require separate verification. |
| Android | Boot header v3 and v4 regression fixtures | Kernel and ramdisk ranges; optional v4 signature range. A complete handset update and iOS firmware remain untested. |
| Audio | JBL Bar 5.1 Surround 20.43.51.00 | Hash-based identification of both distribution ZIP and inner update ZIP. Six declared files in the inner archive. The 64 MiB automatic archive extraction limit applies. |
| RGB lighting | WLED ESP02 16.0.1 | Exact build identity; internal segments have not been decoded. |
| Printers | Original Prusa i3 MK3 3.14.1 | Two Intel HEX streams, with every record checksum verified. Exported streams retain their original text encoding. This sample is a 3D printer. |
| Scanners | Epson esfw41.bin from the GT-F500 package | Exact image match for Perfection 2480 PHOTO and 2580 PHOTO. Internal format remains unrecognized. |

The desktop's file picker accepts HEX and FD alongside BIN, DAV and other common extensions. For exact-build identification the evidence field includes the source link. Byte offsets in exported components refer to the analyzed image.
