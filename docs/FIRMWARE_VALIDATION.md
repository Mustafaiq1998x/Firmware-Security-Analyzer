# OpenWrt firmware validation

Three official OpenWrt 24.10.0 images were downloaded and their SHA-256 digests compared with the target directory's published sha256sums. The CLI scanning engine inspected the original image bytes. The open-source file/libmagic utility independently identified the outer format. The browser scan of the Archer C7 image produced the same SHA-256 as the command-line engine.

| Image | Outer format (file) | FSA marker types sampled | SHA-256 |
|---|---|---|---|
| [TP-Link Archer C7 v5](https://downloads.openwrt.org/releases/24.10.0/targets/ath79/generic/openwrt-24.10.0-ath79-generic-tplink_archer-c7-v5-squashfs-sysupgrade.bin) | U-Boot legacy uImage | U-Boot uImage, SquashFS, JFFS2, XZ, gzip | `e04e3eafc6c2847b3a5d376ad0c0e154ea13f9e56a5bec87005fcd0e6bb28ee7` |
| [GL.iNet GL-MT6000](https://downloads.openwrt.org/releases/24.10.0/targets/mediatek/filogic/openwrt-24.10.0-mediatek-filogic-glinet_gl-mt6000-squashfs-sysupgrade.bin) | GNU TAR | SquashFS, JFFS2, XZ, gzip | `9d919742a6f832b9f0d4073fa301dc78c9627acd7cab200acd703b6cf2351a82` |
| [x86-64 EFI combined image](https://downloads.openwrt.org/releases/24.10.0/targets/x86/64/openwrt-24.10.0-x86-64-generic-squashfs-combined-efi.img.gz) | gzip | JFFS2, XZ, gzip | `0c0e48fd2739093e60ebc8459876bed11b355cf132de2dd2a5cacd3dea890801` |

Each scan reached the 200-hit limit. Short patterns such as JFFS2 can occur inside compressed data. The x86 result describes the compressed input bytes. The GL-MT6000 sample led to a checksummed first-header TAR check in FSA. The outer TAR was identified independently and checked with FSA's extraction command. Reproduce with `fsa scan IMAGE --out report.json` and, for the TAR sample, `fsa extract IMAGE --outdir new-directory --report manifest.json`.

## TP-Link Archer AX10 Cloud update

The BIN from the [official US V2 support download](https://www.tp-link.com/us/support/download/archer-ax10/v2/) for 1.3.11 Build 20250325 Rel. 24737 has SHA-256 `be8b16276eff31ccdf1a5dfd876e30d722adc41169bbb669c50e25e7f3dacc9e` and 15,173,297 bytes. The validated table at offset 4116 contains ten update partitions. Its support-list names Archer AX10, AX1500 and AX1450 with hardware revisions. The Broadcom OS header declares board TP6750_AX1500V1. A bounded decode of the BRCM LZMA kernel exposes a Linux 4.1.52 banner and an ARMv7 processor string. The embedded SquashFS uses XZ. The number of partitions and filesystem inode count describe different layers.
