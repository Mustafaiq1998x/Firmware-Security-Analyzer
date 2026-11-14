"""TP-Link legacy v1 factory images with a checked partition layout."""
import hashlib
import lzma
import re
import struct

FORMAT = "TP-Link legacy v1"
FORMAT_V3 = "TP-Link legacy v3"
PREFIX = b"\x01\0\0\0TP-LINK Technologies\0"
OPENWRT_PREFIX = b"\x01\0\0\0OpenWrt\0"
# IDs observed in the named OpenWrt factory and TP-Link vendor images.
DEVICES = {
    "08100001": "tplink,tl-wr810n-v1",
    "08410008": "TL-WR841N family v8",
    "08410009": "TL-WR841N family v9",
    "08410011": "TL-WR841N family v11",
    "08411002": "tplink,tl-wr841hp-v2",
    "08411003": "tplink,tl-wr841hp-v3",
    "08420003": "tplink,tl-wr842n-v3",
    "10430002": "tplink,tl-wr1043nd-v2",
    "10430003": "tplink,tl-wr1043nd-v3",
    "10450002": "tplink,tl-wr1045nd-v2",
    "25430001": "tplink,tl-wr2543-v1",
    "35000001": "tplink,tl-wdr3500-v1",
    "36000001": "tplink,tl-wdr3600-v1",
    "43000001": "tplink,tl-wdr4300-v1",
    "43008001": "tplink,tl-wdr4300-v1-il",
    "43100001": "tplink,tl-wdr4310-v1",
    "49000002": "tplink,tl-wdr4900-v2",
    "64000001": "tplink,tl-mr6400-v1",
    "65000002": "tplink,tl-wdr6500-v2",
    "75000001": "tplink,archer-c7-v1",
    "75000003": "tplink,tl-wdr7500-v3",
    "86300001": "tplink,tl-wpa8630-v1",
    "c5000001": "tplink,archer-c5-v1",
    "c7000002": "tplink,archer-c7-v2",
}
NORMAL = bytes.fromhex("dcd73aa5c39598fbddf9e7f40eae4738")
BOOT = bytes.fromhex("8cef335bd5c5cefaa79c28dab2e90f42")


def _header(data, start, end, trimmed=False):
    if end - start < 512 or not data[start:start + len(PREFIX)].startswith((PREFIX, OPENWRT_PREFIX)):
        return None
    fields = struct.unpack_from(">7I3H", data, start + 124)
    if fields[0] < end - start or (not trimmed and fields[0] != end - start):
        return None
    digest = hashlib.md5(usedforsecurity=False)
    digest.update(memoryview(data)[start:start + 76])
    digest.update(BOOT if fields[6] else NORMAL)
    digest.update(memoryview(data)[start + 92:end])
    if digest.digest() == data[start + 76:start + 92]:
        return fields


def _kernel(data, part, identity, versions):
    if part["size_bytes"] > 8 << 20:
        return
    start = part["offset"]
    stream = lzma.LZMADecompressor(lzma.FORMAT_ALONE, memlimit=64 << 20)
    try:
        raw = stream.decompress(data[start:start + part["size_bytes"]], max_length=(16 << 20) + 1)
    except lzma.LZMAError:
        return
    if not stream.eof or len(raw) > 16 << 20:
        return
    part["compression"] = "lzma"
    banner = re.search(rb"Linux version (\d+\.\d+\.\d+)(?=[ .+-])", raw)
    if banner:
        identity["os_family"] = "Linux"
        identity["evidence"]["kernel_banner_offset_in_decoded_kernel"] = banner.start()
        if banner[1].decode() not in versions:
            versions.append(banner[1].decode())
    if b"mod_unload MIPS32_R2 32BIT " in raw:
        identity["architecture"] = "MIPS32 Release 2 (kernel module metadata)"


def inspect_sysupgrade(data, metadata, versions, filesystems):
    """Handle trimmed OpenWrt variants with a verified fwtool trailer and SquashFS."""
    if not metadata:
        return None
    end = metadata["evidence"]["offset"]
    if end < 512:
        return None
    v3 = data[:13] == b"\x03\0\0\0ver. 2.0\0"
    if not v3 and data[:len(OPENWRT_PREFIX)] != OPENWRT_PREFIX:
        return None
    total, kernel, size, root, rsize, boot, bsize = struct.unpack_from(">7I", data, 112 if v3 else 124)
    if kernel != 512 or not size or kernel + size > root or root >= end or boot or bsize:
        return None
    fs = next((p for p in filesystems if p["offset"] == root), None)
    if not fs or root + fs["size_bytes"] > end:
        return None
    if v3:
        if total < end or not fs["size_bytes"] <= rsize <= end - root:
            return None
        digest = hashlib.md5(usedforsecurity=False)
        digest.update(data[:64])
        digest.update(bytes.fromhex("dcd73aa5c39598fbdcf9e7f40eae4737"))
        digest.update(memoryview(data)[80:end])
        if digest.digest() != data[64:80]:
            return None
    elif total or rsize or data[76:92] != bytes(16):
        return None
    identity = dict(metadata, vendor="TP-Link")
    identity["evidence"] = dict(metadata["evidence"], kernel_header_offset=0, filesystem_offset=root)
    part = {"name": "kernel", "format": "legacy partition", "offset": kernel,
            "size_bytes": size, "scope": "update partition", "compression": None}
    _kernel(data, part, identity, versions)
    return {"outer_format": FORMAT_V3 if v3 else FORMAT, "identity": identity,
            "components": [part, dict(fs, name="rootfs")], "embedded_filesystems": filesystems,
            "partition_count": 2, "directory_bytes": 512,
            "encryption": {"status": "undetermined", "algorithm": None,
                           "evidence": "Readable kernel header and filesystem superblock."}}


def inspect(data, versions, metadata=None):
    openwrt = data[:len(OPENWRT_PREFIX)] == OPENWRT_PREFIX
    trimmed = openwrt and metadata is not None
    end = metadata["evidence"]["offset"] if trimmed else len(data)
    fields = _header(data, 0, end, trimmed)
    if not fields:
        return None
    base = 0
    ranges = []
    if fields[6]:
        base = 512 + 0x20000
        if fields[5] or 512 + fields[6] > base or data[64:72] != data[base + 64:base + 72]:
            return None
        ranges.append(("bootloader", 512, fields[6]))
        fields = _header(data, base, end)
        if not fields or fields[6]:
            return None
    _, kernel, ksize, root, rsize, _, _, *release = fields
    if not (512 <= kernel and ksize and kernel + ksize <= root and rsize and base + root + rsize <= end):
        return None
    ranges.extend([("kernel", base + kernel, ksize), ("rootfs", base + root, rsize)])
    parts = [{"name": name, "offset": offset, "size_bytes": length, "format": "legacy partition",
              "compression": None, "scope": "update partition"} for name, offset, length in ranges]
    board = bytes(data[64:68]).hex()
    identity = {"vendor": "TP-Link", "board": "0x" + board,
                "evidence": {"source": "legacy header with verified format checksum and partition bounds",
                             "hardware_id_offset": 64, "version_offset": base + 152}}
    if openwrt:
        identity["distribution"] = "OpenWrt"
        build = data[28:64].split(b"\0", 1)[0]
        if re.fullmatch(rb"r[0-9]+-[0-9a-f]+", build):
            identity["build"] = build.decode()
    elif any(release):
        identity["release"] = ".".join(map(str, release))
    device = DEVICES.get(board)
    if device:
        identity["supported_devices"] = [device]
    if trimmed:
        identity["hardware_id"] = identity["board"]
        identity.update({key: value for key, value in metadata.items() if key != "evidence" and value})
        identity["evidence"]["openwrt_trailer"] = metadata["evidence"]
    _kernel(data, parts[-2], identity, versions)
    return {"outer_format": FORMAT, "identity": identity, "components": parts,
            "partition_count": len(parts), "directory_bytes": 512,
            "encryption": {"status": "undetermined", "algorithm": None,
                           "evidence": "Readable partition header. No cipher identified."}}
