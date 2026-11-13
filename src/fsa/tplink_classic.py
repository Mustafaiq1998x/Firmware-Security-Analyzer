"""TP-Link legacy v1 factory images with a checked partition layout."""
import hashlib
import lzma
import re
import struct

FORMAT = "TP-Link legacy v1"
PREFIX = b"\x01\0\0\0TP-LINK Technologies\0"
NORMAL = bytes.fromhex("dcd73aa5c39598fbddf9e7f40eae4738")
BOOT = bytes.fromhex("8cef335bd5c5cefaa79c28dab2e90f42")


def _header(data, start):
    if len(data) - start < 512 or data[start:start + len(PREFIX)] != PREFIX:
        return None
    fields = struct.unpack_from(">7I3H", data, start + 124)
    if fields[0] != len(data) - start:
        return None
    digest = hashlib.md5(usedforsecurity=False)
    digest.update(memoryview(data)[start:start + 76])
    digest.update(BOOT if fields[6] else NORMAL)
    digest.update(memoryview(data)[start + 92:])
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


def inspect(data, versions):
    fields = _header(data, 0)
    if not fields:
        return None
    base = 0
    ranges = []
    if fields[6]:
        base = 512 + 0x20000
        if fields[5] or 512 + fields[6] > base or data[64:72] != data[base + 64:base + 72]:
            return None
        ranges.append(("bootloader", 512, fields[6]))
        fields = _header(data, base)
        if not fields or fields[6]:
            return None
    _, kernel, ksize, root, rsize, _, _, *release = fields
    if not (512 <= kernel and ksize and kernel + ksize <= root and rsize and base + root + rsize <= len(data)):
        return None
    ranges.extend([("kernel", base + kernel, ksize), ("rootfs", base + root, rsize)])
    parts = [{"name": name, "offset": offset, "size_bytes": length, "format": "legacy partition",
              "compression": None, "scope": "update partition"} for name, offset, length in ranges]
    board = bytes(data[64:68]).hex()
    identity = {"vendor": "TP-Link", "board": "0x" + board,
                "release": ".".join(map(str, release)),
                "evidence": {"source": "legacy header with verified format checksum and partition bounds",
                             "hardware_id_offset": 64, "version_offset": base + 152}}
    if board == "08410008":
        identity["supported_devices"] = ["TL-WR841N family v8"]
    _kernel(data, parts[-2], identity, versions)
    return {"outer_format": FORMAT, "identity": identity, "components": parts,
            "partition_count": len(parts), "directory_bytes": 512,
            "encryption": {"status": "undetermined", "algorithm": None,
                           "evidence": "Readable partition header. No cipher identified."}}
