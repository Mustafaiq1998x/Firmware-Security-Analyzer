"""Conservative magic-byte identification for common firmware components."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Signature:
    name: str
    magic: bytes
    offset: int = 0
    description: str = ""


SIGNATURES = (
    Signature("SquashFS", b"hsqs", 0, "SquashFS little-endian superblock"),
    Signature("SquashFS", b"sqsh", 0, "SquashFS big-endian superblock"),
    Signature("CramFS", b"E=\xcd(", 0, "CramFS superblock"),
    Signature("JFFS2", b"\x85\x19", 0, "JFFS2 node marker"),
    Signature("U-Boot uImage", b"\x27\x05\x19\x56", 0, "Legacy U-Boot image header"),
    Signature("ELF", b"\x7fELF", 0, "Executable and Linkable Format"),
    Signature("gzip", b"\x1f\x8b\x08", 0, "gzip stream"),
    Signature("XZ", b"\xfd7zXZ\x00", 0, "XZ stream"),
    Signature("ZIP", b"PK\x03\x04", 0, "ZIP local file header"),
    Signature("Device Tree Blob", b"\xd0\x0d\xfe\xed", 0, "Flattened device tree / FIT image marker"),
    Signature("UBI erase-counter header", b"UBI#", 0, "UBI erase-counter header marker"),
    Signature("UBIFS node", b"\x31\x18\x10\x06", 0, "UBIFS node magic marker"),
    Signature("Android boot image", b"ANDROID!", 0, "Android boot image header marker"),
    Signature("Android sparse image", b":\xff&\xed", 0, "Android sparse image header marker"),
    Signature("Zstandard", b"\x28\xb5\x2f\xfd", 0, "Zstandard frame magic"),
    Signature("LZ4 frame", b"\x04\x22\x4d\x18", 0, "LZ4 frame magic"),
    Signature("bzip2", b"BZh", 0, "bzip2 stream marker"),
    Signature("CPIO newc", b"070701", 0, "CPIO new ASCII format header"),
    Signature("OpenWrt TRX", b"HDR0", 0, "Broadcom TRX container header"),
)


def identify_signatures(data: bytes, max_hits: int = 200) -> list[dict]:
    """Find known markers throughout an image; offsets are byte offsets."""
    if max_hits < 0:
        raise ValueError("max_hits must be zero or greater")
    if max_hits == 0:
        return []
    hits = []
    for sig in SIGNATURES:
        start = 0
        while len(hits) < max_hits:
            pos = data.find(sig.magic, start)
            if pos < 0:
                break
            hits.append({"name": sig.name, "offset": pos, "magic_hex": sig.magic.hex(),
                         "description": sig.description})
            start = pos + 1
        if len(hits) >= max_hits:
            break
    return sorted(hits, key=lambda x: x["offset"])
