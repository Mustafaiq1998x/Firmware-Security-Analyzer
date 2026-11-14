"""Offline published-image identity and bounded TRX v1 partition tables."""
import hashlib
import json
import re
import struct
import zlib
from functools import lru_cache
from importlib.resources import files

TRX = "Broadcom TRX v1"
CHK = "NETGEAR CHK with TRX v1"


@lru_cache(maxsize=16)
def _index(prefix):
    resource = files("fsa").joinpath("assets", "openwrt", prefix + ".json")
    return json.loads(resource.read_text(encoding="utf-8"))


def identify(profile, digest):
    if digest == "50ff0338014842bfb6e179ca250c8a1389050776bad4be50c9b1d5f8503010ec":
        identity = profile["identity"]
        identity.update(vendor="D-Link", supported_devices=["D-Link DIR-842 C1"],
                        release="3.13B05")
        identity.setdefault("evidence", {})["published_image"] = {
            "sha256": digest, "member": "DIR842C1_FW313WWb05.bin",
            "source": "https://support.dlink.com/resource/PRODUCTS/DIR-842/REVC/DIR-842_REVC_FIRMWARE_v3.13B05.zip",
        }
        return
    row = _index(digest[0]).get(digest)
    if row is None:
        return
    board, models, vendors, target, release, kind = row
    identity = profile["identity"]
    identity.setdefault("board", board)
    if not identity.get("supported_devices"):
        identity["supported_devices"] = models
    if len(vendors) == 1:
        identity.setdefault("vendor", vendors[0])
    identity.update(distribution="OpenWrt", release=release, target=target)
    evidence = identity.setdefault("evidence", {})
    evidence["published_image"] = {
        "sha256": digest, "board": board, "devices": models, "image_type": kind,
        "source": f"https://downloads.openwrt.org/releases/{release}/targets/{target}/profiles.json",
    }


def _chk_header(data):
    if len(data) < 41:
        return None
    offset = int.from_bytes(data[4:8], "big")
    if not 41 <= offset <= min(256, len(data)):
        return None
    board = data[40:offset]
    if not re.fullmatch(rb"[A-Za-z0-9_-]+", board):
        return None
    size, root = struct.unpack_from(">II", data, 24)
    if root or size != len(data) - offset:
        return None
    a = b = 0
    for byte in data[:36] + bytes(4) + board:
        a += byte
        b += a
    if (b % 65535 << 16 | a % 65535) != int.from_bytes(data[36:40], "big"):
        return None
    return offset, board.decode()


SEAMA = "SEAMA firmware"


def inspect_seama(data, metadata):
    magic = b"\x5e\xa3\xa4\x17"
    if len(data) < 28 or data[:4] != magic:
        return None
    start = 0
    if data[8:12] == bytes(4):
        size = int.from_bytes(data[6:8], "big")
        start = 12 + size
        if (data[4:6] != bytes(2) or not 1 <= size <= 4096
                or not data[12:start].startswith(b"signature=")):
            return None
    if start + 28 > len(data) or data[start:start + 6] != magic + bytes(2):
        return None
    size, length = struct.unpack_from(">HI", data, start + 6)
    offset = start + 28 + size
    end = offset + length
    limit = metadata["evidence"]["offset"] if metadata else len(data)
    if size > 4096 or length == 0 or end > limit:
        return None
    digest = hashlib.md5(memoryview(data)[offset:end], usedforsecurity=False)
    if digest.digest() != data[start + 12:start + 28]:
        return None
    identity = metadata or {}
    identity.setdefault("evidence", {})["seama_header_offset"] = start
    return {"outer_format": SEAMA, "identity": identity,
            "components": [{"format": "SEAMA payload", "name": "firmware", "scope": "update partition",
                            "offset": offset, "size_bytes": length, "compression": None}],
            "encryption": {"status": "undetermined", "algorithm": None,
                           "evidence": "Readable SEAMA header with a checked payload digest."}}


def inspect(data):
    start = 0
    identity = {}
    if data[:4] == b"*#$^":
        header = _chk_header(data)
        if not header:
            return None
        start, board = header
        identity.update(vendor="NETGEAR", board=board)
        if board == "U12H270T00_NETGEAR":
            identity["supported_devices"] = ["NETGEAR R7000"]
    if data[start:start + 4] != b"HDR0" or len(data) - start < 28:
        return None
    length, crc, flags, *offsets = struct.unpack_from("<6I", data, start + 4)
    if flags >> 16 != 1 or length != len(data) - start:
        return None
    while offsets and offsets[-1] == 0:
        offsets.pop()
    if not offsets or offsets[0] < 28:
        return None
    if zlib.crc32(memoryview(data)[start + 12:]) ^ 0xffffffff != crc:
        return None
    components = []
    for i, (pos, end) in enumerate(zip(offsets, offsets[1:] + [length]), 1):
        if pos >= end:
            return None
        components.append({"format": "TRX partition", "name": f"partition-{i}", "offset": start + pos,
                           "size_bytes": end - pos, "compression": None, "scope": "update partition"})
    identity["evidence"] = {"source": "TRX length, partition bounds and CRC32", "offset": start}
    return {"outer_format": CHK if start else TRX, "identity": identity, "components": components,
            "partition_count": len(components), "directory_bytes": 28,
            "encryption": {"status": "undetermined", "algorithm": None,
                           "evidence": "The TRX partition table does not declare a cipher."}}
