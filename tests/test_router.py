import struct
import zlib

from fsa.router import TRX, identify, inspect


def test_trx_partitions_need_checksum_and_strict_offsets():
    data = bytearray(struct.pack("<4s6I", b"HDR0", 40, 0, 1 << 16, 28, 36, 0) + bytes(12))
    struct.pack_into("<I", data, 8, zlib.crc32(data[12:]) ^ 0xffffffff)
    assert inspect(data)["outer_format"] == TRX
    assert [p["size_bytes"] for p in inspect(data)["components"]] == [8, 4]
    data[-1] ^= 1
    assert inspect(data) is None
    struct.pack_into("<I", data, 20, 27)
    struct.pack_into("<I", data, 8, zlib.crc32(data[12:]) ^ 0xffffffff)
    assert inspect(data) is None


def test_catalogue_needs_exact_hash():
    import hashlib
    from importlib.resources import files
    import json

    root = files("fsa").joinpath("assets", "openwrt")
    index = json.loads(root.joinpath("0.json").read_text())
    key, row = next(iter(index.items()))
    profile = {"identity": {"supported_devices": []}}
    identify(profile, key)
    assert profile["identity"]["supported_devices"] == row[1]
    untouched = {"identity": {}}
    identify(untouched, hashlib.sha256(b"unlisted").hexdigest())
    assert untouched == {"identity": {}}


def test_seama_export_requires_payload_digest():
    import hashlib
    from fsa.router import inspect_seama

    payload = b"sample payload"
    header = struct.pack(">IHHI", 0x5ea3a417, 0, 0, len(payload))
    image = header + hashlib.md5(payload, usedforsecurity=False).digest() + payload
    assert inspect_seama(image, None)["components"][0]["offset"] == 28
    assert inspect_seama(image[:-1], None) is None
    assert inspect_seama(image[:-1] + b"!", None) is None
