import struct

import pytest

from fsa.analyzer import scan_file
from fsa.desktop import describe
from fsa.tplink import BASE, TABLE_SIZE


def image(overlap=False):
    def metadata(text):
        return struct.pack(">II", len(text), 0) + text

    pieces = {"os-image": b"test", "support-list": metadata(
        b"SupportList:\n{product_name:Example,product_ver:2.0,special_id:00000000}"),
        "soft-version": metadata(b"soft_ver:1.2.3 Build 20250101 Rel. 42\n")}
    directory = bytearray()
    payload = bytearray()
    for name, data in pieces.items():
        offset = TABLE_SIZE if overlap else TABLE_SIZE + len(payload)
        directory.extend(f"fwup-ptn {name} base 0x{offset:x} size 0x{len(data):x}\n".encode())
        payload.extend(data)
    raw = bytearray(BASE) + directory.ljust(TABLE_SIZE, b"\0") + payload
    raw[20:34] = b"fw-type:Cloud\n"
    raw[:4] = len(raw).to_bytes(4, "big")
    return raw


def test_safe_loader_metadata_survives_rename(tmp_path):
    p = tmp_path / "renamed.img"
    p.write_bytes(image())
    r = scan_file(p)
    f = r["analysis"]["firmware_profile"]
    assert f["partition_count"] == 3
    assert f["identity"]["supported_devices"] == ["Example v2.0"]
    assert f["identity"]["build"] == "20250101 rel.42"
    assert "Cipher / mode" not in dict(describe(r))


@pytest.mark.parametrize("raw", [image(True), image()[:-1], b"TP-Link Archer AX10"])
def test_filename_or_invalid_directory_does_not_identify_vendor(raw, tmp_path):
    p = tmp_path / "Archer_AX10.bin"
    p.write_bytes(raw)
    r = scan_file(p)
    assert "vendor" not in r["analysis"]["firmware_profile"]["identity"]
    assert "Format coverage" in dict(describe(r))


def test_factory_directory_without_cloud_marker(tmp_path):
    raw = image()
    raw[20:34] = bytes(14)
    path = tmp_path / "renamed.bin"
    path.write_bytes(raw)
    profile = scan_file(path)["analysis"]["firmware_profile"]
    assert profile["outer_format"] == "TP-Link SafeLoader (factory)"
    assert profile["identity"]["supported_devices"] == ["Example v2.0"]


def test_legacy_partition_bounds_and_integrity():
    import hashlib
    from fsa import tplink_classic

    data = bytearray(1024)
    data[:len(tplink_classic.PREFIX)] = tplink_classic.PREFIX
    struct.pack_into(">7I3H", data, 124, 1024, 512, 128, 640, 384, 0, 0, 2, 3, 4)

    def checksum():
        data[76:92] = tplink_classic.NORMAL
        data[76:92] = hashlib.md5(data, usedforsecurity=False).digest()

    checksum()
    profile = tplink_classic.inspect(data, [])
    assert profile["identity"]["release"] == "2.3.4"
    assert "supported_devices" not in profile["identity"]
    assert [p["offset"] for p in profile["components"]] == [512, 640]
    data[-1] = 1
    assert tplink_classic.inspect(data, []) is None
    struct.pack_into(">I", data, 136, 600)
    checksum()
    assert tplink_classic.inspect(data, []) is None
