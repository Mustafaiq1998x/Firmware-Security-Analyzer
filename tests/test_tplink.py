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
