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


@pytest.mark.parametrize("second,expected", [("manual.pdf", True), ("other.bin", False)])
def test_zip_selects_only_unambiguous_firmware(tmp_path, second, expected):
    import asyncio
    import zipfile
    from fsa.scan_worker import inspect_upload

    path = tmp_path / "update.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("upgrade/firmware.BIN", image())
        archive.writestr(second, b"additional member")

    async def connected():
        return False

    result = asyncio.run(inspect_upload(path, tmp_path, 65536, True, connected))
    assert result["archive_inspection"]["summary"]["files"] == 2
    assert ("packaged_firmware" in result) is expected
    if expected:
        plain = scan_file(tmp_path / "files/upgrade/firmware.BIN")
        inner = result["packaged_firmware"]
        assert inner["firmware_profile"] == plain["analysis"]["firmware_profile"]
        assert inner["sha256"] == plain["input"]["sha256"]


def test_safeloader_padding_is_bounded():
    from fsa import tplink

    raw = image()
    assert tplink.inspect(raw + bytes(128), [])
    assert tplink.inspect(raw + bytes(127), []) is None
    assert tplink.inspect(raw + bytes(127) + b"!", []) is None


def test_elf_loader_validates_segment_and_entry():
    from fsa.profile import _mips_elf_loader

    data = bytearray(128)
    data[:7] = b"\x7fELF\x01\x02\x01"
    struct.pack_into(">HHIII", data, 16, 2, 8, 1, 0x8000, 52)
    struct.pack_into(">HHH", data, 40, 52, 32, 1)
    struct.pack_into(">8I", data, 52, 1, 96, 0x8000, 0x8000, 32, 32, 4, 16)
    assert _mips_elf_loader(data, len(data))
    assert not _mips_elf_loader(data, len(data) - 1)
    struct.pack_into(">I", data, 24, 0x8020)
    assert not _mips_elf_loader(data, len(data))


def test_trimmed_v3_rejects_bad_checksum_or_partition_boundary():
    import hashlib
    from fsa.tplink_classic import FORMAT_V3, inspect_sysupgrade

    data = bytearray(1024)
    data[:13] = b"\x03\0\0\0ver. 2.0\0"
    struct.pack_into(">7I", data, 112, 4096, 512, 128, 640, 384, 0, 0)
    meta = {"evidence": {"offset": len(data)}}
    fs = [{"format": "SquashFS 4.0", "size_bytes": 384, "offset": 640}]
    data[64:80] = bytes.fromhex("dcd73aa5c39598fbdcf9e7f40eae4737")
    data[64:80] = hashlib.md5(data, usedforsecurity=False).digest()
    assert inspect_sysupgrade(data, meta, [], fs)["outer_format"] == FORMAT_V3
    assert inspect_sysupgrade(data, meta, [], [dict(fs[0], offset=639)]) is None
    data[-1] ^= 1
    assert inspect_sysupgrade(data, meta, [], fs) is None
