import struct
import zipfile
import zlib

import pytest

from fsa.analyzer import scan_file
from fsa.profile import inspect_profile
from fsa.unpack import unpack_image


@pytest.mark.parametrize("suffix", [".bin", ".dav"])
def test_archive_identity_and_unpack_are_content_based(tmp_path, suffix):
    path = tmp_path / ("camera" + suffix)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("etc/config", b"example")
    report = scan_file(path)
    profile = report["analysis"]["firmware_profile"]
    assert profile["outer_format"] == "ZIP"
    assert profile["zip_inventory"]["regular_members"] == 1
    assert profile["encryption"]["status"] == "no ZIP-layer encryption declared"
    out = tmp_path / "files"
    assert unpack_image(path, out, report)["summary"]["files"] == 1
    assert (out / "etc/config").read_bytes() == b"example"


def test_unknown_dav_does_not_claim_a_model_or_cipher(tmp_path):
    path = tmp_path / "camera.dav"
    path.write_bytes(bytes(range(256)) * 8)
    a = scan_file(path)["analysis"]
    assert a["firmware_profile"]["identity"] == {}
    assert a["firmware_profile"]["encryption"]["status"] == "undetermined"
    assert a["cve_assessment"] == "not assessed: no feed"


def test_component_export_requires_checked_crc(tmp_path):
    payload = b"sample data"
    header = bytearray(64)
    struct.pack_into(">I", header, 0, 0x27051956)
    struct.pack_into(">I", header, 12, len(payload))
    struct.pack_into(">I", header, 24, zlib.crc32(payload))
    header[28] = 5
    struct.pack_into(">I", header, 4, zlib.crc32(header))
    path = tmp_path / "demo.bin"
    path.write_bytes(header + payload)
    report = scan_file(path)
    out = tmp_path / "out"
    manifest = unpack_image(path, out, report)
    assert manifest["summary"]["files"] == 1
    assert (out / manifest["entries"][0]["path"]).read_bytes() == payload
    path.write_bytes(header + payload[::-1])
    assert not scan_file(path)["analysis"]["firmware_profile"]["components"]


def test_luks1_header_with_payload_boundary():
    data = bytearray(2048)
    data[:8] = b"LUKS\xba\xbe\x00\x01"
    data[8:11] = b"aes"
    data[40:45] = b"xts-x"
    struct.pack_into(">II", data, 104, 2, 32)
    assert inspect_profile(data, None, [])["encryption"]["algorithm"] == "aes"
    assert inspect_profile(data[:592], None, [])["encryption"]["algorithm"] is None

def test_device_advisory_requires_exact_board_and_release():
    from fsa.cve import match_device_cves
    identity = {"board": "fixture-v1", "distribution": "Demo", "release": "1.0"}
    row = {"component": "device-firmware", **identity, "cve": "CVE-2024-0001",
           "advisory_url": "https://example.org/test-fixture"}
    assert match_device_cves(identity, [row])[0]["status"] == "needs_manual_validation"
    assert match_device_cves({**identity, "board": "fixture-v2"}, [row]) == []
    assert match_device_cves({**identity, "release": "1.1"}, [row]) == []
