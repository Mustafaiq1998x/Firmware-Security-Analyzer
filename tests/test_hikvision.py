import struct
import zipfile

from fsa.analyzer import scan_file
from fsa.unpack import unpack_image


def synthetic_update():
    data = b"fixture"
    header = bytearray(108)
    struct.pack_into("<4sIII", header, 0, b"SWKH", 0, len(header), 1)
    struct.pack_into("<32sIII", header, 64, b"config", len(header), len(data), sum(data))
    struct.pack_into("<I", header, 4, sum(header[12:]))
    mask = bytes.fromhex("bacdbcfed6caddd3bab9a3abbfcbb5be")
    return bytes(b ^ mask[(i + i//16) % 16] for i, b in enumerate(header)) + data


def test_index_is_content_based_and_export_is_byte_exact(tmp_path):
    path = tmp_path / "renamed.img"
    path.write_bytes(synthetic_update())
    report = scan_file(path)
    profile = report["analysis"]["firmware_profile"]
    assert profile["outer_format"] == "Hikvision SWKH update"
    assert profile["components"][0]["name"] == "config"
    manifest = unpack_image(path, tmp_path / "out", report)
    assert (tmp_path / "out" / manifest["entries"][0]["path"]).read_bytes() == b"fixture"


def test_truncated_changed_or_corrupt_directory_is_rejected(tmp_path):
    path = tmp_path / "digicap.dav"
    data = synthetic_update()
    for bad in (data[:20], data[:-1], data[:-1]+b"!", data[:9]+b"X"+data[10:]):
        path.write_bytes(bad)
        assert scan_file(path)["analysis"]["firmware_profile"]["outer_format"] == "unknown"


def test_desktop_reads_single_dav_in_zip(tmp_path):
    from fsa.scan_worker import inspect_upload
    import asyncio

    path = tmp_path / "update.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("upgrade/digicap.dav", synthetic_update())

    async def connected():
        return False
    result = asyncio.run(inspect_upload(path, tmp_path, 4096, True, connected))
    assert result["analysis"]["firmware_profile"]["outer_format"] == "ZIP"
    assert result["packaged_firmware"]["firmware_profile"]["identity"]["vendor"] == "Hikvision"
