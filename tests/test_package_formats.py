import io
import struct
import tarfile

from fsa.analyzer import scan_file
from fsa.package_formats import uf2
from fsa.unpack import unpack_image


def block(number, address, payload):
    raw = bytearray(512)
    struct.pack_into("<8I", raw, 0, 0x0a324655, 0x9e5d5157, 0x2000, address, len(payload), number, 2, 123)
    raw[32:32+len(payload)] = payload
    struct.pack_into("<I", raw, 508, 0x0ab16f30)
    return raw


def test_uf2_export_skips_block_framing(tmp_path):
    first = block(0, 0x1000, b"abcd")
    second = block(1, 0x1004, b"efgh")
    source = tmp_path / "neutral"
    source.write_bytes(first + second)
    report = scan_file(source)
    dest = tmp_path / "out"
    entry = unpack_image(source, dest, report)["entries"][0]
    assert (dest / entry["path"]).read_bytes() == b"abcdefgh"
    assert uf2(first + first) is None
    assert uf2(first + second[:-1]) is None
    assert uf2(first + block(1, 0x1001, b"overlap")) is None


def test_gzip_tar_can_be_exported(tmp_path):
    path = tmp_path / "neutral"
    with tarfile.open(path, "w:gz") as archive:
        member = tarfile.TarInfo("firmware.bin")
        member.size = 4
        archive.addfile(member, io.BytesIO(b"demo"))
    report = scan_file(path)
    assert report["analysis"]["firmware_profile"]["outer_format"] == "gzip-compressed TAR"
    unpack_image(path, tmp_path / "out", report)
    assert (tmp_path / "out/firmware.bin").read_bytes() == b"demo"


def test_cabinet_requires_directory_and_folder_reference():
    from fsa.package_formats import cabinet
    data = bytearray(77)
    struct.pack_into("<4s5I2B5H", data, 0, b"MSCF", 0, 77, 0, 44, 0, 3, 1, 1, 1, 0, 0, 0)
    struct.pack_into("<IHH", data, 36, 68, 1, 0)
    data[60:67] = b"up.bin\0"
    assert cabinet(data)["identity"]["evidence"]["declared_files"] == 1
    struct.pack_into("<H", data, 52, 1)
    assert cabinet(data) is None


def test_rockbox_metadata_requires_matching_binary_size(tmp_path):
    import zipfile
    for declared in (4, 12):
        path = tmp_path / f"{declared}.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(".rockbox/rockbox-info.txt",
                             f"Target: sample\nVersion: 3.15\nBinary: rockbox.bin\nBinary size: {declared}\n")
            archive.writestr(".rockbox/rockbox.bin", b"test")
        identity = scan_file(path)["analysis"]["firmware_profile"]["identity"]
        assert (identity.get("board") == "sample") == (declared == 4)


def test_bbf_checks_digest_and_record_bounds():
    import hashlib
    from fsa.device_formats import inspect
    image = bytearray(576) + b"code"
    image[112] = 2
    image[96:100] = (4).to_bytes(4, "little")
    image[64:96] = hashlib.sha256(image[96:]).digest()
    image.extend(b"\x09\x03\0\0\0abc")
    assert [p["size_bytes"] for p in inspect(image)["components"]] == [4, 3]
    assert inspect(image[:-1]) is None
    image[576] ^= 1
    assert inspect(image) is None
