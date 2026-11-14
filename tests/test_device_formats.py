import struct

import pytest

from fsa.device_formats import inspect


@pytest.mark.parametrize("version", [3, 4])
def test_android_sections(version):
    image = bytearray(8195)
    image[:8] = b"ANDROID!"
    struct.pack_into("<4I", image, 8, 17, 3, 0, 1580 + 4 * (version == 4))
    struct.pack_into("<I", image, 40, version)
    assert [p["offset"] for p in inspect(image)["components"]] == [4096, 8192]
    assert inspect(image[:-1]) is None
    image[24] = 1
    assert inspect(image) is None


def test_hex_checks_every_record_and_real_eof():
    stream = b":0100000042BD\r\n:00000001FF\r\n"
    assert len(inspect(stream * 2)["components"]) == 2
    assert inspect(stream.replace(b"BD", b"BC")) is None
    assert inspect(stream.splitlines()[0]) is None


def test_uefi_block_map_and_checksum():
    image = bytearray(4096)
    struct.pack_into("<Q4s", image, 32, 4096, b"_FVH")
    struct.pack_into("<H", image, 48, 72)
    image[55] = 2
    struct.pack_into("<II", image, 56, 1, 4096)
    checksum = -sum(struct.unpack_from("<36H", image)) & 65535
    struct.pack_into("<H", image, 50, checksum)
    assert inspect(image)["components"][0]["size_bytes"] == 4096
    assert inspect(image[:-1]) is None
    image[20] ^= 1
    assert inspect(image) is None
