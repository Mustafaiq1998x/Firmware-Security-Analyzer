"""Read bounded Android boot, UEFI firmware-volume and Intel HEX structures."""
import binascii
import struct
import json
from functools import lru_cache
from importlib.resources import files

ANDROID = "Android boot image"
UEFI = "UEFI firmware volumes"
HEX = "Intel HEX"
FORMATS = {ANDROID, UEFI, HEX}


def _part(name, kind, offset, size):
    return {"name": name, "format": kind, "offset": offset, "size_bytes": size,
            "compression": None, "scope": "image component"}


def _report(kind, parts, evidence, **identity):
    return {"outer_format": kind, "components": parts, "identity": dict(identity, evidence=evidence),
            "encryption": {"status": "undetermined", "algorithm": None,
                           "evidence": "Container metadata does not establish payload encryption."}}


def _android(data):
    if len(data) < 1580:
        return None
    version, = struct.unpack_from("<I", data, 40)
    if version not in (3, 4):
        return None
    kernel, ramdisk, _, header = struct.unpack_from("<4I", data, 8)
    if header != (1580 if version == 3 else 1584) or len(data) < header or any(data[24:40]):
        return None
    sizes = [("kernel", kernel), ("ramdisk", ramdisk)]
    if version == 4:
        sizes.append(("boot-signature", struct.unpack_from("<I", data, 1580)[0]))
    if not kernel and not ramdisk:
        return None
    parts = []
    pos = 4096
    for name, size in sizes:
        if size:
            if pos + size > len(data):
                return None
            parts.append(_part(name, "Android boot component", pos, size))
            pos += (size + 4095) & ~4095
    return _report(ANDROID, parts, {"source": "Android boot header", "version": version,
                                     "header_size": header}, os_family="Android")


def _uefi(data):
    pos = 0
    parts = []
    while pos < len(data):
        if len(parts) >= 256 or len(data) - pos < 72 or data[pos+40:pos+44] != b"_FVH":
            return None
        size, = struct.unpack_from("<Q", data, pos + 32)
        header, = struct.unpack_from("<H", data, pos + 48)
        if not 72 <= header <= size <= len(data) - pos or header % 2 or data[pos + 55] != 2:
            return None
        words = struct.unpack_from(f"<{header // 2}H", data, pos)
        if sum(words) & 0xffff:
            return None
        total = 0
        for off in range(pos + 56, pos + header - 7, 8):
            blocks, length = struct.unpack_from("<II", data, off)
            if not blocks and not length:
                break
            if not blocks or not length:
                return None
            total += blocks * length
        else:
            return None
        if total != size:
            return None
        parts.append(_part(f"volume-{len(parts)+1}", "UEFI firmware volume", pos, size))
        pos += size
    return _report(UEFI, parts, {"source": "FV signatures, header checksums and block maps"})


def _hex(data):
    if len(data) > 32 << 20:
        return None
    start = pos = records = payload_bytes = 0
    parts = []
    while pos < len(data):
        end = data.find(b"\n", pos, pos + 524)
        if end < 0:
            end = len(data)
        line = data[pos:end].rstrip(b"\r")
        if not 11 <= len(line) <= 521 or line[:1] != b":" or records >= 500000:
            return None
        try:
            record = binascii.unhexlify(line[1:])
        except binascii.Error:
            return None
        length, address, kind = struct.unpack_from(">BHB", record)
        if len(record) != length + 5 or sum(record) & 255:
            return None
        pos = min(end + 1, len(data))
        records += 1
        if kind == 0:
            payload_bytes += length
        elif address or kind not in (1, 2, 3, 4, 5) or length != {1:0, 2:2, 3:4, 4:2, 5:4}[kind]:
            return None
        if kind == 1:
            if not payload_bytes or len(parts) >= 64:
                return None
            parts.append(_part(f"hex-stream-{len(parts)+1}", "Intel HEX text stream", start, pos-start))
            start, payload_bytes = pos, 0
    if start != len(data) or not parts:
        return None
    return _report(HEX, parts, {"source": "Record lengths, checksums and end-of-file records",
                                "records": records})


def inspect(data):
    if data[:8] == b"ANDROID!":
        return _android(data)
    if data[40:44] == b"_FVH":
        return _uefi(data)
    if data[:1] == b":":
        return _hex(data)
    return None


@lru_cache(maxsize=1)
def _published_images():
    return json.loads(files("fsa").joinpath("assets", "device-images.json").read_text(encoding="utf-8"))


def identify(profile, digest):
    image = _published_images().get(digest)
    if image:
        identity = profile["identity"]
        identity.update({k: v for k, v in image.items() if k != "source"})
        identity.setdefault("evidence", {})["published_image"] = {"sha256": digest, "source": image["source"]}
