"""Bounded readers for UF2 flash blocks and standalone Microsoft cabinets."""
import re
import struct
import zlib

UF2 = "UF2 flash image"
CAB = "Microsoft Cabinet"
_BANNER = re.compile(rb"Adafruit CircuitPython ([0-9][a-zA-Z0-9.\\-]{0,24}) on [0-9-]{10}; ([ -~]{1,96}?) with ([a-zA-Z0-9_-]{1,32})\x00")


def uf2(data):
    count, remainder = divmod(len(data), 512)
    if remainder or not 1 <= count <= 65536:
        return None
    runs = []
    previous_end = None
    family = None
    decoded = bytearray()
    for index in range(count):
        pos = index * 512
        a, b, flags, address, size, number, total, tag = struct.unpack_from("<8I", data, pos)
        if ((a, b) != (0x0a324655, 0x9e5d5157) or data[pos+508:pos+512] != b"0o\xb1\x0a"
                or flags not in (0, 0x2000) or number != index or total != count
                or not 1 <= size <= 476 or address + size > 1 << 32):
            return None
        if index and (family != (flags, tag) or address < previous_end):
            return None
        family = flags, tag
        if previous_end != address or runs[-1]["block_payload_bytes"] != size:
            if len(runs) >= 256:
                return None
            runs.append({"name": f"flash-{address:08x}", "format": "UF2 flash payload",
                         "scope": "contiguous flash range", "offset": pos + 32, "flash_address": address,
                         "size_bytes": 0, "block_payload_bytes": size, "compression": None})
        runs[-1]["size_bytes"] += size
        decoded.extend(data[pos+32:pos+32+size])
        previous_end = address + size
    evidence = {"source": "UF2 block headers, ordered addresses and block count", "block_count": count}
    if family[0]:
        evidence["uf2_family_id"] = hex(family[1])
    identity = {"evidence": evidence}
    banner = _BANNER.search(decoded)
    if banner:
        identity.update(distribution="CircuitPython", release=banner[1].decode(),
                        supported_devices=[banner[2].decode()], target=banner[3].decode())
        evidence["banner_offset_in_decoded_payload"] = banner.start()
    return {"outer_format": UF2, "components": runs, "identity": identity,
            "encryption": {"status": "undetermined", "algorithm": None,
                           "evidence": "UF2 does not declare a payload cipher."}}


def cabinet(data):
    if len(data) < 44 or data[:4] != b"MSCF":
        return None
    reserved, size, reserved2, files, reserved3, minor, major, folders, entries, flags = struct.unpack_from("<5I2B3H", data, 4)
    if (size != len(data) or any((reserved, reserved2, reserved3, flags)) or (minor, major) != (3, 1)
            or not 1 <= folders <= 1024 or not 1 <= entries <= 10000 or not 36 + 8 * folders <= files < size):
        return None
    starts = []
    for index in range(folders):
        start, blocks, method = struct.unpack_from("<IHH", data, 36 + index * 8)
        if not files < start <= size - 8 or not blocks or method & 15 > 3:
            return None
        starts.append(start)
    pos, limit = files, min(starts)
    for _ in range(entries):
        if pos + 17 > limit or int.from_bytes(data[pos+8:pos+10], "little") >= folders:
            return None
        end = data.find(b"\x00", pos + 16, min(limit, pos + 1041))
        if end <= pos + 16:
            return None
        pos = end + 1
    return {"outer_format": CAB, "components": [], "identity": {"evidence": {
        "source": "CAB header, folder bounds and file directory", "declared_files": entries}},
        "encryption": {"status": "undetermined", "algorithm": None, "evidence": "Directory inspection only."}}


def rockbox(archive, entries):
    """Read the small release manifest and corroborate its firmware member."""
    import zipfile

    manifests = [e for e in entries if e.filename == ".rockbox/rockbox-info.txt"]
    if len(manifests) != 1:
        return None
    info = manifests[0]
    if (info.flag_bits & 1 or not 0 < info.file_size <= 8192 or info.compress_size > 8192
            or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
        return None
    try:
        text = archive.read(info).decode("ascii")
    except (ValueError, OSError, RuntimeError, zipfile.BadZipFile, zlib.error):
        return None
    fields = dict(line.split(": ", 1) for line in text.splitlines() if ": " in line)
    for key in ("Target", "Version", "Binary"):
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", fields.get(key, "")):
            return None
    binary = [e for e in entries if e.filename == ".rockbox/" + fields["Binary"]]
    if len(binary) != 1 or str(binary[0].file_size) != fields.get("Binary size"):
        return None
    return {"distribution": "Rockbox", "release": fields["Version"], "board": fields["Target"],
            "device_class": "Digital audio player", "evidence": {"source": info.filename,
            "firmware_member": binary[0].filename, "binary_size": binary[0].file_size}}
