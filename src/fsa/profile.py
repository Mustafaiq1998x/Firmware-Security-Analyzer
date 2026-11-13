"""Read bounded image headers and report their claims with byte offsets."""
import json
import re
import struct
import zlib

from . import device_formats, hikvision, tplink, tplink_classic, router as router_formats


def _crc(data, start, end):
    with memoryview(data)[start:end] as view:
        return zlib.crc32(view)


def _field(value):
    if isinstance(value, str) and 0 < len(value) <= 160 and value.isprintable():
        return value
    return None


def _openwrt(data):
    end = len(data)
    for _ in range(4):
        if end < 24:
            break
        pos = end - 16
        magic, crc, kind, size = struct.unpack_from(">4sIB3xI", data, pos)
        if magic != b"FWx0" or not 24 <= size <= min(end, 65536):
            break
        if _crc(data, 0, pos) ^ 0xffffffff != crc:
            break
        start = end - size
        if kind == 0:
            end = start
            continue
        if kind != 1 or data[start:start+8] != bytes(8):
            break
        try:
            record = json.loads(data[start+8:pos])
        except (ValueError, UnicodeError, RecursionError):
            break
        if not isinstance(record, dict):
            break
        version = record.get("version")
        if not isinstance(version, dict) or version.get("dist") != "OpenWrt":
            break
        devices = record.get("supported_devices", [])
        return {
            "distribution": "OpenWrt", "os_family": "Linux",
            "release": _field(version.get("version")), "board": _field(version.get("board")),
            "target": _field(version.get("target")),
            "supported_devices": [v for v in devices[:64] if _field(v)] if isinstance(devices, list) else [],
            "evidence": {"source": "OpenWrt metadata trailer", "offset": start, "crc32_checked": True},
        }
    return None


def _uimage(data):
    if len(data) < 64 or data[:4] != bytes.fromhex("27051956"):
        return None
    header = bytearray(data[:64])
    crc, = struct.unpack_from(">I", header, 4)
    header[4:8] = bytes(4)
    size, = struct.unpack_from(">I", header, 12)
    if not 0 < size <= len(data)-64 or zlib.crc32(header) != crc:
        return None
    payload_crc, = struct.unpack_from(">I", header, 24)
    if _crc(data, 64, 64+size) != payload_crc:
        return None
    return {"format": "U-Boot legacy image", "offset": 64, "size_bytes": size,
            "scope": "payload", "name": _field(header[32:].split(b"\0")[0].decode("ascii", "replace")),
            "os": "Linux" if header[28] == 5 else None,
            "compression": {0:"none",1:"gzip",2:"bzip2",3:"lzma",4:"lzo",5:"lz4",6:"zstd"}.get(header[31]),
            "evidence": "Header and payload CRC32 at offset 0"}


def _mips_elf_loader(data, limit):
    """Check the ELF32 big-endian MIPS loader preceding a sysupgrade payload."""
    if limit < 52 or data[:7] != b"\x7fELF\x01\x02\x01":
        return False
    kind, machine, version, entry, phoff = struct.unpack_from(">HHIII", data, 16)
    header_size, stride, count = struct.unpack_from(">HHH", data, 40)
    if ((kind, machine, version, header_size, stride) != (2, 8, 1, 52, 32)
            or not 1 <= count <= 64 or not 52 <= phoff <= limit - stride * count):
        return False
    contains_entry = False
    for index in range(count):
        kind, pos, address, _, size, memory, _, _ = struct.unpack_from(">8I", data, phoff + index * stride)
        if pos + size > limit:
            return False
        if kind == 1:
            if size > memory:
                return False
            contains_entry |= address <= entry < address + size
    return contains_entry


def _squashfs(data):
    start = 0
    for _ in range(256):
        pos = data.find(b"hsqs", start)
        if pos < 0 or pos + 96 > len(data):
            return
        start = pos + 4
        inodes, _, block = struct.unpack_from("<III", data, pos+4)
        compression, log = struct.unpack_from("<HH", data, pos+20)
        major, minor = struct.unpack_from("<HH", data, pos+28)
        used, = struct.unpack_from("<Q", data, pos+40)
        inode_table, directory_table = struct.unpack_from("<QQ", data, pos+64)
        if ((major, minor) != (4, 0) or not inodes or not 12 <= log <= 20 or block != 1 << log
                or not 96 <= inode_table <= directory_table < used <= len(data)-pos):
            continue
        yield {"format":"SquashFS 4.0", "offset":pos, "size_bytes":used, "scope":"filesystem image",
               "inode_count":inodes, "compression":{1:"gzip",2:"lzma",3:"lzo",4:"xz",5:"lz4",6:"zstd"}.get(compression),
               "evidence":"Superblock version, block size, table offsets and declared length checked"}
        start = pos + used


def inspect_profile(data, tar_header, versions):
    device = device_formats.inspect(data)
    if device:
        return device
    trx = router_formats.inspect(data)
    if trx:
        trx["embedded_filesystems"] = list(_squashfs(data))
        return trx
    metadata = _openwrt(data)
    seama = router_formats.inspect_seama(data, metadata)
    if seama:
        seama["embedded_filesystems"] = list(_squashfs(data))
        return seama
    router = tplink.inspect(data, versions) or tplink_classic.inspect(data, versions, metadata)
    if router:
        router["embedded_filesystems"] = list(_squashfs(data))
        for part in router["components"]:
            if part["name"] != "os-image":
                continue
            start = part["offset"]
            header = _uimage(memoryview(data)[start:start + part["size_bytes"]])
            if header:
                identity = router["identity"]
                identity["evidence"]["uimage_header_offset"] = start
                if header["os"]:
                    identity["os_family"] = header["os"]
                architecture = {2: "ARM", 5: "MIPS", 22: "ARM64"}.get(data[start + 29])
                if architecture:
                    identity["architecture"] = architecture
                match = re.fullmatch(r"\w+ OpenWrt Linux-([0-9]+(?:\.[0-9]+){2})", header["name"] or "")
                if match:
                    identity["distribution"] = "OpenWrt"
                    if match[1] not in versions:
                        versions.append(match[1])
        return router
    index = hikvision.read_index(data)
    if index:
        identity = {"vendor": "Hikvision", "evidence": {"source": "SWKH update directory", "offset": 0}}
        for part in index["entries"]:
            start = part["offset"]
            if data[start:start+4] != bytes.fromhex("27051956"):
                continue
            with memoryview(data)[start:start + part["size_bytes"]] as member:
                header = _uimage(member)
            if header:
                part["format"] = header["format"]
                part["compression"] = header["compression"]
                part["header_name"] = header["name"]
                if header["os"]:
                    identity["os_family"] = header["os"]
                    identity["evidence"]["os_header_offset"] = start
                arch = {2:"ARM", 5:"MIPS", 22:"ARM64"}.get(data[start+29])
                if arch:
                    identity["architecture"] = arch
                match = re.search(r"\bLinux-(\d+\.\d+(?:\.\d+)?)\b", header["name"] or "")
                if match and match[1] not in versions:
                    versions.append(match[1])
        return {"outer_format": hikvision.FORMAT, "identity": identity, "components": index["entries"],
                "directory_bytes": index["directory_bytes"], "trailing_bytes": index["trailing_bytes"],
                "encryption": {"status": "undetermined", "algorithm": None,
                               "evidence": "SWKH directory encoding does not establish payload encryption."}}
    identity = metadata or {}
    uimage = _uimage(data)
    filesystems = list(_squashfs(data))
    trimmed = tplink_classic.inspect_sysupgrade(data, metadata, versions, filesystems)
    if trimmed:
        return trimmed
    components = ([uimage] if uimage else []) + filesystems
    if uimage and uimage["os"]:
        identity.setdefault("os_family", uimage["os"])
        identity.setdefault("evidence", {"source":"U-Boot OS field", "offset":28})
        match = re.search(r"\bLinux-(\d+\.\d+(?:\.\d+)?)\b", uimage["name"] or "")
        if match and match[1] not in versions:
            versions.append(match[1])
    if not identity.get("os_family") and versions:
        identity["os_hint"] = "Linux"
        identity["evidence"] = {"source":"kernel version string"}
    outer = "unknown"
    if tar_header:
        outer = "TAR"
    elif uimage:
        outer = uimage["format"]
    elif components and components[0]["offset"] == 0:
        outer = components[0]["format"]
    elif data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        outer = "ZIP header marker"
    elif data[:3] == b"\x1f\x8b\x08" and len(data) >= 18 and not data[3] & 0xe0:
        outer = "gzip header"
    if outer == "unknown" and metadata and _mips_elf_loader(data, metadata["evidence"]["offset"]):
        outer = "OpenWrt sysupgrade (MIPS ELF loader)"
        identity["architecture"] = "MIPS (32-bit big-endian ELF)"
        identity["evidence"]["elf_header_offset"] = 0
    crypto = {"status":"undetermined", "algorithm":None,
              "evidence":"No recognized encryption header. Compressed or high-entropy bytes alone are inconclusive."}
    if len(data) >= 592 and data[:8] == b"LUKS\xba\xbe\x00\x01":
        cipher, mode = [v.split(b"\0")[0].decode("ascii", "replace") for v in (data[8:40], data[40:72])]
        sector, key_bytes = struct.unpack_from(">II", data, 104)
        if (_field(cipher) and _field(mode) and 0 < key_bytes <= 1024 and 592 <= sector*512 < len(data)):
            outer = "LUKS1"
            crypto = {"status":"encrypted container declared", "algorithm":cipher, "mode":mode,
                      "evidence":"LUKS1 header at offset 0, cipher and mode fields, payload offset within input"}
    return {"outer_format":outer, "identity":identity, "components":components, "encryption":crypto}


def inspect_zip(path, profile):
    """Describe the ZIP layer from bounded metadata without opening member data."""
    import stat
    import zipfile
    from .extraction import ExtractionLimits, _zip_central_directory_info

    limits = ExtractionLimits()
    try:
        _zip_central_directory_info(path, limits.max_files + limits.max_directories,
                                    limits.max_central_directory_bytes)
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            encrypted = sum(bool(e.flag_bits & 1) for e in entries)
            regular = sum(not e.is_dir() and not e.external_attr & 0x10 and
                          stat.S_IFMT(e.external_attr >> 16) in (0, stat.S_IFREG) for e in entries)
    except (OSError, ValueError, zipfile.BadZipFile, NotImplementedError):
        return
    profile["outer_format"] = "ZIP"
    profile["zip_inventory"] = {"declared_entries":len(entries),"regular_members":regular}
    profile["encryption"] = {
        "status":"encrypted ZIP members declared" if encrypted else "no ZIP-layer encryption declared",
        "algorithm":None, "encrypted_members":encrypted,
        "evidence":"General-purpose encryption flags in the bounded ZIP central directory; applies only to the ZIP layer.",
    }
