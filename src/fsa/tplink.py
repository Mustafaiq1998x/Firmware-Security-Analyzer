"""Read TP-Link Cloud SafeLoader tables and bounded Broadcom kernel metadata."""
import lzma
import re

FORMAT = "TP-Link SafeLoader (Cloud)"
BASE = 0x1014
TABLE_SIZE = 0x800
ROW = re.compile(rb"fwup-ptn ([a-zA-Z0-9_-]{1,48}) base 0x([0-9a-fA-F]{1,8}) size 0x([0-9a-fA-F]{1,8})")


def _metadata(data, part):
    pos, size = part["offset"], part["size_bytes"]
    if size < 8:
        return b""
    length = int.from_bytes(data[pos:pos+4], "big")
    return data[pos+8:pos+8+length] if length <= min(size-8, 65536) else b""


def _broadcom(data, part, identity, versions):
    pos, size = part["offset"], part["size_bytes"]
    header = data[pos:pos+min(size, 256)]
    if len(header) != 256 or not header.startswith(b"7\0\0\0Broadcom Corporatio\0"):
        return
    board = header[44:60].split(b"\0")[0]
    if re.fullmatch(rb"[a-zA-Z0-9_-]{1,16}", board):
        identity["board"] = board.decode()
        identity["evidence"]["board_header_offset"] = pos + 44
    root_size = header[106:116].split(b"\0")[0]
    kernel_size = header[128:138].split(b"\0")[0]
    if not root_size.isdigit() or not kernel_size.isdigit():
        return
    kernel = pos + 256 + int(root_size)
    length = int(kernel_size)
    if not 34 <= length <= 8 << 20 or kernel + length > pos + size or data[kernel+12:kernel+16] != b"BRCM":
        return
    try:
        reader = lzma.LZMADecompressor(lzma.FORMAT_ALONE, memlimit=32 << 20)
        image = reader.decompress(data[kernel+20:kernel+length], max_length=(16 << 20)+1)
    except lzma.LZMAError:
        return
    if not reader.eof or len(image) > 16 << 20:
        return
    banner = re.search(rb"Linux version (\d+\.\d+\.\d+)(?=[ -])", image)
    if banner:
        version = banner[1].decode()
        if version not in versions:
            versions.append(version)
        identity["os_family"] = "Linux"
        identity["evidence"]["kernel"] = {"compression":"LZMA", "offset":kernel+20,
                                         "banner_offset_in_decoded_kernel":banner.start()}
        marker = image.find(b"ARMv7 Processor\0")
        if marker >= 0:
            identity["architecture"] = "ARMv7 (kernel processor string)"
            identity["evidence"]["processor_string_offset_in_decoded_kernel"] = marker


def inspect(data, versions):
    if (len(data) < BASE + TABLE_SIZE or data[20:34] != b"fw-type:Cloud\n"
            or int.from_bytes(data[:4], "big") != len(data)):
        return None
    directory = data[BASE:BASE+TABLE_SIZE]
    end = directory.find(b"\0")
    if end < 0:
        return None
    parts = {}
    for line in directory[:end].splitlines():
        match = ROW.fullmatch(line.strip())
        if not match:
            return None
        name = match[1].decode()
        relative, length = int(match[2], 16), int(match[3], 16)
        offset = BASE + relative
        if (relative < TABLE_SIZE or not length or offset+length > len(data) or name in parts):
            return None
        parts[name] = {"name":name, "format":"SafeLoader partition", "offset":offset,
                       "size_bytes":length, "compression":None, "scope":"update partition"}
    ordered = sorted(parts.values(), key=lambda p:p["offset"])
    if (not {"os-image", "support-list", "soft-version"} <= parts.keys() or
            any(a["offset"]+a["size_bytes"] > b["offset"] for a,b in zip(ordered, ordered[1:]))):
        return None
    identity = {"vendor":"TP-Link", "evidence":{"source":"Cloud header and bounded fwup-ptn directory",
                                                "offset":BASE}}
    support = _metadata(data, parts["support-list"])
    if support.startswith(b"SupportList:"):
        devices = re.findall(rb"\{product_name:([\w .+-]{1,48}),product_ver:([\d.]{1,16}),special_id:[a-fA-F0-9]{8}\}", support)
        if devices:
            identity["supported_devices"] = list(dict.fromkeys(n.decode()+" v"+v.decode() for n,v in devices))
            identity["evidence"]["support_list_offset"] = parts["support-list"]["offset"]
    soft = re.match(rb"soft_ver:([\d.]{1,20}) Build (\d{8}) Rel\. (\d{1,8})(?:\r?\n|\0)", _metadata(data, parts["soft-version"]))
    if soft:
        identity["release"] = soft[1].decode()
        identity["build"] = soft[2].decode()+" rel."+soft[3].decode()
        identity["evidence"]["soft_version_offset"] = parts["soft-version"]["offset"]
    _broadcom(data, parts["os-image"], identity, versions)
    return {"outer_format":FORMAT, "identity":identity, "components":ordered,
            "directory_bytes":TABLE_SIZE, "partition_count":len(parts),
            "encryption":{"status":"not established for the complete image","algorithm":None,
                          "evidence":"Readable update directory; encryption of individual partitions is not assessed."}}
