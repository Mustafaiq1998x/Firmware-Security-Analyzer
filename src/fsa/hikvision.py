"""Bounded identification of indexed Hikvision SWKH update containers."""
import re
import struct


FORMAT = "Hikvision SWKH update"
_MASK = bytes.fromhex("bacdbcfed6caddd3bab9a3abbfcbb5be")
_RECORD = struct.Struct("<32sIII")


def _header(data, size):
    return bytes(data[i] ^ _MASK[(i + i // 16) % 16] for i in range(size))


def read_index(data):
    if len(data) < 64 or data[:4] != b"\xe9\x9a\xf7\xb6":
        return None
    prefix = _header(data, 64)
    magic, checksum, length, count = struct.unpack_from("<4sIII", prefix)
    if (magic != b"SWKH" or not 0 < count <= 1024 or
            length != 64 + count * _RECORD.size or length > len(data)):
        return None
    table = _header(data, length)
    if sum(table[12:]) != checksum:
        return None
    entries = []
    previous_end = length
    for raw_name, offset, size, expected_sum in _RECORD.iter_unpack(table[64:]):
        name = raw_name.partition(b"\0")[0]
        if (not re.fullmatch(rb"[a-zA-Z0-9_.+-]{1,32}", name) or name in (b".", b"..")
                or size == 0 or offset < previous_end or offset + size > len(data)):
            return None
        with memoryview(data)[offset:offset + size] as payload:
            if sum(payload) & 0xffffffff != expected_sum:
                return None
        entries.append({"format": "SWKH entry", "name": name.decode("ascii"), "offset": offset,
                        "size_bytes": size, "scope": "stored update entry", "compression": None,
                        "evidence": "Validated directory bounds and stored-byte checksum"})
        previous_end = offset + size
    return {"entries": entries, "directory_bytes": length, "trailing_bytes": len(data) - previous_end}
