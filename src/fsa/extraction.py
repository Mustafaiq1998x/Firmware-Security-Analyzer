"""Bounded, non-recursive extraction for untrusted ZIP and TAR archives.

The extractor is deliberately conservative: it never invokes external tools,
never follows archive links, and enforces resource limits while bytes are read.
It is a safe archive primitive, not a general firmware filesystem unpacker.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import stat
import struct
import tarfile
import time
import unicodedata
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import BinaryIO


@dataclass(frozen=True)
class ExtractionLimits:
    max_archive_bytes: int = 64 * 1024 * 1024
    max_central_directory_bytes: int = 16 * 1024 * 1024
    max_total_bytes: int = 512 * 1024 * 1024
    max_file_bytes: int = 128 * 1024 * 1024
    max_files: int = 20_000
    max_directories: int = 10_000
    max_depth: int = 64
    max_compression_ratio: float = 200.0
    max_seconds: float = 120.0
    chunk_bytes: int = 1024 * 1024
    max_tar_metadata_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        integer_fields = (
            "max_archive_bytes", "max_central_directory_bytes", "max_total_bytes",
            "max_tar_metadata_bytes", "max_file_bytes", "max_files", "max_directories", "max_depth", "chunk_bytes",
        )
        for name in integer_fields:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        for name in ("max_seconds", "max_compression_ratio"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ValueError(f"{name} must be finite")
        if self.max_seconds <= 0:
            raise ValueError("max_seconds must be positive")
        if self.max_compression_ratio < 1:
            raise ValueError("max_compression_ratio must be at least 1")


class ExtractionError(ValueError):
    """Archive rejected or extraction aborted by a safety limit."""


def _safe_parts(name: str) -> tuple[str, ...]:
    if not name or "\x00" in name:
        raise ExtractionError("empty or NUL-containing path")
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith("//"):
        raise ExtractionError("absolute or UNC path")
    if re.match(r"^[A-Za-z]:", normalized):
        raise ExtractionError("Windows drive path")
    parts = normalized.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ExtractionError("path traversal or non-canonical path")
    if any(part.endswith((".", " ")) for part in parts):
        raise ExtractionError("Windows-ambiguous path component")
    reserved = {
        "CON", "PRN", "AUX", "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
    for part in parts:
        stem = part.split(".", 1)[0].upper()
        if stem in reserved or any(ch in part for ch in '<>:\\"|?*'):
            raise ExtractionError("Windows-reserved or ambiguous path component")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in part):
            raise ExtractionError("control character in path")
    return tuple(parts)


def _archive_name(name: str, is_dir: bool) -> str | None:
    """Normalize conventional TAR ./ prefixes and directory terminators."""
    normalized = name.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized.startswith("/"):
        raise ExtractionError("absolute or UNC path")
    if is_dir and normalized.endswith("/"):
        normalized = normalized[:-1]
    if normalized in ("", ".") and is_dir:
        return None
    return normalized


def _zip_central_directory_info(path: Path, max_entries: int,
                                max_directory_bytes: int) -> tuple[int, int]:
    """Bound ZIP metadata before ZipFile.infolist() allocates ZipInfo objects.

    Supports ordinary and ZIP64 end records. The central-directory records
    themselves are counted, rather than trusting only the EOCD count field.
    Multi-disk ZIP files are rejected.
    """
    size = path.stat().st_size
    tail_size = min(size, 22 + 65535)
    with path.open("rb") as handle:
        handle.seek(size - tail_size)
        tail = handle.read(tail_size)
        eocd_index = tail.rfind(b"PK\x05\x06")
        if eocd_index < 0 or len(tail) - eocd_index < 22:
            raise ExtractionError("invalid ZIP: end-of-central-directory record not found")
        eocd_offset = size - tail_size + eocd_index
        fields = struct.unpack_from("<4s4H2LH", tail, eocd_index)
        _, disk_no, cd_disk, entries_disk, entries_total, cd_size, cd_offset, comment_len = fields
        if eocd_index + 22 + comment_len != len(tail):
            raise ExtractionError("invalid ZIP: truncated archive comment")
        if disk_no != 0 or cd_disk != 0 or entries_disk != entries_total:
            raise ExtractionError("multi-disk ZIP archives are not supported")

        directory_boundary = eocd_offset
        needs_zip64 = (
            entries_disk == 0xFFFF or entries_total == 0xFFFF
            or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF
        )
        locator_offset = eocd_offset - 20
        has_locator = False
        if locator_offset >= 0:
            handle.seek(locator_offset)
            has_locator = handle.read(4) == b"PK\x06\x07"
        if needs_zip64 or has_locator:
            if locator_offset < 0:
                raise ExtractionError("invalid ZIP64 locator")
            handle.seek(locator_offset)
            locator = handle.read(20)
            if len(locator) != 20:
                raise ExtractionError("truncated ZIP64 locator")
            sig, locator_disk, zip64_offset, total_disks = struct.unpack("<4sLQL", locator)
            if sig != b"PK\x06\x07" or locator_disk != 0 or total_disks != 1:
                raise ExtractionError("multi-disk or invalid ZIP64 archive")
            if zip64_offset + 56 != locator_offset:
                raise ExtractionError("unsupported ZIP64 end-record layout")
            handle.seek(zip64_offset)
            header = handle.read(56)
            if len(header) != 56:
                raise ExtractionError("truncated ZIP64 end record")
            values = struct.unpack("<4sQ2H2L4Q", header)
            if values[0] != b"PK\x06\x06" or values[1] != 44:
                raise ExtractionError("invalid ZIP64 end record")
            disk_no, cd_disk = values[4], values[5]
            entries_disk, entries_total, cd_size, cd_offset = values[6:10]
            if disk_no != 0 or cd_disk != 0 or entries_disk != entries_total:
                raise ExtractionError("multi-disk ZIP64 archives are not supported")
            if cd_offset + cd_size != zip64_offset:
                raise ExtractionError("invalid ZIP64 directory bounds")
            directory_boundary = zip64_offset

        if entries_total > max_entries:
            raise ExtractionError("archive entry count limit exceeded")
        if cd_size > max_directory_bytes:
            raise ExtractionError("ZIP central-directory size limit exceeded")
        if cd_size > size or cd_offset > size or cd_offset + cd_size > size:
            raise ExtractionError("invalid ZIP central-directory bounds")

        # zipfile accounts for self-extracting prefixes by shifting the
        # recorded central-directory offset. Its effective start is the end
        # record location minus the declared central-directory size.
        directory_start = directory_boundary - cd_size
        if directory_start < 0 or directory_start < cd_offset:
            raise ExtractionError("invalid ZIP central-directory offset")
        handle.seek(directory_start)
        cursor = directory_start
        actual_entries = 0
        while cursor < directory_boundary:
            fixed = handle.read(46)
            if len(fixed) != 46 or fixed[:4] != b"PK\x01\x02":
                raise ExtractionError("invalid ZIP central-directory record")
            filename_len, extra_len, entry_comment_len = struct.unpack_from("<HHH", fixed, 28)
            disk_start = struct.unpack_from("<H", fixed, 34)[0]
            if disk_start != 0:
                raise ExtractionError("multi-disk ZIP entries are not supported")
            record_size = 46 + filename_len + extra_len + entry_comment_len
            cursor += record_size
            if cursor > directory_boundary:
                raise ExtractionError("truncated ZIP central-directory entry")
            handle.seek(cursor)
            actual_entries += 1
            if actual_entries > max_entries:
                raise ExtractionError("archive entry count limit exceeded")

        if actual_entries != entries_total:
            raise ExtractionError("ZIP central-directory entry count mismatch")
    return int(actual_entries), int(cd_size)


def _copy_limited(src: BinaryIO, dst: BinaryIO, *, expected: int | None,
                  state: dict, limits: ExtractionLimits, deadline: float) -> tuple[int, str]:
    written = 0
    digest = hashlib.sha256()
    while True:
        if time.monotonic() > deadline:
            raise ExtractionError("extraction time limit exceeded")
        chunk = src.read(limits.chunk_bytes)
        if not chunk:
            break
        written += len(chunk)
        state["total_bytes"] += len(chunk)
        if written > limits.max_file_bytes:
            raise ExtractionError("single-file size limit exceeded")
        if state["total_bytes"] > limits.max_total_bytes:
            raise ExtractionError("total extracted size limit exceeded")
        if expected is not None and written > expected:
            raise ExtractionError("entry expanded beyond declared size")
        dst.write(chunk)
        digest.update(chunk)
    if expected is not None and written != expected:
        raise ExtractionError("entry size does not match declared size")
    return written, digest.hexdigest()


def safe_extract_archive(archive: str | Path, destination: str | Path,
                         limits: ExtractionLimits | None = None) -> dict:
    """Extract ZIP or TAR into a new/empty destination, without recursion.

    On any failure, only filesystem objects created by this invocation are
    removed. Destination must not be a symlink and must not contain files.
    """
    limits = limits or ExtractionLimits()
    source = Path(archive)
    if not source.is_file() or source.is_symlink():
        raise ExtractionError("archive must be a regular, non-symlink file")
    archive_size = source.stat().st_size
    if archive_size > limits.max_archive_bytes:
        raise ExtractionError("archive size limit exceeded")

    requested_root = Path(destination).absolute()
    if not requested_root.parent.is_dir():
        raise ExtractionError("destination parent directory must already exist")
    root = requested_root.parent.resolve() / requested_root.name
    if root.is_symlink() or (root.exists() and (not root.is_dir() or any(root.iterdir()))):
        raise ExtractionError("destination must be a new or empty real directory")
    created_root = not root.exists()
    if created_root:
        root.mkdir()

    created_nodes: list[Path] = [root] if created_root else []
    state = {"total_bytes": 0, "files": 0, "directories": 0}
    results: list[dict] = []
    # Registry tracks every path component, including implicit directories.
    registry: dict[tuple[str, ...], tuple[tuple[str, ...], str, bool]] = {}
    deadline = time.monotonic() + limits.max_seconds
    max_entries = limits.max_files + limits.max_directories

    def cleanup() -> None:
        for node in reversed(created_nodes):
            try:
                if node.is_symlink() or not node.is_dir():
                    node.unlink(missing_ok=True)
                else:
                    node.rmdir()
            except OSError:
                # Do not recursively delete untracked concurrent files.
                pass

    def register(name: str, is_dir: bool) -> tuple[Path, bool]:
        spelling = _safe_parts(name)
        parts = tuple(unicodedata.normalize("NFC", p) for p in spelling)
        if len(parts) > limits.max_depth:
            raise ExtractionError("path depth limit exceeded")
        target = root.joinpath(*parts)
        if os.path.commonpath((str(root), str(target))) != str(root):
            raise ExtractionError("path escapes extraction root")

        for index in range(1, len(parts) + 1):
            original = spelling[:index]
            key = tuple(unicodedata.normalize("NFC", p).casefold() for p in original)
            final = index == len(parts)
            wanted_kind = "directory" if (not final or is_dir) else "file"
            previous = registry.get(key)
            if previous is not None:
                old_parts, old_kind, explicit = previous
                if old_parts != original:
                    raise ExtractionError("duplicate or case-colliding path component")
                if old_kind != wanted_kind:
                    raise ExtractionError("file/directory path collision")
                if final:
                    if is_dir and not explicit:
                        registry[key] = (old_parts, old_kind, True)
                        return target, False  # already-created implicit directory
                    raise ExtractionError("duplicate archive path")
                continue

            if final and is_dir:
                target.mkdir()
                created_nodes.append(target)
                state["directories"] += 1
                if state["directories"] > limits.max_directories:
                    raise ExtractionError("directory count limit exceeded")
                registry[key] = (original, "directory", True)
            elif final:
                state["files"] += 1
                if state["files"] > limits.max_files:
                    raise ExtractionError("file count limit exceeded")
                registry[key] = (original, "file", True)
            else:
                parent = root.joinpath(*parts[:index])
                parent.mkdir()
                created_nodes.append(parent)
                state["directories"] += 1
                if state["directories"] > limits.max_directories:
                    raise ExtractionError("directory count limit exceeded")
                registry[key] = (original, "directory", False)
        return target, True

    try:
        if zipfile.is_zipfile(source):
            fmt = "zip"
            expected_entries, _ = _zip_central_directory_info(
                source, max_entries, limits.max_central_directory_bytes
            )
            with zipfile.ZipFile(source) as zf:
                # infolist() is now bounded by the preflight entry and byte limits.
                infos = zf.infolist()
                if len(infos) != expected_entries:
                    raise ExtractionError("ZIP central-directory entry count mismatch")
                if len(infos) > max_entries:
                    raise ExtractionError("archive entry count limit exceeded")
                for info in infos:
                    if time.monotonic() > deadline:
                        raise ExtractionError("extraction time limit exceeded")
                    mode = (info.external_attr >> 16) & 0xFFFF
                    unix_type = stat.S_IFMT(mode)
                    dos_attributes = info.external_attr & 0xFF
                    if unix_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                        raise ExtractionError("links and special ZIP entries are not allowed")
                    name_says_dir = info.filename.endswith(("/", "\\"))
                    metadata_says_dir = unix_type == stat.S_IFDIR or bool(dos_attributes & 0x10)
                    if name_says_dir and unix_type == stat.S_IFREG:
                        raise ExtractionError("conflicting ZIP directory metadata")
                    if metadata_says_dir and unix_type == stat.S_IFREG:
                        raise ExtractionError("conflicting ZIP directory metadata")
                    is_dir = name_says_dir or metadata_says_dir
                    raw_name = _archive_name(info.orig_filename, is_dir)
                    if info.flag_bits & (0x1 | 0x40):
                        raise ExtractionError("encrypted ZIP entries are not supported")
                    if info.file_size < 0 or info.compress_size < 0:
                        raise ExtractionError("invalid ZIP entry sizes")
                    if is_dir and info.file_size != 0:
                        raise ExtractionError("ZIP directory entry contains data")
                    if not is_dir and info.file_size > limits.max_file_bytes:
                        raise ExtractionError("single-file size limit exceeded")
                    if not is_dir and info.file_size and info.compress_size == 0:
                        raise ExtractionError("invalid zero compressed-size entry")
                    if (not is_dir and info.compress_size
                            and info.file_size / info.compress_size > limits.max_compression_ratio):
                        raise ExtractionError("compression ratio limit exceeded")
                    if raw_name is None:
                        continue
                    target, should_create = register(raw_name, is_dir)
                    if is_dir:
                        if should_create:
                            results.append({"path": target.relative_to(root).as_posix(), "status": "directory", "size_bytes": 0})
                        continue
                    with zf.open(info, "r") as src, target.open("xb") as dst:
                        created_nodes.append(target)
                        size, digest = _copy_limited(src, dst, expected=info.file_size,
                                                     state=state, limits=limits, deadline=deadline)
                    results.append({"path": target.relative_to(root).as_posix(), "status": "extracted", "size_bytes": size,
                                    "sha256": digest})
        else:
            fmt = "tar"
            metadata_bytes = 0
            header_count = 0

            class BoundedTarInfo(tarfile.TarInfo):
                @classmethod
                def fromtarfile(cls, archive):
                    try:
                        return super().fromtarfile(archive)
                    except (tarfile.InvalidHeaderError, tarfile.TruncatedHeaderError,
                            tarfile.EmptyHeaderError) as exc:
                        # TarFile.next otherwise treats a bad later header as end-of-archive.
                        raise ExtractionError("unsupported or corrupt TAR header") from exc

                def _proc_member(self, archive):
                    nonlocal metadata_bytes, header_count
                    header_count += 1
                    if header_count > max_entries * 2:
                        raise ExtractionError("TAR header count limit exceeded")
                    if time.monotonic() > deadline:
                        raise ExtractionError("extraction time limit exceeded")
                    if self.type == tarfile.GNUTYPE_SPARSE:
                        raise ExtractionError("sparse TAR entries are not allowed")
                    if self.type in (tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK,
                                       tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE):
                        metadata_bytes += self.size
                        if self.size < 0 or metadata_bytes > limits.max_tar_metadata_bytes:
                            raise ExtractionError("TAR metadata size limit exceeded")
                    return super()._proc_member(archive)

            with tarfile.open(source, mode="r|*", tarinfo=BoundedTarInfo) as tf:
                entries_seen = 0
                for member in tf:
                    entries_seen += 1
                    if entries_seen > max_entries:
                        raise ExtractionError("archive entry count limit exceeded")
                    if time.monotonic() > deadline:
                        raise ExtractionError("extraction time limit exceeded")
                    is_dir = member.isdir()
                    raw_name = _archive_name(member.name, is_dir)
                    if is_dir:
                        if member.size != 0:
                            raise ExtractionError("TAR directory entry contains data")
                        if raw_name is None:
                            continue
                        target, should_create = register(raw_name, True)
                        if should_create:
                            results.append({"path": target.relative_to(root).as_posix(), "status": "directory", "size_bytes": 0})
                        continue
                    if not member.isfile() or member.sparse is not None:
                        raise ExtractionError("links, sparse files, and special TAR entries are not allowed")
                    if member.size < 0 or member.size > limits.max_file_bytes:
                        raise ExtractionError("single-file size limit exceeded")
                    target, _ = register(raw_name, False)
                    src = tf.extractfile(member)
                    if src is None:
                        raise ExtractionError("unable to read TAR entry")
                    with src, target.open("xb") as dst:
                        created_nodes.append(target)
                        size, digest = _copy_limited(src, dst, expected=member.size,
                                                     state=state, limits=limits, deadline=deadline)
                    results.append({"path": target.relative_to(root).as_posix(), "status": "extracted", "size_bytes": size,
                                    "sha256": digest})

        return {
            "format": fmt,
            "status": "completed",
            "archive": {"name": source.name, "size_bytes": archive_size},
            "limits": asdict(limits),
            "summary": {**state, "rejected": 0},
            "entries": results,
            "notes": [
                "Nested archives are not recursively extracted.",
                "Firmware filesystem images require dedicated parsers and are not supported here.",
                "Extracted files are untrusted data; do not execute them.",
            ],
        }
    except (zipfile.BadZipFile, tarfile.TarError, NotImplementedError, EOFError) as exc:
        cleanup()
        raise ExtractionError("unsupported or corrupt archive") from exc
    except BaseException:
        # Includes KeyboardInterrupt and SystemExit; remove partial output first.
        cleanup()
        raise
