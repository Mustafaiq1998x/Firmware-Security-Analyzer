"""Unpack supported containers or export bounded, structurally checked components."""
from hashlib import sha256
from pathlib import Path

from . import tplink, tplink_classic
from .hikvision import FORMAT
from .extraction import ExtractionError, ExtractionLimits, safe_extract_archive


def unpack_image(source, destination, report):
    source, destination = Path(source), Path(destination)
    profile = report["analysis"]["firmware_profile"]
    if profile["outer_format"] in {"TAR", "ZIP", "ZIP header marker", "gzip header"}:
        return safe_extract_archive(source, destination)
    parts = profile["components"]
    if not parts:
        raise ExtractionError("No supported archive or bounded component identified")
    limits = ExtractionLimits()
    if any(p["size_bytes"] > limits.max_file_bytes for p in parts):
        raise ExtractionError("Component exceeds the single-file limit")
    if sum(p["size_bytes"] for p in parts) > limits.max_total_bytes:
        raise ExtractionError("Component output exceeds the total-byte limit")
    entries = []
    with source.open("rb") as src:
        digest = sha256()
        for chunk in iter(lambda: src.read(1024 * 1024), b""):
            digest.update(chunk)
        if digest.hexdigest() != report["input"]["sha256"]:
            raise ExtractionError("Input changed since inspection")
        destination.mkdir()
        try:
            for part in parts:
                suffix = "rootfs.squashfs" if part["format"] == "SquashFS 4.0" else "payload.bin"
                if profile["outer_format"] in (FORMAT, tplink.FORMAT, tplink.FACTORY, tplink_classic.FORMAT):
                    # Use a fixed data suffix even when the stored entry names an executable.
                    suffix = part["name"] + ".bin"
                name = f"{part['offset']:08x}-{suffix}"
                path = destination / name
                src.seek(part["offset"])
                remaining = part["size_bytes"]
                digest = sha256()
                with path.open("xb") as dst:
                    while remaining:
                        chunk = src.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise ExtractionError("Truncated component")
                        dst.write(chunk)
                        digest.update(chunk)
                        remaining -= len(chunk)
                entries.append({"path": name, "size_bytes": part["size_bytes"], "offset": part["offset"],
                                "status": "extracted", "sha256": digest.hexdigest()})
        except BaseException:
            # This private directory was created by this invocation.
            import shutil
            shutil.rmtree(destination)
            raise
    return {"status": "completed", "format": "components", "summary": {"files":len(entries),
            "directories":0, "total_bytes":sum(e["size_bytes"] for e in entries)}, "entries":entries,
            "notes":["Counts exported components. Files inside filesystem images are not enumerated."]}
