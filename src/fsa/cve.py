"""Small offline CVE-feed matcher. Matches are leads, never vulnerability verdicts."""
import json
import re
from pathlib import Path

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
MAX_FEED_BYTES = 16 * 1024 * 1024
MAX_FEED_ITEMS = 100_000


def _version_tuple(value: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", value)
    return tuple(int(n) for n in nums[:8])


def load_feed(path: str | Path) -> list[dict]:
    source = Path(path)
    if source.stat().st_size > MAX_FEED_BYTES:
        raise ValueError(f"CVE feed exceeds {MAX_FEED_BYTES} bytes")
    payload = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("CVE feed must be a JSON object")
    items = payload.get("items", [])
    if not isinstance(items, list):
        raise ValueError("CVE feed 'items' must be a list")
    if len(items) > MAX_FEED_ITEMS:
        raise ValueError(f"CVE feed contains more than {MAX_FEED_ITEMS} items")
    validated = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"CVE feed item {index} must be an object")
        cve = item.get("cve")
        if not isinstance(cve, str) or not CVE_ID_RE.fullmatch(cve):
            raise ValueError(f"CVE feed item {index} has an invalid CVE identifier")
        if not isinstance(item.get("component"), str):
            raise ValueError(f"CVE feed item {index} has no valid component")
        if item["component"] == "device-firmware":
            fields = ("board", "distribution", "release", "advisory_url")
            if not all(isinstance(item.get(k), str) and item[k].strip() for k in fields):
                raise ValueError(f"CVE feed item {index} lacks device advisory metadata")
            if not item["advisory_url"].startswith("https://"):
                raise ValueError(f"CVE feed item {index} needs an HTTPS advisory reference")
            validated.append(item)
            continue
        if not isinstance(item.get("version_start"), str) or not isinstance(item.get("version_end"), str):
            raise ValueError(f"CVE feed item {index} has invalid version bounds")
        if not _version_tuple(item["version_start"]) or not _version_tuple(item["version_end"]):
            raise ValueError(f"CVE feed item {index} has unparsable version bounds")
        validated.append(item)
    return validated


def match_kernel_cves(versions: list[str], items: list[dict]) -> list[dict]:
    matches = []
    for version in versions:
        current = _version_tuple(version)
        for item in items:
            if str(item.get("component", "")).lower() != "linux":
                continue
            start = _version_tuple(str(item.get("version_start", "")))
            end = _version_tuple(str(item.get("version_end", "")))
            if not current or not start or not end:
                continue
            width = max(len(current), len(start), len(end))
            pad = lambda value: value + (0,) * (width - len(value))
            if pad(start) <= pad(current) <= pad(end):
                matches.append({
                    "cve": item["cve"],
                    "component": "linux",
                    "detected_version": version,
                    "summary": item.get("summary", ""),
                    "status": "needs_manual_validation",
                    "warning": "Numeric range match is approximate; verify vendor patches, configuration, and exact applicability.",
                })
    return matches

def match_device_cves(identity: dict, items: list[dict]) -> list[dict]:
    """Require the exact board, distribution and release named by a local advisory."""
    boards = set(identity.get("supported_devices", []))
    if identity.get("board"):
        boards.add(identity["board"])
    matches = []
    for item in items:
        if (item["component"] != "device-firmware" or item["board"] not in boards
                or item["distribution"] != identity.get("distribution")
                or item["release"] != identity.get("release")):
            continue
        matches.append({"cve": item["cve"], "component": "device-firmware",
                        "detected_version": item["release"], "board": item["board"],
                        "summary": item.get("summary", ""), "advisory_url": item["advisory_url"],
                        "status": "needs_manual_validation",
                        "evidence": "Board, distribution and release match the supplied advisory."})
    return matches
