"""Build the offline device index from OpenWrt release profiles.json files."""
import argparse
import json
import re
from pathlib import Path


def build(paths):
    records = {}
    for path in sorted(paths):
        release = json.loads(path.read_text())
        for board, profile in release["profiles"].items():
            titles = profile.get("titles") or []
            models = [" ".join(str(t[k]) for k in ("vendor", "model", "variant") if t.get(k)) for t in titles]
            vendors = sorted({t["vendor"] for t in titles if t.get("vendor")})
            for image in profile["images"]:
                if image["type"] not in {"trx", "chk", "factory", "sysupgrade"} or not models or not all(models):
                    continue
                key = image["sha256"]
                if not re.fullmatch(r"[0-9a-f]{64}", key):
                    raise ValueError(f"Malformed image digest in {path}")
                row = [board, models, vendors, release["target"], release["version_number"], image["type"]]
                if key in records and records[key] != row:
                    raise ValueError(f"Ambiguous image digest {key}")
                records[key] = row
    return records


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profiles", type=Path, nargs="+")
    parser.add_argument("--outdir", type=Path, required=True)
    args = parser.parse_args()
    records = build(args.profiles)
    args.outdir.mkdir(parents=True, exist_ok=True)
    for prefix in "0123456789abcdef":
        rows = {k: records[k] for k in sorted(records) if k.startswith(prefix)}
        lines = [f'{json.dumps(k)}: {json.dumps(value, ensure_ascii=False)}' for k, value in rows.items()]
        (args.outdir / f"{prefix}.json").write_text("{\n" + ",\n".join(lines) + "\n}\n", encoding="utf-8")
