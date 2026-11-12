"""Scan public FSA distribution files and produce a Markdown receipt."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import urlsplit

import httpx

ROOT = "https://www.virustotal.com/api/v3"
START = "<!-- FSA-VT-START -->"
END = "<!-- FSA-VT-END -->"


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def scan(client, path, digest):
    url = f"{ROOT}/files"
    if path.stat().st_size > 32 * 1024 * 1024:
        url = client.get(f"{url}/upload_url").raise_for_status().json()["data"]
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in {"www.virustotal.com", "virustotal.com"}:
            raise ValueError("Unexpected VirusTotal upload host")
    with path.open("rb") as handle:
        response = client.post(url, files={"file": (path.name, handle)})
    analysis_id = response.raise_for_status().json()["data"]["id"]
    if not re.fullmatch(r"[a-zA-Z0-9_=-]+", analysis_id):
        raise ValueError("Invalid analysis identifier")
    for _ in range(40):
        time.sleep(25)
        response = client.get(f"{ROOT}/analyses/{analysis_id}")
        if response.status_code == 429:
            continue
        result = response.raise_for_status().json()
        analysis = result["data"]["attributes"]
        if analysis["status"] == "completed":
            if result.get("meta", {}).get("file_info", {}).get("sha256") != digest:
                raise ValueError("VirusTotal report digest mismatch")
            return analysis
    raise TimeoutError(f"VirusTotal analysis did not complete for {path.name}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("assets", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    release = json.loads(args.manifest.read_text())
    if release["isDraft"]:
        raise ValueError("Select a published release")
    rows = []
    with httpx.Client(headers={"x-apikey": os.environ["VT_API_KEY"]}, timeout=180) as client:
        for asset in release["assets"]:
            name = asset["name"]
            if not name.lower().endswith((".whl", ".tar.gz", ".zip", ".exe", ".msi", ".appimage", ".deb")):
                continue
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", name):
                raise ValueError("Unexpected package filename")
            path = args.assets / name
            digest = sha256(path)
            if asset["digest"] != f"sha256:{digest}":
                raise ValueError(f"Release digest mismatch for {name}")
            analysis = scan(client, path, digest)
            stats = analysis["stats"]
            date = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(analysis["date"]))
            link = f"https://www.virustotal.com/gui/file/{digest}"
            rows.append(f"| {name} | `{digest}` | {date} | {stats['malicious']} | {stats['suspicious']} | [Report]({link}) |")
    if not rows:
        raise ValueError("No supported public distribution assets found")
    body = release["body"] or ""
    if START in body or END in body:
        if body.count(START) != 1 or body.count(END) != 1 or body.index(START) > body.index(END):
            raise ValueError("Invalid release receipt markers")
        before, rest = body.split(START)
        _, after = rest.split(END)
    else:
        before, after = body, ""
    table = ["## VirusTotal verification", "", "| Package | SHA-256 | Scan date | Malicious | Suspicious | VirusTotal |",
             "|---|---|---|---:|---:|---|", *rows]
    args.output.write_text(before.rstrip() + "\n\n" + START + "\n" + "\n".join(table) + "\n" + END + after + "\n")


if __name__ == "__main__":
    main()
