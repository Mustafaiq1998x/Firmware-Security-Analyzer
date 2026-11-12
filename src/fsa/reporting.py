"""Write machine-readable and standalone human-readable inspection reports."""
import html
import json
from pathlib import Path


def write_json(report: dict, path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


def _text(value):
    return html.escape(str(value))


def _table(columns, records, empty):
    if not records:
        return f"<p>{_text(empty)}</p>"
    headers = "".join(f"<th scope='col'>{_text(c)}</th>" for c in columns)
    rows = []
    for record in records:
        cells = "".join(f"<td>{_text(value)}</td>" for value in record)
        rows.append(f"<tr>{cells}</tr>")
    return f"<div class='scroll'><table><thead><tr>{headers}</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"


def write_html(report: dict, path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    source = report.get("input", {})
    analysis = report.get("analysis", {})
    signatures = analysis.get("signatures", [])
    findings = analysis.get("heuristic_findings", [])
    evidence = []
    for finding in findings:
        excerpts = "".join(f"<pre>{_text(s)}</pre>" for s in finding.get("evidence", []))
        evidence.append(f"<article><h3>{_text(finding.get('rule', 'Indicator'))}</h3>"
                        f"<p>Confidence · {_text(finding.get('confidence', 'unspecified'))}</p>"
                        f"<p>{_text(finding.get('message', ''))}</p>{excerpts}</article>")
    components = _table(
        ["Component", "Byte offset", "Magic bytes", "Description"],
        [(s.get("name", ""), s.get("offset", ""), s.get("magic_hex", ""), s.get("description", ""))
         for s in signatures], "No matching signatures in the sampled data.")
    advisories = _table(
        ["Advisory", "Component", "Version", "Status"],
        [(c.get("cve", ""), c.get("component", ""), c.get("detected_version", ""), c.get("status", ""))
         for c in report.get("packaged_firmware", analysis).get("cve_matches", [])], "No advisory matches recorded.")
    limitations = "".join(f"<li>{_text(s)}</li>" for s in report.get("limitations", []))
    firmware = report.get("packaged_firmware", analysis)
    profile = firmware.get("firmware_profile", {})
    identity = profile.get("identity", {})
    encryption = profile.get("encryption", {})
    inventory = report.get("archive_inspection", {})
    detail_rows = [
        ("Outer format", analysis.get("firmware_profile", {}).get("outer_format", "Unknown")),
        ("Firmware format", profile.get("outer_format", "Unknown")),
        ("Vendor", identity.get("vendor") or "Unknown"),
        ("Architecture", identity.get("architecture") or "Unknown"),
        ("Firmware kernel versions", ", ".join(firmware.get("kernel_versions", [])) or "Unknown"),
        ("Board", identity.get("board") or "Unknown"),
        ("Supported devices", ", ".join(identity.get("supported_devices", [])) or "Unknown"),
        ("System", " ".join(filter(None, [identity.get("os_family"), identity.get("distribution"), identity.get("release")])) or "Unknown"),
        ("Encryption", encryption.get("status", "Undetermined")),
        ("Cipher and mode", " ".join(filter(None, [encryption.get("algorithm"), encryption.get("mode")])) or "Unknown"),
        ("Encryption evidence", encryption.get("evidence", "Unavailable")),
        ("CVE assessment", firmware.get("cve_assessment", "Unavailable")),
    ]
    if inventory.get("status") == "completed":
        scope = "Exported components" if inventory["format"] == "components" else "Extracted regular members"
        detail_rows.append((scope, inventory["summary"]["files"]))
    profile_table = _table(["Field", "Value"], detail_rows, "")
    raw = _text(json.dumps(report, indent=2, ensure_ascii=False))
    style = (Path(__file__).with_name("assets") / "report.css").read_text(encoding="utf-8")
    document = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_text(source.get('name', 'Image'))} · FSA inspection report</title><style>{style}</style></head>
<body><header>Firmware Security Analyzer</header><main><h1>{_text(source.get('name', 'Inspection report'))}</h1>
<dl><dt>SHA-256</dt><dd>{_text(source.get('sha256', 'Unavailable'))}</dd>
<dt>Input size</dt><dd>{_text(source.get('size_bytes', 'Unknown'))} bytes</dd>
<dt>Kernel strings</dt><dd>{_text(', '.join(analysis.get('kernel_versions', [])) or 'None detected')}</dd></dl>
<nav><a href="#structure">Component signatures ({len(signatures)})</a>
<a href="#evidence">Indicator rules ({len(findings)})</a><a href="#advisories">Advisories</a></nav>
<section><h2>Firmware identification</h2>{profile_table}</section>
<section id="structure"><h2>Component signatures</h2>{components}</section>
<section id="evidence"><h2>Evidence for review</h2>{''.join(evidence) or '<p>No heuristic indicators recorded.</p>'}</section>
<section id="advisories"><h2>Advisory matches</h2>{advisories}</section>
<h2>Analysis limitations</h2><ul>{limitations}</ul>
<details><summary>Complete report data</summary><pre>{raw}</pre></details></main></body></html>"""
    target.write_text(document, encoding="utf-8")
