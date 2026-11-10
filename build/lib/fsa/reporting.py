"""Report serialization."""
import html
import json
from pathlib import Path

def write_json(report: dict, path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

def write_html(report: dict, path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    pretty = html.escape(json.dumps(report, indent=2, ensure_ascii=False))
    document = f"""<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>FSA Report</title>
<style>
body{{font:15px/1.6 system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;background:#10151d;color:#e8edf4}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#182230;padding:1rem;border-radius:8px}}
h1{{color:#8fc7ff}} .note{{color:#ffd58a}}
</style><h1>Firmware Security Analyzer</h1>
<p class="note">Static triage report. Indicators are not proof of exploitability.</p>
<pre>{pretty}</pre></html>"""
    target.write_text(document, encoding="utf-8")
