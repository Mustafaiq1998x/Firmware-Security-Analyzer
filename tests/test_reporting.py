from fsa.reporting import write_html, write_json


def test_report_writers_escape_html(tmp_path):
    report = {"value": "<script>alert('xss')</script>"}
    json_path = tmp_path / "nested" / "report.json"
    html_path = tmp_path / "nested" / "report.html"
    write_json(report, json_path)
    write_html(report, html_path)
    assert "<script>" in json_path.read_text(encoding="utf-8")
    html = html_path.read_text(encoding="utf-8")
    assert "&lt;script&gt;" in html
    assert "<script>" not in html


def test_bundled_demo_matches_scanner():
    from pathlib import Path
    import json
    from fsa.analyzer import scan_file

    root = Path(__file__).resolve().parents[1]
    example = root / "src/fsa/assets/example-report.json"
    assert json.loads(example.read_text(encoding="utf-8")) == scan_file(root / "samples/demo_firmware.bin")


def test_html_report_renders_evidence_and_offsets(tmp_path):
    from fsa.analyzer import scan_file

    source = tmp_path / "fixture.bin"
    source.write_bytes(b"\x7fELF\x00password=not-a-real-secret")
    report = tmp_path / "result.html"
    write_html(scan_file(source), report)
    page = report.read_text(encoding="utf-8")
    assert "<td>ELF</td><td>0</td>" in page
    assert "<pre>password=not-a-real-secret</pre>" in page
    assert "Complete report data" in page
