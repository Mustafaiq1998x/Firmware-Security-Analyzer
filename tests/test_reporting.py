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
