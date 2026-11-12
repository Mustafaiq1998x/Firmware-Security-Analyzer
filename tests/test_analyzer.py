from fsa.analyzer import scan_file
from fsa.heuristics import extract_strings


def test_scan_file(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x7fELF" + b"\x00Linux version 4.9.138\x00password=sample123")
    report = scan_file(sample)
    assert report["input"]["size_bytes"] > 0
    assert report["analysis"]["kernel_versions"] == ["4.9.138"]
    assert report["analysis"]["signatures"][0]["name"] == "ELF"


def test_scan_rejects_oversized_input(tmp_path):
    import pytest
    sample = tmp_path / "large.bin"
    sample.write_bytes(b"12345")
    with pytest.raises(ValueError, match="size limit"):
        scan_file(sample, max_file_size=4)


def test_cli_refuses_to_overwrite_input(tmp_path):
    import pytest
    from fsa.cli import _ensure_safe_report_paths
    image = tmp_path / "firmware.bin"
    image.write_bytes(b"firmware")
    with pytest.raises(SystemExit, match="overwrite"):
        _ensure_safe_report_paths(str(image), str(image), None)


def test_cli_refuses_same_json_and_html_path(tmp_path):
    import pytest
    from fsa.cli import _ensure_safe_report_paths
    image = tmp_path / "firmware.bin"
    image.write_bytes(b"firmware")
    report = tmp_path / "report.out"
    with pytest.raises(SystemExit, match="different"):
        _ensure_safe_report_paths(str(image), str(report), str(report))


def test_scan_empty_file(tmp_path):
    sample = tmp_path / "empty.bin"
    sample.write_bytes(b"")
    report = scan_file(sample)
    assert report["input"]["size_bytes"] == 0
    assert report["analysis"]["signatures"] == []
    assert report["analysis"]["entropy_samples"] == []


def test_scan_uses_bounded_printable_strings(tmp_path):
    sample = tmp_path / "long-string.bin"
    sample.write_bytes(b"A" * 100_000)
    report = scan_file(sample)
    assert report["analysis"]["printable_strings_count"] <= 20_000
    assert all(len(value) <= 1024 for value in extract_strings(sample.read_bytes()))
