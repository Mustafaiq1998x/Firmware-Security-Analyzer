import json

import pytest
from fsa.cli import main


def test_extract_cli_writes_report(tmp_path, monkeypatch):
    import zipfile

    archive = tmp_path / "firmware.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("etc/config", "safe")
    out = tmp_path / "extracted"
    report = tmp_path / "report.json"
    monkeypatch.setattr("sys.argv", ["fsa", "extract", str(archive), "--outdir", str(out), "--report", str(report)])
    main()
    assert (out / "etc/config").read_text() == "safe"
    data = json.loads(report.read_text())
    assert data["status"] == "completed"
    assert data["summary"]["files"] == 1


def test_extract_cli_rejects_report_inside_output(tmp_path, monkeypatch):
    archive = tmp_path / "firmware.zip"
    import zipfile
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("file", "data")
    out = tmp_path / "extracted"
    monkeypatch.setattr("sys.argv", ["fsa", "extract", str(archive), "--outdir", str(out), "--report", str(out / "report.json")])
    with pytest.raises(SystemExit, match="outside"):
        main()
    assert not out.exists()


def test_extract_cli_accepts_central_directory_limit(tmp_path, monkeypatch):
    import zipfile

    archive = tmp_path / "firmware.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("etc/config", "safe")
    out = tmp_path / "extracted"
    monkeypatch.setattr("sys.argv", [
        "fsa", "extract", str(archive), "--outdir", str(out),
        "--max-central-directory-mib", "1",
    ])
    main()
    assert (out / "etc/config").read_text() == "safe"


@pytest.mark.parametrize("link_kind", ["symbolic", "hard"])
def test_cli_archive_identity(tmp_path, monkeypatch, link_kind):
    import zipfile

    archive = tmp_path / "input.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("config", "ok")
    original = archive.read_bytes()
    alias = tmp_path / "alias"
    out = tmp_path / "out"
    try:
        if link_kind == "symbolic":
            alias.symlink_to(archive)
            args = ["extract", str(alias), "--outdir", str(out)]
        else:
            alias.hardlink_to(archive)
            args = ["extract", str(archive), "--outdir", str(out), "--report", str(alias)]
    except (OSError, NotImplementedError):
        pytest.skip("filesystem link unavailable")
    monkeypatch.setattr("sys.argv", ["fsa", *args])
    with pytest.raises(SystemExit, match="non-symlink|overwrite"):
        main()
    assert archive.read_bytes() == original
    assert not out.exists()
