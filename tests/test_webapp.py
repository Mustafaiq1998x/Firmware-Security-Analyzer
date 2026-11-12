from fastapi.testclient import TestClient
from fsa.webapp import app


def test_health_and_root_routes():
    client = TestClient(app)
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert health.json()["version"] == "0.1.2"
    assert health.headers["cache-control"] == "no-store"
    page = client.get("/")
    assert page.status_code == 200
    assert "Firmware Security Analyzer" in page.text
    assert "بدء التحليل" in page.text
    assert 'id="languageToggle"' in page.text
    assert "Firmware inspection" in page.text
    for asset in ("dashboard.css", "dashboard.js", "fsa.svg"):
        assert client.get(f"/assets/{asset}").status_code == 200
    assert 'id="entropy"' in page.text
    assert page.headers["x-content-type-options"] == "nosniff"


def test_scan_upload():
    client = TestClient(app)
    response = client.post(
        "/scan",
        files={"upload": ("demo.bin", b"\x7fELF\x00Linux version 4.9.138", "application/octet-stream")},
    )
    assert response.status_code == 200
    assert response.json()["input"]["name"] == "demo.bin"
    assert response.json()["analysis"]["kernel_versions"] == ["4.9.138"]


def test_scan_upload_rejects_oversized_file(monkeypatch):
    import fsa.webapp as webapp
    monkeypatch.setattr(webapp, "API_MAX_UPLOAD_BYTES", 8)
    client = TestClient(app)
    response = client.post(
        "/scan",
        files={"upload": ("large.bin", b"0123456789", "application/octet-stream")},
    )
    assert response.status_code == 413


def test_archive_inspection_lists_regular_file():
    import io
    import zipfile

    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("etc/config", b"demo")
    response = TestClient(app).post("/scan", data={"inspect_archive": "true"},
                                    files={"upload": ("firmware.zip", data.getvalue())})
    assert response.status_code == 200
    report = response.json()["archive_inspection"]
    assert report["archive"]["name"] == "firmware.zip"
    assert report["entries"][0]["path"] == "etc/config"


def test_worker_timeout_leaves_slot_available(monkeypatch):
    import fsa.scan_worker as worker

    client = TestClient(app)
    with monkeypatch.context() as patch:
        patch.setattr(worker, "MAX_SECONDS", 0)
        assert client.post("/scan", files={"upload": ("demo.bin", b"sample")}).status_code == 408
    assert client.post("/scan", files={"upload": ("demo.bin", b"sample")}).status_code == 200
