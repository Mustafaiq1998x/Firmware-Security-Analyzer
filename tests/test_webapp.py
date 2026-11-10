from fastapi.testclient import TestClient
from fsa.webapp import app


def test_health_and_root_routes():
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 200


def test_scan_upload():
    client = TestClient(app)
    response = client.post(
        "/scan",
        files={"upload": ("demo.bin", b"\x7fELF\x00Linux version 4.9.138", "application/octet-stream")},
    )
    assert response.status_code == 200
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
