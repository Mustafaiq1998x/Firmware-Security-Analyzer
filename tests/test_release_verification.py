import importlib.util
from pathlib import Path

import pytest

httpx = pytest.importorskip("httpx")
script = Path(__file__).resolve().parents[1] / "scripts" / "verify_release.py"
spec = importlib.util.spec_from_file_location("verify_release", script)
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


@pytest.mark.parametrize("matches", [True, False])
def test_release_receipt_requires_matching_digest(tmp_path, monkeypatch, matches):
    sample = tmp_path / "fsa.whl"
    sample.write_bytes(b"fixture")
    digest = verify.sha256(sample)
    attrs = {"status": "completed", "stats": {"malicious": 0, "suspicious": 0}}

    def reply(request):
        if request.method == "POST":
            return httpx.Response(200, json={"data": {"id": "abc"}})
        return httpx.Response(200, json={"data": {"attributes": attrs},
                                        "meta": {"file_info": {"sha256": digest if matches else ""}}})

    monkeypatch.setattr(verify.time, "sleep", lambda _: None)
    with httpx.Client(transport=httpx.MockTransport(reply)) as client:
        if matches:
            assert verify.scan(client, sample, digest) == attrs
        else:
            with pytest.raises(ValueError, match="digest mismatch"):
                verify.scan(client, sample, digest)
