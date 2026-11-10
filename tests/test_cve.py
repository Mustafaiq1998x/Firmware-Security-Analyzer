from fsa.cve import match_kernel_cves

def test_approximate_kernel_range_match():
    items = [{"cve": "CVE-2024-0001", "component": "linux",
              "version_start": "4.0", "version_end": "4.9.999",
              "summary": "Example"}]
    matches = match_kernel_cves(["4.9.138"], items)
    assert matches[0]["cve"] == "CVE-2024-0001"
    assert matches[0]["status"] == "needs_manual_validation"


def test_load_feed_rejects_invalid_cve_id(tmp_path):
    import json
    import pytest
    from fsa.cve import load_feed
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps({"items": [{
        "cve": "not-a-cve", "component": "linux",
        "version_start": "4.0", "version_end": "5.0"
    }]}), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid CVE"):
        load_feed(feed)


def test_load_feed_rejects_non_object(tmp_path):
    from fsa.cve import load_feed
    import pytest
    feed = tmp_path / "feed.json"
    feed.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        load_feed(feed)
