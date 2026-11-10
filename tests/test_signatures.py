from fsa.signatures import identify_signatures

def test_finds_multiple_signatures():
    data = b"abc" + b"\x7fELF" + b"padding" + b"\xfd7zXZ\x00"
    hits = identify_signatures(data)
    assert [x["name"] for x in hits] == ["ELF", "XZ"]
    assert hits[0]["offset"] == 3


def test_zero_signature_limit():
    assert identify_signatures(b"\x7fELF", 0) == []


def test_negative_signature_limit_rejected():
    import pytest
    with pytest.raises(ValueError):
        identify_signatures(b"\x7fELF", -1)
