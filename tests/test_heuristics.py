from fsa.heuristics import extract_strings, inspect_strings, find_kernel_versions


def test_extract_strings():
    assert "hello firmware" in extract_strings(b"\x00hello firmware\x00")


def test_detects_indicators():
    findings = inspect_strings(["password=sample123", "Linux version 4.9.138"])
    assert findings[0]["rule"] == "possible_hardcoded_password"


def test_kernel_version():
    assert find_kernel_versions(["Linux version 4.9.138 (builder)"]) == ["4.9.138"]


def test_extract_strings_zero_limit():
    assert extract_strings(b"first printable string", 0) == []


def test_extract_strings_rejects_negative_limit():
    import pytest
    with pytest.raises(ValueError):
        extract_strings(b"first printable string", -1)


def test_inspect_strings_zero_evidence_limit():
    assert inspect_strings(["password=sample123"], 0) == []


def test_inspect_strings_rejects_negative_evidence_limit():
    import pytest
    with pytest.raises(ValueError):
        inspect_strings(["password=sample123"], -1)


def test_long_printable_runs_are_split_into_bounded_strings():
    values = extract_strings(b"A" * 10_000)
    assert values
    assert all(len(value) <= 1024 for value in values)
