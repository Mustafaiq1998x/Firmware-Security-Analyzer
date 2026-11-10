from fsa.entropy import shannon_entropy, sample_entropy

def test_empty_entropy():
    assert shannon_entropy(b"") == 0.0

def test_uniform_byte_entropy():
    assert shannon_entropy(b"A" * 100) == 0.0

def test_all_byte_values_entropy():
    assert shannon_entropy(bytes(range(256))) == 8.0

def test_sample_offsets():
    result = sample_entropy(b"A" * 5000, block_size=4096)
    assert [x["offset"] for x in result] == [0, 4096]


def test_negative_max_blocks_rejected():
    import pytest
    with pytest.raises(ValueError, match="max_blocks"):
        sample_entropy(b"abc", max_blocks=-1)
