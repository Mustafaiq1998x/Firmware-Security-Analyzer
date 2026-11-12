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


def test_entropy_samples_cover_large_input_end_to_end():
    data = b"A" * (4096 * 1000)
    result = sample_entropy(data, block_size=4096, max_blocks=4)
    assert len(result) == 4
    assert result[0]["offset"] == 0
    assert result[-1]["offset"] == len(data) - 4096
    assert result[-1]["offset"] > len(data) // 2
