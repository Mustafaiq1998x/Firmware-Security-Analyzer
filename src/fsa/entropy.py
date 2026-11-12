"""Entropy sampling helpers with coverage across the complete input image."""
import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def sample_entropy(data, block_size: int = 4096, max_blocks: int = 256) -> list[dict]:
    """Sample entropy evenly across the file, not only at its beginning."""
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    if max_blocks < 0:
        raise ValueError("max_blocks must be zero or greater")
    if max_blocks == 0 or not data:
        return []

    length = len(data)
    last_start = max(0, length - block_size)
    if length <= block_size * max_blocks:
        starts = list(range(0, length, block_size))[:max_blocks]
    elif max_blocks == 1:
        starts = [0]
    else:
        # Include both the beginning and the end while distributing the
        # remaining samples over the full address range.
        starts = [round(i * last_start / (max_blocks - 1)) for i in range(max_blocks)]

    result = []
    for start in starts:
        chunk = data[start:start + block_size]
        result.append({"offset": start, "size": len(chunk), "entropy": round(shannon_entropy(chunk), 4)})
    return result
