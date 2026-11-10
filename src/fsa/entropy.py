"""Entropy sampling helpers."""
import math
from collections import Counter

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())

def sample_entropy(data: bytes, block_size: int = 4096, max_blocks: int = 256) -> list[dict]:
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    if max_blocks < 0:
        raise ValueError("max_blocks must be zero or greater")
    result = []
    for index, start in enumerate(range(0, len(data), block_size)):
        if index >= max_blocks:
            break
        chunk = data[start:start + block_size]
        result.append({"offset": start, "size": len(chunk), "entropy": round(shannon_entropy(chunk), 4)})
    return result
