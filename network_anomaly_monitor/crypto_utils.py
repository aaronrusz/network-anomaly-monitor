"""
crypto_utils.py — Pure-Python 3 utility functions for entropy and statistical analysis.

No third-party dependencies.
"""

import math
from collections import Counter


def calculate_entropy(data: bytes | str) -> float:
    """
    Calculate the Shannon entropy (in bits) of *data*.

    Accepts either :class:`bytes` or :class:`str`; strings are UTF-8 encoded
    before processing.  Returns 0.0 for empty input.
    """
    if not data:
        return 0.0

    if isinstance(data, str):
        data = data.encode("utf-8", errors="ignore")

    data_len = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        probability = count / data_len
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def chi_square_uniformity(payload: bytes) -> float:
    """
    Return the chi-square statistic comparing *payload*'s byte-value distribution
    against a perfectly uniform distribution across all 256 possible byte values.

    A very high statistic (empirically > 300 for payloads ≥ 100 bytes) suggests
    non-random structure — i.e. poor encryption or nested encoding.
    """
    expected = len(payload) / 256
    if expected == 0:
        return 0.0

    byte_freqs = [payload.count(i) for i in range(256)]
    return sum((observed - expected) ** 2 / expected for observed in byte_freqs)
