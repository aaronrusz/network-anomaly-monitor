"""
crypto_utils.py — Utility functions for entropy calculation and statistical analysis.
"""

import math
from collections import Counter


def calculate_entropy(data):
    """Calculate Shannon entropy of data to detect encryption patterns."""
    if not data:
        return 0

    if isinstance(data, str):
        data = data.encode('utf-8', errors='ignore')

    byte_counts = Counter(data)
    data_len = len(data)

    entropy = 0
    for count in byte_counts.values():
        probability = count / data_len
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def chi_square_uniformity(payload):
    """
    Return the chi-square statistic comparing the payload's byte distribution
    against a perfectly uniform distribution (256 values).
    A very high value suggests poor encryption or nested protocols.
    """
    byte_freqs = [payload.count(i) for i in range(256)]
    expected = len(payload) / 256
    return sum(
        (observed - expected) ** 2 / expected
        for observed in byte_freqs
        if expected > 0
    )
