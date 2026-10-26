"""Shannon entropy shared by the report redactor and the secret scanner."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character: high for random tokens, low for words."""
    if not value:
        return 0.0
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in Counter(value).values())
