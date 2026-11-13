"""Probabilities as percentages without rounding to certainty or to zero."""

from __future__ import annotations


def probability_percent(probability: float) -> str:
    """One decimal unless that would show a value below 1 as 100.0% or a positive value as 0.0%."""
    percent = probability * 100
    for digits in range(1, 5):
        text = f"{percent:.{digits}f}"
        rounded = float(text)
        if (probability < 1 and rounded >= 100) or (probability > 0 and rounded <= 0):
            continue
        return f"{text}%"
    return f"{percent:.4f}%"
