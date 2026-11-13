"""Regex pieces shared by the model reference patterns.

Vendors publish IDs as a family and version followed by variant words and
snapshot numbers (``claude-sonnet-4-5-20250929``, ``gpt-5.1-codex-mini``,
``gemini-2.5-flash-native-audio-preview-12-2025``). Trailing parts are limited
to known variant words and numbers so prose such as ``gpt-5-based`` is not
read as a model ID.
"""

from __future__ import annotations

# A model ID never ends before ``-<digit>`` or ``.<digit>`` (claude-sonnet-4 is not inside claude-sonnet-4-5).
MODEL_END = r"(?![\w]|[.-]\d)"

# Variant words from the vendors' model pages, and numeric tokens (versions, dates, 120b, 32k).
MODEL_VARIANT = (
    r"(?:mini|nano|pro|max|plus|turbo|preview|latest|chat|codex|instruct|vision|audio|native|realtime|search|deep-research|"
    r"flash|lite|ultra|exp|thinking|extended|live|transcribe|translate|tts|image|embedding|computer-use|hd|it|"
    r"sol|terra|luna|astra|cyber|sunburst|flare|carbon|argon|hydrogen|\d+(?:\.\d+)?[bk]?)"
)
MODEL_SUFFIX = rf"(?:-{MODEL_VARIANT}){{0,8}}"

# Open families must end the ID: ``gpt-5-based`` is prose. A Bedrock ``-v1:0`` version may follow.
MODEL_ID_END = r"(?![\w]|[.-](?!v\d)[A-Za-z0-9])"
