"""Collapse legacy ``generic:`` control copies onto their framework-qualified tag.

The flat legacy ``compliance_tags`` list repeats every control a finding also
carries under its named framework (``cis:CIS-02.3`` and ``generic:CIS-02.3``).
Counting both doubles "mapped controls"; a ``generic`` tag survives only when
no named framework claims the same control id.
"""

from __future__ import annotations

from collections.abc import Iterable

GENERIC_FRAMEWORK = "generic"


def drop_generic_duplicates(tags: Iterable[str]) -> list[str]:
    ordered = list(dict.fromkeys(tags))
    named = {control for framework, _, control in (tag.partition(":") for tag in ordered) if framework != GENERIC_FRAMEWORK}
    return [tag for tag in ordered if not (tag.startswith(GENERIC_FRAMEWORK + ":") and tag.partition(":")[2] in named)]
