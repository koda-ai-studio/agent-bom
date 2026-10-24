"""YAML loading that remembers the source line of every mapping key and list item.

Scanners that walk parsed YAML used to recover a finding's line by searching
the raw text for ``key: value``. That returns the first match in the whole file
(wrong for multi-document manifests) and falls back to line 1 whenever the
value is not on the key's line. Loading through :func:`safe_load_all_with_lines`
returns ordinary ``dict``/``list`` subclasses, so existing rule code keeps
working, and :func:`key_line` / :func:`item_line` give the exact 1-based line.
"""

from __future__ import annotations

from typing import Any

import yaml  # type: ignore[import-untyped]


class LineDict(dict):
    """A mapping that records the line of each key and of the mapping itself."""

    line: int = 0
    key_lines: dict[Any, int]


class LineList(list):
    """A sequence that records the line of each item and of the sequence itself."""

    line: int = 0
    item_lines: list[int]


class _LineLoader(yaml.SafeLoader):  # type: ignore[misc]
    pass


def _construct_mapping(loader: _LineLoader, node: yaml.MappingNode, deep: bool = False) -> LineDict:
    loader.flatten_mapping(node)
    mapping = LineDict()
    mapping.line = node.start_mark.line + 1
    mapping.key_lines = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        try:
            hash(key)
        except TypeError:
            continue
        mapping[key] = loader.construct_object(value_node, deep=True)
        mapping.key_lines[key] = key_node.start_mark.line + 1
    return mapping


def _construct_sequence(loader: _LineLoader, node: yaml.SequenceNode, deep: bool = False) -> LineList:
    sequence = LineList(loader.construct_object(child, deep=True) for child in node.value)
    sequence.line = node.start_mark.line + 1
    sequence.item_lines = [child.start_mark.line + 1 for child in node.value]
    return sequence


_LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)
_LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG, _construct_sequence)


def safe_load_all_with_lines(content: str) -> list[Any]:
    """``yaml.safe_load_all`` with line-tracking mappings and sequences."""
    return list(yaml.load_all(content, Loader=_LineLoader))  # nosec B506 - SafeLoader subclass, no arbitrary object construction


def safe_load_with_lines(content: str) -> Any:
    """``yaml.safe_load`` with line-tracking mappings and sequences."""
    return yaml.load(content, Loader=_LineLoader)  # nosec B506 - SafeLoader subclass, no arbitrary object construction


def key_line(obj: Any, key: Any, default: int = 0) -> int:
    """Line of ``key`` inside a loaded mapping, else the mapping's line, else ``default``."""
    if isinstance(obj, LineDict):
        return obj.key_lines.get(key) or obj.line or default
    return default


def item_line(obj: Any, index: int, default: int = 0) -> int:
    """Line of item ``index`` inside a loaded sequence, else ``default``."""
    if isinstance(obj, LineList) and 0 <= index < len(obj.item_lines):
        return obj.item_lines[index]
    return default


def node_line(obj: Any, default: int = 0) -> int:
    """Line where a loaded mapping or sequence starts."""
    if isinstance(obj, (LineDict, LineList)) and obj.line:
        return obj.line
    return default
