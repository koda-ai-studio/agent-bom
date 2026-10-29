"""Recognize exact, published CPython documentation blocks, never their values alone."""

from __future__ import annotations

import ast
import hashlib
import inspect
from pathlib import Path

# CPython 3.13.5 / 3.14.8 documentation, reproduced with license/provenance
# under tests/fixtures/source_samples. Any changed text loses the exemption.
_URLLIB_DOC = "da3caa508119fc7a7499e9b0bf724f469c6e4ee081f9259a6c924da42a69116b"
_SENDMAIL_DOC = "992b2fb02626849708ba58c6ab9632547230673a475eecd6ec63ab8619c00368"
_MAX_PARSE_BYTES = 256 * 1024


def mask_public_docstrings(content: str, path: Path) -> str:
    """Mask only verified docstring spans while preserving line numbers.

    Both source ownership (module or SMTP.sendmail) and the complete canonical
    block must match. The same literal in executable code remains scannable.
    Invalid or oversized source receives no exemption.
    """
    urllib_module = path.parts[-2:] == ("urllib", "request.py")
    if not urllib_module and path.name != "smtplib.py":
        return content
    if len(content.encode("utf-8")) > _MAX_PARSE_BYTES:
        return content
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError, RecursionError):
        return content
    owners: list[ast.Module | ast.FunctionDef] = (
        [tree]
        if urllib_module
        else [
            method
            for cls in tree.body
            if isinstance(cls, ast.ClassDef) and cls.name == "SMTP"
            for method in cls.body
            if isinstance(method, ast.FunctionDef) and method.name == "sendmail"
        ]
    )
    lines = content.splitlines(keepends=True)
    for owner in owners:
        doc = ast.get_docstring(owner, clean=True)
        if doc is None or hashlib.sha256(inspect.cleandoc(doc).encode()).hexdigest() != (_URLLIB_DOC if urllib_module else _SENDMAIL_DOC):
            continue
        node = owner.body[0]
        for number in range(node.lineno, (node.end_lineno or node.lineno) + 1):
            # AST columns are UTF-8 byte offsets. Preserve all text outside the
            # expression, including a second statement on its closing line.
            line = lines[number - 1].encode()
            start = node.col_offset if number == node.lineno else 0
            end = node.end_col_offset if number == node.end_lineno and node.end_col_offset is not None else len(line.rstrip(b"\r\n"))
            lines[number - 1] = (line[:start] + b" " * (end - start) + line[end:]).decode()
    return "".join(lines)


def mask_public_module_links(content: str, path: Path) -> str:
    """Mask exact CPython module-catalog links, never arbitrary assignments.

    CPython 3.14.8 Lib/pydoc_data/module_docs.py maps module names to public
    documentation anchors. The spwd key resembles a password assignment.
    Only the canonical value in that module's top-level module_docs dictionary
    is masked; changed values, duplicate entries and adjacent code are scanned.
    """
    if path.parts[-2:] != ("pydoc_data", "module_docs.py") or len(content.encode("utf-8")) > _MAX_PARSE_BYTES:
        return content
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError, RecursionError):
        return content
    lines = content.splitlines(keepends=True)
    for statement in tree.body:
        if not (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
            and statement.targets[0].id == "module_docs"
            and isinstance(statement.value, ast.Dict)
        ):
            continue
        for key, value in zip(statement.value.keys, statement.value.values):
            if not (
                isinstance(key, ast.Constant)
                and key.value in ("pwd", "spwd")
                and isinstance(value, ast.Constant)
                and value.value == f"{key.value}#module-{key.value}"
            ):
                continue
            # AST columns count UTF-8 bytes. Keep surrounding code and lines.
            for number in range(value.lineno, (value.end_lineno or value.lineno) + 1):
                line = lines[number - 1].encode()
                start = value.col_offset if number == value.lineno else 0
                end = value.end_col_offset if number == value.end_lineno else len(line.rstrip(b"\r\n"))
                assert end is not None
                lines[number - 1] = (line[:start] + b" " * (end - start) + line[end:]).decode()
    return "".join(lines)
