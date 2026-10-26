"""Project SPDX 2.x tag-value documents onto the SPDX 2.x JSON shape.

Tag names follow the SPDX 2.2/2.3 specification (clauses 6-12). Only the
re-shaping lives here: the JSON reader owns package semantics, so a tag-value
document and its JSON twin produce identical packages. Multi-line values use
the spec's ``<text>...</text>`` wrapper.
"""

from __future__ import annotations

from typing import Any

MAX_TAG_VALUE_LINES = 2_000_000

_DOCUMENT_TAGS = {
    "SPDXVersion": "spdxVersion",
    "DataLicense": "dataLicense",
    "DocumentName": "name",
    "DocumentNamespace": "documentNamespace",
    "DocumentComment": "comment",
}
_CREATION_TAGS = {"Created": "created", "CreatorComment": "comment", "LicenseListVersion": "licenseListVersion"}
_PACKAGE_TAGS = {
    "PackageVersion": "versionInfo",
    "PackageFileName": "packageFileName",
    "PackageSupplier": "supplier",
    "PackageOriginator": "originator",
    "PackageDownloadLocation": "downloadLocation",
    "PackageHomePage": "homepage",
    "PackageSourceInfo": "sourceInfo",
    "PackageLicenseConcluded": "licenseConcluded",
    "PackageLicenseDeclared": "licenseDeclared",
    "PackageLicenseComments": "licenseComments",
    "PackageCopyrightText": "copyrightText",
    "PackageSummary": "summary",
    "PackageDescription": "description",
    "PackageComment": "comment",
    "PrimaryPackagePurpose": "primaryPackagePurpose",
    "ReleaseDate": "releaseDate",
    "BuiltDate": "builtDate",
    "ValidUntilDate": "validUntilDate",
}
_ANNOTATION_TAGS = {"AnnotationDate": "annotationDate", "AnnotationType": "annotationType", "AnnotationComment": "comment"}
# Tags that open a section whose own tags must not leak onto the previous package.
_SECTION_STARTS = {"FileName", "SnippetSPDXID", "LicenseID"}


def _unwrap(value: str) -> str:
    if value.startswith("<text>") and value.endswith("</text>"):
        return value[len("<text>") : -len("</text>")]
    return value


def _tag_lines(text: str) -> list[tuple[str, str]]:
    """Split into ``(tag, value)`` pairs, joining ``<text>`` blocks."""
    lines = text.splitlines()
    if len(lines) > MAX_TAG_VALUE_LINES:
        raise ValueError("SPDX tag-value document exceeds the supported line count")
    pairs: list[tuple[str, str]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        tag, sep, value = line.partition(":")
        if not sep:
            raise ValueError(f"SPDX tag-value line {index} is not a 'Tag: value' pair")
        value = value.strip()
        if value.startswith("<text>") and "</text>" not in value:
            block = [value]
            while index < len(lines) and "</text>" not in lines[index]:
                block.append(lines[index])
                index += 1
            if index >= len(lines):
                raise ValueError("SPDX tag-value <text> block is not terminated")
            block.append(lines[index].rstrip())
            index += 1
            value = "\n".join(block)
        pairs.append((tag.strip(), _unwrap(value)))
    return pairs


class _Builder:
    def __init__(self) -> None:
        self.document: dict[str, Any] = {"creationInfo": {"creators": []}, "packages": [], "relationships": []}
        self.package: dict[str, Any] | None = None
        self.annotation: dict[str, Any] | None = None
        self.section = "document"
        self.annotations: list[dict[str, Any]] = []

    def add(self, tag: str, value: str) -> None:
        if tag == "PackageName":
            self.package = {"name": value}
            self.document["packages"].append(self.package)
            self.section = "package"
        elif tag in _SECTION_STARTS:
            self.package, self.section = None, "other"
        elif tag == "Annotator":
            self.annotation = {"annotator": value}
            self.annotations.append(self.annotation)
        elif tag in _ANNOTATION_TAGS or tag == "SPDXREF":
            self._annotation_tag(tag, value)
        elif tag == "Relationship":
            self._relationship(value)
        elif tag == "RelationshipComment" and self.document["relationships"]:
            self.document["relationships"][-1]["comment"] = value
        elif tag == "SPDXID":
            self._spdx_id(value)
        elif self.section == "package" and self.package is not None:
            self._package_tag(tag, value)
        elif self.section == "document":
            self._document_tag(tag, value)

    def _annotation_tag(self, tag: str, value: str) -> None:
        if self.annotation is None:
            raise ValueError(f"SPDX tag-value {tag} appears before any Annotator")
        self.annotation["SPDXREF" if tag == "SPDXREF" else _ANNOTATION_TAGS[tag]] = value

    def _relationship(self, value: str) -> None:
        parts = value.split()
        if len(parts) != 3:
            raise ValueError("SPDX tag-value Relationship must be '<element> <TYPE> <element>'")
        self.document["relationships"].append({"spdxElementId": parts[0], "relationshipType": parts[1], "relatedSpdxElement": parts[2]})

    def _spdx_id(self, value: str) -> None:
        if self.section == "document":
            self.document["SPDXID"] = value
        elif self.section == "package" and self.package is not None:
            self.package["SPDXID"] = value

    def _package_tag(self, tag: str, value: str) -> None:
        package = self.package
        assert package is not None  # nosec B101 - guarded by caller
        if tag in _PACKAGE_TAGS:
            package[_PACKAGE_TAGS[tag]] = value
        elif tag == "FilesAnalyzed":
            package["filesAnalyzed"] = value.lower() == "true"
        elif tag == "PackageChecksum":
            algorithm, _, digest = value.partition(":")
            package.setdefault("checksums", []).append({"algorithm": algorithm.strip(), "checksumValue": digest.strip()})
        elif tag == "ExternalRef":
            parts = value.split(None, 2)
            if len(parts) != 3:
                raise ValueError("SPDX tag-value ExternalRef must be '<category> <type> <locator>'")
            package.setdefault("externalRefs", []).append(
                {"referenceCategory": parts[0], "referenceType": parts[1], "referenceLocator": parts[2]}
            )
        elif tag == "ExternalRefComment" and package.get("externalRefs"):
            package["externalRefs"][-1]["comment"] = value
        elif tag == "PackageLicenseInfoFromFiles":
            package.setdefault("licenseInfoFromFiles", []).append(value)
        elif tag == "PackageAttributionText":
            package.setdefault("attributionTexts", []).append(value)

    def _document_tag(self, tag: str, value: str) -> None:
        if tag in _DOCUMENT_TAGS:
            self.document[_DOCUMENT_TAGS[tag]] = value
        elif tag == "Creator":
            self.document["creationInfo"]["creators"].append(value)
        elif tag in _CREATION_TAGS:
            self.document["creationInfo"][_CREATION_TAGS[tag]] = value

    def finish(self) -> dict[str, Any]:
        document_id = self.document.get("SPDXID")
        packages = {pkg.get("SPDXID"): pkg for pkg in self.document["packages"] if pkg.get("SPDXID")}
        for annotation in self.annotations:
            subject = annotation.pop("SPDXREF", document_id)
            if subject in packages:
                packages[subject].setdefault("annotations", []).append(annotation)
            elif subject == document_id:
                self.document.setdefault("annotations", []).append(annotation)
        return self.document


def spdx_tagvalue_to_document(text: str) -> dict[str, Any]:
    """Return the SPDX 2.x JSON-shaped projection of a tag-value document."""
    builder = _Builder()
    for tag, value in _tag_lines(text):
        builder.add(tag, value)
    document = builder.finish()
    if not str(document.get("spdxVersion", "")).startswith("SPDX-2"):
        raise ValueError("SPDX tag-value input must declare SPDXVersion: SPDX-2.x")
    return document


def is_spdx_tagvalue(text: str) -> bool:
    """True when the first meaningful line is the SPDX version tag."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped.startswith("SPDXVersion:")
    return False
