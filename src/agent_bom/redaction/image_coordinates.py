"""Bounded recognition for public image coordinates in secret redaction."""

import string

_LOWER_ALNUM = frozenset(string.ascii_lowercase + string.digits)
_TAG_START = frozenset(string.ascii_letters + string.digits + "_")
_TAG_CHARS = _TAG_START | frozenset(".-")
_HEX = frozenset(string.digits + "abcdef")


def _repository_component(value: str) -> bool:
    """Match alphanumeric runs separated by single dots, underscores or dashes."""
    if not value or value[0] not in _LOWER_ALNUM or value[-1] not in _LOWER_ALNUM:
        return False
    separator = False
    for char in value:
        if char in _LOWER_ALNUM:
            separator = False
        elif char in "._-" and not separator:
            separator = True
        else:
            return False
    return True


def is_digest_image_coordinate(value: str) -> bool:
    """Recognize the digest exception in linear, bounded work; never validate secrets.

    Oversized or malformed values use ordinary full-value redaction. The caller
    must still inspect a recognized repository/tag for embedded credentials.
    """
    if len(value) > 4096:
        return False
    reference, marker, digest = value.rpartition("@sha256:")
    if not marker or len(digest) != 64 or any(char not in _HEX for char in digest):
        return False
    components = reference.split("/")
    name, colon, tag = components[-1].partition(":")
    if colon and (not tag or len(tag) > 128 or tag[0] not in _TAG_START or any(char not in _TAG_CHARS for char in tag)):
        return False
    if not _repository_component(name):
        return False
    for component in components[:-1]:
        name, colon, port = component.partition(":")
        if colon and (not port or len(port) > 5 or any(char not in string.digits for char in port)):
            return False
        if not _repository_component(name):
            return False
    return True
