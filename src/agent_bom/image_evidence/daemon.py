"""Bind local Docker images to an unambiguous observed registry reference."""

from agent_bom.oci_registry.reference import ImageReference, ReferenceError, parse_reference


def daemon_registry_reference(image_ref: str, repo_digests: object) -> ImageReference | None:
    """Never infer a registry repository from a local config ID or an unrelated alias."""
    if not isinstance(repo_digests, list) or len(repo_digests) > 256:
        return None
    try:
        requested = None if image_ref.startswith("sha256:") else parse_reference(image_ref)
    except ReferenceError:
        return None
    candidates = {}
    for raw in repo_digests:
        if not isinstance(raw, str):
            continue
        try:
            ref = parse_reference(raw)
        except ReferenceError:
            continue
        if ref.digest is None:
            continue
        if requested and (ref.registry, ref.repository) != (requested.registry, requested.repository):
            continue
        if requested and requested.digest and ref.digest != requested.digest:
            continue
        candidates[(ref.registry, ref.repository, ref.digest)] = ref
    return next(iter(candidates.values())) if len(candidates) == 1 else None
