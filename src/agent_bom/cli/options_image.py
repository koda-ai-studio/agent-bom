"""Image pull and supply-chain options shared by ``scan --image`` and ``agent-bom image``."""

from __future__ import annotations

from typing import Any

import click

PULL_MODE_HELP = (
    "How to fetch images: auto (registry over the OCI distribution API, Docker daemon only if that fails), "
    "registry (never the daemon) or daemon (never the registry)."
)


def image_supply_chain_options(*, short_aliases: bool = False) -> list[Any]:
    """``--image-pull-mode``, ``--image-cosign-key`` and ``--require-image-signature``.

    ``short_aliases`` adds ``--pull-mode`` / ``--cosign-key`` / ``--require-signature``
    for the focused ``image`` command, where the ``image-`` prefix is redundant.
    """
    pull = ("--pull-mode", "--image-pull-mode") if short_aliases else ("--image-pull-mode",)
    key = ("--cosign-key", "--image-cosign-key") if short_aliases else ("--image-cosign-key",)
    require = ("--require-signature", "--require-image-signature") if short_aliases else ("--require-image-signature",)
    return [
        click.option(
            *pull,
            "image_pull_mode",
            type=click.Choice(["auto", "registry", "daemon"]),
            default="auto",
            show_default=True,
            envvar="AGENT_BOM_IMAGE_PULL_MODE",
            help=PULL_MODE_HELP,
        ),
        click.option(
            *key,
            "image_cosign_key",
            type=click.Path(dir_okay=False),
            default=None,
            envvar="AGENT_BOM_IMAGE_COSIGN_KEY",
            help="Cosign public key (PEM) to verify image signatures with. Without it, signatures are reported as present, not verified.",
        ),
        click.option(
            *require,
            "require_image_signature",
            is_flag=True,
            default=False,
            help="Fail (exit 1) when an image is not signed — or, with a cosign key, when its signature does not verify.",
        ),
    ]


def image_supply_chain_option_group(fn: Any) -> Any:
    """The image pull/signature options as a ``scan`` option group."""
    for option in reversed(image_supply_chain_options()):
        fn = option(fn)
    return fn
