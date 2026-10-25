"""Which distro packages ship an upstream CPE product.

A CPE advisory (``php:php``) names upstream releases. Distributions ship the
same code under their own package names and backport fixes without changing
the upstream version, so an upstream range can never decide a distro package.
This explicit, tested mapping says which packages carry the product so a
matcher can report them as needing the distribution's verdict instead of
silently clean. No fuzzy name matching: a product is listed here or not at
all.

Each entry matches the source package when the scan recorded one (that is
what distro trackers key on, and it separates ``php8.2-cli`` built from
``php8.2`` from ``php8.2-redis`` built from ``php-redis``), and otherwise the
binary package name against the subpackages the core source builds.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DistroPackagePattern:
    ecosystem: str
    source: re.Pattern[str]
    binary: re.Pattern[str]


_PHP_DEB_CORE = (
    r"bcmath|bz2|cgi|cli|common|curl|dba|dev|enchant|fpm|gd|gmp|imap|interbase|intl|ldap|mbstring|mysql|odbc|opcache"
    r"|pgsql|phpdbg|pspell|readline|snmp|soap|sqlite3|sybase|tidy|xml|xsl|zip"
)
_PHP_RPM_CORE = (
    r"bcmath|cli|common|dba|dbg|devel|embedded|enchant|ffi|fpm|gd|gmp|intl|ldap|mbstring|mysqlnd|odbc|opcache|pdo"
    r"|pgsql|process|snmp|soap|sodium|tidy|xml"
)

CPE_DISTRO_PACKAGES: dict[str, tuple[DistroPackagePattern, ...]] = {
    "php:php": (
        DistroPackagePattern(
            "deb",
            re.compile(r"php\d+\.\d+"),
            re.compile(rf"php\d+\.\d+(?:-(?:{_PHP_DEB_CORE}))?|libapache2-mod-php\d+\.\d+|libphp\d+\.\d+-embed"),
        ),
        DistroPackagePattern("apk", re.compile(r"php\d+"), re.compile(r"php\d+(?:-(?!pecl-)[a-z0-9_-]+)?")),
        DistroPackagePattern("rpm", re.compile(r"php"), re.compile(rf"php(?:-(?:{_PHP_RPM_CORE}))?")),
    ),
}


def distro_ships_cpe_product(cpe_product: str, package: dict[str, Any]) -> bool:
    """Whether a stored distro package carries ``cpe_product`` (``vendor:product``)."""
    ecosystem = str(package.get("ecosystem") or "").lower()
    for pattern in CPE_DISTRO_PACKAGES.get(cpe_product.lower(), ()):
        if pattern.ecosystem != ecosystem:
            continue
        source = str(package.get("source_package") or "").strip().lower()
        if source:
            return pattern.source.fullmatch(source) is not None
        return pattern.binary.fullmatch(str(package.get("name") or "").strip().lower()) is not None
    return False
