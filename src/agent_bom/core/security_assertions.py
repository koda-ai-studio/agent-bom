"""Boolean risk assertions shared by graph observation and correlation merges."""

SECURITY_ASSERTIONS = frozenset(
    {
        "admin_equivalent",
        "internet_exposed",
        "internet_facing",
        "is_public",
        "on_attack_path",
        "public",
        "public_access",
        "publicly_accessible",
        "toxic_exposed_sensitive",
        "toxic_exposed_vulnerable",
    }
)
