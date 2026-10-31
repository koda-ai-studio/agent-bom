"""Count a current graph's ordered source identities without decoding payloads."""

import json
from typing import Any


def count_snapshot_nodes(conn: Any, tenant: str, scans: list[str], entity_type: str, *, postgres: bool = False) -> int:
    """Match UnifiedGraph.add_node: the first source owns a duplicate ID's type."""
    if not scans:
        return 0
    marker = "%s" if postgres else "?"
    sources = (
        "SELECT scan_id, priority FROM jsonb_array_elements_text(%s::jsonb) WITH ORDINALITY AS s(scan_id, priority)"
        if postgres
        else "SELECT value AS scan_id, CAST(key AS INTEGER) AS priority FROM json_each(?)"
    )
    # Only fixed dialect fragments are interpolated; all caller values are bound.
    row = conn.execute(
        f"""WITH sources AS ({sources}), ranked AS (
            SELECT n.entity_type, ROW_NUMBER() OVER (PARTITION BY n.id ORDER BY s.priority) AS position
            FROM graph_nodes n JOIN sources s ON n.scan_id = s.scan_id
            WHERE n.tenant_id = {marker}
        ) SELECT COUNT(*) FROM ranked WHERE position = 1 AND entity_type = {marker}""",  # nosec B608
        (json.dumps(list(dict.fromkeys(scans))), tenant, entity_type),
    ).fetchone()
    return int(row[0])
