"""agent-bom-guard: a PreToolUse hook that vets package installs before Claude runs them.

Reads the hook event on stdin and writes at most one JSON object to stdout. It
blocks known-malicious and typosquatted packages (OSV MAL- reports and CWE-506
malware advisories included), warns on advisories for an exact pinned version,
and prints nothing for anything else. Shell text is
parsed, never executed. Any internal failure exits 0 so the command proceeds.
"""

from __future__ import annotations

import json
import os
import re
import sys
from difflib import SequenceMatcher
from typing import Any, Mapping, Sequence

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
# Keep the plugin folder unmodified: no __pycache__ beside the parser. Set after
# the stdlib imports so the interpreter's own bytecode cache still applies to them.
sys.dont_write_bytecode = True

from command_parser import Package, parse_command  # noqa: E402

DEFAULTS: dict[str, Any] = {"on_match": "block", "osv_lookup": True}
OSV_QUERY_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
OSV_ECOSYSTEMS = {"npm": "npm", "pypi": "PyPI", "cargo": "crates.io", "go": "Go"}
QUERY_TIMEOUT = 3.0
DETAIL_TIMEOUT = 2.0
MAX_DETAILS = 6
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
TYPOSQUAT_THRESHOLD = 0.85
EDIT1_MIN_LEN = 6
MAX_EDITS = 2
MALWARE_CWE = "CWE-506"
SEVERITY_RANK = {"critical": 0, "high": 1, "moderate": 2, "medium": 2, "low": 3}

_DATA: dict[str, Any] | None = None


def _data() -> dict[str, Any]:
    global _DATA
    if _DATA is None:
        with open(os.path.join(HERE, "guard_data.json"), encoding="utf-8") as handle:
            _DATA = json.load(handle)
    return _DATA


# --- typosquat check: a port of agent_bom.malicious.check_typosquat over the bundled data ---


def _single_substitution(a: str, b: str) -> bool:
    return len(a) == len(b) and sum(1 for x, y in zip(a, b) if x != y) == 1


def _edit_distance(a: str, b: str, limit: int) -> int:
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        row = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            row[j] = min(prev[j] + 1, row[j - 1] + 1, prev[j - 1] + (ca != cb))
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                row[j] = min(row[j], prev2[j - 2] + 1)
        if min(row) > limit:
            return limit + 1
        prev2, prev = prev, row
    return prev[-1]


def check_typosquat(name: str, ecosystem: str) -> str | None:
    """Return the popular package ``name`` imitates, or None."""
    data = _data()
    eco = ecosystem.lower()
    popular = data["popular"].get(eco, [])
    normalized = re.sub(r"[-_.]+", "-", name.lower()) if eco == "pypi" else name.lower()
    if not popular or normalized in popular:
        return None
    if normalized in data["known_legitimate"].get(eco, []) or normalized in data["established"].get(eco, []):
        return None
    if eco == "npm" and normalized.startswith(tuple(data["safe_npm_scopes"])):
        return None
    best, best_ratio = "", 0.0
    matcher = SequenceMatcher(None, "", normalized, autojunk=False)
    for candidate in popular:
        if 2 * min(len(normalized), len(candidate)) < TYPOSQUAT_THRESHOLD * (len(normalized) + len(candidate)):
            continue
        if normalized.startswith(candidate + "-") or normalized.endswith("-" + candidate):
            continue
        matcher.set_seq1(candidate)
        if matcher.quick_ratio() < TYPOSQUAT_THRESHOLD:
            continue
        ratio = matcher.ratio()
        if ratio > best_ratio and ratio >= TYPOSQUAT_THRESHOLD and _edit_distance(normalized, candidate, MAX_EDITS) <= MAX_EDITS:
            best, best_ratio = candidate, ratio
    if best:
        return best
    if len(normalized) >= EDIT1_MIN_LEN:
        return next((c for c in sorted(popular) if _single_substitution(normalized, c)), None)
    return None


# --- bundled known-malicious names ---


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version))


def _in_range(version: str | None, spec: str) -> bool:
    """True when ``version`` falls in an affected range such as ``*``, ``>=1.0.16`` or ``0.0.2``.

    An unversioned install resolves to whatever the registry serves, so it counts
    as affected; so does a range this parser does not understand.
    """
    if version is None or spec.strip() in {"", "*"}:
        return True
    key = _version_key(version)
    for clause in spec.split(","):
        match = re.fullmatch(r"\s*(>=|<=|>|<|==|=)?\s*([0-9][0-9A-Za-z.+-]*)\s*", clause)
        if not match:
            return True
        op, bound = match.group(1) or "==", _version_key(match.group(2))
        checks = {">=": key >= bound, "<=": key <= bound, ">": key > bound, "<": key < bound}
        if not checks.get(op, key == bound):
            return False
    return True


def _label(pkg: Package) -> str:
    return f"{pkg.name}@{pkg.version}" if pkg.version else pkg.name


def _offline_findings(packages: Sequence[Package]) -> tuple[dict[str, list[str]], list[str]]:
    blocks: dict[str, list[str]] = {}
    warnings: list[str] = []
    known = {(eco, name): (spec, adv) for eco, name, spec, adv in _data()["known_malicious"]}
    for pkg in packages:
        hit = known.get((pkg.ecosystem, pkg.name))
        if hit and _in_range(pkg.version, hit[0]):
            blocks.setdefault(_label(pkg), []).append(f"listed as malicious by agent-bom ({hit[1]}, affected {hit[0]})")
        elif hit:
            warnings.append(f"{_label(pkg)}: this name is listed as malicious ({hit[1]}) for versions {hit[0]}; check the source")
        target = check_typosquat(pkg.name, pkg.ecosystem)
        if target:
            blocks.setdefault(_label(pkg), []).append(f"looks like a typosquat of {target}; did you mean {target}?")
    return blocks, warnings


# --- OSV lookup ---


class OSVClient:
    """Minimal api.osv.dev client. Sends only package name, ecosystem and version."""

    def _request(self, url: str, payload: dict[str, Any] | None, timeout: float) -> Any:
        import urllib.request  # deferred: importing it costs more than the whole offline check

        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json", "User-Agent": "agent-bom-guard"}
        request = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read(MAX_RESPONSE_BYTES))

    def query(self, packages: Sequence[Package], timeout: float) -> list[list[str]]:
        queries = []
        for pkg in packages:
            query: dict[str, Any] = {"package": {"name": pkg.name, "ecosystem": OSV_ECOSYSTEMS[pkg.ecosystem]}}
            if pkg.version:
                query["version"] = pkg.version
            queries.append(query)
        results = self._request(OSV_QUERY_URL, {"queries": queries}, timeout)["results"]
        return [[str(v["id"]) for v in result.get("vulns", [])] for result in results]

    def detail(self, vuln_id: str, timeout: float) -> dict[str, Any]:
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", vuln_id):
            return {}
        return self._request(OSV_VULN_URL + vuln_id, None, timeout)


def _severity(detail: Mapping[str, Any]) -> str:
    value = str((detail.get("database_specific") or {}).get("severity") or "").lower()
    return value if value in SEVERITY_RANK else "unrated"


def _details(osv: Any, ids: Sequence[str]) -> dict[str, dict[str, Any]]:
    from concurrent.futures import ThreadPoolExecutor

    def fetch(vuln_id: str) -> dict[str, Any]:
        try:
            return osv.detail(vuln_id, DETAIL_TIMEOUT) or {}
        except Exception:
            return {}

    wanted = list(ids)[:MAX_DETAILS]
    with ThreadPoolExecutor(max_workers=max(1, len(wanted))) as pool:
        return dict(zip(wanted, pool.map(fetch, wanted)))


def _distinct(ids: Sequence[str], details: Mapping[str, dict[str, Any]]) -> list[str]:
    """Drop withdrawn advisories and aliases of one already kept, most severe first."""
    live = [i for i in ids if not details.get(i, {}).get("withdrawn")]
    ranked = sorted(live, key=lambda i: (SEVERITY_RANK.get(_severity(details.get(i, {})), 9), i))
    kept: list[str] = []
    seen: set[str] = set()
    for vuln_id in ranked:
        names = {vuln_id, *details.get(vuln_id, {}).get("aliases", [])}
        if names & seen:
            continue
        seen |= names
        kept.append(vuln_id)
    return kept


def _advisory_warning(pkg: Package, ids: Sequence[str], details: Mapping[str, dict[str, Any]]) -> str | None:
    kept = _distinct(ids, details)
    if not kept:
        return None
    shown = ", ".join(f"{i} ({_severity(details[i])})" if i in details else i for i in kept[:5])
    more = f" and {len(kept) - 5} more" if len(kept) > 5 else ""
    noun = "advisory" if len(kept) == 1 else "advisories"
    return f"{_label(pkg)} has {len(kept)} known {noun}: {shown}{more}. Prefer a fixed version."


def _is_malware(vuln_id: str, detail: Mapping[str, Any]) -> bool:
    """OSV malware: an OpenSSF MAL- report, or an advisory tagged CWE-506 (embedded malicious code).

    GitHub's malware advisories (crossenv, event-stream 3.3.6) reach OSV as
    GHSA ids with CWE-506 and no MAL- alias, so the id prefix alone misses them.
    """
    if vuln_id.upper().startswith("MAL-"):
        return True
    return MALWARE_CWE in ((detail.get("database_specific") or {}).get("cwe_ids") or [])


def _has_clean_release(detail: Mapping[str, Any], pkg: Package) -> bool:
    """True when the advisory leaves ``pkg`` a clean release for an unpinned install to resolve to.

    That is a range with a ``fixed`` event, or an affected entry that lists
    explicit versions only. A range without a fix (``introduced: 0``, or only a
    ``last_affected``) covers every release.
    """
    entries = [a for a in detail.get("affected") or [] if str((a.get("package") or {}).get("name") or "").lower() == pkg.name.lower()]
    if not entries:
        return False
    for affected in entries:
        ranges = affected.get("ranges") or []
        if not ranges and not affected.get("versions"):
            return False
        for affected_range in ranges:
            if not any("fixed" in event for event in affected_range.get("events") or []):
                return False
    return True


def _interleaved(pending: Sequence[tuple[Package, list[str]]]) -> list[str]:
    """Advisory ids round-robin across packages, so one package's long history cannot use up the detail budget."""
    # MAL- reports first: whether one blocks depends on its affected versions.
    ordered = [i for _, ids in pending for i in ids if i.upper().startswith("MAL-")]
    for depth in range(max((len(ids) for _, ids in pending), default=0)):
        ordered.extend(ids[depth] for _, ids in pending if depth < len(ids) and ids[depth] not in ordered)
    return ordered


def _osv_findings(packages: Sequence[Package], osv: Any) -> tuple[dict[str, list[str]], list[str], list[str]]:
    try:
        results = osv.query(packages, QUERY_TIMEOUT)
        if len(results) != len(packages):
            raise ValueError("result count mismatch")
    except Exception:
        return {}, [], ["api.osv.dev could not be reached, so only the offline checks ran"]
    blocks: dict[str, list[str]] = {}
    pending = [(pkg, ids) for pkg, ids in zip(packages, results) if ids]
    details = _details(osv, _interleaved(pending))
    warnings: list[str] = []
    for pkg, ids in pending:
        live = [i for i in ids if not details.get(i, {}).get("withdrawn")]
        malware = [i for i in live if _is_malware(i, details.get(i, {}))]
        # A MAL- report whose document could not be fetched still blocks: fail closed on malware.
        every_release = [i for i in malware if i not in details or not _has_clean_release(details[i], pkg)]
        if malware and (pkg.version or every_release):
            shown = (malware if pkg.version else every_release)[:3]
            blocks.setdefault(_label(pkg), []).append(f"reported malicious on OSV ({', '.join(shown)})")
        elif malware:
            warnings.append(
                f"{_label(pkg)}: OSV reports malicious releases of this package ({', '.join(malware[:3])}); "
                "pin a version outside the affected range"
            )
        elif pkg.version and (warning := _advisory_warning(pkg, ids, details)):
            warnings.append(warning)
    return blocks, warnings, []


# --- decision ---


def read_options(env: Mapping[str, str]) -> dict[str, Any]:
    mode = env.get("CLAUDE_PLUGIN_OPTION_ON_MATCH", "").strip().lower()
    lookup = env.get("CLAUDE_PLUGIN_OPTION_OSV_LOOKUP", "").strip().lower()
    return {
        "on_match": mode if mode in {"block", "warn"} else DEFAULTS["on_match"],
        "osv_lookup": lookup not in {"false", "0", "no", "off"} if lookup else DEFAULTS["osv_lookup"],
    }


def _command(event: Any) -> str | None:
    if not isinstance(event, dict) or event.get("tool_name") != "Bash":
        return None
    tool_input = event.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    return command if isinstance(command, str) else None


def _render(blocks: Mapping[str, list[str]], warnings: list[str], notes: list[str], mode: str) -> dict[str, Any] | None:
    if not (blocks or warnings or notes):
        return None
    block_lines = [f"{label}: {'; '.join(reasons)}" for label, reasons in blocks.items()]
    lines = block_lines + warnings + notes
    output: dict[str, Any] = {"systemMessage": "agent-bom-guard: " + " | ".join(lines)}
    hook: dict[str, Any] = {"hookEventName": "PreToolUse", "additionalContext": "agent-bom-guard findings:\n- " + "\n- ".join(lines)}
    if block_lines and mode == "block":
        hook["permissionDecision"] = "deny"
        hook["permissionDecisionReason"] = (
            "agent-bom-guard blocked this install. "
            + " ".join(block_lines)
            + " Do not retry under another name; tell the user. They can install it themselves or set on_match to warn."
        )
    output["hookSpecificOutput"] = hook
    return output


def decide(event: Any, env: Mapping[str, str], osv: Any) -> dict[str, Any] | None:
    """Return the hook's JSON output for ``event``, or None to stay silent."""
    command = _command(event)
    if command is None:
        return None
    plan = parse_command(command)
    if not plan.packages and not plan.requirement_files:
        return None
    options = read_options(env)
    blocks, warnings = _offline_findings(plan.packages)
    notes: list[str] = []
    if options["osv_lookup"] and plan.packages:
        osv_blocks, osv_warnings, notes = _osv_findings(plan.packages, osv)
        for label, reasons in osv_blocks.items():
            blocks.setdefault(label, []).extend(reasons)
        warnings.extend(osv_warnings)
    if plan.requirement_files:
        files = ", ".join(plan.requirement_files[:5])
        notes.append(f"requirement files are not checked by this hook ({files}); check them with the agent-bom plugin or CLI")
    return _render(blocks, warnings, notes, options["on_match"])


def run(stdin_text: str, env: Mapping[str, str], osv: Any) -> str:
    try:
        event = json.loads(stdin_text)
    except ValueError:
        return ""
    try:
        output = decide(event, env, osv)
    except Exception as exc:
        note = f"agent-bom-guard: internal error ({type(exc).__name__}); this command was not checked"
        return json.dumps({"systemMessage": note})
    return json.dumps(output) if output else ""


def main() -> int:
    try:
        text = sys.stdin.read(1024 * 1024)
        out = run(text, os.environ, OSVClient())
        if out:
            sys.stdout.write(out + "\n")
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
