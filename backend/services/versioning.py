"""Ecosystem-aware version comparison and OSV affected-range evaluation.

The comparators are intentionally small. They cover the version formats
found in the vast majority of npm / PyPI / Maven releases. When a version
cannot be parsed, VersionParseError is raised so callers can report the
result as *inconclusive* instead of guessing.
"""

from __future__ import annotations

import re
from typing import Any

from packaging.version import InvalidVersion, Version


class VersionParseError(ValueError):
    pass


# --------------------------------------------------------------- npm/semver -

_SEMVER = re.compile(
    r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


def _semver_key(version: str) -> tuple:
    m = _SEMVER.match(version.strip().lstrip("="))
    if not m:
        raise VersionParseError(f"not a semver version: {version!r}")
    major, minor, patch, pre = m.groups()
    if pre is None:
        pre_key: tuple = (1,)  # a release sorts after all its prereleases
    else:
        parts = tuple(
            (0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")
        )
        pre_key = (0, parts)
    return (int(major), int(minor), int(patch), pre_key)


# ------------------------------------------------------------------- Maven -

_MAVEN_QUALIFIERS = {
    "alpha": 1, "a": 1, "beta": 2, "b": 2, "milestone": 3, "m": 3,
    "rc": 4, "cr": 4, "snapshot": 5, "": 6, "ga": 6, "final": 6,
    "release": 6, "sp": 7,
}
_RELEASE_TOKEN = (0, 6, "")
_MAVEN_KEY_LEN = 12


def _maven_key(version: str) -> tuple:
    tokens = re.findall(r"\d+|[a-zA-Z]+", version.lower())
    if not tokens:
        raise VersionParseError(f"not a Maven version: {version!r}")
    items: list[tuple] = []
    for t in tokens:
        if t.isdigit():
            items.append((1, int(t), ""))
        else:
            items.append((0, _MAVEN_QUALIFIERS.get(t, 8), t))
    # Maven normalisation: zeros before a qualifier or at the end are dropped
    # so that 1.0 == 1.0.0 and 1.0-rc1 == 1-rc-1.
    cleaned: list[tuple] = []
    for i, item in enumerate(items):
        nxt = items[i + 1] if i + 1 < len(items) else None
        if item == (1, 0, "") and (nxt is None or nxt[0] == 0) and i > 0:
            continue
        cleaned.append(item)
    while len(cleaned) > 1 and cleaned[-1] == (1, 0, ""):
        cleaned.pop()
    # Release-equivalent qualifiers at the end mean the same as nothing.
    while cleaned and cleaned[-1][0] == 0 and cleaned[-1][1] == 6:
        cleaned.pop()
    if len(cleaned) > _MAVEN_KEY_LEN:
        cleaned = cleaned[:_MAVEN_KEY_LEN]
    cleaned += [_RELEASE_TOKEN] * (_MAVEN_KEY_LEN - len(cleaned))
    return tuple(cleaned)


# ------------------------------------------------------------------ public -

def version_key(ecosystem: str, version: str) -> tuple:
    """Sortable key. Raises VersionParseError for unparseable input."""
    if version == "0":  # OSV's "introduced: 0" means "from the beginning"
        return (0,)
    if ecosystem == "PyPI":
        try:
            return (1, Version(version))
        except InvalidVersion as exc:
            raise VersionParseError(str(exc)) from exc
    if ecosystem == "npm":
        return (1, _semver_key(version))
    return (1, _maven_key(version))


def compare(ecosystem: str, a: str, b: str) -> int:
    ka, kb = version_key(ecosystem, a), version_key(ecosystem, b)
    return (ka > kb) - (ka < kb)


def major_of(ecosystem: str, version: str) -> int | None:
    try:
        if ecosystem == "PyPI":
            return Version(version).major
        m = re.match(r"v?(\d+)", version)
        return int(m.group(1)) if m else None
    except InvalidVersion:
        return None


def _event_kind(event: dict[str, str]) -> tuple[str, str] | None:
    for kind in ("introduced", "fixed", "last_affected", "limit"):
        if kind in event:
            return kind, event[kind]
    return None


def _range_contains(ecosystem: str, version: str, events: list[dict]) -> bool:
    vk = version_key(ecosystem, version)
    parsed = [k for k in (_event_kind(e) for e in events) if k]
    parsed.sort(key=lambda kv: version_key(ecosystem, kv[1]))
    affected = False
    for kind, ev in parsed:
        ek = version_key(ecosystem, ev)
        if kind == "introduced" and ek <= vk:
            affected = True
        elif kind == "fixed" and ek <= vk:
            affected = False
        elif kind == "last_affected" and ek < vk:
            affected = False
        elif kind == "limit" and ek <= vk:
            affected = False
    return affected


def _usable_ranges(entry: dict[str, Any]) -> list[dict]:
    return [r for r in entry.get("ranges", []) if r.get("type") in ("SEMVER", "ECOSYSTEM")]


def is_affected(ecosystem: str, version: str, entry: dict[str, Any]) -> bool | None:
    """Evaluate one OSV `affected[]` entry.

    Returns True/False, or None when the entry cannot be evaluated locally
    (no usable ranges, or versions we cannot parse).
    """
    if version in entry.get("versions", []):
        return True
    ranges = _usable_ranges(entry)
    if not ranges:
        return False if entry.get("versions") else None
    try:
        return any(_range_contains(ecosystem, version, r.get("events", [])) for r in ranges)
    except VersionParseError:
        return None


def fixed_version_for(ecosystem: str, version: str, entry: dict[str, Any]) -> str | None:
    """Smallest `fixed` event greater than `version` in a range that contains it."""
    best: str | None = None
    try:
        vk = version_key(ecosystem, version)
        for r in _usable_ranges(entry):
            events = r.get("events", [])
            if not _range_contains(ecosystem, version, events):
                continue
            for e in events:
                fx = e.get("fixed")
                if fx and version_key(ecosystem, fx) > vk:
                    if best is None or version_key(ecosystem, fx) < version_key(ecosystem, best):
                        best = fx
    except VersionParseError:
        return None
    return best


def constraint_allows(ecosystem: str, declared: str | None, candidate: str) -> bool | None:
    """Does the declared manifest constraint already admit `candidate`?

    Returns None when the constraint form is not understood.
    """
    if not declared:
        return None
    spec = declared.strip()
    try:
        if ecosystem == "PyPI":
            from packaging.specifiers import InvalidSpecifier, SpecifierSet
            try:
                return SpecifierSet(spec).contains(candidate, prereleases=False)
            except InvalidSpecifier:
                return None
        if ecosystem == "npm":
            m = re.match(r"^(\^|~|>=)?\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?$", spec)
            if not m:
                return None
            op, ma, mi, pa = m.group(1), int(m.group(2)), int(m.group(3) or 0), int(m.group(4) or 0)
            base = f"{ma}.{mi}.{pa}"
            if compare("npm", candidate, base) < 0:
                return False
            if op is None:
                return compare("npm", candidate, base) == 0
            if op == ">=":
                return True
            c = _semver_key(candidate)
            if op == "~":
                return (c[0], c[1]) == (ma, mi)
            # caret: lock the left-most non-zero component
            if ma > 0:
                return c[0] == ma
            if mi > 0:
                return c[0] == 0 and c[1] == mi
            return (c[0], c[1], c[2]) == (0, 0, pa)
        # Maven: plain versions are exact pins.
        if re.match(r"^[\[(]", spec):
            return None
        return compare("Maven", candidate, spec) == 0
    except VersionParseError:
        return None
