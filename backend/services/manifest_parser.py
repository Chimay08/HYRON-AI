"""Parse dependency manifests and lockfiles into the normalised Project model.

Supported inputs                          coverage
  package.json                            npm, direct dependencies (declared ranges)
  package-lock.json / npm-shrinkwrap.json npm, resolved direct + transitive tree
  requirements*.txt                       PyPI, direct dependencies
  pyproject.toml                          PyPI, direct dependencies (PEP 621 / Poetry)
  poetry.lock (+ pyproject.toml)          PyPI, resolved direct + transitive tree
  pom.xml                                 Maven, direct dependencies
  *dependency-tree*.txt                   Maven, `mvn dependency:tree` output (transitive)
  other *.json                            HYRON dependency-tree format (see sample_data)

Files in the same directory are paired: a lockfile supersedes its manifest,
and pyproject.toml tells poetry.lock which packages are direct.

Content is only ever *parsed* as data; nothing is executed. XML is parsed
with defusedxml to block entity-expansion / XXE attacks.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections import defaultdict
from pathlib import PurePosixPath
from typing import Any

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from schemas.scan_result import Dependency, ParseIssue, Project

MAX_FILE_BYTES = 1_000_000
MAX_LOCKFILE_BYTES = 5_000_000
MAX_TREE_DEPTH = 25
MAX_TREE_NODES = 5_000
MAX_LOCK_DEPTH = 64
MAX_LOCK_NODES = 30_000

SUPPORTED_HELP = (
    "Supported: package.json, package-lock.json, npm-shrinkwrap.json, requirements*.txt, "
    "pyproject.toml, poetry.lock, pom.xml, Maven dependency-tree .txt, dependency-tree .json"
)
LOCKFILE_KINDS = {"npm_lock", "poetry_lock", "maven_tree"}


class ManifestError(ValueError):
    """Raised when a file is unsupported or cannot be parsed at all."""


def _path(filename: str) -> PurePosixPath:
    return PurePosixPath(filename.replace("\\", "/"))


def detect_kind(filename: str) -> str | None:
    name = _path(filename).name.lower()
    if name == "package.json":
        return "npm_manifest"
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        return "npm_lock"
    if name == "poetry.lock":
        return "poetry_lock"
    if name == "pyproject.toml":
        return "pyproject"
    if name == "pom.xml":
        return "maven_pom"
    if name.endswith(".txt") and re.search(r"dep(endency)?[-_]?tree", name):
        return "maven_tree"
    if name.endswith(".txt") and "requirements" in name:
        return "pypi_requirements"
    if name.endswith(".json"):
        return "tree"
    return None


def is_repository_manifest(path: str) -> bool:
    """Files worth fetching from a repository (generic .json files are excluded)."""
    kind = detect_kind(path)
    return kind is not None and kind != "tree"


def max_bytes_for(filename: str) -> int:
    return MAX_LOCKFILE_BYTES if detect_kind(filename) in LOCKFILE_KINDS else MAX_FILE_BYTES


def _decode(filename: str, content: bytes) -> str:
    if detect_kind(filename) is None:
        raise ManifestError(f"{filename}: unsupported file. {SUPPORTED_HELP}.")
    limit = max_bytes_for(filename)
    if len(content) > limit:
        raise ManifestError(f"{filename}: file exceeds {limit // 1000} KB limit")
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ManifestError(f"{filename}: file is not valid UTF-8 text") from exc


def _load_json(text: str, filename: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"{filename}: invalid JSON ({exc.msg} at line {exc.lineno})") from exc


def _load_toml(text: str, filename: str) -> dict:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"{filename}: invalid TOML ({exc})") from exc


def parse_file(filename: str, content: bytes) -> tuple[list[Project], list[ParseIssue]]:
    """Parse a single file. Raises ManifestError if it cannot be used at all."""
    text = _decode(filename, content)
    issues: list[ParseIssue] = []
    return _parse_single(detect_kind(filename), filename, text, issues), issues


def _parse_single(kind: str, filename: str, text: str, issues: list[ParseIssue],
                  companion: dict | None = None) -> list[Project]:
    if kind == "npm_manifest":
        return [parse_package_json(text, filename, issues)]
    if kind == "npm_lock":
        return [parse_npm_lockfile(text, filename, issues, companion)]
    if kind == "pypi_requirements":
        return [parse_requirements(text, filename, issues)]
    if kind == "pyproject":
        return [parse_pyproject(text, filename, issues)]
    if kind == "poetry_lock":
        return [parse_poetry_lock(text, filename, issues, companion)]
    if kind == "maven_pom":
        return [parse_pom(text, filename, issues)]
    if kind == "maven_tree":
        return parse_maven_tree(text, filename, issues)
    return parse_dependency_tree(_load_json(text, filename), filename, issues)


def parse_files(files: list[tuple[str, bytes]]) -> tuple[list[Project], list[ParseIssue]]:
    """Parse many files, pairing lockfiles with manifests in the same directory.

    Per-file failures are reported as issues instead of aborting the batch.
    """
    issues: list[ParseIssue] = []
    groups: dict[str, dict[str, list[tuple[str, str]]]] = defaultdict(lambda: defaultdict(list))
    for filename, content in files:
        try:
            text = _decode(filename, content)
        except ManifestError as exc:
            issues.append(ParseIssue(file=filename, message=str(exc), level="error"))
            continue
        groups[str(_path(filename).parent)][detect_kind(filename)].append((filename, text))

    projects: list[Project] = []

    def attempt(kind: str, filename: str, text: str, companion: dict | None = None) -> bool:
        try:
            projects.extend(_parse_single(kind, filename, text, issues, companion))
            return True
        except ManifestError as exc:
            issues.append(ParseIssue(file=filename, message=str(exc), level="error"))
            return False

    for kinds in groups.values():
        # npm: the lockfile wins; package.json only supplies the name / direct list.
        manifest, locks = kinds.get("npm_manifest", []), kinds.get("npm_lock", [])
        used_lock = False
        if locks:
            companion = None
            if manifest:
                try:
                    companion = _load_json(manifest[0][1], manifest[0][0])
                except ManifestError:
                    companion = None
            used_lock = attempt("npm_lock", *locks[0], companion=companion)
            if used_lock and manifest:
                issues.append(ParseIssue(
                    file=manifest[0][0], level="info",
                    message=f"superseded by {_path(locks[0][0]).name} (resolved versions)",
                ))
        if not used_lock:
            for f, t in manifest:
                attempt("npm_manifest", f, t)

        # Python: poetry.lock (+ pyproject for direct deps), else pyproject alone.
        pyproject, pylock = kinds.get("pyproject", []), kinds.get("poetry_lock", [])
        used_pylock = False
        if pylock:
            companion = None
            if pyproject:
                try:
                    companion = _load_toml(pyproject[0][1], pyproject[0][0])
                except ManifestError:
                    companion = None
            used_pylock = attempt("poetry_lock", *pylock[0], companion=companion)
        if not used_pylock:
            for f, t in pyproject:
                attempt("pyproject", f, t)
        for f, t in kinds.get("pypi_requirements", []):
            attempt("pypi_requirements", f, t)

        # Maven: a dependency:tree report supersedes pom.xml.
        used_tree = any([attempt("maven_tree", f, t) for f, t in kinds.get("maven_tree", [])])
        for f, t in kinds.get("maven_pom", []):
            if used_tree:
                issues.append(ParseIssue(file=f, level="info", message="superseded by Maven dependency-tree report"))
            else:
                attempt("maven_pom", f, t)

        for f, t in kinds.get("tree", []):
            attempt("tree", f, t)
    return projects, issues


def _fallback_name(filename: str, default: str) -> str:
    return _path(filename).parent.name or default


# --------------------------------------------------------------------- npm -

_NPM_EXACT = re.compile(r"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_NPM_LOWER = re.compile(r"^(\^|~|>=|=)?\s*v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?(-[0-9A-Za-z.-]+)?$")


def npm_version_from_spec(spec: str) -> tuple[str | None, str]:
    """Map an npm range to (version_to_scan, version_status)."""
    s = spec.strip()
    if not s or s in ("*", "x", "latest", "next") or re.match(
        r"^(file:|link:|git|http|workspace:|npm:|github:)", s
    ) or "/" in s or "||" in s or " - " in s:
        return None, "unresolved"
    if _NPM_EXACT.match(s.lstrip("=")):
        return s.lstrip("=v"), "exact"
    parts = s.split()
    first = parts[0]
    # ">=1.2.3 <2.0.0" style: use the lower comparator if the rest are upper bounds
    if len(parts) > 1 and not all(p.startswith("<") for p in parts[1:]):
        return None, "unresolved"
    m = _NPM_LOWER.match(first)
    if not m:
        return None, "unresolved"
    op, major, minor, patch, pre = m.groups()
    minor = "0" if minor in (None, "x", "*") else minor
    patch = "0" if patch in (None, "x", "*") else patch
    version = f"{major}.{minor}.{patch}{pre or ''}"
    if op in (None, "=") and m.group(3) not in (None, "x", "*") and m.group(4) not in (None, "x", "*"):
        return version, "exact"
    return version, "range_min"


def parse_package_json(text: str, filename: str, issues: list[ParseIssue]) -> Project:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"{filename}: invalid JSON ({exc.msg} at line {exc.lineno})") from exc
    if not isinstance(data, dict):
        raise ManifestError(f"{filename}: expected a JSON object")

    sections = [
        ("dependencies", "production"),
        ("optionalDependencies", "production"),
        ("devDependencies", "development"),
    ]
    deps: list[Dependency] = []
    seen: set[str] = set()
    for key, scope in sections:
        block = data.get(key) or {}
        if not isinstance(block, dict):
            issues.append(ParseIssue(file=filename, message=f"'{key}' is not an object; skipped"))
            continue
        for name, spec in block.items():
            if name in seen or not isinstance(spec, str):
                continue
            seen.add(name)
            version, status = npm_version_from_spec(spec)
            deps.append(Dependency(
                name=name, ecosystem="npm", version=version, declared=spec,
                version_status=status, scope=scope,
            ))
    if data.get("peerDependencies"):
        issues.append(ParseIssue(file=filename, message="peerDependencies are not analysed"))
    name = data.get("name") if isinstance(data.get("name"), str) else None
    return Project(
        name=name or _fallback_name(filename, "npm-app"), ecosystem="npm",
        source_file=filename, dependencies=deps,
    )


# -------------------------------------------------------------------- PyPI -

def pypi_version_from_req(req: Requirement) -> tuple[str | None, str]:
    specs = list(req.specifier)
    if any(not s.version.strip() for s in specs):
        # "requests===" has an operator but no version. Sending an empty version to
        # OSV would match every advisory for the package, so treat it as unresolved.
        return None, "unresolved"
    if len(specs) == 1 and specs[0].operator in ("==", "===") and "*" not in specs[0].version:
        return specs[0].version, "exact"
    for s in specs:
        if s.operator in (">=", "~="):
            return s.version, "range_min"
        if s.operator == "==" and s.version.endswith(".*"):
            return s.version[:-2] + ".0", "range_min"
    return None, "unresolved"


def parse_requirements(text: str, filename: str, issues: list[ParseIssue]) -> Project:
    lower = _path(filename).name.lower()
    scope = "development" if re.search(r"dev|test|lint|doc", lower) else "unknown"
    deps: list[Dependency] = []
    logical_lines: list[tuple[int, str]] = []
    buf, start = "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #", 1)[0].strip()
        if line.startswith("#"):
            line = ""
        if not buf:
            start = i
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        if buf.strip():
            logical_lines.append((start, buf.strip()))
        buf = ""

    for lineno, line in logical_lines:
        if line.startswith("-"):
            issues.append(ParseIssue(file=filename, message=f"line {lineno}: option '{line.split()[0]}' ignored"))
            continue
        if "://" in line or line.startswith((".", "/")):
            issues.append(ParseIssue(file=filename, message=f"line {lineno}: URL/path requirement not analysed"))
            continue
        line = re.split(r"\s--", line, maxsplit=1)[0]  # strip --hash etc.
        try:
            req = Requirement(line)
        except InvalidRequirement:
            issues.append(ParseIssue(file=filename, message=f"line {lineno}: could not parse '{line[:80]}'"))
            continue
        version, status = pypi_version_from_req(req)
        earlier = next((d for d in deps if d.name == canonicalize_name(req.name)), None)
        if earlier is not None:
            if (earlier.version, earlier.declared) == (version, str(req.specifier) or None):
                continue
            issues.append(ParseIssue(
                file=filename,
                message=f"line {lineno}: {req.name} is listed more than once with different constraints; "
                        "each version is scanned - check which one is actually installed",
            ))
        deps.append(Dependency(
            name=canonicalize_name(req.name), ecosystem="PyPI", version=version,
            declared=str(req.specifier) or None, version_status=status, scope=scope,
        ))
    if scope == "unknown":
        issues.append(ParseIssue(
            file=filename,
            message="requirements files do not state runtime context; scope recorded as 'unknown' "
                    "(scored like production)",
        ))
    stem = _path(filename).stem
    return Project(
        name=_fallback_name(filename, "python-app") if stem.lower() == "requirements" else stem,
        ecosystem="PyPI", source_file=filename, dependencies=deps,
    )


# ------------------------------------------------------------------- Maven -

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(el, name: str):
    for c in el:
        if _local(c.tag) == name:
            return c
    return None


def _text(el, name: str) -> str | None:
    c = _child(el, name)
    return c.text.strip() if c is not None and c.text else None


def parse_pom(text: str, filename: str, issues: list[ParseIssue]) -> Project:
    try:
        root = SafeET.fromstring(text)
    except DefusedXmlException as exc:
        raise ManifestError(f"{filename}: rejected unsafe XML ({type(exc).__name__})") from exc
    except SafeET.ParseError as exc:
        raise ManifestError(f"{filename}: invalid XML ({exc})") from exc
    if _local(root.tag) != "project":
        raise ManifestError(f"{filename}: root element is not <project>")

    parent = _child(root, "parent")
    group = _text(root, "groupId") or (parent is not None and _text(parent, "groupId")) or ""
    artifact = _text(root, "artifactId") or _fallback_name(filename, "maven-app")
    version = _text(root, "version") or (parent is not None and _text(parent, "version")) or ""

    props: dict[str, str] = {"project.version": version, "project.groupId": group}
    props_el = _child(root, "properties")
    if props_el is not None:
        for p in props_el:
            if p.text:
                props[_local(p.tag)] = p.text.strip()

    def resolve(value: str | None) -> str | None:
        if value is None:
            return None
        for _ in range(5):
            new = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), value)
            if new == value:
                break
            value = new
        return value

    deps: list[Dependency] = []
    deps_el = _child(root, "dependencies")
    for d in (deps_el if deps_el is not None else []):
        if _local(d.tag) != "dependency":
            continue
        g, a = resolve(_text(d, "groupId")), resolve(_text(d, "artifactId"))
        if not g or not a:
            issues.append(ParseIssue(file=filename, message="dependency without groupId/artifactId skipped"))
            continue
        raw_version = _text(d, "version")
        v = resolve(raw_version)
        if v is None:
            status, v = "unresolved", None
            issues.append(ParseIssue(file=filename, message=f"{g}:{a}: version managed by parent/BOM; not scanned"))
        elif "${" in v or v.startswith(("[", "(")):
            status, v = "unresolved", None
        else:
            status = "exact"
        mscope = (_text(d, "scope") or "compile").lower()
        scope = {"compile": "production", "runtime": "production", "test": "development"}.get(mscope, "unknown")
        deps.append(Dependency(
            name=f"{g}:{a}", ecosystem="Maven", version=v, declared=raw_version,
            version_status=status, scope=scope,
        ))
    return Project(name=artifact, ecosystem="Maven", source_file=filename, dependencies=deps)


# --------------------------------------------------------- dependency tree -

_ECOSYSTEMS = {"npm": "npm", "pypi": "PyPI", "maven": "Maven"}


def parse_dependency_tree(data: Any, filename: str, issues: list[ParseIssue]) -> list[Project]:
    """Parse the resolved-tree format used by sample_data/demo_dependencies.json."""
    if not isinstance(data, dict) or not isinstance(data.get("projects"), list):
        raise ManifestError(
            f"{filename}: not a dependency tree (expected an object with a 'projects' list). "
            "To scan an npm manifest, the file must be named package.json."
        )
    counter = {"n": 0}

    def build(node: Any, eco: str, inherited: str, depth: int) -> Dependency | None:
        if depth > MAX_TREE_DEPTH:
            raise ManifestError(f"{filename}: dependency tree deeper than {MAX_TREE_DEPTH}")
        counter["n"] += 1
        if counter["n"] > MAX_TREE_NODES:
            raise ManifestError(f"{filename}: more than {MAX_TREE_NODES} dependency nodes")
        if not isinstance(node, dict) or not isinstance(node.get("name"), str):
            issues.append(ParseIssue(file=filename, message="dependency entry without a name skipped"))
            return None
        scope = node.get("scope", inherited)
        if scope not in ("production", "development", "unknown"):
            scope = "unknown"
        version = node.get("version")
        name = canonicalize_name(node["name"]) if eco == "PyPI" else node["name"]
        children = [
            c for c in (build(ch, eco, scope, depth + 1) for ch in node.get("dependencies", []) or [])
            if c is not None
        ]
        return Dependency(
            name=name, ecosystem=eco,
            version=str(version) if version else None, declared=str(version) if version else None,
            version_status="exact" if version else "unresolved",
            scope=scope, dependencies=children,
        )

    projects: list[Project] = []
    for p in data["projects"]:
        if not isinstance(p, dict) or not isinstance(p.get("name"), str):
            issues.append(ParseIssue(file=filename, message="project entry without a name skipped"))
            continue
        eco = _ECOSYSTEMS.get(str(p.get("ecosystem", "")).lower())
        if eco is None:
            issues.append(ParseIssue(file=filename, message=f"{p['name']}: unsupported ecosystem; skipped"))
            continue
        deps = [d for d in (build(n, eco, "unknown", 1) for n in p.get("dependencies", []) or []) if d]
        projects.append(Project(
            name=p["name"], ecosystem=eco, source_file=filename,
            has_transitive_data=True, dependencies=deps,
        ))
    if not projects:
        raise ManifestError(f"{filename}: no valid projects found")
    return projects


# ------------------------------------------------------------ npm lockfile -

_SEMVERISH = re.compile(r"^\d+\.\d+\.\d+")


def _npm_lock_version(value: Any) -> str | None:
    """Lockfile versions can be URLs/aliases for git or tarball deps; those are unresolved."""
    return value if isinstance(value, str) and _SEMVERISH.match(value) else None


class _Budget:
    def __init__(self, filename: str, limit: int) -> None:
        self.filename, self.limit, self.count, self.truncated = filename, limit, 0, False
        self.missing: set[str] = set()

    def tick(self) -> None:
        self.count += 1
        if self.count > self.limit:
            raise ManifestError(f"{self.filename}: dependency tree larger than {self.limit} entries")


def _lock_dep(name: str, version: str | None, scope: str, children: list[Dependency],
              ecosystem: str = "npm", inferred: bool = False) -> Dependency:
    return Dependency(
        name=name, ecosystem=ecosystem, version=version, declared=version,
        version_status="exact" if version else "unresolved", scope=scope,
        inferred=inferred, dependencies=children,
    )


def parse_npm_lockfile(text: str, filename: str, issues: list[ParseIssue], manifest: dict | None = None) -> Project:
    data = _load_json(text, filename)
    if not isinstance(data, dict):
        raise ManifestError(f"{filename}: expected a JSON object")
    manifest = manifest if isinstance(manifest, dict) else {}
    name = manifest.get("name") or data.get("name") or _fallback_name(filename, "npm-app")
    budget = _Budget(filename, MAX_LOCK_NODES)
    packages = data.get("packages")
    if isinstance(packages, dict) and packages:
        deps = _npm_lock_v2(packages, budget, issues, filename)
    elif isinstance(data.get("dependencies"), dict):
        deps = _npm_lock_v1(data["dependencies"], budget, issues, filename, manifest)
    else:
        raise ManifestError(f"{filename}: no 'packages' or 'dependencies' section - not an npm lockfile")
    if budget.missing:
        sample = ", ".join(sorted(budget.missing)[:5])
        issues.append(ParseIssue(file=filename, message=(
            f"{len(budget.missing)} required package(s) are not present in the lockfile and were skipped "
            f"(e.g. {sample}); the graph may be incomplete"
        )))
    if budget.truncated:
        issues.append(ParseIssue(file=filename, message=f"tree deeper than {MAX_LOCK_DEPTH} levels was truncated"))
    return Project(name=str(name), ecosystem="npm", source_file=filename, has_transitive_data=True, dependencies=deps)


def _npm_scope(meta: dict) -> str:
    return "development" if meta.get("dev") or meta.get("devOptional") else "production"


def _npm_lock_v2(packages: dict, budget: _Budget, issues: list[ParseIssue], filename: str) -> list[Dependency]:
    expanded: set[str] = set()

    def resolve(from_path: str, dep: str) -> str | None:
        """Node's module resolution: nearest node_modules/<dep> walking up from from_path."""
        base = from_path
        while True:
            candidate = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
            if candidate in packages:
                return candidate
            if not base:
                return None
            idx = base.rfind("/node_modules/")
            base = base[:idx] if idx >= 0 else ""

    def build(path: str, scope: str, depth: int) -> Dependency:
        budget.tick()
        meta = packages.get(path) or {}
        if meta.get("link") and meta.get("resolved") in packages:   # workspace symlink
            path = meta["resolved"]
            meta = packages[path]
        pkg_name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
        version = _npm_lock_version(meta.get("version"))
        children: list[Dependency] = []
        key = f"{pkg_name}@{version}"
        if key not in expanded:
            expanded.add(key)
            if depth >= MAX_LOCK_DEPTH:
                budget.truncated = True
            else:
                optional = meta.get("optionalDependencies") or {}
                for child in {**(meta.get("dependencies") or {}), **optional}:
                    child_path = resolve(path, child)
                    if child_path is None:
                        if child not in optional:
                            budget.missing.add(child)
                        continue
                    children.append(build(child_path, _npm_scope(packages[child_path]), depth + 1))
        return _lock_dep(pkg_name, version, scope, children)

    root = packages.get("") or {}
    if not root:
        issues.append(ParseIssue(file=filename, message="lockfile has no root entry; direct dependencies unknown"))
    direct: list[Dependency] = []
    seen: set[str] = set()
    for section, scope in (("dependencies", "production"), ("optionalDependencies", "production"),
                           ("devDependencies", "development")):
        for dep in root.get(section) or {}:
            if dep in seen:
                continue
            seen.add(dep)
            path = resolve("", dep)
            if path is None:
                if section != "optionalDependencies":
                    budget.missing.add(dep)
                continue
            direct.append(build(path, scope, 1))
    return direct


def _npm_lock_v1(top: dict, budget: _Budget, issues: list[ParseIssue], filename: str, manifest: dict) -> list[Dependency]:
    expanded: set[str] = set()

    def lookup(name: str, stack: list[dict]) -> tuple[dict | None, list[dict] | None]:
        for i in range(len(stack) - 1, -1, -1):
            if name in stack[i]:
                return stack[i][name], stack[: i + 1]
        return None, None

    def build(name: str, meta: dict, def_stack: list[dict], scope: str, depth: int, inferred: bool = False) -> Dependency:
        budget.tick()
        version = _npm_lock_version(meta.get("version"))
        children: list[Dependency] = []
        key = f"{name}@{version}"
        if key not in expanded:
            expanded.add(key)
            if depth >= MAX_LOCK_DEPTH:
                budget.truncated = True
            else:
                stack = def_stack + [meta.get("dependencies") or {}]
                for child in meta.get("requires") or {}:
                    child_meta, child_stack = lookup(child, stack)
                    if child_meta is None:
                        budget.missing.add(child)
                        continue
                    children.append(build(child, child_meta, child_stack, _npm_scope(child_meta), depth + 1))
        return _lock_dep(name, version, scope, children, inferred=inferred)

    direct_names: list[tuple[str, str]] = []
    for section, scope in (("dependencies", "production"), ("optionalDependencies", "production"),
                           ("devDependencies", "development")):
        for dep in manifest.get(section) or {}:
            if dep not in {n for n, _ in direct_names}:
                direct_names.append((dep, scope))
    inferred = False
    if not direct_names:
        required: set[str] = set()

        def collect(entries: dict) -> None:
            for meta in entries.values():
                required.update((meta.get("requires") or {}).keys())
                collect(meta.get("dependencies") or {})
        collect(top)
        direct_names = [(n, _npm_scope(m)) for n, m in top.items() if n not in required]
        inferred = True
        issues.append(ParseIssue(file=filename, message=(
            "lockfile v1 without package.json: direct dependencies were inferred as packages no other "
            "package requires (shown as inferred links)"
        )))
    out = []
    for dep, scope in direct_names:
        meta = top.get(dep)
        if meta is None:
            budget.missing.add(dep)
            continue
        out.append(build(dep, meta, [top], scope, 1, inferred=inferred))
    return out


# ------------------------------------------------------- pyproject / poetry -

def _poetry_constraint(constraint: str) -> tuple[str | None, str]:
    c = constraint.strip()
    if not c or c == "*":
        return None, "unresolved"
    if re.fullmatch(r"\d+(\.\d+)*", c):               # Poetry: bare version == exact pin
        return c, "exact"
    if c[0] in "^~" and not c.startswith("~="):
        version, _ = npm_version_from_spec(c)
        return (version, "range_min") if version else (None, "unresolved")
    try:
        return pypi_version_from_req(Requirement("x" + c))
    except InvalidRequirement:
        return None, "unresolved"


def _pyproject_direct(data: dict, filename: str, issues: list[ParseIssue]) -> list[Dependency]:
    deps: list[Dependency] = []
    seen: set[str] = set()

    def add(name: str, version: str | None, declared: str | None, status: str, scope: str) -> None:
        cname = canonicalize_name(name)
        if cname in seen or cname == "python":
            return
        seen.add(cname)
        deps.append(Dependency(name=cname, ecosystem="PyPI", version=version, declared=declared,
                               version_status=status, scope=scope))

    def add_pep508(spec: Any, scope: str) -> None:
        if not isinstance(spec, str):
            return
        try:
            req = Requirement(spec)
        except InvalidRequirement:
            issues.append(ParseIssue(file=filename, message=f"could not parse dependency '{spec[:80]}'"))
            return
        version, status = pypi_version_from_req(req)
        add(req.name, version, str(req.specifier) or None, status, scope)

    def add_poetry_table(table: Any, scope: str) -> None:
        for name, spec in (table or {}).items():
            if isinstance(spec, dict):
                spec = spec.get("version")
            if isinstance(spec, list):            # multiple-constraint dependency
                spec = None
            if isinstance(spec, str):
                version, status = _poetry_constraint(spec)
                add(name, version, spec, status, scope)
            else:
                add(name, None, None, "unresolved", scope)

    project = data.get("project") or {}
    for spec in project.get("dependencies") or []:
        add_pep508(spec, "production")
    for specs in (project.get("optional-dependencies") or {}).values():
        for spec in specs or []:
            add_pep508(spec, "unknown")
    for specs in (data.get("dependency-groups") or {}).values():   # PEP 735
        for spec in specs or []:
            add_pep508(spec, "development")
    poetry = (data.get("tool") or {}).get("poetry") or {}
    add_poetry_table(poetry.get("dependencies"), "production")
    add_poetry_table(poetry.get("dev-dependencies"), "development")
    for group in (poetry.get("group") or {}).values():
        add_poetry_table((group or {}).get("dependencies"), "development")
    return deps


def _pyproject_name(data: dict, filename: str) -> str:
    return (
        (data.get("project") or {}).get("name")
        or ((data.get("tool") or {}).get("poetry") or {}).get("name")
        or _fallback_name(filename, "python-app")
    )


def parse_pyproject(text: str, filename: str, issues: list[ParseIssue]) -> Project:
    data = _load_toml(text, filename)
    deps = _pyproject_direct(data, filename, issues)
    if not deps:
        issues.append(ParseIssue(file=filename, message="no dependencies declared in pyproject.toml"))
    return Project(name=str(_pyproject_name(data, filename)), ecosystem="PyPI", source_file=filename, dependencies=deps)


def parse_poetry_lock(text: str, filename: str, issues: list[ParseIssue], pyproject: dict | None = None) -> Project:
    data = _load_toml(text, filename)
    packages = data.get("package")
    if not isinstance(packages, list) or not packages:
        raise ManifestError(f"{filename}: no [[package]] entries - not a poetry.lock file")
    by_name: dict[str, dict] = {}
    for p in packages:
        if isinstance(p, dict) and isinstance(p.get("name"), str):
            by_name.setdefault(canonicalize_name(p["name"]), p)

    def scope_of(p: dict) -> str:
        groups = p.get("groups")
        if isinstance(groups, list) and groups:
            return "production" if "main" in groups else "development"
        return {"main": "production", "dev": "development"}.get(p.get("category"), "unknown")

    budget = _Budget(filename, MAX_LOCK_NODES)
    expanded: set[str] = set()

    def build(name: str, scope: str, depth: int, inferred: bool = False) -> Dependency:
        budget.tick()
        p = by_name[name]
        version = p.get("version") if isinstance(p.get("version"), str) else None
        children: list[Dependency] = []
        if name not in expanded:
            expanded.add(name)
            if depth >= MAX_LOCK_DEPTH:
                budget.truncated = True
            else:
                for dep, spec in (p.get("dependencies") or {}).items():
                    if isinstance(spec, dict) and spec.get("optional"):
                        continue
                    child = canonicalize_name(dep)
                    if child in by_name:
                        children.append(build(child, scope_of(by_name[child]), depth + 1))
        return _lock_dep(name, version, scope, children, ecosystem="PyPI", inferred=inferred)

    direct: list[Dependency] = []
    if pyproject:
        name = _pyproject_name(pyproject, filename)
        for d in _pyproject_direct(pyproject, filename, issues):
            if d.name in by_name:
                direct.append(build(d.name, d.scope, 1))
            else:
                budget.missing.add(d.name)
    else:
        name = _fallback_name(filename, "python-app")
        required = {
            canonicalize_name(dep)
            for p in by_name.values() for dep in (p.get("dependencies") or {})
        }
        roots = [n for n in by_name if n not in required]
        direct = [build(n, scope_of(by_name[n]), 1, inferred=True) for n in roots]
        issues.append(ParseIssue(file=filename, message=(
            "poetry.lock without pyproject.toml: direct dependencies were inferred as packages no other "
            "package requires (shown as inferred links). Upload pyproject.toml alongside for accuracy."
        )))
    if budget.missing:
        issues.append(ParseIssue(file=filename, message=(
            f"{len(budget.missing)} declared package(s) not found in poetry.lock: {', '.join(sorted(budget.missing)[:5])}"
        )))
    return Project(name=str(name), ecosystem="PyPI", source_file=filename, has_transitive_data=True, dependencies=direct)


# ----------------------------------------------------- Maven dependency:tree -

_MAVEN_SCOPES = {"compile": "production", "runtime": "production", "test": "development"}


def parse_maven_tree(text: str, filename: str, issues: list[ParseIssue]) -> list[Project]:
    """Parse `mvn dependency:tree` text output (optionally with [INFO] prefixes).

    Root lines look like  group:artifact:packaging:version
    Children look like    +- group:artifact:type[:classifier]:version:scope
    with three characters of indentation per level.
    """
    projects: list[Project] = []
    stack: list[Dependency] = []
    current: Project | None = None
    budget = _Budget(filename, MAX_LOCK_NODES)
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = re.sub(r"^\[(INFO|DEBUG|WARNING)\]\s?", "", raw.rstrip())
        stripped = line.lstrip(" |+-\\")
        if not stripped or not re.match(r"^[\w.-]+:[\w.-]+:", stripped):
            continue
        indent = len(line) - len(stripped)
        coords = stripped.split()[0].split(":")
        if indent == 0:
            if len(coords) < 4:
                continue
            current = Project(name=coords[1], ecosystem="Maven", source_file=filename, has_transitive_data=True)
            projects.append(current)
            stack = []
            continue
        if current is None:
            raise ManifestError(f"{filename}: dependency lines found before a root artifact line")
        depth = indent // 3
        if len(coords) not in (5, 6) or depth < 1 or depth > len(stack) + 1:
            issues.append(ParseIssue(file=filename, message=f"line {lineno}: unrecognised tree entry skipped"))
            continue
        budget.tick()
        group, artifact = coords[0], coords[1]
        version, mscope = coords[-2], coords[-1].lower()
        dep = Dependency(
            name=f"{group}:{artifact}", ecosystem="Maven",
            version=None if "${" in version else version, declared=version,
            version_status="unresolved" if "${" in version else "exact",
            scope=_MAVEN_SCOPES.get(mscope, "unknown"),
        )
        stack = stack[: depth - 1]
        (stack[-1].dependencies if stack else current.dependencies).append(dep)
        stack.append(dep)
    if not projects:
        raise ManifestError(f"{filename}: no Maven dependency tree found (expected `mvn dependency:tree` output)")
    return projects
