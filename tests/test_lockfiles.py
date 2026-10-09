"""Lockfile / resolved-tree parsing and manifest pairing."""

import json

import pytest

from services import dependency_graph as dg
from services.manifest_parser import ManifestError, parse_file, parse_files


def names(deps):
    return {d.name: d for d in deps}


# --------------------------------------------------------- package-lock v2/3

LOCK_V3 = {
    "name": "shop", "lockfileVersion": 3,
    "packages": {
        "": {"name": "shop", "dependencies": {"express": "^4.17.1"}, "devDependencies": {"jest": "^29.0.0"}},
        "node_modules/express": {"version": "4.17.1", "dependencies": {"qs": "6.7.0", "debug": "2.6.9"}},
        "node_modules/qs": {"version": "6.7.0"},
        "node_modules/debug": {"version": "2.6.9", "dependencies": {"ms": "2.0.0"}},
        "node_modules/ms": {"version": "2.0.0"},
        # nested copy: jest needs a different debug, resolved from its own node_modules
        "node_modules/jest": {"version": "29.7.0", "dev": True, "dependencies": {"debug": "^4.3.0", "ms": "^2.1.0"}},
        "node_modules/jest/node_modules/debug": {"version": "4.3.4", "dev": True, "dependencies": {"ms": "2.1.2"}},
        "node_modules/jest/node_modules/ms": {"version": "2.1.2", "dev": True},
    },
}


def test_package_lock_v3_resolves_nested_modules():
    projects, issues = parse_file("package-lock.json", json.dumps(LOCK_V3).encode())
    p = projects[0]
    assert p.name == "shop" and p.has_transitive_data
    direct = names(p.dependencies)
    assert direct["express"].version == "4.17.1" and direct["express"].scope == "production"
    assert direct["jest"].scope == "development"
    express_children = names(direct["express"].dependencies)
    assert express_children["debug"].version == "2.6.9"
    assert express_children["debug"].dependencies[0].version == "2.0.0"      # hoisted ms
    jest_children = names(direct["jest"].dependencies)
    assert jest_children["debug"].version == "4.3.4"                          # nested resolution wins
    assert jest_children["debug"].dependencies[0].version == "2.1.2"
    assert jest_children["debug"].scope == "development"


def test_package_lock_graph_is_transitive():
    projects, _ = parse_file("package-lock.json", json.dumps(LOCK_V3).encode())
    g = dg.build_graph(projects)
    impacts = dg.blast_radius(g, "npm:ms@2.0.0")
    assert impacts[0].relation == "transitive"
    assert impacts[0].path == ["project:shop", "npm:express@4.17.1", "npm:debug@2.6.9", "npm:ms@2.0.0"]
    assert dg.runtime_context(g, "project:shop", "npm:ms@2.1.2") == "development"


def test_package_lock_missing_and_cycles():
    lock = {"lockfileVersion": 2, "packages": {
        "": {"dependencies": {"a": "1", "ghost": "1"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "1"}},
        "node_modules/b": {"version": "1.0.0", "dependencies": {"a": "1"}},   # cycle a -> b -> a
    }}
    projects, issues = parse_file("package-lock.json", json.dumps(lock).encode())
    a = projects[0].dependencies[0]
    assert a.dependencies[0].name == "b" and a.dependencies[0].dependencies[0].dependencies == []
    assert any("ghost" in i.message for i in issues)


def test_package_lock_v1_with_manifest_pairing():
    lock = {"name": "legacy", "lockfileVersion": 1, "dependencies": {
        "lodash": {"version": "4.17.15"},
        "request": {"version": "2.88.0", "requires": {"qs": "~6.5.2"},
                    "dependencies": {"qs": {"version": "6.5.2"}}},
        "qs": {"version": "6.9.0"},
        "mocha": {"version": "8.0.0", "dev": True},
    }}
    manifest = {"name": "legacy-app", "dependencies": {"lodash": "^4.17.0", "request": "^2.88.0"},
                "devDependencies": {"mocha": "^8.0.0"}}
    projects, issues = parse_files([
        ("package.json", json.dumps(manifest).encode()),
        ("package-lock.json", json.dumps(lock).encode()),
    ])
    assert len(projects) == 1                         # manifest superseded by the lockfile
    p = projects[0]
    assert p.name == "legacy-app" and p.has_transitive_data
    deps = names(p.dependencies)
    assert set(deps) == {"lodash", "request", "mocha"} and not deps["lodash"].inferred
    assert deps["request"].dependencies[0].version == "6.5.2"     # nested copy, not the hoisted 6.9.0
    assert deps["mocha"].scope == "development"
    assert any("superseded" in i.message for i in issues)


def test_package_lock_v1_without_manifest_marks_inferred_roots():
    lock = {"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "requires": {"b": "1"}}, "b": {"version": "1.0.0"},
    }}
    projects, issues = parse_file("package-lock.json", json.dumps(lock).encode())
    roots = projects[0].dependencies
    assert [d.name for d in roots] == ["a"] and roots[0].inferred
    assert any("inferred" in i.message for i in issues)
    g = dg.build_graph(projects)
    impacts = dg.blast_radius(g, "npm:b@1.0.0")
    assert impacts[0].inferred_link


def test_not_a_lockfile():
    with pytest.raises(ManifestError, match="not an npm lockfile"):
        parse_file("package-lock.json", b'{"name": "x"}')


# ------------------------------------------------------------ poetry / pyproject

POETRY_LOCK = b'''
[[package]]
name = "Flask"
version = "2.0.1"
groups = ["main"]
[package.dependencies]
Jinja2 = ">=3.0"
Werkzeug = ">=2.0"

[[package]]
name = "jinja2"
version = "3.0.1"
groups = ["main"]
[package.dependencies]
MarkupSafe = ">=2.0"

[[package]]
name = "markupsafe"
version = "2.0.1"
groups = ["main"]

[[package]]
name = "werkzeug"
version = "2.0.1"
groups = ["main"]

[[package]]
name = "pytest"
version = "6.2.0"
groups = ["dev"]
[package.dependencies]
colorama = {version = "*", markers = "sys_platform == \\"win32\\""}
pyreadline = {version = "*", optional = true}

[[package]]
name = "colorama"
version = "0.4.4"
category = "dev"
'''

PYPROJECT = b'''
[tool.poetry]
name = "api-service"
[tool.poetry.dependencies]
python = "^3.11"
flask = "2.0.1"
[tool.poetry.group.dev.dependencies]
pytest = "^6.2"
'''


def test_poetry_lock_with_pyproject():
    projects, issues = parse_files([("pyproject.toml", PYPROJECT), ("poetry.lock", POETRY_LOCK)])
    assert len(projects) == 1
    p = projects[0]
    assert p.name == "api-service" and p.ecosystem == "PyPI" and p.has_transitive_data
    deps = names(p.dependencies)
    assert set(deps) == {"flask", "pytest"}
    assert deps["flask"].scope == "production" and deps["pytest"].scope == "development"
    jinja = names(deps["flask"].dependencies)["jinja2"]
    assert jinja.version == "3.0.1" and jinja.dependencies[0].name == "markupsafe"
    assert [c.name for c in deps["pytest"].dependencies] == ["colorama"]      # optional dep skipped
    assert deps["pytest"].dependencies[0].scope == "development"              # legacy category field


def test_poetry_lock_without_pyproject_infers_roots():
    projects, issues = parse_file("poetry.lock", POETRY_LOCK)
    roots = {d.name for d in projects[0].dependencies}
    assert roots == {"flask", "pytest"}
    assert all(d.inferred for d in projects[0].dependencies)
    assert any("inferred" in i.message for i in issues)


def test_pyproject_pep621_and_poetry_constraints():
    text = b'''
[project]
name = "svc"
dependencies = ["requests==2.25.0", "urllib3>=1.26", "numpy"]
[project.optional-dependencies]
docs = ["sphinx==7.0.0"]
[dependency-groups]
dev = ["pytest==8.0.0"]
'''
    projects, _ = parse_file("pyproject.toml", text)
    deps = names(projects[0].dependencies)
    assert deps["requests"].version == "2.25.0" and deps["requests"].scope == "production"
    assert deps["urllib3"].version_status == "range_min"
    assert deps["numpy"].version_status == "unresolved"
    assert deps["sphinx"].scope == "unknown" and deps["pytest"].scope == "development"
    assert not projects[0].has_transitive_data


def test_invalid_toml():
    with pytest.raises(ManifestError, match="invalid TOML"):
        parse_file("poetry.lock", b"[[package]\nname=")


# --------------------------------------------------------- Maven dependency:tree

MVN_TREE = b"""[INFO] com.example:billing:jar:1.0.0
[INFO] +- org.apache.logging.log4j:log4j-core:jar:2.14.1:compile
[INFO] |  \\- org.apache.logging.log4j:log4j-api:jar:2.14.1:compile
[INFO] +- com.fasterxml.jackson.core:jackson-databind:jar:2.9.10:compile
[INFO] |  +- com.fasterxml.jackson.core:jackson-annotations:jar:2.9.10:compile
[INFO] |  \\- com.fasterxml.jackson.core:jackson-core:jar:2.9.10:compile
[INFO] \\- junit:junit:jar:4.12:test
[INFO]    \\- org.hamcrest:hamcrest-core:jar:1.3:test
"""


def test_maven_dependency_tree():
    projects, _ = parse_file("dependency-tree.txt", MVN_TREE)
    p = projects[0]
    assert p.name == "billing" and p.has_transitive_data
    deps = names(p.dependencies)
    assert set(deps) == {"org.apache.logging.log4j:log4j-core", "com.fasterxml.jackson.core:jackson-databind", "junit:junit"}
    assert deps["org.apache.logging.log4j:log4j-core"].dependencies[0].name == "org.apache.logging.log4j:log4j-api"
    assert len(deps["com.fasterxml.jackson.core:jackson-databind"].dependencies) == 2
    assert deps["junit:junit"].scope == "development"
    assert deps["junit:junit"].dependencies[0].scope == "development"


def test_maven_tree_supersedes_pom():
    pom = b"<project><artifactId>billing</artifactId></project>"
    projects, issues = parse_files([("pom.xml", pom), ("dependency-tree.txt", MVN_TREE)])
    assert len(projects) == 1 and projects[0].has_transitive_data
    assert any("superseded" in i.message for i in issues)


def test_maven_tree_rejects_garbage():
    with pytest.raises(ManifestError, match="no Maven dependency tree"):
        parse_file("dependency-tree.txt", b"hello world")


# ---------------------------------------------------------------- batching

def test_parse_files_reports_bad_files_without_aborting():
    projects, issues = parse_files([
        ("requirements.txt", b"flask==2.0.1\n"),
        ("package.json", b"{broken"),
        ("notes.md", b"hi"),
    ])
    assert [p.name for p in projects] == ["python-app"]
    errors = [i for i in issues if i.level == "error"]
    assert {e.file for e in errors} == {"package.json", "notes.md"}


def test_repository_paths_group_by_directory():
    projects, _ = parse_files([
        ("services/api/package.json", json.dumps({"dependencies": {"a": "1.0.0"}}).encode()),
        ("services/web/package.json", json.dumps({"dependencies": {"b": "1.0.0"}}).encode()),
    ])
    assert sorted(p.name for p in projects) == ["api", "web"]
