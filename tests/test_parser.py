import json

import pytest

from schemas.scan_result import ParseIssue
from services.manifest_parser import (
    MAX_FILE_BYTES, ManifestError, npm_version_from_spec, parse_dependency_tree, parse_file,
)


def by_name(project):
    return {d.name: d for d in project.dependencies}


# ------------------------------------------------------------- package.json

@pytest.mark.parametrize("spec,expected", [
    ("4.17.15", ("4.17.15", "exact")),
    ("=1.2.3", ("1.2.3", "exact")),
    ("^4.17.1", ("4.17.1", "range_min")),
    ("~1.2", ("1.2.0", "range_min")),
    (">=2.0.0 <3.0.0", ("2.0.0", "range_min")),
    ("1.x", ("1.0.0", "range_min")),
    ("*", (None, "unresolved")),
    ("latest", (None, "unresolved")),
    ("git+https://github.com/x/y.git", (None, "unresolved")),
    ("^1.0.0 || ^2.0.0", (None, "unresolved")),
    ("file:../local", (None, "unresolved")),
])
def test_npm_version_from_spec(spec, expected):
    assert npm_version_from_spec(spec) == expected


def test_package_json_scopes_and_versions():
    content = json.dumps({
        "name": "shop",
        "dependencies": {"lodash": "4.17.15", "express": "^4.17.1", "weird": "latest"},
        "devDependencies": {"jest": "^29.0.0"},
    }).encode()
    projects, _ = parse_file("package.json", content)
    p = projects[0]
    assert p.name == "shop" and p.ecosystem == "npm" and not p.has_transitive_data
    deps = by_name(p)
    assert deps["lodash"].version == "4.17.15" and deps["lodash"].scope == "production"
    assert deps["express"].version_status == "range_min"
    assert deps["weird"].version_status == "unresolved" and deps["weird"].version is None
    assert deps["jest"].scope == "development"


def test_package_json_invalid():
    with pytest.raises(ManifestError, match="invalid JSON"):
        parse_file("package.json", b"{not json")
    with pytest.raises(ManifestError, match="JSON object"):
        parse_file("package.json", b"[1, 2]")


# --------------------------------------------------------- requirements.txt

def test_requirements_parsing():
    text = (
        "# comment\n"
        "Flask==2.0.1\n"
        "jinja2 == 2.11.2  # inline comment\n"
        "requests>=2.25.0,<3\n"
        "Django~=4.2\n"
        "numpy\n"
        "-r other.txt\n"
        "--index-url https://example.org/simple\n"
        "git+https://github.com/x/y.git#egg=y\n"
        "urllib3==1.26.4 \\\n"
        "    --hash=sha256:abc\n"
        "!!!broken\n"
    )
    projects, issues = parse_file("requirements.txt", text.encode())
    deps = by_name(projects[0])
    assert deps["flask"].version == "2.0.1" and deps["flask"].version_status == "exact"
    assert deps["jinja2"].version == "2.11.2"
    assert deps["requests"].version == "2.25.0" and deps["requests"].version_status == "range_min"
    assert deps["django"].version == "4.2" and deps["django"].version_status == "range_min"
    assert deps["numpy"].version_status == "unresolved"
    assert deps["urllib3"].version == "1.26.4"
    assert deps["flask"].scope == "unknown"
    messages = " ".join(i.message for i in issues)
    assert "-r" in messages and "--index-url" in messages and "URL/path" in messages
    assert "could not parse" in messages


def test_requirements_dev_file_is_development_scope():
    projects, _ = parse_file("requirements-dev.txt", b"pytest==8.0.0\n")
    assert projects[0].dependencies[0].scope == "development"


# ------------------------------------------------------------------ pom.xml

POM = b"""<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>billing</artifactId><version>1.0.0</version>
  <properties><log4j.version>2.14.1</log4j.version></properties>
  <dependencies>
    <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId>
      <version>${log4j.version}</version></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version>
      <scope>test</scope></dependency>
    <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId></dependency>
  </dependencies>
</project>"""


def test_pom_parsing():
    projects, issues = parse_file("pom.xml", POM)
    p = projects[0]
    assert p.name == "billing" and p.ecosystem == "Maven"
    deps = by_name(p)
    log4j = deps["org.apache.logging.log4j:log4j-core"]
    assert log4j.version == "2.14.1" and log4j.scope == "production"
    assert deps["junit:junit"].scope == "development"
    assert deps["org.slf4j:slf4j-api"].version_status == "unresolved"
    assert any("managed by parent" in i.message for i in issues)


def test_pom_rejects_entity_expansion():
    evil = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">]>
<project><artifactId>&lol2;</artifactId></project>"""
    with pytest.raises(ManifestError, match="unsafe XML"):
        parse_file("pom.xml", evil)


def test_pom_rejects_non_project_root():
    with pytest.raises(ManifestError, match="not <project>"):
        parse_file("pom.xml", b"<html></html>")


# ---------------------------------------------------------- dependency tree

def test_dependency_tree_transitive_and_scope_inheritance():
    data = {"projects": [{
        "name": "svc", "ecosystem": "npm",
        "dependencies": [
            {"name": "a", "version": "1.0.0", "scope": "development",
             "dependencies": [{"name": "b", "version": "2.0.0"}]},
            {"name": "c", "version": "3.0.0"},
        ],
    }]}
    issues: list[ParseIssue] = []
    p = parse_dependency_tree(data, "tree.json", issues)[0]
    assert p.has_transitive_data
    a, c = p.dependencies
    assert a.scope == "development" and a.dependencies[0].name == "b"
    assert a.dependencies[0].scope == "development"  # inherited from parent
    assert c.scope == "unknown"                       # not stated -> unknown, not assumed production


def test_dependency_tree_requires_projects():
    with pytest.raises(ManifestError, match="not a dependency tree"):
        parse_file("deps.json", b'{"foo": 1}')


def test_demo_file_parses():
    from services.pipeline import load_demo_data
    projects = parse_dependency_tree(load_demo_data(), "demo_dependencies.json", [])
    assert len(projects) == 5


# ---------------------------------------------------------------- validation

def test_unsupported_file_type():
    with pytest.raises(ManifestError, match="unsupported"):
        parse_file("setup.py", b"print('hi')")


def test_file_size_limit():
    with pytest.raises(ManifestError, match="limit"):
        parse_file("requirements.txt", b"a" * (MAX_FILE_BYTES + 1))


def test_non_utf8_rejected():
    with pytest.raises(ManifestError, match="UTF-8"):
        parse_file("requirements.txt", b"\xff\xfe\xfa")
