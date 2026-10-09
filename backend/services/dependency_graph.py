"""Dependency graph construction and blast-radius analysis (NetworkX).

Edges point from dependent -> dependency:
    project:checkout-service -> npm:@scope/http-client@2.3.0 -> npm:@scope/url-parser@1.4.2
so every project that can reach a vulnerable package is one of its ancestors.
"""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from schemas.scan_result import Dependency, Project


def project_node(name: str) -> str:
    return f"project:{name}"


def package_node(dep: Dependency) -> str:
    version = dep.version if dep.version else f"unresolved({dep.declared or '*'})"
    return f"{dep.ecosystem}:{dep.name}@{version}"


def build_graph(projects: list[Project]) -> nx.DiGraph:
    g = nx.DiGraph()

    def add_dep(parent: str, dep: Dependency) -> None:
        node = package_node(dep)
        if node not in g:
            g.add_node(
                node, type="package", name=dep.name, ecosystem=dep.ecosystem,
                version=dep.version, declared=dep.declared, version_status=dep.version_status,
            )
        if g.has_edge(parent, node):
            # Same edge seen twice: keep the most "production" scope.
            rank = {"production": 2, "unknown": 1, "development": 0}
            if rank[dep.scope] > rank[g.edges[parent, node]["scope"]]:
                g.edges[parent, node]["scope"] = dep.scope
        else:
            g.add_edge(parent, node, scope=dep.scope, declared=dep.declared, inferred=dep.inferred)
        for child in dep.dependencies:
            add_dep(node, child)

    for p in projects:
        pid = project_node(p.name)
        g.add_node(
            pid, type="project", name=p.name, ecosystem=p.ecosystem,
            source_file=p.source_file, has_transitive_data=p.has_transitive_data,
        )
        for dep in p.dependencies:
            add_dep(pid, dep)
    return g


def label(g: nx.DiGraph, node: str) -> str:
    data = g.nodes[node]
    if data["type"] == "project":
        return data["name"]
    return f"{data['name']}@{data['version'] or data.get('declared') or '?'}"


def runtime_context(g: nx.DiGraph, project: str, target: str) -> str:
    """production if any all-production path exists; development if every
    path crosses a dev-only edge; otherwise unknown."""
    prod = nx.subgraph_view(g, filter_edge=lambda u, v: g.edges[u, v]["scope"] == "production")
    if nx.has_path(prod, project, target):
        return "production"
    non_dev = nx.subgraph_view(g, filter_edge=lambda u, v: g.edges[u, v]["scope"] != "development")
    if nx.has_path(non_dev, project, target):
        return "unknown"
    return "development"


@dataclass
class Impact:
    project: str            # project node id
    relation: str           # direct | transitive
    path: list[str]         # node ids, project first
    runtime_context: str
    inferred_link: bool = False


def path_has_inferred_edge(g: nx.DiGraph, path: list[str]) -> bool:
    return any(g.edges[u, v].get("inferred") for u, v in zip(path, path[1:]))


def depths_from_projects(g: nx.DiGraph) -> dict[str, int]:
    """Shortest distance of every node from any project (projects are 0)."""
    sources = [n for n, d in g.nodes(data=True) if d["type"] == "project"]
    return nx.multi_source_dijkstra_path_length(g, sources) if sources else {}


def blast_radius(g: nx.DiGraph, target: str) -> list[Impact]:
    """All projects that depend on `target` directly or transitively."""
    impacts: list[Impact] = []
    for node in nx.ancestors(g, target):
        if g.nodes[node]["type"] != "project":
            continue
        direct = g.has_edge(node, target)
        path = [node, target] if direct else nx.shortest_path(g, node, target)
        impacts.append(Impact(
            project=node, relation="direct" if direct else "transitive",
            path=path, runtime_context=runtime_context(g, node, target),
            inferred_link=path_has_inferred_edge(g, path),
        ))
    impacts.sort(key=lambda i: g.nodes[i.project]["name"])
    return impacts


def potentially_affected_nodes(g: nx.DiGraph, vulnerable: set[str]) -> set[str]:
    """Every node (projects and intermediate packages) upstream of a vulnerable package."""
    out: set[str] = set()
    for v in vulnerable:
        out |= nx.ancestors(g, v)
    return out - vulnerable


def direct_parent(path: list[str]) -> str | None:
    """For a transitive path, the project's direct dependency that pulls the package in."""
    return path[1] if len(path) > 2 else None
