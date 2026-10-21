"""Bounded deterministic graph presentation; edges never imply verified access."""

from itertools import zip_longest

from awsherlock.investigation_models import stable_id


def _resource_id(ref: dict) -> str:
    return stable_id(
        "resource",
        [
            ref["account_id"],
            ref["region"] or "",
            ref["service"],
            ref["resource_type"],
            ref["resource_id"],
        ],
    )


def build_investigation_graph(
    investigations: list[dict],
    *,
    max_nodes: int = 80,
    max_edges: int = 160,
    max_investigations: int = 100,
) -> dict:
    """Cap serialized graph data and browser DOM independently of evidence text.

    The full accessible investigation list is retained by the HTML renderer.
    Only one selected graph is rendered at a time; no quadratic force layout.
    """
    if any(
        type(value) is not int or value < 1 for value in (max_nodes, max_edges, max_investigations)
    ):
        raise ValueError("Graph limits must be positive integers")
    graphs = []
    priority_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNASSESSED": 3}
    ordered = sorted(
        investigations,
        key=lambda item: (priority_order[item["priority"]], item["pattern_id"], item["id"]),
    )
    for investigation in ordered[:max_investigations]:
        nodes, edges = {}, {}

        def node(identity: str, kind: str, label: str) -> None:
            nodes[identity] = {"id": identity, "kind": kind, "label": label}

        def edge(source: str, target: str, label: str, semantics: str) -> None:
            identity = stable_id("edge", [source, target, label, semantics])
            edges[identity] = {
                "id": identity,
                "source": source,
                "target": target,
                "label": label,
                "semantics": semantics,
            }

        root = investigation["id"]
        node(root, "INVESTIGATION", investigation["pattern_id"] + " / " + investigation["priority"])
        resource_index: dict[tuple, list[str]] = {}
        for ref in investigation["resources"]:
            identity = _resource_id(ref)
            key = tuple(
                ref[field]
                for field in ("account_id", "region", "service", "resource_id", "resource_arn")
            )
            resource_index.setdefault(key, []).append(identity)
            node(
                identity,
                "RESOURCE",
                f"{ref['service']}/{ref['resource_type']}: {ref['resource_id']}",
            )
            edge(root, identity, "review association", "INFERRED")
        for finding in investigation["supporting_findings"]:
            ref = finding["reference"]
            node(finding["id"], "FINDING", ref["check_id"] + ": " + ref["resource_id"])
            edge(root, finding["id"], "supporting finding", "INFERRED")
            key = tuple(
                ref[field]
                for field in ("account_id", "region", "service", "resource_id", "resource_arn")
            )
            matches = resource_index.get(key, [])
            if len(matches) == 1:
                edge(
                    finding["id"],
                    matches[0],
                    "finding on resource",
                    "INFERRED" if investigation["priority_status"] == "BLOCKED" else "OBSERVED",
                )
        for relationship in investigation["supporting_relationships"]:
            ref = relationship["reference"]
            # BLOCKED candidate support must never be drawn as an observation.
            semantics = "INFERRED" if investigation["priority_status"] == "BLOCKED" else "OBSERVED"
            edge(
                _resource_id(ref["source"]),
                _resource_id(ref["target"]),
                ref["type"] + (" (unverified)" if semantics == "INFERRED" else " (configuration)"),
                semantics,
            )
        for gap in investigation["coverage_gaps"]:
            node(
                gap["id"],
                "COVERAGE",
                gap["code"] + (" / " + gap["reason_code"] if gap["reason_code"] else ""),
            )
            edge(root, gap["id"], "coverage limitation", "INFERRED")
        # Round-robin kinds so many coverage gaps cannot crowd every resource
        # or Finding out of a small view. Stable IDs break ties deterministically.
        groups = [
            sorted(
                (value for value in nodes.values() if value["kind"] == kind),
                key=lambda value: value["id"],
            )
            for kind in ("RESOURCE", "FINDING", "COVERAGE")
        ]
        values = [
            nodes[root],
            *(value for group in zip_longest(*groups) for value in group if value is not None),
        ]
        selected_nodes = values[:max_nodes]
        identities = {value["id"] for value in selected_nodes}
        eligible = [
            value
            for key, value in sorted(edges.items())
            if value["source"] in identities and value["target"] in identities
        ]
        selected_edges = eligible[:max_edges]
        graphs.append(
            {
                "investigation_id": root,
                "title": investigation["title"],
                "priority": investigation["priority"],
                "priority_status": investigation["priority_status"],
                "nodes": selected_nodes,
                "edges": selected_edges,
                "omitted_nodes": len(nodes) - len(selected_nodes),
                "omitted_edges": len(edges) - len(selected_edges),
            }
        )
    return {
        "investigations": graphs,
        "omitted_investigations": max(0, len(ordered) - max_investigations),
        "limits": {
            "nodes_per_investigation": max_nodes,
            "edges_per_investigation": max_edges,
            "investigations": max_investigations,
        },
    }
