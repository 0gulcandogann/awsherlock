"""Offline graph limits, semantics, untrusted labels and report integration."""

from copy import deepcopy
from dataclasses import replace
from html.parser import HTMLParser
import importlib
import json

import pytest
from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.html_report import HtmlScope
from awsherlock.reporting import render_html
from test_lead_delta import pair, LAMBDA, EC2
from test_leads_v2 import function, runs_as


def contextual(value):
    module = importlib.import_module("awsherlock.investigation_engine")
    return module.build_investigations(value).to_dict()


def graph(rows, **kwargs):
    module = importlib.import_module("awsherlock.investigation_graph")
    return module.build_investigation_graph(rows, **kwargs)


def test_graph_references_resolve_and_observed_edges_differ_from_inferences():
    doc = contextual(pair(EC2))
    view = graph(doc["investigations"])
    selected = view["investigations"][0]
    ids = {node["id"] for node in selected["nodes"]}
    assert len(ids) == len(selected["nodes"])
    assert {edge[end] for edge in selected["edges"] for end in ("source", "target")} <= ids
    assert {edge["semantics"] for edge in selected["edges"]} == {"OBSERVED", "INFERRED"}
    assert any(
        edge["label"] == "RUNS_AS (configuration)" and edge["semantics"] == "OBSERVED"
        for edge in selected["edges"]
    )
    assert {node["kind"] for node in selected["nodes"]} >= {"RESOURCE", "FINDING", "INVESTIGATION"}
    assert graph(list(reversed(doc["investigations"]))) == view


def test_large_graph_is_bounded_without_dangling_edges_and_reports_omissions():
    row = contextual(pair(LAMBDA))["investigations"][0]
    rows = []
    for index in range(130):
        item = deepcopy(row)
        item["id"] += str(index)
        for n in range(100):
            item["resources"].append({**item["resources"][0], "resource_id": f"extra-{n}"})
        rows.append(item)
    result = graph(rows, max_nodes=12, max_edges=10, max_investigations=3)
    assert len(result["investigations"]) == 3 and result["omitted_investigations"] == 127
    for item in result["investigations"]:
        assert len(item["nodes"]) <= 12 and len(item["edges"]) <= 10
        assert item["omitted_nodes"] > 0
        ids = {node["id"] for node in item["nodes"]}
        assert all(edge["source"] in ids and edge["target"] in ids for edge in item["edges"])


def test_graph_limits_prioritize_highest_review_urgency():
    low = contextual(pair(LAMBDA))["investigations"][0]
    low["id"], low["priority"] = "aaa-low", "LOW"
    high = deepcopy(low)
    high["id"], high["priority"] = "zzz-high", "HIGH"
    result = graph([low, high], max_investigations=1)
    assert result["investigations"][0]["investigation_id"] == "zzz-high"
    assert result["omitted_investigations"] == 1


def test_small_graph_keeps_supporting_resource_nodes_visible():
    row = contextual(pair(EC2))["investigations"][0]
    # Many coverage nodes must not crowd all resources out of a bounded view.
    for index in range(20):
        row["coverage_gaps"].append(
            {"id": f"coverage:{index}", "code": "LIMITED", "reason_code": None}
        )
    view = graph([row], max_nodes=5)["investigations"][0]
    assert {node["kind"] for node in view["nodes"]} >= {
        "INVESTIGATION",
        "RESOURCE",
        "FINDING",
        "COVERAGE",
    }


class Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


@pytest.mark.parametrize(
    "payload",
    ["</script><img src=x onerror=alert(1)>", '<svg onload="alert(1)">', "\u2028</script>"],
)
def test_graph_and_accessible_evidence_escape_hostile_iam_paths(payload):
    value = pair(EC2)
    role = value.services["iam"].resources[0]
    arn = f"arn:aws:iam::{role.account_id}:role/{payload}/worker"
    value.services["iam"].resources[0] = replace(role, resource_arn=arn)
    edge = value.relationships[0]
    value.relationships = (replace(edge, target=replace(edge.target, resource_arn=arn)),)
    report = evaluate_snapshot(value)
    rendered = render_html(report, scopes=(HtmlScope(value, report),))
    assert 'id="investigation-graph"' in rendered and 'id="contextual-investigations"' in rendered
    parsed = Tags()
    parsed.feed(rendered)
    assert not any(tag in {"img", "iframe", "object"} for tag, attrs in parsed.tags)
    assert not any(name.startswith("on") for _, attrs in parsed.tags for name in attrs)
    assert not any("src" in attrs for tag, attrs in parsed.tags if tag == "script")
    assert payload not in rendered


def test_html_preserves_old_sections_and_no_context_empty_states():
    value = pair(LAMBDA)
    report = evaluate_snapshot(value)
    rendered = render_html(report, scopes=(HtmlScope(value, report),))
    for text in (
        "Investigation Graph",
        "Observed",
        "Inferred",
        "Unknown",
        "PROVISIONAL",
        "Investigation Leads",
        "Relationships",
        "Resources",
        "Findings",
        "Scan coverage",
    ):
        assert text in rendered
    assert "No contextual investigation data" in render_html(report)
    assert graph([])["investigations"] == []


@pytest.mark.parametrize("output", ["json", "html"])
def test_contextual_cli_keeps_evidence_pack_default_and_exclusive_files(tmp_path, output):
    value = pair(LAMBDA)
    source = tmp_path / "facts.json"
    source.write_text(json.dumps(value.to_dict()), encoding="utf-8")
    args = ["investigate", str(source), "--contextual", "--output", output]
    destination = tmp_path / "context.html"
    if output == "html":
        args += ["--report-file", str(destination)]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    if output == "json":
        assert json.loads(result.stdout)["kind"] == "contextual-investigations"
    else:
        assert "Investigation Graph" in destination.read_text(encoding="utf-8")
        assert CliRunner().invoke(app, args).exit_code == 1
    lead_id = contextual(value)["investigations"][0]["lead_id"]
    old = CliRunner().invoke(app, ["investigate", str(source), "--lead-id", lead_id])
    assert json.loads(old.stdout)["kind"] == "investigation-evidence-pack"


def test_contextual_cli_partial_selection_and_usage_exits(tmp_path):
    value = pair(EC2)
    from awsherlock.collectors.common import CollectionIssue

    value.services["iam"].issues.append(CollectionIssue(None, "GetRolePolicy", "AccessDenied"))
    source = tmp_path / "partial.json"
    source.write_text(json.dumps(value.to_dict()), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(app, ["investigate", str(source), "--contextual"])
    assert result.exit_code == 1 and json.loads(result.stdout)["incomplete"]
    assert runner.invoke(app, ["investigate", str(source)]).exit_code == 2
    assert (
        runner.invoke(
            app, ["investigate", str(source), "--contextual", "--lead-id", "missing"]
        ).exit_code
        == 1
    )
    assert (
        runner.invoke(
            app, ["investigate", str(source), "--contextual", "--output", "html"]
        ).exit_code
        == 2
    )


def test_global_role_merge_retains_incomplete_scope_in_both_orders():
    from awsherlock.collectors.common import CollectionIssue
    from awsherlock.evaluation import Report
    from awsherlock.html_report import build_html_view
    from test_lead_delta import STALE

    first = pair(STALE)
    del first.services["lambda"]
    first.relationships = ()
    first.services["iam"].issues.append(CollectionIssue("worker", "GetRolePolicy", "AccessDenied"))
    second = deepcopy(first)
    second.metadata = replace(second.metadata, scan_id="second", region="eu-west-2")
    second.services["iam"].issues.clear()
    reports = [evaluate_snapshot(value) for value in (first, second)]
    aggregate = Report(
        dict(reports[0].metadata),
        reports[0].findings,
        [row for report in reports for row in report.coverage],
    )
    scopes = (HtmlScope(first, reports[0]), HtmlScope(second, reports[1]))
    forward = build_html_view(aggregate, scopes)
    backward = build_html_view(aggregate, tuple(reversed(scopes)))
    assert forward == backward
    row = next(row for row in forward["contextual"] if row["pattern_id"] == STALE)
    assert row["coverage_gaps"] and row["priority_status"] == "PROVISIONAL"
    assert "coverage" in row["priority_explanation"].lower()
    assert any(action["code"] == "VERIFY_EVIDENCE_GAPS" for action in row["recommended_actions"])
    assert len([item for item in forward["contextual"] if item["pattern_id"] == STALE]) == 1


@pytest.mark.browser
def test_offline_graph_selection_and_filtering_in_real_browser(tmp_path):
    from test_report_browser import run_browser

    value = pair(LAMBDA)
    other = function("second")
    value.services["lambda"].resources.append(other)
    value.relationships += (runs_as(other, value.services["iam"].resources[0]),)
    report = evaluate_snapshot(value)
    html = render_html(report, scopes=(HtmlScope(value, report),))
    script = """
    const check = ok => { if (!ok) throw Error('graph assertion failed'); };
    const select = document.getElementById('investigation-select');
    check(select.options.length === 2);
    const svg = document.getElementById('investigation-svg');
    check(svg.querySelectorAll('g[data-node]').length > 0);
    select.selectedIndex = 1; select.dispatchEvent(new Event('change'));
    check(document.getElementById('graph-evidence-link').getAttribute('href').startsWith('#context-'));
    document.getElementById('graph-evidence-link').click();
    check(document.querySelector(document.getElementById('graph-evidence-link').getAttribute('href')).open);
    const toggle = document.getElementById('graph-inferred');
    toggle.checked = false; toggle.dispatchEvent(new Event('change'));
    check(!svg.querySelector('line[data-semantics="INFERRED"]'));
    const search = document.getElementById('graph-search');
    const firstNode = svg.querySelector('g[data-node]');
    search.value = 'no-such-node'; search.dispatchEvent(new Event('input'));
    check(svg.querySelector('g[data-node]') === firstNode);
    check(Array.from(svg.querySelectorAll('g[data-node]')).every(n => n.getAttribute('opacity') === '0.2'));
    search.value = ''; search.dispatchEvent(new Event('input'));
    check(Array.from(svg.querySelectorAll('g[data-node]')).every(n => n.getAttribute('opacity') === '1'));
    document.querySelector('.contextual-record').open = true;
    window.dispatchEvent(new Event('beforeprint'));
    check(Array.from(document.querySelectorAll('.contextual-record')).every(row => row.open));
    window.dispatchEvent(new Event('afterprint'));
    document.body.insertAdjacentHTML('beforeend', '<p id="graph-result">PASS</p>');
    """
    assert '<p id="graph-result">PASS</p>' in run_browser(html, script, tmp_path)


@pytest.mark.browser
@pytest.mark.parametrize("width", [375, 1440])
def test_contextual_standalone_viewport_contains_long_graph_labels(tmp_path, width):
    import json

    from awsherlock.investigation_engine import build_investigations
    from awsherlock.reporting import render_contextual_html
    from test_report_browser import run_browser

    result = build_investigations(pair(LAMBDA))
    item = replace(result.investigations[0], title="Review " + "workload " * 80)
    html = render_contextual_html(replace(result, investigations=(item,)))
    embedded = json.dumps(html).replace("<", "\\u003c")
    script = (
        """
    const frame = document.createElement('iframe');
    frame.style.width = '"""
        + str(width)
        + """px';
    frame.style.height = '1000px';
    frame.onload = () => {
      const doc = frame.contentDocument;
      const fits = () => doc.documentElement.scrollWidth <= doc.documentElement.clientWidth;
      const select = doc.getElementById('investigation-select');
      const bounded = () => select.getBoundingClientRect().right <= doc.documentElement.clientWidth;
      const collapsedFits = fits() && bounded();
      doc.getElementById('graph-evidence-link').click();
      const expandedFits = fits() && bounded() && doc.querySelector('.contextual-record').open;
      const graph = doc.querySelector('.graph-scroll');
      const contained = graph.getBoundingClientRect().right <= doc.documentElement.clientWidth;
      const ok = collapsedFits && expandedFits && contained &&
        doc.querySelectorAll('#investigation-svg g[data-node]').length > 0;
      document.body.insertAdjacentHTML('beforeend', '<p id="viewport-result">' + (ok ? 'PASS' : 'FAIL') + '</p>');
    };
    frame.srcdoc = """
        + embedded
        + ";document.body.append(frame);"
    )
    assert '<p id="viewport-result">PASS</p>' in run_browser(html, script, tmp_path)


@pytest.mark.browser
def test_contextual_standalone_print_restore_and_untrusted_title(tmp_path):
    from awsherlock.investigation_engine import build_investigations
    from awsherlock.reporting import render_contextual_html
    from test_report_browser import run_browser

    result = build_investigations(pair(LAMBDA))
    item = replace(
        result.investigations[0], title='</script><img src=x onerror="globalThis.__xss=1">'
    )
    result = replace(result, investigations=(item,))
    script = """
    const check = ok => { if (!ok) throw Error('standalone assertion failed'); };
    check(!globalThis.__xss && !document.querySelector('img'));
    const row = document.querySelector('.contextual-record');
    check(!row.open);
    window.dispatchEvent(new Event('beforeprint')); check(row.open);
    window.dispatchEvent(new Event('afterprint')); check(!row.open);
    document.getElementById('graph-evidence-link').click(); check(row.open);
    check(document.querySelectorAll('#investigation-svg g[data-node]').length > 0);
    document.body.insertAdjacentHTML('beforeend', '<p id="standalone-result">PASS</p>');
    """
    assert '<p id="standalone-result">PASS</p>' in run_browser(
        render_contextual_html(result), script, tmp_path
    )
