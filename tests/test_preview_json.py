"""Versioned local JSON plans stay separate from findings and AWS work."""

import json
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.snapshot import write_snapshot
from test_snapshot import snapshot


def block_scan_work(monkeypatch):
    blocked = Mock(side_effect=AssertionError("preview must not scan or write"))
    for name in ("create_scan_context", "capture_snapshot", "scan_organization", "scan_regions",
                 "evaluate_snapshot", "write_report", "snapshot_saver"):
        monkeypatch.setattr(f"awsherlock.cli.{name}", blocked)
    return blocked


def test_live_json_preview_is_local_and_has_separate_report_destination(monkeypatch, tmp_path):
    blocked = block_scan_work(monkeypatch)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret-marker")
    report = tmp_path / "report.html"
    facts = tmp_path / "facts"
    result = CliRunner().invoke(app, ["scan", "--preview", "--preview-format", "json",
        "--profile", "prod", "--role", "arn:aws:iam::123456789012:role/Audit",
        "--external-id", "private-external", "--expect-account", "123456789012",
        "--regions", "eu-west-1,eu-central-1", "--services", "iam,s3",
        "--checks", "AWSH-S3-001", "--resources", "bucket-a",
        "--identity-governance", "--timeout", "5", "--output", "html",
        "--report-file", str(report), "--save-snapshot", str(facts)])
    assert result.exit_code == 0, result.output
    assert not result.stderr
    plan = json.loads(result.stdout)
    assert set(plan) == {"schema_version", "kind", "mode", "verification", "target",
                         "collection", "evaluation", "destinations", "options"}
    assert plan["schema_version"] == 1 and plan["kind"] == "scan-preview"
    assert plan["mode"] == "single-account"
    assert plan["verification"] == {"identity": "unverified", "organization_membership": None}
    assert plan["target"]["profile"] == "prod"
    assert plan["target"]["source_role"] == "arn:aws:iam::123456789012:role/Audit"
    assert plan["target"]["expected_account"] == "123456789012"
    assert plan["target"]["regions"] == ["eu-west-1", "eu-central-1"]
    assert plan["target"]["region_source"] == "explicit"
    assert plan["collection"]["services"] == ["iam", "s3"]
    assert plan["evaluation"] == {"checks": ["AWSH-S3-001"], "resources": ["bucket-a"],
                                  "selectors_affect_collection": False}
    assert plan["destinations"] == {"report_format": "html", "report_file": str(report),
                                    "snapshot": str(facts)}
    assert plan["options"] == {"external_id_supplied": True, "identity_governance_requested": True,
                               "max_workers": 1, "request_timeouts_configured": True}
    assert "private-external" not in result.output and "secret-marker" not in result.output
    assert not report.exists() and not facts.exists()
    blocked.assert_not_called()


def test_organization_json_preview_does_not_discover_membership(monkeypatch):
    blocked = block_scan_work(monkeypatch)
    result = CliRunner().invoke(app, ["scan", "organization", "--preview", "--preview-format", "json",
        "--accounts", "123456789012", "--ous", "ou-abcd-12345678", "--role-name", "audit/Reader"])
    assert result.exit_code == 0, result.output
    plan = json.loads(result.stdout)
    assert plan["mode"] == "organization"
    assert plan["verification"]["organization_membership"] == "not_discovered"
    assert plan["target"]["organization_role_name"] == "audit/Reader"
    assert plan["target"]["accounts"] == ["123456789012"]
    assert plan["target"]["ous"] == ["ou-abcd-12345678"]
    assert plan["target"]["region_source"] == "sdk_default"
    assert plan["target"]["regions"] is None
    blocked.assert_not_called()


def test_offline_json_preview_uses_only_saved_metadata(snapshot, monkeypatch, tmp_path):
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    blocked = block_scan_work(monkeypatch)
    result = CliRunner().invoke(app, ["scan", str(path), "--preview", "--preview-format", "json",
        "--checks", "AWSH-S3-001", "--expect-account", snapshot.metadata.account_id])
    assert result.exit_code == 0, result.output
    plan = json.loads(result.stdout)
    assert plan["mode"] == "offline"
    assert plan["verification"]["identity"] == "snapshot_metadata"
    assert plan["target"]["snapshot_path"] == str(path)
    assert plan["target"]["snapshot_account"] == snapshot.metadata.account_id
    assert plan["target"]["snapshot_region"] is None
    assert plan["target"]["profile"] is None
    assert plan["target"]["region_source"] == "snapshot_metadata"
    assert plan["collection"]["services"] == ["s3"]
    assert "public_access_block" not in result.stdout and "AccessDenied" not in result.stdout
    blocked.assert_not_called()


def test_default_and_explicit_text_preview_are_identical(monkeypatch):
    blocked = block_scan_work(monkeypatch)
    default = CliRunner().invoke(app, ["scan", "--preview", "--output", "json"])
    explicit = CliRunner().invoke(app, ["scan", "--preview", "--preview-format", "text", "--output", "json"])
    assert default.exit_code == explicit.exit_code == 0
    assert default.output == explicit.output
    assert "Scan preview:" in default.output and not default.output.lstrip().startswith("{")
    blocked.assert_not_called()


@pytest.mark.parametrize("args", [
    ["--preview-format", "json"], ["--preview", "--preview-format", "xml"],
    ["--preview", "--preview-format", "json", "--services", "unknown"],
    ["--preview", "--preview-format", "json", "--region", "bad region"],
    ["--preview", "--preview-format", "json", "--checks", "bad"],
])
def test_invalid_json_preview_fails_before_aws(monkeypatch, args):
    blocked = block_scan_work(monkeypatch)
    result = CliRunner().invoke(app, ["scan", *args])
    assert result.exit_code == 2
    assert not result.stdout.lstrip().startswith("{")
    blocked.assert_not_called()


def test_offline_json_preview_rejects_wrong_account(snapshot, tmp_path, monkeypatch):
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    blocked = block_scan_work(monkeypatch)
    result = CliRunner().invoke(app, ["scan", str(path), "--preview", "--preview-format", "json",
                                      "--expect-account", "999999999999"])
    assert result.exit_code == 1
    assert not result.stdout.lstrip().startswith("{")
    blocked.assert_not_called()


def test_json_preview_escapes_control_chars_and_never_adds_color(monkeypatch):
    blocked = block_scan_work(monkeypatch)
    result = CliRunner().invoke(app, ["scan", "--preview", "--preview-format", "json",
                                      "--profile", "prod\x1b[2J", "--color", "always"],
                                terminal_width=50)
    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.stdout and "\\u001b" in result.stdout
    assert json.loads(result.stdout)["target"]["profile"] == "prod\x1b[2J"
    assert "\x1b[" not in result.stdout
    blocked.assert_not_called()
