"""Public Kiro contributor aids are bounded and locally executable."""

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def hook_module():
    path = ROOT / ".kiro/scripts/check_rule_tests.py"
    spec = importlib.util.spec_from_file_location("kiro_rule_tests", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_hook_shape_matcher_and_focused_dispatch():
    data = json.loads((ROOT / ".kiro/hooks/check-rule-tests.json").read_text(encoding="utf-8"))
    assert data["version"] == "v1"
    hook, = data["hooks"]
    assert hook["trigger"] == "PostFileSave" and hook["action"]["type"] == "command"
    pattern = re.compile(hook["matcher"])
    assert pattern.search("src/awsherlock/rules/iam.py")
    assert pattern.search(r"C:\work\src\awsherlock\rules\iam.py")
    assert pattern.search("src/awsherlock/collectors/iam.py")
    module = hook_module()
    assert module.commands_for({"filePath": "src/awsherlock/rules/iam.py"}) == ["tests/test_iam.py"]
    assert module.commands_for({"path": "src/awsherlock/rules/new.py"}) == [".github/scripts/ci_checks.py"]
    assert module.commands_for({"path": "src/awsherlock/collectors/rds.py"}) == ["tests/test_rds.py"]


def test_read_only_agent_and_public_resources():
    data = json.loads((ROOT / ".kiro/agents/security-reviewer.json").read_text(encoding="utf-8"))
    assert data["tools"] == data["allowedTools"] == ["read"]
    assert all((ROOT / resource.removeprefix("file://")).is_file() for resource in data["resources"])
    steering = (ROOT / ".kiro/steering/check-authoring.md").read_text(encoding="utf-8")
    template = (ROOT / "docs/check-spec-template.md").read_text(encoding="utf-8")
    assert steering.startswith("---\ninclusion: auto")
    for term in ("requirements", "pagination", "secure", "insecure", "AccessDenied", "snapshot"):
        assert term.lower() in (steering + template).lower()


def test_hook_fallback_runs_synthetic_local_check():
    result = subprocess.run([sys.executable, str(ROOT / ".kiro/scripts/check_rule_tests.py")],
                            input=json.dumps({"filePath": "src/awsherlock/rules/new.py"}),
                            text=True, capture_output=True, cwd=ROOT, timeout=15)
    assert result.returncode == 0, result.stderr
    assert "synthetic EC2" in result.stdout
    assert "WARNING: no focused local test found" in result.stdout
