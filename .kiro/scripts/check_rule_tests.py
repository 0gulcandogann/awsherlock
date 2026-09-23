"""Kiro PostFileSave hook: run focused local tests without shell interpolation."""

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TESTS = {
    "s3.py": ("tests/test_s3.py",),
    "iam.py": ("tests/test_iam.py",),
    "ec2.py": ("tests/test_ec2.py",),
    "serverless.py": ("tests/test_serverless.py", "tests/test_secrets.py"),
    "audit.py": ("tests/test_audit.py",),
    "identity.py": ("tests/test_identity.py",),
}


def saved_path(event: object) -> str | None:
    if isinstance(event, dict):
        for key in ("filePath", "file_path", "path", "filename"):
            if isinstance(event.get(key), str):
                return event[key]
        for value in event.values():
            found = saved_path(value)
            if found:
                return found
    return None


def commands_for(event: object) -> list[str]:
    path = saved_path(event)
    if path is None:
        return [".github/scripts/ci_checks.py"]
    parts = Path(path.replace("\\", "/")).parts
    if len(parts) < 4 or tuple(parts[-4:-1]) != ("src", "awsherlock", "rules"):
        return [".github/scripts/ci_checks.py"]
    candidates = TESTS.get(parts[-1], ())
    existing = [name for name in candidates if (ROOT / name).is_file()]
    return existing or [".github/scripts/ci_checks.py"]


def main() -> int:
    try:
        event = json.loads(sys.stdin.read(65536))
    except (ValueError, OSError):
        event = {}
    targets = commands_for(event)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    if targets[0].startswith("tests/"):
        command = [sys.executable, "-m", "pytest", *targets, "-q"]
    else:
        command = [sys.executable, targets[0]]
    return subprocess.run(command, cwd=ROOT, env=env, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
