"""Allowlisted local diagnostics; no AWS calls or credential inspection."""

from importlib.metadata import PackageNotFoundError, version
import platform
import shutil
import sys

from rich.console import Console

import awsherlock


def runtime_diagnostics() -> dict[str, str]:
    """Describe the running installation, not the contents of its environment."""
    stdout, stderr = Console(), Console(stderr=True)
    data = {
        "AWSherlock": awsherlock.__version__,
        "Python": platform.python_version(),
        "Python executable": sys.executable,
        "Package path": str(awsherlock.__file__),
        "PATH launcher": shutil.which("awsherlock") or "Not found",
        "Stdout terminal": str(stdout.is_terminal),
        "Stderr terminal": str(stderr.is_terminal),
        "Terminal size": f"{stdout.width}x{stdout.height}",
        "Stdout encoding": getattr(sys.stdout, "encoding", None) or "Unknown",
        "Stderr encoding": getattr(sys.stderr, "encoding", None) or "Unknown",
    }
    for name in ("boto3", "typer", "rich", "jinja2"):
        try:
            data[name] = version(name)
        except PackageNotFoundError:
            data[name] = "Not installed"
    return data
