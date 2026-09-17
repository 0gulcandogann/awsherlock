"""Package release checks; AWS credentials are never needed."""
import argparse
from datetime import datetime, timezone
from email.parser import Parser
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile


def stable_version(value: str) -> str:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
        raise ValueError("Release version must be X.Y.Z")
    return value


def check_tag(source: Path, tag: str | None) -> str:
    match = re.search(r'^__version__ = "([^"]+)"$', source.read_text(encoding="utf-8"), re.M)
    if not match:
        raise ValueError("Source version missing")
    version = stable_version(match[1])
    if tag is not None and tag != f"v{version}":
        raise ValueError("Tag must match the source version exactly")
    return version


def artifacts(dist: Path) -> tuple[str, dict[str, str]]:
    wheels = list(dist.glob("*.whl"))
    sources = list(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sources) != 1:
        raise ValueError("Expected exactly one wheel and one source archive")
    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
        metadata = Parser().parsestr(archive.read(next(n for n in names if n.endswith("/METADATA"))).decode())
        entrypoint = archive.read(next(n for n in names if n.endswith("/entry_points.txt"))).decode()
    version = stable_version(metadata["Version"])
    if metadata["Name"] != "awsherlock" or metadata["License-Expression"] != "MIT":
        raise ValueError("Unexpected package name/license")
    if metadata["Requires-Python"] != ">=3.11" or metadata["Description-Content-Type"] != "text/markdown":
        raise ValueError("Unexpected Python/README metadata")
    if "awsherlock = awsherlock.cli:app" not in entrypoint:
        raise ValueError("Missing CLI entrypoint")
    if wheels[0].name != f"awsherlock-{version}-py3-none-any.whl" or sources[0].name != f"awsherlock-{version}.tar.gz":
        raise ValueError("Artifact filenames do not match metadata")
    with tarfile.open(sources[0]) as archive:
        source_names = archive.getnames()
        pkg_info = archive.extractfile(f"awsherlock-{version}/PKG-INFO")
        if pkg_info is None or Parser().parsestr(pkg_info.read().decode())["Version"] != version:
            raise ValueError("Source/wheel versions differ")
    for members in (names, source_names):
        if not any(n.endswith("/templates/report.html") for n in members) or not any(n.endswith("/LICENSE") for n in members):
            raise ValueError("Missing report template/license")
        for name in members:
            path = Path(name)
            if set(path.parts) & {"tests", "reports", ".aws", ".git", ".github", ".venv", "__pycache__"} or path.name in {".env", ".pypirc", "credentials"}:
                raise ValueError("Unexpected local/private file in distribution")
    return version, {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (wheels[0], sources[0])}


def verify_index(dist: Path, index: str, destination: Path) -> None:
    version, hashes = artifacts(dist)
    host = {"testpypi": "test.pypi.org", "pypi": "pypi.org"}[index]
    data = None
    for attempt in range(6):
        try:
            with urllib.request.urlopen(f"https://{host}/pypi/awsherlock/{version}/json", timeout=15) as response:
                data = json.load(response)
            break
        except urllib.error.HTTPError as error:
            if error.code != 404 or attempt == 5:
                raise
            time.sleep(5)
    if data is None or data["info"]["version"] != version:
        raise ValueError("Published version missing")
    files = data["urls"]
    if {file["filename"] for file in files} != set(hashes):
        raise ValueError("Published artifacts differ from build")
    destination.mkdir(parents=True, exist_ok=True)
    for file in files:
        name = file["filename"]
        if file["digests"]["sha256"] != hashes[name]:
            raise ValueError("Published hash differs from build; never replace existing version")
        with urllib.request.urlopen(file["url"], timeout=30) as response:
            content = response.read()
        if hashlib.sha256(content).hexdigest() != hashes[name]:
            raise ValueError("Downloaded hash differs from build")
        (destination / name).write_bytes(content)
    print(f"PASS: {index} published/downloaded wheel and sdist match build {version}")


class OfflineAssets(HTMLParser):
    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if (tag in {"script", "img", "iframe"} and "src" in attributes) or (tag == "link" and "href" in attributes):
            raise ValueError("Report depends on an external asset")


def smoke(dist: Path) -> None:
    import awsherlock
    import boto3
    from awsherlock.cli import app
    from awsherlock.collectors.common import CollectionIssue, CollectionResult
    from awsherlock.models import Resource, ScanMetadata
    from awsherlock.snapshot import Snapshot, write_snapshot
    from typer.testing import CliRunner

    version, _ = artifacts(dist)
    if not Path(awsherlock.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()):
        raise ValueError("Smoke check must use an installed distribution in a virtual environment")
    if awsherlock.__version__ != version:
        raise ValueError("Installed version differs from build")
    with zipfile.ZipFile(next(dist.glob("*.whl"))) as archive:
        for name in archive.namelist():
            if name.startswith("awsherlock/") and Path(name).suffix in {".py", ".html"}:
                installed = Path(awsherlock.__file__).parent.parent / name
                if installed.read_bytes() != archive.read(name):
                    raise ValueError("Installed code/template differs from wheel")
    executable = Path(sys.executable).with_name("awsherlock.exe" if sys.platform == "win32" else "awsherlock")
    result = subprocess.run([str(executable), "--version"], check=True, capture_output=True, text=True)
    if version not in result.stdout:
        raise ValueError("Installed CLI entrypoint failed")

    def forbidden(*args, **kwargs):
        raise AssertionError("Offline smoke attempted network/AWS authentication")

    socket.socket = forbidden
    boto3.Session = forbidden
    runner = CliRunner()
    for args, marker in [(["--version"], version), (["--help"], "Quick start"),
                         (["scan", "--help"], "--identity-governance"), (["--list-checks"], "AWSH-IAM-012")]:
        result = runner.invoke(app, args, terminal_width=160)
        if result.exit_code != 0 or marker not in result.output:
            raise ValueError(f"CLI smoke failed: {args}")
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        metadata = ScanMetadata(scan_id="release-smoke", started_at=datetime(2026, 9, 17, tzinfo=timezone.utc),
                                account_id="123456789012", region="us-east-1", version=version)
        bucket = Resource(service="s3", resource_type="bucket", account_id=metadata.account_id,
                          region=metadata.region, resource_id="synthetic-test-bucket", resource_arn=None,
                          data={"public_access_block": None, "account_public_access_block": None})
        snapshot = Snapshot(metadata, {"s3": CollectionResult([bucket], [CollectionIssue(bucket.resource_id, "GetBucketLogging", "AccessDenied")])})
        path = work / "snapshot.json"
        write_snapshot(snapshot, path)
        result = runner.invoke(app, ["scan", str(path), "--output", "json"])
        if result.exit_code != 1 or not json.loads(result.output)["findings"] or "AccessDenied" not in result.output:
            raise ValueError("Offline JSON/denial smoke failed")
        output = work / "report.html"
        result = runner.invoke(app, ["scan", str(path), "--output", "html", "--report-file", str(output)])
        html = output.read_text(encoding="utf-8")
        if result.exit_code != 1 or "Incomplete scan coverage" not in html or "AccessDenied" not in html:
            raise ValueError("Offline HTML/denial smoke failed")
        OfflineAssets().feed(html)
    print(f"PASS: installed {version} CLI, offline JSON/HTML and visible denial coverage")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["tag", "artifacts", "smoke", "index"])
    parser.add_argument("--source", type=Path, default=Path("src/awsherlock/__init__.py"))
    parser.add_argument("--tag")
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--index", choices=["testpypi", "pypi"])
    parser.add_argument("--download", type=Path, default=Path("downloaded"))
    args = parser.parse_args()
    if args.command == "tag":
        print(check_tag(args.source, args.tag))
    elif args.command == "artifacts":
        version, hashes = artifacts(args.dist)
        if version != check_tag(args.source, args.tag):
            raise ValueError("Build/source/tag versions differ")
        print(json.dumps(hashes, indent=2))
    elif args.command == "smoke":
        smoke(args.dist)
    elif args.command == "index":
        if not args.index:
            parser.error("index command requires --index")
        verify_index(args.dist, args.index, args.download)


if __name__ == "__main__":
    main()
