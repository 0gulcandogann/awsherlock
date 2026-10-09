"""Release guardrails; no AWS credentials or publishing access."""
import importlib.util
import io
import json
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location("release_checks", Path(__file__).resolve().parents[1] / ".github/scripts/release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


@pytest.mark.parametrize("tag", ["v0.1.11", "v0.1.10rc1", "0.1.10", "main", "v0.1.10; echo bad"])
def test_mismatched_tag_is_rejected(tmp_path, tag):
    source = tmp_path / "version.py"
    source.write_text('__version__ = "0.1.10"\n')
    with pytest.raises(ValueError, match="Tag must match"):
        release.check_tag(source, tag)


def test_matching_tag_and_dry_run(tmp_path):
    source = tmp_path / "version.py"
    source.write_text('__version__ = "0.1.10"\n')
    assert release.check_tag(source, "v0.1.10") == "0.1.10"
    assert release.check_tag(source, None) == "0.1.10"


@pytest.mark.parametrize("version", ["0.1.10rc1", "0.1", "", "0.1.10+dev"])
def test_only_stable_versions(version):
    with pytest.raises(ValueError):
        release.stable_version(version)


def test_extra_artifacts_rejected(tmp_path):
    for name in ("one.whl", "two.whl", "one.tar.gz"):
        (tmp_path / name).touch()
    with pytest.raises(ValueError, match="exactly one"):
        release.artifacts(tmp_path)


@pytest.mark.parametrize("published_hash,download", [("wrong", b"wheel"), ("expected", b"altered")])
def test_index_hash_mismatch_prevents_install(monkeypatch, tmp_path, published_hash, download):
    monkeypatch.setattr(release, "artifacts", lambda dist: ("0.1.10", {"package.whl": "expected"}))
    metadata = {"info": {"version": "0.1.10"}, "urls": [{"filename": "package.whl", "digests": {"sha256": published_hash}, "url": "https://files.example/wheel"}]}
    responses = iter([json.dumps(metadata).encode(), download])
    monkeypatch.setattr(release.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(next(responses)))
    with pytest.raises(ValueError, match="hash differs"):
        release.verify_index(tmp_path, "testpypi", tmp_path / "downloaded")
    assert not (tmp_path / "downloaded/package.whl").exists()


def test_index_missing_file_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(release, "artifacts", lambda dist: ("0.1.10", {"package.whl": "expected"}))
    metadata = {"info": {"version": "0.1.10"}, "urls": []}
    monkeypatch.setattr(release.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(json.dumps(metadata).encode()))
    with pytest.raises(ValueError, match="artifacts differ"):
        release.verify_index(tmp_path, "pypi", tmp_path / "downloaded")


def test_offline_report_external_asset_rejected():
    with pytest.raises(ValueError, match="external asset"):
        release.OfflineAssets().feed('<script src="https://example/script.js"></script>')
    release.OfflineAssets().feed('<script>const local = true;</script>')
