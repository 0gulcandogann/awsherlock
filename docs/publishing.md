# Publishing AWSherlock to PyPI

AWSherlock 0.2.0 is published on [PyPI](https://pypi.org/project/awsherlock/0.2.0/) and [TestPyPI](https://test.pypi.org/project/awsherlock/0.2.0/). The tagged release completed its build, fresh-install matrix, Trusted Publishing uploads, and downloaded hash and installation checks on both indices in [GitHub Actions run 35895588709](https://github.com/0gulcandogann/awsherlock/actions/runs/35895588709). Preserve published files. Before a future tag, complete the local release milestone and obtain owner release authorization.

## One-time Trusted Publishing setup

The workflow is `.github/workflows/publish.yml`. No permanent PyPI API token or GitHub secret is needed. Configure a GitHub Actions trusted publisher for the existing `awsherlock` project on each index:

| Field | PyPI | TestPyPI |
| --- | --- | --- |
| Owner | `0gulcandogann` | `0gulcandogann` |
| Repository | `awsherlock` | `awsherlock` |
| Workflow filename | `publish.yml` | `publish.yml` |
| Environment | `pypi` | `testpypi` |

Use [PyPI Publishing](https://pypi.org/manage/project/awsherlock/settings/publishing/) and [TestPyPI Publishing](https://test.pypi.org/manage/project/awsherlock/settings/publishing/), select GitHub Actions, fill in the matching fields, and add the publisher. The workflow filename is just `publish.yml`, without its directory.

Create matching `pypi` and `testpypi` environments in [GitHub environment settings](https://github.com/0gulcandogann/awsherlock/settings/environments). For each, select deployment branch/tag restrictions allowing tags matching `v*`; branch runs do not publish. No environment secrets are required. These restrictions are configured in GitHub, not in the workflow YAML.

Setup is not complete until both publishers are saved, the workflow/scripts are committed and pushed, and remote validation succeeds. Existing API tokens in a local ignored `.env` are not read by this workflow. Authenticated PyPI web configuration must be completed by the project owner.

## Validate without publishing

Once the workflow is on the default branch, open GitHub Actions, select **Publish Python package**, and use **Run workflow** on `main`. This builds once, checks source version, wheel/source metadata and README rendering, then installs the wheel in fresh environments on Linux/Python 3.11 and 3.13, Windows/Python 3.13 and macOS/Python 3.13. Installed-code equality, CLI discovery and offline JSON/HTML are checked. This branch run cannot upload to either index and does not exercise the OIDC exchange.

CI runs committed package smoke checks, not the ignored local full scanner test suite. Before a release, run the relevant local scanner tests as well. None of these checks require AWS credentials or make an AWS request.

## Publish a new stable version

1. Update `__version__` in `src/awsherlock/__init__.py`, update release documentation, and commit the exact source intended for release. Run relevant local tests.
2. Push that commit to `main`.
3. Create and push its matching stable tag, for example `v0.2.1` for package version `0.2.1`, only after the release gate and owner authorization.
4. Check that all **Publish Python package** jobs pass.

Tag pushes matching `v*` trigger the workflow; only exact `vX.Y.Z` tags matching the source version pass validation. Prerelease tags are intentionally unsupported. Package source is checked out at the event's tagged commit. Pushing a normal `main` commit does not publish.

The sequence is: build wheel/source once -> metadata checks -> installation matrix -> TestPyPI upload -> download/hash checks and fresh TestPyPI-wheel install -> PyPI upload -> download/hash checks and fresh production-wheel install. Both indices receive the same original build artifacts. OIDC permission is limited to the two publishing jobs, which only download artifacts and invoke the official PyPA publisher; they do not check out or execute scanner code.

The publisher can skip already uploaded filenames on a retry. Subsequent verification must match their published and downloaded SHA256 values to the original build, so differing existing files fail the run. Retry failed jobs from the same workflow run to retain its original artifacts. Do not rebuild or move a published tag to replace an existing version; make a new version instead. Production verification can fail after an upload has succeeded: check the index before deciding whether a new upload is needed. GitHub releases are not automatically created or changed.

## Installation and update channels

Users install released packages with `pipx install awsherlock` or `python -m pip install awsherlock` inside a virtual environment. Update the index installation with `pipx upgrade awsherlock` or `python -m pip install --upgrade awsherlock`.

**`awsherlock --update` intentionally installs GitHub `main`** so users can test unreleased fixes and features, including changes without a version bump. It requires Git and internet access. This task preserves the existing updater behavior.

The 0.2.0 archives embed the README as it stood at tag time. This page records the verified publication status; its update after publication does not change the tagged archives.

References: [Adding a Trusted Publisher](https://docs.pypi.org/trusted-publishers/adding-a-publisher/), [Publishing with a Trusted Publisher](https://docs.pypi.org/trusted-publishers/using-a-publisher/), [official PyPA publish action](https://github.com/pypa/gh-action-pypi-publish).
