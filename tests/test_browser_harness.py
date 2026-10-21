"""Browser harness failures must be actionable and never counted as passes."""

import subprocess

import pytest

from test_report_browser import chromium_path, run_browser


def test_chrome_stable_is_preferred_to_chromium(monkeypatch):
    monkeypatch.delenv("AWSHERLOCK_TEST_BROWSER", raising=False)
    monkeypatch.setattr(
        "test_report_browser.shutil.which",
        lambda name: f"/usr/bin/{name}" if name in {"google-chrome-stable", "chromium"} else None,
    )
    assert chromium_path() == "/usr/bin/google-chrome-stable"


@pytest.mark.parametrize("opt_out", [None, "0", "1"])
def test_browser_sandbox_is_enabled_unless_explicitly_disabled(monkeypatch, tmp_path, opt_out):
    monkeypatch.setattr("test_report_browser.chromium_path", lambda: "/synthetic/chrome")
    if opt_out is None:
        monkeypatch.delenv("AWSHERLOCK_TEST_BROWSER_NO_SANDBOX", raising=False)
    else:
        monkeypatch.setenv("AWSHERLOCK_TEST_BROWSER_NO_SANDBOX", opt_out)
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "browser output", "")

    monkeypatch.setattr("test_report_browser.subprocess.run", run)
    assert run_browser("<body></body>", "", tmp_path) == "browser output"
    assert ("--no-sandbox" in commands[0]) == (opt_out == "1")


def test_explicit_browser_path_is_used_and_invalid_path_fails(monkeypatch, tmp_path):
    browser = tmp_path / "test-browser"
    browser.write_text("fixture", encoding="utf-8")
    monkeypatch.setenv("AWSHERLOCK_TEST_BROWSER", str(browser))
    monkeypatch.setattr(
        "test_report_browser.shutil.which",
        lambda value: str(browser) if value == str(browser) else None,
    )
    assert chromium_path() == str(browser)
    monkeypatch.setenv("AWSHERLOCK_TEST_BROWSER", "does-not-exist")
    with pytest.raises(AssertionError, match="AWSHERLOCK_TEST_BROWSER"):
        chromium_path()


def test_required_missing_browser_fails_instead_of_skipping(monkeypatch, tmp_path):
    monkeypatch.setattr("test_report_browser.chromium_path", lambda: None)
    monkeypatch.setenv("AWSHERLOCK_REQUIRE_BROWSER", "1")
    with pytest.raises(AssertionError, match="required"):
        run_browser("<body></body>", "", tmp_path)


def test_browser_failure_includes_exit_and_bounded_stderr(monkeypatch, tmp_path):
    monkeypatch.setattr("test_report_browser.chromium_path", lambda: "/synthetic/chromium")
    monkeypatch.setattr(
        "test_report_browser.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], -5, "", "setsockopt: Operation not permitted" + "x" * 10000
        ),
    )
    with pytest.raises(AssertionError) as error:
        run_browser("<body></body>", "", tmp_path)
    assert "exit -5" in str(error.value) and "Operation not permitted" in str(error.value)
    assert len(str(error.value)) < 5000


def test_browser_timeout_is_an_explicit_failure(monkeypatch, tmp_path):
    monkeypatch.setattr("test_report_browser.chromium_path", lambda: "/synthetic/chromium")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 45)

    monkeypatch.setattr("test_report_browser.subprocess.run", timeout)
    with pytest.raises(pytest.fail.Exception, match="45 seconds"):
        run_browser("<body></body>", "", tmp_path)
