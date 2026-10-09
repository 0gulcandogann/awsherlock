"""Optional real Chromium check using a local file, without a server or CDN."""

from pathlib import Path
from dataclasses import replace
import shutil
import subprocess
import pytest
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.reporting import render_html
from awsherlock.models import Severity
from test_snapshot import snapshot


def chromium_path() -> str | None:
    # GitHub's Ubuntu image may expose a non-functional Chromium wrapper while
    # also providing a working Google Chrome binary. Prefer the installed
    # Chrome browser, then fall back to Chromium and Edge for local runs.
    for name in ("google-chrome", "chromium", "chromium-browser", "msedge"):
        found = shutil.which(name)
        if found:
            return found
    for name in (r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                 r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"):
        if Path(name).is_file():
            return name
    return None


def run_browser(html: str, script: str, tmp_path: Path) -> str:
    browser = chromium_path()
    if browser is None:
        pytest.skip("Optional browser test requires installed Chromium/Chrome/Edge")
    harness = html.replace("</body>", "<script>" + script + "</script></body>")
    path = tmp_path / "report.html"
    path.write_text(harness, encoding="utf-8")
    result = subprocess.run([
        browser, "--headless=new", "--disable-gpu", "--no-first-run", "--disable-background-networking",
        "--host-resolver-rules=MAP * ~NOTFOUND", "--no-sandbox", f"--user-data-dir={tmp_path / 'browser-profile'}",
        "--virtual-time-budget=1000", "--dump-dom", path.as_uri(),
    ], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=45)
    assert result.returncode == 0
    return result.stdout


def test_standalone_report_opens(snapshot, tmp_path):
    html = render_html(evaluate_snapshot(snapshot))
    script = """
    const details = document.querySelector('details.finding');
    details.querySelector('summary').click();
    const result = document.createElement('p');
    result.id = 'browser-result';
    result.textContent = details.open && document.title.includes('AWSherlock') ? 'PASS' : 'FAIL';
    document.body.append(result);
    """
    output = run_browser(html, script, tmp_path)
    assert '<p id="browser-result">PASS</p>' in output


def test_filters_sort_and_empty_states(snapshot, tmp_path):
    report = evaluate_snapshot(snapshot)
    base = report.findings[0]
    report.findings.extend([
        replace(base, id="AWSH-IAM-001", service="iam", severity=Severity.HIGH, account_id="000000000002", resource_id="zebra"),
        replace(base, id="AWSH-S3-002", severity=Severity.LOW, resource_id="alpha"),
    ])
    report.coverage.append({**report.coverage[0], "service": "iam"})
    script = """
    const visible = () => Array.from(document.querySelectorAll('.finding')).filter(r => !r.hidden);
    const check = (ok) => { if (!ok) throw Error('Report assertion failed'); };
    const set = (id, value) => { const el = document.getElementById(id); el.value = value; el.dispatchEvent(new Event(id === 'search' ? 'input' : 'change')); };
    const reset = () => document.getElementById('reset').click();
    check(visible()[0].dataset.severity === 'HIGH');
    set('search', 'awsh-s3-002'); check(visible().length === 1);
    set('severity', 'HIGH'); check(visible().length === 0 && !document.getElementById('no-matches').hidden);
    reset(); set('service', 'iam'); check(visible().length === 1);
    reset(); set('account', '000000000002'); check(visible().length === 1);
    reset(); set('severity', 'LOW'); check(visible().length === 1);
    reset(); set('sort', 'severity-asc'); check(visible()[0].dataset.severity === 'LOW');
    set('sort', 'resource'); check(visible()[0].dataset.resource === 'alpha');
    set('sort', 'id'); check(visible()[0].dataset.id === 'AWSH-IAM-001');
    set('sort', 'service'); check(visible()[0].dataset.service === 'iam');
    reset(); check(visible().length === 3 && document.getElementById('result-count').textContent === '3 of 3 findings shown');
    check(document.querySelector('table').textContent.includes('AccessDenied'));
    document.body.insertAdjacentHTML('beforeend', '<p id="browser-result">PASS</p>');
    """
    assert '<p id="browser-result">PASS</p>' in run_browser(render_html(report), script, tmp_path)


def test_light_report_mobile_layout(snapshot, tmp_path):
    import json
    html = render_html(evaluate_snapshot(snapshot))
    embedded = json.dumps(html).replace("<", "\\u003c")
    script = """
    const frame = document.createElement('iframe');
    frame.style.width = '375px';
    frame.style.height = '900px';
    frame.onload = () => {
      const doc = frame.contentDocument;
      const check = doc.documentElement.scrollWidth <= doc.documentElement.clientWidth &&
        frame.contentWindow.getComputedStyle(doc.documentElement).colorScheme === 'light';
      document.body.insertAdjacentHTML('beforeend', '<p id="mobile-result">' + (check ? 'PASS' : 'FAIL') + '</p>');
    };
    frame.srcdoc = """ + embedded + ";document.body.append(frame);"
    assert '<p id="mobile-result">PASS</p>' in run_browser(html, script, tmp_path)
