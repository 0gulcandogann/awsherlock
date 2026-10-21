"""Validate a saved capture offline; never authenticates, collects or provisions.

Run from a checkout with the project installed. Optional live-report comparison
requires the same collection and evaluation options, not a second live scan.
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys

from awsherlock.evaluation import evaluate_snapshot
from awsherlock.investigation_engine import build_investigations, render_investigations_json
from awsherlock.snapshot import SnapshotError, read_snapshot


def _ordered(value: object) -> object:
    if isinstance(value, dict):
        return {key: _ordered(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return sorted(
            (_ordered(item) for item in value),
            key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=True),
        )
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument(
        "--report",
        type=Path,
        help="JSON report from this exact capture; all checks/resources, same identity declarations.",
    )
    args = parser.parse_args()
    try:
        snapshot = read_snapshot(args.snapshot)
        report = evaluate_snapshot(snapshot)
        capture_match = None
        if args.report is not None:
            captured = json.loads(args.report.read_text(encoding="utf-8"))
            if not isinstance(captured, dict):
                raise ValueError("Invalid report shape")
            replayed = report.to_dict()
            fields = ("findings", "coverage", "summary", "identities")
            differing = [
                field
                for field in fields
                if _ordered(captured.get(field)) != _ordered(replayed.get(field))
            ]
            # A different collection's otherwise-identical evidence is not a
            # same-capture validation. Preserve account and collection identity.
            if not isinstance(captured.get("metadata"), dict) or any(
                captured["metadata"].get(key) != replayed["metadata"].get(key)
                for key in ("scan_id", "account_id", "region")
            ):
                differing.append("metadata_scope")
            if differing:
                print("Capture/replay mismatch: " + ", ".join(differing), file=sys.stderr)
                return 1
            capture_match = True
        result = build_investigations(snapshot, report=report)
        content = render_investigations_json(result)
        if content != render_investigations_json(build_investigations(snapshot, report=report)):
            raise ValueError("Non-deterministic investigation output")
        print(
            json.dumps(
                {
                    "validation": "OFFLINE_ONLY",
                    "capture_replay_match": capture_match,
                    "investigations": len(result.investigations),
                    "incomplete": result.incomplete,
                    "investigation_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                },
                sort_keys=True,
            )
        )
        return 0
    except (OSError, ValueError, SnapshotError):
        print(
            "Validation failed: unreadable or invalid saved evidence; no AWS calls performed.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
