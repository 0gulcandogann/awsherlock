"""Shared coverage vocabulary; empty findings never imply successful collection."""


def coverage_status(issues: list[dict], evaluated: int, missing: int) -> str:
    if issues or missing:
        if evaluated:
            return "PARTIAL"
        if any(issue["message"] == "AccessDenied" or issue["message"].startswith("AccessDenied:") for issue in issues):
            return "ACCESS_DENIED"
        return "ERROR" if issues else "NOT_SCANNED"
    return "COMPLETE"
