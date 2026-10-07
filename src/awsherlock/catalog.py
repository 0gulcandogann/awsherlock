"""Read-only descriptions projected from the canonical check registry."""

from awsherlock.registry import check_specs


def check_catalog() -> list[tuple[str, str, str]]:
    """Return check ID, service and title without collecting or evaluating."""
    return [(spec.identifier, spec.service, spec.title) for spec in check_specs()]


def describe_check(check_id: str) -> dict[str, str] | None:
    """Read registered metadata without constructing sample resources or evaluating."""
    requested = check_id.strip().upper()
    for spec in check_specs():
        if spec.identifier == requested:
            return {"Check": spec.identifier, "Title": spec.title, "Service": spec.service,
                    "Required fact": spec.required_fact, "Remediation": spec.remediation,
                    "Scope": spec.scope_limitations}
    return None
