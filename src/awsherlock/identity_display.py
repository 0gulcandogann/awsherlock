"""Human-readable identity diagnostics, separate from finding reports."""

from awsherlock.aws.context import ScanContext
from awsherlock.terminal import Console
from awsherlock.branding import terminal_text


def principal_type(arn: str) -> str:
    resource = arn.split(":", 5)[-1]
    if resource == "root":
        return "root"
    for prefix, label in (("assumed-role/", "assumed role"),
                          ("user/", "IAM user"), ("federated-user/", "federated user")):
        if resource.startswith(prefix):
            return label
    return "unknown"


def show_identity(context: ScanContext, *, err: bool = False,
                  regions: list[str] | None = None, services: list[str] | None = None,
                  purpose: str | None = None) -> None:
    """Use already-verified context; never inspect credentials or infer role paths."""
    rows = [("Identity", "verified live via STS"),
            ("Account", context.account_id),
            ("Principal", principal_type(context.caller_arn)),
            ("Caller ARN", context.caller_arn),
            ("Profile", context.profile or "unknown"),
            ("Regions", ", ".join(regions) if regions else context.region or "unknown")]
    if purpose is not None:
        rows.insert(1, ("Context", purpose))
    if services is not None:
        rows.append(("Services", ", ".join(services)))
    console = Console(stderr=err)
    for label, value in rows:
        console.print(f"{label}: {terminal_text(value)}", markup=False, highlight=False)
    console.print("Profile is configuration metadata; source account is not separately verified.",
                  markup=False, highlight=False)


def show_offline_identity(account_id: str) -> None:
    console = Console(stderr=True)
    console.print("Mode: offline snapshot replay", markup=False, highlight=False)
    console.print(f"Account: {terminal_text(account_id)} (snapshot metadata; not verified live)",
                  markup=False, highlight=False)
    console.print("Live identity: not checked", markup=False, highlight=False)
