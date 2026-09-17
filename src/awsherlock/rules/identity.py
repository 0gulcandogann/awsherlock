"""Bounded identity governance indicators, independent of AWS clients."""

from dataclasses import dataclass

from awsherlock.models import Finding, Severity, Resource


@dataclass(frozen=True)
class IdentityRule:
    number: int
    required_fact: str
    title: str
    remediation: str

    def evaluate(self, resource: Resource) -> list[Finding]:
        if resource.service != "iam" or resource.resource_type not in {"role", "user"}:
            return []
        data = resource.data
        if self.required_fact not in data:
            raise ValueError("Identity evidence was not collected")
        value = data[self.required_fact]
        profile = data.get("identity_profile", {})
        approval = data.get("identity_approval", {})
        if self.number in {7, 8}:
            if profile.get("service_linked"):
                return []
            key = "owner" if self.number == 7 else "purpose"
            matches = not value[key] and not approval.get(key, False)
        elif self.number == 9:
            if profile.get("service_linked"):
                return []
            if value["status"] == "unknown":
                raise ValueError("Role usage tracking evidence is missing")
            matches = (value["last_used_days"] is not None and value["last_used_days"] > 90
                       or value["status"] == "no_record" and value["created_days"] > 90)
        elif self.number == 10:
            if value["status"] != "supported":
                raise ValueError("Unsupported trust conditions")
            matches = value["broad"]
        elif self.number == 11:
            if value["status"] == "unknown":
                raise ValueError("No complete approval inventory for this account")
            matches = value["status"] == "unregistered"
        else:
            trust = data.get("identity_trust")
            if value["status"] != "registered" or trust is None or trust["status"] != "supported":
                raise ValueError("Trust approval evidence is incomplete")
            matches = [principal for principal in trust["principals"] if principal["value"] not in value["allowed_principals"]]
            for requirement, control in (("external_id_required", "external_id_condition"), ("source_identity_required", "source_identity_condition")):
                if value[requirement] and not trust[control]:
                    matches.append({"kind": "MissingTrustControl", "value": requirement})
            for event in data.get("identity_activity", {}).get("events", []):
                caller = event["caller_arn"]
                if caller is not None and not any(caller == allowed or caller.split(":")[4] == allowed
                                                 or allowed.endswith(":root") and caller.split(":")[4] == allowed.split(":")[4]
                                                 for allowed in value["allowed_principals"]):
                    observed = {"kind": "ObservedCaller", "value": caller}
                    if observed not in matches:
                        matches.append(observed)
        if not matches:
            return []
        return [Finding(id=f"AWSH-IAM-{self.number:03}", title=self.title,
                        description="Identity governance review indicator. Declarations, observed use and configured trust are separate evidence.",
                        severity=Severity.HIGH if self.number in {10, 12} else Severity.MEDIUM,
                        service="iam", account_id=resource.account_id, region=None,
                        resource_id=resource.resource_id, resource_arn=resource.resource_arn,
                        evidence={self.required_fact: value, "review_threshold_days": 90,
                                  **({"unapproved_principals": matches} if self.number == 12 else {})},
                        risk="Unowned, stale or broadly trusted identities can retain access without review. This does not prove compromise or unnecessary access.",
                        remediation=self.remediation,
                        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"])]


IDENTITY_RULES = (
    IdentityRule(7, "identity_profile", "Identity owner metadata is missing", "Declare an accountable owner using Owner metadata or the identity inventory."),
    IdentityRule(8, "identity_profile", "Identity purpose metadata is missing", "Document the intended purpose using Purpose metadata or the identity inventory."),
    IdentityRule(9, "identity_usage", "IAM role has a stale usage indicator", "Review roles unused for over 90 days; consider tracking-window limitations before retirement."),
    IdentityRule(10, "identity_trust", "IAM role trust is broadly scoped", "Restrict supported trust principals and OIDC audience/subject conditions to intended callers."),
    IdentityRule(11, "identity_approval", "Identity is absent from the complete approval inventory", "Review this unregistered identity with the account owner; update approvals or retire through your change process."),
    IdentityRule(12, "identity_approval", "IAM role trust differs from declared approvals", "Review trust principals not listed in the identity inventory; verify business approval."),
)
