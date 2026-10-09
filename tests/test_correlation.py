"""Deterministic, immutable lead correlation primitives."""

from dataclasses import FrozenInstanceError, replace

import pytest

from awsherlock.correlation import (
    CorrelationRule,
    CorrelationError,
    FindingRef,
    Lead,
    LeadPriority,
    LeadStatement,
    RelationshipRef,
    lead_to_dict,
    merge_leads,
    validate_correlation_rules,
)
from awsherlock.models import RelationshipType, ResourceRef


ACCOUNT = "123456789012"
REGION = "eu-west-1"


def resource(
    resource_id: str,
    *,
    service: str = "lambda",
    resource_type: str = "function",
    region: str | None = REGION,
    arn: str | None = None,
) -> ResourceRef:
    return ResourceRef(
        service=service,
        resource_type=resource_type,
        account_id=ACCOUNT,
        region=region,
        resource_id=resource_id,
        resource_arn=arn,
    )


def finding(check_id: str, subject: ResourceRef, arn: str | None = None) -> FindingRef:
    return FindingRef(
        check_id=check_id,
        service=subject.service,
        account_id=subject.account_id,
        region=subject.region,
        resource_id=subject.resource_id,
        resource_arn=arn,
    )


def lead(*subjects: ResourceRef, title: str = "Lead", next_step: str = "Review.",
         related_resources: tuple[ResourceRef, ...] = (),
         finding_refs: tuple[FindingRef, ...] = (),
         relationship_refs: tuple[RelationshipRef, ...] = (),
         observed: tuple[LeadStatement, ...] = ()) -> Lead:
    return Lead(
        pattern_id="TEST-PATTERN",
        subjects=subjects,
        title=title,
        priority=LeadPriority.HIGH,
        related_resources=related_resources,
        finding_refs=finding_refs,
        relationship_refs=relationship_refs,
        observed=observed,
        unknown=(LeadStatement(code="UNKNOWN", text="Unknown."),),
        not_proven=(LeadStatement(code="NOT_PROVEN", text="Not proven."),),
        why_it_matters="Review related signals.",
        next_step=next_step,
    )


def test_subject_order_normalizes_lead_identity_and_serialization():
    a = resource("a", arn=f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:a")
    b = resource("b", arn=f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:b")
    forward = lead(a, b)
    reverse = lead(b, a)

    assert forward.subjects == reverse.subjects == (a, b)
    assert forward == reverse
    assert hash(forward) == hash(reverse)
    assert forward.lead_id == reverse.lead_id
    assert lead_to_dict(forward) == lead_to_dict(reverse)


def test_lead_id_uses_only_pattern_and_subject_logical_identity():
    arn = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:worker"
    plain = resource("worker")
    located = resource("worker", arn=arn)
    original = lead(plain)
    presentation_changed = lead(
        located,
        title="Different title",
        next_step="Different next step.",
        observed=(LeadStatement(code="OBSERVED", text="Observed."),),
    )
    different_subject = lead(resource("other"))

    assert original == presentation_changed
    assert original.lead_id == presentation_changed.lead_id
    assert original.lead_id.startswith("TEST-PATTERN:")
    assert len(original.lead_id.split(":", 1)[1]) == 64
    assert original.lead_id != different_subject.lead_id


def test_lead_normalizes_all_supporting_collections_and_is_immutable():
    subject = resource("worker", arn=f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:worker")
    role_plain = resource("role", service="iam", resource_type="role", region=None)
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/role"
    role_located = replace(role_plain, resource_arn=role_arn)
    edge = RelationshipRef(source=subject, relationship_type=RelationshipType.RUNS_AS,
                           target=role_plain)
    edge_located = RelationshipRef(source=subject, relationship_type=RelationshipType.RUNS_AS,
                                   target=role_located)
    candidate = lead(
        subject,
        related_resources=(role_plain, role_located),
        finding_refs=(finding("AWSH-X-002", subject), finding("AWSH-X-001", subject)),
        relationship_refs=(edge, edge_located),
        observed=(LeadStatement(code="Z", text="Zed."), LeadStatement(code="A", text="Aye.")),
    )

    assert candidate.related_resources == (role_located,)
    assert [item.check_id for item in candidate.finding_refs] == ["AWSH-X-001", "AWSH-X-002"]
    assert candidate.relationship_refs == (replace(edge, target=role_located),)
    assert [item.code for item in candidate.observed] == ["A", "Z"]
    with pytest.raises(FrozenInstanceError):
        candidate.pattern_id = "MUTATED"


def test_merge_leads_unions_supporting_data_without_set_loss():
    subject = resource("worker")
    role = resource("role", service="iam", resource_type="role", region=None)
    edge = RelationshipRef(source=subject, relationship_type=RelationshipType.RUNS_AS, target=role)
    first = lead(subject, related_resources=(role,), finding_refs=(finding("AWSH-X-001", subject),),
                 observed=(LeadStatement(code="FIRST", text="First."),))
    second = lead(subject, relationship_refs=(edge,), finding_refs=(finding("AWSH-X-002", subject),),
                  observed=(LeadStatement(code="SECOND", text="Second."),))

    merged = merge_leads((second, first))

    assert len(merged) == 1
    assert merged[0].related_resources == (role,)
    assert {item.check_id for item in merged[0].finding_refs} == {"AWSH-X-001", "AWSH-X-002"}
    assert merged[0].relationship_refs == (edge,)
    assert {item.code for item in merged[0].observed} == {"FIRST", "SECOND"}
    assert lead_to_dict(merge_leads((first, second))[0]) == lead_to_dict(merge_leads((second, first))[0])


def test_conflicting_merge_metadata_and_statement_text_fail_safely():
    subject = resource("worker")
    with pytest.raises(CorrelationError, match="metadata"):
        merge_leads((lead(subject), lead(subject, title="Conflict")))
    with pytest.raises(CorrelationError, match="statement"):
        lead(subject, observed=(
            LeadStatement(code="SAME", text="First."),
            LeadStatement(code="SAME", text="Second."),
        ))


def test_conflicting_optional_locators_fail_safely():
    first = resource("worker", arn=f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:first")
    second = resource("worker", arn=f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:second")
    with pytest.raises(CorrelationError, match="ARN"):
        lead(first, second)
    subject = resource("subject")
    with pytest.raises(CorrelationError, match="ARN"):
        lead(subject, finding_refs=(
            finding("AWSH-X-001", subject, first.resource_arn),
            finding("AWSH-X-001", subject, second.resource_arn),
        ))
    first_edge = RelationshipRef(source=subject, relationship_type=RelationshipType.RUNS_AS,
                                 target=first)
    second_edge = RelationshipRef(source=subject, relationship_type=RelationshipType.RUNS_AS,
                                  target=second)
    with pytest.raises(CorrelationError, match="ARN"):
        lead(subject, relationship_refs=(first_edge, second_edge))


def test_duplicate_correlation_rule_ids_fail_loudly():
    from awsherlock.leads import CORRELATION_RULES
    with pytest.raises(CorrelationError, match="Duplicate"):
        validate_correlation_rules((CORRELATION_RULES[0], CORRELATION_RULES[0]))


def test_models_reject_malformed_nested_values_and_account_ids_safely():
    with pytest.raises(CorrelationError):
        lead("not-a-resource-ref")
    with pytest.raises(CorrelationError, match="account_id"):
        FindingRef(check_id="AWSH-X-001", service="iam", account_id="invalid", region=None,
                   resource_id="role")
    with pytest.raises(CorrelationError):
        CorrelationRule(pattern_id="TEST", title="Test", priority=LeadPriority.LOW,
                        requires_relationships=1, correlate=lambda context: ())
