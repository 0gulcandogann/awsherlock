"""Read existing Access Analyzer findings; never create analyzers or jobs."""

import time
import re
from awsherlock.aws.context import ScanContext
from awsherlock.collectors.common import CollectionResult

from awsherlock.collectors.common import AWS_ERRORS, InvalidResponse, CollectionIssue, items, text_field, error_message


def collect_identity_analyzers(context: ScanContext, result: CollectionResult) -> None:
    options = context.identity_options
    regions = options.regions or ((context.region,) if context.region else ())
    identities = {r.resource_arn: r for r in result.resources if r.resource_type in {"role", "user"}}
    deadline = time.monotonic() + options.max_seconds
    reads = 0
    found = False

    def check():
        nonlocal reads
        if reads >= options.max_pages or time.monotonic() >= deadline:
            raise InvalidResponse()
        reads += 1

    def paginated(client, operation, key, **params):
        iterator = iter(client.get_paginator(operation).paginate(**params))
        while True:
            check()
            try:
                page = next(iterator)
            except StopIteration:
                return
            yield from items(page, key)
            if not page.get("nextToken"):
                return

    for resource in identities.values():
        resource.data["identity_analyzer_findings"] = []
    for region in regions:
        try:
            client = context.client("accessanalyzer", region_name=region)
            for analyzer in paginated(client, "list_analyzers", "analyzers"):
                if not isinstance(analyzer, dict):
                    raise InvalidResponse()
                arn = text_field(analyzer.get("arn"))
                analyzer_type = text_field(analyzer.get("type"))
                if analyzer.get("status") != "ACTIVE":
                    result.issues.append(CollectionIssue(None, "IdentityAnalyzers", "Existing analyzer is not ACTIVE"))
                    continue
                found = True
                for finding in paginated(client, "list_findings_v2", "findings", analyzerArn=arn):
                    if not isinstance(finding, dict):
                        raise InvalidResponse()
                    resource = identities.get(finding.get("resource"))
                    if resource is None or finding.get("status") != "ACTIVE":
                        continue
                    if finding.get("error"):
                        result.issues.append(CollectionIssue(resource.resource_id, "IdentityAnalyzers", "Existing analyzer finding has an analysis error"))
                        continue
                    actions, services, external_principals = [], [], []
                    token = None
                    seen_tokens = set()
                    while True:
                        check()
                        detail = client.get_finding_v2(analyzerArn=arn, id=text_field(finding.get("id")),
                                                       **({"nextToken": token} if token is not None else {}))
                        if not isinstance(detail, dict) or detail.get("resource") != resource.resource_arn or detail.get("status") != "ACTIVE":
                            raise InvalidResponse()
                        for item in items(detail, "findingDetails"):
                            unused = item.get("unusedPermissionDetails") if isinstance(item, dict) else None
                            if isinstance(unused, dict):
                                service = text_field(unused.get("serviceNamespace"))
                                services.append(service)
                                for action in items({"actions": unused.get("actions", [])}, "actions"):
                                    if not isinstance(action, dict):
                                        raise InvalidResponse()
                                    actions.append(service + ":" + text_field(action.get("action")))
                            external = item.get("externalAccessDetails") if isinstance(item, dict) else None
                            if isinstance(external, dict):
                                principal = external.get("principal", {})
                                if not isinstance(principal, dict):
                                    raise InvalidResponse()
                                for value in principal.values():
                                    if isinstance(value, str) and re.fullmatch(r"(?:\*|[0-9]{12}|arn:[a-z0-9-]+:iam::[0-9]{12}:(?:root|(?:role|user|oidc-provider|saml-provider)/[^\s*?]+))", value):
                                        external_principals.append(value)
                        token = detail.get("nextToken")
                        if token is None:
                            break
                        token = text_field(token)
                        if token in seen_tokens:
                            raise InvalidResponse()
                        seen_tokens.add(token)
                    updated = finding.get("updatedAt")
                    if not hasattr(updated, "isoformat"):
                        raise InvalidResponse()
                    configuration = analyzer.get("configuration", {})
                    unused_config = configuration.get("unusedAccess", {}) if isinstance(configuration, dict) else {}
                    window = unused_config.get("unusedAccessAge") if isinstance(unused_config, dict) else None
                    if window is not None and (type(window) is not int or window < 1):
                        raise InvalidResponse()
                    resource.data["identity_analyzer_findings"].append({
                        "analyzer_arn": arn, "analyzer_type": analyzer_type, "region": region,
                        "finding_type": text_field(finding.get("findingType")), "status": "ACTIVE",
                        "updated_at": updated.isoformat(), "resource_arn": resource.resource_arn,
                        "unused_actions": sorted(set(actions)), "unused_services": sorted(set(services)), "tracking_window_days": window,
                        "external_principals": sorted(set(external_principals))})
        except AWS_ERRORS as error:
            result.issues.append(CollectionIssue(None, "IdentityAnalyzers", error_message(error)))
    if not found:
        result.issues.append(CollectionIssue(None, "IdentityAnalyzers", "No active existing analyzer found in selected regions; analyzer evidence NOT_SCANNED"))
