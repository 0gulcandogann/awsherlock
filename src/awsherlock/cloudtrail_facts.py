"""Conservative management-event selector facts, without exporting selectors."""

from awsherlock.collectors.common import InvalidResponse, items

MANAGEMENT_SOURCES = {"kms.amazonaws.com", "rdsdata.amazonaws.com"}


def management_events(response: object) -> bool:
    if not isinstance(response, dict) or not any(key in response for key in ("EventSelectors", "AdvancedEventSelectors")):
        raise InvalidResponse()
    basic = items({"EventSelectors": response.get("EventSelectors", [])}, "EventSelectors")
    advanced = items({"AdvancedEventSelectors": response.get("AdvancedEventSelectors", [])}, "AdvancedEventSelectors")
    if basic and advanced:
        raise InvalidResponse()
    if not basic and not advanced:
        # Empty lists cannot establish exclusions given CloudTrail's defaults.
        raise InvalidResponse()
    included = []
    for selector in basic:
        if not isinstance(selector, dict):
            raise InvalidResponse()
        value = selector.get("IncludeManagementEvents", True)
        if type(value) is not bool or selector.get("ReadWriteType", "All") not in {"All", "ReadOnly", "WriteOnly"}:
            raise InvalidResponse()
        included.append(value)
    for selector in advanced:
        if not isinstance(selector, dict):
            raise InvalidResponse()
        fields = items(selector, "FieldSelectors")
        category_fields = [field for field in fields if isinstance(field, dict) and field.get("Field") == "eventCategory"]
        if len(category_fields) != 1:
            raise InvalidResponse()
        category = category_fields[0]
        if set(category) != {"Field", "Equals"} or not isinstance(category["Equals"], list) or not category["Equals"] or any(
            not isinstance(value, str) or not value for value in category["Equals"]
        ):
            raise InvalidResponse()
        if "Management" not in category["Equals"]:
            # Data/resource filters cannot make a Data-only selector log Management.
            included.append(False)
            continue
        categories = []
        seen = set()
        for field in fields:
            if not isinstance(field, dict) or field.get("Field") not in {"eventCategory", "readOnly", "eventSource"}:
                # More restrictive event-source/name/resource filters are not simulated.
                raise InvalidResponse()
            operator = "NotEquals" if field["Field"] == "eventSource" else "Equals"
            if set(field) != {"Field", operator}:
                raise InvalidResponse()
            if field["Field"] in seen:
                raise InvalidResponse()
            seen.add(field["Field"])
            values = field[operator]
            if not isinstance(values, list) or not values or any(not isinstance(value, str) or not value for value in values):
                raise InvalidResponse()
            if field["Field"] == "eventCategory":
                categories.append("Management" in values)
            elif field["Field"] == "eventSource":
                if not set(values) <= MANAGEMENT_SOURCES:
                    raise InvalidResponse()
            elif any(value not in {"true", "false"} for value in values):
                raise InvalidResponse()
        if len(categories) != 1:
            raise InvalidResponse()
        included.append(categories[0])
    return any(included)


def management_context(response: object) -> dict:
    """Known trail exclusions common to every management-enabled selector.

    A source excluded in only one selector may still be included by another.
    This context does not establish full read/write or API coverage.
    """
    enabled = management_events(response)
    exclusions = []
    for selector in response.get("EventSelectors", []):
        if selector.get("IncludeManagementEvents", True):
            sources = selector.get("ExcludeManagementEventSources", [])
            if not isinstance(sources, list) or any(not isinstance(s, str) or s not in MANAGEMENT_SOURCES for s in sources):
                raise InvalidResponse()
            exclusions.append(set(sources))
    for selector in response.get("AdvancedEventSelectors", []):
        fields = selector["FieldSelectors"]
        if any(isinstance(field, dict) and field.get("Field") == "eventCategory" and "Management" in field.get("Equals", []) for field in fields):
            exclusions.append({source for field in fields if field["Field"] == "eventSource" for source in field["NotEquals"]})
    common = set.intersection(*exclusions) if exclusions else set()
    return {"management_events": enabled, "management_excluded_sources": sorted(common)}
