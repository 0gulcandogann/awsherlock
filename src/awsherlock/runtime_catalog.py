"""Managed Lambda runtime catalogue checked 2026-09-15.

Source: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
Dates are AWS projections and require periodic maintenance. Images are excluded.
"""

from datetime import date
from awsherlock.collectors.common import InvalidResponse

DEPRECATED = set("provided.al2 nodejs20.x ruby3.2 python3.9 nodejs18.x dotnet6 python3.8 nodejs16.x dotnet7 java8 go1.x provided ruby2.7 nodejs14.x python3.7 dotnetcore3.1 nodejs12.x python3.6 dotnet5.0 dotnetcore2.1 nodejs10.x ruby2.5 python2.7 nodejs8.10 nodejs4.3 nodejs4.3-edge nodejs6.10 dotnetcore1.0 dotnetcore2.0 nodejs".split())
SCHEDULE = {
    "python3.10": "2026-10-31", "dotnet8": "2026-11-10", "dotnet9": "2026-11-10",
    "python3.11": "2027-06-30", "java8.al2": "2027-06-30", "java11": "2027-06-30", "java17": "2027-06-30",
    "nodejs22.x": "2027-04-30", "nodejs24.x": "2028-04-30", "ruby3.3": "2027-03-31",
    "ruby3.4": "2028-03-31", "ruby4.0": "2029-03-31", "python3.12": "2028-10-31", "dotnet10": "2028-11-14",
    **dict.fromkeys(("python3.13", "python3.14", "java21", "java25", "java8.al2023", "java11.al2023", "java17.al2023", "provided.al2023"), "2029-06-30"),
}


def runtime_fact(runtime: str, today: date) -> dict:
    if runtime not in DEPRECATED and runtime not in SCHEDULE:
        raise InvalidResponse()  # Unknown/preview is not silently declared supported.
    return {"name": runtime, "deprecated": runtime in DEPRECATED or today >= date.fromisoformat(SCHEDULE[runtime]),
            "catalog_date": "2026-09-15", "evaluated_on": today.isoformat()}
