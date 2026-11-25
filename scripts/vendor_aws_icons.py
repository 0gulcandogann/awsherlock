"""Regenerate the inline AWS service glyph symbols in the report template.

Usage: python scripts/vendor_aws_icons.py PATH/TO/aws-icons/icons/architecture-service

Source: the MIT-licensed `aws-icons` npm package, which redistributes the AWS
Architecture Icons. The icon artwork belongs to Amazon Web Services; see
docs/third-party-notices.md. Only symbols whose id is listed below are replaced.
"""

import re
import sys
from pathlib import Path

ICONS = {
    "lambda": "AWSLambda",
    "ec2": "AmazonEC2",
    "s3": "AmazonSimpleStorageService",
    "iam": "AWSIdentityandAccessManagement",
    "secretsmanager": "AWSSecretsManager",
    "kms": "AWSKeyManagementService",
    "rds": "AmazonRDS",
    "dynamodb": "AmazonDynamoDB",
    "bedrock": "AmazonBedrock",
    "cloudtrail": "AWSCloudTrail",
    "guardduty": "AmazonGuardDuty",
}
TEMPLATE = Path(__file__).resolve().parents[1] / "src/awsherlock/templates/contextual.html"


def symbol(name: str, source: Path) -> str:
    text = source.read_text(encoding="utf-8").strip()
    text = re.sub(r"<title>.*?</title>", "", text, flags=re.S)
    if re.search(r"<(script|style|image|defs)|\bid=|href=|\bon\w+=", text):
        raise SystemExit(f"{source.name}: unexpected markup; review before vendoring")
    match = re.fullmatch(r'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">(.*)</svg>', text, re.S)
    if not match:
        raise SystemExit(f"{source.name}: unexpected SVG envelope")
    return f'<symbol id="ic-{name}" viewBox="0 0 64 64">{match.group(1)}</symbol>'


def main(folder: Path) -> None:
    html = TEMPLATE.read_text(encoding="utf-8")
    for name, stem in ICONS.items():
        pattern = re.compile(rf'<symbol id="ic-{name}" viewBox="0 0 (?:24|64) (?:24|64)">.*?</symbol>', re.S)
        if not pattern.search(html):
            raise SystemExit(f"symbol ic-{name} not found in template")
        html = pattern.sub(lambda _: symbol(name, folder / f"{stem}.svg"), html, count=1)
    TEMPLATE.write_text(html, encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
