# Security checks and permissions

[Back to AWSherlock](../README.md)

AWSherlock implements 28 configuration checks across seven services. The following
sections describe required read permissions and the limits of each detection.

## S3 scanner

```bash
awsherlock scan --services s3
awsherlock scan --profile production --services s3
awsherlock scan --role arn:aws:iam::123456789012:role/AWSherlockAuditRole --services s3
```

Service names can be combined, for example `--services iam,s3`. The S3 collector lists general-purpose
buckets with pagination, resolves each region, and reads five configurations
through the shared session. Each setting is read once per bucket; regional clients
are reused. Required read permissions:

- `s3:ListAllMyBuckets`
- `s3:GetBucketLocation`
- `s3:GetBucketPublicAccessBlock`
- `s3:GetEncryptionConfiguration`
- `s3:GetBucketVersioning`
- `s3:GetBucketLogging`
- `s3:GetBucketPolicyStatus`

| Check | Finding trigger | Severity |
| --- | --- | --- |
| AWSH-S3-001 | Bucket Block Public Access absent or not fully enabled | MEDIUM |
| AWSH-S3-002 | Default encryption absent or algorithm unrecognized | LOW |
| AWSH-S3-003 | Versioning absent or suspended | MEDIUM |
| AWSH-S3-004 | Server access logging destination absent | LOW |
| AWSH-S3-005 | S3 classifies the bucket policy as public (`IsPublic=true`) | HIGH |

Encryption accepts SSE-S3 (`AES256`), SSE-KMS, and DSSE-KMS, including the AWS-managed
KMS default without an explicit key ID. A missing configuration finding does not
mean objects are unencrypted: [S3 encrypts new uploads automatically](https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html).
Existing object encryption and KMS key usability are not inspected.

The policy check uses [S3 GetBucketPolicyStatus](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicyStatus.html)
instead of downloading or interpreting policy documents. It detects S3's public
policy classification, not every unsafe policy or effective access path. No policy
is a valid absence, distinct from an unreadable policy. Logging checks configuration,
not delivery success or alternative CloudTrail coverage.

`AWSH-S3-001` produces a MEDIUM finding when the bucket configuration is absent
or any of its four safeguards is disabled. This identifies potential exposure;
it does not prove anonymous access. Account-level controls, policy documents,
ACLs, access points, and object access are not evaluated. AWS applies the
[most restrictive applicable Block Public Access settings](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetPublicAccessBlock.html).

Missing configuration is distinct from AccessDenied. Failed or malformed reads
are shown as errors; other checks on the same bucket and remaining buckets continue.
Only checks with successfully collected facts run. Coverage is COMPLETE, PARTIAL,
ACCESS_DENIED, ERROR or NOT_SCANNED; the evaluated check count is displayed.
Errors exit with code 1; completed evaluations exit with code 0 even when findings
exist. Directory buckets are not supported. No settings are changed and no objects
are downloaded.

### IAM scanner

`awsherlock scan --services iam` runs six IAM configuration checks: directly
attached AWS AdministratorAccess, wildcard/complement Allow actions, wildcard/
complement Allow resources, console users without MFA, active keys older than 90
days, and active keys unused for more than 90 days (including never-used keys).
Key IDs are used transiently for API requests and excluded from collected data.

Managed policies use the default version; inline policies are included. IAM is
global and scanned once. Group attachments are reported on the group. Policy
checks are risk indicators, not effective-permission simulation: conditions,
explicit denies, boundaries, and SCPs may restrict access. Wildcard resources
are necessary for some actions. Stale passwords/root credentials are not checked.

Required reads: `iam:GetAccountAuthorizationDetails`, `iam:GetLoginProfile`,
`iam:ListMFADevices`, `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed`.

### EC2 scanner

`awsherlock scan --services ec2` scans the SDK-configured region (configure
`AWS_DEFAULT_REGION` or your profile region). It checks internet-wide SSH, RDP,
and common database ports; IMDSv1; public IPv4/global IPv6 addresses; and EBS
encryption. IPv4/IPv6 CIDRs, port ranges, and protocol -1 are supported. SSH uses
TCP; RDP/database checks include TCP/UDP. Database ports: 1433, 1521, 3306, 5432,
6379, 9042, 9200, 27017. Routing, NACLs, and application exposure are not assessed.
Required reads: `ec2:DescribeSecurityGroups`, `ec2:DescribeInstances`,
`ec2:DescribeVolumes`. Missing region or permissions are visible errors.

### Lambda and Secrets Manager

Use `--services lambda,secretsmanager` in the configured region. Lambda checks
unauthenticated function URLs (including aliases), directly attached AWS
AdministratorAccess/PowerUserAccess execution policies, and deprecated managed
runtimes. Custom/inline role policies require IAM review; URL resource policies
and effective access are not evaluated. Container images and unknown runtimes
produce incomplete coverage. The runtime catalogue is dated 2026-09-15 and must
be maintained against [AWS runtime dates](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html).

Secrets Manager checks rotation, broad Allow principals (including conditional
statements, requiring review), and non-enabled custom KMS keys. Default
aws/secretsmanager encryption is accepted. Conditions and denies are not simulated.
No secret values, function code, or environment variable values enter scan data.

Required reads: `lambda:ListFunctions`, `lambda:ListFunctionUrlConfigs`,
`iam:ListAttachedRolePolicies`, `secretsmanager:ListSecrets`,
`secretsmanager:GetResourcePolicy`, and `kms:DescribeKey` for custom secret keys.

### CloudTrail and KMS

Use `--services cloudtrail,kms`. CloudTrail includes organization and shadow trails,
reads status in the home region, and checks for a usable trail visible in the
configured region, multi-region/global-event settings, and log file validation.
No logging/delivery errors trigger review; this does not inspect event selectors,
CloudTrail Lake, log contents, or every region. Permission failures leave availability
unknown. Requires `cloudtrail:DescribeTrails` and `cloudtrail:GetTrailStatus`.

KMS checks automatic rotation of enabled customer-managed symmetric encryption
keys with AWS_KMS origin, plus broad Allow principals in customer key policies.
AWS-managed, imported, asymmetric, and disabled keys are outside automatic rotation
scope. Standard root delegation and `Resource: "*"` alone do not trigger the policy
check. Conditions/denies may restrict broad statements. Requires `kms:ListKeys`,
`kms:DescribeKey`, `kms:GetKeyRotationStatus`, `kms:GetKeyPolicy`. No key material
or decrypted data is requested.
