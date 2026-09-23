# Real-AWS validation matrix

[README](../README.md) · [Pilot procedure](pilot.md) · [Checks and permissions](../README.md#checks-and-permissions)

Prepared 2026-09-17 from the local collectors, rules, snapshot fact allowlist and
evaluation pipeline. There are 36 registered checks: 29 default, six opt-in
IAM governance checks and one opt-in RDS check. This is a validation contract, not live validation evidence.
All 36 checks currently have real-AWS status **UNTESTED**. Mocked tests and the
historical LocalStack exercise do not change that status.

In the tables, positive means the named check produces a finding on the selected
resource; negative means it produces no finding after its applicable facts were
successfully evaluated. Negative does not mean the resource/account is secure.
Inspect snapshot facts as well as finding evidence: findings usually contain only
the matching subset. Evidence identity is check ID + account + region + resource
ID/ARN; access-key resources use sanitized user/key ordinals, never key IDs.

## Permission bundles

Every row requires its service discovery bundle plus the listed detail reads.
These are actions used by the current collector, not a deployable least-privilege
policy. Resource restrictions, trust, SCPs, boundaries and explicit denies can
still block reads. Check selection restricts evaluation, not collection, so
`--checks` does not reduce the collector's permission requirements.

| Bundle | Required discovery/read actions |
| --- | --- |
| S3 | `s3:ListAllMyBuckets`, `s3:GetBucketLocation`; account context also reads `s3:GetAccountPublicAccessBlock` once per collection using S3 Control GetPublicAccessBlock |
| IAM | `iam:GetAccountAuthorizationDetails`; default IAM collection also reads `iam:GetLoginProfile`, `iam:ListMFADevices`, `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed` |
| EC2 | `ec2:DescribeSecurityGroups`, `ec2:DescribeInstances`, `ec2:DescribeVolumes` |
| Lambda | `lambda:ListFunctions` |
| Secrets | `secretsmanager:ListSecrets` |
| CloudTrail | `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`, `cloudtrail:GetEventSelectors`; detail reads use the trail home region |
| KMS | `kms:ListKeys`, `kms:DescribeKey` |
| RDS (opt-in) | `rds:DescribeDBSnapshots`, `rds:DescribeDBSnapshotAttributes`, `rds:DescribeDBClusterSnapshots`, `rds:DescribeDBClusterSnapshotAttributes` |
| Governance | IAM bundle; `iam:ListRoleTags`, `iam:ListUserTags` when tags are absent from authorization details; `iam:GetPolicy`, `iam:GetPolicyVersion` for unresolved managed-policy joins; workload context uses `lambda:ListFunctions`, `ec2:DescribeInstances`, `iam:GetInstanceProfile` |

Single-account authentication resolves `sts:GetCallerIdentity`; cross-account
access requires `sts:AssumeRole` and role trust. Organization discovery uses
`organizations:ListAccounts`; `--ous` additionally uses paginated
`organizations:ListChildren`. These are scope prerequisites, not security checks.

## S3 — bucket configuration

| Check | Finding trigger / evidence | Detail permission | Positive / negative pilot pair | Detection limit |
| --- | --- | --- | --- | --- |
| AWSH-S3-001 | Missing/incomplete `public_access_block`; account and combined safeguards included when known | `s3:GetBucketPublicAccessBlock` | Any bucket flag false or absent / all four bucket flags true. Also verify incomplete bucket with all account flags true still produces the bucket finding, with combined flags true | Bucket safeguard indicator; logical OR combines account/bucket flags. Does not prove anonymous access; ACLs/access points/object requests are not inspected |
| AWSH-S3-002 | `encryption` absent or contains an unrecognized algorithm | `s3:GetEncryptionConfiguration` | Absent default or unknown algorithm / AES256, aws:kms or aws:kms:dsse | AWS automatic upload encryption does not establish existing object encryption or key usability. If AWS cannot supply the positive configuration, record that scenario untested; synthetic evidence is separate |
| AWSH-S3-003 | `versioning` is not Enabled | `s3:GetBucketVersioning` | Absent or Suspended / Enabled | Configuration only; retention/recovery is not tested |
| AWSH-S3-004 | `logging` has no destination | `s3:GetBucketLogging` | No destination / configured destination | No delivery verification or alternative logging evaluation |
| AWSH-S3-005 | `policy_public` is true | `s3:GetBucketPolicyStatus` | IsPublic true / false or confirmed NoSuchBucketPolicy | AWS policy classification; no downloaded policy analysis or effective-access proof |

## IAM — default configuration

| Check | Finding trigger / evidence | Detail permission beyond IAM bundle | Positive / negative pilot pair | Detection limit |
| --- | --- | --- | --- | --- |
| AWSH-IAM-001 | `attached` contains AWS-managed AdministratorAccess | None | Direct AdministratorAccess attachment / task-specific policy | Direct attachments; group findings are on groups by default. No effective-permission simulation |
| AWSH-IAM-002 | Allow `statements` contain wildcard (* or ?) actions or NotAction | None | Allow s3:* or NotAction / exact Allow action | Conditions, denies, boundaries and SCPs are not simulated; default managed-policy version and inline policies |
| AWSH-IAM-003 | Allow `statements` contain wildcard resources or NotResource | None | Allow Resource * or NotResource / exact supported resource ARN | Some actions require wildcard resources; review indicator |
| AWSH-IAM-004 | `console_mfa`: console profile exists and no MFA device | `iam:GetLoginProfile`, `iam:ListMFADevices` | Console user without MFA / registered MFA or no login profile | IAM users only; root and federated/SSO MFA are not assessed |
| AWSH-IAM-005 | `key_age`: active key older than 90 days | `iam:ListAccessKeys` | Active key age 91 days / age 90 days or inactive | Age at collection; no credential material exported; cannot accelerate real AWS age with a mocked clock |
| AWSH-IAM-006 | `key_stale`: active key unused over 90 days; never-used key uses creation age | `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed` | Last use 91 days ago or never-used age 91 / last use or never-used age at most 90 | Metadata review indicator; inactive keys skipped, no proof that retirement is safe |

## EC2 — regional configuration

| Check | Finding trigger / evidence | Detail permission (in EC2 bundle) | Positive / negative pilot pair | Detection limit |
| --- | --- | --- | --- | --- |
| AWSH-EC2-001 | `ingress` allows internet-wide TCP SSH 22 or all protocols | `ec2:DescribeSecurityGroups` | TCP 22 from 0.0.0.0/0, then ::/0 / restricted CIDR or no port 22 | Port ranges supported; no routing/NACL/application reachability test |
| AWSH-EC2-002 | `ingress` allows internet-wide TCP/UDP RDP 3389 or all protocols | `ec2:DescribeSecurityGroups` | TCP/UDP 3389 from either internet-wide CIDR / restricted CIDR | Configuration only; verify protocol -1 and ranges separately |
| AWSH-EC2-003 | Internet-wide `ingress` includes database ports 1433,1521,3306,5432,6379,9042,9200,27017 | `ec2:DescribeSecurityGroups` | TCP/UDP range including 5432 from internet / private CIDR or range excluding listed ports | Fixed port list; does not identify running databases |
| AWSH-EC2-004 | `metadata`: endpoint enabled and tokens optional | `ec2:DescribeInstances` | HttpEndpoint enabled + HttpTokens optional / tokens required or endpoint disabled | Metadata configuration; no SSRF/exploit verification |
| AWSH-EC2-005 | Nonempty `addresses` with public IPv4/global IPv6 | `ec2:DescribeInstances` | Public IPv4 or global IPv6 / no public addresses | Address assignment does not prove ingress reachability |
| AWSH-EC2-006 | `encrypted` is false | `ec2:DescribeVolumes` | Unencrypted volume / encrypted volume | Volume configuration; key permissions, snapshots and guest data not inspected |

## Lambda and Secrets Manager — regional configuration

| Check | Finding trigger / evidence | Detail permission | Positive / negative pilot pair | Detection limit |
| --- | --- | --- | --- | --- |
| AWSH-LAMBDA-001 | `urls` contains auth NONE | `lambda:ListFunctionUrlConfigs` + Lambda bundle | Unauthenticated URL, including alias / AWS_IAM URL or no URLs | Resource policies and actual invocation access not evaluated |
| AWSH-LAMBDA-002 | `role_policies` contains AWS-managed AdministratorAccess or PowerUserAccess | `iam:ListAttachedRolePolicies` + Lambda bundle | Execution role with either policy / task-specific attachment | Inline/custom policies require separate IAM review; no permission simulation |
| AWSH-LAMBDA-003 | `runtime` has deprecated true | Lambda bundle | Runtime deprecated in local catalogue on evaluation date / recognized nondeprecated runtime | Catalogue dated 2026-09-15; compare current AWS schedule independently. Images/unknown runtimes remain incomplete; do not create obsolete runtimes merely for the pilot |
| AWSH-SECRET-001 | `rotation` is false | Secrets bundle | Rotation disabled / enabled | No rotation execution or secret-value read |
| AWSH-SECRET-002 | Allow `policy` has broad principal | `secretsmanager:GetResourcePolicy` + Secrets bundle | Broad Allow principal / restricted principal or confirmed no policy | Conditions/denies not simulated; never retrieve secret values |
| AWSH-SECRET-003 | Custom-key `encryption` state is not Enabled | `kms:DescribeKey` + Secrets bundle | Custom key Disabled / Enabled or AWS-managed default | Key state only; no decrypt/permission test |

## CloudTrail and KMS — regional configuration

| Check | Finding trigger / evidence | Detail permission | Positive / negative pilot pair | Detection limit |
| --- | --- | --- | --- | --- |
| AWSH-CT-001 | Regional summary `usable_trail` false | CloudTrail bundle | No visible usable trail / logging trail without reported delivery error covering selected region and including management events | Summary resource uses account ID. Organization/shadow trails included; no Lake, actual delivery or retention proof. Unknown trail facts must not become a confirmed absence |
| AWSH-CT-002 | `trail_settings`: multi-region or global-service-event flag false | CloudTrail bundle | Either flag false / both true | Configuration per trail, not complete coverage of all regions |
| AWSH-CT-003 | `trail_settings`: LogFileValidationEnabled false | CloudTrail bundle | Validation disabled / enabled | No delivered-log integrity verification |
| AWSH-CT-004 | `management_events` false or known `management_excluded_sources` nonempty | CloudTrail bundle | Management events excluded, or supported KMS/RDS Data API source exclusions / management included with known empty source exclusions | Basic and supported advanced selectors only; read/write restrictions can remain. Unknown restrictive shapes remain partial; old positive facts without source context cannot complete evaluation |
| AWSH-KMS-001 | Eligible `rotation` has enabled false | `kms:GetKeyRotationStatus` + KMS bundle | Enabled customer-managed symmetric AWS_KMS encryption key with rotation off / rotation on | AWS-managed/imported/asymmetric/disabled keys outside automatic-rotation scope; absence of finding on excluded keys is not a tested negative |
| AWSH-KMS-002 | Customer-key Allow `policy` contains broad principal | `kms:GetKeyPolicy` + KMS bundle | Broad Allow principal / restricted principal or standard account-root delegation | Resource * alone does not trigger. Conditions/denies not simulated; AWS-managed policies skipped |

## RDS — opt-in public manual snapshot restore

Select `--services rds` and a region. This check reads account-owned manual DB-instance and Aurora/DB-cluster snapshots only. A public restore attribute is a configuration finding; no copy or data access is observed.

| Check ID | Positive | Reads | Positive / negative fixture | Limits |
| --- | --- | --- | --- | --- |
| AWSH-RDS-001 | `restore` attribute includes `all` | RDS bundle | Manual DB and cluster snapshot with `all` / each with private restore values | Missing attributes and denied reads are incomplete coverage, never PASS; automated/shared snapshots and general DB public access are outside scope |

## IAM — opt-in governance

Use `--identity-governance`; the last two checks require approval evidence from
`--identity-inventory`. Without it they are not approval PASS. Governance policy
joins enrich existing IAM policy checks instead of introducing duplicate rules.

| Check | Finding trigger / evidence | Required evidence/reads | Positive / negative pilot pair | Detection limit |
| --- | --- | --- | --- | --- |
| AWSH-IAM-007 | `identity_profile`: owner absent in tag and declaration | Governance bundle; optional inventory | Owner absent from both / nonblank Owner tag or inventory owner | Role/user convention, exact tag case; service-linked roles skipped. Metadata is not verified accountability |
| AWSH-IAM-008 | `identity_profile`: purpose absent in tag and declaration | Governance bundle; optional inventory | Purpose absent from both / nonblank Purpose tag or inventory purpose | Roles/users, service-linked roles skipped; declaration does not prove actual use |
| AWSH-IAM-009 | `identity_usage`: last use over 90 days or no record and creation over 90 days | Governance bundle; RoleLastUsed/CreateDate from authorization details | Role last used 91 days ago or no-record role age 91 / recent-use role or no-record role age at most 90 | Roles only, service-linked roles skipped; at most 400-day tracking window. Unknown tracking data stays unevaluated |
| AWSH-IAM-010 | Supported `identity_trust` broad true | Governance bundle; AssumeRolePolicyDocument | Supported wildcard trust or OIDC without exact audience/subject constraints / narrow supported trust | Roles only; unsupported conditions unknown, no effective trust simulation or AI inference |
| AWSH-IAM-011 | `identity_approval`: unregistered in complete account inventory | Governance bundle + version-1 exact-ARN inventory | Identity omitted from complete account list / exact registered identity | Partial/out-of-account inventory unknown; declarations are business assertions, not AWS authentication |
| AWSH-IAM-012 | `identity_approval`/trust mismatch or missing declared controls; optional observed unapproved caller | Governance bundle + inventory and supported trust; optional `cloudtrail:LookupEvents` | Trust principal outside approvals or required ExternalId/sourceIdentity condition missing / allowed principals and required controls present | Roles only; registered approval and supported trust required. Missing observations do not prove all callers approved; no raw events/control values exported |

Optional governance context reads: `cloudtrail:LookupEvents` for bounded regional
1–90-day history; `bedrock:ListAgents`, `bedrock:GetAgent`,
`bedrock-agentcore:ListAgentRuntimes`, `bedrock-agentcore:GetAgentRuntime` for
metadata role bindings; `access-analyzer:ListAnalyzers`,
`access-analyzer:ListFindings`, `access-analyzer:GetFinding` for existing analyzer
V2 evidence. Enable only with the corresponding CLI switches. This is context
for the six checks, not extra checks. Native bindings, declarations and observed
callers remain separate; external/shared application actors may remain unknown.

## Missing-data and orchestration scenarios (apply to every row)

1. Deny the row's detail read using an independently managed pilot role, or use a
   mocked fixture. Confirm an issue and incomplete coverage, no negative/PASS
   assertion for the absent fact, and surviving evaluations for known facts.
   A denied discovery read can hide unknown resources; not-scanned counts cannot
   enumerate them. This also applies to malformed responses and timeouts.
2. Remove the required fact in a sanitized synthetic snapshot: replay remains
   honest about missing evaluations. S3 missing account facts keep context partial
   even if bucket checks run; CT-004 positive facts need source context. Governance
   missing/incomplete inventory and unsupported trust must stay unevaluated.
3. Where paginated discovery exists, exercise multiple pages and later-page
   failure: known resources survive; unseen resources are not assumed safe.
   Track real-AWS pagination separately from mocked pagination evidence.
4. Evaluate the same saved collection live/offline with identical services,
   checks, resources and identity inventory. Compare findings, identities,
   coverage and summary; explain metadata differences, never suppress them blindly.
5. Select checks/resources and an unmatched resource; confirm exclusions and the
   unmatched selection coverage row remain visible. For organizations, exercise
   accounts/descendant OUs, their intersection and failed membership discovery
   preventing uncertain member-role assumptions. Verify account/region isolation.
6. Open standalone HTML with network disconnected. Confirm evidence, remediation,
   search/filter/sort and coverage remain understandable. Record reader answers:
   which resource, why flagged, what fact to verify, what next action?

Confirmed absence is not a failed read: NoSuchBucketPolicy, absent logging or no
login profile have specific valid meanings. Do not replace AccessDenied with
those absence values. Exit 0 means completed evaluation even with findings; exit
1 means incomplete/error, including intentional scope exclusions where reported.

## Pilot result ledger

Copy this record for each matrix ID and scenario, keeping all 36 IDs represented.
Initial status for every ID is UNTESTED; unavailable positive/negative scenarios
stay untested even if another scenario for that ID succeeds.

| Field | Record |
| --- | --- |
| Check ID, scenario, status | ID; positive/negative/denial/replay; UNTESTED / VERIFIED / MISMATCH |
| Scope and collection | Account alias, region, resource alias/type, UTC time, scan ID |
| Build and selection | Installed version, source commit, command, services/checks/resources, governance switches |
| Expected / observed | Expected named finding and facts / actual finding and evaluated coverage |
| Independent evidence | Read-only API/configuration export or reviewer observation, timestamp, artifact location |
| Artifacts | Restricted JSON, same-collection snapshot, replay JSON, HTML, hashes, inventory revision |
| Measurements | Elapsed time, resource/evaluated/not-scanned counts, permission issues, partial failures |
| Reader result | Resource/reason/verification/action answers; assistance required |
| Mismatch disposition | Explanation, issue reference, follow-up owner; untested scenario reason |

VERIFIED requires independent facts matching the observed result in the stated
scope. Another scanner agreeing is supporting evidence only. Never infer service
accuracy, a general security score or resolved risk from finding counts.

## Source and test references

Implementation: [catalog](../src/awsherlock/catalog.py),
[collectors](../src/awsherlock/collectors/), [rules](../src/awsherlock/rules/),
[snapshot facts](../src/awsherlock/snapshot.py), [evaluation](../src/awsherlock/evaluation.py).
Local ignored tests: test_s3_complete.py/test_s3_account.py, test_iam.py,
test_ec2.py, test_serverless.py, test_audit.py/test_cloudtrail_management.py,
test_identity.py/test_identity_integrations.py, test_collection_resilience.py,
test_resource_selection.py/test_ou_selection.py and test_report_browser.py.
They provide fixture evidence, not live-AWS verification.

AWS reference: [service authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/),
[Lambda runtime schedule](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html),
[RoleLastUsed](https://docs.aws.amazon.com/IAM/latest/APIReference/API_RoleLastUsed.html).
Recheck changing runtime dates and permissions during the pilot. The local catalogue
controls current scanner behavior; a documentation mismatch is recorded, not fixed
by silently expanding this documentation task.
