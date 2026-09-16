# Synthetic offline demo

All identifiers and facts here were invented. Account `000000000000` is a
placeholder and `203.0.113.10` is a documentation address; this is not an AWS scan.

`demo-snapshot.json` demonstrates S3 and EC2 configuration findings, an empty IAM
inventory and an S3 permission failure. Offline scanning deliberately exits with
code 1 because coverage is incomplete, while producing useful findings.

```bash
awsherlock scan examples/demo-snapshot.json
awsherlock scan examples/demo-snapshot.json --output json
awsherlock scan examples/demo-snapshot.json --output html --report-file demo.html
```

`demo-report.json` and `demo-report.html` are generated examples. Open the HTML
locally to try search, filters, sorting and coverage details without internet.
