# Security

LeakyBucket is a security inspection component. Applications remain responsible
for enforcing decisions, authenticating actors, authorizing access, isolating
tenants, and constraining execution and network access.

Known evaluation gaps are recorded in [docs/EVALUATION.md](docs/EVALUATION.md).
Deployment boundaries are documented in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).
Do not treat pattern matches or passing tests as a guarantee of safe model behavior.

## Reporting vulnerabilities

Use GitHub's private vulnerability reporting for this repository when available.
Include the affected revision, inspected path, expected decision, actual result,
and a minimal reproduction using synthetic data. Do not put credentials or
private user content in public issues. If private reporting is unavailable,
request a private reporting channel without publishing exploit details.
