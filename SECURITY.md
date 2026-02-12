# Security Policy

## Supported Versions
SuperSCP is currently maintained on the latest commit in the default branch.

## Reporting a Vulnerability
Please do not open public issues for potential security vulnerabilities.

Instead, report privately to the repository owner with:
- A clear description of the issue.
- Steps to reproduce.
- Potential impact.
- Any proof-of-concept details (if available).

If contact details are not yet published, open an issue that only requests a private contact channel (without technical vulnerability details).

## Response Expectations
- Initial acknowledgment target: within 5 business days.
- Triage and severity assessment after reproduction.
- Fix timeline depends on impact and complexity.

## Disclosure
Please allow reasonable time for validation and remediation before public disclosure.

## Hardening Guidance
For users running SuperSCP in production workflows:
- Use dedicated SSH keys and least-privilege remote accounts.
- Use `--fail-cancel-threshold` to reduce risk of repeated bad-auth attempts.
- Prefer explicit host verification and secure SSH config settings.
