# Security Policy

## Supported Versions

Security fixes are currently applied to:

- Latest code on `main` (current `0.2.x` development line).
- Most recent tagged release in `0.2.x` when a hotfix can be safely backported.

## Reporting A Vulnerability

Please report security issues privately through GitHub Security Advisories:

- Go to `Security` -> `Advisories` -> `Report a vulnerability` in this repository.

If private advisory reporting is unavailable, open a minimal GitHub issue without exploit details and request a private contact channel.

## What To Include

- Affected endpoint/module and version/commit.
- Reproduction steps (request samples, payloads, configuration).
- Security impact (confidentiality, integrity, availability).
- Any suggested mitigation.

## Response Targets

- Initial triage response target: 3 business days.
- Status update target: within 7 business days after triage.
- Fix target by severity (from confirmed triage date):
  - Critical: patch or mitigation within 72 hours.
  - High: patch or mitigation within 7 calendar days.
  - Medium/Low: next scheduled patch release (target within 30 days).

## Scope Notes

- Do not test against infrastructure you do not own or have permission to assess.
- Avoid destructive testing in shared/public environments.
