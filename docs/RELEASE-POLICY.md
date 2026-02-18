# LOOM Release Policy

## Cadence

Target release rhythm:

- Patch releases (`0.x.P`): every 1-2 weeks as needed.
- Minor releases (`0.X.0`): every 4-8 weeks when feature scope is ready.
- Security releases: out-of-band when required by severity.

Cadence is a target, not a hard guarantee.

## Release Types

- Patch: fixes, hardening, docs, and additive safe improvements.
- Minor: larger capability additions and approved breaking changes with migration notes.

## Quality Gates

Before release:

- CI passes.
- Conformance vectors pass (`npm test`).
- `CHANGELOG.md` is updated with user-visible changes.
- Security-impacting changes are documented and linked to policy updates when needed.

## Security Patch SLAs

SLA targets from confirmed triage date:

- Critical: mitigation/patch in 72 hours.
- High: mitigation/patch in 7 calendar days.
- Medium/Low: next scheduled patch release (target within 30 days).

See `SECURITY.md` for reporting and response process.

## Support Window

Maintainers focus active fixes on:

- `main` (current development line).
- Most recent tagged release in the current minor series.
