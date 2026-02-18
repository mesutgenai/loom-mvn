# LOOM Open-Source Strategy

## Open Core

This repository keeps the protocol and reference node fully open under Apache-2.0, including:

- Protocol specifications.
- Conformance vectors and interoperability tests.
- Reference implementation and operational hardening baseline.

## Product Differentiation Outside The Repo

Commercial/hosted differentiation can be built in operations, not protocol lock-in, for example:

- Managed federation operations.
- Compliance and audit workflows.
- Advanced monitoring/alerting and SRE tooling.
- Enterprise controls, onboarding, and support services.

## Specs As Product Surface

The primary trust surface for adopters is:

- Normative protocol docs.
- Conformance vectors.
- Clear compatibility and release policies.

For this reason, protocol behavior changes should be documented and tested as first-class deliverables.

## Distribution

The repository is open source, while npm publish is intentionally disabled (`"private": true`) to prevent accidental package publication until a stable package distribution plan is defined.
