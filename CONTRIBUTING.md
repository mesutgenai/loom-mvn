# Contributing to LOOM

Thanks for contributing to LOOM.

## Scope

This repository maintains the open protocol and the reference Minimum Viable Node implementation. Managed operations offerings (for example hosted federation, compliance tooling, and advanced monitoring) are outside this repository.

## Ground Rules

- Be respectful and follow `CODE_OF_CONDUCT.md`.
- For larger or potentially breaking changes, open an issue first to align on approach.
- Keep pull requests focused and reviewable.

## Local Setup

Requirements:

- Node.js `>=22`
- npm

Commands:

```bash
npm ci
npm test
npm start
```

## What A Good Change Includes

- Tests that cover behavior changes.
- Changelog updates for user-visible behavior (`CHANGELOG.md`).
- Protocol/spec updates when protocol behavior changes:
  - `LOOM-Protocol-Spec-v1.1.md`
  - `docs/CONFORMANCE.md`
  - Conformance vectors in `test/conformance_vectors.test.js` where relevant.

## Compatibility Expectations

- Follow `docs/STABILITY.md` for `0.x` compatibility and deprecation rules.
- Prefer additive changes over breaking changes.
- If a breaking change is required, include migration notes and deprecation timeline.

## Pull Request Checklist

- `npm test` passes locally.
- New/changed behavior has tests.
- Docs are updated.
- Security-sensitive changes include threat/risk notes in the PR description.

## Reporting Security Issues

Do not open public exploit details. Follow `SECURITY.md`.

## Contributor License

By submitting a contribution, you agree the contribution is provided under the Apache License 2.0 in this repository (`LICENSE`), unless explicitly stated otherwise in writing before submission.
