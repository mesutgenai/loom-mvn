# LOOM Stability Policy (0.x)

This document defines compatibility expectations for the current pre-1.0 lifecycle.

## Versioning Model

LOOM uses `0.MINOR.PATCH`.

- `PATCH`: bug fixes, security fixes, and additive non-breaking updates.
- `MINOR`: may include breaking changes when necessary, with migration notes.

## Core Compatibility Commitments

Within a given minor line (for example `0.2.x`), maintainers target compatibility for:

- Protocol envelope/signature/canonicalization behavior captured by conformance vectors.
- Existing endpoint behavior unless explicitly documented as experimental.
- Persisted data import/restore from prior patch releases in the same minor line.

## Experimental Surface

The following are explicitly lower-stability surfaces during `0.x`:

- Wire-level legacy gateway parity behavior.
- Newly introduced admin/ops extensions not yet covered by conformance vectors.

Experimental behavior may change faster and may not receive long deprecation windows.

## Deprecation Policy

When deprecating stable behavior:

- Document deprecation in `CHANGELOG.md`.
- Add replacement guidance.
- Keep old behavior for at least 2 patch releases or 30 days (whichever is longer), unless security risk requires faster removal.

## Breaking Changes

Breaking changes should:

- Land on minor version bumps (`0.x -> 0.(x+1)`), except emergency security changes.
- Include migration notes in `CHANGELOG.md`.
- Update `docs/CONFORMANCE.md` and tests when protocol behavior changes.
