# Release Gate Evidence (Local Runtime)

- Timestamp (UTC): 
  - 20260218T134331Z
- Result:
  - PASS
- Gate command:
  -     npm run gate:release -- --env-file /tmp/loom-gate-20260218T134331Z-k6jg/gate.env --base-url http://127.0.0.1:8787 --admin-token <redacted> --bootstrap-audit-token
- Local runtime:
  - base_url: http://127.0.0.1:8787
  - postgres_url: postgresql://loom@127.0.0.1:55432/loom

## Evidence Artifacts

- Release gate raw log:
  - ops/releases/gates/20260218T134331Z-gate-release-local.log
- Federation interop matrix report:
  - scripts/output/federation-interop-matrix/interop-matrix-20260218T134337Z/report.json
- Federation interop matrix summary:
  - scripts/output/federation-interop-matrix/interop-matrix-20260218T134337Z/summary.md
- Compliance drill output directory:
  - scripts/output/compliance-drills/compliance-20260218T134339Z
- LOOM server runtime log:
  - ops/releases/gates/20260218T134331Z-loom-runtime.log
- PostgreSQL runtime log:
  - ops/releases/gates/20260218T134331Z-postgres-runtime.log

## Notes

- Runtime stack was created in an ephemeral temp directory:
  - /tmp/loom-gate-20260218T134331Z-k6jg
- Cleanup (server + postgres) runs automatically at script exit.
