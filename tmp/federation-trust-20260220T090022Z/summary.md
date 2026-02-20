# Federation Trust Freshness Drill

- Drill ID: `federation-trust-20260220T090022Z`
- Started: `2026-02-20T09:00:22.479Z`
- Finished: `2026-02-20T09:00:22.540Z`
- Local Base URL: `http://127.0.0.1:63748`
- Remote Base URL: `http://127.0.0.1:63747`
- Result: **FAIL**

## Verified Flow

- Public DNS bootstrap trust registration
- Remote trust epoch/keyset version rotation
- Single batch revalidation cycle trigger
- Freshness enforcement on signed federation delivery

- Report JSON: `/Users/mesut/Desktop/email++/tmp/federation-trust-20260220T090022Z/report.json`
- Failure: `Fresh trust epoch delivery failed (expected HTTP 202, got 400)`
