# LOOM Request Tracing

This runbook is the implementation artifact for `P1-01` in `docs/PRODUCTION-READINESS.md`.

## Objective

Correlate API requests, outbox worker processing, and federation/email/webhook delivery outcomes through stable trace identifiers.

## Trace Fields

- `x-loom-request-id`: response header returned on every HTTP request.
- `request_id`: request log field (same value as `x-loom-request-id`).
- `trace_id`: generic trace key used by API and worker contexts.
- `source_request_id`: original API request that queued an outbox item.
- `source_trace_id`: originating trace for outbox-derived events.

## Runtime Behavior

1. API handler accepts incoming trace headers (`x-loom-request-id`, `x-request-id`, `x-correlation-id`) when valid; otherwise generates `req_<uuid>`.
2. Trace context is propagated into audit entries automatically.
3. Outbox queue items persist `source_request_id` + `source_trace_id`.
4. Worker loops run with dedicated worker trace IDs and emit structured batch logs with:
   - `trace_id`
   - `outbox_ids`
   - `source_request_ids`
   - `source_trace_ids`

## Recommended Config

```bash
LOOM_REQUEST_LOG_ENABLED=true
LOOM_REQUEST_LOG_FORMAT=json
```

## Verification

Static + optional runtime checks:

```bash
npm run check:tracing -- --env-file .env.production.example
npm run check:tracing -- --base-url http://127.0.0.1:8787
```

Quick manual probe:

```bash
curl -i http://127.0.0.1:8787/health \
  -H "x-request-id: trace-demo-001"
```

Expected:

- response includes `x-loom-request-id: trace-demo-001`
- request log includes `request_id":"trace-demo-001"`

## Evidence For P1-01

- `docs/REQUEST-TRACING.md`
- `npm run check:tracing` output
- request log sample showing API `request_id`
- worker log sample showing `worker.batch.processed` with `source_request_ids`
