# LOOM Wire IMAP Compatibility Matrix

This document is the implementation artifact for `P2-02` in `docs/PRODUCTION-READINESS.md`.

## Target Profile

LOOM targets practical IMAP interoperability for common mailbox clients using a focused compatibility profile:

- mailbox discovery and selection
- read/search/fetch of message content
- mailbox-state mutation (`\Seen`, `\Flagged`, `\Deleted`)
- move/archive/trash flows without multi-folder copy semantics
- secure auth with STARTTLS and token-backed login

## Command Coverage

| Command / Extension | Status | Notes |
| --- | --- | --- |
| `CAPABILITY` | Supported | Advertises `IMAP4rev1`, `UIDPLUS`, `NAMESPACE`, `ID`, `IDLE`, `MOVE`, `UNSELECT`, auth/starttls capabilities. |
| `LOGIN`, `AUTHENTICATE PLAIN` | Supported | Token-backed auth model. |
| `STARTTLS` | Supported | Required in secure-auth mode before login. |
| `NAMESPACE`, `ID` | Supported | Basic interoperability metadata responses. |
| `LIST`, `LSUB`, `XLIST` | Supported | Folder enumeration with LOOM folder aliases. |
| `STATUS` | Supported | `MESSAGES`, `UNSEEN`, `UIDNEXT`, `UIDVALIDITY`, `RECENT`. |
| `SELECT`, `EXAMINE` | Supported | Read-write and read-only selection modes. |
| `CHECK`, `NOOP`, `LOGOUT` | Supported | Standard control commands. |
| `SEARCH`, `UID SEARCH` | Supported | Core criteria plus boolean composition (`OR`, `NOT`) with grouped expressions (`(...)`). Parser remains permissive for unknown tokens. |
| `FETCH`, `UID FETCH` | Supported | Sectioned body/header fetches supported. |
| `STORE`, `UID STORE` | Supported | `\Seen`, `\Flagged`, `\Deleted` mutation semantics. |
| `MOVE`, `UID MOVE` | Supported | Maps to LOOM mailbox state transitions. |
| `IDLE` | Supported | `DONE` terminates IDLE as expected. |
| `APPEND` | Supported | Inline message data and IMAP literal continuation mode (`{n}`) are supported. |
| `EXPUNGE`, `UID EXPUNGE` | Partial | Accepted for compatibility; LOOM applies mailbox-state changes eagerly, so expunge is effectively a no-op. |
| `COPY`, `UID COPY` | Not Supported | Explicitly rejected to preserve single effective-folder mailbox model. |
| `UID THREAD` | Supported | `REFERENCES` and `ORDEREDSUBJECT` algorithms; unsupported algorithms/charsets are rejected. |
| `UID SORT` | Supported | Standard sort keys with `US-ASCII`/`UTF-8` charset handling. |

## Known Intentional Limitations

- single effective folder per participant/thread prevents full IMAP `COPY` parity
- non-`UID` `THREAD`/`SORT` commands are outside the current compatibility profile
- many RFC3501 criteria tokens are accepted permissively but not all map to full mailbox semantics yet

## Validation

- coverage and behavior are validated by `test/wire_gateway.test.js`
- run with:

```bash
npm test -- test/wire_gateway.test.js
```
