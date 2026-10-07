# 0017 - Confirmed transaction deletion

## Status

Accepted.

## Context

`transactions delete` sends `Common_DeleteTransactionMutation`, whose payload has `deleted` and `errors`. The command used to report `{"status":"deleted"}` whenever the GraphQL request succeeded. It never checked `deleted` and ignored `errors`, so a response saying the transaction was **not** deleted was still reported as a deletion.

A caller that keeps an audit trail of deletions (household-finance SPEC-003) needs three cases kept apart:

- the deletion was confirmed;
- the deletion was definitively rejected;
- the outcome is unknown.

## Decision

- **Success** only when `deleteTransaction.deleted` is the boolean `true` and `deleteTransaction.errors` is absent, `null` or empty. The success data is `{"status":"deleted","deleted":true,"transaction_id":"<id>"}`.
- **`DELETE_REJECTED`** (exit 11) only when the payload is well formed and `deleted` is the boolean `false`, with or without payload `errors`. This is definitive: the transaction was not deleted.
- **`DELETE_UNCONFIRMED`** (exit 12) for every other response that does not prove the outcome:
  - `deleted: true` together with payload errors;
  - a missing or non-boolean `deleted`;
  - a missing `deleteTransaction` payload;
  - malformed `errors`.
- Transport and GraphQL top-level failures keep their existing codes, which are never definitive.
- `CONFIRMATION_REQUIRED` and `READ_ONLY_VIOLATION` are raised locally by the safety check, before any request is made.
- `transactions delete --dry-run` is rendered locally, before the safety check, and never creates a client or sends a request. It is therefore permitted in read-only mode, so a caller can keep `MONARCH_READONLY` set for every non-destructive invocation. Every other command keeps the general rule that read-only takes precedence over dry-run.

## Consequences

- No delete is reported as successful unless Monarch said so.
- Callers can record a definitive failure only for `DELETE_REJECTED` (or the local safety codes). They must treat `DELETE_UNCONFIRMED` and network errors as unknown outcomes and verify state independently.
- Contract tests pin every case: `internal/monarch/delete_confirmation_test.go` and `internal/cli/transactions_delete_confirmation_test.go`.
