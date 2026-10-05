# 0016 - Browser-session authentication

## Status

Accepted.

## Context

As of October 2026, Monarch no longer accepts programmatic password login through `POST /auth/login/`:

- Without current web-client identification, it returns `403 {"detail": "Please update to the latest version of the app to continue login."}`.
- With current web-client identification, Monarch's Cloudflare edge returns error `1010` ("blocked access based on your browser's signature").

The web app now logs in through `POST /auth/web/login/`, which runs behind Cloudflare's in-browser bot detection and establishes a cookie session (`session_id`, `csrftoken`) instead of returning a long-lived API token. GraphQL accepts that session in place of `Authorization: Token`.

A non-browser client was verified on 2026-10-05 to make authenticated GraphQL requests with only:

- the `session_id` and `csrftoken` cookies;
- `X-CSRFToken` equal to `csrftoken`;
- `Origin: https://app.monarch.com`;
- `Client-Platform: web`.

No device UUID, `Monarch-Client`/`Monarch-Client-Version` header, browser `User-Agent`, Cloudflare cookie, or other browser cookie was needed.

Other maintained Monarch clients reached the same point and import a session from the user's browser. Several of them persist every pasted cookie, including Cloudflare's `cf_clearance`.

## Decision

- Authentication is applied to requests in one place: the `graphql.Credentials` interface. `TokenAuth` sends `Authorization: Token`. `SessionAuth` sends the two cookies, `X-CSRFToken`, and `Origin`.
  - The GraphQL client and the REST upload endpoints both call `ApplyAuth`; no command knows which kind of credentials it runs with.
- `SessionAuth` attaches cookies only to `https://api.monarch.com`, so a misconfigured endpoint never receives them. Redirects remain rejected.
- `monarch auth import-session` stores a session the user established by logging into Monarch normally in their own browser.
  - The CLI never performs that login. It never reads browser cookie stores. It does not attempt to pass Cloudflare or CAPTCHA checks.
  - Secrets are read from hidden prompts or stdin, never from flags.
  - Only `session_id` and `csrftoken` are kept; a pasted `Cookie` header is reduced to those two locally and the rest is discarded.
  - The session is validated with the read-only `GetIdentity` query before it is saved, and an invalid session is never persisted.
- The session file stores `auth_method: "browser_session"` with `session_id` and `csrf_token`, under the same `0600` and `env:NAME` contract as the token (ADR-0006). A session without `auth_method` is a legacy token session and keeps working.
- No device identifier is stored or sent, because the verified minimum does not need one.
- A GraphQL `403` is split:
  - Monarch's own JSON rejection (missing or expired session, failed CSRF check) maps to `AUTH_SESSION_EXPIRED`.
  - The edge's browser-signature block (error `1010`, or a Cloudflare page) maps to `API_ERROR` and is never reported as an expired session or MFA.
  - Neither is retried.
- `monarch auth logout` deletes only the local session. The imported session belongs to the user's browser login; revoking it server-side would also log the browser out, so revocation stays with the browser.
- `auth status` reports `auth_method`. This is an additive JSON field.

## Consequences

### Positive

- Every data command works again without code changes in the domain layer.
- The stored state is the proven minimum. Nothing tied to the browser's fingerprint or Cloudflare clearance is persisted.
- Legacy token sessions continue to work, so existing users and `env:NAME` setups are unaffected.

### Negative

- Sessions expire on Monarch's schedule, which the CLI cannot read at import. The user re-imports after logging into the browser again; expiry surfaces as `AUTH_SESSION_EXPIRED` with that instruction.
- Logging out of Monarch in the browser invalidates the CLI session too.
- `auth login` is kept but currently fails against Monarch. Its errors say so instead of asking for an MFA code (see `docs/auth.md`).
- The verified request used curl's `User-Agent`. The CLI still sends the desktop-Chrome `User-Agent` from ADR-0001. If Monarch's edge rejects that combination, import validation fails visibly and nothing is saved.
