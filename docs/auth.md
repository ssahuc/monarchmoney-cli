# Authentication & Session Management

`monarchmoney-cli` uses the unofficial Monarch Money API. It handles authentication, MFA, and session persistence locally and securely.

## Authentication Flow

### Standard Login
Run the following command to start the interactive login process:
```bash
monarch auth login
```
You will be prompted for your email and password.
After login completes, the CLI prints the account email, the login timestamp, and the local session file path so you can confirm exactly which account was stored.

### MFA Support
If your account has Multi-Factor Authentication enabled:
1. The CLI will detect the requirement and prompt you for the 6-digit code interactively.
2. Alternatively, you can provide the code via the `--mfa-code` flag.

**Automatic MFA:**
If you have your TOTP secret key, you can automate the process:
```bash
monarch auth login --email user@example.com --password "..." --mfa-secret "YOUR_SECRET"
```

### Login Errors
Monarch rejects many unrelated login attempts with HTTP 401/403 — wrong credentials, its minimum-app-version gate ("Please update to the latest version of the app"), email one-time-code verification, CAPTCHA, and its edge's browser-signature block. The CLI reports MFA only when Monarch's response names an MFA challenge (`error_code` `MFA_REQUIRED`, or an MFA/two-factor/TOTP message):

| Response | Code | MFA prompt |
|---|---|---|
| MFA challenge, no code supplied | `AUTH_MFA_REQUIRED` | yes (interactive only) |
| MFA challenge, code or secret supplied | `AUTH_MFA_INVALID` | no |
| Any other 401/403 | `AUTH_REQUIRED`, message `Monarch rejected the login: <Monarch's detail>` | no |

Only Monarch's `detail` (or `error_code`, or the HTTP status) is surfaced; the request body, password, and MFA secret never appear in errors.

## Session Persistence

Once authenticated, a session token is stored locally. This token is used for all subsequent commands.

- **Storage Path**: `~/.monarchmoney-cli/session.json`
- **Security**: The file is saved with `0600` permissions (read/write by owner only).
- **Contents**: The session file stores the token, account email, timestamps, and profile metadata needed for `auth status`.

### Secret Indirection (`env:NAME`)

The stored `token` value may be a literal token or the indirection form `env:NAME`. When the token is `env:NAME`, it is resolved from the environment variable `NAME` each time the session is loaded, so the real secret never has to sit in the file. If `NAME` is unset, the CLI fails with an explicit error rather than proceeding unauthenticated.

This is the agent-first alternative to an OS keychain (which cannot be used unattended). For example, write a `0600` session file containing `"token": "env:MONARCH_TOKEN"` and supply the secret from the environment or a secret manager at run time:

```bash
export MONARCH_TOKEN="..."
monarch accounts list --json
```

See `docs/adr/0006-secrets-storage.md` for the full rationale.

### Checking Status
To check if you have a valid local session:
```bash
monarch auth status
```
This command now performs a live Monarch identity check by default, so it can tell you whether the stored session is still valid.
If the token has expired or been revoked, the command reports `AUTH_SESSION_EXPIRED` and keeps the stored email visible so you know which account needs to be re-authenticated.

### Logging Out
To remove the local session token:
```bash
monarch auth logout
```

## Session Status and Local Commands

- The session token is stored at `~/.monarchmoney-cli/session.json` by default.
- `auth status` reports the stored email, the last login time, and whether the session is still valid.
- Cache-backed commands such as `cache stats`, `cache search`, and `hledger backup` work entirely from local data without a session or network access. Everything else talks to the Monarch API and requires a valid session.

## Local Cache Database

The local cache lives at `~/.monarchmoney-cli/cache/monarch.sqlite`.

- It is a standard SQLite database, not AES-256 encrypted.
- The cache file is created with `0600` permissions and the directory is created with `0700` permissions.
- It may contain cached account and transaction data, so treat it as sensitive local data.
- `cache sync` is manual. It upserts all accounts, up to the latest 1000 transactions (optionally filtered with `--from YYYY-MM-DD`), and replaces the investment-holdings snapshot on every run.
- The transaction cache is cumulative: rows returned by later syncs replace matching IDs and add new IDs, but old cached rows are not removed automatically.
- The cache stores archive-grade detail (tags, splits, review state, category groups, raw merchant names, account lifecycle flags, holdings, closing balances) so offline commands and ledger backups never need the API. A cache created by an older version of the CLI is rejected with a prompt to re-run `cache sync`, which rebuilds it.
- The cache is not a complete mirror of Monarch. Remote deletions are not reconciled locally; use `cache cleanup --before YYYY-MM-DD` to explicitly prune old cached transactions.
- If you want stronger at-rest protection, rely on full-disk encryption such as FileVault or store the profile on an encrypted volume.

## Security Best Practices

1. **Permissions**: Ensure your `~/.monarchmoney-cli` directory has `0700` permissions.
2. **Environment Variables**: For scripts, you can use environment variables instead of interactive prompts:
   - `MONARCH_EMAIL`: Your account email address.
   - `MONARCH_PASSWORD`: Your account password.
   - `MONARCH_MFA_CODE`: A 6-digit MFA code (for single-use scripts).
   - `MONARCH_MFA_SECRET`: Your TOTP secret key for automatic code generation.
   - `MONARCH_USER_AGENT`: Override the default HTTP User-Agent string.
3. **Session Safety**: Never share your `session.json` file. It contains a long-lived token that grants access to your Monarch account.

### Credential Security

**Prefer environment variables over CLI flags.** The `--password` and `--mfa-secret` flags expose credentials in the process table (`/proc/PID/cmdline`), which is visible to other processes on the system. Environment variables are safer for scripts and automation:

```bash
# Safer: credentials via environment variables
export MONARCH_PASSWORD="..."
export MONARCH_MFA_SECRET="..."
monarch auth login --email user@example.com

# Less safe: credentials visible in process table
monarch auth login --email user@example.com --password "..." --mfa-secret "..."
```

The interactive prompt (default behavior, no flags) is the most secure option for manual use, as it reads the password via `term.ReadPassword()` without echoing.
