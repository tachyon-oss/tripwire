# Tripwire REST API reference

This file is the transport contract for the Tripwire skills. The skills describe
*what* to do (plant a canary, check whether one fired); this file says *which
API call* performs each step. An agent can drive these endpoints directly with
any HTTP client (`curl`, `httpx`, `fetch`). The `tripwire` CLI is one optional
wrapper over the same API; a separate `tripwire-cli.md` will document that path.
Nothing in the skills should assume the CLI is installed.

- Base URL: `https://tripwire.so/api/v1` (override with `$TRIPWIRE_SERVER` for
  self-host/testing; strip any trailing slash).
- Auth: send `Authorization: Bearer <access_token>` on every call except the
  two login endpoints and `/readyz`.
- Content type: requests and responses are JSON. Errors are
  `{"detail": <string or object>}` with a non-2xx status.
- Token handling: hold the bearer token in memory and re-send it on each call.
  It does not need to be persisted anywhere for the agentic flow.

## Action -> endpoint map

| Skill action | Method + path |
|---|---|
| Begin email login (send a code) | `POST /auth/login/start` |
| Complete login (exchange the code for a token) | `POST /auth/login` |
| Read the logged-in identity (incl. email) | `GET /auth/me` |
| Plant a canary (one-time credential reveal) | `POST /canary` |
| List the canaries you own | `GET /canary` |
| Read one canary (did it fire?) | `GET /canary/{id}` |
| Deactivate a canary | `POST /canary/{id}/deactivate` |
| Delete a canary | `DELETE /canary/{id}` |

## Auth (email-code login)

Tripwire login is passwordless email-code. The agentic flow:

1. Look up a default email with `git config user.email`. Show it to the user
   and ask them to confirm it or supply another address. Never guess silently.
2. `POST /auth/login/start` with `{"email": "<addr>"}`. Always returns
   `200 {"status": "ok"}` (neutral by design; it never reveals whether the
   address is known). This emails a 6-digit sign-in code. Self-signup: a first-
   time address is provisioned as a normal user on login.
3. Ask the user for the 6-digit code from their inbox.
4. `POST /auth/login` with `{"email": "<addr>", "code": "<6 digits>"}`. On
   success returns:
   ```json
   {"access_token":"<token>","token_type":"bearer","expires_at":<unix>,
    "user_id":"usr_...","role":"user"}
   ```
   A wrong/expired/used code returns `400 {"detail":"invalid_or_expired_code"}`.
5. Use `access_token` as the bearer token for everything below.
   `GET /auth/me` returns `{"user":{"id","email","role"}}` if you need to echo
   the resolved email back to the user.

## Plant a canary: `POST /canary`

Body: `{"type": "<type>", "memo": "<optional note>"}`. `type` is one of six
values, in two families:

- Provider credentials (real provider mint, inert against real infra):
  `aws_access_key`, `github_pat`.
- Request-path credentials (Tripwire-hosted facades, no provider mint):
  `web_login_credential`, `browser_session_cookie`, `postgres_login`,
  `kubernetes_kubeconfig`.

`github_pat` additionally accepts `"token_type": "classic_pat" | "oauth"`. Only
a genuinely unknown `type`, or extra or cross-type fields in the body, are
rejected with `422` (`extra="forbid"`). For the request-path types, send only
`type` (and optional `memo`); the server generates every name/host/value, so do
not send any name/host/value fields.

Response `201` is the canary object with its secret/placement inlined at the top
level. This is the ONLY time the secret is returned; capture it now.

Provider credentials:

- `aws_access_key` -> `access_key_id`, `secret_access_key`, `region`
- `github_pat` -> `raw_token`

Request-path credentials:

- `web_login_credential` -> `url`, `username`, `password` (the `url` is a real
  Tripwire-hosted login facade page)
- `browser_session_cookie` -> `url`, `cookie_name`, `cookie_value`,
  `cookie_domain`, `cookie_path`
- `postgres_login` -> `database_url`, `host`, `port`, `database`, `username`,
  `password`, `sslmode`, `url`
- `kubernetes_kubeconfig` -> `kubeconfig` (full YAML), `server`, `cluster_name`,
  `user_name`, `bearer_token`, `token`

plus summary fields `id`, `type`, `status`, `user_id`, `memo`, `expires_at`,
`last_checked_at`, `last_used_at`, `created_at`, `updated_at`.

Important: create is synchronous. For request-path types the credential is
returned right away; for provider types it is returned once it's ready, usually
in a second or two but occasionally up to ~2 min. Use a generous HTTP read
timeout (>=180s) as a safety net, and show a "provisioning" state rather than
letting a slow create look hung.

Warm-up for request-path types: the credential is returned immediately, and the
facade becomes fully live (it serves its page and detects credential use) within
about 5s of create. It is not a 30-60s wait; if you have just created one, a few
seconds is enough before it is armed.

Non-201 outcomes:
- `429 {"detail":"canary_pending"}` - not minted within the wait window. The
  canary was still created, but because the secret reveal is one-time it was not
  returned in-band and is unrecoverable. Do NOT retry the create (a retry mints a
  second canary and trips the per-type quota); instead find this orphan via
  `GET /canary`, `DELETE /canary/{id}` it, then create again. Prefer a client
  read timeout above the server wait window (below) so this outcome is rare.
- `403 {"detail":{"error":"quota_exceeded","type","cap"}}` - the per-type live
  cap for this tier is reached. Caps vary by type (1-2 on the default tier):
  `web_login_credential`, `browser_session_cookie`, `postgres_login`,
  `kubernetes_kubeconfig` 2 each; `github_pat` 1; `aws_access_key` 1. The
  response echoes the offending `type` and its `cap`. Deactivate or delete an
  existing one of that type first.
- `429 {"detail":"create_rate_limited"}` - too many creates in the window.
- `502 {"detail":"provisioning_failed"}` - provider mint failed; nothing issued;
  retry.

## Read / list / lifecycle

- `GET /canary?type=<type>&include_deleted=<bool>` -> `{"canaries":[<summary>...]}`.
  Summary only, never the secret. `type` and `include_deleted` are optional.
- `GET /canary/{id}` -> one summary. "Did it fire?" is answered by
  `last_used_at` for all six types: nothing legitimate should ever touch a
  canary credential, so a populated `last_used_at` means something reached for
  it. The read reflects the latest activity, so request-path types report through
  the same field. For request-path types `last_used_at` fires when the attacker
  actually USES the credential (POSTs the username/password to the login facade,
  presents the session cookie, sends the bearer token, or connects with the
  postgres password), not when they merely view the facade page. That is
  intended. `last_checked_at` is when Tripwire last checked for use. Point the
  user at their Tripwire account for full per-event detail (source IP, time,
  action).
- `POST /canary/{id}/deactivate` -> summary. Disables the credential.
  Request-path facades stop matching within a few seconds; provider types
  disable shortly after.
- `DELETE /canary/{id}` -> summary. Sets the canary to be torn down. Request-path
  facades are removed within a few seconds; provider types are soft-deleted and
  the underlying resource is removed shortly after, so the immediate response may
  still show `status:"active"`. Re-read with `GET /canary/{id}` (or list with
  `include_deleted=true`) to confirm it reached `deleted`.

## Notes for skill authors

- Treat the create response as sensitive: write the returned secret only into the
  decoy artifact at the path the user approved, never echo it elsewhere.
- Everything is tenant-scoped to the caller's token; there is no cross-tenant
  read on this surface.
- Keep the flow API-first. If the user already has the `tripwire` CLI installed
  and prefers it, the same actions map onto its subcommands (documented
  separately in `tripwire-cli.md`), but do not require it.
