---
name: add-canary
description: Use when the user wants to plant, set up, add, or create a Tripwire canary / decoy credential / honeytoken (AWS key, GitHub PAT, web login, browser session cookie, Postgres login, or Kubernetes kubeconfig). The natural-language path to creating a canary.
allowed-tools: Bash(curl:*), Bash(git:*), Bash(tripwire:*), AskUserQuestion, Write, Read
---

# Plant a Tripwire canary

The user wants to plant a decoy credential. Run the flow below (the same one
`/tripwire:init` runs), from this natural-language entry point.

This skill is transport-agnostic. Drive the Tripwire REST API directly with any
HTTP client; every endpoint and the action-to-endpoint map live in
[../tripwire-api.md](../tripwire-api.md). If the user has the `tripwire` CLI
installed and prefers it, the same actions map onto its subcommands, but do not
depend on the CLI being present.

**Hard constraint — ask before you look.** Reading the user's project,
environment, or filesystem to find believable placements is fine *only after*
they say yes, and only in the areas they approve. Never create or edit a file
until the user approves the exact path, and never copy a real secret out of
their environment. Nothing in their real systems is touched without explicit
consent.

Flow:

1. **Auth.** Make sure you have a bearer token. If not, log in with the
   email-code flow in [../tripwire-api.md](../tripwire-api.md) ("Auth"):
   read a default address from `git config user.email`, ask the user to confirm
   it or give another (`AskUserQuestion`), call `POST /auth/login/start`, then
   exchange the 6-digit code they paste via `POST /auth/login`. Hold the token
   in memory for the rest of the session; it does not need to be stored.

2. **Understand the environment first — with consent.** Ask whether you may look
   around to ground your suggestions. With their go-ahead, explore the approved
   areas (their stack, where credentials already live, what an attacker would
   grep for) and work out which credential types are present and which canary
   types fit where (see "Choosing a canary type" below). Without consent, make a
   best guess from what they have told you, or ask them for suggestions. Then
   propose 2-3 concrete placements. A strong canary is often a credential type
   they do not even use; its only job is to be triggered. Let them choose
   (`AskUserQuestion`).

3. **Confirm placement.** State the exact fresh path you will create and get
   approval. Never write into an existing user file unless they name it and
   confirm.

4. **Create the canary** via `POST /canary` (see
   [../tripwire-api.md](../tripwire-api.md), "Plant a canary") with the chosen
   `type` and a short `memo`. Create is synchronous and is the one-time
   credential reveal: the response inlines the secret/placement for that type
   (`aws_access_key`: `access_key_id`/`secret_access_key`/`region`; `github_pat`:
   `raw_token`; `web_login_credential`: `url`/`username`/`password`;
   `browser_session_cookie`:
   `url`/`cookie_name`/`cookie_value`/`cookie_domain`/`cookie_path`;
   `postgres_login`: `database_url`/`host`/`port`/`database`/`username`/`password`/`sslmode`/`url`;
   `kubernetes_kubeconfig`: `kubeconfig` (full YAML) plus
   `server`/`cluster_name`/`user_name`/`bearer_token`/`token`; the server
   generates every name/host/value, send no name/host flags). For provider
   types create usually returns in a second or two; use a read timeout of at
   least 180s as a safety net while it provisions. For the request-path types
   (`web_login_credential`, `browser_session_cookie`, `postgres_login`,
   `kubernetes_kubeconfig`) create is instant and the facade becomes fully live
   within about 5s, so a brief pause
   before you expect it to detect use is enough; it is not a 30-60s wait.
   Capture the secret now; reads never return it again. If create answers
   `canary_pending`, the one-time reveal is gone and unrecoverable: do NOT retry
   (a retry mints a second canary and trips the quota); find the orphan via
   `GET /canary`, delete it, then create again.

5. **Materialize the decoy** only at the approved path, created fresh, in a form
   that looks organic for that surface. No canary-revealing comments.

6. **Explain the signal.** Fires surface in the user's Tripwire account; the
   credential is inert against real infrastructure, so anything that reads or
   uses it is the signal, and where it lives tells them what was reached.

Report the canary id and surface at the end.

## Choosing a canary type

Match the lure to what an attacker in this environment would actually grep for.

Provider-credential types (inert real-looking provider secrets):

- `aws_access_key` — decoy `.env`, `~/.aws/credentials`, CI secrets, Terraform
  vars. A strong lure even if they do not use AWS.
- `github_pat` — dotfiles, `.netrc`, CI/CD secrets, a git remote URL, a deploy
  script.

Request-path types (Tripwire-hosted facades; each fires when the attacker
actually uses the credential, not when they merely view it):

- `web_login_credential`: a fake admin or login URL with a username and
  password. Plant the URL plus creds in a README, an internal-tools doc, a
  password-manager export, or a "credentials" note. Fires when someone submits
  the username/password to the login page.
- `browser_session_cookie`: a planted session cookie (name, value, domain,
  path). Drop it in a saved browser-state or HAR export, a "remember me" note,
  or a scraped-session snippet. Fires when someone presents the cookie.
- `postgres_login`: a `DATABASE_URL` / Postgres connection string. Plant it in
  a `.env`, a backup or restore script, or infra config (the kind of string an
  attacker pipes straight into `psql`). Fires when someone connects with the
  password.
- `kubernetes_kubeconfig`: a decoy `~/.kube/config` YAML, or its bearer token
  in a CI secret or deploy script. Fires when someone uses the kubeconfig or
  sends the bearer token.
