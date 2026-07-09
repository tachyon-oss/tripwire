---
description: Set up your first Tripwire canary — a working decoy credential planted where attackers look, with alerts wired to your channel.
argument-hint: "[what you want covered, optional]"
allowed-tools: Bash(curl:*), Bash(git:*), Bash(tripwire:*), AskUserQuestion, Write, Read
---

# Tripwire onboarding

You are guiding the user through planting their first Tripwire canary. A
canary is a credential nothing legitimate ever touches; if it is ever used,
an attacker is on the other end. It authenticates only against Tripwire's
decoy backend — never the user's real infrastructure.

This flow is transport-agnostic. Drive the Tripwire REST API directly with any
HTTP client; every endpoint and the action-to-endpoint map live in
[../skills/tripwire-api.md](../skills/tripwire-api.md). If the user has the
`tripwire` CLI installed and prefers it, the same actions map onto its
subcommands, but do not depend on the CLI being present.

## Hard constraint — do not violate

**Ask before you explore.** Reading the user's repositories, environment, or
filesystem to find believable placements is fine *only after* they say yes,
and only in the areas they approve — never rummage uninvited. Never create or
modify a file until the user has approved the exact path, and never copy a
real secret out of their environment. Nothing in the user's real systems is
touched without their explicit say-so. This is a promise the product makes;
honor it exactly.

## Steps

1. **Auth.** Make sure you have a bearer token. If not, log in with the
   email-code flow in
   [../skills/tripwire-api.md](../skills/tripwire-api.md) ("Auth"): read a
   default address from `git config user.email`, ask the user to confirm it or
   give another (`AskUserQuestion`), call `POST /auth/login/start`, then
   exchange the 6-digit code they paste via `POST /auth/login`. Hold the token
   in memory for the session; it does not need to be stored.

2. **Understand the environment first, then suggest — with consent.** Start from
   what the user said (the optional argument was: "$ARGUMENTS") and the context
   they shared. Offer to look around to ground your suggestions; with their
   go-ahead, explore the approved areas (their stack, where credentials already
   live, what an attacker would grep for) and work out which credential types
   are present and which canary types fit where. Then propose 2-3 concrete
   scenarios. There are eight canary types, in two families. Provider
   credentials (inert real-looking secrets):
   - an `aws_access_key` in a decoy `.env` / credentials file (a strong lure
     even if they do not use AWS, its only purpose is to be triggered);
   - a `dns_label` referenced in a config snippet;
   - an `anthropic_api_key` or `github_pat` in a decoy script or dotfile.
   Request-path credentials (Tripwire-hosted facades; each fires when the
   credential is actually used):
   - a `web_login_credential` (a fake admin/login URL with username and
     password) in a README, internal-tools doc, or password-manager export;
   - a `browser_session_cookie` in a saved browser-state / HAR export or a
     "remember me" note;
   - a `postgres_login` (a `DATABASE_URL` connection string) in a `.env`, a
     backup script, or infra config;
   - a `kubernetes_kubeconfig` (a decoy `~/.kube/config`) or its bearer token in
     a CI secret.
   Use `AskUserQuestion` to let them pick, or to ask where they want coverage
   if you have no signal. Do not proceed without a choice.

3. **Confirm placement.** State exactly what you will create and where (a
   fresh path you propose, e.g. `~/tripwire-demo/.env.example`). Get explicit
   approval of that path before creating anything. Never write into an
   existing user file unless they name it and confirm.

4. **Create the canary** via `POST /canary` (see
   [../skills/tripwire-api.md](../skills/tripwire-api.md), "Plant a canary")
   with the chosen `type` and a short `memo`, and keep the response. Create is
   synchronous and is the one-time credential reveal: the response inlines the
   secret/placement for that type at the top level. `aws_access_key`:
   `access_key_id`/`secret_access_key`/`region`; `github_pat`: `raw_token`;
   `anthropic_api_key`: `raw_key`; `dns_label`: `fqdn`/`qtype`;
   `web_login_credential`: `url`/`username`/`password`; `browser_session_cookie`:
   `url`/`cookie_name`/`cookie_value`/`cookie_domain`/`cookie_path`;
   `postgres_login`: `database_url`/`host`/`port`/`database`/`username`/`password`/`sslmode`/`url`;
   `kubernetes_kubeconfig`: `kubeconfig` (full YAML) plus
   `server`/`cluster_name`/`user_name`/`bearer_token`/`token`. The server
   generates every name/host/value, so do not invent zone/name/value/host flags.
   For provider types create is usually near-instant (the server claims a
   pre-warmed credential), but use a read timeout of at least 180s as a safety net
   for a rare cold-pool fallback. For the request-path types
   (`web_login_credential`, `browser_session_cookie`, `postgres_login`,
   `kubernetes_kubeconfig`) create is instant and the facade becomes fully live
   within about 5s, not a 30-60s wait. Capture it now; reads never return the
   secret again. If create answers `canary_pending`, the one-time reveal is gone
   and unrecoverable: do NOT retry (a retry mints a second canary and trips the
   quota); find the orphan via `GET /canary`, delete it, then create again.

5. **Materialize the decoy artifact** only at the approved path, created
   fresh. Put the returned credential there in a form that looks organic for
   the chosen surface (e.g. `AWS_ACCESS_KEY_ID=...` /
   `AWS_SECRET_ACCESS_KEY=...` in `.env.example`). Do not add comments that
   reveal it is a canary.

6. **Explain alert routing.** Tell the user fires show up in their Tripwire
   account (dashboard / configured email). Channel routing is configured
   server-side; point them there rather than inventing a mechanism here.

7. **Explain the signal.** Close by stating plainly: this credential is inert
   against real infrastructure; anything that reads or uses it is the signal,
   and where it lives tells them what was reached.

Keep the interaction tight and concrete. Show the canary id and surface at
the end so the user knows what they just planted.
