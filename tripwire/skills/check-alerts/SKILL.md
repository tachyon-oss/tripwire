---
name: check-alerts
description: Use when the user asks whether a Tripwire canary fired, wants to see recent alerts/activity, list their canaries, or check the status/last-used time of a planted decoy credential.
allowed-tools: Bash(curl:*), Bash(git:*), Bash(tripwire:*), Read
---

# Check Tripwire canaries and alerts

The user wants to know the state of their canaries or whether any fired.

This skill is transport-agnostic. Drive the Tripwire REST API directly with any
HTTP client; every endpoint and the action-to-endpoint map live in
[../tripwire-api.md](../tripwire-api.md). If the user has the `tripwire` CLI
installed and prefers it, the same actions map onto its subcommands, but do not
depend on the CLI being present. This is a read-only flow; do not create,
modify, or delete anything.

1. **Auth.** Make sure you have a bearer token. If not, log in with the
   email-code flow in [../tripwire-api.md](../tripwire-api.md) ("Auth"): read a
   default address from `git config user.email`, confirm it with the user or
   take another, call `POST /auth/login/start`, and exchange the 6-digit code
   via `POST /auth/login`. Hold the token in memory.

2. **List what they own** with `GET /canary`
   (see [../tripwire-api.md](../tripwire-api.md), "Read / list / lifecycle").
   Each canary's `last_used_at` / `last_checked_at` indicate activity.

3. For any canary of interest, `GET /canary/{id}` for its summary: type, status,
   memo, and the `last_used_at` / `last_checked_at` / `expires_at` timestamps.
   The credential itself is shown only once, at create, and is never returned
   again by reads.

4. **Summarize plainly:** which canaries exist, their type and surface, and
   whether any shows use. A populated `last_used_at` means something reached
   for that credential. This is the fired signal for all eight types
   (`dns_label`, `aws_access_key`, `anthropic_api_key`, `github_pat`,
   `web_login_credential`, `browser_session_cookie`, `postgres_login`,
   `kubernetes_kubeconfig`); the read folds in the latest events, so the
   request-path types report through the same `last_used_at` field. For the
   request-path types that field fires when the attacker actually uses the
   credential (submits the login username/password, presents the session cookie,
   sends the bearer token, or connects with the postgres password), not when
   they merely view the facade page. By construction nothing legitimate should
   touch any of these, so treat any use as worth investigating and point the
   user at their Tripwire account for the full event detail (source IP, time,
   action). Output the API's JSON faithfully; do not fabricate events or times.
