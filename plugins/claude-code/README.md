# Tripwire — Claude Code plugin

Plant decoy credentials where attackers look. When one is used, you get one
alert — and by construction, it's real.

A Tripwire canary is a working credential that nothing legitimate ever
touches. It authenticates only against Tripwire's decoy backend, never your
real infrastructure, so it can never make an incident worse. If it fires,
someone reached somewhere they shouldn't have — and where it lives tells you
what was reached.

## Install

```
/plugin marketplace add tachyon-oss/tripwire
/plugin install tripwire@tripwire
```

That's it. The plugin bundles its own client; there is nothing else to
install. (`uvx` is used under the hood to run it in an isolated environment.)

## Use

- `/tripwire:init` — guided setup of your first canary. It suggests scenarios
  that fit how you work, you pick one, and it plants a decoy artifact only
  where you approve.
- Ask in natural language — "help me plant a canary", "did anything fire?" —
  and the plugin's skills handle it.
- Power users can also drive the bundled `tripwire` CLI directly:
  `tripwire canary list`, `tripwire canary show <id>`.

## Canary types

Six types, in two families:

- Provider credentials, inert real-looking secrets: `aws_access_key`,
  `github_pat`.
- Request-path credentials, served from Tripwire-hosted facades:
  `web_login_credential` (a fake login URL plus username/password),
  `browser_session_cookie` (a planted session cookie), `postgres_login` (a
  decoy `DATABASE_URL` connection string), `kubernetes_kubeconfig` (a decoy
  `~/.kube/config` or bearer token).

Whichever you plant, the credential is inert against real infrastructure and
fires when something uses it. The request-path types fire when the credential is
actually used (a login is submitted, a cookie or token is presented, a Postgres
connection is made), not when the facade page is merely viewed.

## Authentication

The plugin logs you in by email, no password. When you run `/tripwire:init` or
ask it to plant a canary, it reads your git email (`git config user.email`),
asks you to confirm it or give another, and Tripwire emails you a 6-digit
sign-in code; paste it back and you're in. First-time addresses are signed up
automatically, and the token is kept only for the session.

Under the hood the skills call the Tripwire REST API directly (see
[`skills/tripwire-api.md`](skills/tripwire-api.md)); they do not require the
bundled CLI.

Self-hosting? Point the plugin at your server with the `server` option (or
`$TRIPWIRE_SERVER`) before logging in.

## What this plugin will not do

It does not read, scan, or traverse your repositories, secrets, environment,
or filesystem to decide where to plant a canary. It suggests from what you
tell it, and never creates or edits a file until you approve the exact path.
Nothing in your real systems is touched without your say-so.

## Configuration

| Option | Default | Meaning |
|---|---|---|
| `server` | (Tripwire production API) | Self-hosting only. Consumed at `tripwire login`; set it before logging in. |
