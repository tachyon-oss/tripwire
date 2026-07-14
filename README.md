# Tripwire

Real-credential-backed canaries (honeytokens) for detecting intrusions.

[Tripwire](https://tripwire.so) hands you a bundle of decoy credentials that
look and work like the real thing — an AWS access key, a GitHub token, a
database URL, a login. Nothing legitimate ever touches them, so they sit quietly
wherever you plant them. The moment one is *used*, you get a single, unambiguous
alert: someone reached somewhere they shouldn't have, and where the decoy lived
tells you what was reached.

Because each canary authenticates only against Tripwire's decoy backend and
never your real infrastructure, a fired canary can never make an incident worse.

Tripwire is a product of [Tachyon International Inc.](https://tachyon.so)

## Quickstart

```bash
npm i -g @tachyonhq/tripwire
tripwire bundle download    # get your bundle of decoy credentials
```

No login step: the first command that needs an account signs you in, with a
6-digit code emailed to you. (`tripwire auth login` if you would rather do it up
front. In CI or inside an agent, where there is no terminal to prompt at, sign in
once interactively first.)

## What's in this repo

This is the Tripwire product monorepo. Three components share one REST API and
one account:

| Path | What it is |
|---|---|
| [`cli/node`](cli/node) | **The canonical CLI** — `@tachyonhq/tripwire`, run with `npx @tachyonhq/tripwire` or install globally. TypeScript/Node (requires Node >= 18). |
| [`cli/python`](cli/python) | The PyPI client (`tripwire-cli`). Same REST API and credential cache as the Node CLI, so either works against the same account. |
| [`plugins/claude-code`](plugins/claude-code) | The Tripwire Claude Code plugin — plant and check canaries from inside your coding agent in natural language. Bundles its own client. |

### Claude Code plugin

```
/plugin marketplace add tachyon-oss/tripwire
/plugin install tripwire@tripwire
```

Then `/tripwire:init` for guided setup, or just ask ("help me plant a canary",
"did anything fire?").

## Canary types

Six released types, in two families:

- **Provider credentials** — inert real-looking secrets: `aws.access_key`,
  `github.token`.
- **Request-path credentials** — served from Tripwire-hosted facades:
  `web.login`, `web.cookie`, `database.credentials`, `k8s.config`.

Each fires when the credential is actually *used* (a key call is made, a login
is submitted, a cookie or token is presented, a connection is opened), not when
a page is merely viewed. See [`cli/node/README.md`](cli/node/README.md) for the
full command grammar and type catalog.

## Self-hosting

All three components point at the Tripwire production API by default. Point them
at a self-hosted or test server by exporting `TRIPWIRE_SERVER=https://host/api/v1`
before you log in (the server is bound to your token at login time). The plugin
exposes the same setting as its `server` option.

## License

MIT — see [`LICENSE`](LICENSE). Copyright (c) 2026 Tachyon International Inc.
