# @tachyonhq/tripwire

The `tripwire` command-line client for [Tripwire](https://tripwire.so) security
canaries. Create decoy credentials that look real, plant them where an intruder
would look, and get alerted the moment one is used.

This is the TypeScript/Node CLI. It talks to the same REST API as the legacy
Python client and shares its credential cache, so you can use either against the
same account.

## Install

```bash
npm install -g @tachyonhq/tripwire
# then
tripwire --help
```

Requires Node >= 18 (uses the built-in `fetch`).

## Getting started

```bash
tripwire login                 # emailed 6-digit code -> cached token
tripwire canary create aws.access_key
tripwire status                # did anything fire?
```

Login caches a token at `~/.config/tripwire/credentials.json` (honoring
`XDG_CONFIG_HOME`). Point at a self-hosted or test server by exporting
`TRIPWIRE_SERVER=https://host/api/v1` before `tripwire login`.

## Grammar

Noun-first: one object (`canary`), closed verbs over an open type catalog.

```
tripwire login [--email <addr>]
tripwire logout
tripwire whoami
tripwire status [--watch] [--json]
tripwire api <METHOD> <path> [body] [--json]

tripwire canary create <type> [--name N] [--note S] [--in <id>] [--expires D] [-o <file>]
tripwire canary list [--type T] [--fired] [--in <id>] [--json]
tripwire canary show <id> [--json]
tripwire canary disarm <id>
tripwire canary delete <id>
tripwire canary types [<type>] [--json]
tripwire canary api <METHOD> <path> [body] [--json]

tripwire bundle download [<id>] [-o <path>] [--zip]
tripwire bundle show <id> [--json]
tripwire bundle contents <id> [--json]
tripwire bundle create
```

Single canonical names only — there are no command aliases and no back-compat
surface.

## Canary types

Types use a dotted `namespace.artifact` id, and the dotted id is the only value
`create` accepts. Internally the CLI translates it to the snake id today's API
expects on the wire (e.g. `aws.access_key` → `aws_access_key`); `--json` output
is verbatim server truth (snake ids), while human tables show the dotted ids.

| type | backing | fires via |
|---|---|---|
| `aws.access_key` | real IAM key | CloudTrail |
| `github.token` | real PAT/OAuth token | audit stream |
| `database.credentials` | Tripwire TCP edge | connect |
| `web.login` | Tripwire HTTP edge | credential submit |
| `web.cookie` | Tripwire HTTP edge | cookie presented |
| `k8s.config` | Tripwire k8s edge | API use |

`database.credentials` renders a PostgreSQL login; `web.cookie` renders a
browser session cookie. `anthropic.api_key` is coming soon (not yet creatable).

Run `tripwire canary types` for the released catalog and `tripwire canary types
<type>` for detail.

## AWS placements

Placements are CLI sugar: they mint an `aws.access_key` and render the returned
credential straight into an AWS config format. The stored canary is still an
`aws.access_key`.

```bash
# print the block to stdout; append it to your real config
tripwire canary create aws.profile >> ~/.aws/config

# or let the CLI write the file (append-or-create, chmod 0600)
tripwire canary create aws.credentials -o ~/.aws/credentials
```

- `aws.profile` renders a `[profile <name>]` block for `~/.aws/config`.
- `aws.credentials` renders a `[<name>]` block for `~/.aws/credentials`.

Placements appear in `tripwire canary types`, nested under `aws.access_key`, and
`tripwire canary types aws.profile` explains what they create and render.

Delivery contract:

- **Default:** only the rendered block goes to **stdout** (with a leading and
  trailing newline, so `>>` composes cleanly); every status line goes to
  **stderr**.
- **`-o <file>`:** the CLI appends the block (or creates the file with mode
  0600). If that write fails *after* the credential was minted, the block is
  dumped to stdout with a loud warning so the one-time secret is never lost.

`--name` is checked against a list of operator terms (`canary`, `honeypot`,
`decoy`, ...) and rejected if it would blow the decoy's cover. Omit it and the
CLI generates an organic `{repo}-{role}` name. `--note` is stored on the canary
but is **never** written into the config file.

## Scripting

Every read command takes `--json`. For anything the porcelain does not cover,
use the authenticated passthrough:

```bash
tripwire api GET /canary --json
tripwire api POST /canary '{"type":"aws_access_key"}'
```

## Development

```bash
npm install
npm run build     # tsup -> dist/
npm test          # vitest (offline)
npm run typecheck # tsc --noEmit
```

## Notes on API coverage

`--in` (containment) on `create`/`list` is ahead of today's server and reports
"not yet supported" instead of faking success; it lights up the moment the
server gains it.
