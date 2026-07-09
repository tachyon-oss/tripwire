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

tripwire canary create <type> [--note S] [--expires D] [-o <file>]
tripwire canary list [--type T] [--fired] [--json]
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

| type | what it is |
|---|---|
| `aws.access_key` | AWS access key |
| `github.token` | GitHub token |
| `database.credentials` | database login |
| `web.login` | fake login page + password |
| `web.cookie` | browser session cookie |
| `k8s.config` | Kubernetes kubeconfig |
| `aws.profile` | AWS access key, rendered into `~/.aws/config` |
| `aws.credentials` | AWS access key, rendered into `~/.aws/credentials` |

The last two rows are AWS placements: CLI sugar that mints an `aws.access_key`
and renders it straight into a real AWS config format (see below).

Run `tripwire canary types` for the full catalog and `tripwire canary types
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

The profile/label name is generated automatically to look organic, so it never
blows the decoy's cover; you do not choose it. `--note` is stored on the canary
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
