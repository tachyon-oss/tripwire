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
tripwire canary create aws.access_key
tripwire status                # did anything fire?
```

There is no separate login step. Any command that needs an account signs you in
first: it emails you a 6-digit code, prompts for it, then carries on with what
you asked for. `tripwire auth login` exists for when you would rather do it up
front.

Signing in needs a terminal. Without a TTY (CI, a pipe, a coding agent) there is
no way to ask you for a code, so the command fails immediately with `run
`tripwire auth login`` instead of hanging on a prompt you cannot see. Log in once
interactively; the cached token is then used non-interactively.

Login caches a token at `~/.config/tripwire/credentials.json` (honoring
`XDG_CONFIG_HOME`). Point at a self-hosted or test server by exporting
`TRIPWIRE_SERVER=https://host/api/v1` before you sign in.

## Grammar

Noun-first: objects (`canary`, `bundle`) with closed verbs over an open type
catalog.

```
tripwire auth login [--email <addr>]
tripwire auth logout
tripwire auth status
tripwire status [--watch] [--json]

tripwire canary create <type> [--note S] [-o <file>]
tripwire canary list [--type T] [--fired] [--json]
tripwire canary show <id> [--json]
tripwire canary delete <id>

tripwire bundle download [<id>] [-o <path>] [--zip]
```

`tripwire status` is the dashboard (did anything fire?). `tripwire auth status`
is your session (who am I, when does it expire?).

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

Run `tripwire canary create --help` to see the full list of types you can
create.

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

Every read command takes `--json`, which emits verbatim server truth (snake
type ids) for piping into `jq` and friends:

```bash
tripwire canary list --json
tripwire canary show <id> --json
```

## Development

```bash
npm install
npm run build     # tsup -> dist/
npm test          # vitest (offline)
npm run typecheck # tsc --noEmit
```
