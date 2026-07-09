# tripwire-cli

Command-line client for [Tripwire](https://tripwire.so) canaries. Installs a
single `tripwire` command.

## Install

```bash
uv tool install --from . tripwire-cli
```

Or run without installing:

```bash
uvx --from . tripwire --help
```

## Usage

```bash
# Log in and cache a token. Defaults to passwordless email-code login: it
# prompts for your email (defaulting to `git config user.email`) and the
# 6-digit code emailed to you.
tripwire login

# Create a canary. The credential is returned once, in this response, so
# capture it now. AWS can take ~2 min; the CLI waits and prints a progress note
# while it provisions.
tripwire canaries create --type aws_access_key --memo "warehouse reporting key"

# Inspect what you own (summaries only; the credential is never shown again).
tripwire canaries list
tripwire canaries get can_1234abcd

# Wind one down.
tripwire canaries deactivate can_1234abcd
tripwire canaries delete can_1234abcd
```

`canaries` subcommands print JSON to stdout (pipe to `jq`); progress and other
plain-text messages go to stderr, so stdout stays clean JSON. Run
`tripwire --help` for the full reference.

Supported create types are `aws_access_key`, `web_login_credential`,
`browser_session_cookie`, `postgres_login`, and `kubernetes_kubeconfig`. The
request-path types
(`web_login_credential`, `browser_session_cookie`, `postgres_login`,
`kubernetes_kubeconfig`) inline their artifact fields directly in the create
response.

`canaries create` accepts `--timeout <seconds>` (env `TRIPWIRE_CREATE_TIMEOUT`,
default 240) for the per-request read timeout; it must stay above the server's
~180s provisioning wait so the one-time credential reveal is never lost to a
premature client timeout.

## Server

`login` talks to `https://tripwire.so/api/v1` by default. Set `TRIPWIRE_SERVER`
to point at a self-hosted or test server before logging in; the server is bound
to your token at login time. The token is cached at
`~/.config/tripwire/credentials.json` (honoring `XDG_CONFIG_HOME`).
