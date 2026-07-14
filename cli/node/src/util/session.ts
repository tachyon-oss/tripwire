/**
 * Session wiring: the credential store, the API-client factory, and the prompt
 * channel. Collaborators are injectable so command tests can supply fakes
 * without touching the network, the real credential file, or a real TTY.
 *
 * This is the CLI's single authentication choke point. Every authenticated
 * command goes through `authedClient()`, so automatic sign-in lives here and
 * nowhere else.
 */
import { ApiClient } from "../api/client.js";
import {
  CredentialStore,
  type Credentials,
  defaultStore,
  isExpired,
  resolveLoginServer,
  resolvedServer,
} from "../config/credentials.js";
import { CliError } from "./errors.js";
import { emailLogin } from "./login.js";
import { type Prompter, TtyPrompter } from "./prompt.js";

export interface SessionDeps {
  store?: CredentialStore;
  /** Build an `ApiClient` from a base URL and optional token (injectable). */
  clientFactory?: (baseUrl: string, token?: string | null) => ApiClient;
  env?: NodeJS.ProcessEnv;
  prompter?: Prompter;
}

export class Session {
  readonly store: CredentialStore;
  readonly prompter: Prompter;
  private readonly clientFactory: (baseUrl: string, token?: string | null) => ApiClient;
  private readonly env: NodeJS.ProcessEnv;

  constructor(deps: SessionDeps = {}) {
    this.store = deps.store ?? defaultStore();
    this.prompter = deps.prompter ?? new TtyPrompter();
    this.clientFactory =
      deps.clientFactory ??
      ((baseUrl, token) => new ApiClient({ baseUrl, token: token ?? null }));
    this.env = deps.env ?? process.env;
  }

  client(baseUrl: string, token?: string | null): ApiClient {
    return this.clientFactory(baseUrl, token ?? null);
  }

  /**
   * The credentials an authenticated command runs on: the cached token when it
   * is usable, otherwise an interactive sign-in performed right now. Without a
   * TTY there is no way to ask for a code, so fail fast rather than hang.
   */
  async requireCredentials(): Promise<Credentials> {
    const cached = this.store.tryLoad();
    if (cached && !isExpired(cached)) return cached;

    if (!this.prompter.interactive()) {
      throw new CliError(
        "not logged in. run `tripwire auth login` first.\n" +
          "(no TTY available to prompt for a sign-in code)",
      );
    }
    this.prompter.notify(
      cached
        ? "your session has expired. signing you in again."
        : "not logged in. signing you in first.",
    );
    return this.login();
  }

  /** Run the interactive email-code login and cache the result. */
  async login(emailFlag?: string): Promise<Credentials> {
    const server = this.loginServer();
    const creds = await emailLogin(this.client(server), server, this.prompter, {
      emailFlag,
      defaultEmail: this.store.tryLoad()?.email ?? null,
    });
    this.store.save(creds);
    return creds;
  }

  /** A client bound to the cached server + token, signing in first if needed. */
  async authedClient(): Promise<ApiClient> {
    const creds = await this.requireCredentials();
    return this.client(resolvedServer(creds), creds.access_token);
  }

  /** The cached credentials, or `null`. Never prompts: this is what `auth
   *  status` reports on, and asking for a sign-in code there would be absurd. */
  currentCredentials(): Credentials | null {
    return this.store.tryLoad();
  }

  /** Server for `login`: env override, then cached, then default. */
  loginServer(): string {
    return resolveLoginServer(this.env, this.store.cachedServer());
  }
}
